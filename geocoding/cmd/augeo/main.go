// Command augeo is the geocoder server. It wires config (D-020), structured
// logging (INV-1), the parse ladder, the public API (auth/rate/quota/abuse) and
// the HTTP endpoints. It never writes to the geocoding DBs — it only reads
// through the resolution contract.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"augeocoding/internal/config"
	"ausystem/shared/contract"
	"ausystem/shared/metrics"
	"augeocoding/internal/ladder"
	"augeocoding/internal/llm"
	"ausystem/shared/normalise"
	"augeocoding/internal/placesclient"
	"augeocoding/internal/publicapi"
	"ausystem/shared/slog"
)

func main() {
	// Parse config. Fail fast on invalid config (D-020).
	cfg, err := config.Load(os.Args[1:], "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	log := slog.New(os.Stderr, slog.ParseLevel(cfg.Log.Level), map[string]any{"service": "augeo"})
	log.Info("boot", "config", cfg.Redacted(), "llm_configured", cfg.LLM.Enabled)

	// Control token: /ctrl/llm is a control-plane operation on an otherwise
	// read-only server. It must never be reachable without the token (mirrors
	// au-places' /ctrl/activate gate). Empty token => endpoint disabled.
	ctrlToken := os.Getenv("AUGEO_CTRL_TOKEN")

	// Split-mode resolver. In single-binary mode this would be an in-process
	// call; here we call the au-places HTTP API.
	var resolver contract.Resolver
	if cfg.PlacesURL != "" {
		resolver = placesclient.New(cfg.PlacesURL)
	} else {
		log.Error("boot_failed", "reason", "no resolver configured (set AUGEO_PLACES_URL)")
		os.Exit(1)
	}

	// Public API store (app.db — service state, separate from geocoding DBs).
	store, err := publicapi.Open(cfg.Data.AppDB)
	if err != nil {
		log.Error("boot_failed", "reason", "app_db", "error", err.Error())
		os.Exit(1)
	}
	defer store.Close()

	// Rate limiters: per-key (D-006) and per-IP anonymous (D-034). Anonymous
	// has its own budget — AnonRPS/AnonBurst — NOT the keyed one.
	limiter := publicapi.NewRateLimiter(cfg.Rate.KeyDefaultRPS, cfg.Rate.KeyDefaultBurst)
	anonLimiter := publicapi.NewRateLimiter(cfg.Rate.AnonRPS, cfg.Rate.AnonBurst)

	// LLM: runtime-configurable provider client (rung 5). The holder is seeded
	// from boot config and is updated at runtime by /ctrl/llm — no restart. The
	// provider is only wired when the boot config enables it; otherwise the rung
	// stays configured-but-not-wired (501) until an operator enables it.
	llmHolder := llm.NewHolder(llm.Config{
		BaseURL:   cfg.LLM.BaseURL,
		APIKey:    cfg.LLM.APIKey,
		Model:     cfg.LLM.Model,
		Timeout:   cfg.LLM.Timeout,
		MaxTokens: cfg.LLM.MaxTokens,
		Enabled:   cfg.LLM.Enabled,
	})
	var llmClient *llm.Client
	if cfg.LLM.Enabled {
		llmClient = llm.NewClient(llmHolder)
	}

	// The ladder: rungs 1–4 deterministic + rung 5 LLM (queued) when configured.
	l := buildLadder(resolver, cfg, llmClient, log)

	// Metrics: in-memory counters, no query-derived labels (runtime.md).
	met := metrics.New("augeo")

	// WriteTimeout must cover the batch path: Batch.MaxDuration (D-034) allows
	// a batch to run up to 600s, but the default 20s WriteTimeout would cut any
	// multi-item batch mid-write (HTTP 000). Slowloris protection is preserved
	// because ReadHeaderTimeout/ReadTimeout stay short; WriteTimeout only bounds
	// how long a handler may hold the connection, which the rate limiter + quota
	// already bound for the batch path.
	writeTimeout := time.Duration(cfg.Server.WriteTimeout) * time.Second
	if bd := time.Duration(cfg.Batch.MaxDuration) * time.Second; bd > writeTimeout {
		writeTimeout = bd
	}

	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           newMux(l, store, limiter, anonLimiter, resolver, cfg, log, met, llmHolder, ctrlToken),
		ReadHeaderTimeout: time.Duration(cfg.Server.ReadTimeout) * time.Second,
		ReadTimeout:       time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	// Graceful shutdown.
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.ShutdownGrace)*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		close(done)
	}()

	log.Info("listening", "addr", cfg.Server.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server_failed", "error", err.Error())
		os.Exit(1)
	}
	<-done
	log.Info("shutdown")
}

// buildLadder constructs the parse ladder. Rungs 1–4 are deterministic; rung 5
// (LLM) is present only when an endpoint is configured (runtime.md: "the LLM
// only sees genuinely messy input"). provider is the LLM client — nil keeps the
// rung configured-but-not-wired (callers report 501).
func buildLadder(res contract.Resolver, cfg config.Config, provider *llm.Client, log *slog.Logger) *ladder.Ladder {
	rungs := []ladder.Rung{
		ladder.NewCoordRung(),
		ladder.NewAddressRung(res),
		ladder.NewPOIAnchorRung(res),
		ladder.NewPOIRung(res),
		ladder.NewReverseRung(res),
	}
	var llmRung *ladder.LLMRung
	if cfg.LLM.Enabled {
		// Bound the LLM queue with a semaphore at Queue.Depth so admission
		// control is real, not a no-op (adversarial review M2). When the queue
		// is at capacity, Admit returns false and the caller sees ErrQueueFull.
		// Release returns the slot after the request completes (both paths).
		admit := make(chan struct{}, cfg.Queue.Depth)
		llmRung = &ladder.LLMRung{
			Configured: true,
			Admit: func() bool {
				select {
				case admit <- struct{}{}:
					return true
				default:
					return false
				}
			},
			Release: func() { <-admit },
			Singleflight: &sync.Map{},
			Breaker:      ladder.NewBreaker(cfg.Queue.BreakerThreshold, time.Duration(cfg.Queue.BreakerCooldown)*time.Second),
		}
		if provider != nil {
			llmRung.Provider = provider
		}
	}
	return &ladder.Ladder{Rungs: rungs, LLM: llmRung}
}

// newMux builds the HTTP routes.
func newMux(l *ladder.Ladder, store *publicapi.Store, limiter *publicapi.RateLimiter, anonLimiter *publicapi.RateLimiter, resolver contract.Resolver, cfg config.Config, log *slog.Logger, met *metrics.Collector, llmHolder *llm.Holder, ctrlToken string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/search", handleSearch(l, store, limiter, anonLimiter, cfg, log, met))
	mux.HandleFunc("/geocode", handleGeocode(l, store, limiter, anonLimiter, cfg, log, met))
	mux.HandleFunc("/reverse", handleReverse(l, store, limiter, anonLimiter, cfg, log, met))
	mux.HandleFunc("/poi", handlePOI(l, store, limiter, anonLimiter, cfg, log, met))
	mux.HandleFunc("/parse", handleParse(l, store, limiter, anonLimiter, cfg, log, met))
	mux.HandleFunc("/batch", handleBatch(l, store, limiter, cfg, log))
	mux.HandleFunc("/suggest", handleSuggest(resolver, store, limiter, anonLimiter, cfg, log, met))
	mux.HandleFunc("/healthz", handleHealthz())
	mux.HandleFunc("/readyz", handleReadyz(resolver, cfg))
	mux.HandleFunc("/metrics", handleMetrics(met))
	mux.HandleFunc("/ctrl/llm", handleCtrlLLM(llmHolder, ctrlToken, log))

	return mux
}

// --- handlers ---

// handleSearch is the front door: it classifies free text and dispatches to the
// right rung (all rungs). This is /search.
func handleSearch(l *ladder.Ladder, store *publicapi.Store, limiter *publicapi.RateLimiter, anonLimiter *publicapi.RateLimiter, cfg config.Config, log *slog.Logger, met *metrics.Collector) http.HandlerFunc {
	return handleQuery(l, store, limiter, anonLimiter, cfg, log, met, "search", "/search")
}

// handleGeocode is /geocode: address text → G-NAF. Only the address rung (and
// coord) serve it — never POI.
func handleGeocode(l *ladder.Ladder, store *publicapi.Store, limiter *publicapi.RateLimiter, anonLimiter *publicapi.RateLimiter, cfg config.Config, log *slog.Logger, met *metrics.Collector) http.HandlerFunc {
	return handleQuery(l, store, limiter, anonLimiter, cfg, log, met, "geocode", "/geocode")
}

// handleReverse is /reverse: lat/lon → RTree nearest. Only the coord rung serves
// it; an address string is rejected.
func handleReverse(l *ladder.Ladder, store *publicapi.Store, limiter *publicapi.RateLimiter, anonLimiter *publicapi.RateLimiter, cfg config.Config, log *slog.Logger, met *metrics.Collector) http.HandlerFunc {
	return handleQuery(l, store, limiter, anonLimiter, cfg, log, met, "reverse", "/reverse")
}

// handlePOI is /poi: name (+ optional area) → OSM. Only POI rungs serve it.
func handlePOI(l *ladder.Ladder, store *publicapi.Store, limiter *publicapi.RateLimiter, anonLimiter *publicapi.RateLimiter, cfg config.Config, log *slog.Logger, met *metrics.Collector) http.HandlerFunc {
	return handleQuery(l, store, limiter, anonLimiter, cfg, log, met, "poi", "/poi")
}

// handleParse is /parse: conversational → LLM structured intent. Deterministic
// rungs never serve it; only the LLM rung participates.
func handleParse(l *ladder.Ladder, store *publicapi.Store, limiter *publicapi.RateLimiter, anonLimiter *publicapi.RateLimiter, cfg config.Config, log *slog.Logger, met *metrics.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// LLM layer must be enabled; /parse is LLM-only (rung 5). Without it the
		// endpoint is unavailable, not "input unparseable" — distinct signal.
		if !cfg.LLM.Enabled {
			writeJSONError(w, http.StatusServiceUnavailable, "llm not configured")
			met.Record("/parse", 503, 0, 0)
			return
		}
		h := handleQuery(l, store, limiter, anonLimiter, cfg, log, met, "parse", "/parse")
		h.ServeHTTP(w, r)
	}
}

// handleQuery is the shared request path. kind constrains which rungs run;
// endpoint is the canonical name for logging.
func handleQuery(l *ladder.Ladder, store *publicapi.Store, limiter *publicapi.RateLimiter, anonLimiter *publicapi.RateLimiter, cfg config.Config, log *slog.Logger, met *metrics.Collector, kind, endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Metrics: record endpoint/status/latency/result-count per request.
		start := time.Now()
		status := int64(200)
		var resultRows int64
		defer func() {
			met.Record(endpoint, status, time.Since(start).Milliseconds(), resultRows)
		}()
		if r.Method != http.MethodPost {
			status = 405
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		// D-032: query in the POST body, never a URL.
		body := readBody(w, r, cfg, log)
		if body == "" {
			// T1: empty body is a no-token query — reject, never serve 200.
			status = 400
			writeJSONError(w, http.StatusBadRequest, "empty query")
			return
		}
		// T5: MAX_QUERY_LEN enforced before normalisation.
		if len(body) > cfg.Limits.MaxQueryLen {
			status = 400
			writeJSONError(w, http.StatusBadRequest, "query too long")
			return
		}
		auth, anon, keyID, authErr := authenticate(r, store, limiter, anonLimiter, cfg, log)
		if authErr != nil {
			if errors.Is(authErr, publicapi.ErrInvalidKey) {
				status = 401
				writeJSONError(w, http.StatusUnauthorized, "invalid api key")
			} else {
				status = 429
				writeJSONError(w, http.StatusTooManyRequests, "rate limited")
			}
			return
		}
		// Scope enforcement: a key's scopes gate which endpoints it may use
		// (security.md: /batch requires the batch scope, never anonymous).
		if !anon && !hasScope(auth.Scopes, endpointScope(kind)) {
			status = 403
			writeJSONError(w, http.StatusForbidden, "key not permitted for this endpoint")
			return
		}

		// PR-8.1/8.2 — structured input. A caller who already holds parsed
		// fields sends them as components instead of a string, and the request
		// skips the ladder entirely: there is nothing to interpret.
		//
		// Only /geocode and /search accept components. /reverse is coordinates,
		// /poi is a name, /parse is explicitly the LLM path.
		if kind == "geocode" || kind == "search" {
			comps, hasQuery, perr := structuredRequest(body)
			if perr != nil {
				status = 400
				writeJSONError(w, http.StatusBadRequest, perr.Error())
				return
			}
			if comps != nil {
				// PR-8.1: both forms supplied is an error, never a merge. A
				// silent merge would pick one and discard the other, and the
				// caller would not know which.
				if hasQuery {
					status = 400
					writeJSONError(w, http.StatusBadRequest, "supply either query or components, not both")
					return
				}
				ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.Limits.RequestTimeout)*time.Second)
				defer cancel()
				res, err := l.ResolveStructured(ctx, *comps, cfg.Limits.MaxResults)
				if err != nil {
					status = int64(writeError(w, err))
					return
				}
				rows := int64(len(res.Response.Candidates))
				if !anon {
					ok, _ := store.ChargeRows(keyID, auth.Tier, rows)
					if !ok {
						status = 429
						writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
						return
					}
				} else {
					ip := clientIP(r, cfg.Server.TrustedProxy)
					ok, _ := store.ChargeAnonDaily(ip, rows, cfg.Rate.AnonDaily, cfg.AnonLLM.DailyGlobal)
					if !ok {
						status = 429
						writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
						return
					}
				}
				if touchesOSM(res.Response) {
					w.Header().Set("X-Augeo-Attribution", "© OpenStreetMap contributors, ODbL 1.0 — https://www.openstreetmap.org/copyright")
				}
				status = 200
				resultRows = rows
				store.LogRequest(keyID, endpoint, http.StatusOK, 0, len(res.Response.Candidates), res.Strategy)
				// Echo the contract version so the caller can verify which wire
				// format it got (UX review finding #3).
				w.Header().Set(contract.ContractVersionHeader, contract.Version)
				writeJSON(w, makeSearchResponse(res, cfg))
				return
			}
		}

		// Abuse guard T1: reject empty/wildcard queries. The request body is
		// JSON {"query": "..."} (or {"lat":..,"lon":..} for /reverse) — extract
		// the actual query text before normalising, never the raw JSON (the
		// normaliser would see "query" as a token and misclassify the rung).
		body = requestText(body, kind)
		q := ladder.Query{Raw: body, Normal: normalise.Normalise(body)}
		if len(q.Normal.Tokens) == 0 {
			status = 400
			writeJSONError(w, http.StatusBadRequest, "no tokens")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.Limits.RequestTimeout)*time.Second)
		defer cancel()
		// Kind-constrained walk: /geocode never returns poi, /reverse rejects an
		// address string, /poi never returns an address, /parse is LLM-only.
		var res ladder.Result
		var err error
		if kind == "search" {
			res, err = l.Walk(ctx, q)
		} else {
			res, err = l.WalkKind(ctx, q, kind)
		}
		if err != nil {
			status = int64(writeError(w, err))
			return
		}
		// D-034: charge quota per result row. Keyed rows go to the usage table;
		// anonymous rows go to the in-memory per-IP daily counter (D-026).
		rows := int64(len(res.Response.Candidates))
		if !anon {
			ok, _ := store.ChargeRows(keyID, auth.Tier, rows)
			if !ok {
				status = 429
				writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
				return
			}
		} else {
			ip := clientIP(r, cfg.Server.TrustedProxy)
			ok, _ := store.ChargeAnonDaily(ip, rows, cfg.Rate.AnonDaily, cfg.AnonLLM.DailyGlobal)
			if !ok {
				status = 429
				writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
				return
			}
		}
		// Attribution (D-018): OSM-touching responses carry the ODbL notice.
		if touchesOSM(res.Response) {
			w.Header().Set("X-Augeo-Attribution", "© OpenStreetMap contributors, ODbL 1.0 — https://www.openstreetmap.org/copyright")
		}
		// Success.
		status = 200
		resultRows = rows
		store.LogRequest(keyID, endpoint, http.StatusOK, 0, len(res.Response.Candidates), res.Strategy)
		// Echo the contract version so the caller can verify which wire
		// format it got (UX review finding #3).
		w.Header().Set(contract.ContractVersionHeader, contract.Version)
		writeJSON(w, makeSearchResponse(res, cfg))
	}
}

// batchItem is one item's result in a /batch response. Each carries its own
// status — one bad item does not fail the batch.
type batchItem struct {
	Index      int                  `json:"index"`
	Status     int                  `json:"status"`
	Strategy   string               `json:"strategy,omitempty"`
	Candidates []contract.Candidate `json:"candidates,omitempty"`
	Error      string               `json:"error,omitempty"`
}

// batchResp is the /batch response envelope.
type batchResp struct {
	Items []batchItem `json:"items"`
}

func handleBatch(l *ladder.Ladder, store *publicapi.Store, limiter *publicapi.RateLimiter, cfg config.Config, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /batch requires a key with the batch scope; never anonymous
		// (security.md: batch is scoped and keyed).
		keyStr := r.Header.Get("X-Api-Key")
		if keyStr == "" {
			writeJSONError(w, http.StatusForbidden, "batch requires a key")
			return
		}
		k, err := store.Authenticate(keyStr)
		if err != nil {
			log.Warn("auth_rejected", "reason", "invalid_key")
			writeJSONError(w, http.StatusUnauthorized, "invalid api key")
			return
		}
		if !hasScope(k.Scopes, "batch") {
			writeJSONError(w, http.StatusForbidden, "key not permitted for this endpoint")
			return
		}
		// Rate limit the keyed batch path.
		if !limiter.Allow("key:" + keyStr) {
			writeJSONError(w, http.StatusTooManyRequests, "rate limited")
			return
		}

		// D-032: batch body via readBody (same cap + empty-body rejection as the
		// single-query path). Never trust a raw JSON blob — parse to a struct.
		body := readBody(w, r, cfg, log)
		if body == "" {
			writeJSONError(w, http.StatusBadRequest, "empty body")
			return
		}
		var req struct {
			Items []struct {
				Query string  `json:"query"`
				Kind  string  `json:"kind"`   // geocode|reverse|poi|search (default search)
				Lat   float64 `json:"lat"`
				Lon   float64 `json:"lon"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request")
			return
		}
		// Cap the batch size (Batch.MaxRows). Reject over-cap — never silently
		// truncate (callers must know their request was refused, not partial).
		if len(req.Items) == 0 {
			writeJSONError(w, http.StatusBadRequest, "no items")
			return
		}
		if len(req.Items) > cfg.Batch.MaxRows {
			writeJSONError(w, http.StatusBadRequest, "batch too large")
			return
		}

		// Batch runtime is bounded by Batch.MaxDuration (D-034), NOT the
		// single-query RequestTimeout — a batch is allowed to run far longer
		// than one geocode. The write deadline already covers this.
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.Batch.MaxDuration)*time.Second)
		defer cancel()

		// Worker pool (Batch.Workers): process items in parallel. Sequential
		// processing would be unusable for large batches (each item is a ladder
		// walk). Results are written into a pre-sized slice by item index so
		// response order matches request order regardless of completion order.
		workers := cfg.Batch.Workers
		if workers < 1 {
			workers = 1
		}
		n := len(req.Items)
		resp := batchResp{Items: make([]batchItem, n)}
		var totalMu sync.Mutex
		var totalRows int64
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			i := i
			it := req.Items[i]
			wg.Add(1)
			sem <- struct{}{} // acquire a worker slot (bounded concurrency)
			go func() {
				defer wg.Done()
				defer func() { <-sem }() // release the slot
				bi := batchItem{Index: i}
				// Per-item query-length cap (same as the single path).
				it.Query = strings.TrimSpace(it.Query)
				if len(it.Query) > cfg.Limits.MaxQueryLen {
					bi.Status = 400
					bi.Error = "query too long"
					resp.Items[i] = bi
					return
				}
				kind := it.Kind
				if kind == "" {
					kind = "search"
				}
				q := ladder.Query{Raw: it.Query, Normal: normalise.Normalise(it.Query)}
				// Reverse items carry lat/lon, not a query string. The reverse rung
				// parses lat/lon from q.Raw (reverseCoord reads the raw JSON body),
				// so we hand it the same JSON form the /reverse endpoint sends.
				if kind == "reverse" {
					if it.Lat == 0 && it.Lon == 0 {
						bi.Status = 400
						bi.Error = "reverse needs lat/lon"
						resp.Items[i] = bi
						return
					}
					q.Raw = fmt.Sprintf(`{"lat":%v,"lon":%v}`, it.Lat, it.Lon)
				}
				var res ladder.Result
				var err error
				if kind == "search" {
					res, err = l.Walk(ctx, q)
				} else {
					res, err = l.WalkKind(ctx, q, kind)
				}
				if err != nil {
					bi.Status = 400
					bi.Error = err.Error()
					resp.Items[i] = bi
					return
				}
				bi.Status = 200
				bi.Strategy = res.Strategy
				bi.Candidates = res.Response.Candidates
				totalMu.Lock()
				totalRows += int64(len(res.Response.Candidates))
				totalMu.Unlock()
				resp.Items[i] = bi
			}()
		}
		wg.Wait()

		// Charge quota for the total result rows across all items (D-034). If the
		// keyed quota is exhausted, refuse the whole batch — the caller retries.
		if !k.Enabled {
			writeJSONError(w, http.StatusForbidden, "key disabled")
			return
		}
		if ok, _ := store.ChargeRows(k.ID, k.Tier, totalRows); !ok {
			writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
			return
		}
		store.LogRequest(k.ID, "/batch", http.StatusOK, 0, int(totalRows), "batch")

		// Attribution (D-018): OSM-touching responses carry the ODbL notice.
		if touchesOSMItems(resp) {
			w.Header().Set("X-Augeo-Attribution", "© OpenStreetMap contributors, ODbL 1.0 — https://www.openstreetmap.org/copyright")
		}
		writeJSON(w, resp)
	}
}

// touchesOSMItems reports whether any item's candidates touch OSM (D-018).
func touchesOSMItems(resp batchResp) bool {
	for _, it := range resp.Items {
		for _, c := range it.Candidates {
			if c.Source == "osm" {
				return true
			}
		}
	}
	return false
}

// handleSuggest is /suggest: keystroke prefix → street+locality suggestions.
// It is NOT a rung walk — autocomplete is a genuinely different problem (PR-7).
// It calls the resolver's Suggest directly. The prefix is never logged and
// never a metric label (PR-7.5 / INV-1): only the suggestion count is recorded.
func handleSuggest(resolver contract.Resolver, store *publicapi.Store, limiter *publicapi.RateLimiter, anonLimiter *publicapi.RateLimiter, cfg config.Config, log *slog.Logger, met *metrics.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		status := int64(200)
		var resultRows int64
		defer func() {
			met.Record("/suggest", status, time.Since(start).Milliseconds(), resultRows)
		}()
		if r.Method != http.MethodPost {
			status = 405
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		body := readBody(w, r, cfg, log)
		if body == "" {
			status = 400
			writeJSONError(w, http.StatusBadRequest, "empty query")
			return
		}
		if len(body) > cfg.Limits.MaxQueryLen {
			status = 400
			writeJSONError(w, http.StatusBadRequest, "query too long")
			return
		}
		auth, anon, keyID, authErr := authenticate(r, store, limiter, anonLimiter, cfg, log)
		if authErr != nil {
			if errors.Is(authErr, publicapi.ErrInvalidKey) {
				status = 401
				writeJSONError(w, http.StatusUnauthorized, "invalid api key")
			} else {
				status = 429
				writeJSONError(w, http.StatusTooManyRequests, "rate limited")
			}
			return
		}
		if !anon && !hasScope(auth.Scopes, "search") {
			status = 403
			writeJSONError(w, http.StatusForbidden, "key not permitted for this endpoint")
			return
		}
		// Decode the prefix. Suggest is keystroke-driven — the prefix is short.
		var req struct {
			Prefix string `json:"prefix"`
			Limit  int    `json:"limit,omitempty"`
		}
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			status = 400
			writeJSONError(w, http.StatusBadRequest, "bad request")
			return
		}
		req.Prefix = strings.TrimSpace(req.Prefix)
		if req.Prefix == "" {
			status = 400
			writeJSONError(w, http.StatusBadRequest, "empty prefix")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.Limits.RequestTimeout)*time.Second)
		defer cancel()
		// Wire the caller's Limit through to the upstream so it isn't silently
		// capped at 10 (UX review finding #7: SuggestRequest.Limit was dead code).
		sres, err := resolver.Suggest(ctx, contract.SuggestRequest{Prefix: req.Prefix, Limit: req.Limit})
		if err != nil {
			status = 502
			writeJSONError(w, http.StatusBadGateway, "suggest upstream unavailable")
			return
		}
		rows := int64(len(sres.Suggestions))
		// D-034: charge quota per suggestion row. Session semantics (PR-7.4)
		// are a caller concern — the meter still counts rows; a session-aware
		// billing shim (S-14) sits in front of this endpoint.
		if !anon {
			ok, _ := store.ChargeRows(keyID, auth.Tier, rows)
			if !ok {
				status = 429
				writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
				return
			}
		} else {
			ip := clientIP(r, cfg.Server.TrustedProxy)
			ok, _ := store.ChargeAnonDaily(ip, rows, cfg.Rate.AnonDaily, cfg.AnonLLM.DailyGlobal)
			if !ok {
				status = 429
				writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
				return
			}
		}
		status = 200
		resultRows = rows
		store.LogRequest(keyID, "/suggest", http.StatusOK, 0, int(rows), "suggest")
		// Echo the contract version so the caller can verify which wire
		// format it got (UX review finding #3).
		w.Header().Set(contract.ContractVersionHeader, contract.Version)
		writeJSON(w, sres)
	}
}

// metrics moved to ausystem/shared/metrics (see shared/metrics).
// endpointScope maps an endpoint kind to the scope a key needs to call it.
// /search and /geocode use the "search" scope; /poi, /reverse, /parse too;
// /batch requires "batch". Unknown kinds default to "search".
func endpointScope(kind string) string {
	if kind == "batch" {
		return "batch"
	}
	return "search"
}

// hasScope reports whether scopes contains s (case-insensitive). An empty
// scope set is treated as "search" — a key issued with no scopes can search
// (the historical default), and only an explicit non-search scope restricts it.
func hasScope(scopes []string, s string) bool {
	if len(scopes) == 0 {
		return s == "search"
	}
	for _, sc := range scopes {
		if strings.EqualFold(sc, s) {
			return true
		}
	}
	return false
}

// clientIP returns the client IP for anonymous rate limiting. It trusts
// X-Forwarded-For only when the direct peer is a configured trusted proxy
// (security.md assigns connection-flood control to the reverse proxy; blindly
// trusting XFF lets any client spoof a fresh IP and bypass the per-IP limiter).
// Otherwise it uses the peer address, stripping the port from IPv4 and IPv6.
func clientIP(r *http.Request, trustedProxy string) string {
	if trustedProxy != "" {
		if peerIP(r) == trustedProxy {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// Use the first (client) address in the chain.
				if i := strings.Index(xff, ","); i >= 0 {
					xff = xff[:i]
				}
				xff = strings.TrimSpace(xff)
				if h, _, err := net.SplitHostPort(xff); err == nil {
					return h
				}
				return xff
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port (rare); return as-is.
		return r.RemoteAddr
	}
	return host
}

// peerIP returns the immediate peer address (no port), for proxy comparison.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// requestText extracts the query string from a request body. For /geocode and
// /poi the body is {"query": "..."}; for /reverse it's {"lat":..,"lon":..}.
// The normaliser must see the query text, not JSON keys — "query" as a token
// would misclassify the rung (e.g. an address "query high st" → no street).
// structuredRequest extracts caller-supplied address components from the body.
//
// It returns nil components when the caller sent free text, so the normal
// ladder path runs unchanged. hasQuery reports whether a query/q field was
// also present, which is what makes "both forms supplied" detectable rather
// than silently resolved one way.
func structuredRequest(body string) (comps *contract.AddressComponents, hasQuery bool, err error) {
	var obj struct {
		Query      string                     `json:"query"`
		Q          string                     `json:"q"`
		Components *contract.AddressComponents `json:"components"`
		// Components may also be supplied flat at the top level, which is what
		// a caller mapping their own record shape will reach for first.
		StreetNumber string `json:"street_number"`
		StreetName   string `json:"street_name"`
		StreetType   string `json:"street_type"`
		Locality     string `json:"locality"`
		State        string `json:"state"`
		Postcode     string `json:"postcode"`
	}
	if e := json.Unmarshal([]byte(body), &obj); e != nil {
		// Not JSON at all — treat as free text, as the existing path does.
		return nil, false, nil
	}
	hasQuery = obj.Query != "" || obj.Q != ""

	if obj.Components != nil && !obj.Components.Empty() {
		flat := contract.AddressComponents{
			StreetNumber: obj.StreetNumber, StreetName: obj.StreetName,
			StreetType: obj.StreetType, Locality: obj.Locality,
			State: obj.State, Postcode: obj.Postcode,
		}
		if !flat.Empty() {
			return nil, hasQuery, errors.New("supply components either nested or flat, not both")
		}
		return obj.Components, hasQuery, nil
	}
	flat := contract.AddressComponents{
		StreetNumber: obj.StreetNumber, StreetName: obj.StreetName,
		StreetType: obj.StreetType, Locality: obj.Locality,
		State: obj.State, Postcode: obj.Postcode,
	}
	if !flat.Empty() {
		return &flat, hasQuery, nil
	}
	return nil, hasQuery, nil
}

func requestText(body, kind string) string {
	body = strings.TrimSpace(body)
	// /reverse keeps the JSON — the reverse rung parses lat/lon from it.
	if kind == "reverse" {
		return body
	}
	var obj struct {
		Query string `json:"query"`
		Q     string `json:"q"`
	}
	if err := json.Unmarshal([]byte(body), &obj); err == nil {
		if obj.Query != "" {
			return obj.Query
		}
		if obj.Q != "" {
			return obj.Q
		}
	}
	return body
}

// readBody reads the request body, enforcing the max-body limit (T5) and
// rejecting an empty body (T1). It returns the raw bytes as a string.
func readBody(w http.ResponseWriter, r *http.Request, cfg config.Config, log *slog.Logger) string {
	r.Body = http.MaxBytesReader(w, r.Body, int64(cfg.Limits.MaxBodyBytes))
	var sb strings.Builder
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			if err != io.EOF && err != http.ErrBodyReadAfterClose {
				// Log the read failure (INV-1: event + k/v only, never query text).
				// The request is still rejected as empty/partial — but a read
				// error is distinct from a genuinely empty body.
				log.Warn("body_read_error", "error", err.Error())
			}
			break
		}
	}
	return strings.TrimSpace(sb.String())
}

func authenticate(r *http.Request, store *publicapi.Store, limiter *publicapi.RateLimiter, anonLimiter *publicapi.RateLimiter, cfg config.Config, log *slog.Logger) (publicapi.Key, bool, int64, error) {
	keyStr := r.Header.Get("X-Api-Key")
	if keyStr == "" {
		// Anonymous is limited per-IP, not per-connection. RemoteAddr carries
		// host:port; keying on the port gives a fresh bucket per connection,
		// which a client can exploit by simply reconnecting. Strip to the IP.
		ip := clientIP(r, cfg.Server.TrustedProxy)
		if !anonLimiter.Allow("anon:" + ip) {
			return publicapi.Key{}, true, 0, publicapi.ErrRateLimited
		}
		return publicapi.Key{}, true, 0, nil
	}
	k, err := store.Authenticate(keyStr)
	if err != nil {
		// Uniform 401 for unknown/revoked/disabled (T6) — never fall through to
		// anonymous. An invalid key must be rejected, not silently served.
		log.Warn("auth_rejected", "reason", "invalid_key")
		return publicapi.Key{}, false, 0, publicapi.ErrInvalidKey
	}
	if !limiter.Allow("key:" + keyStr) {
		return k, false, k.ID, publicapi.ErrRateLimited
	}
	return k, false, k.ID, nil
}

// writeJSONError writes a JSON error body with the application/json content
// type. http.Error forces text/plain even when the body is a JSON object, so
// the geocoder's error paths must use this helper instead — clients parsing
// JSON errors would break on text/plain (UX review finding #4).
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = jsonEncode(w, struct {
		Error string `json:"error"`
	}{Error: msg})
}

// writeError writes the error body and returns the HTTP status it wrote, so
// the caller can record an accurate metric (the Prometheus status must match
// what the client actually saw — UX review finding #5).
func writeError(w http.ResponseWriter, err error) int {
	switch {
	case errors.Is(err, contract.ErrOutOfScope):
		writeJSONError(w, http.StatusBadRequest, "out of scope")
		return http.StatusBadRequest
	case errors.Is(err, contract.ErrNoCandidates):
		writeJSONError(w, http.StatusNotFound, "no candidates")
		return http.StatusNotFound
	case errors.Is(err, ladder.ErrNoRung):
		// No rung applies to this input for the requested endpoint kind — a
		// client error, not a server failure (e.g. an address string sent to
		// /reverse). 400.
		writeJSONError(w, http.StatusBadRequest, "no parse rung applies")
		return http.StatusBadRequest
	case errors.Is(err, ladder.ErrQueueFull):
		writeJSONError(w, http.StatusTooManyRequests, "queue full")
		return http.StatusTooManyRequests
	case errors.Is(err, ladder.ErrLLMNotImplemented):
		// The LLM rung is configured but not wired — a server-side gap, not a
		// client error. Distinct 501 so callers know the endpoint is absent,
		// not that their input was unparseable.
		writeJSONError(w, http.StatusNotImplemented, "llm not implemented")
		return http.StatusNotImplemented
	case errors.Is(err, contract.ErrNotLoaded):
		writeJSONError(w, http.StatusServiceUnavailable, "not loaded")
		return http.StatusServiceUnavailable
	default:
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = jsonEncode(w, v)
}

func jsonEncode(w http.ResponseWriter, v any) error {
	return json.NewEncoder(w).Encode(v)
}

// searchResponse is the /search result: candidates + strategy + attribution
// + truncation visibility. The truncation/total/generated fields come from the
// resolve contract (INV-6) so a caller can tell whether results were cut off —
// previously the geocoder dropped them, hiding truncation (UX review finding #6).
type searchResponse struct {
	Candidates     []contract.Candidate `json:"candidates"`
	Strategy       string               `json:"strategy"`
	Attribution    string               `json:"attribution,omitempty"`
	Truncated      bool                 `json:"truncated"`
	Total          int                  `json:"total"`
	Generated      int                  `json:"generated"`
	DatasetVersion string               `json:"dataset_version,omitempty"`
}

func makeSearchResponse(res ladder.Result, cfg config.Config) searchResponse {
	attr := ""
	if touchesOSM(res.Response) {
		attr = "© OpenStreetMap contributors, ODbL 1.0 — https://www.openstreetmap.org/copyright"
	}
	return searchResponse{
		Candidates:     res.Response.Candidates,
		Strategy:       res.Strategy,
		Attribution:    attr,
		Truncated:      res.Response.Truncated,
		Total:          res.Response.TotalMatched,
		Generated:      res.Response.GeneratedCount,
		DatasetVersion: res.Response.DatasetVersion,
	}
}

func touchesOSM(r contract.ResolveResponse) bool {
	for _, c := range r.Candidates {
		if c.Source == "osm" {
			return true
		}
	}
	return false
}

func handleHealthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

func handleReadyz(resolver contract.Resolver, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Probe the upstream resolver (split mode). In single-binary mode the
		// resolver is in-process and always available.
		status := "ready"
		dataset := ""
		if resolver != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			ready, ds, err := resolver.Ready(ctx)
			if err != nil || !ready {
				status = "not_ready"
				if err != nil {
					status = "not_ready:" + err.Error()
				}
			}
			dataset = ds
		}
		states := strings.Join(cfg.Data.States, ",")
		w.Header().Set("Content-Type", "application/json")
		_ = jsonEncode(w, map[string]any{
			"status":         status,
			"states":         states,
			"dataset":        dataset,
			"llm_configured": cfg.LLM.Enabled,
			"query_leak":     cfg.LLM.Enabled && cfg.LLM.BaseURL != "",
		})
	}
}

// handleCtrlLLM is the operator LLM-config interface (control plane). GET reads
// the current runtime LLM config (API key redacted); POST updates it (base URL,
// model, key, timeout, max tokens, enabled) and applies immediately — no
// restart. Gated by AUGEO_CTRL_TOKEN (constant-time compare); empty token =>
// endpoint disabled entirely (fail closed). This is config-only: data reloads
// stay cold (runtime.md), but LLM config is a control-plane concern.
func handleCtrlLLM(h *llm.Holder, ctrlToken string, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		// Token gate. Empty token => endpoint disabled entirely (fail closed).
		if ctrlToken == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Augeo-Ctrl-Token")), []byte(ctrlToken)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}

		if r.Method == http.MethodGet {
			cfg := h.Get()
			// Never echo the API key back.
			key := cfg.APIKey
			if key != "" {
				key = "REDACTED"
			}
			writeJSON(w, map[string]any{
				"base_url":   cfg.BaseURL,
				"model":      cfg.Model,
				"timeout":    cfg.Timeout,
				"max_tokens": cfg.MaxTokens,
				"enabled":    cfg.Enabled,
				"api_key":    key,
			})
			return
		}

		// POST: update the LLM config. The body may carry any subset; absent
		// fields keep their current value.
		var upd struct {
			BaseURL   *string `json:"base_url"`
			Model     *string `json:"model"`
			APIKey    *string `json:"api_key"`
			Timeout   *int    `json:"timeout"`
			MaxTokens *int    `json:"max_tokens"`
			Enabled   *bool   `json:"enabled"`
		}
		// Bound the control body the same way readBody bounds query bodies.
		// The control API mutates the running config — an unbounded decode is
		// a memory-exhaustion and config-corruption vector (adversarial review C1).
		// The control endpoint is operator-only, so a fixed cap suffices.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&upd); err != nil {
			writeJSONError(w, http.StatusBadRequest, `{"error":"bad request"}`)
			return
		}
		cur := h.Get()
		if upd.BaseURL != nil {
			cur.BaseURL = *upd.BaseURL
		}
		if upd.Model != nil {
			cur.Model = *upd.Model
		}
		if upd.APIKey != nil {
			cur.APIKey = *upd.APIKey
		}
		if upd.Timeout != nil {
			cur.Timeout = *upd.Timeout
		}
		if upd.MaxTokens != nil {
			cur.MaxTokens = *upd.MaxTokens
		}
		if upd.Enabled != nil {
			cur.Enabled = *upd.Enabled
		}
		h.Set(cur)
		log.Info("llm_config_updated", "base_url", cur.BaseURL, "model", cur.Model, "enabled", cur.Enabled)
		writeJSON(w, map[string]any{"updated": true, "base_url": cur.BaseURL, "model": cur.Model, "enabled": cur.Enabled})
	}
}

func handleMetrics(met *metrics.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		met.Render(w)
	}
}

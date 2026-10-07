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
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"augeocoding/internal/apiauth"
	"augeocoding/internal/appdb"
	"augeocoding/internal/config"
	"augeocoding/internal/console"
	"augeocoding/internal/identity"
	"augeocoding/internal/ladder"
	"augeocoding/internal/llm"
	"augeocoding/internal/mail"
	"augeocoding/internal/oidcrp"
	"augeocoding/internal/outbox"
	"augeocoding/internal/placesclient"
	"augeocoding/internal/publicapi"
	"augeocoding/internal/safehttp"
	"augeocoding/internal/scim"
	"augeocoding/internal/secretbox"
	"ausystem/shared/contract"
	"ausystem/shared/metrics"
	"ausystem/shared/normalise"
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
	// Read from AUGEO_CTRL_TOKEN or AUGEO_CTRL_TOKEN_FILE by config.Load.
	ctrlToken := cfg.CtrlToken

	// Split-mode resolver. In single-binary mode this would be an in-process
	// call; here we call the au-places HTTP API.
	var resolver contract.Resolver
	if cfg.PlacesURL != "" {
		resolver = placesclient.New(cfg.PlacesURL)
	} else {
		log.Error("boot_failed", "reason", "no resolver configured (set AUGEO_PLACES_URL)")
		os.Exit(1)
	}

	// app.db — service state, separate from the geocoding DBs. One handle is
	// shared by the key/quota store and the identity store.
	db, err := appdb.Open(cfg.Data.AppDB)
	if err != nil {
		log.Error("boot_failed", "reason", "app_db", "error", err.Error())
		os.Exit(1)
	}
	defer db.Close()
	store, err := publicapi.New(db)
	if err != nil {
		log.Error("boot_failed", "reason", "app_db", "error", err.Error())
		os.Exit(1)
	}
	var box *secretbox.Box
	if cfg.Auth.ConsoleEnabled() {
		key, err := secretbox.ParseKey(cfg.Auth.SecretKey)
		if err == nil {
			box, err = secretbox.New(key)
		}
		if err != nil {
			log.Error("boot_failed", "reason", "secret_key", "error", err.Error())
			os.Exit(1)
		}
	}
	ids, err := identity.New(db, box)
	if err != nil {
		log.Error("boot_failed", "reason", "identity_db", "error", err.Error())
		os.Exit(1)
	}
	// Admin-controlled URLs (discovery, JWKS, SAML metadata) are fetched
	// through a client that refuses private addresses (SSRF).
	fetch := safehttp.Client(10*time.Second, cfg.Auth.AllowPrivateFetch)

	// Rate limiters: per-key (D-006) and per-IP anonymous (D-034). Anonymous
	// has its own budget — AnonRPS/AnonBurst — NOT the keyed one.
	limiter := publicapi.NewRateLimiter(cfg.Rate.KeyDefaultRPS, cfg.Rate.KeyDefaultBurst)
	anonLimiter := publicapi.NewRateLimiter(cfg.Rate.AnonRPS, cfg.Rate.AnonBurst)
	// Bearer tokens are throttled per client IP before verification, at the
	// keyed rate: a legitimate caller is still bounded by its per-principal
	// bucket, while a forged-token flood from one address stops here.
	bearerIPLimiter := publicapi.NewRateLimiter(cfg.Rate.KeyDefaultRPS, cfg.Rate.KeyDefaultBurst)
	authn := &apiauth.Authenticator{
		Keys: store, KeyLimiter: limiter, AnonLimiter: anonLimiter, BearerIPLimiter: bearerIPLimiter, HTTPClient: fetch,
		ClientIP: func(r *http.Request) string { return clientIP(r, cfg.Server.TrustedProxies) },
		Reject:   func(reason string) { log.Warn("auth_rejected", "reason", reason) },
	}
	if cfg.Auth.JWTBearer {
		authn.Issuers = ids
	}

	// Console, SSO and SCIM (docs/auth.md). Off unless AUGEO_PUBLIC_URL and
	// AUGEO_SECRET_KEY are set.
	var con *console.Server
	// Background work (the mail outbox) stops when bgCtx ends at shutdown.
	bgCtx, bgStop := context.WithCancel(context.Background())
	defer bgStop()
	var bgDone []chan struct{}
	if cfg.Auth.ConsoleEnabled() {
		if cfg.Auth.ProvidersFile != "" {
			warnings, err := console.LoadProviders(context.Background(), ids, cfg.Auth.ProvidersFile)
			if err != nil {
				log.Error("boot_failed", "reason", "providers_file", "error", err.Error())
				os.Exit(1)
			}
			for _, w := range warnings {
				log.Warn("providers_file", "warning", w)
			}
		}
		rp := &oidcrp.RP{CallbackURL: cfg.Auth.PublicURL + "/auth/oidc/callback", HTTP: fetch}
		con, err = console.New(console.Config{
			PublicURL: cfg.Auth.PublicURL,
			Session:   identity.SessionPolicy{Idle: time.Duration(cfg.Auth.SessionIdle) * time.Second, Max: time.Duration(cfg.Auth.SessionMax) * time.Second},
			Login:     identity.LoginPolicy{SignupOpen: cfg.Auth.Signup == "open", BootstrapAdmins: cfg.Auth.BootstrapAdmins},
		}, ids, store, rp, log, fetch)
		if err != nil {
			log.Error("boot_failed", "reason", "console", "error", err.Error())
			os.Exit(1)
		}
		con.ClientIP = func(r *http.Request) string { return clientIP(r, cfg.Server.TrustedProxies) }
		if cfg.Auth.RateRPS > 0 {
			con.AuthLimiter = publicapi.NewRateLimiter(cfg.Auth.RateRPS, cfg.Auth.RateBurst)
		}
		if cfg.SMTP.Host != "" {
			sender, err := mail.NewSMTP(mail.Config{Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, Username: cfg.SMTP.Username, Password: cfg.SMTP.Password,
				From: cfg.SMTP.From, TLS: cfg.SMTP.TLS})
			if err != nil {
				log.Error("boot_failed", "reason", "smtp", "error", err.Error())
				os.Exit(1)
			}
			worker := outbox.New(ids, sender, log)
			con.MailOn, con.MailWake = true, worker.Wake
			done := make(chan struct{})
			bgDone = append(bgDone, done)
			go func() { defer close(done); worker.Run(bgCtx) }()
		}
		log.Info("console_enabled", "public_url", cfg.Auth.PublicURL, "signup", cfg.Auth.Signup, "invite_email", cfg.SMTP.Host != "",
			"smtp_tls", cfg.SMTP.TLS, "auth_rate_rps", cfg.Auth.RateRPS)
	}

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
		Handler:           newMux(l, store, authn, resolver, cfg, log, met, llmHolder, ctrlToken, con, ids),
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
		// Stop background workers; a send in flight is abandoned and left
		// pending for the next start.
		bgStop()
		for _, d := range bgDone {
			select {
			case <-d:
			case <-ctx.Done():
			}
		}
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
			Release:      func() { <-admit },
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
func newMux(l *ladder.Ladder, store *publicapi.Store, authn *apiauth.Authenticator, resolver contract.Resolver, cfg config.Config, log *slog.Logger, met *metrics.Collector, llmHolder *llm.Holder, ctrlToken string, con *console.Server, ids *identity.Store) http.Handler {
	mux := http.NewServeMux()
	if con != nil {
		con.Register(mux)
		mux.Handle("/scim/v2/", &scim.Server{IDs: ids, Log: log, BaseURL: cfg.Auth.PublicURL + "/scim/v2"})
	}

	lim := &apiLimits{}
	mux.HandleFunc("/search", handleQuery(l, store, authn, cfg, log, met, lim, "search", "/search"))
	mux.HandleFunc("/geocode", handleQuery(l, store, authn, cfg, log, met, lim, "geocode", "/geocode"))
	mux.HandleFunc("/reverse", handleQuery(l, store, authn, cfg, log, met, lim, "reverse", "/reverse"))
	mux.HandleFunc("/poi", handleQuery(l, store, authn, cfg, log, met, lim, "poi", "/poi"))
	mux.HandleFunc("/parse", handleParse(l, store, authn, cfg, log, met, lim))
	mux.HandleFunc("/batch", handleBatch(l, store, authn, cfg, log, lim))
	mux.HandleFunc("/suggest", handleSuggest(resolver, store, authn, cfg, log, met))
	mux.HandleFunc("/healthz", handleHealthz())
	mux.HandleFunc("/readyz", handleReadyz(resolver, cfg, log))
	mux.HandleFunc("/metrics", handleMetrics(met))
	mux.HandleFunc("/ctrl/llm", handleCtrlLLM(llmHolder, ctrlToken, log))

	return mux
}

// --- handlers ---

// handleParse is /parse: conversational → LLM structured intent. Deterministic
// rungs never serve it; only the LLM rung participates.
func handleParse(l *ladder.Ladder, store *publicapi.Store, authn *apiauth.Authenticator, cfg config.Config, log *slog.Logger, met *metrics.Collector, lim *apiLimits) http.HandlerFunc {
	h := handleQuery(l, store, authn, cfg, log, met, lim, "parse", "/parse")
	return func(w http.ResponseWriter, r *http.Request) {
		// LLM layer must be enabled; /parse is LLM-only (rung 5). Without it the
		// endpoint is unavailable, not "input unparseable" — distinct signal.
		if !cfg.LLM.Enabled {
			writeJSONError(w, http.StatusServiceUnavailable, "llm not configured")
			met.Record("/parse", 503, 0, 0)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// handleQuery is the shared request path for /search, /geocode, /reverse,
// /poi and /parse. kind constrains which rungs run; endpoint is the
// canonical name for logging.
func handleQuery(l *ladder.Ladder, store *publicapi.Store, authn *apiauth.Authenticator, cfg config.Config, log *slog.Logger, met *metrics.Collector, lim *apiLimits, kind, endpoint string) http.HandlerFunc {
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
		p, authErr := authn.Authenticate(r)
		if authErr != nil {
			status = int64(writeAuthError(w, authErr))
			return
		}
		anon := p.Anonymous()
		// Scope enforcement: a key's scopes gate which endpoints it may use
		// (security.md: /batch requires the batch scope, never anonymous).
		if !anon && !hasScope(p.Scopes, endpointScope(kind)) {
			status = 403
			writeJSONError(w, http.StatusForbidden, "key not permitted for this endpoint")
			return
		}
		ip := clientIP(r, cfg.Server.TrustedProxies)
		// Pre-flight: a caller already at its daily ceiling is refused before
		// any resolver or LLM work.
		if ok, err := preflight(p, ip, store, cfg); err != nil || !ok {
			if err != nil {
				status = int64(writeError(w, log, endpoint, err))
				return
			}
			status = 429
			writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
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
					status = int64(writeError(w, log, endpoint, err))
					return
				}
				rows := int64(len(res.Response.Candidates))
				if !chargeRows(p, ip, rows, store, cfg) {
					status = 429
					writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
					return
				}
				if touchesOSM(res.Response) {
					w.Header().Set("X-Augeo-Attribution", "© OpenStreetMap contributors, ODbL 1.0 — https://www.openstreetmap.org/copyright")
				}
				status = 200
				resultRows = rows
				store.LogPrincipalRequest(p, endpoint, http.StatusOK, 0, len(res.Response.Candidates), res.Strategy)
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
		// Rung 5 spend control: per-caller in-flight cap and daily LLM-call
		// cap, applied only if the walk reaches the LLM.
		ctx = ladder.WithLLMGate(ctx, lim.llmGate(p, ip, store, cfg))
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
			status = int64(writeError(w, log, endpoint, err))
			return
		}
		// D-034: charge quota per result row; an LLM answer costs at least one.
		rows := billableRows(res)
		if !chargeRows(p, ip, rows, store, cfg) {
			status = 429
			writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
			return
		}
		// Attribution (D-018): OSM-touching responses carry the ODbL notice.
		if touchesOSM(res.Response) {
			w.Header().Set("X-Augeo-Attribution", "© OpenStreetMap contributors, ODbL 1.0 — https://www.openstreetmap.org/copyright")
		}
		// Success.
		status = 200
		resultRows = rows
		store.LogPrincipalRequest(p, endpoint, http.StatusOK, 0, len(res.Response.Candidates), res.Strategy)
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

func handleBatch(l *ladder.Ladder, store *publicapi.Store, authn *apiauth.Authenticator, cfg config.Config, log *slog.Logger, lim *apiLimits) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /batch requires a key or bearer token with the batch scope; never
		// anonymous (security.md: batch is scoped and keyed).
		if r.Header.Get("X-Api-Key") == "" && r.Header.Get("Authorization") == "" {
			writeJSONError(w, http.StatusForbidden, "batch requires a key")
			return
		}
		p, err := authn.Authenticate(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}
		if !hasScope(p.Scopes, "batch") {
			writeJSONError(w, http.StatusForbidden, "key not permitted for this endpoint")
			return
		}
		// The scope alone is not enough: a key minted under the batch tier
		// must stop working for /batch once its org leaves that tier.
		if p.Tier != publicapi.TierBatch {
			writeJSONError(w, http.StatusForbidden, "batch requires the batch tier")
			return
		}
		// Batch.MaxConcurrentPerKey: one caller cannot run many batches at once.
		if !lim.batch.acquire(p.RateKey, cfg.Batch.MaxConcurrentPerKey) {
			writeJSONError(w, http.StatusTooManyRequests, "too many concurrent batches")
			return
		}
		defer lim.batch.release(p.RateKey)

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
				Kind  string  `json:"kind"` // geocode|reverse|poi|search (default search)
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
		// Pre-flight quota: every item can cost at least one row, so a batch
		// larger than what is left today is refused before any work.
		left, err := store.QuotaRemaining(p)
		if err != nil {
			writeError(w, log, "/batch", err)
			return
		}
		if int64(len(req.Items)) > left {
			writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
			return
		}

		// Batch runtime is bounded by Batch.MaxDuration (D-034), NOT the
		// single-query RequestTimeout — a batch is allowed to run far longer
		// than one geocode. The write deadline already covers this.
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.Batch.MaxDuration)*time.Second)
		defer cancel()
		ctx = ladder.WithLLMGate(ctx, lim.llmGate(p, clientIP(r, cfg.Server.TrustedProxies), store, cfg))

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
		errReasons := map[string]int{}
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
					// Fixed messages only: raw errors can carry upstream detail.
					st, msg, reason := errorResponse(err)
					bi.Status, bi.Error = st, msg
					resp.Items[i] = bi
					if st >= 500 {
						totalMu.Lock()
						errReasons[reason]++
						totalMu.Unlock()
					}
					return
				}
				bi.Status = 200
				bi.Strategy = res.Strategy
				bi.Candidates = res.Response.Candidates
				totalMu.Lock()
				totalRows += billableRows(res)
				totalMu.Unlock()
				resp.Items[i] = bi
			}()
		}
		wg.Wait()
		for reason, count := range errReasons {
			log.Warn("batch_item_errors", "reason", reason, "count", count)
		}

		// Charge quota for the total result rows across all items (D-034). If the
		// keyed quota is exhausted, refuse the whole batch — the caller retries.
		if ok, _ := store.ChargePrincipal(p, totalRows); !ok {
			writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
			return
		}
		store.LogPrincipalRequest(p, "/batch", http.StatusOK, 0, int(totalRows), "batch")

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
func handleSuggest(resolver contract.Resolver, store *publicapi.Store, authn *apiauth.Authenticator, cfg config.Config, log *slog.Logger, met *metrics.Collector) http.HandlerFunc {
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
		p, authErr := authn.Authenticate(r)
		if authErr != nil {
			status = int64(writeAuthError(w, authErr))
			return
		}
		anon := p.Anonymous()
		if !anon && !hasScope(p.Scopes, "search") {
			status = 403
			writeJSONError(w, http.StatusForbidden, "key not permitted for this endpoint")
			return
		}
		ip := clientIP(r, cfg.Server.TrustedProxies)
		if ok, err := preflight(p, ip, store, cfg); err != nil || !ok {
			if err != nil {
				status = int64(writeError(w, log, "/suggest", err))
				return
			}
			status = 429
			writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
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
		if !chargeRows(p, ip, rows, store, cfg) {
			status = 429
			writeJSONError(w, http.StatusTooManyRequests, "quota exceeded")
			return
		}
		status = 200
		resultRows = rows
		store.LogPrincipalRequest(p, "/suggest", http.StatusOK, 0, int(rows), "suggest")
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
		Query      string                      `json:"query"`
		Q          string                      `json:"q"`
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

// writeAuthError maps an authentication failure to its response and returns
// the status. Every credential failure is the same 401 (T6).
func writeAuthError(w http.ResponseWriter, err error) int {
	switch {
	case errors.Is(err, apiauth.ErrBothCredentials):
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return http.StatusBadRequest
	case errors.Is(err, publicapi.ErrRateLimited):
		writeJSONError(w, http.StatusTooManyRequests, "rate limited")
		return http.StatusTooManyRequests
	default:
		writeJSONError(w, http.StatusUnauthorized, "invalid api key")
		return http.StatusUnauthorized
	}
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
// what the client actually saw — UX review finding #5). The body is always a
// fixed message (errorResponse); server-side failures are logged as a reason
// code and error type, never the error text.
func writeError(w http.ResponseWriter, log *slog.Logger, endpoint string, err error) int {
	status, msg, reason := errorResponse(err)
	logRequestError(log, endpoint, status, reason, err)
	writeJSONError(w, status, msg)
	return status
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

func handleReadyz(resolver contract.Resolver, cfg config.Config, log *slog.Logger) http.HandlerFunc {
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
				// The upstream error stays in the log (as a code): /readyz is
				// unauthenticated and must not describe the internal network.
				status = "not_ready"
				reason := "resolver_not_ready"
				if err != nil {
					_, _, reason = errorResponse(err)
					reason = "resolver_" + reason
				}
				if log != nil {
					log.Warn("readyz_not_ready", "reason", reason)
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

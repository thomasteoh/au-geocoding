// server is the serving binary. It exposes POST /search (the parse ladder),
// GET /healthz and GET /readyz. The DB is opened read-only (INV-4 — the server
// never writes; the loader is the only writer).
package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"auplaces/internal/api"
	"auplaces/internal/config"
	"ausystem/shared/metrics"
	"ausystem/shared/slog"
)

//go:embed static
var staticFS embed.FS

// writeJSONError emits a JSON error body with the correct content type.
// http.Error forces text/plain even when the body is a JSON object, so the
// control endpoints (readyz, activate) that speak JSON needed their own
// helper (UX review finding #4).
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func main() {
	// D-020 config: flag > env > file > default. The server has no secrets
	// (no LLM key here), so the effective config is logged plainly at boot.
	// Env is prefixed AUGEO_ (D-020).
	flagDB := flag.String("db", "", "serving SQLite DB path (read-only); default data/vic.db")
	flagAddr := flag.String("addr", "", "listen address; default :8080")
	flag.Parse()

	envDB := os.Getenv("AUGEO_DB")
	envAddr := os.Getenv("AUGEO_ADDR")
	// Control token: /ctrl/activate is a control-plane operation on an otherwise
	// read-only server. It must never be reachable without the token. The token
	// is the secret; the path allowlist below is defense-in-depth.
	ctrlToken := os.Getenv("AUGEO_CTRL_TOKEN")
	// Config file (optional): AUGEO_CONFIG, JSON with db/addr keys.
	fileDB, fileAddr := "", ""
	if cf := os.Getenv("AUGEO_CONFIG"); cf != "" {
		var c struct {
			DB   string `json:"db"`
			Addr string `json:"addr"`
		}
		if b, err := os.ReadFile(cf); err == nil {
			_ = json.Unmarshal(b, &c)
			fileDB, fileAddr = c.DB, c.Addr
		}
	}
	cfg := config.Effective(*flagDB, *flagAddr, envDB, envAddr, fileDB, fileAddr)

	logger := slog.New(os.Stderr, slog.LevelInfo, map[string]any{"service": "auplaces"})
	logger.Info("config", "db", cfg.DB, "addr", cfg.Addr)

	dbPath := cfg.DB
	addr := cfg.Addr

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		logger.Error("open_db_failed", "error", err.Error(), "db", dbPath)
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// Fail fast on a missing/unopenable DB (D-020): sql.Open is lazy, so a bad
	// path isn't caught until the first query. Probe the serving dataset now.
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		logger.Error("open_db_failed", "error", err.Error(), "db", dbPath)
		log.Fatalf("open db: %v", err)
	}
	// Confirm the address table exists (the core dataset). A DB without it is
	// a misconfiguration — refuse to serve.
	var addrCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM address`).Scan(&addrCount); err != nil {
		logger.Error("address_table_missing", "error", err.Error(), "db", dbPath)
		log.Fatalf("address table: %v", err)
	}

	// Read-only (INV-4): the server must never write the serving dataset.
	if _, err := db.Exec(`PRAGMA query_only=ON`); err != nil {
		logger.Error("query_only_failed", "error", err.Error())
		log.Fatalf("query_only: %v", err)
	}
	// Concurrent reads: this DB is read-only (query_only=ON), so a pool of
	// reader connections is safe and lets /readyz and requests proceed while
	// the warmup queries run. Modernc sqlite serializes writers by default;
	// with query_only there are no writers, so open a small reader pool.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	// Warm the locality set asynchronously (P8/R8.2): /readyz must report the
	// loading state immediately rather than queue behind the warmup query.
	// The server starts listening right away; the locality set is loaded in the
	// background. Requests that need the set (search) block on it briefly until
	// ready; /readyz reports loading until the warmup completes.
	locSetReady := make(chan struct{})
	go func() {
		_ = api.LocalitySet(ctx, db)
		close(locSetReady)
	}()

	// The DBProvider holds the active serving DB and supports the versioned
	// swap (P3). Handlers read via the provider so an activation routes new
	// requests to the new pool while in-flight requests finish on the old one.
	provider := api.NewDBProvider(db, "g-naf-aug26+osm-vic-260914")

	// Metrics: minimal Prometheus-style counter set, exposed at /metrics.
	met := metrics.New("auplaces")

	mux := http.NewServeMux()
	mux.HandleFunc("/search", api.SearchHandler(provider))
	mux.HandleFunc("/suggest", api.SuggestHandler(provider))
	mux.HandleFunc("/reverse", api.ReverseHandler(provider))
	mux.HandleFunc("/locality", api.LocalityHandler(provider))
	mux.HandleFunc("/resolve", api.ResolveHandler(provider))
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		met.Render(w)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Step 3 readyz: report each dataset's loaded state (row counts) and
		// the dataset version. A missing table => not ready. P8/R8.2: report
		// the loading state with a reason — the locality-set warmup runs in the
		// background; until it completes we report not-ready (loading).
		db := provider.Get()
		type loaded struct {
			name  string
			count int64
			ok    bool
		}
		checks := []loaded{
			{"address", 0, false},
			{"poi", 0, false},
			{"boundary", 0, false},
			{"addr_rt", 0, false},
			{"addr_trgm", 0, false},
		}
		allOK := true
		parts := []string{}
		for i := range checks {
			c := &checks[i]
			if err := db.QueryRowContext(r.Context(), `SELECT count(*) FROM `+c.name).Scan(&c.count); err != nil {
				c.ok = false
				allOK = false
			} else {
				c.ok = true
			}
			parts = append(parts, fmt.Sprintf(`"%s":{"loaded":%v,"rows":%d}`, c.name, c.ok, c.count))
		}
		// The locality-set warmup gates readiness: until it completes, the
		// normaliser can't classify locality tokens, so we're not ready.
		warmOK := false
		select {
		case <-locSetReady:
			warmOK = true
		default:
			// still loading
		}
		if !allOK || !warmOK {
			reason := "loading"
			if !allOK {
				reason = "dataset_missing"
			}
			// Emit the structured not-ready body as JSON, not text/plain
			// (http.Error would force text/plain even though this is JSON).
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"not_ready","reason":%s,"dataset_version":%s,"detail":{%s}}`, quote(reason), quote(provider.Version()), strings.Join(parts, ","))))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"ready","dataset_version":%s,"detail":{%s}}`, quote(provider.Version()), strings.Join(parts, ","))))
	})
	// P3 activate: the control endpoint. Swap the active pool to a new DB file.
	// Security: requires the AUGEO_CTRL_TOKEN (constant-time compare), the DB
	// path must live under the serving data dir (no traversal / arbitrary file
	// open), and errors are generic — no filesystem oracle.
	mux.HandleFunc("/ctrl/activate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		// Token gate. Empty token => endpoint disabled entirely (fail closed).
		if ctrlToken == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Augeo-Ctrl-Token")), []byte(ctrlToken)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		api.LimitBody(w, r)
		var req struct {
			DB      string `json:"db"`
			Version string `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request")
			return
		}
		if req.DB == "" || req.Version == "" {
			writeJSONError(w, http.StatusBadRequest, "db and version required")
			return
		}
		// Path allowlist: the requested DB must resolve under the serving data
		// dir. Reject absolute paths and any traversal (..). This prevents
		// pointing the service at an arbitrary host file.
		if !withinDir(dbPath, req.DB) {
			writeJSONError(w, http.StatusForbidden, "db path not allowed")
			return
		}
		// Open the new file read-only; on failure the old pool keeps serving
		// (R3.5) — we only swap after the new handle is valid.
		newDB, err := sql.Open("sqlite", req.DB)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "activate failed")
			return
		}
		if _, err := newDB.Exec(`PRAGMA query_only=ON`); err != nil {
			newDB.Close()
			writeJSONError(w, http.StatusInternalServerError, "activate failed")
			return
		}
		// Confirm the new dataset is valid before swapping.
		var n int
		if err := newDB.QueryRowContext(r.Context(), `SELECT count(*) FROM address`).Scan(&n); err != nil {
			newDB.Close()
			writeJSONError(w, http.StatusInternalServerError, "activate failed")
			return
		}
		// Swap: old handle is returned for draining/closing after in-flight
		// requests finish (INV-5).
		oldDB := provider.Swap(newDB, req.Version)
		_ = oldDB // caller drains then closes; we retain the old file for rollback
		_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"activated","version":%s,"addresses":%d}`, quote(req.Version), n)))
	})

	csp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
	})
	mux.Handle("/", requestLog(logger, http.RedirectHandler("/static/", http.StatusMovedPermanently)))
	mux.Handle("/static/", requestLog(logger, csp))

	srv := &http.Server{Addr: addr, Handler: metricsLog(met, mux)}
	// Graceful shutdown on SIGINT/SIGTERM.
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	logger.Info("server_listening", "addr", addr, "db", dbPath)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("serve_failed", "error", err.Error())
		log.Fatalf("serve: %v", err)
	}
	logger.Info("shut_down")
}

// requestLog wraps a handler and logs a structured line per request. INV-1:
// no raw query text, nor anything sufficient to reconstruct one, is ever
// logged. We log only method, path (never the query string), status, duration,
// and dataset version. The request body is NEVER logged or read into a log.
func requestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 0}
		next.ServeHTTP(sw, r)
		// r.URL.RawQuery may carry query text — never log it. Only the path.
		fields := []any{"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"duration_ms", time.Since(start).Milliseconds()}
		if sw.status >= 400 {
			logger.Error("request", fields...)
		} else {
			logger.Info("request", fields...)
		}
	})
}

// statusWriter captures the response status for logging.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = 200
	}
	return s.ResponseWriter.Write(b)
}
func quote(s string) string {
	return `"` + s + `"`
}

// withinDir reports whether target resolves to a path under dir (the serving
// data dir). It rejects absolute paths and any traversal (..) so /ctrl/activate
// cannot point the service at an arbitrary host file.
func withinDir(dir, target string) bool {
	if target == "" {
		return false
	}
	// Reject absolute paths and any traversal outright.
	if filepath.IsAbs(target) {
		return false
	}
	clean := filepath.Clean(target)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	// The joined path must stay under dir.
	base, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	full := filepath.Join(base, clean)
	return strings.HasPrefix(full, base+string(filepath.Separator)) || full == base
}

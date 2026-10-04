package main

// metricsLog wraps the mux to record per-request counters into the shared
// metrics collector. The collector lives in ausystem/shared/metrics; this file
// only wires the middleware. INV-1: only the path (never query text) is a
// label; the handler records endpoint/status/latency, never the query.

import (
	"net/http"
	"time"

	"ausystem/shared/metrics"
)

func metricsLog(met *metrics.Collector, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 0}
		next.ServeHTTP(sw, r)
		met.Record(r.URL.Path, int64(sw.status), time.Since(start).Milliseconds(), 0)
	})
}

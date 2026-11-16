package main

// metricsLog wraps the mux to record per-request counters into the shared
// metrics collector. The collector lives in ausystem/shared/metrics; this file
// only wires the middleware. INV-1: only the matched route pattern (never the
// raw path, never query text) is a label, so the label set is bounded by the
// registered routes; unmatched requests are recorded as "other".

import (
	"net/http"
	"time"

	"ausystem/shared/metrics"
)

func metricsLog(met *metrics.Collector, mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		endpoint := routeLabel(mux, r)
		sw := &statusWriter{ResponseWriter: w, status: 0}
		mux.ServeHTTP(sw, r)
		status := sw.status
		if status == 0 {
			status = http.StatusOK // handler wrote nothing: net/http sends 200
		}
		met.Record(endpoint, int64(status), time.Since(start).Milliseconds(), 0)
	})
}

// routeLabel returns the registered pattern that serves r. The catch-all "/"
// pattern and unmatched paths map to metrics.OtherEndpoint, so arbitrary
// client paths never become label values.
func routeLabel(mux *http.ServeMux, r *http.Request) string {
	_, pattern := mux.Handler(r)
	if pattern == "" || pattern == "/" {
		return metrics.OtherEndpoint
	}
	return pattern
}

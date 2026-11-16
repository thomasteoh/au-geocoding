package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ausystem/shared/metrics"
)

func TestMetricsLogUsesRoutePatterns(t *testing.T) {
	met := metrics.New("auplaces")
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	h := metricsLog(met, mux)
	for _, p := range []string{"/search?q=12+high+st", "/static/x/y/z", "/static/\xff", "/no/such/route", "/"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://x"+strings.ReplaceAll(p, "\xff", "%FF"), nil))
	}
	out := met.Exposition()
	for _, want := range []string{
		`auplaces_requests_total{endpoint="/search",status="200"} 1`,
		`auplaces_requests_total{endpoint="/static/",status="404"} 2`,
		`auplaces_requests_total{endpoint="other",status="404"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, leak := range []string{"high", "/x/y/z", "no/such"} {
		if strings.Contains(out, leak) {
			t.Errorf("raw path/query %q leaked into labels:\n%s", leak, out)
		}
	}
}

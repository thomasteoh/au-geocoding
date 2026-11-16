package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"ausystem/shared/metrics"
)

func TestMetricsRequiresCtrlToken(t *testing.T) {
	met := metrics.New("augeo", "/search")
	for _, tc := range []struct {
		name, token, header, value string
		want                       int
	}{
		{"no token configured", "", "X-Augeo-Ctrl-Token", "", http.StatusUnauthorized},
		{"no token configured, empty bearer", "", "Authorization", "Bearer ", http.StatusUnauthorized},
		{"missing header", "s3cret", "", "", http.StatusUnauthorized},
		{"wrong token", "s3cret", "X-Augeo-Ctrl-Token", "nope", http.StatusUnauthorized},
		{"ctrl header", "s3cret", "X-Augeo-Ctrl-Token", "s3cret", http.StatusOK},
		{"bearer", "s3cret", "Authorization", "Bearer s3cret", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.header != "" {
				req.Header.Set(tc.header, tc.value)
			}
			rec := httptest.NewRecorder()
			handleMetrics(met, tc.token)(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

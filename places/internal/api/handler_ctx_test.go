package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ausystem/shared/contract"
)

// TestHandlers shares one fixture DB (building it takes a while).
func TestHandlers(t *testing.T) {
	db := fixtureDB(t, "../../testdata/golden_fixture.tsv.gz")
	p := NewDBProvider(db, "test")
	t.Run("version gate", func(t *testing.T) { testContractVersionGate(t, p) })
	t.Run("request context", func(t *testing.T) { testResolveUsesRequestContext(t, p) })
}

// The version gate uses the shared contract constants: the geocoder's own
// version passes it and any other is refused with the distinct message the
// geocoder's placesclient maps to a contract mismatch.
func testContractVersionGate(t *testing.T, p *DBProvider) {
	body := `{"kind":0,"generate":["high"],"score":["12","high","st"]}`
	for _, ep := range []struct {
		name  string
		body  string
		serve func(*httptest.ResponseRecorder, string, string)
	}{
		{"resolve", body, func(w *httptest.ResponseRecorder, v, b string) { serve(ResolveHandler(p), w, v, b) }},
		{"search", `{"query":"12 high st"}`, func(w *httptest.ResponseRecorder, v, b string) { serve(SearchHandler(p), w, v, b) }},
		{"suggest", `{"prefix":"high"}`, func(w *httptest.ResponseRecorder, v, b string) { serve(SuggestHandler(p), w, v, b) }},
	} {
		w := httptest.NewRecorder()
		ep.serve(w, "v0", ep.body)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "contract version mismatch") {
			t.Errorf("%s with v0: %d %s", ep.name, w.Code, w.Body)
		}
		w = httptest.NewRecorder()
		ep.serve(w, contract.Version, ep.body)
		if strings.Contains(w.Body.String(), "contract version mismatch") {
			t.Errorf("%s refused its own version", ep.name)
		}
		if w.Code == 200 && w.Header().Get(contract.ContractVersionHeader) != contract.Version {
			t.Errorf("%s did not echo %s", ep.name, contract.Version)
		}
	}
}

// The handler resolves under the request's context: a request whose client
// has gone away does no work and does not report success.
func testResolveUsesRequestContext(t *testing.T, p *DBProvider) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/resolve", strings.NewReader(`{"kind":0,"generate":["high"],"score":["12","high","st"]}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	ResolveHandler(p)(w, r)
	if w.Code == 200 {
		t.Fatalf("cancelled request resolved: %d %s", w.Code, w.Body)
	}
}

func serve(h http.HandlerFunc, w *httptest.ResponseRecorder, version, body string) {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set(contract.ContractVersionHeader, version)
	h(w, r)
}

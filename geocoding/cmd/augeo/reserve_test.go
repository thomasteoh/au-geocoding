package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"augeocoding/internal/apiauth"
	"augeocoding/internal/config"
	"augeocoding/internal/ladder"
	"augeocoding/internal/llm"
	"augeocoding/internal/placesclient"
	"augeocoding/internal/publicapi"
	"ausystem/shared/contract"
	"ausystem/shared/metrics"
	"ausystem/shared/slog"
)

// --- row reservation (finding 5) ---

// A caller with 5 rows left gets 5, not a refusal after the work, and the
// resolver is asked for no more than it can pay for.
func TestNearCapCallerServedWhatItHolds(t *testing.T) {
	h := newHarness(t, nil)
	h.res.n = 20
	k, raw := h.key(publicapi.TierDemo)
	quota := publicapi.TierQuota[publicapi.TierDemo]
	if ok, _ := h.store.ChargePrincipal(publicapi.KeyPrincipal(k), quota-5); !ok {
		t.Fatal("charge")
	}
	w := h.do("/search", `{"query":"12 high st"}`, raw, "")
	if w.Code != 200 {
		t.Fatalf("near cap: %d %s", w.Code, w.Body)
	}
	var sr searchResponse
	_ = json.Unmarshal(w.Body.Bytes(), &sr)
	if len(sr.Candidates) != 5 || !sr.Truncated {
		t.Fatalf("got %d candidates (truncated=%v), want 5", len(sr.Candidates), sr.Truncated)
	}
	if got := h.res.lastLimit.Load(); got != 5 {
		t.Fatalf("resolver asked for %d rows, want 5", got)
	}
	if used, _ := h.store.UsageToday(usageKey(k)); used != quota {
		t.Fatalf("usage %d, want %d", used, quota)
	}
}

// Unused reserved rows go back: a 1-row answer costs 1, an error costs 0.
func TestReservationSettles(t *testing.T) {
	h := newHarness(t, nil)
	k, raw := h.key(publicapi.TierStandard)
	if w := h.do("/search", `{"query":"12 high st"}`, raw, ""); w.Code != 200 {
		t.Fatalf("search: %d", w.Code)
	}
	if used, _ := h.store.UsageToday(usageKey(k)); used != 1 {
		t.Fatalf("1-row answer charged %d", used)
	}
	h.res.err = contract.ErrOutOfScope
	if w := h.do("/geocode", `{"query":"12 high st"}`, raw, ""); w.Code != 400 {
		t.Fatalf("out of scope: %d", w.Code)
	}
	if used, _ := h.store.UsageToday(usageKey(k)); used != 1 {
		t.Fatalf("failed request left %d charged, want 1", used)
	}
	// Anonymous: same, on the in-memory counter.
	h2 := newHarness(t, func(c *config.Config) { c.Rate.AnonDaily = 3 })
	for i := 0; i < 3; i++ {
		if w := h2.do("/search", `{"query":"12 high st"}`, "", ""); w.Code != 200 {
			t.Fatalf("anon %d: %d (a 20-row reservation was not refunded)", i, w.Code)
		}
	}
	if w := h2.do("/search", `{"query":"12 high st"}`, "", ""); w.Code != 429 {
		t.Fatalf("anon over 3 rows: %d", w.Code)
	}
}

// A store fault is a server error, not a quota refusal.
func TestQuotaStoreFaultIs5xx(t *testing.T) {
	h := newHarness(t, nil)
	_, raw := h.key(publicapi.TierStandard)
	h.store.Close()
	w := h.do("/search", `{"query":"12 high st"}`, raw, "")
	if w.Code < 500 {
		t.Fatalf("store fault answered %d %s", w.Code, w.Body)
	}
	if h.res.calls.Load() != 0 {
		t.Fatal("work done without a reservation")
	}
}

func TestMaxResultsBoundsFreeText(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Limits.MaxResults = 3 })
	h.res.n = 10
	w := h.do("/search", `{"query":"12 high st"}`, "", "")
	var sr searchResponse
	_ = json.Unmarshal(w.Body.Bytes(), &sr)
	if w.Code != 200 || len(sr.Candidates) != 3 || h.res.lastLimit.Load() != 3 {
		t.Fatalf("MaxResults 3: %d, %d candidates, resolver limit %d", w.Code, len(sr.Candidates), h.res.lastLimit.Load())
	}
}

// --- /batch (findings 5, 6) ---

func decodeBatch(t *testing.T, w *httptest.ResponseRecorder) batchResp {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("batch: %d %s", w.Code, w.Body)
	}
	var br batchResp
	if err := json.Unmarshal(w.Body.Bytes(), &br); err != nil {
		t.Fatal(err)
	}
	return br
}

// Items the quota cannot cover are refused without being run; the ones
// before them are served and paid for. Nothing is all-or-nothing.
func TestBatchPerItemReservation(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Batch.Workers = 1 })
	h.res.n = 2
	k, raw := h.key(publicapi.TierBatch, "batch")
	quota := publicapi.TierQuota[publicapi.TierBatch]
	if ok, _ := h.store.ChargePrincipal(publicapi.KeyPrincipal(k), quota-3); !ok {
		t.Fatal("charge")
	}
	br := decodeBatch(t, h.do("/batch", `{"items":[{"query":"1 high st"},{"query":"2 high st"},{"query":"3 high st"}]}`, raw, ""))
	got := []int{br.Items[0].Status, br.Items[1].Status, br.Items[2].Status}
	if got[0] != 200 || got[1] != 200 || got[2] != 429 {
		t.Fatalf("statuses %v, want [200 200 429]", got)
	}
	if n := len(br.Items[0].Candidates) + len(br.Items[1].Candidates); n != 3 {
		t.Fatalf("served %d rows, want 3", n)
	}
	if c := h.res.calls.Load(); c != 2 {
		t.Fatalf("resolver ran %d items, want 2 (the unpaid one must not run)", c)
	}
	if used, _ := h.store.UsageToday(usageKey(k)); used != quota {
		t.Fatalf("usage %d, want %d", used, quota)
	}
}

func TestBatchRejectsEmptyItems(t *testing.T) {
	h := newHarness(t, nil)
	h.res.err = contract.ErrNoCandidates // anything that walks would reach the LLM
	_, raw := h.key(publicapi.TierBatch, "batch")
	br := decodeBatch(t, h.do("/batch", `{"items":[{"query":""},{"query":"   "},{"query":"!!!"},{"query":"x","kind":"parse"}]}`, raw, ""))
	for i, it := range br.Items {
		if it.Status != 400 {
			t.Errorf("item %d: %d %q", i, it.Status, it.Error)
		}
	}
	if h.llm.calls.Load() != 0 || h.res.calls.Load() != 0 {
		t.Fatalf("empty items did work: llm %d, resolver %d", h.llm.calls.Load(), h.res.calls.Load())
	}
}

// Batch workers outnumber the per-key LLM cap; the batch's own items queue
// for it instead of failing each other with llm_busy.
func TestBatchLLMItemsQueueForInflightCap(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Batch.Workers = 4; c.Queue.PerKeyInflight = 1 })
	h.res.err = contract.ErrNoCandidates
	h.llm.block = make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); close(h.llm.block) }()
	_, raw := h.key(publicapi.TierBatch, "batch")
	var items []string
	for i := 0; i < 4; i++ {
		items = append(items, fmt.Sprintf(`{"query":"messy query number %d"}`, i))
	}
	br := decodeBatch(t, h.do("/batch", `{"items":[`+strings.Join(items, ",")+`]}`, raw, ""))
	for i, it := range br.Items {
		if it.Status != 200 {
			t.Errorf("item %d: %d %q", i, it.Status, it.Error)
		}
	}
	if n := h.llm.calls.Load(); n != 4 {
		t.Fatalf("llm calls %d, want 4", n)
	}
}

// --- error mapping (findings 2, 7, 9, 10) ---

func TestErrorResponseMappingLLMAndContract(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{
		{ladder.ErrLLMNotImplemented, 501},
		{ladder.ErrLLMBadOutput, 502},
		{llm.ErrNoResult, 502},
		{fmt.Errorf("%w: status 500", llm.ErrProvider), 502},
		{ladder.ErrLLMDegraded, 503},
		{llm.ErrDisabled, 503},
		{fmt.Errorf("%w: v2", placesclient.ErrContractMismatch), 502},
	} {
		if st, _, _ := errorResponse(tc.err); st != tc.status {
			t.Errorf("%v -> %d, want %d", tc.err, st, tc.status)
		}
	}
}

// --- runtime LLM control (finding 10) ---

// openAIStub answers chat completions with one candidate.
func openAIStub(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := "```json\n{\"candidates\":[{\"point\":{\"lat\":-37.8,\"lon\":144.9},\"text\":\"guess\",\"source\":\"gnaf\"}]}\n```"
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": content}}}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCtrlLLMEnablesAndDisablesAtRuntime(t *testing.T) {
	cfg, err := config.Load(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := publicapi.Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	res := &fakeResolver{err: contract.ErrNoCandidates}
	holder := llm.NewHolder(llm.Config{}) // off at boot
	log := slog.New(io.Discard, slog.LevelError, nil)
	authn := &apiauth.Authenticator{Keys: store, KeyLimiter: publicapi.NewRateLimiter(1000, 1000), AnonLimiter: publicapi.NewRateLimiter(1000, 1000),
		ClientIP: func(r *http.Request) string { return clientIP(r, nil) }}
	mux := newMux(buildLadder(res, cfg, holder, log), store, authn, res, cfg, log, metrics.New("test"), holder, "tok", nil, nil)
	do := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-Augeo-Ctrl-Token", "tok")
		r.RemoteAddr = "192.0.2.9:1"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := do("POST", "/parse", parseBody); w.Code != 503 {
		t.Fatalf("parse with LLM off: %d", w.Code)
	}
	// Enabling without a URL is refused, not silently ignored.
	if w := do("POST", "/ctrl/llm", `{"enabled":true}`); w.Code != 400 {
		t.Fatalf("enable without base_url: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/ctrl/llm", `{"enabled":true,"base_url":"`+openAIStub(t).URL+`"}`); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body)
	}
	w := do("POST", "/parse", parseBody)
	if w.Code != 200 {
		t.Fatalf("parse after runtime enable: %d %s", w.Code, w.Body)
	}
	var sr searchResponse
	_ = json.Unmarshal(w.Body.Bytes(), &sr)
	if sr.Strategy != "llm" || len(sr.Candidates) != 1 || sr.Candidates[0].Source != "llm" {
		t.Fatalf("parse answer: %+v", sr)
	}
	rz := do("GET", "/readyz", "")
	if !strings.Contains(rz.Body.String(), `"llm_configured":true`) {
		t.Fatalf("readyz after enable: %s", rz.Body)
	}
	if w := do("POST", "/ctrl/llm", `{"enabled":false}`); w.Code != 200 {
		t.Fatalf("disable: %d", w.Code)
	}
	if w := do("POST", "/parse", parseBody); w.Code != 503 {
		t.Fatalf("parse after disable: %d", w.Code)
	}
	// Free text no rung can place: a client error, not a 500.
	if w := do("POST", "/search", parseBody); w.Code != 400 {
		t.Fatalf("search with LLM off: %d %s", w.Code, w.Body)
	}
}

func TestCtrlLLMErrorsEncodedOnce(t *testing.T) {
	h := llm.NewHolder(llm.Config{})
	for _, tc := range []struct{ token, body, want string }{
		{"wrong", "", `{"error":"unauthorized"}`},
		{"tok", "not json", `{"error":"bad request"}`},
	} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/ctrl/llm", strings.NewReader(tc.body))
		r.Header.Set("X-Augeo-Ctrl-Token", tc.token)
		handleCtrlLLM(h, "tok", slog.New(io.Discard, slog.LevelError, nil))(rec, r)
		if got := strings.TrimSpace(rec.Body.String()); got != tc.want {
			t.Errorf("body %s, want %s", got, tc.want)
		}
	}
}

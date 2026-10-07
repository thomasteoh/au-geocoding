package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"augeocoding/internal/apiauth"
	"augeocoding/internal/config"
	"augeocoding/internal/ladder"
	"augeocoding/internal/llm"
	"augeocoding/internal/publicapi"
	"ausystem/shared/contract"
	"ausystem/shared/metrics"
	"ausystem/shared/slog"
)

// --- client IP (finding 2) ---

func mustProxies(t *testing.T, s string) []netip.Prefix {
	t.Helper()
	p, err := config.ParseTrustedProxies(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClientIPXFF(t *testing.T) {
	trusted := mustProxies(t, "10.0.0.1, 172.16.0.0/12")
	for _, tc := range []struct {
		name, peer string
		xff        []string
		trusted    []netip.Prefix
		want       string
	}{
		{"no trusted proxy ignores XFF", "1.2.3.4:5678", []string{"6.7.8.9"}, nil, "1.2.3.4"},
		{"untrusted peer ignores XFF", "1.2.3.4:5678", []string{"6.7.8.9"}, trusted, "1.2.3.4"},
		{"single proxy", "10.0.0.1:1234", []string{"6.7.8.9"}, trusted, "6.7.8.9"},
		// The client prepends a spoofed entry; the proxy appends the real
		// peer. The rightmost untrusted entry wins.
		{"spoofed leftmost ignored", "10.0.0.1:1234", []string{"1.1.1.1, 6.7.8.9"}, trusted, "6.7.8.9"},
		{"chain of trusted proxies (CIDR)", "10.0.0.1:1234", []string{"6.7.8.9, 172.16.5.5, 172.20.0.1"}, trusted, "6.7.8.9"},
		{"multiple headers", "10.0.0.1:1234", []string{"1.1.1.1", "6.7.8.9, 172.16.5.5"}, trusted, "6.7.8.9"},
		{"garbage falls back to peer", "10.0.0.1:1234", []string{"6.7.8.9, not-an-ip"}, trusted, "10.0.0.1"},
		{"entry with port", "10.0.0.1:1234", []string{"6.7.8.9:4444"}, trusted, "6.7.8.9"},
		{"ipv6 client keyed by /64", "10.0.0.1:1234", []string{"2001:db8:1:2:aaaa::1"}, trusted, "2001:db8:1:2::/64"},
		{"ipv6 peer keyed by /64", "[2001:db8::5]:80", nil, nil, "2001:db8::/64"},
		{"mapped v4 peer", "[::ffff:1.2.3.4]:80", nil, nil, "1.2.3.4"},
		{"all hops trusted", "10.0.0.1:1234", []string{"172.16.0.9"}, trusted, "172.16.0.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/search", nil)
			r.RemoteAddr = tc.peer
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := clientIP(r, tc.trusted); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	// Two addresses in one /64 share a key; the exact address is kept apart.
	a := httptest.NewRequest("POST", "/", nil)
	a.RemoteAddr = "[2001:db8::1]:1"
	b := httptest.NewRequest("POST", "/", nil)
	b.RemoteAddr = "[2001:db8::ffff]:1"
	if clientIP(a, nil) != clientIP(b, nil) || clientAddr(a, nil) == clientAddr(b, nil) {
		t.Fatal("/64 keying or exact address wrong")
	}
}

// --- handler harness ---

type fakeResolver struct {
	calls atomic.Int64
	err   error
	ready error
}

func (f *fakeResolver) Resolve(ctx context.Context, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	f.calls.Add(1)
	if f.err != nil {
		return contract.ResolveResponse{}, f.err
	}
	return contract.ResolveResponse{Candidates: []contract.Candidate{{Source: "gnaf", MatchScore: 0.9}}}, nil
}

func (f *fakeResolver) Suggest(ctx context.Context, req contract.SuggestRequest) (contract.SuggestResponse, error) {
	return contract.SuggestResponse{}, nil
}

func (f *fakeResolver) Ready(ctx context.Context) (bool, string, error) {
	return f.ready == nil, "test", f.ready
}

// fakeLLM answers with no candidates, optionally blocking until released.
type fakeLLM struct {
	calls   atomic.Int64
	entered chan struct{}
	block   chan struct{}
}

func (f *fakeLLM) Complete(ctx context.Context, q string) (string, error) {
	f.calls.Add(1)
	if f.entered != nil {
		f.entered <- struct{}{}
	}
	if f.block != nil {
		<-f.block
	}
	return `{"candidates":[]}`, nil
}

type harness struct {
	t     *testing.T
	h     http.Handler
	store *publicapi.Store
	res   *fakeResolver
	llm   *fakeLLM
	cfg   config.Config
}

func newHarness(t *testing.T, tweak func(*config.Config)) *harness {
	t.Helper()
	cfg, err := config.Load(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.LLM.Enabled = true
	cfg.Rate.AnonRPS, cfg.Rate.AnonBurst = 1000, 1000
	cfg.Rate.KeyDefaultRPS, cfg.Rate.KeyDefaultBurst = 1000, 1000
	if tweak != nil {
		tweak(&cfg)
	}
	store, err := publicapi.Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	res := &fakeResolver{}
	prov := &fakeLLM{}
	l := &ladder.Ladder{
		Rungs: []ladder.Rung{ladder.NewCoordRung(), ladder.NewAddressRung(res)},
		LLM: &ladder.LLMRung{Configured: true, Admit: func() bool { return true }, Release: func() {},
			Singleflight: &sync.Map{}, Breaker: ladder.NewBreaker(100, time.Minute), Provider: prov},
	}
	authn := &apiauth.Authenticator{
		Keys: store, KeyLimiter: publicapi.NewRateLimiter(1000, 1000), AnonLimiter: publicapi.NewRateLimiter(1000, 1000),
		ClientIP: func(r *http.Request) string { return clientIP(r, cfg.Server.TrustedProxies) },
	}
	log := slog.New(io.Discard, slog.LevelError, nil)
	h := newMux(l, store, authn, res, cfg, log, metrics.New("test"), llm.NewHolder(llm.Config{}), "", nil, nil)
	return &harness{t: t, h: h, store: store, res: res, llm: prov, cfg: cfg}
}

func (h *harness) do(path, body, key, ip string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	if key != "" {
		r.Header.Set("X-Api-Key", key)
	}
	if ip == "" {
		ip = "192.0.2.1"
	}
	r.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w
}

func (h *harness) key(tier publicapi.Tier, scopes ...string) (publicapi.Key, string) {
	k, raw, err := h.store.IssueKeyWith(publicapi.IssueOptions{Label: "t", Tier: tier, Scopes: scopes})
	if err != nil {
		h.t.Fatal(err)
	}
	return k, raw
}

func usageKey(k publicapi.Key) string { return publicapi.KeyPrincipal(k).UsageKey }

const parseBody = `{"query":"somewhere nice by the water"}`

// --- LLM spend (finding 4) ---

func TestAnonLLMPerIPAndGlobalCaps(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.AnonLLM.DailyPerIP, c.AnonLLM.DailyGlobal = 2, 3 })
	for i := 0; i < 2; i++ {
		if w := h.do("/parse", parseBody, "", "198.51.100.1"); w.Code != 200 {
			t.Fatalf("call %d: %d %s", i, w.Code, w.Body)
		}
	}
	if w := h.do("/parse", parseBody, "", "198.51.100.1"); w.Code != 429 || !strings.Contains(w.Body.String(), "llm quota") {
		t.Fatalf("per-IP cap: %d %s", w.Code, w.Body)
	}
	if w := h.do("/parse", parseBody, "", "198.51.100.2"); w.Code != 200 {
		t.Fatalf("second IP: %d", w.Code)
	}
	if w := h.do("/parse", parseBody, "", "198.51.100.3"); w.Code != 429 {
		t.Fatalf("global cap: %d", w.Code)
	}
	if n := h.llm.calls.Load(); n != 3 {
		t.Fatalf("provider called %d times, want 3", n)
	}
}

func TestAnonLLMOffWhenCapZero(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.AnonLLM.DailyPerIP = 0 })
	if w := h.do("/parse", parseBody, "", ""); w.Code != 429 || h.llm.calls.Load() != 0 {
		t.Fatalf("anonymous LLM with cap 0: %d, calls %d", w.Code, h.llm.calls.Load())
	}
}

func TestZeroCandidateLLMChargesOneRow(t *testing.T) {
	h := newHarness(t, nil)
	k, raw := h.key(publicapi.TierStandard)
	if w := h.do("/parse", parseBody, raw, ""); w.Code != 200 {
		t.Fatalf("parse: %d %s", w.Code, w.Body)
	}
	if rows, _ := h.store.UsageToday(usageKey(k)); rows != 1 {
		t.Fatalf("0-candidate LLM result charged %d rows, want 1", rows)
	}
	if n, _ := h.store.LLMCallsToday(usageKey(k)); n != 1 {
		t.Fatalf("llm_calls = %d, want 1", n)
	}
}

func TestKeyedLLMTierCap(t *testing.T) {
	old := publicapi.TierLLMQuota[publicapi.TierDemo]
	publicapi.TierLLMQuota[publicapi.TierDemo] = 1
	defer func() { publicapi.TierLLMQuota[publicapi.TierDemo] = old }()
	h := newHarness(t, nil)
	_, raw := h.key(publicapi.TierDemo)
	if w := h.do("/parse", parseBody, raw, ""); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	if w := h.do("/parse", parseBody, raw, ""); w.Code != 429 {
		t.Fatalf("over tier LLM cap: %d", w.Code)
	}
	if h.llm.calls.Load() != 1 {
		t.Fatalf("provider calls %d", h.llm.calls.Load())
	}
}

func TestPreflightRefusesBeforeWork(t *testing.T) {
	h := newHarness(t, nil)
	k, raw := h.key(publicapi.TierDemo)
	if ok, _ := h.store.ChargePrincipal(publicapi.KeyPrincipal(k), publicapi.TierQuota[publicapi.TierDemo]); !ok {
		t.Fatal("charge to ceiling")
	}
	if w := h.do("/search", `{"query":"12 high st"}`, raw, ""); w.Code != 429 {
		t.Fatalf("at ceiling: %d", w.Code)
	}
	if w := h.do("/parse", parseBody, raw, ""); w.Code != 429 {
		t.Fatalf("parse at ceiling: %d", w.Code)
	}
	if h.res.calls.Load() != 0 || h.llm.calls.Load() != 0 {
		t.Fatalf("work done for a caller at ceiling: resolver %d, llm %d", h.res.calls.Load(), h.llm.calls.Load())
	}
	// Anonymous at its per-IP ceiling is refused the same way.
	h2 := newHarness(t, func(c *config.Config) { c.Rate.AnonDaily = 1 })
	if w := h2.do("/search", `{"query":"12 high st"}`, "", ""); w.Code != 200 {
		t.Fatalf("anon first: %d", w.Code)
	}
	before := h2.res.calls.Load()
	if w := h2.do("/search", `{"query":"12 high st"}`, "", ""); w.Code != 429 || h2.res.calls.Load() != before {
		t.Fatalf("anon at ceiling: %d, resolver calls %d->%d", w.Code, before, h2.res.calls.Load())
	}
}

func TestPerKeyLLMInflight(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Queue.PerKeyInflight = 1 })
	h.llm.entered = make(chan struct{}, 1)
	h.llm.block = make(chan struct{})
	_, raw := h.key(publicapi.TierStandard)
	done := make(chan int)
	go func() { done <- h.do("/parse", parseBody, raw, "").Code }()
	<-h.llm.entered
	if w := h.do("/parse", `{"query":"another one entirely"}`, raw, ""); w.Code != 429 || !strings.Contains(w.Body.String(), "in flight") {
		t.Fatalf("second in-flight LLM request: %d %s", w.Code, w.Body)
	}
	// Another key is not affected.
	_, other := h.key(publicapi.TierStandard)
	go func() { done <- h.do("/parse", `{"query":"a third query here"}`, other, "").Code }()
	<-h.llm.entered
	close(h.llm.block)
	for i := 0; i < 2; i++ {
		if c := <-done; c != 200 {
			t.Fatalf("blocked request finished %d", c)
		}
	}
}

// --- /batch (finding 5) ---

func TestBatchRequiresBatchTier(t *testing.T) {
	h := newHarness(t, nil)
	_, raw := h.key(publicapi.TierStandard, "search", "batch")
	if w := h.do("/batch", `{"items":[{"query":"12 high st"}]}`, raw, ""); w.Code != 403 {
		t.Fatalf("batch scope on standard tier: %d %s", w.Code, w.Body)
	}
	_, ok := h.key(publicapi.TierBatch, "batch")
	if w := h.do("/batch", `{"items":[{"query":"12 high st"}]}`, ok, ""); w.Code != 200 {
		t.Fatalf("batch tier: %d %s", w.Code, w.Body)
	}
}

func TestBatchQuotaPreflight(t *testing.T) {
	h := newHarness(t, nil)
	k, raw := h.key(publicapi.TierBatch, "batch")
	quota := publicapi.TierQuota[publicapi.TierBatch]
	if ok, _ := h.store.ChargePrincipal(publicapi.KeyPrincipal(k), quota-1); !ok {
		t.Fatal("charge")
	}
	if w := h.do("/batch", `{"items":[{"query":"12 high st"},{"query":"14 high st"}]}`, raw, ""); w.Code != 429 {
		t.Fatalf("2 items with 1 row left: %d", w.Code)
	}
	if h.res.calls.Load() != 0 {
		t.Fatal("batch ran before the quota check")
	}
}

func TestBatchConcurrencyPerKey(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Batch.MaxConcurrentPerKey = 1 })
	k, raw := h.key(publicapi.TierBatch, "batch")
	// Simulate a batch already running for this key.
	rk := publicapi.KeyPrincipal(k).RateKey
	limits := limitsFor(t, h)
	if !limits.batch.acquire(rk, 1) {
		t.Fatal("acquire")
	}
	if w := h.do("/batch", `{"items":[{"query":"12 high st"}]}`, raw, ""); w.Code != 429 {
		t.Fatalf("second concurrent batch: %d", w.Code)
	}
	limits.batch.release(rk)
	if w := h.do("/batch", `{"items":[{"query":"12 high st"}]}`, raw, ""); w.Code != 200 {
		t.Fatalf("after release: %d %s", w.Code, w.Body)
	}
}

// limitsFor rebuilds the harness around a known apiLimits so a test can
// hold slots directly.
func limitsFor(t *testing.T, h *harness) *apiLimits {
	t.Helper()
	lim := &apiLimits{}
	l := &ladder.Ladder{Rungs: []ladder.Rung{ladder.NewAddressRung(h.res)}}
	authn := &apiauth.Authenticator{Keys: h.store, KeyLimiter: publicapi.NewRateLimiter(1000, 1000), AnonLimiter: publicapi.NewRateLimiter(1000, 1000),
		ClientIP: func(r *http.Request) string { return clientIP(r, nil) }}
	mux := http.NewServeMux()
	mux.HandleFunc("/batch", handleBatch(l, h.store, authn, h.cfg, slog.New(io.Discard, slog.LevelError, nil), lim))
	h.h = mux
	return lim
}

// --- error text (finding 7) ---

func TestInternalErrorsAreGeneric(t *testing.T) {
	h := newHarness(t, nil)
	secret := "dial tcp 10.9.8.7:8080: secret-upstream-detail"
	h.res.err = errors.New(secret)
	h.res.ready = errors.New(secret)
	w := h.do("/geocode", `{"query":"12 high st"}`, "", "")
	if w.Code != 500 || strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "internal error") {
		t.Fatalf("single: %d %s", w.Code, w.Body)
	}
	_, raw := h.key(publicapi.TierBatch, "batch")
	w = h.do("/batch", `{"items":[{"query":"12 high st"}]}`, raw, "")
	var br batchResp
	json.Unmarshal(w.Body.Bytes(), &br)
	if len(br.Items) != 1 || br.Items[0].Status != 500 || br.Items[0].Error != "internal error" {
		t.Fatalf("batch item: %s", w.Body)
	}
	r := httptest.NewRequest("GET", "/readyz", nil)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, r)
	if strings.Contains(rec.Body.String(), "secret") || !strings.Contains(rec.Body.String(), `"not_ready"`) {
		t.Fatalf("readyz: %s", rec.Body)
	}
}

func TestErrorResponseMapping(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{
		{contract.ErrOutOfScope, 400},
		{ladder.ErrNoRung, 400},
		{ladder.ErrLLMBusy, 429},
		{ladder.ErrLLMQuota, 429},
		{context.DeadlineExceeded, 504},
		{errors.New("anything"), 500},
	} {
		if st, msg, _ := errorResponse(tc.err); st != tc.status || msg == tc.err.Error() && st == 500 {
			t.Fatalf("%v -> %d %q", tc.err, st, msg)
		}
	}
}

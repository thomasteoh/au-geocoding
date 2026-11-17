package ladder

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ausystem/shared/contract"
	"ausystem/shared/normalise"
)

// replyProvider answers every call with a fixed reply, optionally blocking
// until released so tests can hold a call in flight.
type replyProvider struct {
	reply   string
	err     error
	calls   atomic.Int64
	entered chan struct{}
	block   chan struct{}
}

func (p *replyProvider) Complete(ctx context.Context, q string) (string, error) {
	p.calls.Add(1)
	if p.entered != nil {
		p.entered <- struct{}{}
	}
	if p.block != nil {
		select {
		case <-p.block:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return p.reply, p.err
}

func newRung(p *replyProvider) *LLMRung {
	return &LLMRung{Configured: true, Admit: func() bool { return true }, Release: func() {},
		Breaker: NewBreaker(3, time.Minute), Provider: p}
}

// A model told to emit JSON can claim to be G-NAF. None of that survives.
func TestLLMOutputCannotPassAsGNAF(t *testing.T) {
	p := &replyProvider{reply: `{"candidates":[{"id":{"source":"gnaf","pid":"GAVIC123"},"kind":3,
		"point":{"lat":-37.8,"lon":144.9},"source":"gnaf","text":"<b>1 Main St</b>","gnaf_pid":"GAVIC123",
		"gnaf_confidence":2,"geocode_reliability":6,"match_score":97,"precision":"address","locality_id":7}],
		"dataset_version":"gnaf-2026-08","total_matched":9999,"truncated":true}`}
	_, resp, err := newRung(p).Try(context.Background(), Query{Raw: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Candidates) != 1 {
		t.Fatalf("candidates: %+v", resp.Candidates)
	}
	c := resp.Candidates[0]
	if c.Source != "llm" || c.ID.Source != "llm" || c.ID.PID != "" || c.GnafPID != "" ||
		c.GnafConfidence != 0 || c.GeocodeReliability != 0 || c.Precision != "" || c.LocalityID != 0 {
		t.Fatalf("model-supplied provenance survived: %+v", c)
	}
	if c.MatchScore != llmMaxMatchScore {
		t.Fatalf("match_score %v, want capped at %v", c.MatchScore, llmMaxMatchScore)
	}
	if c.Kind != contract.KindAddress || c.Text != "b1 Main St/b" {
		t.Fatalf("kind/text: %+v", c)
	}
	if resp.DatasetVersion != "" || resp.TotalMatched != 1 || resp.Truncated {
		t.Fatalf("response-level fields: %+v", resp)
	}
}

func TestLLMMatchScoreClamped(t *testing.T) {
	p := &replyProvider{reply: `{"candidates":[{"point":{"lat":-37.8,"lon":144.9},"match_score":-4},
		{"point":{"lat":-37.8,"lon":144.9},"match_score":0.2}]}`}
	_, resp, err := newRung(p).Try(context.Background(), Query{Raw: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Candidates[0].MatchScore != 0 || resp.Candidates[1].MatchScore != 0.2 {
		t.Fatalf("scores: %v %v", resp.Candidates[0].MatchScore, resp.Candidates[1].MatchScore)
	}
}

func TestLLMReplyExtraction(t *testing.T) {
	obj := `{"candidates":[{"point":{"lat":-37.8,"lon":144.9},"text":"a"}]}`
	for name, reply := range map[string]string{
		"bare":    obj,
		"fenced":  "```json\n" + obj + "\n```",
		"prose":   "Sure! Here is the result:\n" + obj + "\nLet me know if you need more.",
		"braces":  "Format {like this}: " + obj,
		"padding": "\n\n  " + obj + "  ",
	} {
		_, resp, err := newRung(&replyProvider{reply: reply}).Try(context.Background(), Query{Raw: "x"})
		if err != nil || len(resp.Candidates) != 1 {
			t.Errorf("%s: %v %+v", name, err, resp)
		}
	}
	// Genuinely unusable output is its own error, never "not implemented",
	// and does not count against the breaker (a caller can provoke it).
	p := &replyProvider{reply: "I cannot help with that."}
	r := newRung(p)
	for i := 0; i < 5; i++ {
		_, _, err := r.Try(context.Background(), Query{Raw: "x"})
		if !errors.Is(err, ErrLLMBadOutput) || errors.Is(err, ErrLLMNotImplemented) {
			t.Fatalf("unparseable reply: %v", err)
		}
	}
	if ok, _ := r.Breaker.acquire(); !ok {
		t.Fatal("bad model output opened the breaker")
	}
}

func TestLLMSingleflightMergesConcurrentQueries(t *testing.T) {
	p := &replyProvider{reply: `{"candidates":[]}`, entered: make(chan struct{}, 8), block: make(chan struct{})}
	r := newRung(p)
	var charged atomic.Int64
	ctx := WithLLMGate(context.Background(), LLMGate{Charge: func() error { charged.Add(1); return nil }})
	const n = 5
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, err := r.Try(ctx, Query{Raw: "same query"})
		errs <- err
	}()
	<-p.entered // the leader is in the provider
	for i := 1; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := r.Try(ctx, Query{Raw: "same query"})
			errs <- err
		}()
	}
	// Wait until every follower is charged (and so about to join the flight).
	for charged.Load() < n {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(p.block)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := p.calls.Load(); got != 1 {
		t.Fatalf("provider called %d times for %d identical concurrent queries", got, n)
	}
	r.flight.mu.Lock()
	left := len(r.flight.m)
	r.flight.mu.Unlock()
	if left != 0 {
		t.Fatalf("flight map holds %d entries after the call", left)
	}
}

// A follower whose leader's request was cancelled runs the call itself.
func TestLLMSingleflightFollowerOutlivesLeader(t *testing.T) {
	p := &replyProvider{reply: `{"candidates":[]}`, entered: make(chan struct{}, 8), block: make(chan struct{})}
	r := newRung(p)
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, _, err := r.Try(leaderCtx, Query{Raw: "q"})
		leaderDone <- err
	}()
	<-p.entered
	followerDone := make(chan error, 1)
	go func() {
		_, _, err := r.Try(context.Background(), Query{Raw: "q"})
		followerDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader: %v", err)
	}
	<-p.entered // the follower retried as leader
	close(p.block)
	if err := <-followerDone; err != nil {
		t.Fatalf("follower inherited the leader's cancellation: %v", err)
	}
}

func TestBreakerHalfOpenAdmitsOneProbe(t *testing.T) {
	b := NewBreaker(1, 10*time.Millisecond)
	ok, probe := b.acquire()
	if !ok || probe {
		t.Fatal("closed breaker should admit without probing")
	}
	b.finish(false, outcomeFailure)
	if ok, _ := b.acquire(); ok {
		t.Fatal("open breaker admitted a call")
	}
	time.Sleep(15 * time.Millisecond)
	ok, probe = b.acquire()
	if !ok || !probe {
		t.Fatal("cooled-down breaker should admit a probe")
	}
	if ok, _ := b.acquire(); ok {
		t.Fatal("second call admitted while the probe is out")
	}
	// A failed probe reopens for a full cooldown.
	b.finish(true, outcomeFailure)
	if ok, _ := b.acquire(); ok {
		t.Fatal("breaker admitted right after a failed probe")
	}
	time.Sleep(15 * time.Millisecond)
	// A probe that ends without a verdict frees the slot for the next one.
	_, probe = b.acquire()
	b.finish(probe, outcomeNone)
	ok, probe = b.acquire()
	if !ok || !probe {
		t.Fatal("abandoned probe did not free the slot")
	}
	b.finish(probe, outcomeSuccess)
	for i := 0; i < 3; i++ {
		if ok, probe := b.acquire(); !ok || probe {
			t.Fatal("successful probe should close the breaker")
		}
	}
}

// A refused call (quota) after the breaker admitted the probe must not hold
// the probe slot forever.
func TestBreakerProbeReleasedOnRefusal(t *testing.T) {
	r := newRung(&replyProvider{reply: `{}`})
	r.Breaker = NewBreaker(1, time.Millisecond)
	r.Breaker.finish(false, outcomeFailure)
	time.Sleep(2 * time.Millisecond)
	ctx := WithLLMGate(context.Background(), LLMGate{Charge: func() error { return ErrLLMQuota }})
	if _, _, err := r.Try(ctx, Query{Raw: "x"}); !errors.Is(err, ErrLLMQuota) {
		t.Fatalf("want quota refusal, got %v", err)
	}
	if ok, _ := r.Breaker.acquire(); !ok {
		t.Fatal("probe slot leaked by a refused call")
	}
}

func TestLLMDisabledAtRuntime(t *testing.T) {
	p := &replyProvider{reply: `{}`}
	r := newRung(p)
	on := false
	r.Enabled = func() bool { return on }
	if _, _, err := r.Try(context.Background(), Query{Raw: "x"}); !errors.Is(err, ErrNoRung) || p.calls.Load() != 0 {
		t.Fatalf("disabled rung: %v, calls %d", err, p.calls.Load())
	}
	on = true
	if _, _, err := r.Try(context.Background(), Query{Raw: "x"}); err != nil {
		t.Fatalf("enabled rung: %v", err)
	}
}

func TestLLMCandidatesCappedToLimit(t *testing.T) {
	p := &replyProvider{reply: `{"candidates":[{"point":{"lat":-37.8,"lon":144.9}},{"point":{"lat":-37.8,"lon":144.9}},{"point":{"lat":-37.8,"lon":144.9}}]}`}
	_, resp, err := newRung(p).Try(context.Background(), Query{Raw: "x", Limit: 2})
	if err != nil || len(resp.Candidates) != 2 || !resp.Truncated {
		t.Fatalf("limit 2: %v %d truncated=%v", err, len(resp.Candidates), resp.Truncated)
	}
}

// failingLLM always errors, so the breaker opens after Threshold calls.
type failingLLM struct{ calls atomic.Int64 }

func (f *failingLLM) Complete(ctx context.Context, q string) (string, error) {
	f.calls.Add(1)
	return "", errors.New("connection refused")
}

// With the breaker open the fallback must honour the endpoint kind: a POI
// rung that answers must not serve /geocode.
func TestBreakerFallbackRespectsKind(t *testing.T) {
	poiOnly := poiOnlyResolver{}
	l := &Ladder{
		Rungs: []Rung{NewAddressRung(poiOnly), NewPOIRung(poiOnly)},
		LLM: &LLMRung{Configured: true, Admit: func() bool { return true }, Release: func() {},
			Breaker: NewBreaker(1, time.Hour), Provider: &failingLLM{}},
	}
	l.LLM.Breaker.finish(false, outcomeFailure) // open
	q := Query{Raw: "woolworths", Normal: normalise.Normalise("woolworths")}
	res, err := l.WalkKind(context.Background(), q, "geocode")
	if err == nil {
		t.Fatalf("/geocode with the breaker open returned strategy %q", res.Strategy)
	}
	if !errors.Is(err, ErrLLMDegraded) {
		t.Fatalf("want ErrLLMDegraded, got %v", err)
	}
}

// poiOnlyResolver declines addresses and answers POIs.
type poiOnlyResolver struct{ mockResolver }

func (poiOnlyResolver) Resolve(ctx context.Context, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	if req.Kind == contract.KindPOI {
		return contract.ResolveResponse{Candidates: []contract.Candidate{{Source: "osm", Name: "Woolworths", MatchScore: 0.9}}}, nil
	}
	return contract.ResolveResponse{}, contract.ErrNoCandidates
}

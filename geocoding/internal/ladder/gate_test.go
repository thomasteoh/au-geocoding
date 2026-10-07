package ladder

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type countingProvider struct{ calls int }

func (p *countingProvider) Complete(ctx context.Context, q string) (string, error) {
	p.calls++
	return `{"candidates":[]}`, nil
}

func newTestLLMRung(p *countingProvider) *LLMRung {
	return &LLMRung{
		Configured: true, Admit: func() bool { return true }, Release: func() {},
		Singleflight: &sync.Map{}, Breaker: NewBreaker(5, time.Minute), Provider: p,
	}
}

func TestLLMGateChargeRefusalSkipsProvider(t *testing.T) {
	p := &countingProvider{}
	r := newTestLLMRung(p)
	entered, left := 0, 0
	ctx := WithLLMGate(context.Background(), LLMGate{
		Enter:  func() (func(), error) { entered++; return func() { left++ }, nil },
		Charge: func() error { return ErrLLMQuota },
	})
	if _, _, err := r.Try(ctx, Query{Raw: "x"}); !errors.Is(err, ErrLLMQuota) {
		t.Fatalf("want ErrLLMQuota, got %v", err)
	}
	if p.calls != 0 {
		t.Fatal("provider called after the quota refused")
	}
	if entered != 1 || left != 1 {
		t.Fatalf("enter/leave %d/%d", entered, left)
	}
}

func TestLLMGateEnterRefusal(t *testing.T) {
	p := &countingProvider{}
	r := newTestLLMRung(p)
	charged := false
	ctx := WithLLMGate(context.Background(), LLMGate{
		Enter:  func() (func(), error) { return nil, ErrLLMBusy },
		Charge: func() error { charged = true; return nil },
	})
	l := &Ladder{LLM: r}
	if _, err := l.WalkKind(ctx, Query{Raw: "x"}, "parse"); !errors.Is(err, ErrLLMBusy) {
		t.Fatalf("want ErrLLMBusy through the walk, got %v", err)
	}
	if charged || p.calls != 0 {
		t.Fatal("busy caller was charged or reached the provider")
	}
}

func TestLLMGateChargesEachCall(t *testing.T) {
	p := &countingProvider{}
	r := newTestLLMRung(p)
	n := 0
	ctx := WithLLMGate(context.Background(), LLMGate{Charge: func() error { n++; return nil }})
	for i := 0; i < 3; i++ {
		if _, _, err := r.Try(ctx, Query{Raw: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if n != 3 || p.calls != 3 {
		t.Fatalf("charged %d, provider %d", n, p.calls)
	}
}

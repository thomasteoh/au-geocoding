package ladder

import (
	"context"
	"errors"
)

// LLMGate is the per-request spend control for rung 5, carried on the
// context by the HTTP layer (which knows the caller). Both hooks run only
// when a request actually reaches the LLM rung, so deterministic queries
// never touch LLM budgets.
type LLMGate struct {
	// Enter admits the caller (per-principal in-flight cap). It returns a
	// release func, called once the rung is done, or an error (ErrLLMBusy).
	Enter func() (func(), error)
	// Charge counts one LLM call against the caller's daily LLM cap, just
	// before the provider is called. An error (ErrLLMQuota) refuses the call.
	Charge func() error
}

// ErrLLMBusy is returned when the caller already has Queue.PerKeyInflight
// LLM requests in flight.
var ErrLLMBusy = errors.New("too many llm requests in flight for this caller")

// ErrLLMQuota is returned when the caller's daily LLM-call cap is reached.
var ErrLLMQuota = errors.New("llm quota exceeded")

type gateKey struct{}

// WithLLMGate attaches g to ctx for LLMRung.Try.
func WithLLMGate(ctx context.Context, g LLMGate) context.Context {
	return context.WithValue(ctx, gateKey{}, g)
}

func gateFrom(ctx context.Context) LLMGate {
	g, _ := ctx.Value(gateKey{}).(LLMGate)
	return g
}

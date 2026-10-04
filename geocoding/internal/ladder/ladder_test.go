package ladder

import (
	"context"
	"errors"
	"testing"

	"ausystem/shared/contract"
	"ausystem/shared/normalise"
)

// mockResolver returns canned candidates, or ErrOutOfScope for state=qld.
type mockResolver struct{}

func (mockResolver) Resolve(ctx context.Context, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	if req.State == "queensland" || req.State == "qld" {
		return contract.ResolveResponse{}, contract.ErrOutOfScope
	}
	return contract.ResolveResponse{Candidates: []contract.Candidate{{Source: "gnaf", MatchScore: 0.9}}}, nil
}

func (mockResolver) Ready(ctx context.Context) (bool, string, error) { return true, "test", nil }

func (mockResolver) Suggest(ctx context.Context, req contract.SuggestRequest) (contract.SuggestResponse, error) {
	return contract.SuggestResponse{}, nil
}

func TestCoordRung(t *testing.T) {
	r := NewCoordRung()
	_, _, err := r.Try(context.Background(), Query{Raw: "-37.8136, 144.9631"})
	if err != nil {
		t.Fatalf("coord: %v", err)
	}
}

func TestOutOfScopePropagates(t *testing.T) {
	// Address rung must propagate ErrOutOfScope, never swallow it.
	r := NewAddressRung(mockResolver{})
	_, _, err := r.Try(context.Background(), Query{Raw: "1 Main St QLD", Normal: normalise.Normalise("1 Main St QLD")})
	if err == nil || !errors.Is(err, contract.ErrOutOfScope) {
		t.Fatalf("expected ErrOutOfScope, got %v", err)
	}
}

func TestWalkFallsThrough(t *testing.T) {
	// A bare POI with no anchor/address falls to rung 4.
	l := &Ladder{Rungs: []Rung{NewPOIRung(mockResolver{})}}
	res, err := l.Walk(context.Background(), Query{Raw: "woolworths", Normal: normalise.Normalise("woolworths")})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if res.Strategy != StrategyPOI {
		t.Fatalf("expected poi, got %s", res.Strategy)
	}
}

func TestWalkKindConstrainsRungs(t *testing.T) {
	// A full ladder. /geocode on a POI name must NOT return strategy=poi —
	// only the address/coord rungs participate.
	full := &Ladder{Rungs: []Rung{
		NewCoordRung(),
		NewAddressRung(mockResolver{}),
		NewPOIAnchorRung(mockResolver{}),
		NewPOIRung(mockResolver{}),
	}}
	// /poi on an address ("12 main road") must not return strategy=address.
	res, err := full.WalkKind(context.Background(), Query{Raw: "12 main road", Normal: normalise.Normalise("12 main road")}, "poi")
	if err == nil && res.Strategy == StrategyAddress {
		t.Fatalf("poi kind returned address strategy: %s", res.Strategy)
	}
	// /reverse on an address must not resolve — coord rung only.
	res, err = full.WalkKind(context.Background(), Query{Raw: "12 main road", Normal: normalise.Normalise("12 main road")}, "reverse")
	if err == nil && res.Strategy == StrategyAddress {
		t.Fatalf("reverse kind returned address strategy: %s", res.Strategy)
	}
}

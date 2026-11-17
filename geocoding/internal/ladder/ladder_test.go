package ladder

import (
	"context"
	"errors"
	"sync"
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

// declineResolver answers addresses only for streets it knows and declines
// everything else, the way places declines text it cannot place.
type declineResolver struct{ mockResolver }

func (declineResolver) Resolve(ctx context.Context, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	if req.Kind == contract.KindAddress {
		for _, t := range req.Score {
			if t == "kilda" || t == "north" {
				return contract.ResolveResponse{Candidates: []contract.Candidate{{Source: "gnaf", Precision: contract.PrecisionLocality}}}, nil
			}
		}
		return contract.ResolveResponse{}, contract.ErrNoCandidates
	}
	return contract.ResolveResponse{Candidates: []contract.Candidate{{Source: "osm", Name: "poi"}}}, nil
}

func TestAddressRungAsksPlacesWithoutNumber(t *testing.T) {
	full := &Ladder{Rungs: []Rung{NewAddressRung(declineResolver{}), NewPOIRung(declineResolver{})}}
	walk := func(q string) Result {
		res, err := full.Walk(context.Background(), Query{Raw: q, Normal: normalise.Normalise(q)})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		return res
	}
	// A street or locality with no number goes to places first...
	for _, q := range []string{"St Kilda Rd St Kilda", "Box Hill North"} {
		if res := walk(q); res.Strategy != StrategyAddress {
			t.Errorf("%q: strategy %s, want address", q, res.Strategy)
		}
	}
	// ...and when places declines, the walk moves on to POI search.
	if res := walk("woolworths"); res.Strategy != StrategyPOI {
		t.Errorf("woolworths: strategy %s, want poi", res.Strategy)
	}
}

// recordingResolver records the requests it receives and answers each with
// one candidate.
type recordingResolver struct {
	mockResolver
	mu   sync.Mutex
	reqs []contract.ResolveRequest
}

func (r *recordingResolver) Resolve(ctx context.Context, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	return contract.ResolveResponse{Candidates: []contract.Candidate{{Source: "gnaf", Text: "1 NEAREST ST", MatchScore: 0.9}}}, nil
}

// /reverse with "lat, lon" text must reach the reverse rung, not the coord
// rung's echo of the input, and must never fall through to the paid LLM.
func TestReverseUsesReverseRungNotEcho(t *testing.T) {
	res := &recordingResolver{}
	llmP := &replyProvider{reply: `{"candidates":[]}`}
	l := &Ladder{
		Rungs: []Rung{NewCoordRung(), NewAddressRung(res), NewReverseRung(res)},
		LLM:   newRung(llmP),
	}
	q := "-33.86, 151.2"
	got, err := l.WalkKind(context.Background(), Query{Raw: q, Normal: normalise.Normalise(q)}, "reverse")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.reqs) != 1 || res.reqs[0].Kind != contract.KindReverse {
		t.Fatalf("resolver requests: %+v", res.reqs)
	}
	if got.Response.Candidates[0].Text != "1 NEAREST ST" {
		t.Fatalf("reverse echoed the input: %+v", got.Response.Candidates)
	}
	// A coordinate outside AU: no rung applies, and the LLM is not asked.
	q = `{"lat":51.5,"lon":-0.1}`
	if _, err := l.WalkKind(context.Background(), Query{Raw: q, Normal: normalise.Normalise(q)}, "reverse"); !errors.Is(err, ErrNoRung) {
		t.Fatalf("out-of-AU reverse: %v", err)
	}
	if llmP.calls.Load() != 0 {
		t.Fatal("/reverse reached the LLM")
	}
}

func TestQueryLimitReachesResolver(t *testing.T) {
	res := &recordingResolver{}
	l := &Ladder{Rungs: []Rung{NewAddressRung(res)}}
	q := "12 high st"
	for _, tc := range []struct{ limit, want int }{{0, 20}, {7, 7}, {50, 20}} {
		res.reqs = nil
		if _, err := l.Walk(context.Background(), Query{Raw: q, Normal: normalise.Normalise(q), Limit: tc.limit}); err != nil {
			t.Fatal(err)
		}
		if res.reqs[0].Limit != tc.want {
			t.Errorf("Limit %d: resolver asked for %d, want %d", tc.limit, res.reqs[0].Limit, tc.want)
		}
	}
}

// A postal box goes to places as an address, with the box leading Score, and
// is never searched as a POI name when places cannot place it.
func TestPostalBoxIsNotAPOI(t *testing.T) {
	st := &stubResolver{err: contract.ErrNoCandidates}
	l := &Ladder{Rungs: []Rung{NewAddressRung(st), NewPOIRung(declineResolver{})}}
	q := "PO Box 123 Nowhere VIC 3001"
	_, err := l.Walk(context.Background(), Query{Raw: q, Normal: normalise.Normalise(q)})
	if !errors.Is(err, ErrNoRung) {
		t.Errorf("walk: err %v, want ErrNoRung (no POI fallback)", err)
	}
	if st.got.Kind != contract.KindAddress || len(st.got.Score) < 3 ||
		st.got.Score[0] != "po" || st.got.Score[1] != "box" || st.got.Score[2] != "123" {
		t.Errorf("address request %+v, want Score opening po box 123", st.got)
	}
}

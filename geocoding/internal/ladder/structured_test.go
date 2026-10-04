package ladder

import (
	"context"
	"testing"

	"ausystem/shared/contract"
)

// stubResolver captures the request it was handed, so tests can assert on what
// the structured path actually sends rather than on its return value.
type stubResolver struct {
	got  contract.ResolveRequest
	resp contract.ResolveResponse
	err  error
}

func (s *stubResolver) Resolve(_ context.Context, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	s.got = req
	return s.resp, s.err
}
func (s *stubResolver) Ready(context.Context) (bool, string, error) { return true, "", nil }

func (s *stubResolver) Suggest(_ context.Context, req contract.SuggestRequest) (contract.SuggestResponse, error) {
	return contract.SuggestResponse{}, nil
}

func ladderWith(res contract.Resolver) *Ladder {
	return &Ladder{Rungs: []Rung{NewCoordRung(), NewAddressRung(res)}}
}

func oneCandidate() contract.ResolveResponse {
	return contract.ResolveResponse{Candidates: []contract.Candidate{{GnafPID: "GAVIC1"}}}
}

// PR-8.2 — structured input skips the ladder. The proof is that the resolver
// receives an address request carrying components, with no rung having parsed
// anything.
func TestStructuredSkipsTheLadder(t *testing.T) {
	st := &stubResolver{resp: oneCandidate()}
	l := ladderWith(st)

	res, err := l.ResolveStructured(context.Background(), contract.AddressComponents{
		StreetNumber: "36", StreetName: "Collins", StreetType: "St",
		Locality: "Melbourne", State: "VIC", Postcode: "3000",
	}, 10)
	if err != nil {
		t.Fatalf("ResolveStructured: %v", err)
	}
	if res.Strategy != StrategyStructured {
		t.Errorf("strategy = %q, want %q", res.Strategy, StrategyStructured)
	}
	if st.got.Kind != contract.KindAddress {
		t.Errorf("kind = %v, want KindAddress", st.got.Kind)
	}
	if st.got.Components == nil {
		t.Fatal("components not carried to the resolver")
	}
	if st.got.Components.StreetName != "collins" {
		t.Errorf("street name = %q, want folded \"collins\"", st.got.Components.StreetName)
	}
	if st.got.Components.StreetType != "street" {
		t.Errorf("street type = %q, want \"st\" expanded to \"street\"", st.got.Components.StreetType)
	}
	if st.got.Limit != 10 {
		t.Errorf("limit = %d, want 10", st.got.Limit)
	}
}

// The street number must not become a generation anchor: the trigram index
// does not cover tokens under three characters, so anchoring on "36" would
// generate nothing.
func TestStructuredExcludesShortTokensFromGeneration(t *testing.T) {
	st := &stubResolver{resp: oneCandidate()}
	l := ladderWith(st)
	if _, err := l.ResolveStructured(context.Background(), contract.AddressComponents{
		StreetNumber: "36", StreetName: "Collins", Locality: "Melbourne",
	}, 0); err != nil {
		t.Fatal(err)
	}
	for _, g := range st.got.Generate {
		if g == "36" {
			t.Error("street number used as a generation anchor")
		}
		if len(g) < 3 {
			t.Errorf("short token %q used as a generation anchor", g)
		}
	}
	// But it must still be available for scoring.
	var found bool
	for _, sc := range st.got.Score {
		if sc == "36" {
			found = true
		}
	}
	if !found {
		t.Error("street number dropped from the score set")
	}
}

// PR-8.4 — locality and postcode with no street is a coarser query, not an
// error.
func TestStructuredWithoutStreetResolvesAtLocalityLevel(t *testing.T) {
	st := &stubResolver{resp: oneCandidate()}
	l := ladderWith(st)
	res, err := l.ResolveStructured(context.Background(), contract.AddressComponents{
		Locality: "Melbourne", State: "VIC", Postcode: "3000",
	}, 0)
	if err != nil {
		t.Fatalf("locality-only should resolve, got %v", err)
	}
	if st.got.Kind != contract.KindLocality {
		t.Errorf("kind = %v, want KindLocality", st.got.Kind)
	}
	if res.Strategy != StrategyStructuredLocality {
		t.Errorf("strategy = %q, want %q", res.Strategy, StrategyStructuredLocality)
	}
}

func TestStructuredEmptyIsRejected(t *testing.T) {
	st := &stubResolver{resp: oneCandidate()}
	l := ladderWith(st)
	if _, err := l.ResolveStructured(context.Background(), contract.AddressComponents{}, 0); err == nil {
		t.Error("empty components should not resolve")
	}
}

// Normalisation is applied per field, so the labelling survives it. Mixing the
// fields into one string and re-splitting would be the bug this whole path
// exists to avoid.
func TestStructuredNormalisesPerFieldNotAsOneString(t *testing.T) {
	st := &stubResolver{resp: oneCandidate()}
	l := ladderWith(st)
	if _, err := l.ResolveStructured(context.Background(), contract.AddressComponents{
		StreetName: "st kilda", Locality: "elwood", State: "vic",
	}, 0); err != nil {
		t.Fatal(err)
	}
	c := st.got.Components
	// "st kilda" must NOT become "street kilda": expansion belongs to the
	// street-type field alone, and the caller already said this is a name.
	if c.StreetName != "st kilda" {
		t.Errorf("street name = %q, want %q — abbreviation expansion corrupted a labelled name", c.StreetName, "st kilda")
	}
	if c.Locality != "elwood" {
		t.Errorf("locality = %q", c.Locality)
	}
}

func TestStructuredPropagatesResolverError(t *testing.T) {
	st := &stubResolver{err: contract.ErrOutOfScope}
	l := ladderWith(st)
	if _, err := l.ResolveStructured(context.Background(), contract.AddressComponents{
		StreetName: "Collins", Locality: "Melbourne",
	}, 0); err == nil {
		t.Error("resolver error should propagate, not become an empty result")
	}
}

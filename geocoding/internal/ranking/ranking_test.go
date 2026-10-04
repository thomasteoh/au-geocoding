package ranking

import (
	"testing"

	"ausystem/shared/contract"
)

func TestRankPrefersGNAF(t *testing.T) {
	cs := []contract.Candidate{
		{Source: "osm", MatchScore: 0.9, GnafPID: ""},
		{Source: "gnaf", MatchScore: 0.9, GnafPID: "gnaf-1", GnafConfidence: 2, GeocodeReliability: 5},
	}
	out := Rank(cs, 1)
	if len(out) != 1 || out[0].Source != "gnaf" {
		t.Fatalf("expected gnaf first, got %+v", out)
	}
}

func TestRankLimitsN(t *testing.T) {
	cs := []contract.Candidate{{Source: "gnaf"}, {Source: "osm"}, {Source: "osm"}}
	out := Rank(cs, 2)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
}

// The refining terms must refine, not decide. Before normalisation they could
// not: GnafConfidence (0..2) and GeocodeReliability (1..6) applied raw
// contribute up to 2.5 against match quality's 1.0, so a barely-matching
// candidate with a precise coordinate outranked a near-perfect match.
func TestMatchQualityDominatesRefiners(t *testing.T) {
	cs := []contract.Candidate{
		// Weak match, best possible authority and precision.
		{Source: "gnaf", MatchScore: 0.10, GnafPID: "weak", GnafConfidence: 2, GeocodeReliability: 6},
		// Strong match, worst authority and precision.
		{Source: "gnaf", MatchScore: 0.95, GnafPID: "strong", GnafConfidence: 0, GeocodeReliability: 1},
	}
	out := Rank(cs, 1)
	if out[0].GnafPID != "strong" {
		t.Fatalf("refining terms outweighed match quality: got %q", out[0].GnafPID)
	}
}

// Each refining term is capped at its declared weight.
func TestRefinersCappedAtDeclaredWeight(t *testing.T) {
	base := Composite(contract.Candidate{Source: "gnaf", GnafPID: "x", MatchScore: 0})
	best := Composite(contract.Candidate{
		Source: "gnaf", GnafPID: "x", MatchScore: 0,
		GnafConfidence: 2, GeocodeReliability: 6,
	})
	if got, want := float64(best-base), WGnafConf+WGeocodeRel; got > want+1e-9 {
		t.Errorf("refiners contribute %.4f, declared maximum is %.4f", got, want)
	}
}

// An out-of-range value from a future dataset must not be able to outweigh
// match quality.
func TestRefinerOutOfRangeIsClamped(t *testing.T) {
	sane := Composite(contract.Candidate{Source: "gnaf", GnafPID: "x", GeocodeReliability: 6})
	wild := Composite(contract.Candidate{Source: "gnaf", GnafPID: "x", GeocodeReliability: 127})
	if wild != sane {
		t.Errorf("out-of-range reliability not clamped: %.4f vs %.4f", wild, sane)
	}
}

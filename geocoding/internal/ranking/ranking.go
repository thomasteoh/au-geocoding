// Package ranking scores and sorts resolution candidates in Go. This is the
// second phase of D-010's two-phase ranking: the FTS5 query caps candidates
// (no ORDER BY rank), then Go combines match_score, gnaf_confidence,
// geocode_reliability and distance-to-anchor. bm25 over the full candidate set
// is the +64 ms cost D-010 avoids.
package ranking

import (
	"math"
	"sort"

	"ausystem/shared/contract"
)

// Score is a single candidate's composite score. Higher is better.
type Score float64

// Weights for the composite. Match quality dominates; authority confidence and
// coordinate precision refine; distance breaks ties for anchored queries.
//
// The refining terms are normalised to 0..1 before weighting, so the weights
// below are the actual maximum contribution of each. Applied raw they would
// not be: GnafConfidence runs 0..2 and GeocodeReliability 1..6, so the two
// "refining" terms could contribute up to 2.5 against match quality's 1.0 —
// inverting the stated intent and letting a poorly-matched but precisely
// located candidate outrank a well-matched one.
const (
	WMatch        = 1.0
	WGnafConf     = 0.5
	WGeocodeRel   = 0.25
	WDistance     = 0.3    // applied only when an anchor is present
	DistanceScale = 5000.0 // metres at which distance penalty saturates

	// Full-scale values of the refining inputs, used to normalise them.
	MaxGnafConfidence     = 2.0
	MaxGeocodeReliability = 6.0
)

// Composite returns the composite score for a candidate.
func Composite(c contract.Candidate) Score {
	s := WMatch * c.MatchScore
	if c.GnafPID != "" {
		s += WGnafConf * clamp01(float64(c.GnafConfidence)/MaxGnafConfidence)
		s += WGeocodeRel * clamp01(float64(c.GeocodeReliability)/MaxGeocodeReliability)
	}
	if c.DistanceM != nil {
		d := *c.DistanceM
		s -= WDistance * math.Min(d/DistanceScale, 1.0)
	}
	return Score(s)
}

// Rank sorts candidates by composite score descending, ties broken by source
// preference (G-NAF before OSM — authoritative data wins) then distance.
// Returns the top n, or all if n <= 0.
func Rank(cs []contract.Candidate, n int) []contract.Candidate {
	out := make([]contract.Candidate, len(cs))
	copy(out, cs)
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := Composite(out[i]), Composite(out[j])
		if si != sj {
			return si > sj
		}
		if out[i].Source != out[j].Source {
			return out[i].Source == "gnaf"
		}
		if out[i].DistanceM != nil && out[j].DistanceM != nil {
			return *out[i].DistanceM < *out[j].DistanceM
		}
		return false
	})
	if n > 0 && len(out) > n {
		return out[:n]
	}
	return out
}

// clamp01 bounds a normalised input to 0..1, so an out-of-range value from a
// future dataset cannot silently outweigh match quality.
func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	}
	return v
}

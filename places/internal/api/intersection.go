package api

// Intersections: "cnr Bourke St & Swanston St Melbourne" names the point where
// two streets meet. /resolve answers it at PrecisionIntersection, but only when
// both streets are in the named locality (or, with none named, a locality that
// has both) and actually meet there. Anything else declines, so text that only
// has the shape ("woolworths near doncaster and blackburn road") moves on to
// the other readings and the POI rungs.

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"auplaces/internal/match"
	"auplaces/internal/normalise"
	"ausystem/shared/contract"
)

// maxInferLocalities bounds the localities tried when the text names none.
// Two common names (HIGH STREET, STATION STREET) share dozens; past this the
// text is too vague to answer.
const maxInferLocalities = 40

// sameCornerM: meetings this close, found from neighbouring localities, are
// one corner (a boundary street seen from both sides).
const sameCornerM = 100

// resolveIntersection answers a parsed intersection, or returns no
// candidates (and no error) when the streets are not found or do not meet.
func resolveIntersection(ctx context.Context, db *sql.DB, sets *matchSets, ix normalise.Intersection, limit int) (contract.ResolveResponse, error) {
	type try struct {
		a, b     string
		locality string
		score    float64
	}
	var tries []try
	switch {
	case ix.Locality != "":
		if !sets.localities[ix.Locality] {
			return contract.ResolveResponse{}, nil
		}
		a, simA := sets.fuzzy.NearestStreetIn(ix.A.Name, ix.Locality)
		b, simB := sets.fuzzy.NearestStreetIn(ix.B.Name, ix.Locality)
		if simA < nearStreetCoarse || simB < nearStreetCoarse {
			return contract.ResolveResponse{}, nil
		}
		tries = append(tries, try{a, b, ix.Locality, simA * simB})
	default:
		// No locality: every locality holding both names exactly, narrowed to
		// the postcode when there is one.
		inB := map[string]bool{}
		for _, l := range sets.fuzzy.LocalitiesOf(ix.B.Name) {
			inB[l] = true
		}
		for _, l := range sets.fuzzy.LocalitiesOf(ix.A.Name) {
			if inB[l] {
				tries = append(tries, try{ix.A.Name, ix.B.Name, l, 1})
			}
		}
		if len(tries) > maxInferLocalities {
			return contract.ResolveResponse{}, nil
		}
	}

	type found struct {
		try
		m *match.Meeting
	}
	// With no locality named, the busiest place goes first: "cnr Bourke St
	// & Swanston St" is more likely the city than a suburb with the same
	// two street names.
	var all []found
	sc := match.NewStreetCache(db)
	for _, t := range tries {
		m, err := match.StreetsMeet(ctx, sc,
			match.StreetRef{Name: t.a, Type: ix.A.Type}, match.StreetRef{Name: t.b, Type: ix.B.Type}, t.locality)
		if err != nil {
			return contract.ResolveResponse{}, err
		}
		if m == nil || ix.Postcode != "" && ix.Locality == "" && m.Postcode != ix.Postcode {
			continue
		}
		all = append(all, found{t, m})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].m.Rows > all[j].m.Rows })
	var hits []found
	for _, f := range all {
		dup := false
		for _, h := range hits {
			if match.HaversineM(h.m.Lat, h.m.Lon, f.m.Lat, f.m.Lon) < sameCornerM {
				dup = true
				break
			}
		}
		if !dup {
			hits = append(hits, f)
		}
	}
	if len(hits) == 0 {
		return contract.ResolveResponse{}, nil
	}

	var cands []contract.Candidate
	for _, h := range hits {
		streets := []string{
			strings.TrimSpace(h.a + " " + h.m.TypeA),
			strings.TrimSpace(h.b + " " + h.m.TypeB),
		}
		sort.Strings(streets)
		score := h.score
		if len(hits) > 1 {
			score *= 0.8 // the text fits more than one corner
		}
		cands = append(cands, contract.Candidate{
			ID:                 contract.CandidateID{Source: "gnaf", PID: "intersection:" + streets[0] + "|" + streets[1] + "|" + h.locality},
			Kind:               contract.KindAddress,
			Precision:          contract.PrecisionIntersection,
			Point:              contract.Point{Lat: h.m.Lat, Lon: h.m.Lon},
			Source:             "gnaf",
			Text:               streets[0] + " & " + streets[1] + ", " + placeText(h.locality, h.m.State, h.m.Postcode),
			GeocodeReliability: reliabilityStreet,
			MatchScore:         score,
		})
	}
	resp := contract.ResolveResponse{GeneratedCount: len(cands), TotalMatched: len(cands)}
	if len(cands) > limit {
		resp.Truncated = true
		cands = cands[:limit]
	}
	resp.Candidates = cands
	resp.DatasetVersion = datasetVersion(ctx, db)
	return resp, nil
}

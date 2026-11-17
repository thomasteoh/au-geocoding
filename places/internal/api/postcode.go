package api

// Postcode-level answers. The centre of a postcode's addresses is usually the
// best point for it (it sits where people are), but an average can fall
// outside an oddly shaped area, between two arms of it, and a PO box postcode
// has no addresses at all. So:
//
//   - the address average, when it lies inside the postcode's ABS postal area
//     (or the dataset has no postal areas);
//   - otherwise the area's representative point, which is always inside it;
//   - a postcode with no addresses and no area: the locality a curated PO box
//     table (internal/postbox) says it is delivered at.

import (
	"context"
	"database/sql"

	"auplaces/internal/match"
	"auplaces/internal/postbox"
	"ausystem/shared/contract"
)

// postcodeCentre answers postcode with one candidate per state.
func postcodeCentre(ctx context.Context, db *sql.DB, postcode string) ([]contract.Candidate, error) {
	cands, err := placeCentre(ctx, db, contract.PrecisionPostcode, `postcode = ?`, postcode)
	if err != nil {
		return nil, err
	}
	for i := range cands {
		inside, known, err := match.PostcodeContains(ctx, db, postcode, cands[i].Point.Lon, cands[i].Point.Lat)
		if err != nil {
			return nil, err
		}
		if known && !inside {
			lat, lon, _, err := match.PostcodePoint(ctx, db, postcode)
			if err != nil {
				return nil, err
			}
			cands[i].Point = contract.Point{Lat: lat, Lon: lon}
		}
	}
	if len(cands) > 0 {
		return cands, nil
	}
	if lat, lon, ok, err := match.PostcodePoint(ctx, db, postcode); err != nil || ok {
		if !ok {
			return nil, err
		}
		return []contract.Candidate{{
			ID:                 contract.CandidateID{Source: "abs", PID: "postcode:" + postcode},
			Kind:               contract.KindLocality,
			Precision:          contract.PrecisionPostcode,
			Point:              contract.Point{Lat: lat, Lon: lon},
			Source:             "abs",
			Text:               "VIC " + postcode,
			GeocodeReliability: reliabilityLocality,
			MatchScore:         1,
		}}, nil
	}
	e, ok := postbox.Lookup(postcode)
	if !ok {
		return nil, nil
	}
	locs, err := placeCentre(ctx, db, contract.PrecisionPostcode, `locality_name = ? AND state = ?`, e.Locality, e.State)
	if err != nil || len(locs) == 0 {
		return nil, err
	}
	c := locs[0]
	c.ID = contract.CandidateID{Source: "gnaf", PID: "postcode:" + postcode}
	c.Text = placeText(e.Locality, e.State, postcode)
	return []contract.Candidate{c}, nil
}

// poboxLocality is the locality a PO box postcode is delivered at, when the
// curated table knows it and the dataset has it; "" otherwise.
func poboxLocality(sets *matchSets, postcode string) string {
	if e, ok := postbox.Lookup(postcode); ok && sets.localities[e.Locality] {
		return e.Locality
	}
	return ""
}

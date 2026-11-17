package api

// Coarse resolution: a query that names a street but no number, or only a
// locality or postcode, still has a right answer — the centre of that street,
// locality or postcode — as long as the response says that is what it is
// (Candidate.Precision). These levels are deliberately strict: /resolve is tried
// before POI search, so a coarse level only answers when the text is clearly a
// street in a known place or exactly a locality or postcode. Anything else
// returns no candidates and the caller moves on.

import (
	"context"
	"database/sql"
	"strings"

	"auplaces/internal/match"
	"ausystem/shared/contract"
)

// nearStreetCoarse is how close a misspelt street name must be to a street in
// the named locality. It is stricter than generation's threshold because a
// coarse answer has no street number to confirm it.
const nearStreetCoarse = 0.8

// Geocode reliability for coarse points, on the dataset's higher-is-better
// scale (see buildaddr): G-NAF's STREET LOCALITY and LOCALITY geocode types.
const (
	reliabilityStreet   = 3
	reliabilityLocality = 1
)

// resolveCoarse answers an address request that has no street number and
// street, or no street at all. It returns errNoCandidates when the text is not
// clearly a street, locality or postcode.
func resolveCoarse(ctx context.Context, db *sql.DB, sets *matchSets, q match.Query, limit int) (contract.ResolveResponse, error) {
	if hasUntagged(q) {
		return contract.ResolveResponse{}, &resolveError{errNoCandidates}
	}
	street, locality, postcode := q.Field("street_name"), q.Field("locality_name"), q.Field("postcode")
	if locality != "" && !sets.localities[locality] {
		locality = ""
	}
	var cands []contract.Candidate
	var err error
	switch {
	case street != "":
		if countField(q, "street_name") != 1 || locality == "" {
			break
		}
		cands, err = streetLevel(ctx, db, sets, street, q.Field("street_type"), locality)
	case locality != "":
		cands, err = localityLevel(ctx, db, locality, postcode)
	case postcode != "":
		cands, err = postcodeLevel(ctx, db, postcode)
	}
	if err != nil {
		return contract.ResolveResponse{}, err
	}
	if len(cands) == 0 {
		return contract.ResolveResponse{}, &resolveError{errNoCandidates}
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

// resolvePostal answers a postal delivery point: a PO box, GPO box, locked
// bag or private bag. G-NAF has no location for one, so the answer is the
// centre of the locality it is addressed to, or of its postcode when no known
// locality is named, with Candidate.PostalDelivery set so the caller can tell
// a postal box from a street that could not be found. The locality goes first
// because PO box postcodes (3001, 8001) often hold no street address at all;
// a postcode that does not match the locality is ignored, as in
// localityLevel. Other words are ignored too: a postal box has no street.
func resolvePostal(ctx context.Context, db *sql.DB, sets *matchSets, q match.Query, box string, limit int) (contract.ResolveResponse, error) {
	locality, postcode := q.Field("locality_name"), q.Field("postcode")
	var cands []contract.Candidate
	var err error
	switch {
	case sets.localities[locality]:
		cands, err = localityLevel(ctx, db, locality, postcode)
	case postcode != "":
		cands, err = postcodeLevel(ctx, db, postcode)
	}
	if err != nil {
		return contract.ResolveResponse{}, err
	}
	if len(cands) == 0 {
		return contract.ResolveResponse{}, &resolveError{errNoCandidates}
	}
	for i := range cands {
		cands[i].PostalDelivery = box
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

// streetLevel returns the centre of the named street in locality, one
// candidate per street type ("COLLINS STREET" and "COLLINS WAY" are different
// streets), the asked-for type first.
func streetLevel(ctx context.Context, db *sql.DB, sets *matchSets, street, streetType, locality string) ([]contract.Candidate, error) {
	name, sim := sets.fuzzy.NearestStreetIn(street, locality)
	if name == "" || sim < nearStreetCoarse {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT street_type, state, MIN(postcode), AVG(latitude), AVG(longitude)
		FROM address WHERE street_name = ? AND locality_name = ?
		GROUP BY street_type, state
		ORDER BY COALESCE(street_type, '') = ? DESC, COUNT(*) DESC`,
		name, locality, streetType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []contract.Candidate
	for rows.Next() {
		var typ, state, pc sql.NullString
		var lat, lon float64
		if err := rows.Scan(&typ, &state, &pc, &lat, &lon); err != nil {
			return nil, err
		}
		score := sim
		if streetType != "" && typ.String != streetType {
			score *= 0.9
		}
		full := strings.TrimSpace(name + " " + typ.String)
		out = append(out, contract.Candidate{
			ID:                 contract.CandidateID{Source: "gnaf", PID: "street:" + full + "|" + locality},
			Kind:               contract.KindAddress,
			Precision:          contract.PrecisionStreet,
			Point:              contract.Point{Lat: lat, Lon: lon},
			Source:             "gnaf",
			Text:               full + ", " + placeText(locality, state.String, pc.String),
			GeocodeReliability: reliabilityStreet,
			MatchScore:         score,
		})
	}
	return out, rows.Err()
}

// localityLevel returns the centre of a locality's addresses. A postcode that
// does not match the locality is ignored rather than failing the lookup.
func localityLevel(ctx context.Context, db *sql.DB, locality, postcode string) ([]contract.Candidate, error) {
	if postcode != "" {
		out, err := placeCentre(ctx, db, contract.PrecisionLocality,
			`locality_name = ? AND postcode = ?`, locality, postcode)
		if err != nil || len(out) > 0 {
			return out, err
		}
	}
	return placeCentre(ctx, db, contract.PrecisionLocality, `locality_name = ?`, locality)
}

// postcodeLevel returns the centre of a postcode's addresses.
func postcodeLevel(ctx context.Context, db *sql.DB, postcode string) ([]contract.Candidate, error) {
	return placeCentre(ctx, db, contract.PrecisionPostcode, `postcode = ?`, postcode)
}

// placeCentre averages the address points matching where. Localities are
// grouped by name and state (one candidate per same-named locality); a postcode
// gives one candidate. The text names the postcode only when it is the only
// one, since many localities span several.
func placeCentre(ctx context.Context, db *sql.DB, p contract.Precision, where string, args ...any) ([]contract.Candidate, error) {
	group := `locality_name, state`
	if p == contract.PrecisionPostcode {
		group = `postcode, state`
	}
	rows, err := db.QueryContext(ctx, `
		SELECT `+group+`, COUNT(DISTINCT postcode), MIN(postcode), COUNT(DISTINCT locality_name),
		       AVG(latitude), AVG(longitude)
		FROM address WHERE `+where+`
		GROUP BY `+group+` ORDER BY COUNT(*) DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []contract.Candidate
	for rows.Next() {
		var key, state, pc sql.NullString
		var nPostcodes, nLocalities int
		var lat, lon float64
		if err := rows.Scan(&key, &state, &nPostcodes, &pc, &nLocalities, &lat, &lon); err != nil {
			return nil, err
		}
		c := contract.Candidate{
			Kind:               contract.KindLocality,
			Precision:          p,
			Point:              contract.Point{Lat: lat, Lon: lon},
			Source:             "gnaf",
			GeocodeReliability: reliabilityLocality,
			MatchScore:         1,
		}
		if p == contract.PrecisionPostcode {
			c.ID = contract.CandidateID{Source: "gnaf", PID: "postcode:" + key.String}
			c.Text = strings.TrimSpace(state.String + " " + key.String)
		} else {
			if nPostcodes != 1 {
				pc.String = ""
			}
			c.ID = contract.CandidateID{Source: "gnaf", PID: "locality:" + key.String + "|" + state.String}
			c.Text = placeText(key.String, state.String, pc.String)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func placeText(locality, state, postcode string) string {
	return strings.Join(strings.Fields(locality+" "+state+" "+postcode), " ")
}

// hasUntagged reports words that fit no address part: the text is not just a
// street, locality or postcode.
func hasUntagged(q match.Query) bool {
	for _, f := range q.Fields {
		if f == "" {
			return true
		}
	}
	return false
}

func countField(q match.Query, name string) int {
	n := 0
	for _, f := range q.Fields {
		if f == name {
			n++
		}
	}
	return n
}

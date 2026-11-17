package api

// POST /resolve — the split-service contract endpoint. The geocoder (public
// API) calls this with a structured resolution request; au-places resolves it
// against the data and returns candidates.
//
// This is the single interface between the two services. It maps the request
// Kind (Address | POI | Reverse | Locality) to the existing internal resolvers
// (search/reverse/locality) and exposes the G-NAF quality axes (confidence,
// reliability) plus a computed MatchScore — the ranker's inputs — which the
// plain /search response does not carry.
//
// The wire types below mirror the geocoder's contract (internal/contract) JSON
// shape. au-places is a separate Go module and cannot import the geocoder's
// internal package, so it defines matching structs with the same json tags.
// The field names and tags are the wire contract — they must stay in sync with
// contract.go (both sides round-trip the same JSON).
//
// The contract is versioned: X-Augeo-Contract-Version must match; a mismatch is
// a startup failure (contract.md § Versioning), not a per-request error.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"auplaces/internal/match"
	"auplaces/internal/normalise"
	"ausystem/shared/contract"
)

// The version this side implements and the header carrying it come from the
// shared contract package, so the two services cannot drift apart: bumping
// contract.Version moves both, and a deployment mixing old and new binaries
// fails the version check instead of mis-reading the wire format.
const (
	contractVersion       = contract.Version
	contractVersionHeader = contract.ContractVersionHeader
)

// Wire error strings mirror the geocoder's contract error taxonomy. The wire
// protocol carries them as HTTP status + error string; the geocoder's
// placesclient maps them back to its own errors (it checks for "out_of_scope").
const (
	errNoCandidates = "no candidates"
	errOutOfScope   = "out_of_scope"
	errNotLoaded    = "not_loaded"

	// Request bound caps (security): Limit, MaxRadiusM and token slices are
	// caller-controlled — clamp them so an expensive query can't be driven
	// unbounded. Match the geocoder's limits.
	maxResults = 20
	maxRadiusM = 5000
	maxTokens  = 32

	// generateCap bounds how many address candidates are scored per query.
	generateCap = 200
)

// ResolveHandler is the /resolve HTTP handler. p provides the active serving DB.
func ResolveHandler(p *DBProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		// Contract version enforcement (contract.md § Versioning): a mismatch is
		// a startup failure — refuse with a distinct signal so the caller can
		// fail fast at boot, not silently per-call.
		if v := r.Header.Get(contractVersionHeader); v != "" && v != contractVersion {
			writeJSONError(w, http.StatusBadRequest, "contract version mismatch")
			return
		}
		var req contract.ResolveRequest
		LimitBody(w, r)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request")
			return
		}
		// Clamp request bounds: Limit, MaxRadiusM, and token slices are all
		// caller-controlled. Cap them so an expensive query can't be driven
		// unbounded (perf/DoS-lite; the SQL is parameterized, not injection).
		if req.Limit > maxResults {
			req.Limit = maxResults
		}
		if req.MaxRadiusM > maxRadiusM {
			req.MaxRadiusM = maxRadiusM
		}
		if len(req.Generate) > maxTokens {
			req.Generate = req.Generate[:maxTokens]
		}
		if len(req.Score) > maxTokens {
			req.Score = req.Score[:maxTokens]
		}
		resp, err := Resolve(r.Context(), p.Get(), req)
		if err != nil {
			writeResolveError(w, err)
			return
		}
		// Echo the contract version so the caller can verify which wire format
		// it got (UX review finding #3: no endpoint returned it).
		w.Header().Set(contractVersionHeader, contractVersion)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// writeResolveError maps the local error taxonomy to HTTP status + wire error
// string, matching the geocoder's placesclient expectations. Errors are JSON
// with application/json (UX review finding #4: http.Error forced text/plain).
func writeResolveError(w http.ResponseWriter, err error) {
	switch err.Error() {
	case errOutOfScope, errNoCandidates:
		writeJSONError(w, http.StatusBadRequest, err.Error())
	case errNotLoaded:
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, "resolve failed")
	}
}

// Resolve dispatches a contract request to the internal resolver by Kind.
// It never re-parses free text — the contract carries structured intent.
func Resolve(ctx context.Context, db *sql.DB, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	switch req.Kind {
	case contract.KindAddress:
		return resolveAddress(ctx, db, req)
	case contract.KindPOI:
		return resolvePOI(ctx, db, req)
	case contract.KindReverse:
		return resolveReverse(ctx, db, req)
	case contract.KindLocality, contract.KindContains:
		return resolveLocality(ctx, db, req)
	default:
		return contract.ResolveResponse{}, &resolveError{errNoCandidates}
	}
}

// resolveError is a typed error carrying the wire error string.
type resolveError struct{ msg string }

func (e *resolveError) Error() string { return e.msg }

// resolveAddress resolves a structured address request (rung 2). Generate on
// the reliable tokens, score on the full set, expose G-NAF quality.
func resolveAddress(ctx context.Context, db *sql.DB, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	sets, err := setsFor(db)
	if err != nil {
		return contract.ResolveResponse{}, err
	}
	var rel, score, fields []string
	var text string // the free text, for the intersection reading
	if req.Components != nil {
		// The caller labelled every value, so no inference is needed or wanted.
		// fieldOfToken has to guess from token shape and gets genuinely
		// ambiguous cases wrong — "ST" is both a street type and a state-like
		// token, "3000" is a postcode but could be a street number. Structured
		// input exists precisely to remove that guess.
		rel, score, fields = componentTokens(*req.Components)
	} else {
		text = contractText(req.Generate, req.Score)
		rel, score, fields = normalise.Tokenise(text, maxTokens, sets.localities, sets.fuzzy.NearestLocality)
	}
	rel, score, fields = sets.fuzzy.CanonicalTokens(rel, score, fields) // aliases -> official names
	qm := match.Query{Reliable: rel, Score: score, Fields: fields}
	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}
	// A query for a state this dataset does not cover is refused before any
	// matching: fuzzy generation would find some street of the same name here.
	// The parsed state wins over the caller's state hint. The postcode hint is
	// not used: the geocoder's parser takes any later four-digit word for one,
	// where this parser knows a street number by position.
	state := qm.Field("state")
	if state == "" {
		state = req.State
	}
	if outOfScope(sets, state, qm.Field("postcode"), qm.Field("locality_name")) {
		return contract.ResolveResponse{}, &resolveError{errOutOfScope}
	}
	// A postal box with no street address beside it has no G-NAF row: answer
	// at the locality or postcode it is addressed to, marked as a postal box.
	number := qm.Field("street_number")
	if number == "" {
		number = qm.Field("lot_number") // a lot stands in for the number
	}
	if box := qm.Field("postal_delivery"); box != "" && number == "" {
		return resolvePostal(ctx, db, sets, qm, box, limit)
	}
	// Two streets that meet ("cnr Bourke St & Swanston St Melbourne"). Text
	// that only looks like one falls through to the readings below.
	if number == "" && text != "" {
		if ix, ok := normalise.ParseIntersection(text, maxTokens, sets.localities, sets.fuzzy.NearestLocality); ok {
			resp, err := resolveIntersection(ctx, db, sets, ix, limit)
			if err != nil || len(resp.Candidates) > 0 {
				return resp, err
			}
		}
	}
	// No street number, or no street: answer at street, locality or postcode
	// precision, or not at all.
	if number == "" || qm.Field("street_name") == "" {
		return resolveCoarse(ctx, db, sets, qm, limit)
	}
	cands, _ := match.Generate(ctx, db, qm, sets.fuzzy, generateCap)

	resp := contract.ResolveResponse{GeneratedCount: len(cands)}
	if len(cands) == 0 {
		return resp, &resolveError{errNoCandidates}
	}

	// Rank by score, apply the caller's limit AFTER ordering (contract.md).
	scored := make([]scoredCandidate, 0, len(cands))
	for _, c := range cands {
		sc := match.Score(qm, c)
		scored = append(scored, scoredCandidate{c: c, s: sc})
	}
	sortScored(scored)
	if len(scored) > limit {
		resp.Truncated = true
		scored = scored[:limit]
	}
	resp.TotalMatched = len(cands)

	// G-NAF quality columns (confidence, geocode reliability) live in the
	// address table but not in the match Candidate — one batched query.
	quality := loadQuality(ctx, db, scored)
	for _, sc := range scored {
		c := sc.c
		q := quality[c.PID]
		resp.Candidates = append(resp.Candidates, contract.Candidate{
			ID:                 contract.CandidateID{Source: "gnaf", PID: c.PID},
			Kind:               contract.KindAddress,
			Precision:          contract.PrecisionAddress,
			Point:              contract.Point{Lat: c.Lat, Lon: c.Lon},
			Source:             "gnaf",
			Text:               formatCandidateText(c),
			GnafPID:            c.PID,
			GnafConfidence:     q.confidence,
			GeocodeReliability: q.reliability,
			MatchScore:         sc.s,
		})
	}
	resp.DatasetVersion = datasetVersion(ctx, db)
	return resp, nil
}

// resolvePOI resolves a POI request (rung 4). The contract carries the POI name
// (Generate) and optionally an anchor for distance ranking.
func resolvePOI(ctx context.Context, db *sql.DB, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	name := strings.Join(req.Generate, " ")
	if name == "" {
		name = strings.Join(req.Score, " ")
	}
	if name == "" {
		return contract.ResolveResponse{}, &resolveError{errNoCandidates}
	}
	var anchor *match.Point
	if req.Anchor != nil {
		anchor = &match.Point{Lat: req.Anchor.Lat, Lon: req.Anchor.Lon}
	}
	cands, _ := match.LookupPOI(ctx, db, name, 200, anchor)

	resp := contract.ResolveResponse{GeneratedCount: len(cands)}
	if len(cands) == 0 {
		return resp, &resolveError{errNoCandidates}
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}
	if len(cands) > limit {
		resp.Truncated = true
		cands = cands[:limit]
	}
	resp.TotalMatched = len(cands)
	for _, c := range cands {
		var dist *float64
		if req.Anchor != nil {
			d := c.DistanceM
			dist = &d
		}
		resp.Candidates = append(resp.Candidates, contract.Candidate{
			ID:         contract.CandidateID{Source: "osm", PID: c.OsmID},
			Kind:       contract.KindPOI,
			Point:      contract.Point{Lat: c.Lat, Lon: c.Lon},
			Source:     "osm",
			Text:       c.Name,
			Name:       c.Name,
			Brand:      c.Brand,
			Operator:   c.Operator,
			DistanceM:  dist,
			MatchScore: c.Score,
		})
	}
	resp.DatasetVersion = datasetVersion(ctx, db)
	return resp, nil
}

// resolveReverse resolves a reverse request (coordinate → nearest address).
// It uses the real RTree nearest (addr_rt), not a coord echo.
func resolveReverse(ctx context.Context, db *sql.DB, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	if req.Anchor == nil {
		return contract.ResolveResponse{}, &resolveError{errNoCandidates}
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 5
	}
	res, err := match.ReverseWithin(ctx, db, req.Anchor.Lon, req.Anchor.Lat, limit, float64(req.MaxRadiusM))
	if err != nil {
		return contract.ResolveResponse{}, err
	}
	if len(res) == 0 {
		return contract.ResolveResponse{}, &resolveError{errNoCandidates}
	}
	resp := contract.ResolveResponse{GeneratedCount: len(res), TotalMatched: len(res)}
	for _, c := range res {
		d := c.DistanceM
		resp.Candidates = append(resp.Candidates, contract.Candidate{
			ID:        contract.CandidateID{Source: "gnaf", PID: c.PID},
			Kind:      contract.KindAddress,
			Precision: contract.PrecisionAddress,
			Point:     contract.Point{Lat: c.Lat, Lon: c.Lon},
			Source:    "gnaf",
			Text:      formatAddress(c),
			GnafPID:   c.PID,
			DistanceM: &d,
		})
	}
	resp.DatasetVersion = datasetVersion(ctx, db)
	return resp, nil
}

// resolveLocality resolves a locality containment request (point → containing
// locality). It uses the boundary geopoly index.
func resolveLocality(ctx context.Context, db *sql.DB, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	if req.Anchor == nil {
		return contract.ResolveResponse{}, &resolveError{errNoCandidates}
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 3
	}
	hits, err := match.LocalityAt(ctx, db, req.Anchor.Lon, req.Anchor.Lat, limit)
	if err != nil {
		return contract.ResolveResponse{}, err
	}
	if len(hits) == 0 {
		return contract.ResolveResponse{}, &resolveError{errNoCandidates}
	}
	resp := contract.ResolveResponse{GeneratedCount: len(hits), TotalMatched: len(hits)}
	for _, h := range hits {
		resp.Candidates = append(resp.Candidates, contract.Candidate{
			Kind:    contract.KindLocality,
			Text:    h.Name,
			GnafPID: h.LocPID,
		})
	}
	resp.DatasetVersion = datasetVersion(ctx, db)
	return resp, nil
}

// ---- helpers ----

// scoredCandidate is a match.Candidate plus its score, for sort-then-cap.
type scoredCandidate struct {
	c match.Candidate
	s float64
}

func sortScored(sc []scoredCandidate) {
	for i := 1; i < len(sc); i++ {
		for j := i; j > 0 && sc[j].s > sc[j-1].s; j-- {
			sc[j], sc[j-1] = sc[j-1], sc[j]
		}
	}
}

// quality is the G-NAF quality axes for one address row.
type quality struct {
	confidence  int8
	reliability int8
}

// loadQuality loads confidence/geocode_rel for the selected PIDs.
func loadQuality(ctx context.Context, db *sql.DB, sc []scoredCandidate) map[string]quality {
	out := map[string]quality{}
	if len(sc) == 0 {
		return out
	}
	pids := make([]string, 0, len(sc))
	for _, s := range sc {
		pids = append(pids, s.c.PID)
	}
	ph := strings.Repeat("?,", len(pids))
	ph = strings.TrimSuffix(ph, ",")
	args := make([]any, len(pids))
	for i, p := range pids {
		args[i] = p
	}
	rows, err := db.QueryContext(ctx, `SELECT gnaf_pid, confidence, geocode_rel FROM address WHERE gnaf_pid IN (`+ph+`)`, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var pid string
		var conf, rel int8
		if err := rows.Scan(&pid, &conf, &rel); err == nil {
			out[pid] = quality{confidence: conf, reliability: rel}
		}
	}
	return out
}

// componentTokens builds the match inputs from labelled components. Each value
// carries its own field tag, so the scorer compares like with like without any
// token-shape heuristic.
//
// Generation anchors are the street name and locality only: the trigram index
// does not cover tokens under three characters, so a street number cannot
// anchor generation and is carried as a scoring signal instead — the same rule
// the free-text path follows. Values are upper-cased to match the dataset; the
// geocoder folds them to lower case.
func componentTokens(c contract.AddressComponents) (reliable, sc, fields []string) {
	add := func(v, field string) {
		v = strings.ToUpper(v)
		if v == "" {
			return
		}
		sc = append(sc, v)
		fields = append(fields, field)
	}
	add(c.StreetNumber, "street_number")
	add(leadingDigits(c.Unit), "flat_number")
	add(leadingDigits(c.Lot), "lot_number")
	add(c.StreetName, "street_name")
	add(c.StreetType, "street_type")
	add(c.Locality, "locality_name")
	add(c.State, "state")
	add(c.Postcode, "postcode")

	seen := map[string]bool{}
	for _, t := range []string{c.StreetName, c.Locality} {
		t = strings.ToUpper(t)
		if len(t) >= 3 && !seen[t] {
			seen[t] = true
			reliable = append(reliable, t)
		}
	}
	return reliable, sc, fields
}

// leadingDigits reduces a unit or lot to the digits the dataset stores ("3A"
// is unit 3), the same reading the free-text parser gives it. A value with no
// leading digits is kept, so it still scores against the column.
func leadingDigits(v string) string {
	v = strings.TrimSpace(v)
	n := 0
	for n < len(v) && v[n] >= '0' && v[n] <= '9' {
		n++
	}
	if n == 0 {
		return v
	}
	return v[:n]
}

// contractText is the free text the contract's token sets carry. Score is the
// geocoder's full normalised token list, in query order; the parts of an
// address are known by position, so the tokens are parsed as a sequence with
// the same parser as /search, not classified one at a time.
func contractText(gen, score []string) string {
	toks := score
	if len(toks) == 0 {
		toks = gen
	}
	return strings.Join(toks, " ")
}

// formatCandidateText builds the display address text for a candidate. A unit
// row reads "2/36 COLLINS STREET", a lot "LOT 14 OLD SYDNEY ROAD".
func formatCandidateText(c match.Candidate) string {
	parts := []string{}
	switch {
	case c.FlatNumber != "" && c.StreetNumber != "":
		parts = append(parts, c.FlatNumber+"/"+c.StreetNumber)
	case c.StreetNumber != "":
		parts = append(parts, c.StreetNumber)
	case c.LotNumber != "":
		parts = append(parts, "LOT "+c.LotNumber)
	}
	if c.StreetName != "" {
		parts = append(parts, c.StreetName)
	}
	if c.StreetType != "" {
		parts = append(parts, c.StreetType)
	}
	if len(parts) == 0 {
		return c.Locality
	}
	s := strings.Join(parts, " ") + ", " + c.Locality
	if c.State != "" {
		s += " " + c.State
	}
	if c.Postcode != "" {
		s += " " + c.Postcode
	}
	return s
}

// datasetVersion reads the dataset version from the DB (INV-5). Handlers no
// longer hardcode it — the version comes from the open dataset.
func datasetVersion(ctx context.Context, db *sql.DB) string {
	var v string
	if err := db.QueryRowContext(ctx, `SELECT dataset_version FROM address LIMIT 1`).Scan(&v); err != nil {
		return ""
	}
	return v
}

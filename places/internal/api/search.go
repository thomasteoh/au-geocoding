package api

// POST /search — the free-text endpoint that walks the parse ladder. It takes
// raw text, classifies it (strategy package), resolves the plan against the
// data (match package), and returns candidates with the strategy that fired.
//
// The demo exit: "woolworths near doncaster and blackburn road" resolves via
// poi_anchor with NO LLM call. Every response carries strategy so the caller
// (and the demo UI) sees which rung fired.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"auplaces/internal/match"
	"auplaces/internal/normalise"
	"auplaces/internal/strategy"
)

// SearchRequest is the /search request body.
type SearchRequest struct {
	Query string `json:"query"`
	State string `json:"state,omitempty"` // optional state hint
	// Limit caps the number of candidates returned. 0 means the server default
	// (maxResults, declared in resolve.go). Without this field a caller could
	// never request more than the hardcoded 20, and total/generated would report
	// a count the caller could not actually receive (UX review finding #1).
	Limit int `json:"limit,omitempty"`
}

// MaxQueryLen caps the /search query string length before normalisation
// (D-032). A huge query through Tokenise/Classify allocates disproportionately
// and can OOM the server; the body limit alone is not enough. Matches the
// geocoder's MaxQueryLen=256.
const MaxQueryLen = 256

// SearchResponse is the /search response.
type SearchResponse struct {
	Strategy   string      `json:"strategy"`
	Candidates []Candidate `json:"candidates"`
	Ambiguous  []Ambiguous `json:"ambiguous,omitempty"`
	Truncated  bool        `json:"truncated"`
	Total      int         `json:"total"`
	Generated  int         `json:"generated"`
	Version    string      `json:"dataset_version"`
	Anchor     *Anchor     `json:"anchor,omitempty"`
	// Attribution (D-018): present when the response carries an OSM-derived
	// POI, per the ODbL requirement. Empty otherwise.
	Attribution string `json:"attribution,omitempty"`
}

// Candidate is the API-facing candidate (address or POI).
type Candidate struct {
	ID       string  `json:"id"`
	Kind     string  `json:"kind"`
	Name     string  `json:"name,omitempty"`
	Address  string  `json:"address,omitempty"`
	Brand    string  `json:"brand,omitempty"`
	Lat      float64 `json:"latitude"`
	Lon      float64 `json:"longitude"`
	Distance float64 `json:"distance_m,omitempty"`
	Source   string  `json:"source"`
	Match    float64 `json:"match_score,omitempty"`
	Conf     int     `json:"gnaf_confidence,omitempty"`
	Rel      int     `json:"geocode_reliability,omitempty"`
}

// Ambiguous is a locality ambiguity result.
type Ambiguous struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// Anchor is the resolved anchor point.
type Anchor struct {
	Lat float64 `json:"latitude"`
	Lon float64 `json:"longitude"`
}

// SearchHandler is the /search HTTP handler. p provides the active serving DB.
func SearchHandler(p *DBProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		// Contract version enforcement (contract.md § Versioning): a mismatch is
		// a startup failure — refuse with a distinct signal so the caller can
		// fail fast at boot, not silently per-call. Matches /resolve and /suggest.
		// Previously /search ignored the header entirely (UX review finding #3).
		if v := r.Header.Get(contractVersionHeader); v != "" && v != contractVersion {
			writeJSONError(w, http.StatusBadRequest, "contract version mismatch")
			return
		}
		var req SearchRequest
		LimitBody(w, r)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad request")
			return
		}
		req.Query = strings.TrimSpace(req.Query)
		if req.Query == "" {
			writeJSONError(w, http.StatusBadRequest, "empty query")
			return
		}
		// D-032: cap the query length before normalisation. A huge query string
		// through Tokenise/Classify allocates disproportionately (a 500KB query
		// spikes RSS ~500MB) — without this cap an attacker can OOM the server.
		// Match the geocoder's MaxQueryLen=256.
		if len(req.Query) > MaxQueryLen {
			writeJSONError(w, http.StatusBadRequest, "query too long")
			return
		}
		// Clamp the caller's Limit to the server bound (perf/DoS-lite, matching
		// the resolve handler's clamp on ResolveRequest.Limit).
		if req.Limit > maxResults {
			req.Limit = maxResults
		}

		resp := Search(context.Background(), p.Get(), req)
		// Echo the contract version so the caller can verify which wire
		// format it got (UX review finding #3).
		w.Header().Set(contractVersionHeader, contractVersion)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Attribution is the ODbL attribution string for OSM-derived responses (D-018).
const Attribution = "© OpenStreetMap contributors, ODbL 1.0 — https://www.openstreetmap.org/copyright"

// Search walks the ladder for a query. It is the deterministic resolver —
// no LLM. Returns the response with the strategy that fired.
func Search(ctx context.Context, db *sql.DB, req SearchRequest) SearchResponse {
	limit := req.Limit
	if limit <= 0 {
		limit = maxResults
	}
	plan := strategy.Classify(req.Query)
	switch plan.Strategy {
	case strategy.StrategyCoord:
		return searchCoord(ctx, db, plan.Query)
	case strategy.StrategyAddress:
		return searchAddress(ctx, db, plan.Query, req.State, limit)
	case strategy.StrategyPOIAnchor:
		return searchPOIAnchor(ctx, db, plan.Query, plan.Anchors, req.State, limit)
	case strategy.StrategyPOI:
		return searchPOI(ctx, db, plan.Query, limit)
	default:
		// rung 5 (LLM) is deferred — the demo doesn't need it. Fall through
		// to the deterministic rungs.
		return searchPOI(ctx, db, plan.Query, limit)
	}
}

// searchCoord resolves a bare coordinate.
func searchCoord(ctx context.Context, db *sql.DB, coord string) SearchResponse {
	lat, lon := parseCoord(coord)
	return SearchResponse{
		Strategy:   "coord",
		Version:    datasetVersion(ctx, db),
		Candidates: []Candidate{{ID: "coord", Kind: "coord", Lat: lat, Lon: lon, Source: "coord"}},
	}
}

// searchAddress resolves a full address (rung 2).
func searchAddress(ctx context.Context, db *sql.DB, query string, state string, limit int) SearchResponse {
	locSet := LocalitySet(ctx, db)
	rel, score, fields := normalise.Tokenise(query, 32, locSet)
	qm := match.Query{Reliable: rel, Score: score, Fields: fields}
	fs, _ := match.LoadFuzzySet(ctx, db)
	// Generate returns candidates up to the caller's cap; the address path is
	// a best-match (single candidate), so the cap only bounds the scoring scan.
	cands, _ := match.Generate(ctx, db, qm, fs, limit)

	resp := SearchResponse{Strategy: "address", Version: datasetVersion(ctx, db)}
	best := ""
	var bestC match.Candidate
	bestScore := -1.0
	for _, c := range cands {
		s := match.Score(qm, c)
		if s > bestScore {
			bestScore, best, bestC = s, c.PID, c
		}
	}
	if best != "" {
		resp.Candidates = append(resp.Candidates, Candidate{
			ID: best, Kind: "address", Source: "gnaf",
			Lat: bestC.Lat, Lon: bestC.Lon,
			Match: bestScore, Conf: bestC.Confidence, Rel: bestC.GeocodeRel,
			Address: bestC.StreetNumber + " " + bestC.StreetName + " " + bestC.StreetType + ", " + bestC.Locality + " " + bestC.State + " " + bestC.Postcode,
		})
		// Total is the matched set size (INV-6 cost visibility); generated is
		// the pre-filter count. Both were previously unset on this path —
		// total stayed 0 while a candidate was returned (UX review finding #2).
		// The address path returns a single best match by design, so when more
		// than one candidate was considered, flag truncation honestly: the
		// caller got 1 of N (was misleadingly truncated:false with total:N).
		resp.Generated = len(cands)
		resp.Total = len(cands)
		if len(cands) > 1 {
			resp.Truncated = true
		}
	}
	return resp
}

// searchPOIAnchor resolves a POI near an anchor (rung 3).
func searchPOIAnchor(ctx context.Context, db *sql.DB, poi string, anchors []string, state string, limit int) SearchResponse {
	resp := SearchResponse{Strategy: "poi_anchor", Version: datasetVersion(ctx, db), Attribution: Attribution}

	// Resolve the first anchor that resolves to a point. Multiple anchors may
	// be present ("THE CORNER OF X AND Y" splits into THE + X AND Y); the first
	// that resolves wins. This makes the anchor resolution robust to connector
	// prefixes that split into a stray token ("THE").
	anchorPoint := &match.Point{}
	anchorFound := false
	for _, anchorFrag := range anchors {
		a, err := match.ResolveAnchor(ctx, db, anchorFrag, extractLocality(ctx, db, anchorFrag))
		if err == nil && a != nil {
			anchorPoint = &match.Point{Lat: a.Lat, Lon: a.Lon}
			anchorFound = true
			resp.Anchor = &Anchor{Lat: a.Lat, Lon: a.Lon}
			break
		}
	}
	if !anchorFound {
		// Fall back to a plain POI search (rung 4) if the anchor can't resolve.
		return searchPOI(ctx, db, poi, limit)
	}

	// Fetch limit+1 so truncation can be detected (LookupPOI caps in SQL).
	cands, _ := match.LookupPOI(ctx, db, poi, limit+1, anchorPoint)
	// Cap the returned candidates at the caller's limit; total/generated
	// report the full matched set so the caller knows results were truncated
	// (UX review finding #1: total:200 but only 20 were ever returned).
	for i, c := range cands {
		if i >= limit {
			resp.Truncated = true
			break
		}
		resp.Candidates = append(resp.Candidates, Candidate{
			ID: c.OsmID, Kind: "poi", Name: c.Name, Brand: c.Brand,
			Lat: c.Lat, Lon: c.Lon, Distance: c.DistanceM, Source: "osm",
		})
	}
	resp.Generated = len(cands)
	resp.Total = len(cands)
	return resp
}

// searchPOI resolves a bare POI name (rung 4).
func searchPOI(ctx context.Context, db *sql.DB, poi string, limit int) SearchResponse {
	// Fetch limit+1 so truncation can be detected: LookupPOI applies the cap in
	// SQL, so a cap==limit query can never see more than limit rows and would
	// always report truncated=false even when more matches exist.
	cands, _ := match.LookupPOI(ctx, db, poi, limit+1, nil)
	resp := SearchResponse{Strategy: "poi", Version: datasetVersion(ctx, db), Attribution: Attribution}
	for i, c := range cands {
		if i >= limit {
			resp.Truncated = true
			break
		}
		resp.Candidates = append(resp.Candidates, Candidate{
			ID: c.OsmID, Kind: "poi", Name: c.Name, Brand: c.Brand,
			Lat: c.Lat, Lon: c.Lon, Source: "osm",
		})
	}
	resp.Generated = len(cands)
	resp.Total = len(cands)
	return resp
}

// LocalitySet loads the distinct locality names (for normalisation). This is
// the known-localities set the normaliser uses to classify tokens; it's
// warmed once at server start (the per-request load of 4M rows is too slow).
func LocalitySet(ctx context.Context, db *sql.DB) map[string]bool {
	set := map[string]bool{}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT locality_name FROM address`)
	if err != nil {
		return set
	}
	defer rows.Close()
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err == nil {
			set[l] = true
		}
	}
	return set
}

// extractLocality extracts a locality name from an anchor fragment. For
// "DONCASTER AND BLACKBURN ROAD", the locality is "DONCASTER". We look up which
// known locality the fragment starts with — matching the LONGEST prefix, so
// "DONCASTER EAST" resolves to DONCASTER EAST, not DONCASTER.
func extractLocality(ctx context.Context, db *sql.DB, fragment string) string {
	up := strings.ToUpper(strings.TrimSpace(fragment))
	fields := strings.Fields(up)
	if len(fields) == 0 {
		return ""
	}
	// Try the leading token(s) as a locality — longest prefix first.
	// A fragment may start with a connector ("CORNER OF DONCASTER...") — strip
	// it so the locality can be found.
	clean := up
	for _, pre := range []string{"CORNER OF ", "CNR ", "THE CORNER OF ", "CORNER "} {
		if strings.HasPrefix(clean, pre) {
			clean = strings.TrimSpace(strings.TrimPrefix(clean, pre))
		}
	}
	fields = strings.Fields(clean)
	q := `SELECT DISTINCT locality_name FROM address WHERE locality_name = ? LIMIT 1`
	// Try longest prefix first (up to 4 tokens).
	for i := min(len(fields), 4); i >= 1; i-- {
		probe := strings.Join(fields[:i], " ")
		var loc string
		if err := db.QueryRowContext(ctx, q, probe).Scan(&loc); err == nil {
			return loc
		}
	}
	return ""
}

// parseCoord parses "-37.81, 144.96" or "37°48'S 144°57'E".
func parseCoord(s string) (float64, float64) {
	// Simple decimal comma form.
	parts := strings.Split(s, ",")
	if len(parts) == 2 {
		lat, lon := 0.0, 0.0
		_, _ = fmt.Sscanf(parts[0], "%f", &lat)
		_, _ = fmt.Sscanf(parts[1], "%f", &lon)
		return lat, lon
	}
	return 0, 0
}

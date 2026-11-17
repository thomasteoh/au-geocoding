package match

// Two-stage matching per the v2 design (architecture.md + contract.md):
//   generate on the anchors (reliable tokens) via trigram,
//   score on everything (full token set) with edit distance in Go.
// The principle: generate on the anchors, score on everything.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
)

// Query is a normalised user query: tokens split, reliable vs score sets.
// The contract separates Generate (reliable) and Score (everything).
// Fields tags each score token's field so the scorer matches field-to-field.
type Query struct {
	Reliable []string // locality, state, postcode, street number — anchors
	Score    []string // full normalised token set, includes misspelled ones
	// Fields tags each score token: locality_name, state, postcode,
	// street_name, street_number, street_type, flat_number, lot_number, or
	// postal_delivery (which only routes the query; it is never scored).
	Fields []string
}

// Candidate is a generated row, unscored.
type Candidate struct {
	PID            string
	FlatNumber     string // "" for an address with no unit
	LotNumber      string
	StreetNumber   string
	StreetName     string
	StreetType     string
	Locality       string
	State          string
	Postcode       string
	Lat, Lon       float64
	Confidence     int // G-NAF confidence (0-100)
	GeocodeRel     int // G-NAF geocode reliability (0-100)
	GeneratedCount int // INV-8: cost is visible, not inferred
}

// Generate produces candidates via trigram on reliable tokens. This is the
// generation stage: it bounds the set so the planner can keep INV-8.
// It reports GeneratedCount so cost is explicit.
// cap bounds the candidate set (INV-8: generation is bounded, cost visible).
// fs is the fuzzy set (locality + street names); when a reliable token is a
// typo (matches 0 trigram rows), fs resolves it to its near-match instead of
// dropping it — the fix for the real-data broad-fallback finding.
func Generate(ctx context.Context, db *sql.DB, q Query, fs *FuzzySet, cap int) ([]Candidate, error) {
	// Build a trigram FTS5 MATCH from reliable tokens. Each reliable token
	// becomes a phrase; the design caps and reports the generated count.
	// FTS5 trigram only indexes tokens >= 3 chars, so short reliable tokens
	// (street numbers 1-2 digits) are EXCLUDED from generation — they go in
	// the score set instead. This is the design-relevant finding: street
	// numbers are not trigram anchors.
	var phrases []string
	seen := map[string]bool{}
	for _, t := range q.Reliable {
		if t == "" || len(t) < 3 || seen[t] {
			continue
		}
		seen[t] = true
		// Escape double quotes for FTS5 phrase syntax.
		phrases = append(phrases, `"`+strings.ReplaceAll(t, `"`, `""`)+`"`)
	}
	if len(phrases) == 0 {
		// No trigram-able reliable tokens — generation can't proceed via
		// trigram. Return empty; the caller's planner supplies anchors.
		return nil, nil
	}
	// AND semantics across reliable tokens — the design's generation is
	// intersection, not union, because reliable tokens are anchors.
	// BUT: a reliable token that is itself misspelled (a typo in a locality
	// or street name) returns 0 rows and kills the whole AND. The design's
	// "generate on the anchors" must be typo-tolerant at generation too.
	// Strategy: try the full AND; if it returns 0, use the fuzzy set to
	// resolve the typo'd tokens to their near-match (real anchors) and retry.
	// This is the fix for the real-data finding (fuzzy generation, not drop).
	match := strings.Join(phrases, " AND ")

	// Try full AND first.
	cands, err := generateMatch(ctx, db, q, match, cap)
	if err != nil {
		return nil, err
	}
	if len(cands) > 0 {
		return cands, nil
	}

	// Zero rows with a known locality: the street is misspelt or in the wrong
	// place. Try the nearest street that exists in that locality before any
	// global correction, which would keep a misspelling that happens to be a
	// real street elsewhere and then drop the locality to find it.
	street, locality := q.Field("street_name"), q.Field("locality_name")
	if fs != nil && street != "" && locality != "" {
		if near, sim := fs.NearestStreetIn(street, locality); near != "" && near != street && sim >= nearStreetInLocality {
			return Generate(ctx, db, q.withStreet(street, near), fs, cap)
		}
	}

	// Zero rows: try fuzzy generation — resolve each reliable token to its
	// near-match via the fuzzy set, then AND. This keeps the anchor narrow
	// (a typo'd locality becomes its real locality, not dropped).
	if fs != nil {
		return q.fuzzyGenerate(ctx, db, fs, cap)
	}

	// No fuzzy set: fall back to dropping anchors (old behaviour).
	for i := len(phrases) - 1; i > 0; i-- {
		relaxed := strings.Join(phrases[:i], " AND ")
		cands, err := generateMatch(ctx, db, q, relaxed, cap)
		if err != nil {
			return nil, err
		}
		if len(cands) > 0 {
			return cands, nil
		}
	}
	return nil, nil
}

// innerCap bounds the trigram match set read before ordering, so a very broad
// anchor (a locality on its own) cannot pull the whole table into one query.
// It is far above any single street-in-locality: Collins St, Melbourne, the
// largest, is about 10K rows.
const innerCap = 50000

// generateMatch runs one trigram MATCH and returns up to cap rows, best first.
// The order matters because the cap truncates: rows at the query's street
// number (or lot) come first, then rows whose street and locality match
// exactly. Without it the cap kept whatever rows SQLite produced first, and on
// a long street the asked-for number was usually not among them.
//
// Within one street address G-NAF has a row per unit (157 Fitzroy St, St
// Kilda has about 200), so the asked-for unit comes next. After that rows stay
// grouped by street address, in order of each address's first row, and the
// primary row leads its address: with no unit in the query the base address
// is the answer when it exists, and Score ties keep this order. Ranking the
// addresses by their first row rather than putting every primary row first
// keeps ties between different addresses ("133 WARRAGUL", no street) going
// the way they did before units were read.
func generateMatch(ctx context.Context, db *sql.DB, q Query, match string, cap int) ([]Candidate, error) {
	limit := ""
	if cap > 0 {
		limit = fmt.Sprintf(" LIMIT %d", cap)
	}
	number, street, locality := q.field("street_number"), q.field("street_name"), q.field("locality_name")
	flat, lot := q.field("flat_number"), q.field("lot_number")
	flatCol, lotCol := `a.flat_number`, `a.lot_number`
	if !hasUnitColumns(ctx, db) {
		flatCol, lotCol = `''`, `''`
	}
	rows, err := db.QueryContext(ctx, `
		SELECT gnaf_pid, `+flatCol+`, `+lotCol+`, street_number, street_name, street_type,
		       locality_name, state, postcode, latitude, longitude, confidence, geocode_rel
		FROM address a
		WHERE a.gnaf_pid IN (
			SELECT gnaf_pid FROM addr_trgm WHERE addr_trgm MATCH ? LIMIT `+fmt.Sprint(innerCap)+`
		)
		ORDER BY CAST(a.street_number AS TEXT) = ? DESC, `+lotCol+` = ? DESC,
			a.street_name = ? DESC, a.locality_name = ? DESC, `+flatCol+` = ? DESC,
			MIN(a.rowid) OVER (PARTITION BY a.street_number, a.street_name, a.street_type, a.locality_name),
			a.primary_sec <> 'S' DESC, a.rowid`+limit,
		match, number, lot, street, locality, flat)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Candidate
	for rows.Next() {
		var c Candidate
		if err := rows.Scan(&c.PID, &c.FlatNumber, &c.LotNumber, &c.StreetNumber, &c.StreetName, &c.StreetType,
			&c.Locality, &c.State, &c.Postcode, &c.Lat, &c.Lon, &c.Confidence, &c.GeocodeRel); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// unitColumns records, per dataset, whether address has flat_number and
// lot_number. A dataset built before buildaddr added them still serves street
// addresses, with units and lots unmatched, instead of failing every query.
var unitColumns sync.Map // *sql.DB -> bool

func hasUnitColumns(ctx context.Context, db *sql.DB) bool {
	if v, ok := unitColumns.Load(db); ok {
		return v.(bool)
	}
	var n int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('address')
		WHERE name IN ('flat_number', 'lot_number')`).Scan(&n)
	if err != nil {
		return false // not cached: a cancelled request must not decide for the dataset
	}
	unitColumns.Store(db, n == 2)
	return n == 2
}

// field returns the first score token tagged with field, or nil when there is
// none (so an SQL equality against it never matches).
func (q Query) field(name string) any {
	if v := q.Field(name); v != "" {
		return v
	}
	return nil
}

// Field returns the first score token tagged with name, or "".
func (q Query) Field(name string) string {
	for i, f := range q.Fields {
		if f == name && i < len(q.Score) {
			return q.Score[i]
		}
	}
	return ""
}

// withStreet returns a copy of q with its street name replaced everywhere it
// appears (anchors and scoring tokens).
func (q Query) withStreet(from, to string) Query {
	out := Query{Fields: q.Fields}
	for _, t := range q.Reliable {
		if t == from {
			t = to
		}
		out.Reliable = append(out.Reliable, t)
	}
	for i, t := range q.Score {
		if t == from && i < len(q.Fields) && q.Fields[i] == "street_name" {
			t = to
		}
		out.Score = append(out.Score, t)
	}
	return out
}

// nearStreetInLocality is how close a misspelt street must be to a street in
// the query's locality to be corrected to it.
const nearStreetInLocality = 0.75

// Score computes edit-distance similarity between a query token and a row token.
// The design scores against the full query, not just the reliable set.
// Returns a per-row match score in [0,1]. 1.0 = exact on all score tokens.
// REAL-DATA FINDING (2026-09-14): exact locality/state must outweigh street
// similarity. A typo'd street (MUtRAY) with a wrong locality scores high on
// street edit-distance but is the WRONG address. Weight locality/state exact
// matches so the candidate in the query's locality beats a wrong-locality one.
func Score(q Query, row Candidate) float64 {
	// Field-aware scoring using q.Fields tags. Each query token is compared
	// against its OWN field (locality vs locality, street vs street). This is
	// the fix the spike found: flat scoring conflates fields (a street token
	// matching a locality substring), which drops match rate.
	// When a token has no tag (Fields empty), fall back to best-across-fields.
	fieldMap := map[string]string{
		"locality_name": row.Locality,
		"state":         row.State,
		"postcode":      row.Postcode,
		"street_name":   row.StreetName,
		"street_number": row.StreetNumber,
		"street_type":   row.StreetType,
		"flat_number":   row.FlatNumber,
		"lot_number":    row.LotNumber,
	}
	// Weight per field: locality and state are anchors — an exact match there
	// strongly signals the right address, so they outweigh street similarity.
	fieldWeight := map[string]float64{
		"locality_name": 2.0, // exact locality match is decisive
		"state":         3.0, // state must match
		"postcode":      1.5,
		"street_name":   1.0,
		"street_number": 2.0, // number is decisive when present
		"street_type":   0.5,
		// The unit picks a row within the street address; it must not pull
		// in the same unit number at a neighbouring street number.
		"flat_number": 0.5,
		// A lot stands in for the street number, and is as decisive.
		"lot_number": 2.0,
	}

	total := 0.0
	weightSum := 0.0
	for i, qt := range q.Score {
		if qt == "" {
			continue
		}
		if i < len(q.Fields) && q.Fields[i] == "postal_delivery" {
			continue
		}
		sim := 0.0
		w := 1.0
		if i < len(q.Fields) {
			tag := q.Fields[i]
			val, ok := fieldMap[tag]
			switch {
			case ok && (tag == "flat_number" || tag == "lot_number"):
				// An identifier, not a word: unit 9 is no nearer unit 99
				// than unit 40 is, so only the exact row scores.
				if qt == val {
					sim = 1
				}
				w = fieldWeight[tag]
			case ok:
				sim = levenshteinSim(qt, val)
				if tw, ok := fieldWeight[tag]; ok {
					w = tw
				}
			default:
				sim = bestAcrossFields(qt, row)
			}
		} else {
			sim = bestAcrossFields(qt, row)
		}
		total += sim * w
		weightSum += w
	}
	if weightSum == 0 {
		return 0
	}
	return total / weightSum
}

// bestAcrossFields is the fallback: a token's best similarity against all
// fields, used when the token has no field tag.
func bestAcrossFields(qt string, row Candidate) float64 {
	fields := []string{
		row.StreetName, row.Locality, row.State, row.Postcode, row.StreetNumber,
	}
	best := 0.0
	for _, f := range fields {
		s := levenshteinSim(qt, f)
		if s > best {
			best = s
		}
	}
	return best
}

// levenshteinSim is normalised edit-distance similarity in [0,1].
// 1.0 when equal; falls off with distance. Case-insensitive, already normalised.
// The distance is optimal string alignment: Levenshtein plus adjacent
// transposition as one edit, so "WINSDOR" is one edit from WINDSOR, not two.
// Swapped letters are among the commonest typing errors.
func levenshteinSim(a, b string) float64 {
	if a == b {
		return 1.0
	}
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return 0
	}
	// OSA distance (DP over three rows, O(la*lb)).
	prev2 := make([]int, lb+1)
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			m := prev[j-1] + cost
			if v := prev[j] + 1; v < m {
				m = v
			}
			if v := cur[j-1] + 1; v < m {
				m = v
			}
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if v := prev2[j-2] + 1; v < m {
					m = v
				}
			}
			cur[j] = m
		}
		prev2, prev, cur = prev, cur, prev2
	}
	dist := prev[lb]
	// Normalise: similarity = 1 - dist/maxLen, clamped.
	sim := 1.0 - float64(dist)/float64(max(la, lb))
	if sim < 0 {
		sim = 0
	}
	return sim
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Similarity is the normalised edit-distance similarity used for scoring and
// fuzzy correction, in [0,1].
func Similarity(a, b string) float64 { return levenshteinSim(a, b) }

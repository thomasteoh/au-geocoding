package match

// Fuzzy generation: when a reliable token (locality/street) matches 0 trigram
// rows, it's a typo. Instead of dropping it (the old fallback, which loses the
// anchor and makes generation broad), find its near-miss in the DB's known
// locality/street names and substitute the canonical name as the anchor.
//
// REAL-DATA FINDING (2026-09-14): resolution MUST be locality-aware. A typo'd
// street (MUtRAY) that fuzzy-resolves globally picks MOUTRAY (WARRNAMBOOL,
// 1 edit) over MURRAY (COBURG, 2 edits) — but the query's locality is COBURG.
// Resolving locality-blind picks the wrong street. When the query has a
// locality, prefer the street that exists in that locality.

import (
	"context"
	"database/sql"
	"sort"
	"strings"
)

// FuzzySet holds known locality and street names for near-match lookup.
// It also tracks which localities each street exists in, so resolution can
// prefer a street that exists in the query's locality.
type FuzzySet struct {
	localities map[string]bool            // canonical locality names (upper)
	streets    map[string]bool            // canonical street names (upper)
	streetLocs map[string]map[string]bool // street -> set of localities it appears in
	locStreets map[string][]string        // locality -> streets in it
	aliases                               // G-NAF locality and street aliases (alias.go)
}

// LoadFuzzySet builds the fuzzy set from the real address table.
// locality_name and street_name are the generation anchors; their canonical
// forms are what a typo'd token should resolve to.
func LoadFuzzySet(ctx context.Context, db *sql.DB) (*FuzzySet, error) {
	fs := &FuzzySet{
		localities: map[string]bool{},
		streets:    map[string]bool{},
		streetLocs: map[string]map[string]bool{},
		locStreets: map[string][]string{},
	}
	rows, err := db.QueryContext(ctx, `SELECT locality_name, street_name FROM address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var loc, st string
		if err := rows.Scan(&loc, &st); err != nil {
			return nil, err
		}
		if loc != "" {
			fs.localities[strings.ToUpper(loc)] = true
		}
		if st != "" {
			up := strings.ToUpper(st)
			fs.streets[up] = true
			// Track street -> localities.
			if loc != "" {
				locs, ok := fs.streetLocs[up]
				if !ok {
					locs = map[string]bool{}
					fs.streetLocs[up] = locs
				}
				ul := strings.ToUpper(loc)
				if !locs[ul] {
					locs[ul] = true
					fs.locStreets[ul] = append(fs.locStreets[ul], up)
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return fs, fs.loadAliases(ctx, db)
}

// Localities returns the known locality names (upper case), aliases included:
// the parser recognises an alias as a locality, and CanonicalLocality then
// names the official locality. The map is shared, not copied: callers must
// not modify it.
func (fs *FuzzySet) Localities() map[string]bool { return fs.known() }

// LocalitiesOf returns the localities a street name (exact, upper case) is
// in, sorted.
func (fs *FuzzySet) LocalitiesOf(street string) []string {
	out := make([]string, 0, len(fs.streetLocs[street]))
	for l := range fs.streetLocs[street] {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// NearestLocality returns the known locality closest to name by edit distance,
// and its similarity. It scans the locality names (a few thousand per state).
func (fs *FuzzySet) NearestLocality(name string) (string, float64) {
	up := strings.ToUpper(name)
	known := fs.known()
	if known[up] {
		return up, 1
	}
	best, bestSim := "", 0.0
	for loc := range known {
		if s := levenshteinSim(up, loc); s > bestSim {
			best, bestSim = loc, s
		}
	}
	return best, bestSim
}

// NearestStreetIn returns the street in locality closest to name by edit
// distance, and its similarity. An exact street in the locality scores 1. It
// returns "", 0 when the locality is unknown.
//
// This is the locality-first correction: "COLINS" is a real street (in
// Leongatha), so global resolution keeps it, but in MELBOURNE the street meant
// is COLLINS.
func (fs *FuzzySet) NearestStreetIn(name, locality string) (string, float64) {
	up, loc := strings.ToUpper(name), strings.ToUpper(locality)
	best, bestSim := "", 0.0
	for _, st := range fs.locStreets[loc] {
		if st == up {
			return st, 1
		}
		if s := levenshteinSim(up, st); s > bestSim {
			best, bestSim = st, s
		}
	}
	return best, bestSim
}

// Resolve finds the canonical form of a possibly-typo'd token. If the token is
// already in the set, it returns it unchanged. Otherwise it finds the best
// edit-distance near-match in the set, PREFERRING streets that exist in the
// query's locality. Returns the original token if no good match exists.
func (fs *FuzzySet) Resolve(token string, locality string, threshold float64) string {
	up := strings.ToUpper(token)
	if fs.localities[up] || fs.streets[up] {
		return up
	}
	// Search both sets for the best near-match. Streets in the query's
	// locality get a bonus: they're far more likely to be the real street.
	best := ""
	bestScore := -1.0
	locUp := strings.ToUpper(locality)
	for name := range fs.localities {
		if s := levenshteinSim(up, name); s > bestScore {
			bestScore = s
			best = name
		}
	}
	for name := range fs.streets {
		s := levenshteinSim(up, name)
		// Bonus if this street exists in the query's locality.
		if locUp != "" {
			if locs, ok := fs.streetLocs[name]; ok && locs[locUp] {
				s += 0.25 // locality-consistent street is strongly preferred
			}
		}
		if s > bestScore {
			bestScore = s
			best = name
		}
	}
	if bestScore >= threshold {
		return best
	}
	return up
}

func (q Query) fuzzyGenerate(ctx context.Context, db *sql.DB, fs *FuzzySet, cap int) ([]Candidate, error) {
	// Build phrases, resolving each reliable token to its canonical form.
	// Short tokens (<3) are skipped (not trigram-able).
	// Find the query's locality (from the reliable tokens) for locality-aware
	// street resolution.
	queryLoc := ""
	for _, t := range q.Reliable {
		if fs.localities[strings.ToUpper(t)] {
			queryLoc = t
			break
		}
	}
	var phrases []string
	seen := map[string]bool{}
	for _, t := range q.Reliable {
		if t == "" || len(t) < 3 {
			continue
		}
		resolved := fs.Resolve(t, queryLoc, 0.75)
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		phrases = append(phrases, `"`+strings.ReplaceAll(resolved, `"`, `""`)+`"`)
	}
	if len(phrases) == 0 {
		return nil, nil
	}
	// Try full AND with resolved anchors.
	match := strings.Join(phrases, " AND ")
	cands, err := generateMatch(ctx, db, q, match, cap)
	if err != nil {
		return nil, err
	}
	if len(cands) > 0 {
		return cands, nil
	}
	// Still zero: drop one anchor at a time (resolved).
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

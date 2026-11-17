package match

// Postcode areas (ABS POA, loaded by cmd/loadpostcode): which postcode
// contains a point, and whether a given postcode does. Lookups pair a tiny
// geopoly_overlap probe (R-Tree) with the exact geopoly_contains_point, as
// LocalityAt does, and subtract holes.

import (
	"context"
	"database/sql"
	"sort"
	"sync"
)

// PostcodeHit is one postal area containing a point.
type PostcodeHit struct {
	Postcode string
	RepLat   float64 // the area's representative point (inside it)
	RepLon   float64
}

var postcodeTables sync.Map // *sql.DB -> bool

// HasPostcodes reports whether db has the postcode tables.
func HasPostcodes(ctx context.Context, db *sql.DB) bool {
	if v, ok := postcodeTables.Load(db); ok {
		return v.(bool)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master
		WHERE name IN ('postcode', 'postcode_shape', 'postcode_shape_hole')`).Scan(&n); err != nil {
		return false
	}
	postcodeTables.Store(db, n == 3)
	return n == 3
}

// PostcodeAt returns the postal areas containing (lon, lat), smallest first.
// It returns nothing on a dataset without postcode tables.
func PostcodeAt(ctx context.Context, db *sql.DB, lon, lat float64) ([]PostcodeHit, error) {
	if !HasPostcodes(ctx, db) {
		return nil, nil
	}
	pr := probe(lon, lat)
	rows, err := db.QueryContext(ctx, `
		SELECT s.rowid, s.postcode, abs(geopoly_area(s._shape)), p.rep_lat, p.rep_lon
		FROM postcode_shape s JOIN postcode p ON p.postcode = s.postcode
		WHERE geopoly_overlap(s._shape, ?) AND geopoly_contains_point(s._shape, ?, ?)`, pr, lon, lat)
	if err != nil {
		return nil, err
	}
	type ring struct {
		id   int64
		hit  PostcodeHit
		area float64
	}
	var rings []ring
	for rows.Next() {
		var r ring
		if err := rows.Scan(&r.id, &r.hit.Postcode, &r.area, &r.hit.RepLat, &r.hit.RepLon); err != nil {
			rows.Close()
			return nil, err
		}
		rings = append(rings, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(rings) == 0 {
		return nil, nil
	}
	inHole, err := postcodeHolesAt(ctx, db, pr, lon, lat)
	if err != nil {
		return nil, err
	}
	sort.Slice(rings, func(i, j int) bool {
		if rings[i].area != rings[j].area {
			return rings[i].area < rings[j].area
		}
		return rings[i].hit.Postcode < rings[j].hit.Postcode
	})
	seen := map[string]bool{}
	var out []PostcodeHit
	for _, r := range rings {
		if inHole[r.id] || seen[r.hit.Postcode] {
			continue
		}
		seen[r.hit.Postcode] = true
		out = append(out, r.hit)
	}
	return out, nil
}

// PostcodeContains reports whether postcode's area contains (lon, lat). ok is
// false when the dataset has no area for the postcode, so the caller cannot
// tell.
func PostcodeContains(ctx context.Context, db *sql.DB, postcode string, lon, lat float64) (inside, ok bool, err error) {
	if !HasPostcodes(ctx, db) {
		return false, false, nil
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM postcode WHERE postcode = ?`, postcode).Scan(&n); err != nil || n == 0 {
		return false, false, err
	}
	hits, err := PostcodeAt(ctx, db, lon, lat)
	if err != nil {
		return false, false, err
	}
	for _, h := range hits {
		if h.Postcode == postcode {
			return true, true, nil
		}
	}
	return false, true, nil
}

// PostcodePoint returns postcode's representative point; ok is false when the
// dataset has no area for it.
func PostcodePoint(ctx context.Context, db *sql.DB, postcode string) (lat, lon float64, ok bool, err error) {
	if !HasPostcodes(ctx, db) {
		return 0, 0, false, nil
	}
	err = db.QueryRowContext(ctx, `SELECT rep_lat, rep_lon FROM postcode WHERE postcode = ?`, postcode).Scan(&lat, &lon)
	if err == sql.ErrNoRows {
		return 0, 0, false, nil
	}
	return lat, lon, err == nil, err
}

func postcodeHolesAt(ctx context.Context, db *sql.DB, pr string, lon, lat float64) (map[int64]bool, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT outer_id FROM postcode_shape_hole
		WHERE geopoly_overlap(_shape, ?) AND geopoly_contains_point(_shape, ?, ?)`, pr, lon, lat)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

package match

// Boundary/locality containment (Step 3): given a lat/lon, find the locality
// polygon containing it via geopoly_contains_point. This powers the boundary
// endpoint — a point's locality — and can resolve an ambiguous address to its
// containing locality.

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// LocalityHit is one locality polygon containing a point.
type LocalityHit struct {
	LocPID        string
	Name          string
	LocalityClass string
}

// probeHalf is the half-width, in degrees, of the small square used to drive
// the geopoly R-Tree: about ten metres. geopoly stores vertices as 32-bit
// floats, which at longitude 145 resolve to ~1.5e-5 degrees, so a smaller
// square collapses to a point and overlaps nothing. The prefilter only has to
// be small; geopoly_contains_point makes the exact decision.
const probeHalf = 1e-4

// probe returns the geopoly JSON for a tiny CCW square around (lon, lat).
func probe(lon, lat float64) string {
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
	x0, x1 := f(lon-probeHalf), f(lon+probeHalf)
	y0, y1 := f(lat-probeHalf), f(lat+probeHalf)
	return fmt.Sprintf("[[%s,%s],[%s,%s],[%s,%s],[%s,%s],[%s,%s]]",
		x0, y0, x1, y0, x1, y1, x0, y1, x0, y0)
}

// LocalityAt returns the distinct localities containing (lon, lat), most
// specific (smallest containing ring) first, then by locality_pid, so the
// answer is deterministic. Returns up to limit rows.
//
// geopoly_contains_point alone cannot use the geopoly R-Tree and would test
// every polygon in Victoria on each request. geopoly_overlap against a tiny
// probe square can, so it narrows the scan to the few rings whose bbox covers
// the point before the exact test runs.
func LocalityAt(ctx context.Context, db *sql.DB, lon, lat float64, limit int) ([]LocalityHit, error) {
	if limit <= 0 {
		limit = 3
	}
	pr := probe(lon, lat)
	rows, err := db.QueryContext(ctx, `
		SELECT rowid, locality_pid, name, locality_class, abs(geopoly_area(_shape))
		FROM boundary
		WHERE geopoly_overlap(_shape, ?) AND geopoly_contains_point(_shape, ?, ?)
	`, pr, lon, lat)
	if err != nil {
		return nil, err
	}
	type ring struct {
		id   int64
		hit  LocalityHit
		area float64
	}
	var rings []ring
	for rows.Next() {
		var r ring
		if err := rows.Scan(&r.id, &r.hit.LocPID, &r.hit.Name, &r.hit.LocalityClass, &r.area); err != nil {
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

	// Subtract holes: a point inside a hole of ring R is not in R, though it
	// may still be in another ring of the same locality (an island in a lake).
	inHole, err := holesAt(ctx, db, pr, lon, lat)
	if err != nil {
		return nil, err
	}

	sort.Slice(rings, func(i, j int) bool {
		if rings[i].area != rings[j].area {
			return rings[i].area < rings[j].area
		}
		return rings[i].hit.LocPID < rings[j].hit.LocPID
	})
	seen := map[string]bool{}
	var out []LocalityHit
	for _, r := range rings {
		if inHole[r.id] || seen[r.hit.LocPID] {
			continue
		}
		seen[r.hit.LocPID] = true
		out = append(out, r.hit)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// holesAt returns the outer-ring ids whose holes contain the point. A dataset
// built before boundary_hole existed has no such table; it is treated as
// having no holes rather than failing every lookup.
func holesAt(ctx context.Context, db *sql.DB, pr string, lon, lat float64) (map[int64]bool, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT outer_id FROM boundary_hole
		WHERE geopoly_overlap(_shape, ?) AND geopoly_contains_point(_shape, ?, ?)
	`, pr, lon, lat)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
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

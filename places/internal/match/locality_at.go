package match

// Boundary/locality containment (Step 3): given a lat/lon, find the locality
// polygon containing it via geopoly_contains_point. This powers the boundary
// endpoint — a point's locality — and can resolve an ambiguous address to its
// containing locality.

import (
	"context"
	"database/sql"
)

// LocalityHit is one locality polygon containing a point.
type LocalityHit struct {
	LocPID        string
	Name          string
	LocalityClass string
}

// LocalityAt returns the locality polygons containing (lon, lat). The geopoly
// index returns rows whose bbox contains the point; geopoly_contains_point
// refines to exact containment. Returns up to limit rows.
func LocalityAt(ctx context.Context, db *sql.DB, lon, lat float64, limit int) ([]LocalityHit, error) {
	if limit <= 0 {
		limit = 3
	}
	rows, err := db.QueryContext(ctx, `
		SELECT locality_pid, name, locality_class
		FROM boundary
		WHERE geopoly_contains_point(_shape, ?, ?)
		LIMIT ?
	`, lon, lat, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LocalityHit
	for rows.Next() {
		var h LocalityHit
		if err := rows.Scan(&h.LocPID, &h.Name, &h.LocalityClass); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

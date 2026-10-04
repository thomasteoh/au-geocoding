package match

// Reverse geocoding (Step 3): given a lat/lon, find the nearest address.
// The reverse index is addr_rt (an RTree over address.rowid -> point bbox),
// built at load time by buildaddr. The RTree finds candidate rowids in a
// bbox; we rank by great-circle distance to the query point and return the
// nearest few. This is the half-width re-query pattern: start with a tight
// bbox and widen if no rows (or too few) are found.

import (
	"context"
	"database/sql"
	"math"
)

// ReverseResult is one address from a reverse lookup.
type ReverseResult struct {
	PID          string
	StreetNumber string
	StreetName   string
	StreetType   string
	Locality     string
	State        string
	Postcode     string
	Lat, Lon     float64
	DistanceM    float64 // great-circle distance to the query point
}

// Reverse finds the nearest addresses to (lon, lat). It queries addr_rt with
// an expanding bbox (half-width re-query), ranks by distance, and returns up
// to limit results. A wider bbox is tried when the tight one yields too few.
func Reverse(ctx context.Context, db *sql.DB, lon, lat float64, limit int) ([]ReverseResult, error) {
	if limit <= 0 {
		limit = 5
	}
	// Half-widths to try: 100m, 250m, 500m, 1km, 2km, 5km, 10km.
	// Degrees: 1 deg lat ~= 111km, so width_deg = km/111.
	widths := []float64{0.001, 0.0025, 0.005, 0.01, 0.02, 0.05, 0.1}
	var lastErr error
	for _, w := range widths {
		res, err := reverseBBox(ctx, db, lon, lat, w, limit)
		if err != nil {
			lastErr = err
			continue
		}
		// Tightest width that returns rows wins — return immediately. This is
		// the half-width re-query: prefer the nearest candidates from the
		// smallest bbox, widening only when empty.
		if len(res) > 0 {
			return res, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

// reverseBBox queries addr_rt for rows whose point bbox intersects the bbox
// around (lon, lat) with half-width w, joins to address, and ranks by
// distance, returning up to limit rows.
func reverseBBox(ctx context.Context, db *sql.DB, lon, lat, w float64, limit int) ([]ReverseResult, error) {
	latLo, latHi := lat-w, lat+w
	lonLo, lonHi := lon-w, lon+w
	rows, err := db.QueryContext(ctx, `
		SELECT a.gnaf_pid, a.street_number, a.street_name, a.street_type,
		       a.locality_name, a.state, a.postcode, a.latitude, a.longitude,
		       a.rowid
		FROM addr_rt rt JOIN address a ON a.rowid = rt.id
		WHERE rt.min_lat BETWEEN ? AND ? AND rt.min_lon BETWEEN ? AND ?
	`, latLo, latHi, lonLo, lonHi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ReverseResult
	var seen = make(map[int64]bool)
	for rows.Next() {
		var r ReverseResult
		var rowid int64
		if err := rows.Scan(&r.PID, &r.StreetNumber, &r.StreetName, &r.StreetType,
			&r.Locality, &r.State, &r.Postcode, &r.Lat, &r.Lon, &rowid); err != nil {
			return nil, err
		}
		// Dedup: the RTree may return the same address rowid once per bbox
		// overlap (a point sits in multiple RTree nodes). Skip repeats.
		if seen[rowid] {
			continue
		}
		seen[rowid] = true
		// Distance in metres (great-circle / haversine).
		r.DistanceM = haversine(lon, lat, r.Lon, r.Lat)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Sort by distance ascending, keep the nearest limit.
	sortByDistance(out, limit)
	return out, nil
}

// haversine computes the great-circle distance between two points in metres.
// (lon1,lat1) and (lon2,lat2) in degrees.
func haversine(lon1, lat1, lon2, lat2 float64) float64 {
	const R = 6371000.0 // mean Earth radius, metres
	φ1 := lat1 * math.Pi / 180
	φ2 := lat2 * math.Pi / 180
	Δφ := (lat2 - lat1) * math.Pi / 180
	Δλ := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(Δφ/2)*math.Sin(Δφ/2) +
		math.Cos(φ1)*math.Cos(φ2)*math.Sin(Δλ/2)*math.Sin(Δλ/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
}

// sortByDistance sorts res ascending by DistanceM in place and truncates to
// the nearest limit. It mutates the caller's slice.
func sortByDistance(res []ReverseResult, limit int) {
	// Insertion sort by distance (small n; fine).
	for i := 1; i < len(res); i++ {
		for j := i; j > 0 && res[j].DistanceM < res[j-1].DistanceM; j-- {
			res[j], res[j-1] = res[j-1], res[j]
		}
	}
	if limit > 0 && len(res) > limit {
		res = res[:limit]
	}
}

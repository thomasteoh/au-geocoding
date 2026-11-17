package match

// Reverse geocoding (Step 3): given a lat/lon, find the nearest address.
// The reverse index is addr_rt (an RTree over address.rowid -> point bbox),
// built at load time by buildaddr. The RTree finds candidate rowids in a
// bbox; we rank by great-circle distance to the query point and return the
// nearest few. This is the half-width re-query pattern: start with a tight
// bbox and widen while too few rows are found, never past the caller's radius.

import (
	"context"
	"database/sql"
	"math"
	"sort"
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

// DefaultReverseRadiusM is the search radius when the caller sets none, and
// MaxReverseRadiusM the most any caller can ask for. Ten kilometres matches the
// widest bbox the reverse lookup has always tried.
const (
	DefaultReverseRadiusM = 10000.0
	MaxReverseRadiusM     = 10000.0
)

// metresPerDegLat is the length of one degree of latitude.
const metresPerDegLat = 111320.0

// reverseSteps are the search radii tried in turn, in metres. Each step is
// cheap when it finds enough rows; widening only happens where addresses are
// sparse.
var reverseSteps = []float64{100, 250, 500, 1000, 2000, 5000, 10000}

// Reverse finds the nearest addresses to (lon, lat) within the default radius.
// It is ReverseWithin with no caller-set radius.
func Reverse(ctx context.Context, db *sql.DB, lon, lat float64, limit int) ([]ReverseResult, error) {
	return ReverseWithin(ctx, db, lon, lat, limit, 0)
}

// ReverseWithin finds up to limit addresses nearest (lon, lat), none further
// than maxRadiusM metres (0 means DefaultReverseRadiusM; anything above
// MaxReverseRadiusM is clamped). It queries addr_rt with an expanding bbox
// (half-width re-query), stopping at the first radius that holds limit rows.
//
// Only rows within the current step's radius are trusted: a row in a bbox
// corner can be further away than a row just outside the bbox's edge, so
// returning bbox rows unfiltered would not be the nearest set.
func ReverseWithin(ctx context.Context, db *sql.DB, lon, lat float64, limit int, maxRadiusM float64) ([]ReverseResult, error) {
	if limit <= 0 {
		limit = 5
	}
	radius := ClampReverseRadius(maxRadiusM)
	var best []ReverseResult
	for _, step := range reverseSteps {
		last := step >= radius
		if last {
			step = radius
		}
		res, err := reverseBBox(ctx, db, lon, lat, step)
		if err != nil {
			return nil, err
		}
		if len(res) >= limit || last {
			return res[:min(limit, len(res))], nil
		}
		best = res
	}
	return best, nil
}

// ClampReverseRadius maps a caller's radius in metres onto the supported
// range: 0 or negative means the default, anything larger than the maximum is
// capped.
func ClampReverseRadius(m float64) float64 {
	if m <= 0 {
		return DefaultReverseRadiusM
	}
	return math.Min(m, MaxReverseRadiusM)
}

// reverseBBox queries addr_rt for rows inside the bbox circumscribing a circle
// of radiusM around (lon, lat), joins to address, drops rows outside the
// circle, and returns the rest nearest first.
func reverseBBox(ctx context.Context, db *sql.DB, lon, lat, radiusM float64) ([]ReverseResult, error) {
	dLat := radiusM / metresPerDegLat
	// A degree of longitude shrinks with cos(latitude); at Victoria's -37 deg
	// it is ~80% of a degree of latitude, so an unscaled bbox would be too
	// narrow east-west.
	cos := math.Max(math.Cos(lat*math.Pi/180), 0.01)
	dLon := radiusM / (metresPerDegLat * cos)
	// G-NAF leaves street type, number and postcode empty on some addresses
	// (STREET_TYPE_CODE is nullable); one NULL in the bbox would otherwise fail
	// the scan for the whole lookup.
	rows, err := db.QueryContext(ctx, `
		SELECT a.gnaf_pid, coalesce(a.street_number, ''), a.street_name,
		       coalesce(a.street_type, ''), a.locality_name, a.state,
		       coalesce(a.postcode, ''), a.latitude, a.longitude, a.rowid
		FROM addr_rt rt JOIN address a ON a.rowid = rt.id
		WHERE rt.min_lat BETWEEN ? AND ? AND rt.min_lon BETWEEN ? AND ?
	`, lat-dLat, lat+dLat, lon-dLon, lon+dLon)
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
		if r.DistanceM > radiusM {
			continue
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortByDistance(out)
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

// sortByDistance sorts res nearest first. A dense bbox holds hundreds of
// rows, so this needs to be O(n log n); PID breaks ties so equal distances
// (units sharing a building geocode) come back in a stable order.
func sortByDistance(res []ReverseResult) {
	sort.Slice(res, func(i, j int) bool {
		if res[i].DistanceM != res[j].DistanceM {
			return res[i].DistanceM < res[j].DistanceM
		}
		return res[i].PID < res[j].PID
	})
}

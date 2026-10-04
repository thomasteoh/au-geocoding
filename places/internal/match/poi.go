package match

// POI lookup — the rung-3/rung-4 layer. Generate on the POI name/brand via
// trigram (same two-stage mechanism as addresses), score in Go, and optionally
// rank by distance to an anchor (for "near <anchor>") or filter by locality
// (for "in <suburb>").

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Point is a geographic coordinate.
type Point struct {
	Lat, Lon float64
}

// POICandidate is a resolved OSM POI row.
type POICandidate struct {
	OsmID     string
	Name      string
	Brand     string
	Operator  string
	Category  string
	Lat, Lon  float64
	DistanceM float64 // 0 when no anchor supplied
	Score     float64 // name/brand similarity, when unanchored
}

// LookupPOI generates POI candidates by name/brand trigram, scores in Go, and
// optionally ranks by distance to an anchor. cap bounds the set (INV-8).
// anchor, when non-nil, enables distance ranking and fills DistanceM.
func LookupPOI(ctx context.Context, db *sql.DB, name string, cap int, anchor *Point) ([]POICandidate, error) {
	if cap <= 0 {
		cap = 200
	}
	if name == "" {
		return nil, nil
	}
	// Trigram FTS5 on name/brand. name may be a typo'd brand ("woolworths"
	// vs "Woolworths") — trigram handles substrings and near-matches.
	// When anchored, the distance sort must see ALL matches — a LIMIT here
	// (FTS5 relevance order) can drop the nearest candidate before the Go
	// distance sort. So only cap when unanchored.
	phrase := strings.ReplaceAll(name, `"`, `""`)
	match := fmt.Sprintf(`"%s"`, phrase)
	q := `SELECT osm_id, name, brand, operator, category, lat, lon
	      FROM poi
	      WHERE osm_id IN (
	          SELECT osm_id FROM poi_trgm WHERE poi_trgm MATCH ?
	      )`
	args := []any{match}
	if anchor == nil {
		q = `SELECT osm_id, name, brand, operator, category, lat, lon
		     FROM poi
		     WHERE osm_id IN (
		         SELECT osm_id FROM poi_trgm WHERE poi_trgm MATCH ? LIMIT ?
		     )`
		args = []any{match, cap}
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []POICandidate
	for rows.Next() {
		var c POICandidate
		if err := rows.Scan(&c.OsmID, &c.Name, &c.Brand, &c.Operator, &c.Category, &c.Lat, &c.Lon); err != nil {
			return nil, err
		}
		if anchor != nil {
			c.DistanceM = HaversineM(anchor.Lat, anchor.Lon, c.Lat, c.Lon)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if anchor != nil {
		// Distance is the primary ordering when anchored.
		sort.Slice(out, func(i, j int) bool {
			return out[i].DistanceM < out[j].DistanceM
		})
	} else {
		// Score by name/brand similarity when unanchored.
		for i := range out {
			out[i].Score = nameSim(out[i].Name, out[i].Brand, name)
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].Score > out[j].Score
		})
	}
	return out, nil
}

// nameSim is the Levenshtein similarity of the candidate's name/brand against
// the query. We score against both name and brand, taking the best.
func nameSim(name, brand, q string) float64 {
	up := strings.ToUpper
	s := levenshteinSim(up(name), up(q))
	if brand != "" {
		if bs := levenshteinSim(up(brand), up(q)); bs > s {
			s = bs
		}
	}
	return s
}

// HaversineM is the great-circle distance in metres between two points.
func HaversineM(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371000.0
	const deg = 3.141592653589793 / 180
	lat1r := lat1 * deg
	lat2r := lat2 * deg
	dlat := (lat2 - lat1) * deg
	dlon := (lon2 - lon1) * deg
	a := math.Sin(dlat/2)*math.Sin(dlat/2) + math.Cos(lat1r)*math.Cos(lat2r)*math.Sin(dlon/2)*math.Sin(dlon/2)
	return 2 * r * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}


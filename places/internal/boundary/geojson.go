package boundary

import (
	"fmt"
	"strconv"
	"strings"
)

// ToGeoJSON converts a Polygon into a GeoJSON polygon string for geopoly.
// Geopoly requires a single simple polygon (no self-intersections, no holes
// in the same row). Shapefile polygons have an outer ring (parts[0]) plus
// optional interior rings (parts[1:]). We emit each ring as a separate geopoly
// row so containment queries work on all of them; the outer ring is the
// locality boundary, interior rings are holes (islands) we keep as separate
// polygons.
//
// GeoJSON format: array of vertexes, each a [x,y] pair, first==last, CCW.
// Geopoly expects coordinates as [X,Y] where X=longitude, Y=latitude in our
// data (shapefile bbox is Xmin,Ymin,Xmax,Ymax = lon,lat).
func ToGeoJSON(ring []Point) (string, error) {
	if len(ring) < 4 {
		return "", fmt.Errorf("ring too short: %d points", len(ring))
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, p := range ring {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('[')
		b.WriteString(strconv.FormatFloat(p.X, 'f', 8, 64))
		b.WriteByte(',')
		b.WriteString(strconv.FormatFloat(p.Y, 'f', 8, 64))
		b.WriteByte(']')
	}
	b.WriteByte(']')
	// Validate: first == last for a closed polygon.
	if ring[0] != ring[len(ring)-1] {
		return "", fmt.Errorf("ring not closed (first != last)")
	}
	return b.String(), nil
}

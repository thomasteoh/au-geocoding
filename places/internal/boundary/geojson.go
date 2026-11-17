package boundary

import (
	"fmt"
	"strconv"
	"strings"
)

// ToGeoJSON converts one ring into a GeoJSON polygon string for geopoly.
// Geopoly requires a single simple polygon (no self-intersections, no holes
// in the same row), so a shapefile polygon is stored ring by ring: outer rings
// in boundary, holes in boundary_hole (see ClassifyRings and
// schema.BoundarySchemaSQL).
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

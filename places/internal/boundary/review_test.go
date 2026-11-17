package boundary

import (
	"encoding/binary"
	"math"
	"testing"
)

// A ring big enough to keep (over MinRingAreaPx) can still collapse to fewer
// than four points on the grid, and buildRings skips it. The gate must then
// compare each remaining simplified ring with its own source: pairing by index
// measured the next ring against the collapsed sliver and failed the build.
func TestGateComparesEachRingWithItsOwnSource(t *testing.T) {
	mainland := square(145.0, -37.8, 0.2, 8)
	// About 8 px by 0.2 px: 1.6 px^2, kept by the area filter, but its long
	// sides land on the same pixel row and the ring collapses.
	sliver := []Point{
		{145.05, -37.7}, {145.06, -37.7}, {145.06, -37.6998}, {145.05, -37.6998}, {145.05, -37.7},
	}
	out, err := Simplify(Polygon{Parts: [][]Point{sliver, mainland}}, Options{})
	if err != nil {
		t.Fatalf("Simplify: %v", err)
	}
	if out.Rings != 1 {
		t.Fatalf("rings=%d, want 1 (sliver collapses on the grid)", out.Rings)
	}
	if out.MaxDevPx > DefaultSubPixel {
		t.Errorf("max deviation %.3f px measured against the wrong ring", out.MaxDevPx)
	}
}

// polygonPayload builds a shape type 5 record payload with the given header
// counts and as many points as actually fit in the body.
func polygonPayload(numParts, numPoints uint32, body int) []byte {
	p := make([]byte, 44+body)
	binary.LittleEndian.PutUint32(p[0:4], ShapeTypePolygon)
	binary.LittleEndian.PutUint32(p[36:40], numParts)
	binary.LittleEndian.PutUint32(p[40:44], numPoints)
	return p
}

// Corrupt counts must be an error naming the problem, not an index panic or a
// huge allocation.
func TestParsePolygonRejectsCountsBeyondPayload(t *testing.T) {
	cases := map[string][]byte{
		"parts beyond payload":  polygonPayload(1000, 0, 8),
		"points beyond payload": polygonPayload(1, 10, 4+16*3),
		"max uint32 counts":     polygonPayload(math.MaxUint32, math.MaxUint32, 16),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			if _, err := parsePolygon(p); err == nil {
				t.Fatal("want error for counts beyond payload")
			}
		})
	}

	// A well-formed record still parses.
	ok := polygonPayload(1, 4, 4+16*4)
	if _, err := parsePolygon(ok); err != nil {
		t.Fatalf("valid payload: %v", err)
	}
}

func TestClassifyRingsByWindingNotOrder(t *testing.T) {
	outer := []Point{{0, 0}, {0, 10}, {10, 10}, {10, 0}, {0, 0}} // clockwise
	hole := []Point{{2, 2}, {4, 2}, {4, 4}, {2, 4}, {2, 2}}      // anticlockwise
	island := []Point{{20, 0}, {20, 1}, {21, 1}, {21, 0}, {20, 0}}
	stray := []Point{{30, 30}, {31, 30}, {31, 31}, {30, 31}, {30, 30}}
	outers, holes, orphans := ClassifyRings([][]Point{hole, island, outer, stray})
	if len(outers) != 2 || len(holes) != 1 || len(orphans) != 1 {
		t.Fatalf("outers=%d holes=%d orphans=%d, want 2/1/1", len(outers), len(holes), len(orphans))
	}
	if got := outers[holes[0].Outer][0]; got != outer[0] {
		t.Errorf("hole assigned to the ring starting %v, want the one starting %v", got, outer[0])
	}
}

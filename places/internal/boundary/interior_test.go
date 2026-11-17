package boundary

import "testing"

func pts(xy ...float64) []Point {
	var out []Point
	for i := 0; i < len(xy); i += 2 {
		out = append(out, Point{xy[i], xy[i+1]})
	}
	return out
}

func TestInteriorPoint(t *testing.T) {
	// A square: the centroid.
	sq := pts(145, -38, 145, -37, 146, -37, 146, -38, 145, -38) // clockwise
	outers, holes, _ := ClassifyRings([][]Point{sq})
	p, m := InteriorPoint(outers, holes, 1e-4)
	if m != "centroid" || p.X != 145.5 || p.Y != -37.5 {
		t.Errorf("square: %v %s", p, m)
	}

	// A U shape: the centroid falls in the notch, so the pole is used, and is
	// inside an arm.
	u := pts(145, -38, 145, -37, 145.2, -37, 145.2, -37.8, 145.8, -37.8, 145.8, -37, 146, -37, 146, -38, 145, -38)
	outers, holes, _ = ClassifyRings([][]Point{u})
	p, m = InteriorPoint(outers, holes, 1e-4)
	if m != "pole" || !insideArea(p, [][]Point{outers[0]}) {
		t.Errorf("U: %v %s, want an interior pole", p, m)
	}

	// A square with a hole in the middle: not in the hole.
	hole := pts(145.3, -37.7, 145.7, -37.7, 145.7, -37.3, 145.3, -37.3, 145.3, -37.7) // anticlockwise
	outers, holes, _ = ClassifyRings([][]Point{sq, hole})
	p, m = InteriorPoint(outers, holes, 1e-4)
	if m != "pole" || pointInRing(p, hole) != -1 || pointInRing(p, sq) != 1 {
		t.Errorf("holed square: %v %s", p, m)
	}

	// The largest of several outer rings (mainland, not island).
	island := pts(147, -39, 147, -38.9, 147.1, -38.9, 147.1, -39, 147, -39)
	outers, holes, _ = ClassifyRings([][]Point{island, sq})
	if p, _ = InteriorPoint(outers, holes, 1e-4); p.X != 145.5 {
		t.Errorf("islands: %v, want the mainland centroid", p)
	}
}

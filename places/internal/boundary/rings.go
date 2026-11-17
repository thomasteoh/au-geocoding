package boundary

import "math"

// Hole is an interior ring and the index (into the outer rings ClassifyRings
// returned) of the outer ring it is cut out of.
type Hole struct {
	Outer int
	Ring  []Point
}

// ClassifyRings splits one shapefile record's parts into outer rings and
// holes. The ESRI spec orders a polygon's vertices clockwise for an outer ring
// and anticlockwise for a hole; part order means nothing (parts[0] is not
// necessarily the outer ring, and a record can have several outer rings).
// Measured on Victoria's localities: 2,973 clockwise rings, 6 anticlockwise.
//
// Each hole is assigned to the smallest outer ring that contains it, so an
// island inside a lake inside a locality stays part of the locality. A hole no
// outer ring contains is returned in orphans, for the caller to report. A
// record with no clockwise ring does not follow the spec's winding at all, so
// every ring is treated as an outer ring rather than all as holes.
func ClassifyRings(parts [][]Point) (outers [][]Point, holes []Hole, orphans [][]Point) {
	var inner [][]Point
	for _, r := range parts {
		r = closeRing(r)
		if len(r) < 4 {
			continue
		}
		switch a := signedArea(r); {
		case a < 0:
			outers = append(outers, r)
		case a > 0:
			inner = append(inner, r)
		}
	}
	if len(outers) == 0 {
		return inner, nil, nil
	}
	for _, h := range inner {
		best, bestArea := -1, math.Inf(1)
		for i, o := range outers {
			if a := ringArea(o); a < bestArea && ringInside(h, o) {
				best, bestArea = i, a
			}
		}
		if best < 0 {
			orphans = append(orphans, h)
			continue
		}
		holes = append(holes, Hole{Outer: best, Ring: h})
	}
	return outers, holes, orphans
}

// signedArea is the shoelace area with sign: positive for anticlockwise
// (x = longitude, y = latitude), negative for clockwise.
func signedArea(r []Point) float64 {
	var s float64
	for i := 0; i < len(r)-1; i++ {
		s += r[i].X*r[i+1].Y - r[i+1].X*r[i].Y
	}
	return s / 2
}

// ringInside reports whether ring h lies inside ring o. A hole may share
// vertices with its outer ring, so a vertex on the boundary decides nothing:
// the first vertex strictly inside or outside answers.
func ringInside(h, o []Point) bool {
	for _, p := range h[:len(h)-1] {
		switch pointInRing(p, o) {
		case 1:
			return true
		case -1:
			return false
		}
	}
	return false
}

// pointInRing is the even-odd ray cast: 1 inside, -1 outside, 0 on the
// boundary.
func pointInRing(p Point, r []Point) int {
	in := false
	for i := 0; i < len(r)-1; i++ {
		a, b := r[i], r[i+1]
		if crossf(a, b, p) == 0 &&
			p.X >= math.Min(a.X, b.X) && p.X <= math.Max(a.X, b.X) &&
			p.Y >= math.Min(a.Y, b.Y) && p.Y <= math.Max(a.Y, b.Y) {
			return 0
		}
		if (a.Y > p.Y) != (b.Y > p.Y) &&
			p.X < (b.X-a.X)*(p.Y-a.Y)/(b.Y-a.Y)+a.X {
			in = !in
		}
	}
	if in {
		return 1
	}
	return -1
}

package boundary

import (
	"container/heap"
	"math"
)

// InteriorPoint returns a representative point for an area made of outers
// (outer rings) and holes, as ClassifyRings returns them: a point guaranteed
// to be inside the area, for answering "where is this postcode" with a point
// that is in it. It works on the largest outer ring (the mainland, not an
// island) and its holes. The ring's centroid is used when it is inside, since
// it is the natural centre of a compact shape; otherwise (a crescent, a ring
// around a lake) the pole of inaccessibility, the interior point furthest
// from the edge, found to within precision degrees. method says which.
func InteriorPoint(outers [][]Point, holes []Hole, precision float64) (p Point, method string) {
	if len(outers) == 0 {
		return Point{}, ""
	}
	big := 0
	for i := range outers {
		if ringArea(outers[i]) > ringArea(outers[big]) {
			big = i
		}
	}
	rings := [][]Point{closeRing(outers[big])}
	for _, h := range holes {
		if h.Outer == big {
			rings = append(rings, closeRing(h.Ring))
		}
	}
	if c, ok := ringCentroid(rings[0]); ok && insideArea(c, rings) {
		return c, "centroid"
	}
	return poleOfInaccessibility(rings, precision), "pole"
}

// insideArea reports whether p is strictly inside rings[0] and outside every
// other ring (its holes).
func insideArea(p Point, rings [][]Point) bool {
	if pointInRing(p, rings[0]) != 1 {
		return false
	}
	for _, h := range rings[1:] {
		if pointInRing(p, h) != -1 {
			return false
		}
	}
	return true
}

// ringCentroid is the area-weighted centroid of a closed ring.
func ringCentroid(r []Point) (Point, bool) {
	var a, cx, cy float64
	for i := 0; i < len(r)-1; i++ {
		f := r[i].X*r[i+1].Y - r[i+1].X*r[i].Y
		a += f
		cx += (r[i].X + r[i+1].X) * f
		cy += (r[i].Y + r[i+1].Y) * f
	}
	if a == 0 {
		return Point{}, false
	}
	return Point{cx / (3 * a), cy / (3 * a)}, true
}

// edgeDist is the signed distance from p to the area's edge: positive inside,
// negative outside. Longitude is scaled by cos(latitude) so distances are
// roughly isotropic.
func edgeDist(p Point, rings [][]Point, kx float64) float64 {
	min := math.Inf(1)
	for _, r := range rings {
		for i := 0; i < len(r)-1; i++ {
			if d := segDist(p, r[i], r[i+1], kx); d < min {
				min = d
			}
		}
	}
	if insideArea(p, rings) {
		return min
	}
	return -min
}

func segDist(p, a, b Point, kx float64) float64 {
	ax, ay := (a.X-p.X)*kx, a.Y-p.Y
	bx, by := (b.X-p.X)*kx, b.Y-p.Y
	dx, dy := bx-ax, by-ay
	t := 0.0
	if l := dx*dx + dy*dy; l > 0 {
		t = math.Max(0, math.Min(1, -(ax*dx+ay*dy)/l))
	}
	x, y := ax+t*dx, ay+t*dy
	return math.Hypot(x, y)
}

type cell struct {
	c      Point
	h      float64 // half size, degrees of latitude
	d, max float64
}

type cellQueue []*cell

func (q cellQueue) Len() int           { return len(q) }
func (q cellQueue) Less(i, j int) bool { return q[i].max > q[j].max }
func (q cellQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *cellQueue) Push(x any)        { *q = append(*q, x.(*cell)) }
func (q *cellQueue) Pop() any          { o := *q; c := o[len(o)-1]; *q = o[:len(o)-1]; return c }

// poleOfInaccessibility is the polylabel search (Mapbox, 2016): cover the
// ring's bbox with square cells, and keep splitting the cell that could hold
// a point further from the edge than the best found, until no cell can beat
// it by more than precision.
func poleOfInaccessibility(rings [][]Point, precision float64) Point {
	b := bbox(rings[:1])
	minX, minY, maxX, maxY := b[0], b[1], b[2], b[3]
	kx := math.Cos((minY + maxY) / 2 * math.Pi / 180)
	w, h := (maxX-minX)*kx, maxY-minY
	size := math.Min(w, h)
	if size == 0 {
		return Point{minX, minY}
	}
	mk := func(x, y, half float64) *cell {
		c := &cell{c: Point{x, y}, h: half}
		c.d = edgeDist(c.c, rings, kx)
		c.max = c.d + half*math.Sqrt2
		return c
	}
	q := &cellQueue{}
	half := size / 2
	for x := minX; x < maxX; x += size / kx {
		for y := minY; y < maxY; y += size {
			heap.Push(q, mk(x+half/kx, y+half, half))
		}
	}
	best := mk((minX+maxX)/2, (minY+maxY)/2, 0)
	if c, ok := ringCentroid(rings[0]); ok {
		if cc := mk(c.X, c.Y, 0); cc.d > best.d {
			best = cc
		}
	}
	for n := 0; q.Len() > 0 && n < 100000; n++ {
		c := heap.Pop(q).(*cell)
		if c.d > best.d {
			best = c
		}
		if c.max-best.d <= precision {
			continue
		}
		hh := c.h / 2
		for _, o := range [][2]float64{{-1, -1}, {1, -1}, {-1, 1}, {1, 1}} {
			heap.Push(q, mk(c.c.X+o[0]*hh/kx, c.c.Y+o[1]*hh, hh))
		}
	}
	return best.c
}

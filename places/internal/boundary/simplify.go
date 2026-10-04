package boundary

// P10 — boundary simplification (processes.md).
//
// Precomputes the locality outline the UI renders as a local SVG. Runs at
// build time (P1 stage 4), so the runtime cost is serving a string.
//
// The tolerance is derived per polygon from its own bbox, never from a global
// constant (R10.1): locality bboxes span three orders of magnitude, so one
// tolerance either shreds the small ones or leaves the large ones dense.
//
//	tol_degrees = (bbox_span_degrees / viewbox_px) x subpixel_factor
//
// This is self-normalising — every locality, whatever its size, is simplified
// to the same *visual* fidelity. Detail finer than one screen pixel is
// storage and bandwidth spent on something nobody can see.
//
// The gate is max pixel deviation, not area error (R10.3). Area error is
// unusable as a gate because inward and outward deviations cancel: Doncaster
// at subpixel=2.0 reports *better* area error than at 1.0 while visibly
// cutting corners. Area error is recorded for information only.

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Defaults from the measured results in processes.md. subpixel=0.5 is the
// point at which the simplified vertex count and the quantised count converge
// (Doncaster 176 -> 171), which is the signal the tolerance is right:
// simplification has removed exactly the detail the grid would have discarded
// anyway, and no more.
const (
	DefaultViewBox       = 200
	DefaultSubPixel      = 0.5
	DefaultMinRingAreaPx = 1.0

	// R10.4: how many times to retry at a finer tolerance before falling back
	// to the convex hull.
	maxSimplifyRetries = 3
)

// Options configure outline generation. The zero value is valid and uses the
// defaults above.
type Options struct {
	// ViewBox is the square pixel grid the outline is quantised onto. Stored
	// with the path (R10.8) — a different display size needs a rebuild, not a
	// runtime rescale.
	ViewBox int
	// SubPixel is the fraction of a pixel the simplification is allowed to
	// deviate. Also the fidelity gate.
	SubPixel float64
	// MinRingAreaPx drops rings smaller than this many square pixels (R10.5).
	// A ring that cannot cover a pixel cannot be seen; the threshold is in
	// display units so it scales with the locality like everything else.
	MinRingAreaPx float64
}

func (o Options) withDefaults() Options {
	if o.ViewBox <= 0 {
		o.ViewBox = DefaultViewBox
	}
	if o.SubPixel <= 0 {
		o.SubPixel = DefaultSubPixel
	}
	if o.MinRingAreaPx <= 0 {
		o.MinRingAreaPx = DefaultMinRingAreaPx
	}
	return o
}

// IPoint is a quantised grid point. Integers only (R10.7) — no floats reach
// the client, and integer coordinates make the self-intersection test exact.
type IPoint struct{ X, Y int }

// Outline is the precomputed render-ready locality outline.
type Outline struct {
	// Path is the SVG path: absolute M to open each subpath, then relative l
	// deltas, then Z. Integers only.
	Path string
	// ViewBox and SubPixel are stored so the path is re-derivable (R10.8).
	ViewBox  int
	SubPixel float64
	// Rings is the number of rings kept (outer + holes + islands).
	Rings int
	// MaxDevPx is the gate value: the largest perpendicular distance from any
	// original vertex to the simplified outline, in pixels.
	MaxDevPx float64
	// AreaErrPct is recorded for information only and gates nothing (R10.3).
	AreaErrPct float64
	// Hull is set when the outline fell back to the convex hull because the
	// *source* geometry crosses itself (R10.4). The locality is flagged
	// rather than silently shipped with a malformed shape.
	Hull bool
	// Pinched is set when the quantised outline crosses itself even though the
	// source geometry is clean — two parts of the boundary pass within a
	// fraction of a pixel and the grid snaps them together. The path is kept
	// because it is accurate and renders correctly under FillRule; the flag
	// records that the artifact is there.
	Pinched bool
	// Degenerate is set when no ring survived (R10.6). Path is empty and the
	// UI falls back to the point marker with no outline.
	Degenerate bool
	// BBox is the source lon/lat extent: minLon, minLat, maxLon, maxLat.
	BBox [4]float64
	// Verts is the final quantised vertex count across all rings.
	Verts int
}

// FillRule is the rule the UI must use to render Path. Holes are kept as
// subpaths (R10.5) rather than as separate shapes, so the renderer needs
// even-odd to punch them out.
const FillRule = "evenodd"

// Simplify turns a source polygon into a render-ready outline.
//
// Stages (processes.md P10): project, simplify, quantise, encode, validate,
// then the caller stores. A non-nil error means the fidelity gate was breached
// and the build must fail (R10.3); the Outline is still returned so the caller
// can report which locality and by how much.
func Simplify(p Polygon, opt Options) (Outline, error) {
	opt = opt.withDefaults()
	out := Outline{ViewBox: opt.ViewBox, SubPixel: opt.SubPixel}

	// Drop degenerate rings up front (R10.6): fewer than 4 points or zero
	// area cannot describe a shape.
	var rings [][]Point
	for _, r := range p.Parts {
		r = closeRing(r)
		if len(r) < 4 || ringArea(r) <= 0 {
			continue
		}
		rings = append(rings, r)
	}
	if len(rings) == 0 {
		out.Degenerate = true
		return out, nil
	}
	out.BBox = bbox(rings)

	// Stage 1 — project. Longitude is scaled by cos(latitude) at the mid
	// latitude (R10.2). At -37 degrees a degree of longitude is ~79% of a
	// degree of latitude; skipping this visibly stretches every outline.
	midLat := (out.BBox[1] + out.BBox[3]) / 2
	cosLat := math.Cos(midLat * math.Pi / 180)
	if cosLat < 1e-6 {
		cosLat = 1e-6
	}
	projected := make([][]Point, len(rings))
	for i, r := range rings {
		projected[i] = projectRing(r, cosLat)
	}

	// Establish the scale, then drop sub-threshold rings (R10.5). Dropping a
	// ring can shrink the extent, which changes the scale, which changes which
	// rings are sub-threshold — so iterate to a fixed point. A far-flung speck
	// of an island would otherwise set the scale for the whole locality and
	// shrink the mainland to nothing.
	kept := projected
	var scale, span float64
	var ox, oy float64
	for i := 0; i < 4; i++ {
		span, scale, ox, oy = fit(kept, opt.ViewBox)
		next := make([][]Point, 0, len(kept))
		for _, r := range kept {
			if ringArea(r)*scale*scale >= opt.MinRingAreaPx {
				next = append(next, r)
			}
		}
		if len(next) == 0 || len(next) == len(kept) {
			kept = next
			break
		}
		kept = next
	}
	if len(kept) == 0 {
		out.Degenerate = true
		return out, nil
	}
	span, scale, ox, oy = fit(kept, opt.ViewBox)
	_ = span

	// Stages 2-3 — simplify at the adaptive tolerance, then quantise onto the
	// integer grid. Quantisation alone does substantial work: consecutive
	// points that land on the same pixel collapse.
	tol0 := opt.SubPixel / scale
	grid, simplified, clean := buildRings(kept, tol0, scale, ox, oy)

	// R10.4 — retry at a finer tolerance. This is the right remedy when the
	// cause is over-simplification pulling a concave section through itself,
	// which is what the spec anticipated.
	if !clean {
		tol := tol0
		for attempt := 1; attempt <= maxSimplifyRetries; attempt++ {
			tol /= 2
			if g, sm, c := buildRings(kept, tol, scale, ox, oy); c {
				grid, simplified, clean = g, sm, true
				break
			}
		}
	}

	if len(grid) == 0 {
		out.Degenerate = true
		return out, nil
	}

	if !clean {
		// Retrying did not clear it, so the two causes have to be told apart —
		// they want opposite responses.
		//
		// On real Geoscape data this is where the spec met a case it had not
		// seen: validated against four Nominatim localities, R10.4 assumed a
		// leftover self-intersection means a malformed shape. Measured across
		// Victoria's 2,973 localities, the usual cause is instead that two parts
		// of a clean boundary pass within a fraction of a pixel of each other —
		// Brighton's narrowest gap is 0.016 px — and the grid snaps them onto
		// crossing segments. A finer tolerance cannot help, because the grid
		// caused it, not the simplification.
		//
		// So: if the source geometry genuinely crosses itself, the data is
		// malformed and the hull is the honest fallback (R10.4 as written). If
		// the source is clean, the crossing is a sub-pixel pinch; keep the
		// accurate outline and flag it. Substituting a hull there is far worse —
		// for Brighton it means 16.67 px deviation and 15.9% area error against
		// 0.50 px for the pinched path.
		if sourceSelfIntersects(kept) {
			hull := convexHull(largestRing(kept))
			g := quantise(hull, scale, ox, oy)
			if len(g) < 4 {
				out.Degenerate = true
				return out, nil
			}
			// A hull is not the shape, so the fidelity gate does not apply; the
			// flag is how the breach surfaces instead.
			out.Hull = true
			out.Rings = 1
			out.Verts = len(g)
			out.Path = encodePath([][]IPoint{g})
			out.MaxDevPx = maxDeviation(largestRing(kept), hull) * scale
			out.AreaErrPct = areaErrPct(kept, [][]Point{hull})
			return out, nil
		}
		// Sub-pixel pinch on clean source geometry. Keep the base-tolerance
		// outline: it is accurate, it still passes the fidelity gate, and
		// even-odd renders it correctly. The flag makes the artifact visible.
		out.Pinched = true
	}

	// Stage 4 — encode.
	out.Rings = len(grid)
	out.Path = encodePath(grid)
	for _, g := range grid {
		out.Verts += len(g)
	}

	// Stage 5 — validate. Deviation is measured against the simplified ring:
	// Douglas-Peucker bounds it by the tolerance, so this is the check that
	// the implementation actually honours that bound. Quantisation error on
	// top is bounded by half a grid cell by construction, and the grid is the
	// display, so it is invisible by definition.
	for i := range simplified {
		if d := maxDeviation(kept[i], simplified[i]) * scale; d > out.MaxDevPx {
			out.MaxDevPx = d
		}
	}
	out.AreaErrPct = areaErrPct(kept, simplified)

	// R10.3 — the gate. A small epsilon absorbs float noise in the distance
	// computation; it is far below anything visible.
	if out.MaxDevPx > opt.SubPixel+1e-9 {
		return out, fmt.Errorf("fidelity gate: max deviation %.4f px exceeds %.4f px", out.MaxDevPx, opt.SubPixel)
	}
	return out, nil
}

// fit returns the projected span, the pixels-per-projected-degree scale, and
// the offsets that centre the shape in the square viewbox. The scale is
// uniform across both axes so the aspect ratio survives.
func fit(rings [][]Point, viewbox int) (span, scale, ox, oy float64) {
	b := bbox(rings)
	w, h := b[2]-b[0], b[3]-b[1]
	span = math.Max(w, h)
	if span <= 0 {
		span = 1e-12
	}
	scale = float64(viewbox) / span
	ox = b[0] - (span-w)/2
	oy = b[3] + (span-h)/2 // y is flipped on encode, so anchor at the top
	return span, scale, ox, oy
}

func projectRing(r []Point, cosLat float64) []Point {
	out := make([]Point, len(r))
	for i, p := range r {
		out[i] = Point{X: p.X * cosLat, Y: p.Y}
	}
	return out
}

func closeRing(r []Point) []Point {
	if len(r) == 0 {
		return r
	}
	if r[0] != r[len(r)-1] {
		out := make([]Point, len(r), len(r)+1)
		copy(out, r)
		return append(out, r[0])
	}
	return r
}

func bbox(rings [][]Point) [4]float64 {
	b := [4]float64{math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)}
	for _, r := range rings {
		for _, p := range r {
			b[0] = math.Min(b[0], p.X)
			b[1] = math.Min(b[1], p.Y)
			b[2] = math.Max(b[2], p.X)
			b[3] = math.Max(b[3], p.Y)
		}
	}
	return b
}

// ringArea is the shoelace area, unsigned. The ring is assumed closed.
func ringArea(r []Point) float64 {
	if len(r) < 4 {
		return 0
	}
	var s float64
	for i := 0; i < len(r)-1; i++ {
		s += r[i].X*r[i+1].Y - r[i+1].X*r[i].Y
	}
	return math.Abs(s) / 2
}

func largestRing(rings [][]Point) []Point {
	best, bestArea := rings[0], ringArea(rings[0])
	for _, r := range rings[1:] {
		if a := ringArea(r); a > bestArea {
			best, bestArea = r, a
		}
	}
	return best
}

func areaErrPct(orig, simp [][]Point) float64 {
	var ao, as float64
	for _, r := range orig {
		ao += ringArea(r)
	}
	for _, r := range simp {
		as += ringArea(r)
	}
	if ao == 0 {
		return 0
	}
	return math.Abs(as-ao) / ao * 100
}

// simplifyRing runs Douglas-Peucker on a closed ring.
//
// DP simplifies a polyline between two fixed anchors, so a ring needs two of
// them or the result collapses. Split the ring at the vertex farthest from the
// first, simplify each arc independently, and rejoin.
func simplifyRing(r []Point, tol float64) []Point {
	open := r[:len(r)-1]
	if len(open) < 3 {
		return r
	}
	far, farD := 0, -1.0
	for i, p := range open {
		if d := dist2(open[0], p); d > farD {
			far, farD = i, d
		}
	}
	if far == 0 {
		return r
	}
	arc1 := douglasPeucker(open[:far+1], tol)
	arc2 := douglasPeucker(append(append([]Point{}, open[far:]...), open[0]), tol)
	out := append(arc1[:len(arc1)-1:len(arc1)-1], arc2...)
	return closeRing(out)
}

func douglasPeucker(pts []Point, tol float64) []Point {
	if len(pts) < 3 {
		return pts
	}
	maxD, idx := -1.0, 0
	a, b := pts[0], pts[len(pts)-1]
	for i := 1; i < len(pts)-1; i++ {
		if d := perpDist(pts[i], a, b); d > maxD {
			maxD, idx = d, i
		}
	}
	if maxD <= tol {
		return []Point{a, b}
	}
	left := douglasPeucker(pts[:idx+1], tol)
	right := douglasPeucker(pts[idx:], tol)
	return append(left[:len(left)-1:len(left)-1], right...)
}

// perpDist is the perpendicular distance from p to segment ab. When a and b
// coincide the segment is a point, so fall back to point distance.
func perpDist(p, a, b Point) float64 {
	dx, dy := b.X-a.X, b.Y-a.Y
	if dx == 0 && dy == 0 {
		return math.Hypot(p.X-a.X, p.Y-a.Y)
	}
	t := ((p.X-a.X)*dx + (p.Y-a.Y)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(p.X-(a.X+t*dx), p.Y-(a.Y+t*dy))
}

func dist2(a, b Point) float64 {
	dx, dy := a.X-b.X, a.Y-b.Y
	return dx*dx + dy*dy
}

// maxDeviation is the largest distance from any original vertex to the
// simplified outline, in projected units. Multiply by scale for pixels.
func maxDeviation(orig, simp []Point) float64 {
	if len(simp) < 2 {
		return 0
	}
	var worst float64
	for _, p := range orig {
		best := math.Inf(1)
		for i := 0; i < len(simp)-1; i++ {
			if d := perpDist(p, simp[i], simp[i+1]); d < best {
				best = d
			}
		}
		if best > worst {
			worst = best
		}
	}
	return worst
}

// quantise maps projected coordinates onto the integer grid and collapses
// consecutive points that land on the same pixel. Y is flipped because SVG
// counts down from the top while latitude counts up.
func quantise(r []Point, scale, ox, oy float64) []IPoint {
	out := make([]IPoint, 0, len(r))
	for _, p := range r {
		q := IPoint{
			X: int(math.Round((p.X - ox) * scale)),
			Y: int(math.Round((oy - p.Y) * scale)),
		}
		if n := len(out); n > 0 && out[n-1] == q {
			continue
		}
		out = append(out, q)
	}
	// Re-close: the collapse may have dropped the duplicate endpoint, and a
	// ring that collapsed to its own start point is not a ring.
	if len(out) > 1 && out[0] != out[len(out)-1] {
		out = append(out, out[0])
	}
	for len(out) > 1 && out[0] == out[len(out)-1] && len(out) < 4 {
		return nil
	}
	return out
}

// encodePath writes the SVG path. Each subpath opens with an absolute M and
// continues with relative l deltas, which is what keeps the numbers small;
// holes and islands are subpaths on the same path, rendered with FillRule.
func encodePath(rings [][]IPoint) string {
	var b strings.Builder
	for _, r := range rings {
		if len(r) < 4 {
			continue
		}
		b.WriteByte('M')
		b.WriteString(strconv.Itoa(r[0].X))
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(r[0].Y))
		// The final point repeats the first; Z closes the ring instead.
		prev := r[0]
		for _, p := range r[1 : len(r)-1] {
			b.WriteByte('l')
			b.WriteString(strconv.Itoa(p.X - prev.X))
			b.WriteByte(' ')
			b.WriteString(strconv.Itoa(p.Y - prev.Y))
			prev = p
		}
		b.WriteByte('Z')
	}
	return b.String()
}

// selfIntersects reports whether a quantised ring crosses itself. The points
// are integers, so the orientation tests below are exact — no epsilon, no
// float tie-breaking.
func selfIntersects(r []IPoint) bool {
	n := len(r) - 1 // last repeats the first
	if n < 4 {
		return false
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			// Adjacent segments legitimately share a vertex, as do the first
			// and last around the closure.
			if j == i+1 || (i == 0 && j == n-1) {
				continue
			}
			if segIntersect(r[i], r[i+1], r[j], r[j+1]) {
				return true
			}
		}
	}
	return false
}

// segIntersect reports a genuine crossing, not a touch.
//
// The distinction matters enormously on a coarse grid. Quantising a 170-vertex
// ring onto 200x200 pixels makes it common — by pigeonhole, near enough to
// inevitable — for some vertex to land exactly on a non-adjacent segment. That
// is a touch, and it renders correctly under even-odd. Counting it as a
// self-intersection sent 7% of Victoria's localities down the hull fallback,
// and retrying at a finer tolerance could never clear it, because the grid
// caused it rather than the simplification.
//
// So: a proper crossing (each segment strictly straddles the other), or a
// collinear overlap sharing actual length. A single shared point is neither.
func segIntersect(p1, p2, p3, p4 IPoint) bool {
	d1 := orient(p3, p4, p1)
	d2 := orient(p3, p4, p2)
	d3 := orient(p1, p2, p3)
	d4 := orient(p1, p2, p4)

	if d1 != 0 && d2 != 0 && d3 != 0 && d4 != 0 &&
		(d1 > 0) != (d2 > 0) && (d3 > 0) != (d4 > 0) {
		return true
	}
	if d1 == 0 && d2 == 0 && d3 == 0 && d4 == 0 {
		return collinearOverlap(p1, p2, p3, p4)
	}
	return false
}

// collinearOverlap reports whether two collinear segments share more than a
// single point. Measured along whichever axis the segments actually extend on,
// so a vertical pair is not judged on its constant x.
func collinearOverlap(p1, p2, p3, p4 IPoint) bool {
	if abs(p2.X-p1.X) >= abs(p2.Y-p1.Y) {
		return spanOverlap(p1.X, p2.X, p3.X, p4.X)
	}
	return spanOverlap(p1.Y, p2.Y, p3.Y, p4.Y)
}

func spanOverlap(a1, a2, b1, b2 int) bool {
	if a1 > a2 {
		a1, a2 = a2, a1
	}
	if b1 > b2 {
		b1, b2 = b2, b1
	}
	return min(a2, b2) > max(a1, b1)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// orient is the sign of the cross product (b-a)x(c-a), computed in int64 so
// it is exact for grid coordinates.
func orient(a, b, c IPoint) int {
	v := int64(b.X-a.X)*int64(c.Y-a.Y) - int64(b.Y-a.Y)*int64(c.X-a.X)
	switch {
	case v > 0:
		return 1
	case v < 0:
		return -1
	}
	return 0
}

// convexHull is the monotone-chain hull, used only as the R10.4 fallback.
func convexHull(pts []Point) []Point {
	if len(pts) < 4 {
		return pts
	}
	ps := append([]Point{}, pts[:len(pts)-1]...)
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].X != ps[j].X {
			return ps[i].X < ps[j].X
		}
		return ps[i].Y < ps[j].Y
	})
	build := func(src []Point) []Point {
		var h []Point
		for _, p := range src {
			for len(h) >= 2 && crossf(h[len(h)-2], h[len(h)-1], p) <= 0 {
				h = h[:len(h)-1]
			}
			h = append(h, p)
		}
		return h
	}
	lower := build(ps)
	rev := make([]Point, len(ps))
	for i, p := range ps {
		rev[len(ps)-1-i] = p
	}
	upper := build(rev)
	hull := append(lower[:len(lower)-1:len(lower)-1], upper...)
	return closeRing(hull)
}

func crossf(o, a, b Point) float64 {
	return (a.X-o.X)*(b.Y-o.Y) - (a.Y-o.Y)*(b.X-o.X)
}

// buildRings simplifies and quantises every ring at tol. clean reports whether
// the result is free of self-intersections; the rings are returned either way,
// because a pinched outline is still the one worth keeping.
func buildRings(rings [][]Point, tol, scale, ox, oy float64) (grid [][]IPoint, simp [][]Point, clean bool) {
	clean = true
	for _, r := range rings {
		s := simplifyRing(r, tol)
		g := quantise(s, scale, ox, oy)
		if len(g) < 4 {
			// Collapsed to nothing on the grid — not renderable, but not a
			// self-intersection either. Skip the ring (R10.6).
			continue
		}
		if selfIntersects(g) {
			clean = false
		}
		simp = append(simp, s)
		grid = append(grid, g)
	}
	return grid, simp, clean
}

// sourceSelfIntersects checks the projected rings at full float precision,
// before quantisation — the question being whether the source data is
// malformed or the grid merely pinched a clean shape.
//
// This is O(n^2) on the raw ring, which is why it runs only after the retries
// have failed: roughly 1% of localities, rather than all of them.
func sourceSelfIntersects(rings [][]Point) bool {
	for _, r := range rings {
		n := len(r) - 1
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				if j == i+1 || (i == 0 && j == n-1) {
					continue
				}
				if properCross(r[i], r[i+1], r[j], r[j+1]) {
					return true
				}
			}
		}
	}
	return false
}

// properCross is the float counterpart of segIntersect's strict-straddle test.
// Only a transversal crossing counts; touching does not.
func properCross(p1, p2, p3, p4 Point) bool {
	d1 := sgnf(crossf(p3, p4, p1))
	d2 := sgnf(crossf(p3, p4, p2))
	d3 := sgnf(crossf(p1, p2, p3))
	d4 := sgnf(crossf(p1, p2, p4))
	return d1 != 0 && d2 != 0 && d3 != 0 && d4 != 0 && d1 != d2 && d3 != d4
}

func sgnf(v float64) int {
	switch {
	case v > 0:
		return 1
	case v < 0:
		return -1
	}
	return 0
}

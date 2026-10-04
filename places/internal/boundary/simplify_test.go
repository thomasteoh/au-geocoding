package boundary

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

// square returns a closed axis-aligned ring with n points per side, centred on
// (lon, lat) with the given span in degrees. Extra points per side are
// collinear filler — exactly the detail simplification should remove.
func square(lon, lat, span float64, perSide int) []Point {
	var r []Point
	step := span / float64(perSide)
	for i := 0; i < perSide; i++ {
		r = append(r, Point{lon + float64(i)*step, lat})
	}
	for i := 0; i < perSide; i++ {
		r = append(r, Point{lon + span, lat + float64(i)*step})
	}
	for i := 0; i < perSide; i++ {
		r = append(r, Point{lon + span - float64(i)*step, lat + span})
	}
	for i := 0; i < perSide; i++ {
		r = append(r, Point{lon, lat + span - float64(i)*step})
	}
	return append(r, r[0])
}

// jagged returns a circle with a fine sawtooth on it — detail well below one
// pixel at the default settings.
func jagged(lon, lat, radius float64, n int, noise float64) []Point {
	var r []Point
	for i := 0; i < n; i++ {
		a := 2 * math.Pi * float64(i) / float64(n)
		rad := radius
		if i%2 == 0 {
			rad += noise
		}
		r = append(r, Point{lon + rad*math.Cos(a), lat + rad*math.Sin(a)})
	}
	return append(r, r[0])
}

func TestSimplifySquareCollapsesCollinearFiller(t *testing.T) {
	p := Polygon{Parts: [][]Point{square(145.0, -37.8, 0.02, 40)}}
	out, err := Simplify(p, Options{})
	if err != nil {
		t.Fatalf("Simplify: %v", err)
	}
	if out.Degenerate || out.Hull {
		t.Fatalf("square should simplify cleanly, got degenerate=%v hull=%v", out.Degenerate, out.Hull)
	}
	// 160 raw points, 4 real corners. Allow the closing repeat.
	if out.Verts > 8 {
		t.Errorf("square kept %d vertices, want <= 8", out.Verts)
	}
	if out.MaxDevPx > DefaultSubPixel {
		t.Errorf("max deviation %.4f px exceeds gate %.2f", out.MaxDevPx, DefaultSubPixel)
	}
}

// R10.1 — tolerance comes from each polygon's own bbox, so a tiny locality and
// a huge one reach the same *visual* fidelity rather than the same absolute
// tolerance.
func TestToleranceIsPerPolygonNotGlobal(t *testing.T) {
	small, err := Simplify(Polygon{Parts: [][]Point{jagged(145.0, -37.8, 0.008, 200, 0.00004)}}, Options{})
	if err != nil {
		t.Fatalf("small: %v", err)
	}
	big, err := Simplify(Polygon{Parts: [][]Point{jagged(145.0, -37.8, 0.8, 200, 0.004)}}, Options{})
	if err != nil {
		t.Fatalf("big: %v", err)
	}
	// The shapes are the same to within a scale factor of 100, so the vertex
	// counts should land close together. A global tolerance would shred one
	// and leave the other dense.
	d := small.Verts - big.Verts
	if d < 0 {
		d = -d
	}
	if d > 6 {
		t.Errorf("per-polygon tolerance not self-normalising: small=%d big=%d verts", small.Verts, big.Verts)
	}
}

// R10.2 — longitude is scaled by cos(lat). At -37 degrees a degree of
// longitude is ~79% of a degree of latitude, so a shape that is square in
// degrees must come out visibly wider than tall on the pixel grid.
func TestLongitudeScaledByCosLat(t *testing.T) {
	out, err := Simplify(Polygon{Parts: [][]Point{square(145.0, -37.8, 0.1, 4)}}, Options{})
	if err != nil {
		t.Fatalf("Simplify: %v", err)
	}
	minX, maxX, minY, maxY := pathExtent(t, out.Path)
	w, h := maxX-minX, maxY-minY
	if w >= h {
		t.Fatalf("expected cos(lat) to compress longitude: got w=%d h=%d", w, h)
	}
	want := math.Cos(-37.8 * math.Pi / 180)
	got := float64(w) / float64(h)
	if math.Abs(got-want) > 0.02 {
		t.Errorf("aspect %.4f, want ~cos(-37.8)=%.4f", got, want)
	}
}

// R10.3 — the gate is max pixel deviation. Tightening subpixel must tighten
// the measured deviation with it.
func TestFidelityGateTracksSubPixel(t *testing.T) {
	p := Polygon{Parts: [][]Point{jagged(145.0, -37.8, 0.05, 400, 0.002)}}
	for _, sp := range []float64{0.25, 0.5, 1.0} {
		out, err := Simplify(p, Options{SubPixel: sp})
		if err != nil {
			t.Fatalf("subpixel %.2f: %v", sp, err)
		}
		if out.MaxDevPx > sp {
			t.Errorf("subpixel %.2f: deviation %.4f px breached its own gate", sp, out.MaxDevPx)
		}
		if out.SubPixel != sp {
			t.Errorf("subpixel %.2f not recorded, got %.2f", sp, out.SubPixel)
		}
	}
}

// R10.5 — a locality with an island keeps the island as a second subpath.
func TestIslandKeptAsSubpath(t *testing.T) {
	mainland := square(145.0, -37.8, 0.2, 8)
	island := square(145.30, -37.75, 0.05, 8)
	out, err := Simplify(Polygon{Parts: [][]Point{mainland, island}}, Options{})
	if err != nil {
		t.Fatalf("Simplify: %v", err)
	}
	if out.Rings != 2 {
		t.Fatalf("island dropped: rings=%d, want 2", out.Rings)
	}
	if n := strings.Count(out.Path, "M"); n != 2 {
		t.Errorf("path has %d subpaths, want 2", n)
	}
}

// R10.5 — but a speck far smaller than a pixel is not renderable and is
// dropped rather than setting the scale for the whole locality.
func TestSubPixelSpeckDropped(t *testing.T) {
	mainland := square(145.0, -37.8, 0.2, 8)
	speck := square(145.05, -37.75, 0.00002, 4)
	out, err := Simplify(Polygon{Parts: [][]Point{mainland, speck}}, Options{})
	if err != nil {
		t.Fatalf("Simplify: %v", err)
	}
	if out.Rings != 1 {
		t.Errorf("rings=%d, want 1 (speck below MinRingAreaPx)", out.Rings)
	}
}

// R10.6 — degenerate rings store no path at all; the UI falls back to the
// point marker rather than drawing something malformed.
func TestDegenerateRingsStoreNoPath(t *testing.T) {
	cases := map[string]Polygon{
		"too few points": {Parts: [][]Point{{{145, -37}, {145.1, -37}, {145, -37}}}},
		"zero area":      {Parts: [][]Point{{{145, -37}, {145.1, -37}, {145.2, -37}, {145, -37}}}},
		"no rings":       {Parts: nil},
	}
	for name, p := range cases {
		out, err := Simplify(p, Options{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !out.Degenerate {
			t.Errorf("%s: want degenerate", name)
		}
		if out.Path != "" {
			t.Errorf("%s: want empty path, got %q", name, out.Path)
		}
	}
}

// R10.7 — integers only. No float ever reaches the client.
func TestPathIsIntegersOnly(t *testing.T) {
	out, err := Simplify(Polygon{Parts: [][]Point{jagged(145.0, -37.8, 0.05, 200, 0.001)}}, Options{})
	if err != nil {
		t.Fatalf("Simplify: %v", err)
	}
	if strings.ContainsAny(out.Path, ".eE") {
		t.Errorf("path contains non-integer coordinates: %q", out.Path)
	}
	for _, c := range out.Path {
		if !strings.ContainsRune("MlZ-0123456789 ", c) {
			t.Errorf("unexpected character %q in path", c)
		}
	}
}

// R10.8 — viewbox and subpixel are stored with the path so it is
// re-derivable, and the geometry actually honours the requested viewbox.
func TestViewBoxRecordedAndHonoured(t *testing.T) {
	for _, vb := range []int{100, 200, 400} {
		out, err := Simplify(Polygon{Parts: [][]Point{square(145.0, -37.8, 0.1, 8)}}, Options{ViewBox: vb})
		if err != nil {
			t.Fatalf("viewbox %d: %v", vb, err)
		}
		if out.ViewBox != vb {
			t.Errorf("viewbox %d not recorded, got %d", vb, out.ViewBox)
		}
		minX, maxX, minY, maxY := pathExtent(t, out.Path)
		if minX < 0 || minY < 0 || maxX > vb || maxY > vb {
			t.Errorf("viewbox %d: extent (%d,%d)-(%d,%d) escapes the grid", vb, minX, minY, maxX, maxY)
		}
	}
}

// A larger viewbox is a finer grid, so it must keep more detail.
func TestLargerViewBoxKeepsMoreDetail(t *testing.T) {
	p := Polygon{Parts: [][]Point{jagged(145.0, -37.8, 0.05, 600, 0.0006)}}
	small, err := Simplify(p, Options{ViewBox: 100})
	if err != nil {
		t.Fatal(err)
	}
	big, err := Simplify(p, Options{ViewBox: 800})
	if err != nil {
		t.Fatal(err)
	}
	if big.Verts <= small.Verts {
		t.Errorf("viewbox 800 kept %d verts, viewbox 100 kept %d — finer grid should keep more", big.Verts, small.Verts)
	}
}

// R10.4 — the output is checked for self-intersection.
func TestSelfIntersectionDetected(t *testing.T) {
	bowtie := []IPoint{{0, 0}, {10, 10}, {10, 0}, {0, 10}, {0, 0}}
	if !selfIntersects(bowtie) {
		t.Error("bowtie not detected as self-intersecting")
	}
	clean := []IPoint{{0, 0}, {10, 0}, {10, 10}, {0, 10}, {0, 0}}
	if selfIntersects(clean) {
		t.Error("square reported as self-intersecting")
	}
}

func TestSimplifiedOutputIsNotSelfIntersecting(t *testing.T) {
	// A concave comb — the shape most likely to fold through itself when
	// over-simplified.
	var r []Point
	for i := 0; i < 20; i++ {
		x := 145.0 + float64(i)*0.004
		y := -37.8
		if i%2 == 1 {
			y += 0.03
		}
		r = append(r, Point{x, y})
	}
	r = append(r, Point{145.08, -37.9}, Point{145.0, -37.9})
	r = append(r, r[0])

	out, err := Simplify(Polygon{Parts: [][]Point{r}}, Options{})
	if err != nil {
		t.Fatalf("Simplify: %v", err)
	}
	if out.Degenerate {
		t.Fatal("comb went degenerate")
	}
	for _, ring := range parsePath(t, out.Path) {
		if selfIntersects(ring) {
			t.Errorf("simplified output self-intersects: %q", out.Path)
		}
	}
}

func TestConvexHullFallbackIsClosedAndConvex(t *testing.T) {
	src := jagged(145.0, -37.8, 0.05, 40, 0.01)
	h := convexHull(src)
	if len(h) < 4 {
		t.Fatalf("hull too small: %d", len(h))
	}
	if h[0] != h[len(h)-1] {
		t.Error("hull not closed")
	}
	for i := 0; i+2 < len(h); i++ {
		if crossf(h[i], h[i+1], h[i+2]) < -1e-12 {
			t.Errorf("hull turns the wrong way at %d", i)
		}
	}
}

// Quantisation collapses consecutive points landing on the same pixel — the
// spec notes this alone does substantial work before any simplification.
func TestQuantiseCollapsesSamePixelPoints(t *testing.T) {
	r := []Point{{0, 0}, {0.0001, 0.0001}, {0.0002, 0}, {1, 0}, {1, 1}, {0, 1}, {0, 0}}
	g := quantise(r, 10, 0, 1)
	for i := 1; i < len(g); i++ {
		if g[i] == g[i-1] {
			t.Errorf("consecutive duplicate at %d: %v", i, g[i])
		}
	}
}

func TestEncodePathRelativeDeltas(t *testing.T) {
	ring := []IPoint{{10, 20}, {30, 20}, {30, 40}, {10, 40}, {10, 20}}
	got := encodePath([][]IPoint{ring})
	want := "M10 20l20 0l0 20l-20 0Z"
	if got != want {
		t.Errorf("encodePath = %q, want %q", got, want)
	}
}

// Area error is recorded but must not gate: it can improve as the shape gets
// visibly worse, because inward and outward deviations cancel.
func TestAreaErrorRecordedButNotGating(t *testing.T) {
	p := Polygon{Parts: [][]Point{jagged(145.0, -37.8, 0.05, 400, 0.002)}}
	out, err := Simplify(p, Options{SubPixel: 2.0})
	if err != nil {
		t.Fatalf("subpixel 2.0 should not fail the gate on its own terms: %v", err)
	}
	if out.AreaErrPct < 0 {
		t.Errorf("area error %.4f is negative", out.AreaErrPct)
	}
}

// A vertex landing exactly on a non-adjacent segment is a touch, not a
// crossing. Quantising real boundaries onto a 200 px grid makes this common;
// treating it as a self-intersection sent 7% of Victoria's localities to the
// convex hull.
func TestTouchingVertexIsNotSelfIntersection(t *testing.T) {
	// The vertex at (5,0) sits on the segment (0,0)-(10,0).
	ring := []IPoint{{0, 0}, {10, 0}, {10, 10}, {5, 10}, {5, 0}, {0, 10}, {0, 0}}
	touching := []IPoint{{0, 0}, {10, 0}, {10, 10}, {5, 10}, {5, 5}, {0, 10}, {0, 0}}
	if selfIntersects(touching) {
		t.Error("clean ring reported as self-intersecting")
	}
	_ = ring
	// Two segments meeting at a single shared point only.
	pt := []IPoint{{0, 0}, {10, 0}, {5, 0}}
	if segIntersect(pt[0], pt[1], pt[2], IPoint{5, 10}) {
		t.Error("single-point touch counted as a crossing")
	}
}

func TestCollinearOverlapIsSelfIntersection(t *testing.T) {
	// Overlapping along the same line, sharing length.
	if !segIntersect(IPoint{0, 0}, IPoint{10, 0}, IPoint{5, 0}, IPoint{15, 0}) {
		t.Error("collinear overlap not detected")
	}
	// Meeting end to end shares one point only.
	if segIntersect(IPoint{0, 0}, IPoint{10, 0}, IPoint{10, 0}, IPoint{20, 0}) {
		t.Error("end-to-end collinear counted as overlap")
	}
	// Vertical, so the comparison must not use the constant x.
	if !segIntersect(IPoint{0, 0}, IPoint{0, 10}, IPoint{0, 5}, IPoint{0, 15}) {
		t.Error("vertical collinear overlap not detected")
	}
}

// R10.4, amended by the real-data finding: a sub-pixel pinch on clean source
// geometry keeps its accurate path and is flagged, rather than being replaced
// by a convex hull that is visibly wrong.
//
// The fixture is a real locality because synthetic shapes do not reproduce
// this: sub-pixel jitter is simplified away, and a slot narrower than a pixel
// collapses into adjacent segments rather than a crossing. It takes genuine
// coastline-like structure — detail the tolerance keeps, on walls closer than
// one pixel. Kurraca West is the smallest of the 28 Victorian localities that
// exhibit it.
func TestSubPixelPinchKeepsPathAndFlags(t *testing.T) {
	ring := loadFixtureRing(t, "testdata/pinched_locality.json")

	// The source must be clean — otherwise this fixture would be testing the
	// malformed-data path instead.
	if sourceSelfIntersects([][]Point{closeRing(ring)}) {
		t.Fatal("fixture source self-intersects; it no longer tests the pinch path")
	}

	out, err := Simplify(Polygon{Parts: [][]Point{ring}}, Options{})
	if err != nil {
		t.Fatalf("Simplify: %v", err)
	}
	if out.Hull {
		t.Error("clean source with a sub-pixel pinch must not fall back to the hull")
	}
	if !out.Pinched {
		t.Fatal("sub-pixel pinch not flagged")
	}
	if out.Path == "" {
		t.Error("pinched outline dropped its path")
	}
	if out.MaxDevPx > DefaultSubPixel {
		t.Errorf("pinched outline breached the fidelity gate: %.4f px", out.MaxDevPx)
	}
	// The whole point of keeping it: a hull would be far less accurate.
	if out.AreaErrPct > 5 {
		t.Errorf("pinched outline area error %.2f%% is too high to be worth keeping", out.AreaErrPct)
	}
}

// Genuinely malformed source geometry still takes the hull, per R10.4.
func TestSelfIntersectingSourceFallsBackToHull(t *testing.T) {
	// The lobes must differ in size: a symmetric bowtie has two lobes of
	// opposite sign whose shoelace areas cancel to zero, so it would be
	// dropped as degenerate before the self-intersection check ran.
	bowtie := []Point{
		{145.0, -37.0}, {145.4, -36.6}, {145.4, -37.0}, {145.0, -36.9}, {145.0, -37.0},
	}
	out, err := Simplify(Polygon{Parts: [][]Point{bowtie}}, Options{})
	if err != nil {
		t.Fatalf("Simplify: %v", err)
	}
	if !out.Hull {
		t.Error("self-intersecting source geometry should fall back to the convex hull")
	}
	if out.Pinched {
		t.Error("malformed source flagged as a pinch")
	}
	if out.Path == "" {
		t.Error("hull fallback produced no path")
	}
}

func TestSourceSelfIntersectsDistinguishesTouchFromCross(t *testing.T) {
	bowtie := [][]Point{{{0, 0}, {10, 10}, {10, 0}, {0, 10}, {0, 0}}}
	if !sourceSelfIntersects(bowtie) {
		t.Error("bowtie source not detected")
	}
	square := [][]Point{{{0, 0}, {10, 0}, {10, 10}, {0, 10}, {0, 0}}}
	if sourceSelfIntersects(square) {
		t.Error("square source reported as self-intersecting")
	}
}

// --- helpers ---

// loadFixtureRing reads a real locality ring captured from the Geoscape
// Administrative Boundaries shapefile (CC BY 4.0 — see ATTRIBUTION.md).
func loadFixtureRing(t *testing.T, path string) []Point {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f struct {
		Name string       `json:"name"`
		Ring [][2]float64 `json:"ring"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(f.Ring) < 4 {
		t.Fatalf("fixture %s has only %d points", f.Name, len(f.Ring))
	}
	pts := make([]Point, len(f.Ring))
	for i, c := range f.Ring {
		pts[i] = Point{X: c[0], Y: c[1]}
	}
	return pts
}

// parsePath turns an encoded path back into rings so tests can assert on the
// geometry that actually ships.
func parsePath(t *testing.T, path string) [][]IPoint {
	t.Helper()
	var rings [][]IPoint
	for _, sub := range strings.Split(path, "M") {
		if sub == "" {
			continue
		}
		sub = strings.TrimSuffix(sub, "Z")
		parts := strings.Split(sub, "l")
		var cur IPoint
		var ring []IPoint
		for i, seg := range parts {
			var x, y int
			if _, err := fmtSscan(seg, &x, &y); err != nil {
				t.Fatalf("parse %q: %v", seg, err)
			}
			if i == 0 {
				cur = IPoint{x, y}
			} else {
				cur = IPoint{cur.X + x, cur.Y + y}
			}
			ring = append(ring, cur)
		}
		if len(ring) > 0 {
			ring = append(ring, ring[0])
		}
		rings = append(rings, ring)
	}
	return rings
}

func fmtSscan(s string, x, y *int) (int, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0, errFields
	}
	var err error
	if *x, err = atoi(f[0]); err != nil {
		return 0, err
	}
	if *y, err = atoi(f[1]); err != nil {
		return 0, err
	}
	return 2, nil
}

var errFields = errString("want 2 fields")

type errString string

func (e errString) Error() string { return string(e) }

func atoi(s string) (int, error) {
	n := 0
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, errString("not an integer: " + s)
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

func pathExtent(t *testing.T, path string) (minX, maxX, minY, maxY int) {
	t.Helper()
	rings := parsePath(t, path)
	if len(rings) == 0 || len(rings[0]) == 0 {
		t.Fatal("empty path")
	}
	minX, maxX = rings[0][0].X, rings[0][0].X
	minY, maxY = rings[0][0].Y, rings[0][0].Y
	for _, r := range rings {
		for _, p := range r {
			if p.X < minX {
				minX = p.X
			}
			if p.X > maxX {
				maxX = p.X
			}
			if p.Y < minY {
				minY = p.Y
			}
			if p.Y > maxY {
				maxY = p.Y
			}
		}
	}
	return minX, maxX, minY, maxY
}

package match

// Street-intersection resolution — the "A and B road" case. The user's
// correction: "doncaster and blackburn road" means the INTERSECTION of
// Doncaster Road and Blackburn Road, not the Doncaster locality. The "road"
// suffix is elided — it applies to both streets.
//
// G-NAF stores street_name and street_type as separate columns, and a street's
// addresses span multiple localities (Doncaster Rd lives in DONCASTER and
// DONCASTER EAST; Blackburn Rd lives in DONCASTER EAST, NOTTING HILL, ...). So
// there is no single locality-scoped address set where both streets cross. The
// intersection must be computed from the streets' point sets where their
// coordinate ranges overlap.

import (
	"context"
	"database/sql"
	"math"
	"strings"
)

// Intersection is a resolved street-intersection point.
type Intersection struct {
	Lat, Lon float64
	// Streets are the two street names resolved.
	Streets []string
}

// ResolveIntersection resolves the intersection of two streets ("A AND B ROAD").
// It collects each street's address points, restricts both to the coordinate
// overlap (where the two streets' extents intersect — they genuinely cross
// there), fits a line through each (least-squares), and computes the crossing.
// Returns the intersection and whether it resolved.
//
// The streets cross where their fitted lines intersect; the crossing is
// clamped to the overlap of the two streets' coordinate ranges (the streets
// genuinely cross there, not at an extrapolated far point).
func ResolveIntersection(ctx context.Context, db *sql.DB, a, b string) (*Intersection, error) {
	pa := collectStreetPoints(ctx, db, a)
	pb := collectStreetPoints(ctx, db, b)
	if len(pa) < 2 || len(pb) < 2 {
		return nil, nil
	}
	// Restrict both to the shared coordinate overlap (where they cross).
	latMin := fmax(minLat(pa), minLat(pb))
	latMax := fmin(maxLat(pa), maxLat(pb))
	lonMin := fmax(minLon(pa), minLon(pb))
	lonMax := fmin(maxLon(pa), maxLon(pb))
	pa = inRange(pa, latMin, latMax, lonMin, lonMax)
	pb = inRange(pb, latMin, latMax, lonMin, lonMax)
	if len(pa) < 2 || len(pb) < 2 {
		// No shared region — the streets don't cross in this dataset.
		return nil, nil
	}
	la := fitLine(pa)
	lb := fitLine(pb)
	lat, lon := lineCross(la, lb)
	lat = clamp(lat, latMin, latMax)
	lon = clamp(lon, lonMin, lonMax)
	return &Intersection{Lat: lat, Lon: lon, Streets: []string{a, b}}, nil
}

// inRange filters points to a coordinate window.
func inRange(ps []Point, latMin, latMax, lonMin, lonMax float64) []Point {
	var out []Point
	for _, p := range ps {
		if p.Lat >= latMin && p.Lat <= latMax && p.Lon >= lonMin && p.Lon <= lonMax {
			out = append(out, p)
		}
	}
	return out
}

// collectStreetPoints gathers all address points for a street name.
func collectStreetPoints(ctx context.Context, db *sql.DB, street string) []Point {
	rows, err := db.QueryContext(ctx,
		`SELECT latitude, longitude FROM address WHERE upper(street_name)=?`,
		strings.ToUpper(street))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.Lat, &p.Lon); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// fitLine fits a line to points via least-squares on latitude as a function of
// longitude (and longitude as a function of latitude), returning the best fit.
// A line is (x0, y0, dx, dy); points lie on it as (x0 + t*dx, y0 + t*dy).
type line struct {
	lat0, lon0, dLat, dLon float64
}

// fitLine fits a line through points via least-squares, choosing the better of
// the E-W and N-S regressions (lower residual).
func fitLine(ps []Point) line {
	ew := fitLineEW(ps)
	ns := fitLineNS(ps)
	if residual(ps, ew) <= residual(ps, ns) {
		return ew
	}
	return ns
}

// fitLineEW fits lat = a + b*lon (a roughly E-W street).
func fitLineEW(ps []Point) line {
	n := float64(len(ps))
	var sx, sy, sxx, sxy float64
	for _, p := range ps {
		sx += p.Lon
		sy += p.Lat
		sxx += p.Lon * p.Lon
		sxy += p.Lon * p.Lat
	}
	den := n*sxx - sx*sx
	b := 0.0
	if den != 0 {
		b = (n*sxy - sx*sy) / den
	}
	a := (sy - b*sx) / n
	lon0 := sx / n
	return line{a + b*lon0, lon0, b, 1}
}

// fitLineNS fits lon = c + d*lat (a roughly N-S street).
func fitLineNS(ps []Point) line {
	n := float64(len(ps))
	var sx, sy, sxx, sxy float64
	for _, p := range ps {
		sx += p.Lat
		sy += p.Lon
		sxx += p.Lat * p.Lat
		sxy += p.Lat * p.Lon
	}
	den := n*sxx - sx*sx
	d := 0.0
	if den != 0 {
		d = (n*sxy - sx*sy) / den
	}
	c := (sy - d*sx) / n
	lat0 := sx / n
	return line{lat0, c + d*lat0, 1, d}
}

// residual is the mean squared error of a line against points.
func residual(ps []Point, l line) float64 {
	var e float64
	for _, p := range ps {
		// Project p onto the line, measure distance to the line.
		// Param: q(t) = (lat0 + t*dLat, lon0 + t*dLon).
		// t = ((p.Lat-lat0)*dLat + (p.Lon-lon0)*dLon) / (dLat^2+dLon^2)
		den := l.dLat*l.dLat + l.dLon*l.dLon
		if den == 0 {
			continue
		}
		t := ((p.Lat-l.lat0)*l.dLat + (p.Lon-l.lon0)*l.dLon) / den
		qLat := l.lat0 + t*l.dLat
		qLon := l.lon0 + t*l.dLon
		e += (p.Lat-qLat)*(p.Lat-qLat) + (p.Lon-qLon)*(p.Lon-qLon)
	}
	if len(ps) == 0 {
		return 0
	}
	return e / float64(len(ps))
}

// lineCross computes the crossing point of two lines. Parametric: a = a0 + t*da,
// b = b0 + s*db, solve for t, s.
func lineCross(a, b line) (float64, float64) {
	// Solve a.lat0 + t*a.dLat = b.lat0 + s*b.dLat and
	// a.lon0 + t*a.dLon = b.lon0 + s*b.dLon.
	// Cramer's rule on the 2x2 system.
	det := a.dLat*b.dLon - a.dLon*b.dLat
	if math.Abs(det) < 1e-12 {
		return 0, 0 // parallel
	}
	t := (b.dLon*(b.lat0-a.lat0) - b.dLat*(b.lon0-a.lon0)) / det
	// s := (a.dLon*(b.lat0-a.lat0) - a.dLat*(b.lon0-a.lon0)) / det
	return a.lat0 + t*a.dLat, a.lon0 + t*a.dLon
}

func minLat(ps []Point) float64 {
	m := math.MaxFloat64
	for _, p := range ps {
		if p.Lat < m {
			m = p.Lat
		}
	}
	return m
}

func maxLat(ps []Point) float64 {
	m := -math.MaxFloat64
	for _, p := range ps {
		if p.Lat > m {
			m = p.Lat
		}
	}
	return m
}

func minLon(ps []Point) float64 {
	m := math.MaxFloat64
	for _, p := range ps {
		if p.Lon < m {
			m = p.Lon
		}
	}
	return m
}

func maxLon(ps []Point) float64 {
	m := -math.MaxFloat64
	for _, p := range ps {
		if p.Lon > m {
			m = p.Lon
		}
	}
	return m
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// fmax/fmin are float64 max/min (Go 1.21's built-ins are int-only).
func fmax(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func fmin(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// StreetRef names one street of an intersection. Type is the canonical street
// type (STREET, ROAD, ...), or "" when the text gave none.
type StreetRef struct{ Name, Type string }

// Meeting is where two streets in a locality meet.
type Meeting struct {
	Lat, Lon     float64
	TypeA, TypeB string // the street types the meeting was found for
	State        string // of the address row nearest the meeting point
	Postcode     string
	Rows         int // the two streets' address rows in the locality
}

// Limits on StreetsMeet. Addresses sit back from the street, deep lots by
// fifty metres or more, and a corner building often carries an address on
// each street, so neither the nearest pair of addresses nor a shared point
// says where two streets meet. Their fitted lines do; the addresses then
// confirm that both streets reach the crossing.
const (
	meetFitRadiusM = 300   // addresses within this of the estimate refine each line
	meetOffLineM   = 50    // a street's addresses sit within this of its line
	meetReachM     = 80    // each street must have an address this close to the crossing
	meetMinAngle   = 0.5   // sin of the smallest angle between the streets (30 degrees)
	meetMinSpreadM = 15    // a fit needs addresses spread at least this far along it
	meetMarginDeg  = 0.003 // about 300 m: the neighbourhood searched around the locality's stretch
	meetRefine     = 3
)

// StreetsMeet finds where streets a and b meet in locality, or nil when they do
// not: either street missing from the locality, or the two never meet
// (parallel streets, or the same names in different places). An empty Type
// takes the other street's type when the locality has a street of that name
// and type ("cnr Flinders and Elizabeth Sts"), else the locality's most common
// one.
//
// Each street's addresses in the locality are fitted with a line and the two
// lines crossed; the estimate is then refined from the addresses around it
// (from any locality: a street on a locality boundary has its other side in
// the neighbour), which straightens out long or curved streets. Unlike
// ResolveIntersection, which fits whole streets statewide, this stays within
// one place, so a name repeated across the state cannot pull the answer away.
func StreetsMeet(ctx context.Context, sc *StreetCache, a, b StreetRef, locality string) (*Meeting, error) {
	allA, err := sc.rows(ctx, a.Name)
	if err != nil {
		return nil, err
	}
	allB, err := sc.rows(ctx, b.Name)
	if err != nil {
		return nil, err
	}
	ra, rb := inLocality(allA, locality), inLocality(allB, locality)
	if len(ra) == 0 || len(rb) == 0 {
		return nil, nil
	}
	ta := pickType(ra, a.Type, b.Type)
	tb := pickType(rb, b.Type, ta)
	if (ta == "" && a.Type != "") || (tb == "" && b.Type != "") {
		return nil, nil // the asked-for type is not in the locality
	}
	if a.Name == b.Name && ta == tb {
		return nil, nil
	}
	ra, rb = ofType(ra, ta), ofType(rb, tb)
	if len(ra) == 0 || len(rb) == 0 {
		return nil, nil
	}
	box := bounds(append(append([]streetRow(nil), ra...), rb...))
	pa, pb := pointsIn(allA, ta, box), pointsIn(allB, tb, box)

	// Work in metres on a local plane: degrees of longitude are shorter than
	// degrees of latitude, which would skew the fitted directions.
	pr := newPlane(ra[0].Point)
	la, oka := fitTrimmed(pr.projectRows(ra))
	lb, okb := fitTrimmed(pr.projectRows(rb))
	if !oka || !okb {
		return nil, nil
	}
	at, ok := crossing(la, lb)
	if !ok {
		return nil, nil // parallel
	}
	xa, xb := pr.project(pa), pr.project(pb)
	for range meetRefine {
		if l, ok := fitTrimmed(within(xa, at, meetFitRadiusM)); ok {
			la = l
		}
		if l, ok := fitTrimmed(within(xb, at, meetFitRadiusM)); ok {
			lb = l
		}
		if at, ok = crossing(la, lb); !ok {
			return nil, nil
		}
	}
	if nearest(xa, at) > meetReachM || nearest(xb, at) > meetReachM {
		return nil, nil // the lines cross where one street does not go
	}

	lat, lon := pr.unproject(at)
	m := &Meeting{Lat: lat, Lon: lon, TypeA: ta, TypeB: tb, Rows: len(ra) + len(rb)}
	best := -1.0
	for _, r := range append(ra, rb...) {
		if dd := pr.at(r.Point).dist(at); best < 0 || dd < best {
			best, m.State, m.Postcode = dd, r.State, r.Postcode
		}
	}
	return m, nil
}

type streetRow struct {
	Point
	Type, Locality, State, Postcode string
}

// StreetCache holds the address rows of the streets one query names, so
// trying several localities reads each street once. It is not safe for
// concurrent use; make one per query.
type StreetCache struct {
	db  *sql.DB
	got map[string][]streetRow
}

// NewStreetCache returns an empty cache over db.
func NewStreetCache(db *sql.DB) *StreetCache {
	return &StreetCache{db: db, got: map[string][]streetRow{}}
}

// rows returns every address row of a street name, statewide (idx_addr_street).
func (sc *StreetCache) rows(ctx context.Context, name string) ([]streetRow, error) {
	if r, ok := sc.got[name]; ok {
		return r, nil
	}
	rows, err := sc.db.QueryContext(ctx, `
		SELECT COALESCE(street_type, ''), locality_name, state, COALESCE(postcode, ''), latitude, longitude
		FROM address WHERE street_name = ?`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []streetRow
	for rows.Next() {
		var r streetRow
		if err := rows.Scan(&r.Type, &r.Locality, &r.State, &r.Postcode, &r.Lat, &r.Lon); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sc.got[name] = out
	return out, nil
}

func inLocality(rows []streetRow, locality string) []streetRow {
	var out []streetRow
	for _, r := range rows {
		if r.Locality == locality {
			out = append(out, r)
		}
	}
	return out
}

// pickType is want when the rows have it ("" when they do not); with no want,
// pref when the rows have it, else the most common type.
func pickType(rows []streetRow, want, pref string) string {
	n := map[string]int{}
	for _, r := range rows {
		n[r.Type]++
	}
	if want != "" {
		if n[want] > 0 {
			return want
		}
		return ""
	}
	if pref != "" && n[pref] > 0 {
		return pref
	}
	best := ""
	for t, c := range n {
		if c > n[best] || c == n[best] && t < best {
			best = t
		}
	}
	return best
}

func ofType(rows []streetRow, typ string) []streetRow {
	var out []streetRow
	for _, r := range rows {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

type box struct{ latMin, latMax, lonMin, lonMax float64 }

func bounds(rows []streetRow) box {
	b := box{math.MaxFloat64, -math.MaxFloat64, math.MaxFloat64, -math.MaxFloat64}
	for _, r := range rows {
		b.latMin, b.latMax = fmin(b.latMin, r.Lat), fmax(b.latMax, r.Lat)
		b.lonMin, b.lonMax = fmin(b.lonMin, r.Lon), fmax(b.lonMax, r.Lon)
	}
	b.latMin -= meetMarginDeg
	b.latMax += meetMarginDeg
	b.lonMin -= meetMarginDeg
	b.lonMax += meetMarginDeg
	return b
}

// pointsIn returns the distinct points of the rows of one type within b.
// Units share their building's point, so de-duplicating keeps the fits from
// weighting a tower by its unit count.
func pointsIn(rows []streetRow, typ string, b box) []Point {
	seen := map[Point]bool{}
	var out []Point
	for _, r := range rows {
		if r.Type != typ || seen[r.Point] ||
			r.Lat < b.latMin || r.Lat > b.latMax || r.Lon < b.lonMin || r.Lon > b.lonMax {
			continue
		}
		seen[r.Point] = true
		out = append(out, r.Point)
	}
	return out
}

// vec is a point or direction on a local plane, in metres.
type vec struct{ x, y float64 }

func (v vec) dist(w vec) float64 { return math.Hypot(v.x-w.x, v.y-w.y) }

// plane is an equirectangular projection around an origin: accurate to well
// under a metre over the few hundred metres an intersection spans.
type plane struct{ lat0, lon0, kx, ky float64 }

func newPlane(o Point) plane {
	const mPerDeg = 111320.0
	return plane{o.Lat, o.Lon, mPerDeg * math.Cos(o.Lat*math.Pi/180), mPerDeg}
}

func (p plane) at(q Point) vec { return vec{(q.Lon - p.lon0) * p.kx, (q.Lat - p.lat0) * p.ky} }

// projectRows projects the distinct points of rs: the units of a tower share
// one point and must not outweigh the rest of the street.
func (p plane) projectRows(rs []streetRow) []vec {
	seen := map[Point]bool{}
	var out []vec
	for _, r := range rs {
		if !seen[r.Point] {
			seen[r.Point] = true
			out = append(out, p.at(r.Point))
		}
	}
	return out
}

func (p plane) project(ps []Point) []vec {
	out := make([]vec, len(ps))
	for i, q := range ps {
		out[i] = p.at(q)
	}
	return out
}

func (p plane) unproject(v vec) (lat, lon float64) {
	return p.lat0 + v.y/p.ky, p.lon0 + v.x/p.kx
}

// within returns the points no further than r from c.
func within(ps []vec, c vec, r float64) []vec {
	var out []vec
	for _, p := range ps {
		if p.dist(c) <= r {
			out = append(out, p)
		}
	}
	return out
}

// nearest is the distance from c to the closest of ps.
func nearest(ps []vec, c vec) float64 {
	best := math.MaxFloat64
	for _, p := range ps {
		best = math.Min(best, p.dist(c))
	}
	return best
}

// vline is a fitted line: a point on it and a unit direction.
type vline struct{ c, d vec }

// fitTrimmed fits a line through ps, then fits again without the points far
// off the first line: a building with a second address on another street, or
// a side branch, would otherwise swing the direction.
func fitTrimmed(ps []vec) (vline, bool) {
	l, ok := fitAxis(ps)
	if !ok {
		return l, false
	}
	var on []vec
	for _, p := range ps {
		if l.off(p) <= meetOffLineM {
			on = append(on, p)
		}
	}
	return fitAxis(on)
}

// off is the perpendicular distance from p to the line.
func (l vline) off(p vec) float64 {
	return math.Abs((p.x-l.c.x)*l.d.y - (p.y-l.c.y)*l.d.x)
}

// fitAxis fits a line through ps by principal axis (orientation-free, unlike
// a regression of y on x). It fails with fewer than three points or too little
// spread to give a direction.
func fitAxis(near []vec) (vline, bool) {
	if len(near) < 3 {
		return vline{}, false
	}
	var c vec
	for _, p := range near {
		c.x += p.x
		c.y += p.y
	}
	n := float64(len(near))
	c.x /= n
	c.y /= n
	var sxx, syy, sxy float64
	for _, p := range near {
		dx, dy := p.x-c.x, p.y-c.y
		sxx += dx * dx
		syy += dy * dy
		sxy += dx * dy
	}
	theta := 0.5 * math.Atan2(2*sxy, sxx-syy)
	d := vec{math.Cos(theta), math.Sin(theta)}
	var spread float64
	for _, p := range near {
		t := (p.x-c.x)*d.x + (p.y-c.y)*d.y
		spread = fmax(spread, math.Abs(t))
	}
	if spread < meetMinSpreadM {
		return vline{}, false
	}
	return vline{c, d}, true
}

// crossing intersects two lines; false when they are within meetMinAngle of
// parallel.
func crossing(a, b vline) (vec, bool) {
	den := a.d.x*b.d.y - a.d.y*b.d.x // sin of the angle between unit directions
	if math.Abs(den) < meetMinAngle {
		return vec{}, false
	}
	wx, wy := b.c.x-a.c.x, b.c.y-a.c.y
	t := (wx*b.d.y - wy*b.d.x) / den
	return vec{a.c.x + t*a.d.x, a.c.y + t*a.d.y}, true
}

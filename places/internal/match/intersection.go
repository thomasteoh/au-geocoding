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

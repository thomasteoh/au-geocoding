package match

// Anchor resolution — resolves an anchor fragment (locality, or street+locality)
// to a point for "near <anchor>" distance ranking. The anchor is what the POI
// candidate is ranked against.
//
// For "woolworths near doncaster and blackburn road", the anchor fragment is
// "DONCASTER AND BLACKBURN ROAD" — a locality (doncaster) and a street
// (blackburn road). The anchor point is the street's midpoint in that locality
// (or the locality centroid when only the locality is named).

import (
	"context"
	"database/sql"
	"strings"

	"ausystem/shared/streettype"
)

// Anchor is a resolved anchor point.
type Anchor struct {
	Lat, Lon float64
	Kind     string // "locality" | "street" | "address"
}

// ResolveAnchor resolves an anchor fragment to a point. tokens is the
// normalised token set; locality is the locality name (for street resolution).
// Returns the anchor and whether it resolved. When only a locality is named,
// the locality centroid is the anchor.
//
// The fragment may be a locality + street ("DONCASTER AND BLACKBURN ROAD" =
// DONCASTER locality, BLACKBURN ROAD street). Prefer the locality centroid when
// the locality resolves and the street doesn't (the street may be a partial or
// cross-locality reference). Street resolution wins only when the street
// actually resolves in the locality.
//
// The fragment may also be TWO STREETS with an elided type suffix ("A AND B
// ROAD" = the intersection of A Road and B Road). This is the user's corrected
// reading: "doncaster and blackburn road" = Doncaster Rd × Blackburn Rd
// intersection. Detect the two-street pattern first.
// Resolution order (presentation-agnostic):
//   1. Whole fragment IS a locality ("DONCASTER EAST", "BOX HILL") → locality.
//   2. Two streets cross ("DONCASTER AND BLACKBURN ROAD", "CORNER OF X AND Y",
//      "X ROAD Y ROAD", "X AND Y") → intersection.
//   3. Street-in-locality ("BLACKBURN ROAD IN DONCASTER EAST") → street anchor.
//   4. Locality centroid (fallback).
func ResolveAnchor(ctx context.Context, db *sql.DB, fragment string, locality string) (*Anchor, error) {
	frag := strings.ToUpper(strings.TrimSpace(fragment))

	// 1. Whole fragment is a locality (multi-word localities like "DONCASTER
	// EAST" must not be mis-split into an intersection of DONCASTER × EAST).
	if whole, ok := wholeLocality(ctx, db, frag); ok {
		return resolveLocalityCentroid(ctx, db, whole)
	}

	// 2. Two-street intersection pattern ("A AND B ROAD" — the type suffix
	// applies to both; AND optional; suffix optional; corner-of/CNR stripped).
	if streets, ok := parseTwoStreet(ctx, db, frag); ok {
		if x, err := ResolveIntersection(ctx, db, streets[0], streets[1]); err == nil && x != nil {
			return &Anchor{Lat: x.Lat, Lon: x.Lon, Kind: "intersection"}, nil
		}
		// Fall through to locality/street resolution if the crossing doesn't
		// resolve (the streets may not cross in this dataset).
	}

	// 3. Street-in-locality: resolve the street's points in the locality.
	if locality != "" {
		if looksStreet(frag) {
			if a, err := resolveStreetAnchor(ctx, db, frag, locality); err == nil && a != nil {
				return a, nil
			}
		}
	}

	// 4. Fall back to the locality centroid.
	return resolveLocalityCentroid(ctx, db, locality)
}

// wholeLocality reports whether the entire fragment is a known locality
// (handles multi-word localities: "DONCASTER EAST", "BOX HILL", "MOUNT
// WAVERLEY"). A connector prefix ("CORNER OF", "CNR") is stripped first.
// The WHOLE fragment must match — a leading-prefix match ("DONCASTER" inside
// "DONCASTER AND BLACKBURN ROAD") must NOT qualify, or it short-circuits the
// intersection path.
//
// A fragment that ALSO names a second street ("DONCASTER EAST AND BLACKBURN
// ROAD" — DONCASTER EAST is both a locality AND a street) is NOT a pure
// locality: "AND ..." signals an intersection. Reject when "AND" or a second
// street suffix appears beyond the locality name.
func wholeLocality(ctx context.Context, db *sql.DB, frag string) (string, bool) {
	clean := frag
	for _, pre := range []string{"CORNER OF ", "CNR ", "THE CORNER OF ", "CORNER "} {
		if strings.HasPrefix(clean, pre) {
			clean = strings.TrimSpace(strings.TrimPrefix(clean, pre))
		}
	}
	clean = strings.TrimSpace(clean)
	// Reject when the fragment is clearly a two-street intersection: contains
	// " AND " (a second street) or has a street suffix ("ROAD") that isn't the
	// locality's own trailing word.
	if strings.Contains(clean, " AND ") {
		return "", false
	}
	// A trailing street suffix ("BLACKBURN ROAD") means a street, not a locality
	// — but "DONCASTER EAST" (no suffix) is a locality.
	if stripped := stripStreetType(clean); stripped != clean {
		return "", false
	}
	// The whole cleaned fragment must BE a locality name (exact match, all
	// tokens). "DONCASTER AND BLACKBURN ROAD" has extra tokens → not a locality.
	var loc string
	err := db.QueryRowContext(ctx,
		`SELECT DISTINCT locality_name FROM address WHERE locality_name = ? LIMIT 1`,
		clean).Scan(&loc)
	if err != nil {
		return "", false
	}
	return loc, true
}

// parseTwoStreet detects the intersection pattern between two street names.
// It is presentation-agnostic — the two streets may be joined by "AND" or
// simply adjacent ("X ROAD Y ROAD", "X Y ROAD"), with or without type suffixes,
// and either may carry the shared suffix ("X AND Y ROAD" — the suffix applies
// to both). We extract candidate street names and return those that resolve as
// streets in the DB (via a street-existence probe).
//
// The connector "CORNER OF"/"CNR" is stripped first — the caller passes the
// fragment AFTER the connector split, so "corner of X and Y" arrives as
// "CORNER OF X AND Y ROAD"; we strip that prefix here.
func parseTwoStreet(ctx context.Context, db *sql.DB, frag string) ([]string, bool) {
	up := frag
	// Strip a leading intersection connector ("CORNER OF", "CNR", "THE CORNER OF").
	for _, pre := range []string{"CORNER OF ", "CNR ", "THE CORNER OF ", "CORNER "} {
		if strings.HasPrefix(up, pre) {
			up = strings.TrimSpace(strings.TrimPrefix(up, pre))
		}
	}
	// Split candidate street names. Join on " AND " if present; otherwise split
	// on the boundary between two street-like tokens.
	var cands []string
	if strings.Contains(up, " AND ") {
		parts := strings.SplitN(up, " AND ", 2)
		cands = []string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])}
	} else {
		// No AND: find two adjacent street tokens. Try each space boundary —
		// the first token is street A, the rest is street B.
		fields := strings.Fields(up)
		for i := 1; i < len(fields); i++ {
			a := strings.TrimSpace(strings.Join(fields[:i], " "))
			b := strings.TrimSpace(strings.Join(fields[i:], " "))
			// Strip type suffixes (the shared suffix applies to both).
			a = stripStreetType(a)
			b = stripStreetType(b)
			if isStreet(ctx, db, a) && isStreet(ctx, db, b) {
				return []string{a, b}, true
			}
		}
		return nil, false
	}
	// AND form: strip suffixes (shared or per-side) and require both resolve.
	a := stripStreetType(cands[0])
	b := stripStreetType(cands[1])
	if isStreet(ctx, db, a) && isStreet(ctx, db, b) {
		return []string{a, b}, true
	}
	return nil, false
}

// isStreet reports whether a name resolves as a street_name in the DB.
func isStreet(ctx context.Context, db *sql.DB, name string) bool {
	if name == "" {
		return false
	}
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM address WHERE street_name = ?`,
		name).Scan(&n)
	return err == nil && n > 0
}

// stripStreetType removes a trailing street-type suffix (" ROAD", " RD", ...).
func stripStreetType(s string) string {
	return streettype.StripSuffix(s)
}

// looksStreet reports whether a fragment contains a street (a word + road/st/
// street/ave/... suffix, or a name that's a known street).
func looksStreet(frag string) bool {
	return streettype.HasSuffix(frag)
}

// resolveStreetAnchor finds the address points for a street in a locality and
// returns their centroid (the anchor point). locality narrows the street.
func resolveStreetAnchor(ctx context.Context, db *sql.DB, street string, locality string) (*Anchor, error) {
	// Extract the street name from the fragment (strip the type suffix) via the
	// shared streettype vocabulary.
	streetName := streettype.StripSuffix(street)
	q := `SELECT latitude, longitude FROM address
	      WHERE street_name = ? AND locality_name = ?`
	rows, err := db.QueryContext(ctx, q, streetName, locality)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lat, lon, n float64
	for rows.Next() {
		var la, lo float64
		if err := rows.Scan(&la, &lo); err != nil {
			return nil, err
		}
		lat += la
		lon += lo
		n++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return &Anchor{Lat: lat / n, Lon: lon / n, Kind: "street"}, nil
}

// resolveLocalityCentroid returns the centroid of a locality's address points.
func resolveLocalityCentroid(ctx context.Context, db *sql.DB, locality string) (*Anchor, error) {
	if locality == "" {
		return nil, nil
	}
	q := `SELECT latitude, longitude FROM address WHERE locality_name = ?`
	rows, err := db.QueryContext(ctx, q, locality)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lat, lon, n float64
	for rows.Next() {
		var la, lo float64
		if err := rows.Scan(&la, &lo); err != nil {
			return nil, err
		}
		lat += la
		lon += lo
		n++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return &Anchor{Lat: lat / n, Lon: lon / n, Kind: "locality"}, nil
}

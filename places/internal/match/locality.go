package match

// Locality resolution — the anchor layer for "in <suburb>" and "near <anchor>".
// A locality name resolves to candidates, with ambiguity SURFACED (the design:
// ambiguity is a first-class result, not an error — 332 locality names repeat
// within a single state, so returning multiple candidates is the normal case).

import (
	"context"
	"database/sql"
)

// Locality is a resolved locality candidate.
type Locality struct {
	Name     string
	State    string
	Postcode string
	Lat, Lon float64
}

// ResolveLocality resolves a locality name to candidates. state, when non-empty,
// narrows the resolution. Multiple candidates = ambiguity (surface it, don't
// pick row one). Returns nil when nothing matches.
func ResolveLocality(ctx context.Context, db *sql.DB, name string, state string) ([]Locality, error) {
	if name == "" {
		return nil, nil
	}
	// The locality table's coordinates are the locality centroid. We join the
	// locality name to its centroid point. State narrows when provided.
	q := `SELECT DISTINCT l.locality_name, l.state, l.postcode, l.latitude, l.longitude
	      FROM address l WHERE l.locality_name = ?`
	args := []any{name}
	if state != "" {
		q += ` AND l.state = ?`
		args = append(args, state)
	}
	q += ` LIMIT 50`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Locality
	for rows.Next() {
		var l Locality
		if err := rows.Scan(&l.Name, &l.State, &l.Postcode, &l.Lat, &l.Lon); err != nil {
			return nil, err
		}
		// Dedup by (name, state, postcode).
		if !containsLocality(out, l) {
			out = append(out, l)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func containsLocality(cs []Locality, l Locality) bool {
	for _, c := range cs {
		if c.Name == l.Name && c.State == l.State && c.Postcode == l.Postcode {
			return true
		}
	}
	return false
}

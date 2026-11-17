package match

// Aliases: G-NAF's other names for localities and streets (JOLIMONT is part
// of EAST MELBOURNE; LITTLE LATROBE STREET is LITTLE LA TROBE STREET). The
// address table carries only official names, so an alias is recognised by the
// parser like any locality, then CanonicalTokens swaps it for the official
// name before generation. cmd/buildaddr builds the tables, keeping only
// aliases that are not official names themselves and name one place.

import (
	"context"
	"database/sql"
	"sort"
)

// StreetAlias is one alias of a street in a locality.
type StreetAlias struct {
	AliasType  string // the alias's street type, "" when it has none
	StreetName string // the official name
	StreetType string
}

type aliases struct {
	aliasLoc    map[string]string        // alias -> official locality
	streetAlias map[string][]StreetAlias // alias name + "|" + locality -> official streets
	knownLocs   map[string]bool          // official localities and aliases
}

// loadAliases reads alias_locality and alias_street. A dataset built before
// they existed has no aliases.
func (fs *FuzzySet) loadAliases(ctx context.Context, db *sql.DB) error {
	fs.aliasLoc = map[string]string{}
	fs.streetAlias = map[string][]StreetAlias{}
	fs.knownLocs = nil
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master
		WHERE type = 'table' AND name IN ('alias_locality', 'alias_street')`).Scan(&n); err != nil {
		return err
	}
	if n < 2 {
		return nil
	}
	rows, err := db.QueryContext(ctx, `SELECT alias, locality_name FROM alias_locality`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var alias, loc string
		if err := rows.Scan(&alias, &loc); err != nil {
			rows.Close()
			return err
		}
		if !fs.localities[alias] && fs.localities[loc] {
			fs.aliasLoc[alias] = loc
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = db.QueryContext(ctx, `SELECT alias_name, alias_type, locality_name, street_name, street_type
		FROM alias_street ORDER BY alias_name, locality_name, alias_type`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, loc string
		var a StreetAlias
		if err := rows.Scan(&name, &a.AliasType, &loc, &a.StreetName, &a.StreetType); err != nil {
			return err
		}
		k := name + "|" + loc
		fs.streetAlias[k] = append(fs.streetAlias[k], a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(fs.aliasLoc) > 0 {
		fs.knownLocs = make(map[string]bool, len(fs.localities)+len(fs.aliasLoc))
		for l := range fs.localities {
			fs.knownLocs[l] = true
		}
		for a := range fs.aliasLoc {
			fs.knownLocs[a] = true
		}
	}
	return nil
}

// known is the locality names the parser recognises: official names and
// aliases.
func (fs *FuzzySet) known() map[string]bool {
	if fs.knownLocs != nil {
		return fs.knownLocs
	}
	return fs.localities
}

// CanonicalLocality returns the official locality an alias stands for, or
// name unchanged when it is official or unknown.
func (fs *FuzzySet) CanonicalLocality(name string) string {
	if fs.localities[name] {
		return name
	}
	if loc, ok := fs.aliasLoc[name]; ok {
		return loc
	}
	return name
}

// CanonicalStreet returns the official street that an alias names in
// locality, preferring an alias of the asked-for type. ok is false when name
// is a real street there, or no alias of it is known.
func (fs *FuzzySet) CanonicalStreet(name, streetType, locality string) (StreetAlias, bool) {
	if fs.streetLocs[name][locality] {
		return StreetAlias{}, false
	}
	cands := fs.streetAlias[name+"|"+locality]
	if len(cands) == 0 {
		return StreetAlias{}, false
	}
	for _, a := range cands {
		if streetType != "" && a.AliasType == streetType {
			return a, true
		}
	}
	// No alias of that type: only answer when every alias names one street.
	first := cands[0]
	for _, a := range cands[1:] {
		if a.StreetName != first.StreetName || a.StreetType != first.StreetType {
			return StreetAlias{}, false
		}
	}
	return first, true
}

// CanonicalTokens rewrites a tokenised query's locality and street aliases to
// the official names, in the score tokens and the anchors alike. The slices
// are copied, not modified. A query whose street is split across several
// tokens (no street type or locality to place it) is left alone.
func (fs *FuzzySet) CanonicalTokens(reliable, score, fields []string) ([]string, []string, []string) {
	if fs == nil || (len(fs.aliasLoc) == 0 && len(fs.streetAlias) == 0) {
		return reliable, score, fields
	}
	rel := append([]string(nil), reliable...)
	sc := append([]string(nil), score...)
	swap := func(i int, to string) {
		from := sc[i]
		sc[i] = to
		for j, r := range rel {
			if r == from {
				rel[j] = to
			}
		}
	}
	locality, streetAt, typeAt, streets := "", -1, -1, 0
	for i, f := range fields {
		if i >= len(sc) {
			break
		}
		switch f {
		case "locality_name":
			if locality == "" {
				if c := fs.CanonicalLocality(sc[i]); c != sc[i] {
					swap(i, c)
				}
				locality = sc[i]
			}
		case "street_name":
			streets++
			if streetAt < 0 {
				streetAt = i
			}
		case "street_type":
			if typeAt < 0 {
				typeAt = i
			}
		}
	}
	if streets == 1 && locality != "" {
		typ := ""
		if typeAt >= 0 {
			typ = sc[typeAt]
		}
		if a, ok := fs.CanonicalStreet(sc[streetAt], typ, locality); ok {
			swap(streetAt, a.StreetName)
			if typeAt >= 0 && (a.AliasType == typ || a.AliasType == "") && a.StreetType != "" {
				sc[typeAt] = a.StreetType
			}
		}
	}
	return rel, sc, fields
}

// LocalityAliases returns the locality aliases, sorted (for tests and tools).
func (fs *FuzzySet) LocalityAliases() []string {
	out := make([]string, 0, len(fs.aliasLoc))
	for a := range fs.aliasLoc {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

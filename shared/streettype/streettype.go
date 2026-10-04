// Package streettype is the single canonical Australian street-type vocabulary.
// It is shared by places (matching/stripping) and geocoding (normalisation),
// so a new street type is added once, not in five places.
package streettype

import "strings"

// Full names (canonical) and their common abbreviations. The canonical form is
// what the dataset uses (STREET, ROAD, AVENUE, ...); abbreviations are the
// short forms a user might type or that appear in raw G-NAF data.
var fullNames = map[string]string{
	"street":    "STREET",
	"st":        "STREET",
	"str":       "STREET",
	"road":      "ROAD",
	"rd":        "ROAD",
	"avenue":    "AVENUE",
	"ave":       "AVENUE",
	"av":        "AVENUE",
	"drive":     "DRIVE",
	"dr":        "DRIVE",
	"drv":       "DRIVE",
	"court":     "COURT",
	"ct":        "COURT",
	"place":     "PLACE",
	"pl":        "PLACE",
	"crescent":  "CRESCENT",
	"cres":      "CRESCENT",
	"cr":        "CRESCENT",
	"terrace":   "TERRACE",
	"tce":       "TERRACE",
	"lane":      "LANE",
	"ln":        "LANE",
	"highway":   "HIGHWAY",
	"hwy":       "HIGHWAY",
	"boulevard": "BOULEVARD",
	"blvd":      "BOULEVARD",
	"bvd":       "BOULEVARD",
	"close":     "CLOSE",
	"cl":        "CLOSE",
	"parade":    "PARADE",
	"pde":       "PARADE",
	"walk":      "WALK",
	"parkway":   "PARKWAY",
	"bypass":    "BYPASS",
	"esplanade": "ESPLANADE",
}

// Suffixes in canonical display form (with a leading space) for stripping.
var canonicalSuffixes = []string{
	" ROAD", " RD", " STREET", " ST", " AVENUE", " AVE",
	" DRIVE", " DR", " COURT", " CT", " CRESCENT", " CRES",
	" TERRACE", " TCE", " LANE", " LN", " HIGHWAY", " HWY",
	" BOULEVARD", " BLVD", " CLOSE", " CL", " PARADE", " PDE",
	" WALK", " PARKWAY", " BYPASS", " ESPLANADE", " PLACE", " PL",
}

// IsStreetType reports whether the (upper-case) word is a known street type.
func IsStreetType(word string) bool {
	_, ok := fullNames[strings.ToLower(word)]
	return ok
}

// Expand returns the canonical full form for an abbreviation or full name.
// Unknown values are returned unchanged (upper-cased) so an unusual real type
// is preserved rather than discarded.
func Expand(word string) string {
	if full, ok := fullNames[strings.ToLower(word)]; ok {
		return full
	}
	return strings.ToUpper(word)
}

// ExpandLower returns the canonical full form in lowercase. The normaliser
// (ausystem/shared/normalise) matches in lowercase, so it needs the lower form.
func ExpandLower(word string) string {
	if full, ok := fullNames[strings.ToLower(word)]; ok {
		return strings.ToLower(full)
	}
	return strings.ToLower(word)
}

// StripSuffix removes a trailing street-type suffix from a name ("ROAD", " RD",
// "STREET", ...). It is presentation-agnostic: it strips whatever suffix is
// present, leaving the bare street name. A name with no suffix is unchanged.
func StripSuffix(s string) string {
	up := strings.ToUpper(strings.TrimSpace(s))
	for _, suf := range canonicalSuffixes {
		if strings.HasSuffix(up, suf) {
			return strings.TrimSpace(strings.TrimSuffix(up, suf))
		}
	}
	return up
}

// HasSuffix reports whether a name carries a trailing street-type suffix.
func HasSuffix(s string) bool {
	up := strings.ToUpper(strings.TrimSpace(s))
	for _, suf := range canonicalSuffixes {
		if strings.HasSuffix(up, suf) {
			return true
		}
	}
	return false
}

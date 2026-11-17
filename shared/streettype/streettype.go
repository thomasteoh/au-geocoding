// Package streettype is the single canonical Australian street-type vocabulary.
// It is shared by places (matching/stripping) and geocoding (normalisation),
// so a new street type is added once, not in five places.
package streettype

import "strings"

// Full names (canonical) and their common abbreviations. The canonical form is
// what the dataset uses (STREET, ROAD, AVENUE, ...); abbreviations are the
// short forms a user might type or that appear in raw G-NAF data.
var fullNames = map[string]string{
	"street":     "STREET",
	"st":         "STREET",
	"str":        "STREET",
	"road":       "ROAD",
	"rd":         "ROAD",
	"avenue":     "AVENUE",
	"ave":        "AVENUE",
	"av":         "AVENUE",
	"drive":      "DRIVE",
	"dr":         "DRIVE",
	"drv":        "DRIVE",
	"court":      "COURT",
	"ct":         "COURT",
	"place":      "PLACE",
	"pl":         "PLACE",
	"crescent":   "CRESCENT",
	"cres":       "CRESCENT",
	"cr":         "CRESCENT",
	"terrace":    "TERRACE",
	"tce":        "TERRACE",
	"lane":       "LANE",
	"ln":         "LANE",
	"highway":    "HIGHWAY",
	"hwy":        "HIGHWAY",
	"boulevard":  "BOULEVARD",
	"blvd":       "BOULEVARD",
	"bvd":        "BOULEVARD",
	"close":      "CLOSE",
	"cl":         "CLOSE",
	"parade":     "PARADE",
	"pde":        "PARADE",
	"walk":       "WALK",
	"parkway":    "PARKWAY",
	"bypass":     "BYPASS",
	"esplanade":  "ESPLANADE",
	"way":        "WAY",
	"mews":       "MEWS",
	"freeway":    "FREEWAY",
	"fwy":        "FREEWAY",
	"grove":      "GROVE",
	"gr":         "GROVE",
	"gve":        "GROVE",
	"circuit":    "CIRCUIT",
	"cct":        "CIRCUIT",
	"square":     "SQUARE",
	"sq":         "SQUARE",
	"rise":       "RISE",
	"gardens":    "GARDENS",
	"gdns":       "GARDENS",
	"track":      "TRACK",
	"trk":        "TRACK",
	"loop":       "LOOP",
	"link":       "LINK",
	"retreat":    "RETREAT",
	"rtt":        "RETREAT",
	"circle":     "CIRCLE",
	"cir":        "CIRCLE",
	"boulevarde": "BOULEVARD",
	"crt":        "COURT",
	"hway":       "HIGHWAY",
	"pkwy":       "PARKWAY",
	"esp":        "ESPLANADE",
	"wk":         "WALK",
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

// StripSuffix removes a trailing street-type word, full or abbreviated, from a
// name ("SYDNEY ROAD" and "SYDNEY RD" both give "SYDNEY"). The name must keep
// at least one word other than THE: "THE ESPLANADE" and a bare "PARADE" are
// names, not types, and are returned unchanged.
func StripSuffix(s string) string {
	up := strings.Join(strings.Fields(strings.ToUpper(s)), " ")
	if !HasSuffix(up) {
		return up
	}
	return up[:strings.LastIndexByte(up, ' ')]
}

// HasSuffix reports whether a name ends in a street-type word that StripSuffix
// would remove.
func HasSuffix(s string) bool {
	words := strings.Fields(strings.ToUpper(s))
	if len(words) < 2 || !IsStreetType(words[len(words)-1]) {
		return false
	}
	return len(words) > 2 || words[0] != "THE"
}

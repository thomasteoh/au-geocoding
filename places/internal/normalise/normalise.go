package normalise

// normalise converts free text into the Query the matcher consumes.
// Per INV-7: untrusted text never influences query structure; operator chars
// are discarded, whitelisted tokens only, token count capped.
//
// Street-type expansion is shared with the geocoder (ausystem/shared/streettype)
// so a new street type is added once. The locality typo aliases below are
// places-specific and stay here.

import (
	"regexp"
	"strings"

	"ausystem/shared/streettype"
)

// Alias map: common Australian locality/street abbreviations.
// The design resolves LOCALITY_ALIAS at interpretation; the spike's normaliser
// carries the same idea for the common cases the corpus uses.
// Street-type abbreviations (st/rd/ave/...) expand via streettype.Expand;
// locality typos (melb, collns, steet, melborne) are handled here.
var Alias = map[string]string{
	"melb":     "MELBOURNE",
	"collins":  "COLLINS", // exact match already
	"collns":   "COLLINS", // typo alias — the T4 case
	"steet":    "STREET",  // typo alias — T4
	"melborne": "MELBOURNE",
}

// Reliable tokens are locality/state/postcode/street-number — the anchors.
// The contract: Generate = reliable, Score = everything.
// REAL-DATA FINDING (2026-09-14): street_name must ALSO be a generation
// anchor. With only locality+state+number as anchors, generation is too broad
// at real scale (10K+ candidates for locality+state alone), and the cap
// truncates the true match. Street name is the strongest discriminator —
// generation narrows by street+locality, then scoring picks the number.
var reliableSet = map[string]bool{
	"locality_name": true,
	"state":         true,
	"postcode":      true,
	"street_number": true,
	"street_name":   true,
}

// Tokenise splits text into normalised tokens. Discards operator chars,
// uppercases, collapses whitespace, resolves aliases.
// localitySet is the known locality names from the DB (the caller supplies it);
// when a token matches, it becomes a reliable anchor.
// Returns reliable tokens, score tokens, and a per-token field tag so the
// scorer can match street-to-street, locality-to-locality (the fix the spike
// found: without field tags, scoring conflates fields and match rate drops).
func Tokenise(input string, maxTokens int, localitySet map[string]bool) (reliable []string, score []string, fields []string) {
	// Strip anything that isn't a letter, digit, or apostrophe — INV-7.
	// Operator characters (AND, OR, *, quotes) never survive.
	clean := regexp.MustCompile(`[^A-Za-z0-9'\s]`).ReplaceAllString(input, " ")
	raw := strings.Fields(strings.ToUpper(clean))

	// Cap token count.
	if maxTokens > 0 && len(raw) > maxTokens {
		raw = raw[:maxTokens]
	}

	// Classify each token to a field, resolve aliases, split reliable/score.
	var rel, sc, fl []string
	for _, f := range raw {
		// Alias resolution (typo/abbrev → canonical). Locality typos come from
		// the local Alias map; street-type abbreviations expand via the shared
		// streettype vocabulary (st → STREET, rd → ROAD, ave → AVENUE, ...).
		if canon, ok := Alias[f]; ok {
			f = canon
		} else if streettype.IsStreetType(f) {
			f = streettype.Expand(f)
		}
		field := fieldOf(f, localitySet)
		// Reliable if it's an anchor kind (state, postcode, locality, number)
		// OR a street name — street_name is a generation anchor (real-data
		// finding: locality+state alone is too broad at 15.9M scale).
		if isState(f) || isPostcode(f) || localitySet[f] || isNumber(f) || field == "street_name" {
			rel = append(rel, f)
		}
		sc = append(sc, f)
		fl = append(fl, field)
	}
	// Dedupe reliable.
	seen := map[string]bool{}
	var relOut []string
	for _, t := range rel {
		if !seen[t] {
			seen[t] = true
			relOut = append(relOut, t)
		}
	}
	return relOut, sc, fl
}

// fieldOf classifies a token to a field: locality, state, postcode,
// street_number, or street_name. The normaliser needs the locality set.
func fieldOf(f string, localitySet map[string]bool) string {
	switch {
	case isState(f):
		return "state"
	case isPostcode(f):
		return "postcode"
	case localitySet[f]:
		return "locality"
	case isNumber(f):
		return "street_number"
	default:
		return "street_name"
	}
}

func isState(f string) bool {
	switch f {
	case "VIC", "NSW", "QLD", "SA", "WA", "TAS", "NT", "ACT":
		return true
	}
	return false
}

func isPostcode(f string) bool {
	if len(f) != 4 {
		return false
	}
	for _, c := range f {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isNumber(f string) bool {
	if f == "" {
		return false
	}
	for _, c := range f {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

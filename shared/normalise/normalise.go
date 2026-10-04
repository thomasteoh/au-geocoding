// Package normalise turns free text into tokens for generation and scoring.
// It is the only place user text becomes structure, so it owns the FTS5-injection
// guard (T3): every operator character is discarded here and the parse ladder
// rebuilds MATCH queries from the alphanumeric whitelist only.
package normalise

import (
	"strings"
	"unicode"

	"ausystem/shared/streettype"
)

// streetTypes maps common Australian street-type abbreviations to the full form
// used for matching. The reverse (full→abbrev) is unnecessary: generation and
// scoring both work from the expanded form.

// unitPrefixes maps unit/level prefixes to the canonical token used for
// matching. "Unit 3" and "3/12" both become a single `unit` token.
var unitPrefixes = map[string]string{
	"unit": "unit", "u": "unit",
	"flat": "flat", "f": "flat",
	"apartment": "apartment", "apt": "apartment",
	"suite": "suite", "su": "suite",
	"level": "level", "l": "level", "lvl": "level",
}

// stateCodes maps state abbreviations to the full name.
var stateCodes = map[string]string{
	"nsw": "new south wales", "vic": "victoria", "qld": "queensland",
	"sa": "south australia", "wa": "western australia", "tas": "tasmania",
	"nt": "northern territory", "act": "australian capital territory",
}

// Result is the normalised form of one query.
type Result struct {
	Tokens     []string // full normalised token set — scoring
	Generate   []string // reliable tokens — candidate generation
	State      string   // hint, "" if absent
	Postcode   string   // hint, "" if absent
	IsPOI      bool     // no numeric street number → likely a named place
	HadNumbers bool
	HadStreet  bool
}

// Normalise folds case, strips punctuation, expands abbreviations, and pulls
// state/postcode hints out of the token stream.
func Normalise(raw string) Result {
	s := strings.ToLower(raw)
	// Strip punctuation, keep alphanumerics and spaces (T3: no operator chars
	// ever reach a MATCH query).
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(r)
		case unicode.IsSpace(r), r == '/', r == '-':
			b.WriteByte(' ')
		default:
			b.WriteByte(' ')
		}
	}
	toks := strings.Fields(b.String())

	var out Result
	var state, postcode string
	var hasStreet, hasNumber bool
	var keep []string

	for i, t := range toks {
		if st := streettype.ExpandLower(t); st != "" && streettype.IsStreetType(t) {
			keep = append(keep, st)
			hasStreet = true
			continue
		}
		if up, ok := unitPrefixes[t]; ok {
			keep = append(keep, up)
			continue
		}
		if st, ok := stateCodes[t]; ok && state == "" {
			state = st
			keep = append(keep, t) // keep the abbrev as a match token
			continue
		}
		// A 4-digit token is a postcode hint.
		if isPostcode(t) && postcode == "" {
			postcode = t
			keep = append(keep, t)
			continue
		}
		// A pure-numeric token is a street number hint.
		if isNumber(t) && !hasNumber {
			hasNumber = true
			keep = append(keep, t)
			continue
		}
		// Skip the ordinal after a number ("12 main road" → "12", "main", "road").
		keep = append(keep, t)
		_ = i
	}

	out.Tokens = keep
	// Generate = reliable tokens only: street names, street type, postcode,
	// state. Numbers are weak alone; unit/level are weak alone.
	for _, t := range keep {
		if t == state || t == postcode {
			out.Generate = append(out.Generate, t)
		} else if streettype.IsStreetType(t) || !isNumber(t) {
			out.Generate = append(out.Generate, t)
		}
	}
	out.State = state
	out.Postcode = postcode
	out.IsPOI = !hasNumber
	out.HadNumbers = hasNumber
	out.HadStreet = hasStreet
	return out
}

// Tokenise is the FTS5-safe tokenisation used by the parse ladder (T3). It
// returns only alphanumeric tokens, joined by the caller with explicit AND.
// Never returns an operator character.
func Tokenise(raw string) []string {
	n := Normalise(raw)
	var out []string
	for _, t := range n.Tokens {
		if isAlnum(t) {
			out = append(out, t)
		}
	}
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func isPostcode(t string) bool {
	if len(t) != 4 {
		return false
	}
	for _, r := range t {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isNumber(t string) bool {
	if t == "" {
		return false
	}
	for _, r := range t {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isAlnum(t string) bool {
	if t == "" {
		return false
	}
	for _, r := range t {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// Fold case-folds and strips punctuation without expanding any abbreviation.
//
// It exists for labelled fields, where expansion is actively wrong: Normalise
// turns "st kilda" into "street kilda", which is correct when "st" appears
// after a street name in free text and badly wrong when the caller has already
// told us the field is a locality. Structured input knows what each value is,
// so it must not be re-guessed.
func Fold(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(raw) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(r)
		default:
			b.WriteByte(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// ExpandStreetType folds a street-type value and expands it to the full form
// used in the dataset ("st" -> "street"). Unknown values are returned folded
// but otherwise untouched, so an unusual real type is preserved rather than
// discarded.
func ExpandStreetType(raw string) string {
	f := Fold(raw)
	if f == "" {
		return ""
	}
	parts := strings.Fields(f)
	for i, p := range parts {
		if streettype.IsStreetType(p) {
			parts[i] = streettype.ExpandLower(p)
		}
	}
	return strings.Join(parts, " ")
}

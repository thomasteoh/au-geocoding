// Package normalise turns free text into tokens for generation and scoring.
// It is the only place user text becomes structure, so it owns the FTS5-injection
// guard (T3): every operator character is discarded here and the parse ladder
// rebuilds MATCH queries from the alphanumeric whitelist only.
package normalise

import (
	"regexp"
	"strings"
	"unicode"

	"ausystem/shared/postal"
	"ausystem/shared/streettype"
)

// streetTypes maps common Australian street-type abbreviations to the full form
// used for matching. The reverse (full→abbrev) is unnecessary: generation and
// scoring both work from the expanded form.

// unitPrefixes introduce a unit, flat, shop or suite number at the start of an
// address ("unit 3", "shop 2"). G-NAF keeps these as FLAT_NUMBER, so the unit
// is recorded in Result.Unit and passed on as "unit N" (see Result.Tokens).
var unitPrefixes = map[string]bool{
	"unit": true, "u": true, "flat": true, "f": true, "apartment": true,
	"apt": true, "suite": true, "su": true, "shop": true,
}

// levelPrefixes introduce a floor ("level 2", "lvl 2", "l2", "floor 2"; "2nd
// floor" is read by ordinalLevelRe). G-NAF keeps the level apart from the flat
// number, so it is recorded in Result.Level and passed on as "level N".
var levelPrefixes = map[string]bool{"level": true, "lvl": true, "l": true, "floor": true, "fl": true}

// stateCodes maps state abbreviations to the full name.
var stateCodes = map[string]string{
	"nsw": "new south wales", "vic": "victoria", "qld": "queensland",
	"sa": "south australia", "wa": "western australia", "tas": "tasmania",
	"nt": "northern territory", "act": "australian capital territory",
}

// Result is the normalised form of one query.
type Result struct {
	// Tokens is the full normalised token set, in query order — scoring. A
	// unit, lot, level or postal delivery point opens it in canonical words
	// ("unit 3", "lot 5", "level 2", "po box 123") so places reads it by position like the rest
	// of the address; none of those words is in Generate.
	Tokens   []string
	Generate []string // reliable tokens — candidate generation
	State    string   // hint, "" if absent
	Postcode string   // hint, "" if absent
	Unit     string   // unit/flat number, "" if absent
	Lot      string   // lot number, "" if absent
	Level    string   // level or floor number, "" if absent
	// POBox is the postal delivery point the address opens with ("po box
	// 123", "locked bag 5"), "" if none. G-NAF has no location for one.
	POBox      string
	IsPOI      bool // no street number, lot or postal box → likely a named place
	HadNumbers bool
	HadStreet  bool
}

var (
	numberRe      = regexp.MustCompile(`^([0-9]+)[a-z]?$`)
	unitPrefixRe  = regexp.MustCompile(`^(unit|apt|shop|u|f)([0-9]+)[a-z]?$`)
	levelPrefixRe = regexp.MustCompile(`^(lvl|l|fl)([0-9]+)[a-z]?$`)
	// ordinalLevelRe is the number in "2nd floor", "1st level".
	ordinalLevelRe = regexp.MustCompile(`^([0-9]+)(st|nd|rd|th)$`)
)

// Normalise folds case, strips punctuation, expands abbreviations, and pulls
// state/postcode hints out of the token stream.
//
// An address is read by position: [unit /] number street-name street-type
// locality [state] [postcode]. So a number before the street is the street
// number even when it has four digits ("1440 hume hwy"), and a four-digit
// number after a word is the postcode. Only the first street-type word after
// the start of the street name is expanded: "st" opening a name is Saint ("st
// kilda rd" stays "st kilda road") and a second "st" after the street type
// begins the locality ("fitzroy st st kilda" is "fitzroy street st kilda").
// Unit forms "3/15", "unit 3 15" and "u3 15" give unit 3, number 15; a range
// "15-17" gives 15, G-NAF's first number; "15a" gives 15. "lot 5" is a lot
// number, which stands in for the street number on rural and new-estate
// addresses, and a level ("level 2", "l2", "2nd floor") is a level number. A postal delivery point
// ("PO Box 123", "GPO Box", "Locked Bag") is recognised only at the start.
func Normalise(raw string) Result {
	s := strings.ToLower(raw)
	// Strip punctuation, keep alphanumerics and spaces (T3: no operator chars
	// ever reach a MATCH query). '/' and '-' survive as their own tokens
	// only long enough to read unit and range forms.
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(r)
		case r == '/', r == '-':
			b.WriteByte(' ')
			b.WriteRune(r)
			b.WriteByte(' ')
		default:
			b.WriteByte(' ')
		}
	}
	toks := strings.Fields(b.String())

	var out Result
	var number string
	i := 0
	if pd, n := postal.Parse(toks); n > 0 {
		out.POBox = strings.ToLower(pd)
		i = n
	}
	// Leading unit, lot, level and street number.
	for i < len(toks) {
		t := toks[i]
		next := i+1 < len(toks) && numberRe.MatchString(toks[i+1])
		if t == "lot" && next {
			out.Lot = numberRe.FindStringSubmatch(toks[i+1])[1]
			i += 2
			continue
		}
		if levelPrefixes[t] && next {
			out.Level = numberRe.FindStringSubmatch(toks[i+1])[1]
			i += 2
			continue
		}
		if m := levelPrefixRe.FindStringSubmatch(t); m != nil {
			out.Level = m[2]
			i++
			continue
		}
		if m := ordinalLevelRe.FindStringSubmatch(t); m != nil && i+1 < len(toks) && levelPrefixes[toks[i+1]] && toks[i+1] != "l" {
			out.Level = m[1]
			i += 2
			continue
		}
		if unitPrefixes[t] && next {
			out.Unit = numberRe.FindStringSubmatch(toks[i+1])[1]
			i += 2
			continue
		}
		if m := unitPrefixRe.FindStringSubmatch(t); m != nil {
			out.Unit = m[2]
			i++
			continue
		}
		m := numberRe.FindStringSubmatch(t)
		if m == nil || number != "" {
			break
		}
		if i+2 < len(toks) && toks[i+1] == "/" && numberRe.MatchString(toks[i+2]) {
			out.Unit = m[1]
			number = numberRe.FindStringSubmatch(toks[i+2])[1]
			i += 3
		} else {
			number = m[1]
			i++
			if i+1 < len(toks) && toks[i] == "-" && numberRe.MatchString(toks[i+1]) {
				i += 2
			}
		}
	}

	var words []string
	for _, t := range toks[i:] {
		if t != "/" && t != "-" {
			words = append(words, t)
		}
	}
	// A lone four-digit number is a postcode, not a street number.
	if number != "" && len(words) == 0 && isPostcode(number) && out.Unit == "" && out.Lot == "" {
		out.Postcode, number = number, ""
		words = []string{out.Postcode}
	}

	var keep []string
	if out.POBox != "" {
		keep = append(keep, strings.Fields(out.POBox)...)
	}
	if out.Unit != "" {
		keep = append(keep, "unit", out.Unit)
	}
	if out.Lot != "" {
		keep = append(keep, "lot", out.Lot)
	}
	if out.Level != "" {
		keep = append(keep, "level", out.Level)
	}
	qualifiers := len(keep)
	if number != "" {
		keep = append(keep, number)
	}
	var state string
	var hasStreet bool
	for j, t := range words {
		if !hasStreet && j > 0 && streettype.IsStreetType(t) {
			keep = append(keep, streettype.ExpandLower(t))
			hasStreet = true
			continue
		}
		if _, ok := stateCodes[t]; ok && state == "" && j > 0 {
			state = t
		} else if isPostcode(t) && out.Postcode == "" && (j > 0 || len(words) == 1) {
			out.Postcode = t
		}
		keep = append(keep, t)
	}

	out.Tokens = keep
	// Generate = reliable tokens only: words, street type, postcode, state.
	// The street number and other bare numbers are weak alone.
	for _, t := range keep[qualifiers:] {
		if t == out.Postcode || !isNumber(t) {
			out.Generate = append(out.Generate, t)
		}
	}
	out.State = stateCodes[state]
	out.IsPOI = number == "" && out.Lot == "" && out.POBox == ""
	out.HadNumbers = number != "" || out.Lot != ""
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

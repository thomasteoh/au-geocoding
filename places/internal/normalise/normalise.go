package normalise

// normalise converts free text into the Query the matcher consumes.
// Per INV-7: untrusted text never influences query structure; operator chars
// are discarded, whitelisted tokens only, token count capped.
//
// An Australian address is read by position, not token shape:
//
//	[unit /] number  street-name  street-type  locality  [state] [postcode]
//
// Shape alone gets the common cases wrong. "1440" is a street number before the
// street and a postcode after it; "ST" is Saint at the start of a name ("ST
// KILDA RD") and Street after one ("FITZROY ST"); localities run to several
// words (BOX HILL NORTH). Parse finds the locality first (the longest known
// name at the end of the text), then the street type is the first type word
// after the start of the street name, and everything else follows from where
// it sits.
//
// Street-type expansion is shared with the geocoder (ausystem/shared/streettype)
// so a new street type is added once. The locality typo aliases below are
// places-specific and stay here.

import (
	"regexp"
	"strings"

	"ausystem/shared/postal"
	"ausystem/shared/streettype"
)

// Alias map: common Australian locality/street abbreviations and typos,
// applied per word to street names and localities. G-NAF spells Saint as ST
// and Mount in full, so both are normalised to the dataset's form.
var Alias = map[string]string{
	"MELB":     "MELBOURNE",
	"COLLNS":   "COLLINS", // typo alias — the T4 case
	"STEET":    "STREET",  // typo alias — T4
	"MELBORNE": "MELBOURNE",
	"SAINT":    "ST",
	"MT":       "MOUNT",
}

// unitWords introduce a unit, flat, shop or suite number ("UNIT 3", "SHOP
// 2"), all of which G-NAF keeps as FLAT_NUMBER.
var unitWords = map[string]bool{
	"UNIT": true, "U": true, "FLAT": true, "F": true, "APARTMENT": true,
	"APT": true, "SUITE": true, "SHOP": true,
}

// levelWords introduce a floor ("LEVEL 2", "L2"). G-NAF keeps the level apart
// from the flat and the address table does not carry it, so a level is read
// only so that it is not taken for the unit, and dropped.
var levelWords = map[string]bool{"LEVEL": true, "LVL": true, "L": true}

var (
	stripRe     = regexp.MustCompile(`[^A-Z0-9'/\-\s]`)
	numberRe    = regexp.MustCompile(`^([0-9]+)[A-Z]?$`)
	unitWordRe  = regexp.MustCompile(`^(UNIT|APT|SHOP|U|F)([0-9]+)[A-Z]?$`)
	levelWordRe = regexp.MustCompile(`^(LVL|L)([0-9]+)[A-Z]?$`)
)

// Parsed is a free-text address split into its parts.
type Parsed struct {
	Unit   string // flat number, digits only
	Lot    string // lot number: stands in for the street number on lots
	Number string
	// POBox is a postal delivery point the text opens with ("PO BOX 123",
	// "LOCKED BAG 5"). G-NAF has no location for one: the answer is the
	// locality or postcode that follows it.
	POBox      string
	Street     string // street name, words joined with single spaces
	StreetType string // canonical full form (STREET, ROAD, ...)
	Locality   string
	State      string
	Postcode   string
	Rest       []string // words that fit no slot

	// uncertain is set when neither a street type nor a locality was found,
	// so the split between street and locality is unknown. Tokens then
	// anchors each word separately and lets generation sort it out.
	uncertain bool
}

// NearestLocality returns the known locality closest to a (possibly
// misspelt) name and its similarity in [0,1].
type NearestLocality func(name string) (string, float64)

// Similarity thresholds for fuzzy locality recognition. Extending an exact
// match leftwards ("NOTRH MELBOURNE" for NORTH MELBOURNE) needs a closer match
// than finding one from nothing, because the exact match already stands.
const (
	nearFind   = 0.75
	nearExtend = 0.8
)

// Parse splits free text into address parts. localitySet is the known
// locality names (upper case); with it, multi-word localities are recognised
// and a locality is told apart from a street. Without it, the words after the
// street type are taken as the locality. nearest, when not nil, recognises
// misspelt localities; the canonical name replaces the misspelling.
func Parse(input string, maxTokens int, localitySet map[string]bool, nearest NearestLocality) Parsed {
	clean := stripRe.ReplaceAllString(strings.ToUpper(input), " ")
	clean = strings.NewReplacer("/", " / ", "-", " - ").Replace(clean)
	toks := strings.Fields(clean)
	if maxTokens > 0 && len(toks) > maxTokens {
		toks = toks[:maxTokens]
	}

	var p Parsed
	i := 0
	if pd, n := postal.Parse(toks); n > 0 {
		p.POBox, i = pd, n
	}
	// Unit and street number. Accepts "UNIT 3 15", "U3 15", "3/15", "15-17"
	// (a range: the first number is G-NAF's number_first) and "15A", plus
	// "LOT 5" and a level, which is skipped.
	for i < len(toks) {
		t := toks[i]
		next := i+1 < len(toks) && numberRe.MatchString(toks[i+1])
		if t == "LOT" && next {
			p.Lot = numberRe.FindStringSubmatch(toks[i+1])[1]
			i += 2
			continue
		}
		if levelWords[t] && next {
			i += 2
			continue
		}
		if levelWordRe.MatchString(t) {
			i++
			continue
		}
		if unitWords[t] && next {
			p.Unit = numberRe.FindStringSubmatch(toks[i+1])[1]
			i += 2
			continue
		}
		if m := unitWordRe.FindStringSubmatch(t); m != nil {
			p.Unit = m[2]
			i++
			continue
		}
		m := numberRe.FindStringSubmatch(t)
		if m == nil || p.Number != "" {
			break
		}
		if i+2 < len(toks) && toks[i+1] == "/" && numberRe.MatchString(toks[i+2]) {
			p.Unit = m[1]
			p.Number = numberRe.FindStringSubmatch(toks[i+2])[1]
			i += 3
		} else {
			p.Number = m[1]
			i++
			if i+1 < len(toks) && toks[i] == "-" && numberRe.MatchString(toks[i+1]) {
				i += 2
			}
		}
	}

	// The remaining words, without separators, aliases applied.
	var words []string
	for _, t := range toks[i:] {
		if t == "/" || t == "-" {
			continue
		}
		if canon, ok := Alias[t]; ok {
			t = canon
		}
		words = append(words, t)
	}
	if len(words) == 0 {
		// A lone four-digit number is a postcode, not a street number.
		if p.Unit == "" && p.Lot == "" && isPostcode(p.Number) {
			p.Postcode, p.Number = p.Number, ""
		}
		return p
	}

	// Postcode and state come last, in either order.
	for len(words) > 0 {
		last := words[len(words)-1]
		switch {
		case p.Postcode == "" && isPostcode(last) && (len(words) > 1 || p.Number != ""):
			p.Postcode = last
		case p.State == "" && isState(last) && len(words) > 1:
			p.State = last
		case last == "AUSTRALIA" && len(words) > 1:
		default:
			goto located
		}
		words = words[:len(words)-1]
	}
located:

	// Locality: the longest known name ending as late as possible, leaving at
	// least one word for the street. A bare locality ("BOX HILL NORTH") is
	// allowed when it is the whole text.
	locStart, locEnd := -1, -1
	for end := len(words); end > 0 && locStart < 0; end-- {
		for n := min(4, end); n >= 1; n-- {
			start := end - n
			if start == 0 && end != len(words) {
				continue
			}
			if localitySet[strings.Join(words[start:end], " ")] {
				locStart, locEnd = start, end
				break
			}
		}
	}
	if nearest != nil {
		locStart, locEnd = fuzzyLocality(words, locStart, locEnd, nearest, &p)
	}
	street := words
	var trailing []string
	if locStart >= 0 && p.Locality == "" {
		p.Locality = strings.Join(words[locStart:locEnd], " ")
	}
	if locStart >= 0 {
		street = words[:locStart]
		trailing = words[locEnd:]
	}

	// Street type: the first type word after the first word of the name. A
	// type word at the start is part of the name (ST GEORGES, PARADE ...).
	typeAt := -1
	for j := 1; j < len(street); j++ {
		if streettype.IsStreetType(street[j]) {
			typeAt = j
			break
		}
	}
	if typeAt < 0 {
		p.Street = strings.Join(street, " ")
	} else {
		p.Street = strings.Join(street[:typeAt], " ")
		p.StreetType = streettype.Expand(street[typeAt])
		after := street[typeAt+1:]
		if locStart < 0 && len(after) > 0 {
			// No known locality: the words after the street type are it.
			p.Locality = strings.Join(after, " ")
		} else {
			trailing = append(after, trailing...)
		}
		// "THE ESPLANADE": the type word is the name. G-NAF stores some of
		// these as ESPLANADE and some as THE BOULEVARD; the name word alone
		// generates both, and scoring sorts out the rest.
		if p.Street == "THE" {
			p.Street = p.StreetType
			p.StreetType = ""
		}
	}
	p.uncertain = locStart < 0 && typeAt < 0
	p.Rest = trailing
	return p
}

// fuzzyLocality improves the exact locality match [start,end) with nearest.
// An exact match is extended leftwards when the longer span is a misspelt
// longer locality (WRECKYN NOTRH MELBOURNE is NORTH MELBOURNE, not MELBOURNE).
// With no exact match and no street type to split on, the best near match
// among the trailing spans is taken. A found name is written to p.Locality.
func fuzzyLocality(words []string, start, end int, nearest NearestLocality, p *Parsed) (int, int) {
	if start >= 0 {
		for k := 2; k >= 1; k-- {
			s := start - k
			if s < 1 || streetTypeAt(words, s) {
				continue
			}
			name, sim := nearest(strings.Join(words[s:end], " "))
			if sim >= nearExtend && len(strings.Fields(name)) == end-s {
				p.Locality = name
				return s, end
			}
		}
		return start, end
	}
	for j := 1; j < len(words); j++ {
		if streettype.IsStreetType(words[j]) {
			return -1, -1 // the street type splits street from locality
		}
	}
	best, bestSim, bestStart := "", 0.0, -1
	for s := len(words) - 1; s >= 1 && s >= len(words)-3; s-- {
		name, sim := nearest(strings.Join(words[s:], " "))
		if sim >= nearFind && sim >= bestSim {
			best, bestSim, bestStart = name, sim, s
		}
	}
	if bestStart < 0 {
		return -1, -1
	}
	p.Locality = best
	return bestStart, len(words)
}

// streetTypeAt reports whether words[s] is the street's type: a type word with
// no other after the first word before it. Extending a locality over it would
// read "COLLINS ST MELBOURNE" as COLLINS in EAST MELBOURNE.
func streetTypeAt(words []string, s int) bool {
	if !streettype.IsStreetType(words[s]) {
		return false
	}
	for j := 1; j < s; j++ {
		if streettype.IsStreetType(words[j]) {
			return false
		}
	}
	return true
}

// Tokenise parses text and returns the matcher's inputs: reliable tokens
// (generation anchors, most important first), score tokens, and a field tag
// per score token. Anchor order matters: when the full set generates nothing,
// generation drops anchors from the end, so the number and postcode go before
// the locality, and the street name is kept longest.
func Tokenise(input string, maxTokens int, localitySet map[string]bool, nearest NearestLocality) (reliable []string, score []string, fields []string) {
	return Parse(input, maxTokens, localitySet, nearest).Tokens()
}

// Tokens converts a parsed address into the matcher's inputs (see Tokenise).
func (p Parsed) Tokens() (reliable []string, score []string, fields []string) {
	add := func(v, field string, anchor bool) {
		if v == "" {
			return
		}
		score = append(score, v)
		fields = append(fields, field)
		if anchor {
			reliable = append(reliable, v)
		}
	}
	if p.uncertain {
		// Street and locality are run together: anchor each word.
		for _, w := range strings.Fields(p.Street) {
			add(w, "street_name", true)
		}
	} else {
		add(p.Street, "street_name", true)
	}
	add(p.Locality, "locality_name", true)
	add(p.Postcode, "postcode", true)
	add(p.Number, "street_number", true)
	// The unit, lot and postal box only order and score rows: addr_trgm
	// does not index them, so they cannot anchor generation.
	add(p.Unit, "flat_number", false)
	add(p.Lot, "lot_number", false)
	add(p.POBox, "postal_delivery", false)
	add(p.StreetType, "street_type", false)
	add(p.State, "state", false)
	for _, r := range p.Rest {
		add(r, "", false)
	}
	return reliable, score, fields
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

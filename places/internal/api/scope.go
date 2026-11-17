package api

// Scope: a dataset covers some states (a VIC build covers only VIC). A query
// for an address in a state the dataset lacks has no right answer here, and
// fuzzy matching would otherwise find one anyway: "1 Smith St Sydney NSW 2000"
// came back as 1 SMITH STREET, MADDINGLEY VIC. Such a query is refused as
// out_of_scope, which the geocoder passes to its caller, instead of answered.
//
// The rule weighs the three parts of an address that name a state:
//
//   - a state token: for a covered state (in scope) or not (out);
//   - a postcode: in scope when the dataset holds it or it falls in a covered
//     state's range, out when it falls in another state's range (AU postcode
//     ranges by state, postcodeState), no signal otherwise;
//   - a locality the dataset knows: in scope.
//
// The query is out of scope when at least one part points outside and the
// parts pointing outside are at least as many as those pointing in. So a
// postcode and locality together outweigh a stray state token ("36 Collins St
// Melbourne NSW 3000" is Melbourne VIC), but a foreign state with a locality
// name that also exists here ("High St Richmond NSW") is refused: answering
// Richmond VIC would be a confident wrong answer, refusing is honest. The
// covered states come from the data, so a national dataset refuses nothing.

import (
	"strconv"
	"strings"
)

// stateNames maps the geocoder's state hint (the full name) to the
// abbreviation the dataset stores.
var stateNames = map[string]string{
	"NEW SOUTH WALES": "NSW", "VICTORIA": "VIC", "QUEENSLAND": "QLD",
	"SOUTH AUSTRALIA": "SA", "WESTERN AUSTRALIA": "WA", "TASMANIA": "TAS",
	"NORTHERN TERRITORY": "NT", "AUSTRALIAN CAPITAL TERRITORY": "ACT",
}

// postcodeRanges are the Australian postcode ranges by state, including the
// PO box and large-user ranges (VIC 8000-8999, QLD 9000-9999). ACT's ranges
// sit inside NSW's, so they are listed first.
var postcodeRanges = []struct {
	lo, hi int
	state  string
}{
	{200, 299, "ACT"}, {2600, 2618, "ACT"}, {2900, 2920, "ACT"},
	{1000, 2599, "NSW"}, {2619, 2899, "NSW"}, {2921, 2999, "NSW"},
	{3000, 3999, "VIC"}, {8000, 8999, "VIC"},
	{4000, 4999, "QLD"}, {9000, 9999, "QLD"},
	{5000, 5999, "SA"},
	{6000, 6999, "WA"},
	{7000, 7999, "TAS"},
	{800, 999, "NT"},
}

// postcodeState returns the state whose range holds a four-digit postcode, or
// "" when none does.
func postcodeState(pc string) string {
	if len(pc) != 4 {
		return ""
	}
	n, err := strconv.Atoi(pc)
	if err != nil {
		return ""
	}
	for _, r := range postcodeRanges {
		if n >= r.lo && n <= r.hi {
			return r.state
		}
	}
	return ""
}

// outOfScope applies the rule above. state is an abbreviation or a full name
// (either case); locality is the canonical name the parser found.
func outOfScope(sets *matchSets, state, postcode, locality string) bool {
	if len(sets.states) == 0 {
		return false // nothing loaded to judge against
	}
	in, out := 0, 0
	if st := strings.ToUpper(strings.TrimSpace(state)); st != "" {
		if abbr, ok := stateNames[st]; ok {
			st = abbr
		}
		if sets.states[st] {
			in++
		} else {
			out++
		}
	}
	if postcode != "" {
		switch st := postcodeState(postcode); {
		case sets.postcodes[postcode], st != "" && sets.states[st]:
			in++
		case st != "":
			out++
		}
	}
	if locality != "" && sets.localities[locality] {
		in++
	}
	return out > 0 && out >= in
}

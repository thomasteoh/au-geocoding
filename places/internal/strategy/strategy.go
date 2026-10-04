package strategy

// The parse ladder — rungs 1–4 (rung 5, LLM, is deferred per the roadmap; the
// demo exit is that rung 3 resolves the flagship query without an LLM).
//
// A single /search endpoint takes free text and walks the rungs, cheapest
// first, stopping at the first one that clears its threshold. Every response
// carries `strategy` so callers and the demo UI see which rung fired.
//
// Rung 3 (poi_anchor) handles "woolworths near doncaster and blackburn road"
// deterministically: connector keywords (near, at, in, on, corner of, cnr, &,
// comma) partition the string; the left fragment goes to POI search, the right
// fragments become anchors. No model required.

import (
	"strings"
)

// Strategy is the ladder rung that fired.
type Strategy string

const (
	StrategyCoord     Strategy = "coord"
	StrategyAddress   Strategy = "address"
	StrategyPOIAnchor Strategy = "poi_anchor"
	StrategyPOI       Strategy = "poi"
	StrategyLLM       Strategy = "llm"
)

// connectors split the input into fragments. Each is a keyword that marks the
// boundary between a POI/address and an anchor ("near", "at", "in", "on",
// "corner of", "cnr", "&", ","). The left fragment before the first connector
// is the query target; the rest are anchors.
// UPPERCASE because Classify uppercases the input first.
var connectors = []string{
	" NEAR ", " AT ", " IN ", " ON ", " CORNER OF ", " CNR ", " & ", " , ",
}

// Plan is the interpreted resolution plan. strategy is the rung; requests are
// the per-part resolution requests (POI target, anchors).
type Plan struct {
	Strategy Strategy
	Query    string   // the query target (left fragment)
	Anchors  []string // the anchor fragments (right fragments)
}

// Classify splits free text into a plan by connector keywords. It returns the
// strategy and the parsed fragments. This is rung 3/4 classification — the
// deterministic split that resolves the flagship query without an LLM.
//
// The split is on connector keywords; the left fragment is the POI target, the
// right fragments are anchors. A fragment with an address (a street number +
// name, or a state) routes to the address rung; a bare name routes to POI.
func Classify(input string) Plan {
	s := strings.ToUpper(strings.TrimSpace(input))
	s = strings.ReplaceAll(s, "&", " & ")
	// Find the first connector.
	first := -1
	firstConn := ""
	for _, c := range connectors {
		if idx := strings.Index(s, c); idx >= 0 && (first < 0 || idx < first) {
			first = idx
			firstConn = c
		}
	}
	if first < 0 {
		// No connector — bare POI or address.
		if isCoord(s) {
			return Plan{Strategy: StrategyCoord, Query: s}
		}
		if looksAddress(s) {
			return Plan{Strategy: StrategyAddress, Query: s}
		}
		return Plan{Strategy: StrategyPOI, Query: s}
	}

	left := strings.TrimSpace(s[:first])
	right := strings.TrimSpace(s[first+len(firstConn):])
	// The right side may have further connectors — split into anchors.
	anchors := splitAnchors(right)

	if left == "" {
		// Connector-first: e.g. "near doncaster" — the target is the anchor.
		if len(anchors) > 0 {
			return Plan{Strategy: StrategyPOIAnchor, Query: anchors[0], Anchors: anchors[1:]}
		}
		return Plan{Strategy: StrategyPOI, Query: right}
	}

	if looksAddress(left) {
		return Plan{Strategy: StrategyAddress, Query: left, Anchors: anchors}
	}
	// Left is a POI (name/brand), right fragments are anchors → rung 3.
	return Plan{Strategy: StrategyPOIAnchor, Query: left, Anchors: anchors}
}

// splitAnchors splits the right fragment on further connectors into anchor
// fragments.
func splitAnchors(right string) []string {
	s := right
	for _, c := range connectors {
		s = strings.ReplaceAll(s, c, "\x00")
	}
	parts := strings.Split(s, "\x00")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// looksAddress reports whether a fragment resembles an address (has a street
// number + name, or a state/postcode, or a street suffix + locality).
func looksAddress(s string) bool {
	up := strings.ToUpper(s)
	if strings.Contains(up, " VIC ") || strings.Contains(up, " NSW ") ||
		strings.Contains(up, " QLD ") || strings.Contains(up, " SA ") ||
		strings.Contains(up, " WA ") || strings.Contains(up, " TAS ") ||
		strings.Contains(up, " NT ") || strings.Contains(up, " ACT ") {
		return true
	}
	fields := strings.Fields(up)
	if len(fields) == 0 {
		return false
	}
	// A digit-led token (street number, unit/format number "12/45", "12-45").
	// isNumeric requires pure digits; a token that STARTS with a digit is a
	// number (or a unit/format number) even if it has / or - or a suffix.
	if startsNumeric(fields[0]) {
		// Need a following word (the street name).
		for i := 1; i < len(fields); i++ {
			if len(fields[i]) > 1 && !startsNumeric(fields[i]) {
				return true
			}
		}
		return false
	}
	// A commercial/unit prefix ("SHOP 12", "UNIT 5", "SUITE 3", "LEVEL 2") —
	// the prefix word followed by a digit-led token is an address.
	prefixes := map[string]bool{"SHOP": true, "UNIT": true, "SUITE": true,
		"LEVEL": true, "APARTMENT": true, "FLAT": true, "OFFICE": true,
		"LOT": true, "TENANCY": true}
	if prefixes[fields[0]] && len(fields) > 1 && startsNumeric(fields[1]) {
		return true
	}
	// Street suffix + locality without a number ("COLLINS ST MELBOURNE"): a
	// street suffix followed by at least one more token is an address.
	streetSuffixes := map[string]bool{"ST": true, "RD": true, "ROAD": true,
		"STREET": true, "AVE": true, "AVENUE": true, "DR": true, "DRIVE": true,
		"CT": true, "COURT": true, "CRES": true, "CRESCENT": true,
		"PARADE": true, "LN": true, "LANE": true, "WALK": true,
		"CLOSE": true, "PLACE": true, "TERRACE": true, "BLVD": true,
		"BOULEVARD": true}
	for i := 0; i < len(fields); i++ {
		if streetSuffixes[fields[i]] {
			// The street name precedes it; at least one token follows (locality).
			return i > 0 && i+1 < len(fields)
		}
	}
	return false
}

// isCoord reports whether the input is a bare coordinate ("-37.81, 144.96").
func isCoord(s string) bool {
	// Contains a decimal point and a comma (two coordinates).
	return strings.Contains(s, ",") && strings.Contains(s, ".")
}

// startsNumeric reports whether a token starts with a digit ("12", "12/45",
// "12A" — unit/format numbers).
func startsNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
		if c != '/' && c != '-' && c != 'A' && c != 'B' && c != 'C' &&
			c != 'D' && c != 'E' && c != 'F' && c != 'G' && c != 'H' {
			return false
		}
	}
	return s[0] >= '0' && s[0] <= '9'
}

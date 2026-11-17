// Package postal recognises postal delivery points: PO boxes, GPO boxes,
// locked bags and private bags. G-NAF holds street addresses only, so neither
// normaliser can match one; both have to recognise it so the text is answered
// at the locality or postcode it names instead of being read as a street.
// It is shared by geocoding and places so a new spelling is added once.
package postal

import (
	"regexp"
	"strings"
)

// forms maps the token sequences people type to the canonical kind. The
// sequences are matched after punctuation is stripped, so "P.O. Box" arrives
// as P O BOX and "P/O Box" as P / O BOX.
var forms = []struct {
	words []string
	kind  string
}{
	{[]string{"PO", "BOX"}, "PO BOX"},
	{[]string{"P", "O", "BOX"}, "PO BOX"},
	{[]string{"P", "/", "O", "BOX"}, "PO BOX"},
	{[]string{"POBOX"}, "PO BOX"},
	{[]string{"POST", "OFFICE", "BOX"}, "PO BOX"},
	{[]string{"GPO", "BOX"}, "GPO BOX"},
	{[]string{"G", "P", "O", "BOX"}, "GPO BOX"},
	{[]string{"GPOBOX"}, "GPO BOX"},
	{[]string{"LOCKED", "BAG"}, "LOCKED BAG"},
	{[]string{"LOCKED", "MAIL", "BAG"}, "LOCKED BAG"},
	{[]string{"LMB"}, "LOCKED BAG"},
	{[]string{"PRIVATE", "BAG"}, "PRIVATE BAG"},
	{[]string{"PRIVATE", "MAIL", "BAG"}, "PRIVATE BAG"},
	{[]string{"PMB"}, "PRIVATE BAG"},
}

var numberRe = regexp.MustCompile(`^[0-9]+[A-Z]?$`)

// Parse reads a postal delivery point at the start of toks (any case). It
// returns the canonical form in upper case ("PO BOX 123", or "PO BOX" when no
// number follows) and how many tokens it used; n is 0 when toks does not open
// with one. The number may be its own token or joined to the last word
// ("BOX123"). A bare "BOX" is not enough: Box Hill is a locality.
func Parse(toks []string) (canonical string, n int) {
	up := make([]string, 0, 5)
	for _, t := range toks[:min(len(toks), 5)] {
		up = append(up, strings.ToUpper(t))
	}
	for _, f := range forms {
		k := len(f.words)
		if len(up) < k || !equal(up[:k-1], f.words[:k-1]) {
			continue
		}
		last, word := up[k-1], f.words[k-1]
		switch {
		case last == word:
			if k < len(up) && numberRe.MatchString(up[k]) {
				return f.kind + " " + up[k], k + 1
			}
			return f.kind, k
		case strings.HasPrefix(last, word) && numberRe.MatchString(last[len(word):]):
			return f.kind + " " + last[len(word):], k
		}
	}
	return "", 0
}

func equal(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

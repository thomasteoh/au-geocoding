// Package postbox maps Victorian post-office-box postcodes to the locality
// they are delivered at. A PO box postcode (3001 is Melbourne's GPO boxes)
// has no street address in G-NAF and no ABS postal area, so neither the
// address table nor the postcode table can place "PO Box 9 3001"; this
// curated table can. It is checked in (pobox_postcodes.tsv), every row with
// the public source it was verified against, and embedded so every dataset
// gets it without a build step.
package postbox

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed pobox_postcodes.tsv
var table string

// Entry is one curated postcode.
type Entry struct {
	Postcode  string
	Locality  string // the G-NAF locality name
	State     string
	Category  string // Australia Post's category ("Post Office Boxes")
	Details   string // "GPO Boxes", "PO Boxes", "Reply Paid"
	SourceURL string
	Retrieved string
}

var entries = mustParse(table)

// Lookup returns the curated entry for postcode.
func Lookup(postcode string) (Entry, bool) {
	e, ok := entries[postcode]
	return e, ok
}

// All returns every curated entry, keyed by postcode. Callers must not modify it.
func All() map[string]Entry { return entries }

func mustParse(s string) map[string]Entry {
	m, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return m
}

// Parse reads the TSV form of pobox_postcodes.tsv. Every row must have all
// seven columns, a four-digit postcode, a locality and an http(s) source URL.
func Parse(s string) (map[string]Entry, error) {
	out := map[string]Entry{}
	for n, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 7 {
			return nil, fmt.Errorf("pobox_postcodes.tsv line %d: %d columns, want 7", n+1, len(f))
		}
		e := Entry{f[0], f[1], f[2], f[3], f[4], f[5], f[6]}
		switch {
		case len(e.Postcode) != 4 || strings.Trim(e.Postcode, "0123456789") != "":
			return nil, fmt.Errorf("line %d: bad postcode %q", n+1, e.Postcode)
		case e.Locality == "" || e.Locality != strings.ToUpper(e.Locality):
			return nil, fmt.Errorf("line %d: locality %q must be the upper-case G-NAF name", n+1, e.Locality)
		case !strings.HasPrefix(e.SourceURL, "https://") && !strings.HasPrefix(e.SourceURL, "http://"):
			return nil, fmt.Errorf("line %d: no source URL", n+1)
		}
		if _, dup := out[e.Postcode]; dup {
			return nil, fmt.Errorf("line %d: postcode %s listed twice", n+1, e.Postcode)
		}
		out[e.Postcode] = e
	}
	return out, nil
}

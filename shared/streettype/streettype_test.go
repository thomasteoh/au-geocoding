package streettype

import "testing"

func TestStripSuffix(t *testing.T) {
	for in, want := range map[string]string{
		"SYDNEY ROAD":   "SYDNEY",
		"Sydney Rd":     "SYDNEY",
		"COLLINS STR":   "COLLINS",
		"HUME FWY":      "HUME",
		"ST KILDA":      "ST KILDA",
		"THE ESPLANADE": "THE ESPLANADE",
		"PARADE":        "PARADE",
		"THE CRESCENT":  "THE CRESCENT",
		"OLD THE MALL":  "OLD THE MALL",
	} {
		if got := StripSuffix(in); got != want {
			t.Errorf("StripSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryAbbreviationStrips(t *testing.T) {
	// StripSuffix and IsStreetType share one vocabulary.
	for abbr := range fullNames {
		if got := StripSuffix("MAIN " + abbr); got != "MAIN" {
			t.Errorf("StripSuffix(MAIN %s) = %q", abbr, got)
		}
	}
}

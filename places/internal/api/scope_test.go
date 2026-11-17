package api

import "testing"

func TestOutOfScope(t *testing.T) {
	vic := &matchSets{
		states:     map[string]bool{"VIC": true},
		postcodes:  map[string]bool{"3000": true, "3121": true, "3690": true},
		localities: map[string]bool{"MELBOURNE": true, "RICHMOND": true},
	}
	cases := []struct {
		state, postcode, locality string
		out                       bool
	}{
		{"NSW", "2000", "", true},           // 1 Smith St Sydney NSW 2000
		{"", "2150", "", true},              // a NSW postcode alone
		{"", "0800", "", true},              // NT, leading zero
		{"", "2600", "", true},              // ACT inside NSW's range
		{"NSW", "", "", true},               // a foreign state alone
		{"NSW", "", "RICHMOND", true},       // a tie: Richmond NSW is real
		{"new south wales", "", "", true},   // the geocoder's state hint
		{"NSW", "3000", "MELBOURNE", false}, // postcode and locality outweigh the state
		{"VIC", "2000", "MELBOURNE", false}, // state and locality outweigh the postcode
		{"", "3999", "", false},             // in VIC's range, not in the data
		{"", "", "MELBOURNE", false},
		{"VIC", "", "", false},
		{"", "", "", false},
		{"", "0100", "", false}, // in no state's range: no signal
	}
	for _, c := range cases {
		if got := outOfScope(vic, c.state, c.postcode, c.locality); got != c.out {
			t.Errorf("outOfScope(%q, %q, %q) = %v, want %v", c.state, c.postcode, c.locality, got, c.out)
		}
	}
	// A dataset that covers NSW refuses none of it.
	both := &matchSets{states: map[string]bool{"VIC": true, "NSW": true}}
	if outOfScope(both, "NSW", "2000", "") {
		t.Error("NSW refused by a dataset that covers it")
	}
}

package normalise

import (
	"reflect"
	"testing"
)

func TestNormalise(t *testing.T) {
	cases := []struct {
		in       string
		tokens   []string
		unit     string
		postcode string
		number   bool
		street   bool
	}{
		{"93 High St Preston", []string{"93", "high", "street", "preston"}, "", "", true, true},
		{"1440 Hume Hwy Craigieburn", []string{"1440", "hume", "highway", "craigieburn"}, "", "", true, true},
		{"157 Fitzroy St St Kilda", []string{"157", "fitzroy", "street", "st", "kilda"}, "", "", true, true},
		{"3 St Kilda Rd", []string{"3", "st", "kilda", "road"}, "", "", true, true},
		{"2/36 Collins St Melbourne VIC 3000", []string{"36", "collins", "street", "melbourne", "vic", "3000"}, "2", "3000", true, true},
		{"Unit 3, 157 Fitzroy St", []string{"157", "fitzroy", "street"}, "3", "", true, true},
		{"u3 15a High St", []string{"15", "high", "street"}, "3", "", true, true},
		{"15-17 Smith St", []string{"15", "smith", "street"}, "", "", true, true},
		{"12 Collins Way Melbourne", []string{"12", "collins", "way", "melbourne"}, "", "", true, true},
		{"3000", []string{"3000"}, "", "3000", false, false},
		{"woolworths", []string{"woolworths"}, "", "", false, false},
	}
	for _, c := range cases {
		r := Normalise(c.in)
		if !reflect.DeepEqual(r.Tokens, c.tokens) || r.Unit != c.unit || r.Postcode != c.postcode ||
			r.HadNumbers != c.number || r.HadStreet != c.street {
			t.Errorf("Normalise(%q) = tokens %v unit %q postcode %q number %v street %v; want %v %q %q %v %v",
				c.in, r.Tokens, r.Unit, r.Postcode, r.HadNumbers, r.HadStreet,
				c.tokens, c.unit, c.postcode, c.number, c.street)
		}
	}
}

func TestNormaliseGenerateExcludesNumbers(t *testing.T) {
	r := Normalise("2/36 Collins St Melbourne VIC 3000")
	want := []string{"collins", "street", "melbourne", "vic", "3000"}
	if !reflect.DeepEqual(r.Generate, want) {
		t.Errorf("Generate = %v, want %v", r.Generate, want)
	}
	if r.State != "victoria" {
		t.Errorf("State = %q, want victoria", r.State)
	}
}

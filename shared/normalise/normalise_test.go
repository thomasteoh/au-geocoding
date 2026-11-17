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
		{"2/36 Collins St Melbourne VIC 3000", []string{"unit", "2", "36", "collins", "street", "melbourne", "vic", "3000"}, "2", "3000", true, true},
		{"Unit 3, 157 Fitzroy St", []string{"unit", "3", "157", "fitzroy", "street"}, "3", "", true, true},
		{"u3 15a High St", []string{"unit", "3", "15", "high", "street"}, "3", "", true, true},
		{"15-17 Smith St", []string{"15", "smith", "street"}, "", "", true, true},
		{"12 Collins Way Melbourne", []string{"12", "collins", "way", "melbourne"}, "", "", true, true},
		{"Level 2, 36 Collins St", []string{"36", "collins", "street"}, "", "", true, true},
		{"L2 36 Collins St", []string{"36", "collins", "street"}, "", "", true, true},
		{"Shop 4 Level 1 36 Collins St", []string{"unit", "4", "36", "collins", "street"}, "4", "", true, true},
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

func TestNormaliseLot(t *testing.T) {
	r := Normalise("Lot 14 Old Sydney Rd Wallan VIC 3756")
	want := []string{"lot", "14", "old", "sydney", "road", "wallan", "vic", "3756"}
	if !reflect.DeepEqual(r.Tokens, want) || r.Lot != "14" || r.Postcode != "3756" {
		t.Errorf("tokens %v lot %q postcode %q; want %v 14 3756", r.Tokens, r.Lot, r.Postcode, want)
	}
	if !r.HadNumbers || r.IsPOI {
		t.Errorf("HadNumbers %v IsPOI %v; a lot is an address, not a place name", r.HadNumbers, r.IsPOI)
	}
	if gen := []string{"old", "sydney", "road", "wallan", "vic", "3756"}; !reflect.DeepEqual(r.Generate, gen) {
		t.Errorf("Generate = %v, want %v", r.Generate, gen)
	}
}

func TestNormalisePostal(t *testing.T) {
	cases := []struct {
		in, pobox, postcode string
		tokens              []string
	}{
		{"PO Box 123 Melbourne VIC 3001", "po box 123", "3001", []string{"po", "box", "123", "melbourne", "vic", "3001"}},
		{"P.O. Box 77, Kilmore", "po box 77", "", []string{"po", "box", "77", "kilmore"}},
		{"P/O Box 5 Bright", "po box 5", "", []string{"po", "box", "5", "bright"}},
		{"POBox 9 Bright", "po box 9", "", []string{"po", "box", "9", "bright"}},
		{"Post Office Box 12 Box Hill", "po box 12", "", []string{"po", "box", "12", "box", "hill"}},
		// A four-digit box number is not the postcode.
		{"GPO Box 1234 Melbourne VIC 3001", "gpo box 1234", "3001", []string{"gpo", "box", "1234", "melbourne", "vic", "3001"}},
		{"G.P.O. Box 4", "gpo box 4", "", []string{"gpo", "box", "4"}},
		{"Locked Bag 10, Geelong VIC 3220", "locked bag 10", "3220", []string{"locked", "bag", "10", "geelong", "vic", "3220"}},
		{"Locked Mail Bag 3 Ballarat", "locked bag 3", "", []string{"locked", "bag", "3", "ballarat"}},
		{"Private Bag 1 Warragul", "private bag 1", "", []string{"private", "bag", "1", "warragul"}},
		{"PMB 2 Mildura", "private bag 2", "", []string{"private", "bag", "2", "mildura"}},
		{"PO Box 500 3550", "po box 500", "3550", []string{"po", "box", "500", "3550"}},
		{"Box Hill North", "", "", []string{"box", "hill", "north"}},
	}
	for _, c := range cases {
		r := Normalise(c.in)
		if r.POBox != c.pobox || r.Postcode != c.postcode || !reflect.DeepEqual(r.Tokens, c.tokens) {
			t.Errorf("Normalise(%q) = pobox %q postcode %q tokens %v; want %q %q %v",
				c.in, r.POBox, r.Postcode, r.Tokens, c.pobox, c.postcode, c.tokens)
		}
		if c.pobox == "" {
			continue
		}
		if r.IsPOI {
			t.Errorf("Normalise(%q).IsPOI = true; a postal box is not a place name", c.in)
		}
	}
	r := Normalise("PO Box 123 Melbourne VIC 3001")
	if want := []string{"melbourne", "vic", "3001"}; !reflect.DeepEqual(r.Generate, want) {
		t.Errorf("Generate = %v, want %v; postal words are not anchors", r.Generate, want)
	}
}

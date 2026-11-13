package normalise

import (
	"reflect"
	"testing"
)

var testLocalities = map[string]bool{
	"ST KILDA": true, "MELBOURNE": true, "NORTH MELBOURNE": true, "BOX HILL": true,
	"BOX HILL NORTH": true, "RICHMOND": true, "TOORAK": true, "FITZROY": true,
	"PRESTON": true, "CRAIGIEBURN": true, "DARTMOUTH": true,
}

// nearest is a stand-in for FuzzySet.NearestLocality over testLocalities.
func nearest(name string) (string, float64) {
	switch name {
	case "DARTMOUHT":
		return "DARTMOUTH", 0.89
	case "NOTRH MELBOURNE":
		return "NORTH MELBOURNE", 0.93
	}
	if testLocalities[name] {
		return name, 1
	}
	return "", 0
}

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Parsed
	}{
		{"93 High St Preston", Parsed{Number: "93", Street: "HIGH", StreetType: "STREET", Locality: "PRESTON"}},
		{"1440 Hume Hwy Craigieburn", Parsed{Number: "1440", Street: "HUME", StreetType: "HIGHWAY", Locality: "CRAIGIEBURN"}},
		{"36 Collins St Melbourne VIC 3000", Parsed{Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE", State: "VIC", Postcode: "3000"}},
		{"157 Fitzroy St St Kilda", Parsed{Number: "157", Street: "FITZROY", StreetType: "STREET", Locality: "ST KILDA"}},
		{"3 St Kilda Rd St Kilda", Parsed{Number: "3", Street: "ST KILDA", StreetType: "ROAD", Locality: "ST KILDA"}},
		{"23 Saint Georges Rd Toorak", Parsed{Number: "23", Street: "ST GEORGES", StreetType: "ROAD", Locality: "TOORAK"}},
		{"883 Station St Box Hill North", Parsed{Number: "883", Street: "STATION", StreetType: "STREET", Locality: "BOX HILL NORTH"}},
		{"12 Richmond Rd", Parsed{Number: "12", Street: "RICHMOND", StreetType: "ROAD"}},
		{"14 Toorak Ave Toorak", Parsed{Number: "14", Street: "TOORAK", StreetType: "AVENUE", Locality: "TOORAK"}},
		{"13 The Esplanade St Kilda", Parsed{Number: "13", Street: "ESPLANADE", Locality: "ST KILDA"}},
		{"2/36 Collins St Melbourne", Parsed{Unit: "2", Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"Unit 3, 157 Fitzroy St, St Kilda", Parsed{Unit: "3", Number: "157", Street: "FITZROY", StreetType: "STREET", Locality: "ST KILDA"}},
		{"U3 15A High St Preston", Parsed{Unit: "3", Number: "15", Street: "HIGH", StreetType: "STREET", Locality: "PRESTON"}},
		{"15-17 High St Preston", Parsed{Number: "15", Street: "HIGH", StreetType: "STREET", Locality: "PRESTON"}},
		{"93 High St Prestn", Parsed{Number: "93", Street: "HIGH", StreetType: "STREET", Locality: "PRESTN"}},
		{"11 Cross Dartmouht VIC", Parsed{Number: "11", Street: "CROSS", Locality: "DARTMOUTH", State: "VIC"}},
		{"24 Wreckyn Notrh Melbourne", Parsed{Number: "24", Street: "WRECKYN", Locality: "NORTH MELBOURNE"}},
		{"Box Hill North", Parsed{Locality: "BOX HILL NORTH"}},
	}
	for _, c := range cases {
		got := Parse(c.in, 32, testLocalities, nearest)
		got.uncertain = false
		if len(got.Rest) == 0 {
			got.Rest = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parse(%q)\n got  %+v\n want %+v", c.in, got, c.want)
		}
	}
}

func TestTokensOrderAndFields(t *testing.T) {
	rel, score, fields := Tokenise("93 High St Preston VIC 3072", 32, testLocalities, nil)
	if want := []string{"HIGH", "PRESTON", "3072", "93"}; !reflect.DeepEqual(rel, want) {
		t.Errorf("reliable = %v, want %v (street first, number last)", rel, want)
	}
	wantFields := map[string]string{"HIGH": "street_name", "PRESTON": "locality_name", "3072": "postcode",
		"93": "street_number", "STREET": "street_type", "VIC": "state"}
	for i, s := range score {
		if fields[i] != wantFields[s] {
			t.Errorf("field of %q = %q, want %q", s, fields[i], wantFields[s])
		}
	}
}

func TestTokensUncertainAnchorsEachWord(t *testing.T) {
	// No street type and no known locality: the street/locality split is
	// unknown, so each word is its own anchor for fuzzy generation.
	rel, _, _ := Tokenise("85 Gladstone Sth", 32, testLocalities, nil)
	if want := []string{"GLADSTONE", "STH", "85"}; !reflect.DeepEqual(rel, want) {
		t.Errorf("reliable = %v, want %v", rel, want)
	}
}

func TestParseDiscardsOperators(t *testing.T) {
	p := Parse(`12 "high" OR st* (preston)`, 32, testLocalities, nil)
	for _, s := range []string{p.Street, p.Locality, p.StreetType} {
		for _, r := range s {
			if r == '"' || r == '*' || r == '(' || r == ')' {
				t.Fatalf("operator character survived: %+v", p)
			}
		}
	}
}

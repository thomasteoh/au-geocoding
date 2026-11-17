package normalise

import (
	"reflect"
	"testing"
)

var testLocalities = map[string]bool{
	"ST KILDA": true, "MELBOURNE": true, "EAST MELBOURNE": true, "NORTH MELBOURNE": true, "BOX HILL": true,
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
	case "ST MELBOURNE": // close to a real locality, but ST is the street type
		return "EAST MELBOURNE", 0.86
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
		{"7/12 Collins St Melbourne", Parsed{Unit: "7", Number: "12", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"Level 2, 36 Collins St Melbourne", Parsed{Level: "2", Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"Shop 4 L1 36 Collins St Melbourne", Parsed{Unit: "4", Level: "1", Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"Lot 14 Old Sydney Rd Wallan", Parsed{Lot: "14", Street: "OLD SYDNEY", StreetType: "ROAD", Locality: "WALLAN"}},
		{"LOT 5 Richmond Rd Toorak VIC 3142", Parsed{Lot: "5", Street: "RICHMOND", StreetType: "ROAD", Locality: "TOORAK", State: "VIC", Postcode: "3142"}},
		{"PO Box 123 Melbourne VIC 3001", Parsed{POBox: "PO BOX 123", Locality: "MELBOURNE", State: "VIC", Postcode: "3001"}},
		{"GPO Box 1234 Melbourne", Parsed{POBox: "GPO BOX 1234", Locality: "MELBOURNE"}},
		{"P.O. Box 12, Box Hill", Parsed{POBox: "PO BOX 12", Locality: "BOX HILL"}},
		{"Locked Bag 10 Richmond 3121", Parsed{POBox: "LOCKED BAG 10", Locality: "RICHMOND", Postcode: "3121"}},
		{"Private Bag 3 3550", Parsed{POBox: "PRIVATE BAG 3", Postcode: "3550"}},
		{"15-17 High St Preston", Parsed{Number: "15", Street: "HIGH", StreetType: "STREET", Locality: "PRESTON"}},
		{"93 High St Prestn", Parsed{Number: "93", Street: "HIGH", StreetType: "STREET", Locality: "PRESTN"}},
		{"11 Cross Dartmouht VIC", Parsed{Number: "11", Street: "CROSS", Locality: "DARTMOUTH", State: "VIC"}},
		{"24 Wreckyn Notrh Melbourne", Parsed{Number: "24", Street: "WRECKYN", Locality: "NORTH MELBOURNE"}},
		{"Box Hill North", Parsed{Locality: "BOX HILL NORTH"}},
		// Positional descriptors before the number are skipped...
		{"Ground Floor 36 Collins St Melbourne", Parsed{Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"G/F, 36 Collins St Melbourne", Parsed{Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"Rear 36 Collins St Melbourne", Parsed{Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"Front, 2/36 Collins St Melbourne", Parsed{Unit: "2", Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"Upper Ground Shop 4 36 Collins St Melbourne", Parsed{Unit: "4", Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"Lower Ground Floor 36 Collins St Melbourne", Parsed{Number: "36", Street: "COLLINS", StreetType: "STREET", Locality: "MELBOURNE"}},
		{"Basement Lot 5 Richmond Rd Toorak", Parsed{Lot: "5", Street: "RICHMOND", StreetType: "ROAD", Locality: "TOORAK"}},
		// ...but name the street when no number follows them.
		{"12 Upper Heidelberg Rd", Parsed{Number: "12", Street: "UPPER HEIDELBERG", StreetType: "ROAD"}},
		{"Front St Richmond", Parsed{Street: "FRONT", StreetType: "STREET", Locality: "RICHMOND"}},
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

func TestTokensUnitLotPostal(t *testing.T) {
	_, score, fields := Parse("UNIT 2 36 COLLINS STREET MELBOURNE", 32, testLocalities, nil).Tokens()
	if !has(score, fields, "2", "flat_number") || !has(score, fields, "36", "street_number") {
		t.Errorf("unit: score %v fields %v", score, fields)
	}
	rel, score, fields := Parse("LOT 14 OLD SYDNEY ROAD WALLAN", 32, testLocalities, nil).Tokens()
	if !has(score, fields, "14", "lot_number") {
		t.Errorf("lot: score %v fields %v", score, fields)
	}
	for _, r := range rel {
		if r == "14" {
			t.Errorf("lot number anchors generation: %v", rel)
		}
	}
	rel, score, fields = Parse("PO BOX 123 MELBOURNE VIC 3001", 32, testLocalities, nil).Tokens()
	if !has(score, fields, "PO BOX 123", "postal_delivery") || !has(score, fields, "MELBOURNE", "locality_name") {
		t.Errorf("postal: score %v fields %v", score, fields)
	}
	if want := []string{"MELBOURNE", "3001"}; !reflect.DeepEqual(rel, want) {
		t.Errorf("postal anchors %v, want %v", rel, want)
	}
}

func has(score, fields []string, v, field string) bool {
	for i := range score {
		if score[i] == v && fields[i] == field {
			return true
		}
	}
	return false
}

func TestParseIntersection(t *testing.T) {
	cases := []struct {
		in   string
		want Intersection
		ok   bool
	}{
		{"Cnr Bourke St & Swanston St Melbourne", Intersection{A: CrossStreet{"BOURKE", "STREET"}, B: CrossStreet{"SWANSTON", "STREET"}, Locality: "MELBOURNE"}, true},
		{"Corner of Flinders and Elizabeth Streets Melbourne", Intersection{A: CrossStreet{"FLINDERS", "STREET"}, B: CrossStreet{"ELIZABETH", "STREET"}, Locality: "MELBOURNE"}, true},
		{"Bourke St and Swanston St, Melbourne VIC 3000", Intersection{A: CrossStreet{"BOURKE", "STREET"}, B: CrossStreet{"SWANSTON", "STREET"}, Locality: "MELBOURNE", State: "VIC", Postcode: "3000"}, true},
		{"cnr Smith St/Johnston St Fitzroy", Intersection{A: CrossStreet{"SMITH", "STREET"}, B: CrossStreet{"JOHNSTON", "STREET"}, Locality: "FITZROY"}, true},
		{"The corner of Swan St and Church St Richmond", Intersection{A: CrossStreet{"SWAN", "STREET"}, B: CrossStreet{"CHURCH", "STREET"}, Locality: "RICHMOND"}, true},
		{"cnr Flinders & Elizabeth St Melbourne", Intersection{A: CrossStreet{"FLINDERS", ""}, B: CrossStreet{"ELIZABETH", "STREET"}, Locality: "MELBOURNE"}, true},
		{"cnr bourke st & swanston st", Intersection{A: CrossStreet{"BOURKE", "STREET"}, B: CrossStreet{"SWANSTON", "STREET"}}, true},
		// The geocoder's tokens: "&" and the slash already read as AND.
		{"cnr smith street and johnston st fitzroy", Intersection{A: CrossStreet{"SMITH", "STREET"}, B: CrossStreet{"JOHNSTON", "STREET"}, Locality: "FITZROY"}, true},
		// Not intersections.
		{"36 Collins St Melbourne", Intersection{}, false},
		{"Bourke and Swanston Melbourne", Intersection{}, false}, // no corner word, no types
		{"doncaster and blackburn road", Intersection{}, false},
		{"cnr Bourke and Swanston", Intersection{}, false}, // nothing to place either street by
		{"1 Bourke St and 2 Swanston St Melbourne", Intersection{}, false},
		{"Cnr Bourke St & 12 Swanston St Melbourne", Intersection{}, false},
	}
	for _, c := range cases {
		got, ok := ParseIntersection(c.in, 32, testLocalities, nearest)
		if ok != c.ok || ok && !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseIntersection(%q) = %+v, %v; want %+v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
	// Shapes the parser accepts but whose first "street" holds other words:
	// the resolver finds no such street and declines.
	for _, in := range []string{"woolworths near doncaster and blackburn roads", "coles corner of bourke and swanston streets melbourne"} {
		if got, ok := ParseIntersection(in, 32, testLocalities, nearest); ok && (got.A.Name == "DONCASTER" || got.A.Name == "BOURKE") {
			t.Errorf("ParseIntersection(%q) = %+v: the leading words were dropped", in, got)
		}
	}
}

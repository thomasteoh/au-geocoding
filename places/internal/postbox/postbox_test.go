package postbox

import "testing"

func TestTable(t *testing.T) {
	if len(All()) == 0 {
		t.Fatal("empty table")
	}
	e, ok := Lookup("3001")
	if !ok || e.Locality != "MELBOURNE" || e.SourceURL == "" {
		t.Errorf("3001 = %+v, %v", e, ok)
	}
	if _, ok := Lookup("3000"); ok {
		t.Error("3000 is a delivery postcode, not in the table")
	}
}

func TestParseRejects(t *testing.T) {
	for _, s := range []string{
		"3001\tMELBOURNE\tVIC\tPost Office Boxes\tGPO Boxes\t\t2026-11-18",                                   // no source
		"3001\tMelbourne\tVIC\tPost Office Boxes\tGPO Boxes\thttps://x.example\t2026-11-18",                  // case
		"301\tMELBOURNE\tVIC\tPost Office Boxes\tGPO Boxes\thttps://x.example\t2026-11-18",                   // postcode
		"3001\tMELBOURNE\tVIC\tPost Office Boxes\tGPO Boxes\thttps://x.example",                              // columns
		"3001\tMELBOURNE\tVIC\ta\tb\thttps://x.example\td\n3001\tMELBOURNE\tVIC\ta\tb\thttps://x.example\td", // dup
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
}

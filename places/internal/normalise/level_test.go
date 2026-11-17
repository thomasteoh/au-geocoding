package normalise

import "testing"

func TestParseLevel(t *testing.T) {
	cases := []struct{ in, level, unit, number string }{
		{"Level 2, 12 Collins St Melbourne", "2", "", "12"},
		{"L2 12 Collins St", "2", "", "12"},
		{"LVL 14 12 Collins St", "14", "", "12"},
		{"Floor 3 12 Collins St", "3", "", "12"},
		{"FL3 12 Collins St", "3", "", "12"},
		{"2nd Floor 12 Collins St", "2", "", "12"},
		{"Suite 5 Level 3 12 Collins St", "3", "5", "12"},
		// The geocoder's canonical form.
		{"level 2 12 collins street", "2", "", "12"},
		{"12 Collins St", "", "", "12"},
	}
	for _, c := range cases {
		p := Parse(c.in, 32, map[string]bool{"MELBOURNE": true}, nil)
		if p.Level != c.level || p.Unit != c.unit || p.Number != c.number {
			t.Errorf("Parse(%q) = level %q unit %q number %q; want %q %q %q", c.in, p.Level, p.Unit, p.Number, c.level, c.unit, c.number)
		}
		_, score, fields := p.Tokens()
		found := ""
		for i, f := range fields {
			if f == "level_number" {
				found = score[i]
			}
		}
		if found != c.level {
			t.Errorf("Parse(%q).Tokens level_number = %q, want %q", c.in, found, c.level)
		}
	}
}

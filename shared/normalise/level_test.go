package normalise

import (
	"reflect"
	"testing"
)

func TestNormaliseLevel(t *testing.T) {
	cases := []struct {
		in, level, unit string
		tokens          []string
	}{
		{"Level 2, 12 Collins St", "2", "", []string{"level", "2", "12", "collins", "street"}},
		{"L2 12 Collins St", "2", "", []string{"level", "2", "12", "collins", "street"}},
		{"Lvl 14 12 Collins St", "14", "", []string{"level", "14", "12", "collins", "street"}},
		{"Floor 3 12 Collins St", "3", "", []string{"level", "3", "12", "collins", "street"}},
		{"2nd Floor, 12 Collins St", "2", "", []string{"level", "2", "12", "collins", "street"}},
		{"1st Level 12 Collins St", "1", "", []string{"level", "1", "12", "collins", "street"}},
		{"Suite 5, Level 3, 12 Collins St", "3", "5", []string{"unit", "5", "level", "3", "12", "collins", "street"}},
		// No level: unchanged.
		{"12 Collins St", "", "", []string{"12", "collins", "street"}},
		// An ordinal not followed by a level word is not a level.
		{"1st Ave Sunshine", "", "", []string{"1st", "avenue", "sunshine"}},
	}
	for _, c := range cases {
		r := Normalise(c.in)
		if r.Level != c.level || r.Unit != c.unit || !reflect.DeepEqual(r.Tokens, c.tokens) {
			t.Errorf("Normalise(%q) = level %q unit %q tokens %v; want %q %q %v",
				c.in, r.Level, r.Unit, r.Tokens, c.level, c.unit, c.tokens)
		}
		for _, g := range r.Generate {
			if g == "level" {
				t.Errorf("Normalise(%q): level word in Generate %v", c.in, r.Generate)
			}
		}
	}
}

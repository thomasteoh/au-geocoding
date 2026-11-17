package postal

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		toks []string
		want string
		n    int
	}{
		{[]string{"PO", "BOX", "123", "MELBOURNE"}, "PO BOX 123", 3},
		{[]string{"po", "box", "12a"}, "PO BOX 12A", 3},
		{[]string{"P", "O", "BOX", "7"}, "PO BOX 7", 4},
		{[]string{"P", "/", "O", "BOX", "7"}, "PO BOX 7", 5},
		{[]string{"PO", "BOX123", "KILMORE"}, "PO BOX 123", 2},
		{[]string{"POBOX", "9"}, "PO BOX 9", 2},
		{[]string{"POST", "OFFICE", "BOX", "1"}, "PO BOX 1", 4},
		{[]string{"GPO", "BOX", "1234"}, "GPO BOX 1234", 3},
		{[]string{"G", "P", "O", "BOX", "4"}, "GPO BOX 4", 5},
		{[]string{"LOCKED", "BAG", "10"}, "LOCKED BAG 10", 3},
		{[]string{"LOCKED", "MAIL", "BAG", "3"}, "LOCKED BAG 3", 4},
		{[]string{"LMB", "3"}, "LOCKED BAG 3", 2},
		{[]string{"PRIVATE", "BAG", "1"}, "PRIVATE BAG 1", 3},
		{[]string{"PMB", "2"}, "PRIVATE BAG 2", 2},
		{[]string{"PO", "BOX", "MELBOURNE"}, "PO BOX", 2},
		{[]string{"BOX", "HILL"}, "", 0},
		{[]string{"12", "PO", "BOX"}, "", 0},
		{[]string{"PRIVATE", "ROAD"}, "", 0},
		{nil, "", 0},
	}
	for _, c := range cases {
		got, n := Parse(c.toks)
		if got != c.want || n != c.n {
			t.Errorf("Parse(%v) = %q, %d; want %q, %d", c.toks, got, n, c.want, c.n)
		}
	}
}

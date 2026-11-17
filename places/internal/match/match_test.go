package match

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/normalise"
	"auplaces/internal/schema"
)

// longStreetDB holds 300 numbers on HIGH STREET, PRESTON plus a HIGH STREET in
// another locality, so a capped generation that ignores the street number
// would miss most of them.
func longStreetDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(schema.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	add := func(pid, num, street, typ, loc, pc string) {
		if _, err := db.Exec(`INSERT INTO address (gnaf_pid, street_number, street_name, street_type,
			locality_name, state, postcode, latitude, longitude, confidence, geocode_rel)
			VALUES (?, ?, ?, ?, ?, 'VIC', ?, -37.7, 145.0, 2, 6)`, pid, num, street, typ, loc, pc); err != nil {
			t.Fatal(err)
		}
	}
	for n := 1; n <= 300; n++ {
		add(fmt.Sprintf("PRESTON-%d", n), fmt.Sprint(n), "HIGH", "STREET", "PRESTON", "3072")
	}
	add("KEW-25", "25", "HIGH", "STREET", "KEW", "3101")
	add("STK-3", "3", "ST KILDA", "ROAD", "ST KILDA", "3182")
	add("MEL-3", "3", "ST KILDA", "ROAD", "MELBOURNE", "3004")
	if _, err := db.Exec(`INSERT INTO addr_trgm (gnaf_pid, street_number, street_name, locality_name, state, postcode)
		SELECT gnaf_pid, street_number, street_name, locality_name, state, postcode FROM address`); err != nil {
		t.Fatal(err)
	}
	return db
}

func best(t *testing.T, db *sql.DB, text string, cap int) string {
	t.Helper()
	locs := map[string]bool{"PRESTON": true, "KEW": true, "ST KILDA": true, "MELBOURNE": true}
	rel, score, fields := normalise.Tokenise(text, 32, locs, nil)
	q := Query{Reliable: rel, Score: score, Fields: fields}
	cands, err := Generate(context.Background(), db, q, nil, cap)
	if err != nil {
		t.Fatal(err)
	}
	pid, top := "", -1.0
	for _, c := range cands {
		if s := Score(q, c); s > top {
			pid, top = c.PID, s
		}
	}
	return pid
}

func TestGenerateKeepsShortNumberOnLongStreet(t *testing.T) {
	db := longStreetDB(t)
	// The cap is far below the street's 300 rows; the asked-for number must
	// still be generated.
	for _, c := range []struct{ q, want string }{
		{"25 High St Preston", "PRESTON-25"},
		{"7 High St Preston", "PRESTON-7"},
		{"250 High St Preston", "PRESTON-250"},
		{"25 High St Kew", "KEW-25"},
	} {
		if got := best(t, db, c.q, 20); got != c.want {
			t.Errorf("%q: got %q, want %q", c.q, got, c.want)
		}
	}
}

func TestScoreWeighsLocality(t *testing.T) {
	db := longStreetDB(t)
	if got := best(t, db, "3 St Kilda Rd St Kilda", 20); got != "STK-3" {
		t.Errorf("got %q, want STK-3", got)
	}
	if got := best(t, db, "3 St Kilda Rd Melbourne", 20); got != "MEL-3" {
		t.Errorf("got %q, want MEL-3", got)
	}
}

func TestLevenshteinSimTransposition(t *testing.T) {
	if got := levenshteinSim("WINSDOR", "WINDSOR"); got < 0.85 {
		t.Errorf("transposition similarity = %.2f, want one edit (>= 0.85)", got)
	}
}

// unitsDB holds a building at 10 SMITH STREET with 60 units listed before its
// base row, unit 5 at the next number, and lot 5 on SMITH STREET, which has no
// street number.
func unitsDB(t *testing.T) *sql.DB {
	t.Helper()
	db := longStreetDB(t)
	add := func(pid, num, flat, lot, sec string) {
		if _, err := db.Exec(`INSERT INTO address (gnaf_pid, street_number, flat_number, lot_number, primary_sec,
			street_name, street_type, locality_name, state, postcode, latitude, longitude, confidence, geocode_rel)
			VALUES (?, ?, ?, ?, ?, 'SMITH', 'STREET', 'PRESTON', 'VIC', '3072', -37.7, 145.0, 2, 6)`,
			pid, num, flat, lot, sec); err != nil {
			t.Fatal(err)
		}
	}
	for u := 1; u <= 60; u++ {
		add(fmt.Sprintf("U%d-10", u), "10", fmt.Sprint(u), "", "S")
	}
	add("BASE-10", "10", "", "", "P")
	add("U5-12", "12", "5", "", "S")
	add("LOT-5", "", "", "5", "P")
	add("NUM-5", "5", "", "", "P")
	if _, err := db.Exec(`DELETE FROM addr_trgm`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO addr_trgm (gnaf_pid, street_number, street_name, locality_name, state, postcode)
		SELECT gnaf_pid, street_number, street_name, locality_name, state, postcode FROM address`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestUnitsAndLots(t *testing.T) {
	db := unitsDB(t)
	for _, c := range []struct{ q, want string }{
		{"10 Smith St Preston", "BASE-10"},      // no unit: the base address
		{"45/10 Smith St Preston", "U45-10"},    // the asked-for unit, past the cap
		{"Unit 5 10 Smith St Preston", "U5-10"}, // not unit 5 at number 12
		{"99/10 Smith St Preston", "BASE-10"},   // no such unit: still number 10
		{"Lot 5 Smith St Preston", "LOT-5"},     // not number 5
		{"5 Smith St Preston", "NUM-5"},         // not lot 5
	} {
		if got := best(t, db, c.q, 20); got != c.want {
			t.Errorf("%q: got %q, want %q", c.q, got, c.want)
		}
	}
}

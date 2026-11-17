package match

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"testing"

	"auplaces/internal/schema"
)

// gridDB lays out, in TOWN, an east-west MAIN STREET (lat -37.80) crossed by
// a north-south HIGH STREET (lon 145.00), and a PARK STREET parallel to MAIN
// 150 m south. Addresses sit 20 m back from each street, both sides. A corner
// building on MAIN and HIGH carries one address on each.
func gridDB(t *testing.T) *sql.DB {
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
	const mLat, mLon = 1 / 110540.0, 1 / 88000.0 // degrees per metre near -37.8
	n := 0
	add := func(street string, lat, lon float64) {
		n++
		if _, err := db.Exec(`INSERT INTO address (gnaf_pid, street_number, street_name, street_type,
			locality_name, state, postcode, latitude, longitude, confidence, geocode_rel)
			VALUES (?, ?, ?, 'STREET', 'TOWN', 'VIC', '3999', ?, ?, 2, 6)`,
			fmt.Sprint("P", n), fmt.Sprint(n), street, lat, lon); err != nil {
			t.Fatal(err)
		}
	}
	for m := -400.0; m <= 400; m += 25 {
		if math.Abs(m) < 30 {
			continue // the crossing itself
		}
		add("MAIN", -37.80+20*mLat, 145.00+m*mLon)
		add("MAIN", -37.80-20*mLat, 145.00+m*mLon)
		add("HIGH", -37.80+m*mLat, 145.00+20*mLon)
		add("HIGH", -37.80+m*mLat, 145.00-20*mLon)
		add("PARK", -37.80-150*mLat+20*mLat, 145.00+m*mLon)
	}
	add("MAIN", -37.80+25*mLat, 145.00+25*mLon) // the corner building
	add("HIGH", -37.80+25*mLat, 145.00+25*mLon)
	return db
}

func TestStreetsMeet(t *testing.T) {
	db := gridDB(t)
	ctx := context.Background()
	m, err := StreetsMeet(ctx, NewStreetCache(db), StreetRef{"MAIN", "STREET"}, StreetRef{"HIGH", ""}, "TOWN")
	if err != nil || m == nil {
		t.Fatalf("MAIN x HIGH: %+v, %v", m, err)
	}
	if d := HaversineM(m.Lat, m.Lon, -37.80, 145.00); d > 10 {
		t.Errorf("MAIN x HIGH at %.6f,%.6f, %.0f m from the crossing", m.Lat, m.Lon, d)
	}
	if m.TypeB != "STREET" || m.Postcode != "3999" {
		t.Errorf("MAIN x HIGH: %+v", m)
	}
	for _, c := range []struct {
		a, b StreetRef
		loc  string
	}{
		{StreetRef{"MAIN", ""}, StreetRef{"PARK", ""}, "TOWN"},     // parallel
		{StreetRef{"MAIN", ""}, StreetRef{"HIGH", "ROAD"}, "TOWN"}, // no HIGH ROAD
		{StreetRef{"MAIN", ""}, StreetRef{"HIGH", ""}, "ELSEWHERE"},
		{StreetRef{"MAIN", ""}, StreetRef{"MAIN", ""}, "TOWN"},
	} {
		if m, err := StreetsMeet(ctx, NewStreetCache(db), c.a, c.b, c.loc); err != nil || m != nil {
			t.Errorf("%v x %v in %s: %+v, %v; want nil", c.a, c.b, c.loc, m, err)
		}
	}
}

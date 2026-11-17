package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/assertion"
	"auplaces/internal/match"
	"auplaces/internal/schema"
)

const pid = "GAVIC000000001"

func servingDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{schema.SchemaSQL, schema.POISchemaSQL,
		`CREATE VIRTUAL TABLE addr_rt USING rtree(id, min_lat, max_lat, min_lon, max_lon)`,
		`INSERT INTO address (gnaf_pid, street_number, street_name, street_type, locality_name, state, postcode, latitude, longitude, confidence, geocode_rel)
			VALUES ('` + pid + `', '36', 'COLLINS', 'STREET', 'MELBOURNE', 'VIC', '3000', -37.81, 144.97, 2, 6)`,
		`INSERT INTO addr_rt SELECT rowid, latitude, latitude, longitude, longitude FROM address`,
		`INSERT INTO addr_trgm SELECT gnaf_pid, street_number, street_name, locality_name, state, postcode FROM address`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// A coordinate correction must move the address in addr_rt too, or reverse
// geocoding keeps answering from the old point.
func TestCoordinateCorrectionMovesReverseIndex(t *testing.T) {
	db := servingDB(t)
	st, err := apply(db, []assertion.CanonicalRow{
		{Subject: pid, Predicate: "latitude", Object: "-37.70"},
		{Subject: pid, Predicate: "longitude", Object: "145.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.moved != 1 {
		t.Errorf("moved = %d, want 1", st.moved)
	}
	ctx := context.Background()
	near, err := match.ReverseWithin(ctx, db, 145.10, -37.70, 1, 100)
	if err != nil || len(near) != 1 || near[0].PID != pid {
		t.Errorf("reverse at the corrected point: %v, %v", near, err)
	}
	old, err := match.ReverseWithin(ctx, db, 144.97, -37.81, 1, 100)
	if err != nil || len(old) != 0 {
		t.Errorf("reverse at the old point still finds %v (%v)", old, err)
	}
}

// A failed overlay changes nothing, indexes included.
func TestFailedOverlayLeavesDatasetUnchanged(t *testing.T) {
	db := servingDB(t)
	_, err := apply(db, []assertion.CanonicalRow{
		{Subject: pid, Predicate: "street_name", Object: "BOURKE"},
		{Subject: "GAVIC999999999", Predicate: "street_name", Object: "X"},
	})
	if err == nil {
		t.Fatal("want error for a correction to a missing PID")
	}
	var name string
	var n int
	if err := db.QueryRow(`SELECT street_name FROM address`).Scan(&name); err != nil || name != "COLLINS" {
		t.Errorf("street_name = %q, %v", name, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM addr_trgm WHERE addr_trgm MATCH 'COLLINS'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("addr_trgm lost its row: %d, %v", n, err)
	}
}

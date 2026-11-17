package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

func smokeDB(t *testing.T, withRT bool) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	stmts := []string{schema.SchemaSQL,
		`CREATE VIRTUAL TABLE addr_rt USING rtree(id, min_lat, max_lat, min_lon, max_lon)`,
		`INSERT INTO address (gnaf_pid, street_number, street_name, street_type, locality_name, state, postcode, latitude, longitude, confidence, geocode_rel) VALUES
			('GAVIC1', '36', 'COLLINS', 'STREET', 'MELBOURNE', 'VIC', '3000', -37.8146, 144.9719, 2, 6),
			('GAVIC2', '38', 'COLLINS', 'STREET', 'MELBOURNE', 'VIC', '3000', -37.8147, 144.9716, 2, 6),
			('GAVIC3', '634', 'BRIDGE', 'ROAD', 'RICHMOND', 'VIC', '3121', -37.8187, 145.0079, 2, 6),
			('GAVIC4', '223', 'MALOP', 'STREET', 'GEELONG', 'VIC', '3220', -38.1471, 144.3570, 2, 6)`,
		`INSERT INTO addr_trgm SELECT gnaf_pid, street_number, street_name, locality_name, state, postcode FROM address`,
	}
	if withRT {
		stmts = append(stmts, `INSERT INTO addr_rt SELECT rowid, latitude, latitude, longitude, longitude FROM address`)
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestSmokeGoesThroughResolverAndReverse(t *testing.T) {
	db := smokeDB(t, true)
	for _, s := range smokeSet {
		if got, err := smokeResolve(db, s.query, s.want); err != nil {
			t.Errorf("%s: got %s, %v", s.query, got, err)
		}
	}
}

func TestSmokeCatchesEmptyReverseIndex(t *testing.T) {
	db := smokeDB(t, false)
	_, err := smokeResolve(db, smokeSet[0].query, smokeSet[0].want)
	if err == nil || !strings.Contains(err.Error(), "reverse") {
		t.Errorf("empty addr_rt passed the smoke: %v", err)
	}
}

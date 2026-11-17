package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

// gnafDB is a one-address G-NAF extract: enough for ADDRESS_VIEW to yield a row.
func gnafDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{schema.RealSchemaSQL, schema.RealViewSQL,
		`INSERT INTO STATE VALUES ('S2', '2020-01-01', NULL, 'VICTORIA', 'VIC')`,
		`INSERT INTO LOCALITY VALUES ('L1', '2020-01-01', NULL, 'MELBOURNE', '3000', 'G', 'S2', NULL, 1)`,
		`INSERT INTO STREET_LOCALITY VALUES ('SL1', '2020-01-01', NULL, 'C', 'COLLINS', 'STREET', NULL, 'L1', NULL, NULL, 1)`,
		`INSERT INTO ADDRESS_DETAIL (address_detail_pid, date_created, date_last_modified, number_first, street_locality_pid,
			locality_pid, postcode, confidence, address_site_pid, level_geocoded_code)
			VALUES ('GAVIC1', '2019-02-01', '2026-08-04', 36, 'SL1', 'L1', '3000', 2, 'S1', 7)`,
		`INSERT INTO ADDRESS_DEFAULT_GEOCODE VALUES ('G1', '2019-02-01', NULL, 'GAVIC1', 'PC', 144.97, -37.81)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestBuildStampsVersionAndIndexes(t *testing.T) {
	db := gnafDB(t)
	v, err := releaseVersion(db)
	if err != nil || v != "gnaf-2026-08" {
		t.Fatalf("releaseVersion = %q, %v; want gnaf-2026-08", v, err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	build(tx, "test-v1")
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var got string
	var rt int
	if err := db.QueryRow(`SELECT dataset_version FROM address`).Scan(&got); err != nil || got != "test-v1" {
		t.Errorf("dataset_version = %q, %v", got, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM addr_rt`).Scan(&rt); err != nil || rt != 1 {
		t.Errorf("addr_rt rows = %d, %v", rt, err)
	}
}

// An interrupted rebuild must leave the previous tables, not an empty DB.
func TestUncommittedBuildLeavesPreviousTables(t *testing.T) {
	db := gnafDB(t)
	tx, _ := db.Begin()
	build(tx, "old")
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, _ = db.Begin()
	build(tx, "new")
	if err := tx.Rollback(); err != nil { // stands in for a crash before commit
		t.Fatal(err)
	}
	var got string
	if err := db.QueryRow(`SELECT dataset_version FROM address`).Scan(&got); err != nil || got != "old" {
		t.Errorf("after rollback: version %q, %v; want old", got, err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM addr_trgm`).Scan(&n); err != nil || n != 1 {
		t.Errorf("addr_trgm rows %d, %v", n, err)
	}
}

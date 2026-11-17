package main

import (
	"testing"

	"auplaces/internal/schema"
)

// buildaddr carries the level, and derives the serving alias tables keeping
// only live, unambiguous aliases that are not official names.
func TestBuildLevelsAndAliases(t *testing.T) {
	db := gnafDB(t)
	for _, s := range []string{schema.AliasRawSchemaSQL,
		`INSERT INTO LEVEL_TYPE_AUT VALUES ('L', 'LEVEL', 'LEVEL'), ('B', 'BASEMENT', 'BASEMENT')`,
		`INSERT INTO LOCALITY VALUES ('L2', '2020-01-01', NULL, 'EAST MELBOURNE', '3002', 'G', 'S2', NULL, 1)`,
		`INSERT INTO STREET_LOCALITY VALUES ('SL2', '2020-01-01', NULL, 'C', 'WELLINGTON', 'PARADE', NULL, 'L2', NULL, NULL, 1)`,
		`INSERT INTO ADDRESS_DETAIL (address_detail_pid, date_created, number_first, level_type_code, level_number, street_locality_pid,
			locality_pid, postcode, confidence, address_site_pid, level_geocoded_code)
			VALUES ('GAVIC2', '2019-02-01', 36, 'L', 2.0, 'SL1', 'L1', '3000', 2, 'S2', 7),
			       ('GAVIC3', '2019-02-01', 36, 'B', 1.0, 'SL1', 'L1', '3000', 2, 'S3', 7),
			       ('GAVIC4', '2019-02-01', 211, NULL, NULL, 'SL2', 'L2', '3002', 2, 'S4', 7)`,
		`INSERT INTO ADDRESS_DEFAULT_GEOCODE VALUES ('G2', '2019-02-01', NULL, 'GAVIC2', 'PC', 144.97, -37.81),
			('G3', '2019-02-01', NULL, 'GAVIC3', 'PC', 144.97, -37.81), ('G4', '2019-02-01', NULL, 'GAVIC4', 'PC', 144.98, -37.81)`,
		`INSERT INTO LOCALITY_ALIAS VALUES
			('1', '2020-01-01', '', 'L2', 'JOLIMONT', '', 'SYN', 'S2'),
			('2', '2020-01-01', '2021-01-01', 'L2', 'RETIRED NAME', '', 'SYN', 'S2'),
			('3', '2020-01-01', '', 'L2', 'MELBOURNE', '', 'SYN', 'S2'),
			('4', '2020-01-01', '', 'L1', 'TWO PLACES', '', 'SYN', 'S2'),
			('5', '2020-01-01', '', 'L2', 'TWO PLACES', '', 'SYN', 'S2')`,
		`INSERT INTO STREET_LOCALITY_ALIAS VALUES
			('A1', '2020-01-01', '', 'SL1', 'O''COLLINS', 'STREET', NULL, 'SYN'),
			('A2', '2020-01-01', '', 'SL1', 'COLLINS', 'LANE', NULL, 'SYN')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	build(tx, "v")
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	levels := map[string]string{}
	rows, err := db.Query(`SELECT gnaf_pid, level_number || '/' || level_type FROM address`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var pid, l string
		rows.Scan(&pid, &l)
		levels[pid] = l
	}
	rows.Close()
	if levels["GAVIC1"] != "/" || levels["GAVIC2"] != "2/LEVEL" || levels["GAVIC3"] != "/BASEMENT" {
		t.Errorf("levels %v; want none, 2/LEVEL, and a basement with no level number", levels)
	}

	var got []string
	rows, _ = db.Query(`SELECT alias || '>' || locality_name FROM alias_locality ORDER BY alias`)
	for rows.Next() {
		var s string
		rows.Scan(&s)
		got = append(got, s)
	}
	rows.Close()
	if len(got) != 1 || got[0] != "JOLIMONT>EAST MELBOURNE" {
		t.Errorf("alias_locality = %v; want only JOLIMONT>EAST MELBOURNE", got)
	}
	got = nil
	rows, _ = db.Query(`SELECT alias_name || '|' || alias_type || '>' || street_name FROM alias_street ORDER BY 1`)
	for rows.Next() {
		var s string
		rows.Scan(&s)
		got = append(got, s)
	}
	rows.Close()
	// COLLINS LANE is dropped: COLLINS is a real street in MELBOURNE.
	want := []string{"O COLLINS|STREET>COLLINS", "O'COLLINS|STREET>COLLINS", "OCOLLINS|STREET>COLLINS"}
	if len(got) != len(want) {
		t.Fatalf("alias_street = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("alias_street = %v; want %v", got, want)
		}
	}
}

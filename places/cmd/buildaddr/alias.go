package main

import (
	"database/sql"
	"fmt"
	"log"

	"auplaces/internal/schema"
)

// buildAliases derives the serving alias tables (schema.AliasSchemaSQL) from
// G-NAF's LOCALITY_ALIAS and STREET_LOCALITY_ALIAS, inside the caller's
// transaction, after address exists. A dataset loaded without the raw alias
// tables gets empty serving tables.
//
// Kept: live aliases (DATE_RETIRED empty) whose name is not an official name
// in the same scope (a real locality, or a real street in that locality),
// pointing at exactly one official name that has addresses. G-NAF's locality
// "synonyms" are mostly neighbouring places (MORELAND is listed against
// COBURG's neighbours); one that is a locality in its own right must keep
// answering as itself, and one listed against several localities (ROSEBUD
// WEST: ROSEBUD, BONEO, CAPEL SOUND) says nothing about which is meant.
//
// A street alias spelt with an apostrophe (O'CONNELL) is also kept without it,
// joined and split (OCONNELL, O CONNELL), since the normalisers strip it;
// a form equal to the official name drops out.
func buildAliases(db *sql.Tx) {
	for _, s := range []string{schema.DropAliasSchemaSQL, schema.AliasSchemaSQL} {
		if _, err := db.Exec(s); err != nil {
			log.Fatalf("alias schema: %v", err)
		}
	}
	if !tableExists(db, "LOCALITY_ALIAS") || !tableExists(db, "STREET_LOCALITY_ALIAS") {
		fmt.Println("no G-NAF alias tables (loadreal -aliases-only loads them): alias tables left empty")
		return
	}
	if _, err := db.Exec(`
		INSERT INTO alias_locality (alias, locality_name, state)
		SELECT alias, MIN(locality_name), MIN(state) FROM (
			SELECT DISTINCT UPPER(TRIM(la.name)) AS alias, l.locality_name, s.state_abbreviation AS state
			FROM LOCALITY_ALIAS la
			JOIN LOCALITY l ON l.locality_pid = la.locality_pid
			JOIN STATE s ON s.state_pid = l.state_pid
			WHERE COALESCE(la.date_retired, '') = '' AND COALESCE(l.date_retired, '') = ''
		)
		WHERE alias <> '' AND alias NOT IN (SELECT locality_name FROM address)
			AND locality_name IN (SELECT locality_name FROM address)
		GROUP BY alias HAVING COUNT(DISTINCT locality_name || '|' || state) = 1`); err != nil {
		log.Fatalf("alias_locality: %v", err)
	}
	if _, err := db.Exec(`
		WITH a AS (
			SELECT UPPER(TRIM(sla.street_name)) AS raw, COALESCE(sla.street_type_code, '') AS alias_type,
				l.locality_name, sl.street_name, COALESCE(sl.street_type_code, '') AS street_type
			FROM STREET_LOCALITY_ALIAS sla
			JOIN STREET_LOCALITY sl ON sl.street_locality_pid = sla.street_locality_pid
			JOIN LOCALITY l ON l.locality_pid = sl.locality_pid
			WHERE COALESCE(sla.date_retired, '') = '' AND COALESCE(sl.date_retired, '') = ''
		), f AS (
			SELECT raw AS alias_name, alias_type, locality_name, street_name, street_type FROM a
			UNION
			SELECT REPLACE(raw, '''', ''), alias_type, locality_name, street_name, street_type FROM a
			UNION
			SELECT TRIM(REPLACE(raw, '''', ' ')), alias_type, locality_name, street_name, street_type FROM a
		)
		INSERT INTO alias_street (alias_name, alias_type, locality_name, street_name, street_type)
		SELECT alias_name, alias_type, locality_name, MIN(street_name), MIN(street_type) FROM f
		WHERE alias_name <> '' AND alias_name <> street_name
			AND NOT EXISTS (SELECT 1 FROM address x WHERE x.street_name = f.alias_name AND x.locality_name = f.locality_name)
			AND EXISTS (SELECT 1 FROM address x WHERE x.street_name = f.street_name AND x.locality_name = f.locality_name)
		GROUP BY alias_name, alias_type, locality_name
		HAVING COUNT(DISTINCT street_name || '|' || street_type) = 1`); err != nil {
		log.Fatalf("alias_street: %v", err)
	}
	var nl, ns int
	db.QueryRow(`SELECT count(*) FROM alias_locality`).Scan(&nl)
	db.QueryRow(`SELECT count(*) FROM alias_street`).Scan(&ns)
	fmt.Printf("aliases: %d locality, %d street\n", nl, ns)
}

func tableExists(db *sql.Tx, name string) bool {
	var n int
	db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
	return n > 0
}

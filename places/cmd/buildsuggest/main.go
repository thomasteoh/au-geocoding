// buildsuggest creates the autocomplete suggestion index (PR-7.1, PR-7.2).
//
// The index is over street+locality — NOT full addresses (S-13). A flat prefix
// over 4.18M addresses is both too slow and unusable ("STATION STREET" occurs
// in 139 Victorian localities); indexing the middle level collapses 36,337
// "HIG%" addresses to 385 distinct street+locality entries, ~141k rows in VIC
// and ~537k projected AU — 30x smaller. Every entry carries its own locality
// and postcode, so the suggestion self-disambiguates:
//
//	STATION STREET, BRIGHTON VIC 3186
//	STATION STREET, FAIRFIELD VIC 3078
//
// The index is built by the loader (INV-4), never derived at query time. It is
// an FTS5 table with the prefix option, so a prefix query "sta* AND bri*" is
// served by the index directly (the trigram index cannot prefix-match).
//
// PR-7.6: each row carries the resolvable handles (street_locality_pid,
// locality_pid) so selection is an exact lookup, never a re-parse.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "SQLite DB path")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Re-runs: drop any existing index.
	if _, err := db.Exec(`DROP TABLE IF EXISTS suggest_idx`); err != nil {
		log.Fatalf("drop suggest_idx: %v", err)
	}

	// FTS5 with prefix indexing. Columns carry the display fields plus the
	// resolvable handles (UNINDEXED: they are lookups, never match targets).
	// prefix='2 3 4' indexes 2-4 char prefixes so "sta*" matches STATION.
	if _, err := db.Exec(`
		CREATE VIRTUAL TABLE suggest_idx USING fts5(
			street_locality_pid UNINDEXED,
			locality_pid UNINDEXED,
			street_name,
			street_type,
			locality_name,
			postcode,
			state,
			tokenize='ascii',
			prefix='2 3 4'
		)`); err != nil {
		log.Fatalf("create suggest_idx: %v", err)
	}

	// Populate from STREET_LOCALITY JOIN LOCALITY (street+locality, not address).
	// Only non-retired, contentful entries. street_type_code is the real street
	// type (STREET/ROAD/AVENUE) — the same fix the rebuild made to address.
	// Postcode lives on ADDRESS_DETAIL (LOCALITY.primary_postcode is empty for
	// ~2,956/2,996 VIC localities), so it is derived per street+locality from
	// the address rows via a subquery. The result is the most-common postcode
	// for that street+locality (a street can span a couple of postcodes).
	if _, err := db.Exec(`
		INSERT INTO suggest_idx (street_locality_pid, locality_pid, street_name, street_type, locality_name, postcode, state)
		SELECT sl.street_locality_pid, l.locality_pid,
		       upper(sl.street_name),
		       upper(coalesce(sl.street_type_code, '')),
		       upper(l.locality_name),
		       coalesce((
		           SELECT ad.postcode
		           FROM ADDRESS_DETAIL ad
		           WHERE ad.street_locality_pid = sl.street_locality_pid
		             AND ad.postcode <> ''
		           GROUP BY ad.postcode
		           ORDER BY count(*) DESC
		           LIMIT 1
		       ), ''),
		       st.state_abbreviation
		FROM STREET_LOCALITY sl
		JOIN LOCALITY l ON l.locality_pid = sl.locality_pid
		JOIN STATE st ON st.state_pid = l.state_pid
		WHERE (sl.date_retired IS NULL OR sl.date_retired = '')
		  AND (l.date_retired IS NULL OR l.date_retired = '')
		  AND sl.street_name <> ''
		  AND l.locality_name <> ''
	`); err != nil {
		log.Fatalf("populate suggest_idx: %v", err)
	}

	var n int
	if err := db.QueryRow(`SELECT count(*) FROM suggest_idx`).Scan(&n); err != nil {
		log.Fatalf("count suggest_idx: %v", err)
	}
	fmt.Printf("suggest_idx rows: %d\n", n)
}

// buildaddr materialises the real matching table (address + addr_trgm) from
// ADDRESS_VIEW. This is the real-data swap for the matcher: the synthetic
// address table is replaced by the real flattened view, and the trigram index
// is built over the real data. After this, the matcher runs unchanged.
//
// The rebuild is one transaction: drop, materialise, index, addr_trgm and
// addr_rt either all land or none do. Run outside a transaction, a crash after
// the DROPs left a DB with no address table at all.
//
// address.dataset_version is the dataset's single version label: the server
// reports it at boot and on activation, and every response carries it. Set it
// with -version; by default it is derived from the G-NAF release.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "SQLite DB path; refused while a server has it open (build a staging copy, then activate it)")
	version := flag.String("version", "", "dataset version label stored in address.dataset_version (default: gnaf-YYYY-MM from the G-NAF release)")
	flag.Parse()

	db, release, err := schema.OpenWriter(*dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer release()
	defer db.Close()

	if *version == "" {
		v, err := releaseVersion(db)
		if err != nil {
			log.Fatalf("derive dataset version (pass -version): %v", err)
		}
		*version = v
	}
	fmt.Printf("dataset version: %s\n", *version)

	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("begin: %v", err)
	}
	// A log.Fatalf inside build exits without committing; SQLite rolls the
	// hot journal back on the next open, so the previous tables survive.
	build(tx, *version)
	if err := tx.Commit(); err != nil {
		log.Fatalf("commit: %v", err)
	}
	fmt.Println("committed")
}

// build replaces address, addr_trgm and addr_rt inside the caller's
// transaction. The parameter is named db so the statements read as before.
func build(db *sql.Tx, version string) {
	// Drop any existing synthetic address/addr_trgm (re-runs).
	for _, s := range []string{
		`DROP TABLE IF EXISTS addr_trgm`,
		`DROP TABLE IF EXISTS address`,
	} {
		if _, err := db.Exec(s); err != nil {
			log.Fatalf("drop: %v", err)
		}
	}

	// Materialise address from ADDRESS_VIEW (real flattened view).
	// Column mapping: ADDRESS_VIEW columns -> synthetic address columns.
	if _, err := db.Exec(`
		CREATE TABLE address AS
		SELECT
			ADDRESS_DETAIL_PID AS gnaf_pid,
			COALESCE(CAST(NUMBER_FIRST AS INTEGER), '') AS street_number,
			STREET_NAME AS street_name,
			-- STREET_TYPE_CODE is the street type (STREET, ROAD, AVENUE).
			-- STREET_CLASS_TYPE is a CONFIRMED/UNCONFIRMED status flag and was
			-- previously mapped here by mistake, which put "CONFIRMED" into
			-- every formatted address and left the street_type scoring field
			-- comparing query tokens against a constant.
			STREET_TYPE_CODE AS street_type,
			LOCALITY_NAME AS locality_name,
			STATE_ABBREVIATION AS state,
			POSTCODE AS postcode,
			LATITUDE AS latitude,
			LONGITUDE AS longitude,
			COALESCE(CAST(CONFIDENCE AS INTEGER), 0) AS confidence,
			-- Coordinate precision, ordinal, HIGHER IS BETTER to match the
			-- contract's documented direction (Candidate.GeocodeReliability).
			-- Note this is the opposite of G-NAF's own RELIABILITY_CODE, where
			-- 1 is best — carrying that raw would invert the ranking.
			-- Previously hardcoded 0, which left the term dead in the
			-- composite score.
			CASE GEOCODE_TYPE
				WHEN 'FRONTAGE CENTRE SETBACK'        THEN 6
				WHEN 'PROPERTY CENTROID MANUAL'       THEN 6
				WHEN 'BUILDING CENTROID MANUAL'       THEN 6
				WHEN 'PROPERTY ACCESS POINT SETBACK'  THEN 5
				WHEN 'STREET LOCALITY'                THEN 3
				WHEN 'GAP GEOCODE'                    THEN 2
				WHEN 'LOCALITY'                       THEN 1
				ELSE 0
			END AS geocode_rel,
			COALESCE(PRIMARY_SECONDARY, 'P') AS primary_sec,
			COALESCE(BUILDING_NAME, '') AS address_alias,
			'' AS mb_2026,
			'real-gnaf-2026' AS dataset_version
		FROM ADDRESS_VIEW
	`); err != nil {
		log.Fatalf("materialise address: %v", err)
	}
	// The SELECT above writes a placeholder label; stamp the real one. Done as
	// an UPDATE so the column list stays a plain mapping from ADDRESS_VIEW, and
	// before the indexes exist so it rewrites only the table.
	if _, err := db.Exec(`UPDATE address SET dataset_version = ?`, version); err != nil {
		log.Fatalf("stamp dataset version: %v", err)
	}
	fmt.Println("address materialised from ADDRESS_VIEW")

	// Indexes.
	for _, s := range []string{
		// Generation looks rows up by PID (gnaf_pid IN (trigram match)), and
		// CREATE TABLE AS carries no key: without this index every address
		// query scans all 4M rows.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_addr_pid ON address(gnaf_pid)`,
		`CREATE INDEX IF NOT EXISTS idx_addr_locality ON address(locality_name)`,
		`CREATE INDEX IF NOT EXISTS idx_addr_state     ON address(state)`,
		`CREATE INDEX IF NOT EXISTS idx_addr_postcode ON address(postcode)`,
		`CREATE INDEX IF NOT EXISTS idx_addr_street    ON address(street_name)`,
	} {
		if _, err := db.Exec(s); err != nil {
			log.Fatalf("index: %v", err)
		}
	}
	fmt.Println("indexes created")

	// Trigram index over the real address (contentful FTS5).
	if _, err := db.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS addr_trgm USING fts5(
			gnaf_pid UNINDEXED,
			street_number,
			street_name,
			locality_name,
			state,
			postcode,
			tokenize='trigram'
		)
	`); err != nil {
		log.Fatalf("trigram: %v", err)
	}
	// Populate the FTS index.
	if _, err := db.Exec(`
		INSERT INTO addr_trgm (gnaf_pid, street_number, street_name, locality_name, state, postcode)
		SELECT gnaf_pid, street_number, street_name, locality_name, state, postcode FROM address
	`); err != nil {
		log.Fatalf("populate trigram: %v", err)
	}
	fmt.Println("addr_trgm built over real address")

	// Reverse index: an RTree over address rowid -> point bbox. This is the
	// reverse-geocoding index (Step 3). Built at load time per processes.md
	// (never incrementally at serve time). The RTree id is the address.rowid;
	// the join back to address uses rowid.
	if _, err := db.Exec(`DROP TABLE IF EXISTS addr_rt`); err != nil {
		log.Fatalf("drop addr_rt: %v", err)
	}
	if _, err := db.Exec(`CREATE VIRTUAL TABLE addr_rt USING rtree(id, min_lat, max_lat, min_lon, max_lon)`); err != nil {
		log.Fatalf("addr_rt create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO addr_rt SELECT rowid, latitude, latitude, longitude, longitude FROM address`); err != nil {
		log.Fatalf("addr_rt populate: %v", err)
	}
	fmt.Println("addr_rt reverse index built")

	// Verify.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM address`).Scan(&n); err != nil {
		log.Fatalf("count address: %v", err)
	}
	fmt.Printf("address rows: %d\n", n)
	var rt int
	if err := db.QueryRow(`SELECT count(*) FROM addr_rt`).Scan(&rt); err != nil {
		log.Fatalf("count addr_rt: %v", err)
	}
	fmt.Printf("addr_rt rows: %d\n", rt)
}

// releaseVersion derives the default version label from the G-NAF release
// loaded into ADDRESS_DETAIL: a quarterly release carries edits up to shortly
// before publication, so the newest created/modified date names its month
// (the AUGUST 2026 release's newest edit is 2026-08-04, giving gnaf-2026-08).
func releaseVersion(db *sql.DB) (string, error) {
	var newest sql.NullString
	if err := db.QueryRow(`
		SELECT max(max(coalesce(date_last_modified, '')), max(coalesce(date_created, '')))
		FROM ADDRESS_DETAIL`).Scan(&newest); err != nil {
		return "", err
	}
	if len(newest.String) < 7 {
		return "", fmt.Errorf("ADDRESS_DETAIL has no dates")
	}
	return "gnaf-" + newest.String[:7], nil
}

// assertapply overlays enrichment from the assertion store onto a freshly
// materialised serving table — the P1 build integration (processes.md:421).
// It reads the derived canonical view and applies it as post-materialise
// corrections: address facts (subject = G-NAF PID) update the address table,
// POI facts (subject = OSM id) update the poi table. It runs at build time,
// offline, after flatten/project, and never touches a live swap (INV-4): the
// target is refused while a server holds it (schema.OpenWriter).
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "modernc.org/sqlite"

	"auplaces/internal/assertion"
	"auplaces/internal/schema"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "serving DB path (the one P1 materialised); refused while a server has it open")
	assertPath := flag.String("assert", "data/assertions.db", "assertion store path")
	flag.Parse()

	db, release, err := schema.OpenWriter(*dbPath)
	if err != nil {
		log.Fatalf("open serving db: %v", err)
	}
	defer release()
	defer db.Close()

	store, err := assertion.Open(*assertPath)
	if err != nil {
		log.Fatalf("open assertion store: %v", err)
	}
	defer store.Close()

	rows, err := store.CanonicalRows()
	if err != nil {
		log.Fatalf("canonical rows: %v", err)
	}

	st, err := apply(db, rows)
	if err != nil {
		log.Fatalf("apply (DB unchanged): %v", err)
	}
	fmt.Printf("address updated: %d\n", st.addrUpdated)
	fmt.Printf("poi updated: %d\n", st.poiUpdated)
	fmt.Printf("skipped (unknown predicate/subject): %d\n", st.skipped)
	fmt.Printf("addr_rt entries moved: %d\n", st.moved)
	fmt.Println("trigram indexes rebuilt after overlay")
}

type applyStats struct {
	addrUpdated, poiUpdated, skipped, moved int
}

// apply overlays the canonical rows and rebuilds the derived indexes in one
// transaction. The index rebuilds used to run after the commit, outside any
// transaction: a crash between DROP and the repopulate left a dataset with no
// addr_trgm. Now the overlay and its indexes land together or not at all.
//
// suggest_idx is not touched: it is built from STREET_LOCALITY and LOCALITY,
// which the overlay does not change, so a rebuild would reproduce it exactly.
func apply(db *sql.DB, rows []assertion.CanonicalRow) (applyStats, error) {
	var st applyStats
	tx, err := db.Begin()
	if err != nil {
		return st, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	// PIDs whose coordinates changed: addr_rt holds a copy of each address's
	// point, and reverse geocoding reads that copy, not address.
	moved := map[string]bool{}
	for _, c := range rows {
		// Address facts: subject is a G-NAF PID. Predicates map to columns.
		if isAddrSubject(c.Subject) {
			col, ok := addrPredicateColumn(c.Predicate)
			if !ok {
				st.skipped++
				continue
			}
			res, err := tx.Exec(fmt.Sprintf(`UPDATE address SET %s=? WHERE gnaf_pid=?`, col), c.Object, c.Subject)
			if err != nil {
				return st, fmt.Errorf("addr update: %w", err)
			}
			n, _ := res.RowsAffected()
			if n == 0 {
				return st, fmt.Errorf("address correction targets missing PID (strict): %s", c.Subject)
			}
			if col == "latitude" || col == "longitude" {
				moved[c.Subject] = true
			}
			st.addrUpdated++
			continue
		}
		// POI facts: subject is an OSM id (n123 / w456).
		if isPOISubject(c.Subject) {
			col, ok := poiPredicateColumn(c.Predicate)
			if !ok {
				st.skipped++
				continue
			}
			res, err := tx.Exec(fmt.Sprintf(`UPDATE poi SET %s=? WHERE osm_id=?`, col), c.Object, c.Subject)
			if err != nil {
				return st, fmt.Errorf("poi update: %w", err)
			}
			n, _ := res.RowsAffected()
			if n == 0 {
				return st, fmt.Errorf("poi correction targets missing osm id (strict): %s", c.Subject)
			}
			st.poiUpdated++
			continue
		}
		st.skipped++
	}

	// Rebuild the trigram indexes after overlay (R1.3 — never incrementally).
	// The address/poi tables changed, so the FTS indexes must be rebuilt to
	// stay consistent.
	for _, s := range []string{
		`DROP TABLE IF EXISTS addr_trgm`,
		`CREATE VIRTUAL TABLE addr_trgm USING fts5(
			gnaf_pid UNINDEXED, street_number, street_name, locality_name, state, postcode,
			tokenize='trigram')`,
		`INSERT INTO addr_trgm SELECT gnaf_pid, street_number, street_name, locality_name, state, postcode FROM address`,
		`DROP TABLE IF EXISTS poi_trgm`,
		`CREATE VIRTUAL TABLE poi_trgm USING fts5(
			osm_id UNINDEXED, name, brand, tokenize='trigram')`,
		`INSERT INTO poi_trgm SELECT osm_id, name, brand FROM poi`,
	} {
		if _, err := tx.Exec(s); err != nil {
			return st, fmt.Errorf("rebuild trigram: %w", err)
		}
	}

	// Re-point the moved addresses in addr_rt. Each entry is keyed by
	// address.rowid and holds exactly what buildaddr would write, so replacing
	// just these rows is the same as a full rebuild at a fraction of the cost.
	for pid := range moved {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO addr_rt
			SELECT rowid, latitude, latitude, longitude, longitude FROM address WHERE gnaf_pid=?`, pid); err != nil {
			return st, fmt.Errorf("addr_rt update %s: %w", pid, err)
		}
		st.moved++
	}

	if err := tx.Commit(); err != nil {
		return st, fmt.Errorf("commit: %w", err)
	}
	return st, nil
}

// isAddrSubject reports whether the subject is a G-NAF PID (address fact).
func isAddrSubject(s string) bool { return len(s) > 0 && s[0] >= 'A' && s[0] <= 'Z' && len(s) >= 12 }

// isPOISubject reports whether the subject is an OSM element id (n/w prefix).
func isPOISubject(s string) bool {
	if len(s) < 2 {
		return false
	}
	return s[0] == 'n' || s[0] == 'w'
}

// addrPredicateColumn maps a canonical predicate to an address column.
func addrPredicateColumn(p string) (string, bool) {
	switch p {
	case "street_name":
		return "street_name", true
	case "street_type":
		return "street_type", true
	case "locality_name":
		return "locality_name", true
	case "state":
		return "state", true
	case "postcode":
		return "postcode", true
	case "latitude":
		return "latitude", true
	case "longitude":
		return "longitude", true
	case "address_alias":
		return "address_alias", true
	default:
		return "", false
	}
}

// poiPredicateColumn maps a canonical predicate to a poi column.
func poiPredicateColumn(p string) (string, bool) {
	switch p {
	case "name":
		return "name", true
	case "brand":
		return "brand", true
	case "operator":
		return "operator", true
	case "category":
		return "category", true
	default:
		return "", false
	}
}

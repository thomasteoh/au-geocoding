// assertapply overlays enrichment from the assertion store onto a freshly
// materialised serving table — the P1 build integration (processes.md:421).
// It reads the derived canonical view and applies it as post-materialise
// corrections: address facts (subject = G-NAF PID) update the address table,
// POI facts (subject = OSM id) update the poi table. It runs at build time,
// offline, after flatten/project, and never touches a live swap (INV-4).
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "modernc.org/sqlite"

	"auplaces/internal/assertion"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "serving DB path (the one P1 materialised)")
	assertPath := flag.String("assert", "data/assertions.db", "assertion store path")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open serving db: %v", err)
	}
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

	var addrUpdated, poiUpdated, skipped int
	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	for _, c := range rows {
		// Address facts: subject is a G-NAF PID. Predicates map to columns.
		if isAddrSubject(c.Subject) {
			col, ok := addrPredicateColumn(c.Predicate)
			if !ok {
				skipped++
				continue
			}
			res, err := tx.Exec(fmt.Sprintf(`UPDATE address SET %s=? WHERE gnaf_pid=?`, col), c.Object, c.Subject)
			if err != nil {
				log.Fatalf("addr update: %v", err)
			}
			n, _ := res.RowsAffected()
			if n == 0 {
				log.Fatalf("address correction targets missing PID (strict): %s", c.Subject)
			}
			addrUpdated++
			continue
		}
		// POI facts: subject is an OSM id (n123 / w456).
		if isPOISubject(c.Subject) {
			col, ok := poiPredicateColumn(c.Predicate)
			if !ok {
				skipped++
				continue
			}
			res, err := tx.Exec(fmt.Sprintf(`UPDATE poi SET %s=? WHERE osm_id=?`, col), c.Object, c.Subject)
			if err != nil {
				log.Fatalf("poi update: %v", err)
			}
			n, _ := res.RowsAffected()
			if n == 0 {
				log.Fatalf("poi correction targets missing osm id (strict): %s", c.Subject)
			}
			poiUpdated++
			continue
		}
		skipped++
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("commit: %v", err)
	}

	// Rebuild the trigram indexes after overlay (R1.3 — never incrementally).
	// The address/poi tables changed, so the FTS indexes must be rebuilt to
	// stay consistent.
	if _, err := db.Exec(`DROP TABLE IF EXISTS addr_trgm`); err != nil {
		log.Fatalf("drop addr_trgm: %v", err)
	}
	if _, err := db.Exec(`CREATE VIRTUAL TABLE addr_trgm USING fts5(
		gnaf_pid UNINDEXED, street_number, street_name, locality_name, state, postcode,
		tokenize='trigram')`); err != nil {
		log.Fatalf("addr_trgm create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO addr_trgm SELECT gnaf_pid, street_number, street_name, locality_name, state, postcode FROM address`); err != nil {
		log.Fatalf("addr_trgm populate: %v", err)
	}

	if _, err := db.Exec(`DROP TABLE IF EXISTS poi_trgm`); err != nil {
		log.Fatalf("drop poi_trgm: %v", err)
	}
	if _, err := db.Exec(`CREATE VIRTUAL TABLE poi_trgm USING fts5(
		osm_id UNINDEXED, name, brand, tokenize='trigram')`); err != nil {
		log.Fatalf("poi_trgm create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO poi_trgm SELECT osm_id, name, brand FROM poi`); err != nil {
		log.Fatalf("poi_trgm populate: %v", err)
	}

	fmt.Printf("address updated: %d\n", addrUpdated)
	fmt.Printf("poi updated: %d\n", poiUpdated)
	fmt.Printf("skipped (unknown predicate/subject): %d\n", skipped)
	fmt.Println("trigram indexes rebuilt after overlay")
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

// buildrt adds the reverse-geocoding RTree index (addr_rt) to an existing
// serving DB. The address table must already exist (built by buildaddr). This
// is a lightweight step: it only creates and populates the RTree from address
// rowids, so it can be run after a full buildaddr without rebuilding the
// heavy address/trigram tables.
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

	// Verify address exists.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM address`).Scan(&n); err != nil {
		log.Fatalf("address table missing (run buildaddr first): %v", err)
	}
	fmt.Printf("address rows: %d\n", n)

	// Drop any stale addr_rt, recreate, populate from address rowids.
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

	var rt int
	if err := db.QueryRow(`SELECT count(*) FROM addr_rt`).Scan(&rt); err != nil {
		log.Fatalf("count addr_rt: %v", err)
	}
	fmt.Printf("addr_rt rows: %d\n", rt)
}

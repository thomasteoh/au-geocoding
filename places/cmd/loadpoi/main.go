// loadpoi builds the OSM POI layer into the serving DB. It creates the poi
// schema (internal/schema/poi.go), scans the Victoria OSM PBF, loads named
// POIs with way centroids, and reports the row count — the Step 2 POI exit
// number.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "modernc.org/sqlite"

	"auplaces/internal/osm"
	"auplaces/internal/schema"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "SQLite DB path (serving DB)")
	pbfPath := flag.String("pbf", "data/victoria-260914.osm.pbf", "OSM Victoria PBF")
	batch := flag.Int("batch", 2000, "insert batch size")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Create the POI schema (drop first for clean reloads).
	if _, err := db.Exec(schema.DropPOISchemaSQL); err != nil {
		log.Fatalf("drop poi schema: %v", err)
	}
	if _, err := db.Exec(schema.POISchemaSQL); err != nil {
		log.Fatalf("poi schema: %v", err)
	}
	fmt.Println("poi schema created")

	n, err := osm.LoadPOI(context.Background(), db, *pbfPath, *batch)
	if err != nil {
		log.Fatalf("load poi: %v", err)
	}
	fmt.Printf("POIs loaded: %d\n", n)

	// Verify counts by category.
	var total int
	if err := db.QueryRow(`SELECT count(*) FROM poi`).Scan(&total); err != nil {
		log.Fatalf("count: %v", err)
	}
	fmt.Printf("poi table rows: %d\n", total)
	var brands int
	if err := db.QueryRow(`SELECT count(*) FROM poi WHERE brand IS NOT NULL`).Scan(&brands); err != nil {
		log.Fatalf("brand count: %v", err)
	}
	fmt.Printf("branded POIs: %d\n", brands)

	// Report shop/amenity split.
	rows, err := db.Query(`SELECT substr(category, 1, instr(category,':')-1), count(*) FROM poi WHERE category LIKE 'shop:%' OR category LIKE 'amenity:%' GROUP BY 1`)
	if err != nil {
		log.Fatalf("split: %v", err)
	}
	defer rows.Close()
	fmt.Println("category split:")
	for rows.Next() {
		var c string
		var n int
		if err := rows.Scan(&c, &n); err != nil {
			log.Fatalf("split scan: %v", err)
		}
		fmt.Printf("  %s: %d\n", c, n)
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("split rows: %v", err)
	}

	// Build the trigram index after bulk insert (processes.md R1.3 — never
	// incrementally).
	if _, err := db.Exec(`INSERT INTO poi_trgm(osm_id, name, brand) SELECT osm_id, name, brand FROM poi`); err != nil {
		log.Fatalf("poi_trgm: %v", err)
	}
	fmt.Println("poi_trgm index built")
}

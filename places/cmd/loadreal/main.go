// loadreal builds the Victoria SQLite DB from the actual G-NAF PSV files.
// It creates the schema (port of create_tables_ansi.sql), loads the VIC
// Standard PSVs + Authority Code tables, creates the address_view.sql port,
// and materialises the flattened view as the matching table. Then it reports
// the row counts — the real-data exit numbers.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "SQLite DB path")
	base := flag.String("base", "data/G-NAF", "G-NAF extraction root")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Create schema. Drop existing tables first (the loader re-runs can leave
	// partial data; the PK constraints then fail on reload).
	if _, err := db.Exec(schema.DropSchemaSQL); err != nil {
		log.Fatalf("drop schema: %v", err)
	}
	if _, err := db.Exec(schema.RealSchemaSQL); err != nil {
		log.Fatalf("schema: %v", err)
	}
	fmt.Println("schema created (dropped + recreated)")

	// Load Authority Code lookup tables (small).
	authBase := filepath.Join(*base, "G-NAF AUGUST 2026", "Authority Code")
	for _, t := range []struct{ file, table, cols string }{
		{"Authority_Code_FLAT_TYPE_AUT_psv.psv", "FLAT_TYPE_AUT", "code,name,description"},
		{"Authority_Code_LEVEL_TYPE_AUT_psv.psv", "LEVEL_TYPE_AUT", "code,name,description"},
		{"Authority_Code_STREET_SUFFIX_AUT_psv.psv", "STREET_SUFFIX_AUT", "code,name,description"},
		{"Authority_Code_STREET_CLASS_AUT_psv.psv", "STREET_CLASS_AUT", "code,name,description"},
		{"Authority_Code_STREET_TYPE_AUT_psv.psv", "STREET_TYPE_AUT", "code,name,description"},
		{"Authority_Code_GEOCODE_TYPE_AUT_psv.psv", "GEOCODE_TYPE_AUT", "code,name,description"},
		{"Authority_Code_GEOCODED_LEVEL_TYPE_AUT_psv.psv", "GEOCODED_LEVEL_TYPE_AUT", "code,name,description"},
	} {
		p := filepath.Join(authBase, t.file)
		if err := schema.LoadPSV(db, p, t.table, strings.Split(t.cols, ","), true); err != nil {
			log.Fatalf("auth %s: %v", t.table, err)
		}
		fmt.Printf("  loaded %s\n", t.table)
	}

	// Load VIC Standard PSVs (the join tables). Column order per the DDL.
	stdBase := filepath.Join(*base, "G-NAF AUGUST 2026", "Standard")
	vicTables := []struct{ file, table, cols string }{
		{"VIC_ADDRESS_DETAIL_psv.psv", "ADDRESS_DETAIL", "address_detail_pid,date_created,date_last_modified,date_retired,building_name,lot_number_prefix,lot_number,lot_number_suffix,flat_type_code,flat_number_prefix,flat_number,flat_number_suffix,level_type_code,level_number_prefix,level_number,level_number_suffix,number_first_prefix,number_first,number_first_suffix,number_last_prefix,number_last,number_last_suffix,street_locality_pid,location_description,locality_pid,alias_principal,postcode,private_street,legal_parcel_id,confidence,address_site_pid,level_geocoded_code,property_pid,gnaf_property_pid,primary_secondary"},
		{"VIC_ADDRESS_DEFAULT_GEOCODE_psv.psv", "ADDRESS_DEFAULT_GEOCODE", "address_default_geocode_pid,date_created,date_retired,address_detail_pid,geocode_type_code,longitude,latitude"},
		{"VIC_STREET_LOCALITY_psv.psv", "STREET_LOCALITY", "street_locality_pid,date_created,date_retired,street_class_code,street_name,street_type_code,street_suffix_code,locality_pid,gnaf_street_pid,gnaf_street_confidence,gnaf_reliability_code"},
		{"VIC_LOCALITY_psv.psv", "LOCALITY", "locality_pid,date_created,date_retired,locality_name,primary_postcode,locality_class_code,state_pid,gnaf_locality_pid,gnaf_reliability_code"},
		{"VIC_STATE_psv.psv", "STATE", "state_pid,date_created,date_retired,state_name,state_abbreviation"},
	}
	for _, t := range vicTables {
		p := filepath.Join(stdBase, t.file)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			log.Fatalf("missing %s (extract it first)", p)
		}
		if err := schema.LoadPSV(db, p, t.table, strings.Split(t.cols, ","), true); err != nil {
			log.Fatalf("load %s: %v", t.table, err)
		}
		fmt.Printf("  loaded %s\n", t.table)
	}

	// Create the view port.
	if _, err := db.Exec(schema.RealViewSQL); err != nil {
		log.Fatalf("view: %v", err)
	}
	fmt.Println("view created (address_view.sql port)")

	// Verify the view works: count rows.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM ADDRESS_VIEW`).Scan(&n); err != nil {
		log.Fatalf("view count: %v", err)
	}
	fmt.Printf("ADDRESS_VIEW rows: %d\n", n)
}

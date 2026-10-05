package schema

// LoadReal builds the Victoria SQLite DB from the actual G-NAF PSV files.
// This is the real-data swap: it replaces the synthetic seeder with the real
// G-NAF Victoria extract, and ports address_view.sql to SQLite.
//
// The port findings (verified below by running it):
//  - CREATE OR REPLACE VIEW is not supported by SQLite → DROP VIEW first.
//  - ANSI types (varchar, numeric, date, char) are all accepted by SQLite's
//    flexible typing. No IDENTITY, no NVARCHAR, no GO. Clean port.

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"strings"
)

// RealSchemaSQL is the SQLite port of create_tables_ansi.sql (the G-NAF table
// DDL). Types are SQLite-compatible: varchar→TEXT affinity, numeric→REAL,
// date→TEXT, char→TEXT. No DDL changes needed beyond the type affinities.
var RealSchemaSQL = `
CREATE TABLE IF NOT EXISTS ADDRESS_DETAIL (
  address_detail_pid TEXT PRIMARY KEY,
  date_created TEXT NOT NULL,
  date_last_modified TEXT,
  date_retired TEXT,
  building_name TEXT,
  lot_number_prefix TEXT,
  lot_number TEXT,
  lot_number_suffix TEXT,
  flat_type_code TEXT,
  flat_number_prefix TEXT,
  flat_number REAL,
  flat_number_suffix TEXT,
  level_type_code TEXT,
  level_number_prefix TEXT,
  level_number REAL,
  level_number_suffix TEXT,
  number_first_prefix TEXT,
  number_first REAL,
  number_first_suffix TEXT,
  number_last_prefix TEXT,
  number_last REAL,
  number_last_suffix TEXT,
  street_locality_pid TEXT,
  location_description TEXT,
  locality_pid TEXT NOT NULL,
  alias_principal TEXT,
  postcode TEXT,
  private_street TEXT,
  legal_parcel_id TEXT,
  confidence REAL,
  address_site_pid TEXT NOT NULL,
  level_geocoded_code REAL NOT NULL,
  property_pid TEXT,
  gnaf_property_pid TEXT,
  primary_secondary TEXT
);

CREATE TABLE IF NOT EXISTS ADDRESS_DEFAULT_GEOCODE (
  address_default_geocode_pid TEXT PRIMARY KEY,
  date_created TEXT NOT NULL,
  date_retired TEXT,
  address_detail_pid TEXT NOT NULL,
  geocode_type_code TEXT,
  longitude REAL,
  latitude REAL
);

CREATE TABLE IF NOT EXISTS STREET_LOCALITY (
  street_locality_pid TEXT PRIMARY KEY,
  date_created TEXT NOT NULL,
  date_retired TEXT,
  street_class_code TEXT NOT NULL,
  street_name TEXT NOT NULL,
  street_type_code TEXT,
  street_suffix_code TEXT,
  locality_pid TEXT NOT NULL,
  gnaf_street_pid TEXT,
  gnaf_street_confidence REAL,
  gnaf_reliability_code REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS LOCALITY (
  locality_pid TEXT PRIMARY KEY,
  date_created TEXT NOT NULL,
  date_retired TEXT,
  locality_name TEXT NOT NULL,
  primary_postcode TEXT,
  locality_class_code TEXT NOT NULL,
  state_pid TEXT NOT NULL,
  gnaf_locality_pid TEXT,
  gnaf_reliability_code REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS STATE (
  state_pid TEXT PRIMARY KEY,
  date_created TEXT NOT NULL,
  date_retired TEXT,
  state_name TEXT NOT NULL,
  state_abbreviation TEXT NOT NULL
);

-- Authority Code lookup tables (the view's LEFT JOINs).
CREATE TABLE IF NOT EXISTS FLAT_TYPE_AUT (
  code TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT
);
CREATE TABLE IF NOT EXISTS LEVEL_TYPE_AUT (
  code TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT
);
CREATE TABLE IF NOT EXISTS STREET_SUFFIX_AUT (
  code TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT
);
CREATE TABLE IF NOT EXISTS STREET_CLASS_AUT (
  code TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT
);
CREATE TABLE IF NOT EXISTS STREET_TYPE_AUT (
  code TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT
);
CREATE TABLE IF NOT EXISTS GEOCODE_TYPE_AUT (
  code TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT
);
CREATE TABLE IF NOT EXISTS GEOCODED_LEVEL_TYPE_AUT (
  code REAL PRIMARY KEY, name TEXT NOT NULL, description TEXT
);

-- Indexes for the matching pipeline (the flattened view is materialised).
CREATE INDEX IF NOT EXISTS idx_addr_detail_locality ON ADDRESS_DETAIL(locality_pid);
CREATE INDEX IF NOT EXISTS idx_addr_detail_street ON ADDRESS_DETAIL(street_locality_pid);
CREATE INDEX IF NOT EXISTS idx_street_locality_name ON STREET_LOCALITY(street_name);
CREATE INDEX IF NOT EXISTS idx_locality_name ON LOCALITY(locality_name);
CREATE INDEX IF NOT EXISTS idx_addr_geocode_detail ON ADDRESS_DEFAULT_GEOCODE(address_detail_pid);
`

// DropSchemaSQL drops all tables before a fresh load (re-runs leave partial
// data that breaks PK constraints).
var DropSchemaSQL = `
DROP TABLE IF EXISTS ADDRESS_VIEW;
DROP TABLE IF EXISTS FLAT_TYPE_AUT;
DROP TABLE IF EXISTS LEVEL_TYPE_AUT;
DROP TABLE IF EXISTS STREET_SUFFIX_AUT;
DROP TABLE IF EXISTS STREET_CLASS_AUT;
DROP TABLE IF EXISTS STREET_TYPE_AUT;
DROP TABLE IF EXISTS GEOCODE_TYPE_AUT;
DROP TABLE IF EXISTS GEOCODED_LEVEL_TYPE_AUT;
DROP TABLE IF EXISTS ADDRESS_DETAIL;
DROP TABLE IF EXISTS ADDRESS_DEFAULT_GEOCODE;
DROP TABLE IF EXISTS STREET_LOCALITY;
DROP TABLE IF EXISTS LOCALITY;
DROP TABLE IF EXISTS STATE;
`

// RealViewSQL is the SQLite port of address_view.sql. The port changes:
//  1. DROP VIEW IF EXISTS ADDRESS_VIEW (SQLite has no CREATE OR REPLACE VIEW).
//  2. The view is materialised as a table (ADDRESS_VIEW) so the trigram index
//     can be built over it. The design's flattened view is the matching table.
//
// The join is unchanged — it's the official flattened view.
var RealViewSQL = `
DROP VIEW IF EXISTS ADDRESS_VIEW;

CREATE VIEW ADDRESS_VIEW AS
SELECT
  AD.ADDRESS_DETAIL_PID,
  AD.STREET_LOCALITY_PID,
  AD.LOCALITY_PID,
  AD.BUILDING_NAME,
  AD.LOT_NUMBER_PREFIX,
  AD.LOT_NUMBER,
  AD.LOT_NUMBER_SUFFIX,
  FTA.NAME as FLAT_TYPE,
  AD.FLAT_NUMBER_PREFIX,
  AD.FLAT_NUMBER,
  AD.FLAT_NUMBER_SUFFIX,
  LTA.NAME as LEVEL_TYPE,
  AD.LEVEL_NUMBER_PREFIX,
  AD.LEVEL_NUMBER,
  AD.LEVEL_NUMBER_SUFFIX,
  AD.NUMBER_FIRST_PREFIX,
  AD.NUMBER_FIRST,
  AD.NUMBER_FIRST_SUFFIX,
  AD.NUMBER_LAST_PREFIX,
  AD.NUMBER_LAST,
  AD.NUMBER_LAST_SUFFIX,
  SL.STREET_NAME,
  SL.STREET_CLASS_CODE,
  SCA.NAME as STREET_CLASS_TYPE,
  SL.STREET_TYPE_CODE,
  SL.STREET_SUFFIX_CODE,
  SSA.NAME as STREET_SUFFIX_TYPE,
  L.LOCALITY_NAME,
  ST.STATE_ABBREVIATION,
  AD.POSTCODE,
  ADG.LATITUDE,
  ADG.LONGITUDE,
  GTA.NAME as GEOCODE_TYPE,
  AD.CONFIDENCE,
  AD.ALIAS_PRINCIPAL,
  AD.PRIMARY_SECONDARY,
  AD.LEGAL_PARCEL_ID,
  AD.DATE_CREATED
FROM ADDRESS_DETAIL AD
LEFT JOIN FLAT_TYPE_AUT FTA ON AD.FLAT_TYPE_CODE=FTA.CODE
LEFT JOIN LEVEL_TYPE_AUT LTA ON AD.LEVEL_TYPE_CODE=LTA.CODE
JOIN STREET_LOCALITY SL ON AD.STREET_LOCALITY_PID=SL.STREET_LOCALITY_PID
LEFT JOIN STREET_SUFFIX_AUT SSA ON SL.STREET_SUFFIX_CODE=SSA.CODE
LEFT JOIN STREET_CLASS_AUT SCA ON SL.STREET_CLASS_CODE=SCA.CODE
LEFT JOIN STREET_TYPE_AUT STA ON SL.STREET_TYPE_CODE=STA.CODE
JOIN LOCALITY L ON AD.LOCALITY_PID = L.LOCALITY_PID
JOIN ADDRESS_DEFAULT_GEOCODE ADG ON AD.ADDRESS_DETAIL_PID=ADG.ADDRESS_DETAIL_PID
LEFT JOIN GEOCODE_TYPE_AUT GTA ON ADG.GEOCODE_TYPE_CODE=GTA.CODE
LEFT JOIN GEOCODED_LEVEL_TYPE_AUT GLTA ON AD.LEVEL_GEOCODED_CODE=GLTA.CODE
JOIN STATE ST ON L.STATE_PID=ST.STATE_PID
WHERE AD.CONFIDENCE > -1;
`

// LoadPSV streams a G-NAF .psv file into a table. PSV is pipe-separated
// with a header row; the header names map to columns.
// Wrapped in a transaction: 4.4M rows needs batch commit, not per-row.
func LoadPSV(db *sql.DB, path, table string, columns []string, hasHeader bool) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// Build INSERT.
	colList := strings.Join(columns, ", ")
	placeholders := strings.Repeat("?, ", len(columns))
	placeholders = strings.TrimSuffix(placeholders, ", ")

	// Transaction for speed. Commit every 50k rows (keeps memory bounded).
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("tx: %w", err)
	}
	defer tx.Rollback() // no-op if committed

	stmt, err := tx.Prepare(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, colList, placeholders))
	if err != nil {
		return fmt.Errorf("prepare %s: %w", table, err)
	}

	// Stream rows. bufio scanner; skip header if present.
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024) // large lines (postcode/name fields)
	first := true
	count := 0
	for sc.Scan() {
		line := sc.Text()
		if first && hasHeader {
			first = false
			continue // skip header
		}
		first = false
		fields := strings.Split(line, "|")
		if len(fields) > len(columns) {
			fields = fields[:len(columns)]
		}
		vals := make([]interface{}, len(columns))
		for i := range columns {
			if i < len(fields) {
				vals[i] = fields[i]
			} else {
				vals[i] = nil
			}
		}
		if _, err := stmt.Exec(vals...); err != nil {
			return fmt.Errorf("%s row %d: %w", table, count, err)
		}
		count++
		// Batch commit; re-prepare stmt on the new tx.
		if count%50000 == 0 {
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("tx commit %d: %w", count, err)
			}
			tx, err = db.Begin()
			if err != nil {
				return err
			}
			stmt.Close()
			stmt, err = tx.Prepare(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, colList, placeholders))
			if err != nil {
				return fmt.Errorf("re-prepare: %w", err)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("final tx commit: %w", err)
	}
	stmt.Close()
	fmt.Printf("  %s: %d rows\n", table, count)
	return nil
}

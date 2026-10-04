package schema

import (
	"database/sql"
	"fmt"
)

// POISchemaSQL creates the OSM POI table in the serving DB. POIs are the
// rung-3/rung-4 layer: OSM shops/amenities with a name, loaded from the
// Victoria extract with way centroids (25% of named shops are ways).
//
// The design (sources.md) filters to "has a name" — the whole named-POI set
// is ~160-200k rows, noise beside 15.9M addresses, so filtering for size is
// pointless and the filter should be "has a name".
//
// Columns follow the contract's Candidate POI fields: Name, Brand, Operator,
// Point (lat/lon), plus the OSM element id and source for attribution.
var POISchemaSQL = `
CREATE TABLE IF NOT EXISTS poi (
  osm_id     TEXT PRIMARY KEY,        -- OSM element id ("n123", "w456")
  name       TEXT NOT NULL,           -- the POI's display name
  brand      TEXT,                    -- brand tag (Woolworths, Coles, ...)
  operator   TEXT,                    -- operator tag
  category   TEXT,                    -- shop/amenity/craft value (supermarket, ...)
  lat        REAL NOT NULL,
  lon        REAL NOT NULL,
  source     TEXT NOT NULL DEFAULT 'osm',
  dataset_version TEXT NOT NULL DEFAULT 'osm-vic-260914',
  -- R2.5: OSM replication metadata, persisted from day one so daily-diff
  -- refresh can be applied later without a rewrite. sequence_number is the
  -- osmosis replication sequence; timestamp is the replication timestamp.
  sequence_number INTEGER NOT NULL DEFAULT 0,
  timestamp      TEXT NOT NULL DEFAULT ''   -- RFC3339 replication time
);

CREATE INDEX IF NOT EXISTS idx_poi_name    ON poi(name);
CREATE INDEX IF NOT EXISTS idx_poi_brand   ON poi(brand);
CREATE INDEX IF NOT EXISTS idx_poi_category ON poi(category);

-- Trigram index for POI name/brand generation. Same two-stage mechanism as
-- addresses: generate on the name/brand (trigram), score in Go.
CREATE VIRTUAL TABLE IF NOT EXISTS poi_trgm USING fts5(
  osm_id UNINDEXED,
  name,
  brand,
  tokenize='trigram'
);

-- poi_meta: the dataset as-of replication anchor (R2.5). One row holds the
-- replication point the poi layer reflects. Per-row sequence_number/timestamp
-- are last-modified provenance, NOT as-of — untouched rows keep their old
-- value while the dataset advances. This anchor is what an orchestrator reads
-- to decide the next daily-diff to apply.
CREATE TABLE IF NOT EXISTS poi_meta (
  id           INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton
  replication_seq  INTEGER NOT NULL DEFAULT 0,
  replication_ts   TEXT NOT NULL DEFAULT ''          -- RFC3339
);`

// DropPOISchemaSQL drops the POI tables before a fresh OSM load.
var DropPOISchemaSQL = `
DROP TABLE IF EXISTS poi;
DROP TABLE IF EXISTS poi_trgm;
DROP TABLE IF EXISTS poi_meta;
`

// MigratePOISchema upgrades an older pipeline/serving DB to the R2.5 schema
// in place: adds sequence_number/timestamp to poi and creates the poi_meta
// anchor table if they're missing. Never destructive — existing rows keep
// their values; new columns default to 0/” (provenance unknown until the next
// full load stamps them). Call before reading poi_meta or writing seq/ts.
func MigratePOISchema(db *sql.DB) error {
	// Does poi have the sequence_number column?
	hasSeq := false
	rows, err := db.Query(`PRAGMA table_info(poi)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "sequence_number" {
			hasSeq = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Does poi_meta exist?
	hasMeta := false
	rows, err = db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name='poi_meta'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		hasMeta = true
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if !hasSeq {
		if _, err := db.Exec(`ALTER TABLE poi ADD COLUMN sequence_number INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add sequence_number: %w", err)
		}
		if _, err := db.Exec(`ALTER TABLE poi ADD COLUMN timestamp TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add timestamp: %w", err)
		}
		fmt.Println("migrate: added sequence_number/timestamp to poi")
	}
	if !hasMeta {
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS poi_meta (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			replication_seq INTEGER NOT NULL DEFAULT 0,
			replication_ts TEXT NOT NULL DEFAULT ''
		)`); err != nil {
			return fmt.Errorf("create poi_meta: %w", err)
		}
		fmt.Println("migrate: created poi_meta")
	}
	return nil
}

package schema

// Schema mirrors the flattened G-NAF address view the design targets:
// ADDRESS_DETAIL → ADDRESS_DEFAULT_GEOCODE → STREET_LOCALITY → LOCALITY → STATE,
// plus the quality columns findings.md calls out.
//
// Synthetic for the spike (real G-NAF port is Step 1's first test), but the
// column set and types follow the official view's shape so a later port is a
// find/replace, not a redesign.

const SchemaSQL = `
CREATE TABLE IF NOT EXISTS address (
  gnaf_pid       TEXT PRIMARY KEY,      -- ADDRESS_DETAIL.gnaf_pid
  street_number  TEXT,                  -- ADDRESS_DETAIL.street_number (may be empty)
  street_name    TEXT NOT NULL,         -- STREET_LOCALITY.flat_name
  street_type    TEXT,                  -- STREET_LOCALITY.street_type (STREET/ROAD/...)
  locality_name  TEXT NOT NULL,         -- LOCALITY.flat_name (LOCALITY_ALIAS-resolved)
  state          TEXT NOT NULL,         -- STATE.abbreviation (VIC/NSW/...)
  postcode       TEXT,                  -- ADDRESS_DETAIL.postcode
  latitude       REAL NOT NULL,
  longitude      REAL NOT NULL,
  confidence     INTEGER NOT NULL,      -- -1..2 contributor agreement
  geocode_rel    INTEGER NOT NULL,      -- 1..6 coordinate precision
  primary_sec    TEXT NOT NULL DEFAULT 'P',  -- PRIMARY_SECONDARY
  address_alias  TEXT NOT NULL DEFAULT '',   -- ADDRESS_ALIAS
  mb_2026        TEXT,                  -- ABS Mesh Block 2026
  dataset_version TEXT NOT NULL DEFAULT 'synthetic-1'
);

CREATE INDEX IF NOT EXISTS idx_addr_locality ON address(locality_name);
CREATE INDEX IF NOT EXISTS idx_addr_state     ON address(state);
CREATE INDEX IF NOT EXISTS idx_addr_postcode ON address(postcode);
CREATE INDEX IF NOT EXISTS idx_addr_street    ON address(street_name);

-- Trigram index for candidate generation. SQLite's FTS5 trigram tokenizer is
-- the generation mechanism; the design verifies it works in modernc.
-- NOTE: FTS5 trigram only indexes tokens >= 3 chars. Short street numbers
-- (1-2 digits) won't be trigram-searchable — a real finding to report.
-- CONTENTFUL (no content='') so the indexed columns return real values;
-- contentless mode returns empty strings for stored columns, which breaks
-- PID retrieval. This is the design-relevant finding.
CREATE VIRTUAL TABLE IF NOT EXISTS addr_trgm USING fts5(
  gnaf_pid UNINDEXED,
  street_number,
  street_name,
  locality_name,
  state,
  postcode,
  tokenize='trigram'
);
`

// Reliable tokens per the contract: locality, state, postcode, street number.
// These are the generation anchors. Score tokens include street_name and type.
var ReliableColumns = []string{"locality_name", "state", "postcode", "street_number"}

var ScoreColumns = []string{"street_name", "street_type", "locality_name", "state", "postcode", "street_number"}

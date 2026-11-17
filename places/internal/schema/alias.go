package schema

// Alias tables. G-NAF names some localities and streets more than one way:
// LOCALITY_ALIAS and STREET_LOCALITY_ALIAS hold the other names (JOLIMONT for
// part of EAST MELBOURNE, LITTLE LATROBE STREET for LITTLE LA TROBE STREET),
// and ADDRESS_ALIAS links alias addresses to their principal one. The raw
// tables are loaded by cmd/loadreal; cmd/buildaddr derives the serving tables
// below from them.
//
// The serving tables keep only aliases that can change an answer: a live
// alias whose name is not itself an official name (an alias that is also a
// real locality or street must not take its place), mapping to exactly one
// official name (ROSEBUD WEST names parts of three localities, so it names
// none of them).

// AliasRawSchemaSQL is the G-NAF alias DDL (create_tables_ansi.sql).
const AliasRawSchemaSQL = `
CREATE TABLE IF NOT EXISTS LOCALITY_ALIAS (
  locality_alias_pid TEXT PRIMARY KEY,
  date_created TEXT NOT NULL,
  date_retired TEXT,
  locality_pid TEXT NOT NULL,
  name TEXT NOT NULL,
  postcode TEXT,
  alias_type_code TEXT NOT NULL,
  state_pid TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS STREET_LOCALITY_ALIAS (
  street_locality_alias_pid TEXT PRIMARY KEY,
  date_created TEXT NOT NULL,
  date_retired TEXT,
  street_locality_pid TEXT NOT NULL,
  street_name TEXT NOT NULL,
  street_type_code TEXT,
  street_suffix_code TEXT,
  alias_type_code TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ADDRESS_ALIAS (
  address_alias_pid TEXT PRIMARY KEY,
  date_created TEXT NOT NULL,
  date_retired TEXT,
  principal_pid TEXT NOT NULL,
  alias_pid TEXT NOT NULL,
  alias_type_code TEXT NOT NULL,
  alias_comment TEXT
);
CREATE TABLE IF NOT EXISTS LOCALITY_ALIAS_TYPE_AUT (
  code TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT
);
CREATE TABLE IF NOT EXISTS STREET_LOCALITY_ALIAS_TYPE_AUT (
  code TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT
);
CREATE TABLE IF NOT EXISTS ADDRESS_ALIAS_TYPE_AUT (
  code TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT
);
CREATE INDEX IF NOT EXISTS idx_locality_alias_pid ON LOCALITY_ALIAS(locality_pid);
CREATE INDEX IF NOT EXISTS idx_street_locality_alias_pid ON STREET_LOCALITY_ALIAS(street_locality_pid);
`

// DropAliasRawSchemaSQL drops the raw alias tables before a reload.
const DropAliasRawSchemaSQL = `
DROP TABLE IF EXISTS LOCALITY_ALIAS;
DROP TABLE IF EXISTS STREET_LOCALITY_ALIAS;
DROP TABLE IF EXISTS ADDRESS_ALIAS;
DROP TABLE IF EXISTS LOCALITY_ALIAS_TYPE_AUT;
DROP TABLE IF EXISTS STREET_LOCALITY_ALIAS_TYPE_AUT;
DROP TABLE IF EXISTS ADDRESS_ALIAS_TYPE_AUT;
`

// AliasSchemaSQL is the serving alias tables, built by cmd/buildaddr. SQLite
// table names ignore case, so these must not be named locality_alias or
// street_alias: dropping one would drop G-NAF's raw table of that name.
//
//   - alias_locality: alias -> the official locality_name it stands for.
//   - alias_street: an alias street name (and type) in a locality -> the
//     official street name and type there.
const AliasSchemaSQL = `
CREATE TABLE IF NOT EXISTS alias_locality (
  alias         TEXT PRIMARY KEY,   -- upper case, as G-NAF spells it
  locality_name TEXT NOT NULL,      -- the official name, as in address.locality_name
  state         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alias_street (
  alias_name    TEXT NOT NULL,
  alias_type    TEXT NOT NULL DEFAULT '',
  locality_name TEXT NOT NULL,
  street_name   TEXT NOT NULL,
  street_type   TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (alias_name, alias_type, locality_name)
);
`

// DropAliasSchemaSQL drops the serving alias tables.
const DropAliasSchemaSQL = `
DROP TABLE IF EXISTS alias_locality;
DROP TABLE IF EXISTS alias_street;
`

package schema

// Postcode areas: ABS Postal Areas (POA, ASGS 2021), loaded by
// cmd/loadpostcode. The ABS builds each postal area from mesh blocks, so it
// approximates the delivery postcode's area; PO box and large-volume-receiver
// postcodes have no area and are not in it.
//
//   - postcode: one row per postcode, with a representative point that is
//     inside the area (rep_lat/rep_lon) and its area in km².
//   - postcode_shape: the area's outer rings for containment (geopoly, one
//     row per ring, like boundary); postcode_shape_hole its holes.
//
// Read-only at serve time (INV-4).
const PostcodeSchemaSQL = `
CREATE TABLE IF NOT EXISTS postcode (
  postcode  TEXT PRIMARY KEY,
  state     TEXT NOT NULL,
  rep_lat   REAL NOT NULL,
  rep_lon   REAL NOT NULL,
  area_km2  REAL NOT NULL,
  source    TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS postcode_shape USING geopoly(postcode);
CREATE VIRTUAL TABLE IF NOT EXISTS postcode_shape_hole USING geopoly(outer_id, postcode);
`

// DropPostcodeSchemaSQL removes the postcode tables for a clean reload.
const DropPostcodeSchemaSQL = `
DROP TABLE IF EXISTS postcode;
DROP TABLE IF EXISTS postcode_shape;
DROP TABLE IF EXISTS postcode_shape_hole;
`

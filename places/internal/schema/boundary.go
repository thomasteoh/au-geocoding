package schema

// Boundary mirrors the Geoscape Administrative Boundaries Locality polygons:
// one row per locality polygon, with the G-NAF locality_pid as the join key
// and the polygon stored as GeoJSON for geopoly containment queries.
//
// The _shape column is the geopoly polygon (GeoJSON array-of-vertexes, CCW,
// first==last vertex) and is implicit (declared last in the column list is
// NOT valid — geopoly takes only auxiliary columns and provides _shape).
// locality_pid, name, locality_class are auxiliary data columns.
// The geopoly module indexes the bounding box; geopoly_contains_point()
// refines the exact answer. This table is built by cmd/loadboundary and is
// read-only at serve time (INV-4: server never writes).
const BoundarySchemaSQL = `
CREATE VIRTUAL TABLE IF NOT EXISTS boundary USING geopoly(
  locality_pid,
  name,
  locality_class
);
`

// DropBoundarySchemaSQL removes the boundary schema for clean reloads.
const DropBoundarySchemaSQL = `
DROP TABLE IF EXISTS boundary;
`

// BoundaryColumns are the auxiliary data columns (in geopoly order after the
// implicit rowid and _shape): locality_pid, name, locality_class.
var BoundaryColumns = []string{"locality_pid", "name", "locality_class"}

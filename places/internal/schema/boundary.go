package schema

// Boundary mirrors the Geoscape Administrative Boundaries Locality polygons
// for geopoly containment queries. It is two tables, because geopoly stores
// one simple polygon per row and cannot represent a polygon with holes:
//
//   - boundary holds the outer rings: one row per outer ring, with the G-NAF
//     locality_pid as the join key. A locality made of several parts (islands)
//     has several rows.
//   - boundary_hole holds the interior rings, each keyed to the boundary row
//     (outer_id = boundary.rowid) it is cut out of.
//
// A point is in a locality when it is inside one of its outer rings and not
// inside a hole of that same ring. Storing a hole as a fill polygon of its own
// locality (as the loader once did) makes a point in an enclave report the
// surrounding locality twice, alongside the enclave.
//
// _shape is implicit in geopoly (it cannot be declared); the listed names are
// auxiliary columns. geopoly keeps an R-Tree over each polygon's bbox, which
// geopoly_overlap() can use; geopoly_contains_point() cannot, so lookups pair
// the two (see match.LocalityAt). Built by cmd/loadboundary and read-only at
// serve time (INV-4: server never writes).
const BoundarySchemaSQL = `
CREATE VIRTUAL TABLE IF NOT EXISTS boundary USING geopoly(
  locality_pid,
  name,
  locality_class
);
CREATE VIRTUAL TABLE IF NOT EXISTS boundary_hole USING geopoly(
  outer_id,
  locality_pid
);
`

// DropBoundarySchemaSQL removes the boundary schema for clean reloads.
const DropBoundarySchemaSQL = `
DROP TABLE IF EXISTS boundary;
DROP TABLE IF EXISTS boundary_hole;
`

// BoundaryColumns are the auxiliary data columns (in geopoly order after the
// implicit rowid and _shape): locality_pid, name, locality_class.
var BoundaryColumns = []string{"locality_pid", "name", "locality_class"}

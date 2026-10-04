package schema

// LocalityOutline stores the P10 precomputed render-ready locality outline:
// one row per locality (not per ring — every ring is a subpath of the single
// path string, rendered with fill-rule="evenodd").
//
// The viewbox and subpixel factor are stored alongside the path (R10.8) so it
// is re-derivable and so a consumer can tell what display the geometry was
// fitted to. A different display size requires a rebuild, not a runtime
// rescale — the coordinates are integers on that specific grid (R10.7).
//
// Localities whose rings are all degenerate get no row at all (R10.6): the UI
// falls back to the point marker rather than drawing a malformed shape.
//
// hull marks an outline that fell back to the convex hull because the source
// geometry crosses itself; pinched marks one whose quantised path crosses
// itself although the source is clean, because two parts of the boundary pass
// within a fraction of a pixel. Both are queryable so a build can be audited.
//
// Built by cmd/loadboundary at P1 stage 4, read-only at serve time (INV-4).
const OutlineSchemaSQL = `
CREATE TABLE IF NOT EXISTS locality_outline (
  locality_pid   TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  path           TEXT NOT NULL,
  viewbox        INTEGER NOT NULL,
  subpixel       REAL NOT NULL,
  rings          INTEGER NOT NULL,
  verts          INTEGER NOT NULL,
  max_dev_px     REAL NOT NULL,
  area_err_pct   REAL NOT NULL,
  hull           INTEGER NOT NULL DEFAULT 0,
  pinched        INTEGER NOT NULL DEFAULT 0,
  min_lon        REAL NOT NULL,
  min_lat        REAL NOT NULL,
  max_lon        REAL NOT NULL,
  max_lat        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_locality_outline_hull ON locality_outline(hull) WHERE hull = 1;
CREATE INDEX IF NOT EXISTS idx_locality_outline_pinched ON locality_outline(pinched) WHERE pinched = 1;
`

// DropOutlineSchemaSQL removes the outline schema for clean reloads.
const DropOutlineSchemaSQL = `
DROP TABLE IF EXISTS locality_outline;
`

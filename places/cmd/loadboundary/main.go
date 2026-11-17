// loadboundary loads Geoscape Administrative Boundaries Locality polygons
// into the serving DB's geopoly index, and precomputes the P10 render-ready
// locality outlines. It reads the .shp/.dbf pair, converts each polygon ring
// to GeoJSON for containment queries, then simplifies each locality's rings
// into a single integer SVG path for the UI.
//
// Both are build-time (P1 stage 4) products of the loader, the only writer
// (INV-4). The fidelity gate (R10.3) fails the build on breach.
//
// The load is all-or-nothing. Outlines are computed and gated before anything
// is written, and the boundary and outline tables are replaced in a single
// transaction: a gate breach or a crash leaves the previous tables as they
// were, never a dataset with a fresh boundary table and half its outlines.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	_ "modernc.org/sqlite"

	"auplaces/internal/boundary"
	"auplaces/internal/schema"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "SQLite DB path; refused while a server has it open (build a staging copy, then activate it)")
	shpPath := flag.String("shp", "data/VIC_LOC_GDA94/vic_localities.shp", "Shapefile path")
	dbfPath := flag.String("dbf", "data/VIC_LOC_GDA94/vic_localities.dbf", "DBF path")
	_ = flag.Int("batch", 0, "ignored: the load is now a single transaction")
	outlines := flag.Bool("outlines", true, "build the P10 locality outlines")
	viewbox := flag.Int("viewbox", boundary.DefaultViewBox, "outline viewbox size in pixels (R10.8)")
	subpixel := flag.Float64("subpixel", boundary.DefaultSubPixel, "outline tolerance as a fraction of a pixel; also the fidelity gate (R10.3)")
	flag.Parse()

	r, err := boundary.Open(*shpPath, *dbfPath)
	if err != nil {
		log.Fatalf("open shapefile: %v", err)
	}
	localities, err := r.ReadAll()
	r.Close()
	if err != nil {
		log.Fatalf("read shapefile: %v", err)
	}
	fmt.Printf("shapefile records: %d\n", len(localities))

	// Gate first, write second: nothing touches the DB until every outline has
	// passed, so a breach costs a rebuild and not a half-written dataset.
	var outs []outlineRow
	if *outlines {
		var breaches []string
		outs, breaches = computeOutlines(localities, boundary.Options{ViewBox: *viewbox, SubPixel: *subpixel})
		if len(breaches) > 0 {
			for _, b := range breaches {
				log.Printf("FIDELITY GATE BREACH: %s", b)
			}
			log.Printf("P10 fidelity gate failed for %d localities — build aborted, DB not modified (R10.3)", len(breaches))
			os.Exit(1)
		}
	}

	db, release, err := schema.OpenWriter(*dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	st, err := load(db, localities, outs, *outlines)
	db.Close()
	release()
	if err != nil {
		log.Fatalf("load boundaries (DB unchanged): %v", err)
	}
	fmt.Printf("boundary outer rings: %d, holes: %d (skipped %d rings)\n", st.outers, st.holes, st.skipped)
	fmt.Printf("distinct localities: %d\n", st.localities)
	if *outlines {
		reportOutlines(outs, *subpixel)
	}
}

// loadStats summarises a load for the build log.
type loadStats struct {
	outers, holes, skipped, localities int
}

// load replaces the boundary tables (and, with withOutlines, the outline
// table) in one transaction. Either every table is the new one or, on any
// error, every table is as it was.
func load(db *sql.DB, localities []boundary.Locality, outs []outlineRow, withOutlines bool) (loadStats, error) {
	var st loadStats
	tx, err := db.Begin()
	if err != nil {
		return st, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(schema.DropBoundarySchemaSQL); err != nil {
		return st, fmt.Errorf("drop boundary schema: %w", err)
	}
	if _, err := tx.Exec(schema.BoundarySchemaSQL); err != nil {
		return st, fmt.Errorf("boundary schema: %w", err)
	}
	// geopoly_ccw normalises the winding: shapefile outer rings are clockwise,
	// and geopoly's own functions assume anticlockwise polygons.
	outerStmt, err := tx.Prepare(`INSERT INTO boundary(rowid, _shape, locality_pid, name, locality_class) VALUES (?, geopoly_ccw(?), ?, ?, ?)`)
	if err != nil {
		return st, err
	}
	defer outerStmt.Close()
	holeStmt, err := tx.Prepare(`INSERT INTO boundary_hole(_shape, outer_id, locality_pid) VALUES (geopoly_ccw(?), ?, ?)`)
	if err != nil {
		return st, err
	}
	defer holeStmt.Close()

	// Outer rings become boundary rows; holes are stored against the outer
	// ring they cut, and subtracted at lookup (match.LocalityAt). Storing a
	// hole as a polygon of its own locality would put the enclave inside it.
	seen := map[string]bool{}
	var nextID int64
	for _, loc := range localities {
		if loc.LocPID == "" || len(loc.Polygon.Parts) == 0 {
			st.skipped++
			continue
		}
		outers, holes, orphans := boundary.ClassifyRings(loc.Polygon.Parts)
		for range orphans {
			log.Printf("loc %s: hole outside every outer ring, dropped", loc.LocPID)
			st.skipped++
		}
		ids := make([]int64, len(outers))
		for i, ring := range outers {
			gj, err := boundary.ToGeoJSON(ring)
			if err != nil {
				log.Printf("loc %s ring %d: %v", loc.LocPID, i, err)
				ids[i] = -1
				st.skipped++
				continue
			}
			nextID++
			ids[i] = nextID
			if _, err := outerStmt.Exec(nextID, gj, loc.LocPID, loc.Name, loc.LocClass); err != nil {
				return st, fmt.Errorf("insert %s: %w", loc.LocPID, err)
			}
			st.outers++
			seen[loc.LocPID] = true
		}
		for _, h := range holes {
			gj, err := boundary.ToGeoJSON(h.Ring)
			if err != nil || ids[h.Outer] < 0 {
				st.skipped++
				continue
			}
			if _, err := holeStmt.Exec(gj, ids[h.Outer], loc.LocPID); err != nil {
				return st, fmt.Errorf("insert hole %s: %w", loc.LocPID, err)
			}
			st.holes++
		}
	}
	st.localities = len(seen)

	if withOutlines {
		if err := writeOutlines(tx, outs); err != nil {
			return st, err
		}
	}
	return st, tx.Commit()
}

// outlineRow is one computed P10 outline, ready to insert.
type outlineRow struct {
	pid, name string
	raw       int
	out       boundary.Outline
}

// computeOutlines is P10. One outline per locality, not per ring: a locality's
// rings (mainland, islands, holes) become subpaths of a single path so the UI
// renders the whole shape in one element. It returns the outlines to store
// and every fidelity-gate breach; it writes nothing.
func computeOutlines(localities []boundary.Locality, opt boundary.Options) ([]outlineRow, []string) {
	// A locality can span several shapefile records; merge their rings before
	// simplifying, or an island locality loses its islands (R10.5).
	type merged struct {
		name  string
		parts [][]boundary.Point
	}
	byPID := map[string]*merged{}
	var order []string
	for _, loc := range localities {
		if loc.LocPID == "" || len(loc.Polygon.Parts) == 0 {
			continue
		}
		m, ok := byPID[loc.LocPID]
		if !ok {
			m = &merged{name: loc.Name}
			byPID[loc.LocPID] = m
			order = append(order, loc.LocPID)
		}
		m.parts = append(m.parts, loc.Polygon.Parts...)
	}
	sort.Strings(order)

	var rows []outlineRow
	var breaches []string
	for _, pid := range order {
		m := byPID[pid]
		var raw int
		for _, p := range m.parts {
			raw += len(p)
		}
		out, err := boundary.Simplify(boundary.Polygon{Parts: m.parts}, opt)
		if err != nil {
			// R10.3 — the gate. Collect rather than exiting on the first, so
			// one run reports every breach instead of one per rebuild.
			breaches = append(breaches, fmt.Sprintf("%s (%s): %v", pid, m.name, err))
			continue
		}
		rows = append(rows, outlineRow{pid: pid, name: m.name, raw: raw, out: out})
	}
	return rows, breaches
}

// writeOutlines replaces locality_outline inside tx.
func writeOutlines(tx *sql.Tx, rows []outlineRow) error {
	if _, err := tx.Exec(schema.DropOutlineSchemaSQL); err != nil {
		return fmt.Errorf("drop outline schema: %w", err)
	}
	if _, err := tx.Exec(schema.OutlineSchemaSQL); err != nil {
		return fmt.Errorf("outline schema: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO locality_outline
	  (locality_pid, name, path, viewbox, subpixel, rings, verts, max_dev_px, area_err_pct, hull, pinched, min_lon, min_lat, max_lon, max_lat)
	  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("outline prepare: %w", err)
	}
	defer stmt.Close()
	for _, r := range rows {
		out := r.out
		if out.Degenerate {
			continue // R10.6: no row; the UI falls back to the point marker
		}
		hull, pinch := 0, 0
		if out.Hull {
			hull = 1
			log.Printf("outline %s (%s): source geometry self-intersects, fell back to convex hull (R10.4)", r.pid, r.name)
		}
		if out.Pinched {
			pinch = 1
		}
		if _, err := stmt.Exec(r.pid, r.name, out.Path, out.ViewBox, out.SubPixel,
			out.Rings, out.Verts, out.MaxDevPx, out.AreaErrPct, hull, pinch,
			out.BBox[0], out.BBox[1], out.BBox[2], out.BBox[3]); err != nil {
			return fmt.Errorf("outline insert %s: %w", r.pid, err)
		}
	}
	return nil
}

// reportOutlines prints the outline build summary.
func reportOutlines(rows []outlineRow, gate float64) {
	var written, degenerate, hulls, pinched int
	var bytes, verts, rawVerts int
	var worstDev float64
	for _, r := range rows {
		out := r.out
		if out.Degenerate {
			degenerate++
			continue
		}
		if out.Hull {
			hulls++
		}
		if out.Pinched {
			pinched++
		}
		written++
		bytes += len(out.Path)
		verts += out.Verts
		rawVerts += r.raw
		worstDev = max(worstDev, out.MaxDevPx)
	}
	fmt.Printf("outlines written: %d (degenerate %d, hull fallback %d, sub-pixel pinch %d)\n",
		written, degenerate, hulls, pinched)
	if written > 0 {
		fmt.Printf("outline bytes: total %d, mean %d\n", bytes, bytes/written)
		fmt.Printf("outline verts: %d raw -> %d simplified (%.1f%% kept)\n",
			rawVerts, verts, float64(verts)/float64(rawVerts)*100)
		fmt.Printf("worst max deviation: %.4f px (gate %.4f px)\n", worstDev, gate)
	}
}

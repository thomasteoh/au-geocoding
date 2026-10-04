// loadboundary loads Geoscape Administrative Boundaries Locality polygons
// into the serving DB's geopoly index, and precomputes the P10 render-ready
// locality outlines. It reads the .shp/.dbf pair, converts each polygon ring
// to GeoJSON for containment queries, then simplifies each locality's rings
// into a single integer SVG path for the UI.
//
// Both are build-time (P1 stage 4) products of the loader, the only writer
// (INV-4). The fidelity gate (R10.3) fails the build on breach.
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
	dbPath := flag.String("db", "data/vic.db", "SQLite DB path (serving DB)")
	shpPath := flag.String("shp", "data/VIC_LOC_GDA94/vic_localities.shp", "Shapefile path")
	dbfPath := flag.String("dbf", "data/VIC_LOC_GDA94/vic_localities.dbf", "DBF path")
	batch := flag.Int("batch", 500, "insert batch size")
	outlines := flag.Bool("outlines", true, "build the P10 locality outlines")
	viewbox := flag.Int("viewbox", boundary.DefaultViewBox, "outline viewbox size in pixels (R10.8)")
	subpixel := flag.Float64("subpixel", boundary.DefaultSubPixel, "outline tolerance as a fraction of a pixel; also the fidelity gate (R10.3)")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(schema.DropBoundarySchemaSQL); err != nil {
		log.Fatalf("drop boundary schema: %v", err)
	}
	if _, err := db.Exec(schema.BoundarySchemaSQL); err != nil {
		log.Fatalf("boundary schema: %v", err)
	}
	fmt.Println("boundary schema created")

	r, err := boundary.Open(*shpPath, *dbfPath)
	if err != nil {
		log.Fatalf("open shapefile: %v", err)
	}
	defer r.Close()

	localities, err := r.ReadAll()
	if err != nil {
		log.Fatalf("read shapefile: %v", err)
	}
	fmt.Printf("shapefile records: %d\n", len(localities))

	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("begin: %v", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO boundary(locality_pid, name, locality_class, _shape) VALUES (?, ?, ?, ?)`)
	if err != nil {
		log.Fatalf("prepare: %v", err)
	}
	defer stmt.Close()

	// For each locality, emit each ring as a separate geopoly row. The outer
	// ring (parts[0]) is the locality boundary; interior rings (parts[1:]) are
	// holes/islands, kept as separate polygons so containment works on them.
	var rows, skipped int
	for _, loc := range localities {
		if loc.LocPID == "" || len(loc.Polygon.Parts) == 0 {
			skipped++
			continue
		}
		for pi, ring := range loc.Polygon.Parts {
			gj, err := boundary.ToGeoJSON(ring)
			if err != nil {
				log.Printf("loc %s ring %d: %v", loc.LocPID, pi, err)
				skipped++
				continue
			}
			if _, err := stmt.Exec(loc.LocPID, loc.Name, loc.LocClass, gj); err != nil {
				log.Fatalf("insert %s: %v", loc.LocPID, err)
			}
			rows++
			if rows%*batch == 0 {
				if err := tx.Commit(); err != nil {
					log.Fatalf("commit: %v", err)
				}
				tx, err = db.Begin()
				if err != nil {
					log.Fatalf("rebegin: %v", err)
				}
				stmt, err = tx.Prepare(`INSERT INTO boundary(locality_pid, name, locality_class, _shape) VALUES (?, ?, ?, ?)`)
				if err != nil {
					log.Fatalf("reprepare: %v", err)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		log.Fatalf("final commit: %v", err)
	}
	fmt.Printf("boundary rows inserted: %d (skipped %d)\n", rows, skipped)

	// Verify count.
	var total int
	if err := db.QueryRow(`SELECT count(*) FROM boundary`).Scan(&total); err != nil {
		log.Fatalf("count: %v", err)
	}
	fmt.Printf("boundary table rows: %d\n", total)
	var localitiesCount int
	if err := db.QueryRow(`SELECT count(DISTINCT locality_pid) FROM boundary`).Scan(&localitiesCount); err != nil {
		log.Fatalf("distinct: %v", err)
	}
	fmt.Printf("distinct localities: %d\n", localitiesCount)

	if *outlines {
		buildOutlines(db, localities, boundary.Options{ViewBox: *viewbox, SubPixel: *subpixel}, *batch)
	}
}

// buildOutlines is P10. One outline per locality, not per ring: a locality's
// rings (mainland, islands, holes) become subpaths of a single path so the UI
// renders the whole shape in one element.
func buildOutlines(db *sql.DB, localities []boundary.Locality, opt boundary.Options, batch int) {
	if _, err := db.Exec(schema.DropOutlineSchemaSQL); err != nil {
		log.Fatalf("drop outline schema: %v", err)
	}
	if _, err := db.Exec(schema.OutlineSchemaSQL); err != nil {
		log.Fatalf("outline schema: %v", err)
	}

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

	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("outline begin: %v", err)
	}
	const insertSQL = `INSERT INTO locality_outline
	  (locality_pid, name, path, viewbox, subpixel, rings, verts, max_dev_px, area_err_pct, hull, pinched, min_lon, min_lat, max_lon, max_lat)
	  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		log.Fatalf("outline prepare: %v", err)
	}

	var written, degenerate, hulls, pinched int
	var bytes, verts, rawVerts int
	var worstDev float64
	var breaches []string

	for i, pid := range order {
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
		if out.Degenerate {
			degenerate++
			continue
		}
		hull, pinch := 0, 0
		if out.Hull {
			hulls++
			hull = 1
			log.Printf("outline %s (%s): source geometry self-intersects, fell back to convex hull (R10.4)", pid, m.name)
		}
		if out.Pinched {
			pinched++
			pinch = 1
		}
		if _, err := stmt.Exec(pid, m.name, out.Path, out.ViewBox, out.SubPixel,
			out.Rings, out.Verts, out.MaxDevPx, out.AreaErrPct, hull, pinch,
			out.BBox[0], out.BBox[1], out.BBox[2], out.BBox[3]); err != nil {
			log.Fatalf("outline insert %s: %v", pid, err)
		}
		written++
		bytes += len(out.Path)
		verts += out.Verts
		rawVerts += raw
		if out.MaxDevPx > worstDev {
			worstDev = out.MaxDevPx
		}
		if (i+1)%batch == 0 {
			if err := tx.Commit(); err != nil {
				log.Fatalf("outline commit: %v", err)
			}
			if tx, err = db.Begin(); err != nil {
				log.Fatalf("outline rebegin: %v", err)
			}
			if stmt, err = tx.Prepare(insertSQL); err != nil {
				log.Fatalf("outline reprepare: %v", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		log.Fatalf("outline final commit: %v", err)
	}

	fmt.Printf("outlines written: %d (degenerate %d, hull fallback %d, sub-pixel pinch %d)\n",
		written, degenerate, hulls, pinched)
	if written > 0 {
		fmt.Printf("outline bytes: total %d, mean %d\n", bytes, bytes/written)
		fmt.Printf("outline verts: %d raw -> %d simplified (%.1f%% kept)\n",
			rawVerts, verts, float64(verts)/float64(rawVerts)*100)
		fmt.Printf("worst max deviation: %.4f px (gate %.4f px)\n", worstDev, opt.SubPixel)
	}

	if len(breaches) > 0 {
		for _, b := range breaches {
			log.Printf("FIDELITY GATE BREACH: %s", b)
		}
		log.Fatalf("P10 fidelity gate failed for %d localities — build aborted (R10.3)", len(breaches))
	}
	os.Stdout.Sync()
}

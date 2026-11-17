// loadpostcode loads ABS Postal Areas (POA, ASGS Edition 3, 2021) into the
// serving DB's postcode tables (schema.PostcodeSchemaSQL): each area's rings
// for "which postcode is this point in", and a representative point inside it
// for postcode-level answers. It reads the .shp/.dbf pair with the boundary
// reader cmd/loadboundary uses.
//
// Only postcodes starting with one of -prefix are kept (Victoria: 3xxx; its
// 8xxx postcodes are PO boxes and have no postal area). The ABS publishes
// GDA2020 coordinates; G-NAF's are GDA94, about 1.8 m apart, which is far
// below what a postcode answer needs.
//
// The load is one transaction: the previous postcode tables survive any
// failure.
//
//	go run ./cmd/loadpostcode -db data/vic.db \
//	  -shp POA_2021_AUST_GDA2020.shp -dbf POA_2021_AUST_GDA2020.dbf
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"

	"auplaces/internal/boundary"
	"auplaces/internal/schema"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "SQLite DB path; refused while a server has it open")
	shpPath := flag.String("shp", "data/POA_2021_AUST_GDA2020.shp", "ABS POA shapefile")
	dbfPath := flag.String("dbf", "data/POA_2021_AUST_GDA2020.dbf", "ABS POA attributes")
	prefix := flag.String("prefix", "3", "comma-separated postcode prefixes to keep")
	state := flag.String("state", "VIC", "state the kept postcodes belong to")
	flag.Parse()

	r, err := boundary.Open(*shpPath, *dbfPath)
	if err != nil {
		log.Fatalf("open shapefile: %v", err)
	}
	recs, err := r.ReadAll()
	r.Close()
	if err != nil {
		log.Fatalf("read shapefile: %v", err)
	}
	areas := selectAreas(recs, strings.Split(*prefix, ","))
	fmt.Printf("shapefile records: %d, kept: %d\n", len(recs), len(areas))

	db, release, err := schema.OpenWriter(*dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	st, err := load(db, areas, *state)
	db.Close()
	release()
	if err != nil {
		log.Fatalf("load postcodes (DB unchanged): %v", err)
	}
	fmt.Printf("postcodes: %d (%d rings, %d holes; representative point: %d centroid, %d pole)\n",
		st.postcodes, st.outers, st.holes, st.centroid, st.pole)
}

// area is one postal area to load.
type area struct {
	postcode string
	areaKm2  float64
	parts    [][]boundary.Point
}

// selectAreas keeps the records whose POA_CODE21 starts with a prefix and
// that have geometry.
func selectAreas(recs []boundary.Locality, prefixes []string) []area {
	var out []area
	for _, rec := range recs {
		code := strings.TrimSpace(rec.Attrs["POA_CODE21"])
		if len(code) != 4 || len(rec.Polygon.Parts) == 0 {
			continue
		}
		keep := false
		for _, p := range prefixes {
			if p = strings.TrimSpace(p); p != "" && strings.HasPrefix(code, p) {
				keep = true
			}
		}
		if !keep {
			continue
		}
		km2, _ := strconv.ParseFloat(strings.TrimSpace(rec.Attrs["AREASQKM21"]), 64)
		out = append(out, area{postcode: code, areaKm2: km2, parts: rec.Polygon.Parts})
	}
	return out
}

type loadStats struct{ postcodes, outers, holes, centroid, pole int }

// load replaces the postcode tables in one transaction.
func load(db *sql.DB, areas []area, state string) (loadStats, error) {
	var st loadStats
	tx, err := db.Begin()
	if err != nil {
		return st, err
	}
	defer tx.Rollback()
	for _, s := range []string{schema.DropPostcodeSchemaSQL, schema.PostcodeSchemaSQL} {
		if _, err := tx.Exec(s); err != nil {
			return st, err
		}
	}
	pcStmt, err := tx.Prepare(`INSERT INTO postcode (postcode, state, rep_lat, rep_lon, area_km2, source) VALUES (?, ?, ?, ?, ?, 'ABS POA 2021')`)
	if err != nil {
		return st, err
	}
	defer pcStmt.Close()
	outerStmt, err := tx.Prepare(`INSERT INTO postcode_shape (rowid, _shape, postcode) VALUES (?, geopoly_ccw(?), ?)`)
	if err != nil {
		return st, err
	}
	defer outerStmt.Close()
	holeStmt, err := tx.Prepare(`INSERT INTO postcode_shape_hole (_shape, outer_id, postcode) VALUES (geopoly_ccw(?), ?, ?)`)
	if err != nil {
		return st, err
	}
	defer holeStmt.Close()

	var nextID int64
	for _, a := range areas {
		outers, holes, orphans := boundary.ClassifyRings(a.parts)
		if len(orphans) > 0 {
			log.Printf("postcode %s: %d holes outside every outer ring, dropped", a.postcode, len(orphans))
		}
		if len(outers) == 0 {
			log.Printf("postcode %s: no usable ring, skipped", a.postcode)
			continue
		}
		ids := make([]int64, len(outers))
		for i, ring := range outers {
			gj, err := boundary.ToGeoJSON(ring)
			if err != nil {
				ids[i] = -1
				continue
			}
			nextID++
			ids[i] = nextID
			if _, err := outerStmt.Exec(nextID, gj, a.postcode); err != nil {
				return st, fmt.Errorf("insert %s: %w", a.postcode, err)
			}
			st.outers++
		}
		for _, h := range holes {
			gj, err := boundary.ToGeoJSON(h.Ring)
			if err != nil || ids[h.Outer] < 0 {
				continue
			}
			if _, err := holeStmt.Exec(gj, ids[h.Outer], a.postcode); err != nil {
				return st, fmt.Errorf("insert hole %s: %w", a.postcode, err)
			}
			st.holes++
		}
		p, method := boundary.InteriorPoint(outers, holes, 1e-4)
		if method == "centroid" {
			st.centroid++
		} else {
			st.pole++
		}
		if _, err := pcStmt.Exec(a.postcode, state, p.Y, p.X, a.areaKm2); err != nil {
			return st, fmt.Errorf("insert postcode %s: %w", a.postcode, err)
		}
		st.postcodes++
	}
	return st, tx.Commit()
}

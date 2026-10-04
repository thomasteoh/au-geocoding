// loadoscdiff applies an OSM change file (OSC) to the poi layer — the R2.5
// daily-diff refresh. It reads the OSC, applies create/modify/delete to the
// poi table, stamps the changed rows with the diff's replication point, and
// advances the poi_meta as-of anchor. This is the incremental per-source path:
// instead of reloading the full OSM PBF, a small daily diff updates only the
// POIs that changed.
package main

import (
	"database/sql"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	_ "modernc.org/sqlite"

	pm "github.com/paulmach/osm"
	"auplaces/internal/osm"
	"auplaces/internal/schema"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "SQLite DB path (serving DB)")
	oscPath := flag.String("osc", "", "OSM change file (.osc) to apply")
	seq := flag.Uint64("seq", 0, "diff replication sequence number (as-of point)")
	ts := flag.String("ts", "", "diff replication timestamp (RFC3339, as-of point)")
	flag.Parse()

	if *oscPath == "" {
		log.Fatal("-osc is required")
	}

	// Parse the as-of replication point. If provided, it's stamped on changed
	// rows (last-modified) and advances the dataset anchor (poi_meta).
	var asOf time.Time
	if *ts != "" {
		var err error
		asOf, err = time.Parse(time.RFC3339, *ts)
		if err != nil {
			log.Fatalf("-ts: %v", err)
		}
	}
	asOfStr := ""
	if !asOf.IsZero() {
		asOfStr = asOf.UTC().Format(time.RFC3339)
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Migrate an older DB: the R2.5 schema (sequence_number/timestamp on poi,
	// the poi_meta anchor) may not exist on a DB materialised before R2.5 was
	// wired. Detect and add the missing pieces in place — never destructive.
	if err := schema.MigratePOISchema(db); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	// Read + parse the OSC.
	f, err := os.Open(*oscPath)
	if err != nil {
		log.Fatalf("open osc: %v", err)
	}
	defer f.Close()

	var change pm.Change
	if err := xml.NewDecoder(f).Decode(&change); err != nil {
		log.Fatalf("decode osc: %v", err)
	}

	var created, modified, deleted int
	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	// Create: insert new POIs.
	for _, o := range change.Create.Objects() {
		if !isPOIObject(o) {
			continue
		}
		id, lat, lon := poiID(o)
		if id == "" {
			continue
		}
		tags := poiTags(o)
		if _, err := tx.Exec(`INSERT INTO poi(osm_id, name, brand, operator, category, lat, lon, sequence_number, timestamp)
			VALUES(?,?,?,?,?,?,?,?,?)`,
			id, tags.Find("name"), tags.Find("brand"), tags.Find("operator"),
			osm.POICategory(tags), lat, lon, *seq, asOfStr); err != nil {
			log.Fatalf("insert create: %v", err)
		}
		created++
	}

	// Modify: upsert existing POIs.
	for _, o := range change.Modify.Objects() {
		if !isPOIObject(o) {
			continue
		}
		id, lat, lon := poiID(o)
		if id == "" {
			continue
		}
		tags := poiTags(o)
		if _, err := tx.Exec(`INSERT INTO poi(osm_id, name, brand, operator, category, lat, lon, sequence_number, timestamp)
			VALUES(?,?,?,?,?,?,?,?,?)
			ON CONFLICT(osm_id) DO UPDATE SET name=excluded.name, brand=excluded.brand,
				operator=excluded.operator, category=excluded.category,
				lat=excluded.lat, lon=excluded.lon, sequence_number=excluded.sequence_number,
				timestamp=excluded.timestamp`,
			id, tags.Find("name"), tags.Find("brand"), tags.Find("operator"),
			osm.POICategory(tags), lat, lon, *seq, asOfStr); err != nil {
			log.Fatalf("upsert modify: %v", err)
		}
		modified++
	}

	// Delete: remove POIs (only named-POI-typed ones).
	for _, o := range change.Delete.Objects() {
		if !isPOIObject(o) {
			continue
		}
		id, _, _ := poiID(o)
		if id == "" {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM poi WHERE osm_id=?`, id); err != nil {
			log.Fatalf("delete: %v", err)
		}
		deleted++
	}

	// Advance the dataset as-of anchor (R2.5). Changed rows carry the diff's
	// seq/ts as last-modified; untouched rows keep their old value. The anchor
	// records the replication point the whole poi layer now reflects.
	if *ts != "" {
		if _, err := tx.Exec(`INSERT INTO poi_meta(id, replication_seq, replication_ts) VALUES(1,?,?)
			ON CONFLICT(id) DO UPDATE SET replication_seq=excluded.replication_seq,
			replication_ts=excluded.replication_ts`, *seq, asOfStr); err != nil {
			log.Fatalf("poi_meta: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("commit: %v", err)
	}

	fmt.Printf("created: %d\nmodified: %d\ndeleted: %d\n", created, modified, deleted)
	fmt.Printf("applied: %d POIs\n", created+modified+deleted)
	if *ts != "" {
		fmt.Printf("as-of: seq=%d ts=%s\n", *seq, asOfStr)
	}
}

// isPOIObject reports whether the element is a named POI (node or way with
// POI-typed tags). Relations are never POIs in this design.
func isPOIObject(o pm.Object) bool {
	var tags pm.Tags
	switch e := o.(type) {
	case *pm.Node:
		tags = e.Tags
	case *pm.Way:
		tags = e.Tags
	default:
		return false
	}
	return osm.IsPOI(tags) && osm.HasName(tags)
}

// poiTags extracts the element tags, or nil for non-node/way elements.
func poiTags(o pm.Object) pm.Tags {
	switch e := o.(type) {
	case *pm.Node:
		return e.Tags
	case *pm.Way:
		return e.Tags
	default:
		return nil
	}
}

// poiID extracts the OSM id string and lat/lon. Nodes carry coords; ways have
// no lat/lon in the diff (centroid computed in the full load), so ways keep
// their existing centroid — a modify of a way updates only its tags.
func poiID(o pm.Object) (id string, lat, lon float64) {
	switch e := o.(type) {
	case *pm.Node:
		return fmt.Sprintf("n%d", e.ID), e.Lat, e.Lon
	case *pm.Way:
		return fmt.Sprintf("w%d", e.ID), 0, 0
	default:
		return "", 0, 0
	}
}

// loadoscdiff applies an OSM change file (OSC) to the poi layer — the R2.5
// daily-diff refresh. It reads the OSC, applies create/modify/delete to the
// poi table, stamps the changed rows with the diff's replication point, and
// advances the poi_meta as-of anchor. This is the incremental per-source path:
// instead of reloading the full OSM PBF, a small daily diff updates only the
// POIs that changed.
//
// The diff is applied in one transaction, poi_trgm included, so search sees
// every change in the diff or none of them.
package main

import (
	"database/sql"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"auplaces/internal/osm"
	"auplaces/internal/schema"
	pm "github.com/paulmach/osm"
)

// vicBBox is Victoria's extent (minLon, minLat, maxLon, maxLat) with a little
// margin. The replication feed is Australia-wide; without a region filter a
// daily diff would add POIs from every state to a Victorian dataset.
const vicBBox = "140.9,-39.3,150.1,-33.9"

func main() {
	dbPath := flag.String("db", "data/vic.db", "SQLite DB path; refused while a server has it open")
	oscPath := flag.String("osc", "", "OSM change file (.osc) to apply")
	seq := flag.Uint64("seq", 0, "diff replication sequence number (as-of point)")
	ts := flag.String("ts", "", "diff replication timestamp (RFC3339, as-of point)")
	bboxFlag := flag.String("bbox", vicBBox, "dataset region minLon,minLat,maxLon,maxLat; POIs outside it are not loaded")
	flag.Parse()

	if *oscPath == "" {
		log.Fatal("-osc is required")
	}
	bbox, err := parseBBox(*bboxFlag)
	if err != nil {
		log.Fatalf("-bbox: %v", err)
	}

	// Parse the as-of replication point. If provided, it's stamped on changed
	// rows (last-modified) and advances the dataset anchor (poi_meta).
	var asOf time.Time
	if *ts != "" {
		asOf, err = time.Parse(time.RFC3339, *ts)
		if err != nil {
			log.Fatalf("-ts: %v", err)
		}
	}

	db, release, err := schema.OpenWriter(*dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer release()
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
	var change pm.Change
	err = xml.NewDecoder(f).Decode(&change)
	f.Close()
	if err != nil {
		log.Fatalf("decode osc: %v", err)
	}

	st, err := apply(db, &change, applyOpts{seq: *seq, asOf: asOf, bbox: bbox})
	if err != nil {
		log.Fatalf("apply (DB unchanged): %v", err)
	}
	fmt.Printf("upserted: %d\ndeleted: %d\nskipped (outside region or no coordinates): %d\n",
		st.upserted, st.deleted, st.skipped)
	fmt.Printf("applied: %d POIs\n", st.upserted+st.deleted)
	if !asOf.IsZero() {
		fmt.Printf("as-of: seq=%d ts=%s\n", *seq, asOf.UTC().Format(time.RFC3339))
	}
}

type applyOpts struct {
	seq  uint64
	asOf time.Time
	bbox [4]float64
}

type applyStats struct {
	upserted, deleted, skipped int
}

// apply applies one change file in a single transaction.
//
// Every element the diff touches is reconciled against the POI rule rather
// than trusting which section it sits in:
//   - create/modify of a named POI inside the region upserts it;
//   - create/modify of anything else (tags removed, renamed to nothing, moved
//     out of the region) deletes any POI row with that id;
//   - delete removes the row by id. Replication diffs carry no tags on a
//     deleted element, so a tag check here would keep every deleted POI.
//
// A way's coordinates are its centroid, which the diff can supply only when
// all of the way's nodes are in it. Otherwise a modified way keeps its stored
// centroid and only its tags change; a new way with no locatable nodes is
// skipped rather than placed at 0,0. (A way whose untagged nodes move without
// the way itself changing is not re-centred; the next full load corrects it.)
func apply(db *sql.DB, change *pm.Change, opt applyOpts) (applyStats, error) {
	var st applyStats
	asOfStr := ""
	if !opt.asOf.IsZero() {
		asOfStr = opt.asOf.UTC().Format(time.RFC3339)
	}

	tx, err := db.Begin()
	if err != nil {
		return st, err
	}
	defer tx.Rollback()

	// Node coordinates the diff carries, POI or not, for way centroids.
	coords := map[pm.NodeID][2]float64{}
	for _, sec := range []*pm.OSM{change.Create, change.Modify} {
		if sec == nil {
			continue
		}
		for _, n := range sec.Nodes {
			coords[n.ID] = [2]float64{n.Lat, n.Lon}
		}
	}

	changed := map[string]bool{}
	del := func(id string) error {
		res, err := tx.Exec(`DELETE FROM poi WHERE osm_id=?`, id)
		if err != nil {
			return fmt.Errorf("delete %s: %w", id, err)
		}
		// Most elements in a diff were never POIs; only a real removal needs
		// its index row dropped.
		if n, _ := res.RowsAffected(); n > 0 {
			st.deleted += int(n)
			changed[id] = true
		}
		return nil
	}

	for _, sec := range []*pm.OSM{change.Create, change.Modify} {
		if sec == nil {
			continue
		}
		for _, o := range sec.Objects() {
			id, tags, pos, ok := element(o, coords)
			if !ok {
				continue
			}
			if !osm.IsPOI(tags) || !osm.HasName(tags) {
				if err := del(id); err != nil {
					return st, err
				}
				continue
			}
			if pos != nil && !inBBox(*pos, opt.bbox) {
				if err := del(id); err != nil {
					return st, err
				}
				st.skipped++
				continue
			}
			name, brand, op, cat := tags.Find("name"), tags.Find("brand"), tags.Find("operator"), osm.POICategory(tags)
			var res sql.Result
			if pos != nil {
				res, err = tx.Exec(`INSERT INTO poi(osm_id, name, brand, operator, category, lat, lon, sequence_number, timestamp)
					VALUES(?,?,?,?,?,?,?,?,?)
					ON CONFLICT(osm_id) DO UPDATE SET name=excluded.name, brand=excluded.brand,
						operator=excluded.operator, category=excluded.category,
						lat=excluded.lat, lon=excluded.lon, sequence_number=excluded.sequence_number,
						timestamp=excluded.timestamp`,
					id, name, brand, op, cat, pos[0], pos[1], opt.seq, asOfStr)
			} else {
				// No centroid from this diff: keep the stored one.
				res, err = tx.Exec(`UPDATE poi SET name=?, brand=?, operator=?, category=?,
					sequence_number=?, timestamp=? WHERE osm_id=?`,
					name, brand, op, cat, opt.seq, asOfStr, id)
			}
			if err != nil {
				return st, fmt.Errorf("upsert %s: %w", id, err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				st.skipped++
				continue
			}
			st.upserted++
			changed[id] = true
		}
	}

	if change.Delete != nil {
		for _, o := range change.Delete.Objects() {
			var id string
			switch e := o.(type) {
			case *pm.Node:
				id = "n" + strconv.FormatInt(int64(e.ID), 10)
			case *pm.Way:
				id = "w" + strconv.FormatInt(int64(e.ID), 10)
			default:
				continue
			}
			if err := del(id); err != nil {
				return st, err
			}
		}
	}

	// Keep poi_trgm in step: drop the index rows for every touched id and
	// re-add those still in poi. Without this, new POIs were unsearchable and
	// deleted ones still matched.
	if _, err := tx.Exec(`CREATE TEMP TABLE IF NOT EXISTS osc_changed(id TEXT PRIMARY KEY)`); err != nil {
		return st, err
	}
	if _, err := tx.Exec(`DELETE FROM osc_changed`); err != nil {
		return st, err
	}
	for id := range changed {
		if _, err := tx.Exec(`INSERT INTO osc_changed(id) VALUES(?)`, id); err != nil {
			return st, err
		}
	}
	if _, err := tx.Exec(`DELETE FROM poi_trgm WHERE osm_id IN (SELECT id FROM osc_changed)`); err != nil {
		return st, fmt.Errorf("poi_trgm delete: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO poi_trgm(osm_id, name, brand)
		SELECT osm_id, name, brand FROM poi WHERE osm_id IN (SELECT id FROM osc_changed)`); err != nil {
		return st, fmt.Errorf("poi_trgm insert: %w", err)
	}

	// Advance the dataset as-of anchor (R2.5). Changed rows carry the diff's
	// seq/ts as last-modified; untouched rows keep their old value. The anchor
	// records the replication point the whole poi layer now reflects.
	if asOfStr != "" {
		if _, err := tx.Exec(`INSERT INTO poi_meta(id, replication_seq, replication_ts) VALUES(1,?,?)
			ON CONFLICT(id) DO UPDATE SET replication_seq=excluded.replication_seq,
			replication_ts=excluded.replication_ts`, opt.seq, asOfStr); err != nil {
			return st, fmt.Errorf("poi_meta: %w", err)
		}
	}
	return st, tx.Commit()
}

// element returns a node's or way's POI id, tags and position. pos is nil for
// a way whose nodes are not all in the diff. ok is false for relations, which
// are never POIs in this design.
func element(o pm.Object, coords map[pm.NodeID][2]float64) (id string, tags pm.Tags, pos *[2]float64, ok bool) {
	switch e := o.(type) {
	case *pm.Node:
		return "n" + strconv.FormatInt(int64(e.ID), 10), e.Tags, &[2]float64{e.Lat, e.Lon}, true
	case *pm.Way:
		id = "w" + strconv.FormatInt(int64(e.ID), 10)
		// Average the node coordinates, as the full load does (osm.LoadPOI).
		var lat, lon float64
		for _, wn := range e.Nodes {
			c, found := coords[wn.ID]
			if !found {
				return id, e.Tags, nil, true
			}
			lat += c[0]
			lon += c[1]
		}
		if len(e.Nodes) == 0 {
			return id, e.Tags, nil, true
		}
		n := float64(len(e.Nodes))
		return id, e.Tags, &[2]float64{lat / n, lon / n}, true
	}
	return "", nil, nil, false
}

func inBBox(p [2]float64, b [4]float64) bool {
	return p[1] >= b[0] && p[0] >= b[1] && p[1] <= b[2] && p[0] <= b[3]
}

// parseBBox parses "minLon,minLat,maxLon,maxLat".
func parseBBox(s string) ([4]float64, error) {
	var b [4]float64
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return b, fmt.Errorf("want minLon,minLat,maxLon,maxLat, got %q", s)
	}
	for i, p := range parts {
		v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return b, err
		}
		b[i] = v
	}
	if b[0] >= b[2] || b[1] >= b[3] {
		return b, fmt.Errorf("empty bbox %q", s)
	}
	return b, nil
}

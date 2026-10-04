package osm

// LoadPOI scans the OSM Victoria PBF and loads named POIs into the poi table.
//
// Two-pass (memory-safe): OSM PBF stores ways as node-ID lists; the node
// coordinates live in separate node blocks. A single pass that keeps all node
// coords would hold ~528 MB for 33M nodes. Instead:
//   Pass 1: collect POI ways and their node-ID sets (small — ~25k ways).
//   Pass 2: re-scan, collecting named node POIs AND coords for the way nodes,
//           then compute way centroids.
//
// POI filter: has a name AND is a POI type (shop/amenity/craft/brand). This is
// the design's filter — "has a name", not "is big enough". 25% of named shops
// are ways, so centroids are core, not an edge case (sources.md D-024).

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/paulmach/osm"
	"github.com/paulmach/osm/osmpbf"
)

// POI is a resolved OSM point-of-interest. Way centroids are the way's node
// coordinates averaged; nodes use their own lat/lon.
type POI struct {
	OsmID    string
	Name     string
	Brand    string
	Operator string
	Category string
	Lat, Lon float64
	// R2.5: OSM replication metadata, persisted from day one so daily-diff
	// refresh can be applied later without a rewrite.
	SequenceNumber uint64
	Timestamp      time.Time
}

// poiCategory extracts the POI's primary category tag value for the category
// column ("shop:supermarket", "amenity:atm", ...).
func poiCategory(tags osm.Tags) string {
	if s := tags.Find("shop"); s != "" {
		return "shop:" + s
	}
	if a := tags.Find("amenity"); a != "" {
		return "amenity:" + a
	}
	if c := tags.Find("craft"); c != "" {
		return "craft:" + c
	}
	if tags.Find("brand") != "" {
		return "brand"
	}
	return ""
}

// hasName reports whether the element is a named POI. The design filters to
// "has a name" — the whole named-POI set is ~160-200k rows, noise beside 15.9M
// addresses, so filtering for size is pointless.
func hasName(tags osm.Tags) bool {
	return tags.Find("name") != "" || tags.Find("brand") != ""
}

// isPOI reports whether the element is a POI type (shop/amenity/craft/brand).
func isPOI(tags osm.Tags) bool {
	return tags.Find("shop") != "" || tags.Find("amenity") != "" ||
		tags.Find("craft") != "" || tags.Find("brand") != ""
}

// IsPOI is the exported form of isPOI for other packages.
func IsPOI(tags osm.Tags) bool { return isPOI(tags) }

// HasName is the exported form of hasName.
func HasName(tags osm.Tags) bool { return hasName(tags) }

// POICategory is the exported form of poiCategory.
func POICategory(tags osm.Tags) string { return poiCategory(tags) }

// nodeCoord is a compact lat/lon pair.
type nodeCoord struct{ lat, lon float64 }

// wayNode is a POI way and its node-ID list (for centroid computation).
type wayNode struct {
	osmID  osm.WayID
	tags   osm.Tags
	nodes  []osm.NodeID
}

// LoadPOI runs the two-pass load. It returns the number of POIs inserted.
// R2.5: the OSM replication header (sequence number + timestamp) is captured
// from the PBF and persisted with every POI, so daily-diff refresh can be
// applied later without a rewrite.
func LoadPOI(ctx context.Context, db *sql.DB, pbfPath string, batchSize int) (int, error) {
	if batchSize <= 0 {
		batchSize = 2000
	}

	// Capture the OSM replication header (R2.5). This is the sequence number
	// and timestamp of the PBF we're loading — persisted per-POI.
	var seqNum uint64
	var ts time.Time
	{
		f, err := os.Open(pbfPath)
		if err != nil {
			return 0, fmt.Errorf("open pbf: %w", err)
		}
		sc := osmpbf.New(ctx, f, 4)
		hdr, err := sc.Header()
		if err != nil {
			f.Close()
			return 0, fmt.Errorf("header: %w", err)
		}
		seqNum = hdr.ReplicationSeqNum
		ts = hdr.ReplicationTimestamp
		f.Close()
	}

	// Pass 1: collect POI ways and their node-ID sets.
	var ways []wayNode
	wantNodes := make(map[osm.NodeID]bool)

	f, err := os.Open(pbfPath)
	if err != nil {
		return 0, fmt.Errorf("open pbf: %w", err)
	}
	sc := osmpbf.New(ctx, f, 4)
	for sc.Scan() {
		switch e := sc.Object().(type) {
		case *osm.Way:
			if isPOI(e.Tags) && hasName(e.Tags) {
				nodes := e.Nodes.NodeIDs()
				ways = append(ways, wayNode{e.ID, e.Tags, nodes})
				for _, id := range nodes {
					wantNodes[id] = true
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		f.Close()
		return 0, fmt.Errorf("scan pass1: %w", err)
	}
	f.Close()

	// Pass 2: named node POIs + coords for the wanted way nodes.
	coords := make(map[osm.NodeID]nodeCoord, len(wantNodes))
	var pois []POI
	f2, err := os.Open(pbfPath)
	if err != nil {
		return 0, fmt.Errorf("open pbf pass2: %w", err)
	}
	sc2 := osmpbf.New(ctx, f2, 4)
	for sc2.Scan() {
		if n, ok := sc2.Object().(*osm.Node); ok {
			if wantNodes[n.ID] {
				coords[n.ID] = nodeCoord{n.Lat, n.Lon}
			}
			if isPOI(n.Tags) && hasName(n.Tags) {
				pois = append(pois, POI{
					OsmID:          fmt.Sprintf("n%d", n.ID),
					Name:           n.Tags.Find("name"),
					Brand:          n.Tags.Find("brand"),
					Operator:       n.Tags.Find("operator"),
					Category:       poiCategory(n.Tags),
					Lat:            n.Lat,
					Lon:            n.Lon,
					SequenceNumber: seqNum,
					Timestamp:      ts,
				})
			}
		}
	}
	if err := sc2.Err(); err != nil {
		f2.Close()
		return 0, fmt.Errorf("scan pass2: %w", err)
	}
	f2.Close()

	// Way centroids from the collected coords.
	for _, w := range ways {
		if len(w.nodes) == 0 {
			continue
		}
		var lat, lon, n float64
		for _, id := range w.nodes {
			c, ok := coords[id]
			if !ok {
				continue
			}
			lat += c.lat
			lon += c.lon
			n++
		}
		if n == 0 {
			continue
		}
		pois = append(pois, POI{
			OsmID:          fmt.Sprintf("w%d", w.osmID),
			Name:           w.tags.Find("name"),
			Brand:          w.tags.Find("brand"),
			Operator:       w.tags.Find("operator"),
			Category:       poiCategory(w.tags),
			Lat:            lat / n,
			Lon:            lon / n,
			SequenceNumber: seqNum,
			Timestamp:      ts,
		})
	}

	// Insert in batches.
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(`INSERT INTO poi(osm_id, name, brand, operator, category, lat, lon, sequence_number, timestamp)
		VALUES(?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	var total int
	for _, p := range pois {
		tsStr := ""
		if !p.Timestamp.IsZero() {
			tsStr = p.Timestamp.UTC().Format(time.RFC3339)
		}
		if _, err := stmt.Exec(p.OsmID, p.Name, p.Brand, p.Operator, p.Category, p.Lat, p.Lon, p.SequenceNumber, tsStr); err != nil {
			return 0, err
		}
		total++
		if total%batchSize == 0 {
			fmt.Printf("  poi: %d\n", total)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}

	// Set the dataset as-of replication anchor (R2.5). The full PBF load
	// reflects the replication point captured from the header; an orchestrator
	// reads this to decide the next daily-diff to apply.
	tsStr := ""
	if !ts.IsZero() {
		tsStr = ts.UTC().Format(time.RFC3339)
	}
	if _, err := db.Exec(`INSERT INTO poi_meta(id, replication_seq, replication_ts) VALUES(1,?,?)
		ON CONFLICT(id) DO UPDATE SET replication_seq=excluded.replication_seq,
		replication_ts=excluded.replication_ts`, seqNum, tsStr); err != nil {
		return 0, err
	}

	return total, nil
}

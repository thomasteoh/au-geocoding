package main

import (
	"database/sql"
	"encoding/xml"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pm "github.com/paulmach/osm"
	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

func poiDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{schema.POISchemaSQL,
		`INSERT INTO poi(osm_id, name, category, lat, lon) VALUES
			('n1', 'GONE CAFE', 'amenity:cafe', -37.8, 144.9),
			('n2', 'RENAMED BAKERY', 'shop:bakery', -37.8, 144.9),
			('w3', 'OLD MARKET', 'amenity:marketplace', -37.7, 145.0)`,
		`INSERT INTO poi_trgm SELECT osm_id, name, brand FROM poi`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

const osc = `<osmChange version="0.6">
<create>
  <node id="10" lat="-37.81" lon="144.96" version="1"><tag k="amenity" v="pharmacy"/><tag k="name" v="NEW CHEMIST"/></node>
  <node id="11" lat="-33.87" lon="151.21" version="1"><tag k="shop" v="books"/><tag k="name" v="SYDNEY BOOKS"/></node>
  <node id="20" lat="-37.60" lon="145.00" version="1"/>
  <node id="21" lat="-37.60" lon="145.02" version="1"/>
  <node id="22" lat="-37.62" lon="145.02" version="1"/>
  <way id="30" version="1"><nd ref="20"/><nd ref="21"/><nd ref="22"/><nd ref="20"/>
    <tag k="shop" v="hardware"/><tag k="name" v="NEW HARDWARE"/></way>
  <way id="31" version="1"><nd ref="999"/><nd ref="998"/><nd ref="999"/>
    <tag k="shop" v="toys"/><tag k="name" v="NOWHERE TOYS"/></way>
</create>
<modify>
  <node id="2" lat="-37.8" lon="144.9" version="2"><tag k="shop" v="bakery"/></node>
  <way id="3" version="2"><nd ref="500"/><nd ref="501"/><nd ref="500"/>
    <tag k="amenity" v="marketplace"/><tag k="name" v="NEW MARKET"/></way>
</modify>
<delete>
  <node id="1" lat="-37.8" lon="144.9" version="3"/>
</delete>
</osmChange>`

func TestApplyDiff(t *testing.T) {
	db := poiDB(t)
	var ch pm.Change
	if err := xml.NewDecoder(strings.NewReader(osc)).Decode(&ch); err != nil {
		t.Fatal(err)
	}
	bbox, _ := parseBBox(vicBBox)
	ts := time.Date(2026, 11, 16, 20, 21, 0, 0, time.UTC)
	if _, err := apply(db, &ch, applyOpts{seq: 4913, asOf: ts, bbox: bbox}); err != nil {
		t.Fatal(err)
	}

	type row struct {
		name     string
		lat, lon float64
	}
	get := func(id string) *row {
		var r row
		err := db.QueryRow(`SELECT name, lat, lon FROM poi WHERE osm_id=?`, id).Scan(&r.name, &r.lat, &r.lon)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return &r
	}
	indexed := func(id string) bool {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM poi_trgm WHERE osm_id=?`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}

	if r := get("n10"); r == nil || !indexed("n10") {
		t.Error("created POI missing from poi or poi_trgm")
	}
	if get("n11") != nil {
		t.Error("POI outside the region was loaded")
	}
	if get("n1") != nil || indexed("n1") {
		t.Error("untagged delete left the POI in place")
	}
	if get("n2") != nil || indexed("n2") {
		t.Error("modify that removed the name kept the POI")
	}
	if r := get("w3"); r == nil || r.name != "NEW MARKET" || r.lat != -37.7 || r.lon != 145.0 {
		t.Errorf("modified way: %+v, want NEW MARKET at its stored centroid", r)
	}
	if !indexed("w3") {
		t.Error("modified way not reindexed")
	}
	var match string
	if err := db.QueryRow(`SELECT osm_id FROM poi_trgm WHERE poi_trgm MATCH 'MARKET' AND name LIKE 'NEW%'`).Scan(&match); err != nil {
		t.Errorf("new way name not searchable: %v", err)
	}
	if r := get("w30"); r == nil || r.lat == 0 || r.lon == 0 {
		t.Errorf("created way: %+v, want a centroid from its nodes", r)
	}
	if get("w31") != nil {
		t.Error("way with no locatable nodes was placed")
	}
	if get("n20") != nil {
		t.Error("untagged node loaded as a POI")
	}
	var seq int64
	var anchor string
	if err := db.QueryRow(`SELECT replication_seq, replication_ts FROM poi_meta`).Scan(&seq, &anchor); err != nil || seq != 4913 || anchor != "2026-11-16T20:21:00Z" {
		t.Errorf("anchor = %d %q (%v)", seq, anchor, err)
	}
}

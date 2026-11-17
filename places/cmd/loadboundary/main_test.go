package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"auplaces/internal/boundary"
	"auplaces/internal/match"
	"auplaces/internal/schema"
)

// ring returns a closed axis-aligned square. cw picks the shapefile winding:
// clockwise for an outer ring, anticlockwise for a hole.
func ring(x0, y0, x1, y1 float64, cw bool) []boundary.Point {
	p := func(x, y float64) boundary.Point { return boundary.Point{X: x, Y: y} }
	if cw {
		return []boundary.Point{p(x0, y0), p(x0, y1), p(x1, y1), p(x1, y0), p(x0, y0)}
	}
	return []boundary.Point{p(x0, y0), p(x1, y0), p(x1, y1), p(x0, y1), p(x0, y0)}
}

func loc(pid, name string, parts ...[]boundary.Point) boundary.Locality {
	return boundary.Locality{LocPID: pid, Name: name, LocClass: "G", Polygon: boundary.Polygon{Parts: parts}}
}

// fixture is locality A, a square with a hole, and locality B filling the
// hole: the enclave layout that used to come back as [A, A, B]. A's hole comes
// first in the part list to show that part order does not decide which ring is
// the outer one.
func fixture() []boundary.Locality {
	return []boundary.Locality{
		loc("A", "OUTER", ring(145.2, -37.8, 145.3, -37.7, false), ring(145.0, -38.0, 145.5, -37.5, true)),
		loc("B", "ENCLAVE", ring(145.2, -37.8, 145.3, -37.7, true)),
		// C has two islands, and the second sits in a hole of the first: a
		// point there is in C even though it is in C's hole.
		loc("C", "LAKE", ring(146.0, -38.0, 146.5, -37.5, true), ring(146.1, -37.9, 146.4, -37.6, false),
			ring(146.2, -37.8, 146.3, -37.7, true)),
	}
}

func openTemp(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func pids(hits []match.LocalityHit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.LocPID)
	}
	return out
}

func TestEnclaveReturnsOnlyTheEnclave(t *testing.T) {
	db := openTemp(t)
	if _, err := load(db, fixture(), nil, false); err != nil {
		t.Fatalf("load: %v", err)
	}
	ctx := context.Background()
	cases := []struct {
		name     string
		lon, lat float64
		want     []string
	}{
		{"in enclave", 145.25, -37.75, []string{"B"}},
		{"in outer, outside hole", 145.1, -37.9, []string{"A"}},
		{"outside everything", 144.0, -37.0, nil},
		{"lake: in hole of first ring", 146.15, -37.85, nil},
		{"lake: island inside the hole", 146.25, -37.75, []string{"C"}},
		{"lake: mainland", 146.05, -37.95, []string{"C"}},
	}
	for _, c := range cases {
		hits, err := match.LocalityAt(ctx, db, c.lon, c.lat, 3)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := pids(hits); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// geopoly_contains_point cannot use the R-Tree; the lookup must go through
// geopoly_overlap so it is not a scan of every polygon in the state.
func TestLocalityLookupUsesTheIndex(t *testing.T) {
	db := openTemp(t)
	if _, err := load(db, fixture(), nil, false); err != nil {
		t.Fatal(err)
	}
	// The same WHERE shape match.LocalityAt uses, with a bound probe.
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT rowid FROM boundary
		WHERE geopoly_overlap(_shape, ?) AND geopoly_contains_point(_shape, 0.5, 0.5)`, "[[0,0],[1,0],[1,1],[0,0]]")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	p := strings.Join(plan, "; ")
	if strings.Contains(p, "fullscan") || !strings.Contains(p, ":rtree") {
		t.Errorf("plan is a full scan: %s", p)
	}
}

// A failure partway through must leave the previous tables exactly as they
// were: no committed boundary table alongside a missing outline table.
func TestLoadIsAllOrNothing(t *testing.T) {
	db := openTemp(t)
	outs, breaches := computeOutlines(fixture(), boundary.Options{})
	if len(breaches) > 0 {
		t.Fatalf("breaches: %v", breaches)
	}
	if _, err := load(db, fixture(), outs, true); err != nil {
		t.Fatalf("first load: %v", err)
	}
	var before int
	if err := db.QueryRow(`SELECT count(*) FROM boundary`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	// The second load drops and refills both tables, then fails on a
	// duplicate outline key at the very end.
	dup := append(outs, outs[0])
	if _, err := load(db, fixture()[:1], dup, true); err == nil {
		t.Fatal("want error from duplicate outline")
	}
	var after, outlines int
	if err := db.QueryRow(`SELECT count(*) FROM boundary`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM locality_outline`).Scan(&outlines); err != nil {
		t.Fatal(err)
	}
	if after != before || outlines != len(outs) {
		t.Errorf("failed load leaked: boundary %d -> %d rows, outlines %d (want %d)", before, after, outlines, len(outs))
	}
}

func TestOpenWriterRefusesAServedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "served.db")
	release, err := schema.LockServing(path)
	if err == nil {
		t.Fatal("LockServing on a missing file should fail")
	}
	db, rel, err := schema.OpenWriter(path)
	if err != nil {
		t.Fatalf("OpenWriter on a fresh path: %v", err)
	}
	db.Close()
	rel()

	release, err = schema.LockServing(path)
	if err != nil {
		t.Fatalf("LockServing: %v", err)
	}
	if _, _, err := schema.OpenWriter(path); err == nil {
		t.Fatal("OpenWriter succeeded on a file a server holds")
	}
	release()
	db, rel, err = schema.OpenWriter(path)
	if err != nil {
		t.Fatalf("OpenWriter after the server let go: %v", err)
	}
	db.Close()
	rel()
}

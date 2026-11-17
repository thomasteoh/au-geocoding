package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/boundary"
	"auplaces/internal/match"
)

func sq(x0, y0, x1, y1 float64, cw bool) []boundary.Point {
	p := func(x, y float64) boundary.Point { return boundary.Point{X: x, Y: y} }
	if cw {
		return []boundary.Point{p(x0, y0), p(x0, y1), p(x1, y1), p(x1, y0), p(x0, y0)}
	}
	return []boundary.Point{p(x0, y0), p(x1, y0), p(x1, y1), p(x0, y1), p(x0, y0)}
}

func rec(code string, parts ...[]boundary.Point) boundary.Locality {
	return boundary.Locality{Attrs: map[string]string{"POA_CODE21": code, "AREASQKM21": "12.5"},
		Polygon: boundary.Polygon{Parts: parts}}
}

func TestLoadPostcodes(t *testing.T) {
	recs := []boundary.Locality{
		// 3999 is a square with a hole that 3998 fills.
		rec("3999", sq(145.0, -38.0, 145.5, -37.5, true), sq(145.2, -37.8, 145.3, -37.7, false)),
		rec("3998", sq(145.2, -37.8, 145.3, -37.7, true)),
		rec("2000", sq(151.0, -34.0, 151.1, -33.9, true)), // another state
		rec("3997"), // null shape
	}
	areas := selectAreas(recs, []string{"3"})
	if len(areas) != 2 {
		t.Fatalf("selected %d areas, want 2", len(areas))
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := load(db, areas, "VIC")
	if err != nil {
		t.Fatal(err)
	}
	if st.postcodes != 2 || st.holes != 1 {
		t.Errorf("stats %+v", st)
	}
	ctx := context.Background()
	for _, c := range []struct {
		lon, lat float64
		want     string
	}{
		{145.1, -37.6, "3999"},
		{145.25, -37.75, "3998"}, // in 3999's hole
		{146.0, -37.0, ""},
	} {
		hits, err := match.PostcodeAt(ctx, db, c.lon, c.lat)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if len(hits) > 0 {
			got = hits[0].Postcode
		}
		if got != c.want || len(hits) > 1 {
			t.Errorf("PostcodeAt(%v, %v) = %v, want %q", c.lon, c.lat, hits, c.want)
		}
	}
	// The representative point of the holed square is inside it, not in the hole.
	lat, lon, ok, err := match.PostcodePoint(ctx, db, "3999")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if in, known, _ := match.PostcodeContains(ctx, db, "3999", lon, lat); !in || !known {
		t.Errorf("3999 representative point %v,%v is not inside 3999", lat, lon)
	}
}

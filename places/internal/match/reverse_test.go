package match

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

// reverseDB holds a dense 20x20 grid of addresses ~11 m apart around a point
// in Melbourne, plus one address 3 km away.
func reverseDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(schema.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE VIRTUAL TABLE addr_rt USING rtree(id, min_lat, max_lat, min_lon, max_lon)`); err != nil {
		t.Fatal(err)
	}
	ins := `INSERT INTO address (gnaf_pid, street_number, street_name, locality_name, state, latitude, longitude, confidence, geocode_rel)
		VALUES (?, ?, 'TEST', 'MELBOURNE', 'VIC', ?, ?, 2, 6)`
	for i := 0; i < 20; i++ {
		for j := 0; j < 20; j++ {
			lat, lon := -37.81+float64(i)*0.0001, 144.96+float64(j)*0.0001
			if _, err := db.Exec(ins, fmt.Sprintf("G%02d%02d", i, j), fmt.Sprint(i*20+j), lat, lon); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.Exec(ins, "FAR", "1", -37.78, 144.96); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO addr_rt SELECT rowid, latitude, latitude, longitude, longitude FROM address`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestReverseHonoursLimit(t *testing.T) {
	db := reverseDB(t)
	res, err := Reverse(context.Background(), db, 144.961, -37.809, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d results, want 2", len(res))
	}
	if res[0].PID != "G1010" || res[0].DistanceM > res[1].DistanceM {
		t.Errorf("not nearest-first: %s %.1fm, %s %.1fm", res[0].PID, res[0].DistanceM, res[1].PID, res[1].DistanceM)
	}
}

func TestReverseHonoursRadius(t *testing.T) {
	db := reverseDB(t)
	ctx := context.Background()
	// 1 km north of the grid: only FAR is within 2.5 km, nothing within 500 m.
	lon, lat := 144.96, -37.79
	if res, err := ReverseWithin(ctx, db, lon, lat, 5, 500); err != nil || len(res) != 0 {
		t.Errorf("500 m radius: %d results (%v), want 0", len(res), err)
	}
	res, err := ReverseWithin(ctx, db, lon, lat, 5, 2500)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.DistanceM > 2500 {
			t.Errorf("%s at %.0f m is outside the 2500 m radius", r.PID, r.DistanceM)
		}
	}
	if len(res) != 5 {
		t.Errorf("2500 m radius: %d results, want 5", len(res))
	}
}

// The tight bbox can hold rows that are not the nearest: one in a bbox corner
// is further than one just outside an edge. Results must be the true nearest.
func TestReverseReturnsTrueNearest(t *testing.T) {
	db := reverseDB(t)
	res, err := ReverseWithin(context.Background(), db, 144.96, -37.7805, 1, 0)
	if err != nil || len(res) != 1 || res[0].PID != "FAR" {
		t.Fatalf("got %v, %v; want FAR", res, err)
	}
}

func TestClampReverseRadius(t *testing.T) {
	for in, want := range map[float64]float64{0: DefaultReverseRadiusM, -5: DefaultReverseRadiusM, 300: 300, 1e9: MaxReverseRadiusM} {
		if got := ClampReverseRadius(in); got != want {
			t.Errorf("ClampReverseRadius(%v) = %v, want %v", in, got, want)
		}
	}
}

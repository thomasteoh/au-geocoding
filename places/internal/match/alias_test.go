package match

import (
	"context"
	"database/sql"
	"reflect"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

func aliasDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{schema.SchemaSQL, schema.AliasSchemaSQL,
		`INSERT INTO address (gnaf_pid, street_number, street_name, street_type, locality_name, state, postcode, latitude, longitude, confidence, geocode_rel)
		 VALUES ('A1', '211', 'WELLINGTON', 'PARADE', 'EAST MELBOURNE', 'VIC', '3002', -37.81, 144.98, 2, 6),
		        ('A2', '4', 'QUEBEC', 'AVENUE', 'WERRIBEE', 'VIC', '3030', -37.9, 144.66, 2, 6),
		        ('A3', '1', 'VALDA', 'WAY', 'WERRIBEE', 'VIC', '3030', -37.9, 144.66, 2, 6)`,
		`INSERT INTO alias_locality VALUES ('JOLIMONT', 'EAST MELBOURNE', 'VIC')`,
		`INSERT INTO alias_street VALUES ('LONERGAN', 'AVENUE', 'WERRIBEE', 'QUEBEC', 'AVENUE'),
		        ('TAVISTOCK', 'STREET', 'WERRIBEE', 'VALDA', 'WAY'),
		        ('QUEBEC', 'STREET', 'WERRIBEE', 'VALDA', 'WAY')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestCanonicalTokens(t *testing.T) {
	fs, err := LoadFuzzySet(context.Background(), aliasDB(t))
	if err != nil {
		t.Fatal(err)
	}
	if !fs.Localities()["JOLIMONT"] || !fs.Localities()["EAST MELBOURNE"] {
		t.Errorf("Localities() lacks the alias or the official name")
	}
	if name, sim := fs.NearestLocality("JOLIMNT"); name != "JOLIMONT" || sim < 0.8 {
		t.Errorf("NearestLocality(JOLIMNT) = %q %v", name, sim)
	}
	cases := []struct {
		rel, score, fields []string
		wantRel, wantScore []string
	}{
		{ // locality alias, in anchors and score
			[]string{"WELLINGTON", "JOLIMONT"}, []string{"211", "WELLINGTON", "PARADE", "JOLIMONT"},
			[]string{"street_number", "street_name", "street_type", "locality_name"},
			[]string{"WELLINGTON", "EAST MELBOURNE"}, []string{"211", "WELLINGTON", "PARADE", "EAST MELBOURNE"},
		},
		{ // street alias with a different official type
			[]string{"TAVISTOCK", "WERRIBEE"}, []string{"TAVISTOCK", "STREET", "WERRIBEE"},
			[]string{"street_name", "street_type", "locality_name"},
			[]string{"VALDA", "WERRIBEE"}, []string{"VALDA", "WAY", "WERRIBEE"},
		},
		{ // a real street in the locality is never replaced by an alias of that name
			[]string{"QUEBEC", "WERRIBEE"}, []string{"4", "QUEBEC", "STREET", "WERRIBEE"},
			[]string{"street_number", "street_name", "street_type", "locality_name"},
			[]string{"QUEBEC", "WERRIBEE"}, []string{"4", "QUEBEC", "STREET", "WERRIBEE"},
		},
		{ // no alias: unchanged
			[]string{"VALDA", "WERRIBEE"}, []string{"VALDA", "WAY", "WERRIBEE"},
			[]string{"street_name", "street_type", "locality_name"},
			[]string{"VALDA", "WERRIBEE"}, []string{"VALDA", "WAY", "WERRIBEE"},
		},
	}
	for _, c := range cases {
		rel, score, _ := fs.CanonicalTokens(c.rel, c.score, c.fields)
		if !reflect.DeepEqual(rel, c.wantRel) || !reflect.DeepEqual(score, c.wantScore) {
			t.Errorf("CanonicalTokens(%v) = %v %v; want %v %v", c.score, rel, score, c.wantRel, c.wantScore)
		}
	}
}

// A dataset without the alias tables loads, with no aliases.
func TestLoadFuzzySetWithoutAliases(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.Exec(schema.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	fs, err := LoadFuzzySet(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	rel, score, _ := fs.CanonicalTokens([]string{"X"}, []string{"X"}, []string{"locality_name"})
	if rel[0] != "X" || score[0] != "X" {
		t.Error("tokens changed with no aliases")
	}
}

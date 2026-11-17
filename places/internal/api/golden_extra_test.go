package api

import (
	"compress/gzip"
	"database/sql"
	"io"
	"os"
	"testing"

	"auplaces/internal/schema"
)

// loadFixtureExtra creates the alias and postcode tables in a fixture dataset
// and runs the INSERTs cmd/goldenfixture wrote for them. A fixture built
// before they existed has no extra file; the tables then stay empty.
func loadFixtureExtra(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	for _, s := range []string{schema.AliasSchemaSQL, schema.PostcodeSchemaSQL} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(b)); err != nil {
		t.Fatal(err)
	}
}

// levelKeyColumn is the address column holding the level, or an empty
// literal on a dataset built before levels were carried.
func levelKeyColumn(db *sql.DB) string {
	var n int
	db.QueryRow(`SELECT count(*) FROM pragma_table_info('address') WHERE name = 'level_number'`).Scan(&n)
	if n == 0 {
		return `''`
	}
	return `level_number`
}

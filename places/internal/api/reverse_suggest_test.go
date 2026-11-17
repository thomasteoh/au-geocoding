package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

func memDB(t *testing.T, stmts ...string) *sql.DB {
	t.Helper()
	// A file, not :memory:, so the pool can hold several connections:
	// Suggest reads the dataset version while its result rows are open.
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// A '"' in the prefix must be escaped inside the FTS5 phrase; unescaped it
// broke the MATCH expression and the whole lookup came back empty.
func TestSuggestEscapesQuotes(t *testing.T) {
	db := memDB(t, `CREATE VIRTUAL TABLE suggest_idx USING fts5(
			street_locality_pid UNINDEXED, locality_pid UNINDEXED,
			street_name, street_type, locality_name, postcode, state,
			tokenize='ascii', prefix='2 3 4')`,
		`INSERT INTO suggest_idx VALUES ('SL1', 'L1', 'STATION', 'STREET', 'BRIGHTON', '3186', 'VIC')`)
	for _, prefix := range []string{`"station brighton`, `station" "bri`} {
		resp := Suggest(context.Background(), db, SuggestRequest{Prefix: prefix})
		if len(resp.Suggestions) != 1 {
			t.Errorf("%q: %d suggestions, want 1", prefix, len(resp.Suggestions))
		}
	}
}

// /reverse caps the caller's limit, and the cap is what comes back.
func TestReverseHandlerClampsLimit(t *testing.T) {
	stmts := []string{schema.SchemaSQL,
		`CREATE VIRTUAL TABLE addr_rt USING rtree(id, min_lat, max_lat, min_lon, max_lon)`}
	for i := 0; i < 50; i++ {
		stmts = append(stmts, fmt.Sprintf(`INSERT INTO address (gnaf_pid, street_number, street_name, locality_name, state, latitude, longitude, confidence, geocode_rel)
			VALUES ('G%d', '%d', 'TEST', 'MELBOURNE', 'VIC', %f, 144.96, 2, 6)`, i, i, -37.81+float64(i)*0.00001))
	}
	stmts = append(stmts, `INSERT INTO addr_rt SELECT rowid, latitude, latitude, longitude, longitude FROM address`)
	db := memDB(t, stmts...)
	h := ReverseHandler(NewDBProvider(db, "test"))
	for limit, want := range map[int]int{2: 2, 1000: maxReverseLimit} {
		body := fmt.Sprintf(`{"latitude":-37.81,"longitude":144.96,"limit":%d}`, limit)
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/reverse", strings.NewReader(body)))
		var resp ReverseResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Candidates) != want {
			t.Errorf("limit %d: %d candidates, want %d", limit, len(resp.Candidates), want)
		}
	}
}

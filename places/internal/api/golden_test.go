package api

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/csv"
	"io"
	"os"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
	"ausystem/shared/contract"
	"ausystem/shared/normalise"
)

// TestGolden runs testdata/golden.tsv through both entry points: /search's
// free-text path, and /resolve fed the tokens the geocoder's normaliser
// produces (the production path). By default it runs against
// testdata/golden_fixture.tsv.gz, a few thousand real rows around the golden
// addresses; AUPLACES_GOLDEN_DB names a full dataset instead, opened read-only.
func TestGolden(t *testing.T) {
	var db *sql.DB
	if path := os.Getenv("AUPLACES_GOLDEN_DB"); path != "" {
		var err error
		if db, err = sql.Open("sqlite", "file:"+path+"?mode=ro"); err != nil {
			t.Fatal(err)
		}
		defer db.Close()
	} else {
		db = fixtureDB(t, "../../testdata/golden_fixture.tsv.gz")
	}
	ctx := context.Background()

	cases := loadGolden(t, "../../testdata/golden.tsv")
	var searchOK, searchN, resolveOK int
	for _, c := range cases {
		coarse := c.want == "(none)" || c.want == "(out_of_scope)" || strings.Contains(c.want, ":")
		if !coarse {
			searchN++
			got := ""
			if resp := Search(ctx, db, SearchRequest{Query: c.query}); len(resp.Candidates) > 0 {
				got = addressKey(t, db, resp.Candidates[0].ID, c.want)
			}
			if got == c.want {
				searchOK++
			} else {
				t.Errorf("search  %-40q got %-45q want %q", c.query, got, c.want)
			}
		}

		got := "(none)"
		n := normalise.Normalise(c.query)
		if len(n.Tokens) > 0 { // the ladder's address-rung gate
			resp, err := Resolve(ctx, db, contract.ResolveRequest{
				Kind: contract.KindAddress, Generate: n.Generate, Score: n.Tokens,
				State: n.State, Postcode: n.Postcode, Limit: 20,
			})
			if err != nil && err.Error() == errOutOfScope {
				got = "(out_of_scope)"
			}
			if err == nil && len(resp.Candidates) > 0 {
				top := resp.Candidates[0]
				switch {
				case top.Precision == contract.PrecisionAddress:
					got = addressKey(t, db, top.GnafPID, c.want)
				case top.PostalDelivery != "":
					got = top.PostalDelivery + "@" + top.ID.PID
				default:
					got = top.ID.PID
				}
			}
		}
		if got == c.want {
			resolveOK++
		} else {
			t.Errorf("resolve %-40q got %-45q want %q", c.query, got, c.want)
		}
	}
	t.Logf("search %d/%d, resolve %d/%d", searchOK, searchN, resolveOK, len(cases))
}

type goldenCase struct{ query, want string }

func loadGolden(t *testing.T, path string) []goldenCase {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []goldenCase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		q, want, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("bad golden line %q", line)
		}
		out = append(out, goldenCase{q, want})
	}
	return out
}

// addressKey is the key for a PID in the form want uses. The street address
// is number|street|type|locality, and any row there will do; a fifth part
// names the row: "unit N", "lot N" for a lot with no street number, or empty
// for the base address (no unit).
func addressKey(t *testing.T, db *sql.DB, pid, want string) string {
	t.Helper()
	var num, flat, lot, name, typ, loc sql.NullString
	err := db.QueryRow(`SELECT street_number, flat_number, lot_number, street_name, street_type, locality_name
		FROM address WHERE gnaf_pid = ?`, pid).Scan(&num, &flat, &lot, &name, &typ, &loc)
	if err != nil {
		return "(lookup " + pid + ": " + err.Error() + ")"
	}
	key := num.String + "|" + name.String + "|" + typ.String + "|" + loc.String
	if strings.Count(want, "|") < 4 {
		return key
	}
	switch {
	case flat.String != "":
		return key + "|unit " + flat.String
	case lot.String != "" && num.String == "":
		return key + "|lot " + lot.String
	}
	return key + "|"
}

// fixtureDB loads a golden fixture (gzipped TSV of address rows, in the
// column order of fixtureColumns) into an in-memory dataset with the same
// schema and indexes the loader builds.
func fixtureDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(schema.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO address (` + fixtureColumns + `)
		VALUES (?` + strings.Repeat(", ?", fixtureColumnCount-1) + `)`)
	if err != nil {
		t.Fatal(err)
	}
	r := csv.NewReader(zr)
	r.Comma = '\t'
	r.FieldsPerRecord = fixtureColumnCount
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		args := make([]any, len(rec))
		for i, v := range rec {
			args[i] = v
		}
		if _, err := stmt.Exec(args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO addr_trgm (gnaf_pid, street_number, street_name, locality_name, state, postcode)
		SELECT gnaf_pid, street_number, street_name, locality_name, state, postcode FROM address`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return db
}

// fixtureColumns is the address column order in the golden fixture; it must
// match cmd/goldenfixture.
const fixtureColumns = `gnaf_pid, street_number, street_name, street_type, locality_name,
	state, postcode, latitude, longitude, confidence, geocode_rel,
	flat_number, lot_number, primary_sec`

const fixtureColumnCount = 14

package api

import (
	"bufio"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"ausystem/shared/contract"
	"ausystem/shared/normalise"
)

// TestGolden runs testdata/golden.tsv against a real G-NAF dataset through both
// entry points: /search's free-text path, and /resolve fed the tokens the
// geocoder's normaliser produces (the production path). It needs the real
// dataset, so it only runs when AUPLACES_GOLDEN_DB names one; the dataset is
// opened read-only.
func TestGolden(t *testing.T) {
	path := os.Getenv("AUPLACES_GOLDEN_DB")
	if path == "" {
		t.Skip("AUPLACES_GOLDEN_DB not set")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()

	cases := loadGolden(t, "../../testdata/golden.tsv")
	var searchOK, resolveOK int
	for _, c := range cases {
		got := ""
		if resp := Search(ctx, db, SearchRequest{Query: c.query}); len(resp.Candidates) > 0 {
			got = streetKey(t, db, resp.Candidates[0].ID)
		}
		if got == c.want {
			searchOK++
		} else {
			t.Errorf("search  %-40q got %-45q want %q", c.query, got, c.want)
		}

		got = ""
		n := normalise.Normalise(c.query)
		if n.HadStreet && n.HadNumbers { // the ladder's address-rung gate
			resp, err := Resolve(ctx, db, contract.ResolveRequest{
				Kind: contract.KindAddress, Generate: n.Generate, Score: n.Tokens,
				State: n.State, Postcode: n.Postcode, Limit: 20,
			})
			if err == nil && len(resp.Candidates) > 0 {
				got = streetKey(t, db, resp.Candidates[0].GnafPID)
			}
		} else {
			got = "(address rung skipped)"
		}
		if got == c.want {
			resolveOK++
		} else {
			t.Errorf("resolve %-40q got %-45q want %q", c.query, got, c.want)
		}
	}
	t.Logf("search %d/%d, resolve %d/%d", searchOK, len(cases), resolveOK, len(cases))
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

// streetKey is the street-address key for a PID: number|street|type|locality.
func streetKey(t *testing.T, db *sql.DB, pid string) string {
	t.Helper()
	var num, name, typ, loc sql.NullString
	err := db.QueryRow(`SELECT street_number, street_name, street_type, locality_name
		FROM address WHERE gnaf_pid = ?`, pid).Scan(&num, &name, &typ, &loc)
	if err != nil {
		return "(lookup " + pid + ": " + err.Error() + ")"
	}
	return num.String + "|" + name.String + "|" + typ.String + "|" + loc.String
}

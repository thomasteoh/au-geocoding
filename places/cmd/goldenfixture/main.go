// goldenfixture extracts the address rows the golden set needs from a real
// dataset into testdata/golden_fixture.tsv.gz, so the golden test runs in CI
// without the full dataset.
//
// For each golden street it keeps every row at the golden number plus enough
// other numbers to exceed the generation cap (so ordered generation is still
// exercised), the same street name in other localities, near-miss street names
// statewide (the misspelling distractors), one row per street in each golden
// locality, and one row per locality statewide (so locality recognition sees
// the full set of names). A lot is kept like a number; units need nothing
// more, since every unit row at a golden number is kept. For an intersection
// it keeps every distinct point of both streets in the locality and around
// it, which is what the meeting point is computed from. Run it again when
// golden.tsv gains a street:
//
//	go run ./cmd/goldenfixture -db /path/to/vic.db
package main

import (
	"bufio"
	"compress/gzip"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	_ "modernc.org/sqlite"

	"auplaces/internal/match"
	"auplaces/internal/postbox"
	"ausystem/shared/streettype"
)

// columns must match fixtureColumns in internal/api/golden_test.go.
const columns = `gnaf_pid, street_number, street_name, COALESCE(street_type, ''), locality_name,
	state, COALESCE(postcode, ''), latitude, longitude, confidence, geocode_rel,
	flat_number, lot_number, primary_sec, level_number`

const ncolumns = 15

func main() {
	dbPath := flag.String("db", "", "real dataset (opened read-only)")
	golden := flag.String("golden", "testdata/golden.tsv", "golden set")
	out := flag.String("out", "testdata/golden_fixture.tsv.gz", "fixture to write")
	extraOut := flag.String("extra", "testdata/golden_fixture_extra.sql.gz", "alias and postcode tables to write")
	perStreet := flag.Int("per-street", 250, "other numbers kept per golden street (above the generation cap)")
	flag.Parse()
	if *dbPath == "" {
		log.Fatal("-db is required")
	}
	db, err := sql.Open("sqlite", "file:"+*dbPath+"?mode=ro")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	type pair struct{ street, locality, number, lot string }
	var pairs []pair
	type cross struct{ a, b, locality string }
	var crosses []cross
	localities, postcodes, streets := map[string]bool{}, map[string]bool{}, map[string]bool{}
	f, err := os.Open(*golden)
	if err != nil {
		log.Fatal(err)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, want, _ := strings.Cut(line, "\t")
		// A postal box answer names the place it fell back to after "@".
		if _, place, ok := strings.Cut(want, "@"); ok {
			want = place
		}
		switch {
		case strings.HasPrefix(want, "intersection:"):
			p := strings.Split(strings.TrimPrefix(want, "intersection:"), "|")
			crosses = append(crosses, cross{streettype.StripSuffix(p[0]), streettype.StripSuffix(p[1]), p[2]})
			localities[p[2]] = true
		case strings.HasPrefix(want, "street:"):
			name, loc, _ := strings.Cut(strings.TrimPrefix(want, "street:"), "|")
			pairs = append(pairs, pair{streettype.StripSuffix(name), loc, "", ""})
		case strings.HasPrefix(want, "locality:"):
			loc, _, _ := strings.Cut(strings.TrimPrefix(want, "locality:"), "|")
			localities[loc] = true
		case strings.HasPrefix(want, "postcode:"):
			postcodes[strings.TrimPrefix(want, "postcode:")] = true
			// A PO box postcode answers at the locality it is delivered at.
			if e, ok := postbox.Lookup(strings.TrimPrefix(want, "postcode:")); ok {
				localities[e.Locality] = true
			}
		case strings.Count(want, "|") >= 3:
			// number|street|type|locality, optionally |unit N or |lot N.
			p := strings.Split(want, "|")
			pr := pair{p[1], p[3], p[0], ""}
			if len(p) > 4 {
				if lot, ok := strings.CutPrefix(p[4], "lot "); ok {
					pr.lot = lot
				}
			}
			pairs = append(pairs, pr)
		}
	}
	f.Close()
	for _, p := range pairs {
		localities[p.locality] = true
		streets[p.street] = true
	}

	rows := map[string][]string{}
	add := func(q string, args ...any) {
		r, err := db.Query(`SELECT `+columns+` FROM address WHERE `+q, args...)
		if err != nil {
			log.Fatalf("%s: %v", q, err)
		}
		defer r.Close()
		for r.Next() {
			v := make([]sql.NullString, ncolumns)
			ptrs := make([]any, ncolumns)
			for i := range v {
				ptrs[i] = &v[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				log.Fatal(err)
			}
			rec := make([]string, ncolumns)
			for i, s := range v {
				rec[i] = s.String
			}
			rows[rec[0]] = rec
		}
		if err := r.Err(); err != nil {
			log.Fatal(err)
		}
	}

	for _, p := range pairs {
		if p.number != "" {
			add(`street_name = ? AND locality_name = ? AND CAST(street_number AS TEXT) = ?`, p.street, p.locality, p.number)
		}
		if p.lot != "" && p.lot != p.number {
			add(`street_name = ? AND locality_name = ? AND lot_number = ?`, p.street, p.locality, p.lot)
		}
		add(`street_name = ? AND locality_name = ? ORDER BY gnaf_pid LIMIT ?`, p.street, p.locality, *perStreet)
	}
	for s := range streets {
		add(`street_name = ? GROUP BY locality_name LIMIT 60`, s)
	}
	// Both streets of an intersection, one row per distinct point, in the
	// locality and within about 300 m of their stretch of it (the margin
	// match.StreetsMeet searches).
	for _, c := range crosses {
		var latMin, latMax, lonMin, lonMax float64
		if err := db.QueryRow(`SELECT MIN(latitude), MAX(latitude), MIN(longitude), MAX(longitude)
			FROM address WHERE street_name IN (?, ?) AND locality_name = ?`, c.a, c.b, c.locality).
			Scan(&latMin, &latMax, &lonMin, &lonMax); err != nil {
			log.Fatalf("intersection %v: %v", c, err)
		}
		const margin = 0.003
		for _, st := range []string{c.a, c.b} {
			add(`street_name = ? AND latitude BETWEEN ? AND ? AND longitude BETWEEN ? AND ?
				GROUP BY locality_name, street_type, latitude, longitude`,
				st, latMin-margin, latMax+margin, lonMin-margin, lonMax+margin)
		}
	}
	// Near-miss street names statewide: what a misspelling might resolve to.
	names, err := db.Query(`SELECT DISTINCT street_name FROM address`)
	if err != nil {
		log.Fatal(err)
	}
	var near []string
	for names.Next() {
		var n string
		if err := names.Scan(&n); err != nil {
			log.Fatal(err)
		}
		for s := range streets {
			if n != s && match.Similarity(n, s) >= 0.75 {
				near = append(near, n)
				break
			}
		}
	}
	names.Close()
	for _, n := range near {
		add(`street_name = ? GROUP BY locality_name LIMIT 10`, n)
	}
	for l := range localities {
		add(`locality_name = ? GROUP BY street_name, street_type LIMIT 400`, l)
	}
	for pc := range postcodes {
		add(`postcode = ? ORDER BY gnaf_pid LIMIT 300`, pc)
	}
	add(`1 GROUP BY locality_name`)

	pids := make([]string, 0, len(rows))
	for pid := range rows {
		pids = append(pids, pid)
	}
	sort.Strings(pids)
	o, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	zw, _ := gzip.NewWriterLevel(o, gzip.BestCompression)
	w := bufio.NewWriter(zw)
	for _, pid := range pids {
		rec := rows[pid]
		for i := 7; i <= 8; i++ { // coordinates to 6 dp (~0.1 m)
			var f float64
			fmt.Sscan(rec[i], &f)
			rec[i] = fmt.Sprintf("%.6f", f)
		}
		fmt.Fprintln(w, strings.Join(rec, "\t"))
	}
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := o.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d rows (%d golden streets, %d intersections, %d near-miss names, %d localities) -> %s\n",
		len(pids), len(streets), len(crosses), len(near), len(localities), *out)
	writeExtra(db, *extraOut, localities, postcodes)
}

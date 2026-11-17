package main

import (
	"bufio"
	"compress/gzip"
	"database/sql"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

// writeExtra writes the non-address tables the golden set needs, as SQL
// INSERTs (the fixture loader creates the tables): every locality alias (the
// parser must see the whole set), the street aliases in golden localities, and
// the postal areas of golden postcodes. A dataset without a table contributes
// nothing for it.
func writeExtra(db *sql.DB, path string, localities, postcodes map[string]bool) {
	o, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	zw, _ := gzip.NewWriterLevel(o, gzip.BestCompression)
	w := bufio.NewWriter(zw)
	n := 0
	dump := func(table, cols, q string, args ...any) {
		rows, err := db.Query(q, args...)
		if err != nil {
			if strings.Contains(err.Error(), "no such table") {
				return
			}
			log.Fatalf("%s: %v", table, err)
		}
		defer rows.Close()
		ncol := len(strings.Split(cols, ","))
		for rows.Next() {
			v := make([]any, ncol)
			ptrs := make([]any, ncol)
			for i := range v {
				ptrs[i] = &v[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				log.Fatal(err)
			}
			lits := make([]string, ncol)
			for i, x := range v {
				lits[i] = sqlLiteral(x)
			}
			fmt.Fprintf(w, "INSERT INTO %s (%s) VALUES (%s);\n", table, cols, strings.Join(lits, ", "))
			n++
		}
		if err := rows.Err(); err != nil {
			log.Fatal(err)
		}
	}
	dump("alias_locality", "alias, locality_name, state",
		`SELECT alias, locality_name, state FROM alias_locality ORDER BY alias`)
	for _, loc := range sortedKeys(localities) {
		dump("alias_street", "alias_name, alias_type, locality_name, street_name, street_type",
			`SELECT alias_name, alias_type, locality_name, street_name, street_type FROM alias_street
			WHERE locality_name = ? ORDER BY alias_name, alias_type`, loc)
	}
	for _, pc := range sortedKeys(postcodes) {
		dump("postcode", "postcode, state, rep_lat, rep_lon, area_km2, source",
			`SELECT postcode, state, rep_lat, rep_lon, area_km2, source FROM postcode WHERE postcode = ?`, pc)
		dump("postcode_shape", "rowid, _shape, postcode",
			`SELECT rowid, geopoly_json(_shape), postcode FROM postcode_shape WHERE postcode = ? ORDER BY rowid`, pc)
		dump("postcode_shape_hole", "_shape, outer_id, postcode",
			`SELECT geopoly_json(_shape), outer_id, postcode FROM postcode_shape_hole WHERE postcode = ? ORDER BY rowid`, pc)
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
	fmt.Printf("%d alias and postcode rows -> %s\n", n, path)
}

func sqlLiteral(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case int64:
		return fmt.Sprint(x)
	case float64:
		return fmt.Sprintf("%.8f", x)
	case []byte:
		return "'" + strings.ReplaceAll(string(x), "'", "''") + "'"
	default:
		return "'" + strings.ReplaceAll(fmt.Sprint(x), "'", "''") + "'"
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

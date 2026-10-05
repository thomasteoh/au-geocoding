package schema

import (
	"database/sql"
	"fmt"
	"math/rand"
	"strings"
)

// SeedSynthetic fills the schema with Victoria-shaped synthetic rows so the
// spike can exercise the pipeline without the 10GB G-NAF download.
// Shape: real Melbourne suburbs, real-ish street names, a small locality set
// so generation breadth is bounded (INV-8 testable at small scale).

type Row struct {
	PID, StreetNumber, StreetName, StreetType, Locality, State, Postcode string
	Lat, Lon                                                             float64
	Confidence, GeocodeRel                                               int
	PrimarySec, Alias                                                    string
}

// LocalitySeed is the anchor set. Real names so normalise aliases work.
var LocalitySeed = []string{
	"Melbourne", "Richmond", "Fitzroy", "Collingwood", "Carlton", "Southbank",
	"Docklands", "Brunswick", "Northcote", "Preston", "Thornbury", "Coburg",
	"Kensington", "Flemington", "Footscray", "Yarraville", "Seddon", "Newport",
	"Williamstown", "Altona", "Sunshine", "Ascot Vale", "Essendon", "Moonee Ponds",
}

var StreetSeed = []string{
	"Collins", "Elizabeth", "Swanston", "Flinders", "Bourke", "Collins", "Lonsdale",
	"Little Collins", "Little Bourke", "Russell", "A'Beckett", "Spring", "Exhibition",
	"Victoria", "Queen", "Elizabeth", "Barkly", "Bridge", "Smith", "Gertrude",
	"Brunswick", "Sydney", "Napier", "Johnston", "Fitzroy", "High", "Church",
}

// gen deterministically builds a synthetic set. rand is passed for reproducibility.
func gen(r *rand.Rand, n int) []Row {
	rows := make([]Row, 0, n)
	for i := 0; i < n; i++ {
		loc := LocalitySeed[r.Intn(len(LocalitySeed))]
		st := StreetSeed[r.Intn(len(StreetSeed))]
		num := fmt.Sprintf("%d", r.Intn(120)+1)
		// A few empty street numbers (rural-style) — normalise must tolerate.
		if r.Intn(20) == 0 {
			num = ""
		}
		// A few aliases.
		alias := ""
		if r.Intn(15) == 0 {
			alias = "alias:" + st
		}
		rows = append(rows, Row{
			PID:          fmt.Sprintf("GAVIC%09d", i),
			StreetNumber: num,
			StreetName:   st,
			StreetType:   streetType(r),
			Locality:     loc,
			State:        "VIC",
			Postcode:     postcodeFor(loc),
			Lat:          -37.8 + float64(r.Intn(1000))/100000,
			Lon:          144.9 + float64(r.Intn(1000))/100000,
			Confidence:   r.Intn(3), // 0..2
			GeocodeRel:   r.Intn(6) + 1,
			PrimarySec:   "P",
			Alias:        alias,
		})
	}
	return rows
}

func streetType(r *rand.Rand) string {
	switch r.Intn(8) {
	case 0:
		return "STREET"
	case 1:
		return "ROAD"
	case 2:
		return "AVENUE"
	case 3:
		return "PARADE"
	default:
		return "STREET"
	}
}

func postcodeFor(loc string) string {
	// Real-ish Melbourne postcodes, keyed loosely.
	m := map[string]string{
		"Melbourne": "3000", "Richmond": "3121", "Fitzroy": "3065",
		"Collingwood": "3066", "Carlton": "3053", "Southbank": "3006",
		"Docklands": "3008", "Brunswick": "3056", "Northcote": "3070",
		"Preston": "3072", "Thornbury": "3048", "Coburg": "3058",
		"Kensington": "3031", "Flemington": "3031", "Footscray": "3011",
		"Yarraville": "3013", "Seddon": "3011", "Newport": "3015",
		"Williamstown": "3016", "Altona": "3018", "Sunshine": "3020",
		"Ascot Vale": "3032", "Essendon": "3040", "Moonee Ponds": "3039",
	}
	if p, ok := m[loc]; ok {
		return p
	}
	return "3000"
}

// InsertRows loads rows into the schema's tables. Batch inserts for speed.
func InsertRows(db *sql.DB, rows []Row) error {
	// Deterministic order; the matcher needs a stable set for the spike.
	for i, r := range rows {
		_, err := db.Exec(`INSERT INTO address (
			gnaf_pid, street_number, street_name, street_type, locality_name,
			state, postcode, latitude, longitude, confidence, geocode_rel,
			primary_sec, address_alias
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.PID, r.StreetNumber, r.StreetName, r.StreetType, r.Locality,
			r.State, r.Postcode, r.Lat, r.Lon, r.Confidence, r.GeocodeRel,
			r.PrimarySec, r.Alias,
		)
		if err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
		// Mirror into the trigram index. FTS5 content='' means external content;
		// we insert via the special 'rebuild' or direct. For the spike, simplest
		// is a direct INSERT into the trigram table.
		_, err = db.Exec(`INSERT INTO addr_trgm (gnaf_pid, street_number, street_name, locality_name, state, postcode)
			VALUES (?,?,?,?,?,?)`,
			r.PID, r.StreetNumber, r.StreetName, r.Locality, r.State, r.Postcode,
		)
		if err != nil {
			return fmt.Errorf("trgm row %d: %w", i, err)
		}
	}
	return nil
}

// BuildSynthetic opens a temp SQLite DB, creates schema, seeds, returns DB.
func BuildSynthetic(dbPath string, n int, seed int64) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(SchemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	r := rand.New(rand.NewSource(seed))
	rows := gen(r, n)
	if err := InsertRows(db, rows); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

var _ = strings.TrimSpace

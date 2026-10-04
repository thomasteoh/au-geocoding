// scenedata is a build-time extractor. It reads data/vic.db read-only and
// writes the JSON data files used by the animated geocoding explainer.
//
// INV-4 (read-only): the extractor never writes the DB — it opens the file
// read-only and sets PRAGMA query_only=ON, mirroring cmd/server.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const (
	dbPath = "data/vic.db"
	outDir = "cmd/server/static/data"

	// scene4 window bounds (verified in findings.md).
	latMin = -37.8011
	latMax = -37.7497
	lonMin = 145.156
	lonMax = 145.169

	// Out-of-window sampling: keep every Nth row of the full street set.
	sampleEvery = 100

	// Out-of-window quantization: 3 decimals (in-window stays 4).
	outQuant = 3
)

type pt struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type scene4 struct {
	Doncaster []pt `json:"doncaster"`
	Blackburn []pt `json:"blackburn"`
	Window    struct {
		LatMin float64 `json:"latMin"`
		LatMax float64 `json:"latMax"`
		LonMin float64 `json:"lonMin"`
		LonMax float64 `json:"lonMax"`
	} `json:"window"`
}

// scene5 and panelB are verified values from findings.md — hard-coded, NOT
// re-queried from the DB (the values are fixed and verified).
type scene5 struct {
	Anchor struct {
		Lat float64 `json:"lat"`
		Lon float64 `json:"lon"`
	} `json:"anchor"`
	Candidates []struct {
		ID         string  `json:"id,omitempty"`
		Name       string  `json:"name"`
		Lat        float64 `json:"lat"`
		Lon        float64 `json:"lon"`
		DistanceM  int     `json:"distanceM"`
	} `json:"candidates"`
}

type panelB struct {
	Name                string  `json:"name"`
	Candidates          int     `json:"candidates"`
	States              int     `json:"states"`
	Percentages         struct {
		Base          float64 `json:"base"`
		State         float64 `json:"state"`
		StatePostcode float64 `json:"statePostcode"`
	} `json:"percentages"`
	WithinStateRepeats int `json:"withinStateRepeats"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("scenedata: %v", err)
	}
}

func run() error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	// Read-only (INV-4): never write the serving dataset.
	if _, err := db.Exec(`PRAGMA query_only=ON`); err != nil {
		return fmt.Errorf("query_only: %w", err)
	}

	// --- scene4.json: DONCASTER / BLACKBURN, in-window full + out-of-window sampled ---
	s4, err := buildScene4(db)
	if err != nil {
		return err
	}
	// Compact JSON for scene4 — the point payload is large; pretty-printing
	// isn't needed (the animation reads it programmatically).
	if err := writeCompactJSON(outDir+"/scene4.json", s4); err != nil {
		return err
	}
	log.Printf("scene4: donner=%d blackburn=%d (in-window %d/%d, sampled out %d/%d)",
		len(s4.Doncaster), len(s4.Blackburn), s4.doncIn(), s4.blackIn(),
		len(s4.Doncaster)-s4.doncIn(), len(s4.Blackburn)-s4.blackIn())

	// --- scene5.json: POI candidates near the anchor (verified, hard-coded) ---
	s5 := scene5{}
	s5.Anchor.Lat = -37.78834
	s5.Anchor.Lon = 145.16195
	s5.Candidates = append(s5.Candidates, struct {
		ID        string  `json:"id,omitempty"`
		Name      string  `json:"name"`
		Lat       float64 `json:"lat"`
		Lon       float64 `json:"lon"`
		DistanceM int     `json:"distanceM"`
	}{ID: "w1185033336", Name: "Woolworths Doncaster", Lat: -37.7894, Lon: 145.1582, DistanceM: 347})
	s5.Candidates = append(s5.Candidates, struct {
		ID        string  `json:"id,omitempty"`
		Name      string  `json:"name"`
		Lat       float64 `json:"lat"`
		Lon       float64 `json:"lon"`
		DistanceM int     `json:"distanceM"`
	}{Name: "Woolworths Devon Plaza", Lat: -37.7856, Lon: 145.1673, DistanceM: 915})
	if err := writeJSON(outDir+"/scene5.json", s5); err != nil {
		return err
	}
	log.Printf("scene5: %d candidates", len(s5.Candidates))

	// --- panelB.json: locality ambiguity facts (verified, hard-coded) ---
	pb := panelB{Name: "RED HILL", Candidates: 11, States: 5, WithinStateRepeats: 332}
	pb.Percentages.Base = 16.17
	pb.Percentages.State = 4.24
	pb.Percentages.StatePostcode = 2.01
	if err := writeJSON(outDir+"/panelB.json", pb); err != nil {
		return err
	}
	log.Printf("panelB: %s candidates=%d states=%d", pb.Name, pb.Candidates, pb.States)

	return nil
}

// buildScene4 queries the address table for each street. In-window points are
// kept full; out-of-window points are sampled to ~10% (every Nth row).
func buildScene4(db *sql.DB) (scene4, error) {
	var s4 scene4
	s4.Window.LatMin = latMin
	s4.Window.LatMax = latMax
	s4.Window.LonMin = lonMin
	s4.Window.LonMax = lonMax

	for _, street := range []struct {
		name string
		dst  *[]pt
	}{{"DONCASTER", &s4.Doncaster}, {"BLACKBURN", &s4.Blackburn}} {
		rows, err := db.Query(`
			SELECT latitude, longitude FROM address
			WHERE upper(street_name) = ?`, street.name)
		if err != nil {
			return s4, fmt.Errorf("query %s: %w", street.name, err)
		}
		defer rows.Close()

		i := 0
		for rows.Next() {
			var lat, lon float64
			if err := rows.Scan(&lat, &lon); err != nil {
				return s4, err
			}
			inWindow := lat >= latMin && lat <= latMax && lon >= lonMin && lon <= lonMax
			if inWindow {
				*street.dst = append(*street.dst, pt{quant(lat, 4), quant(lon, 4)})
				continue
			}
			// Sample every Nth out-of-window row, quantized to 3 decimals.
			if i%sampleEvery == 0 {
				*street.dst = append(*street.dst, pt{quant(lat, outQuant), quant(lon, outQuant)})
			}
			i++
		}
		if err := rows.Err(); err != nil {
			return s4, err
		}
	}
	return s4, nil
}

func (s4 *scene4) doncIn() int {
	n := 0
	for _, p := range s4.Doncaster {
		if p.Lat >= latMin && p.Lat <= latMax && p.Lon >= lonMin && p.Lon <= lonMax {
			n++
		}
	}
	return n
}

func (s4 *scene4) blackIn() int {
	n := 0
	for _, p := range s4.Blackburn {
		if p.Lat >= latMin && p.Lat <= latMax && p.Lon >= lonMin && p.Lon <= lonMax {
			n++
		}
	}
	return n
}

// quant rounds v to n decimal places.
func quant(v float64, n int) float64 {
	f := 1.0
	for i := 0; i < n; i++ {
		f *= 10
	}
	return float64(int64(v*f+0.5)) / f
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// writeCompactJSON writes JSON without indentation — used for the large scene4
// point payload (the animation reads it; human formatting isn't needed).
func writeCompactJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

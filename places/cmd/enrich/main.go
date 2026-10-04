// enrich is the assertion-store batch binary: the "pull a dataset in, update
// per-record as a batch, accommodate ad hoc" path. It reads NDJSON assertions
// (P6 shape), validates each, applies them append-only to the assertion store,
// derives the affected canonical records, and reports the change audit. It
// never touches a serving dataset — enrichment reaches serving only through a
// P1 build (INV-4).
//
// Usage:
//
//	enrich -store data/assertions.db -source mydata -version gnaf-aug26 -rule v1 \
//	      -register mydata "My Data" CC-BY-4.0 bulk 0.9 -in batch.ndjson
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"auplaces/internal/assertion"
)

func main() {
	storePath := flag.String("store", "data/assertions.db", "assertion store path")
	source := flag.String("source", "", "source id (must be registered)")
	version := flag.String("version", "", "dataset version the facts came from")
	rule := flag.String("rule", "", "ingestion rule version")
	batchID := flag.String("batch", "", "batch id (default: timestamp)")
	register := multiFlag{}
	flag.Var(&register, "register", "register a source: id,name,licence,method,trust (repeatable)")
	inPath := flag.String("in", "-", "NDJSON input (default stdin)")
	deriveSubject := flag.String("derive", "", "re-derive canonical for a subject (or a batch)")
	retractSpec := flag.String("retract", "", "retract: source,subject,predicate")
	flag.Parse()

	store, err := assertion.Open(*storePath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// -register id,name,licence,method,trust (repeatable): add sources to the
	// registry. P-D04: licence is mandatory — a source without one fails to load.
	for _, spec := range register.values {
		parts, err := splitFields(spec)
		if err != nil {
			log.Fatalf("-register: %v", err)
		}
		if len(parts) != 5 {
			log.Fatalf("-register needs 5 fields: id,name,licence,method,trust")
		}
		trust := 1.0
		if _, err := fmt.Sscanf(parts[4], "%f", &trust); err != nil {
			log.Fatalf("-register trust: %v", err)
		}
		if err := store.RegisterSource(parts[0], parts[1], parts[2], parts[3], trust); err != nil {
			log.Fatalf("register source: %v", err)
		}
		log.Printf("registered source %s (licence %s)", parts[0], parts[2])
	}

	// -derive subject: re-derive the canonical row for one subject from all
	// live assertions. No batch required — this is a repair/refresh step.
	if *deriveSubject != "" {
		if err := store.DeriveSubject(*deriveSubject); err != nil {
			log.Fatalf("derive: %v", err)
		}
		log.Printf("derived subject %s", *deriveSubject)
		return
	}

	// -retract source,subject,predicate: mark the source's assertion for that
	// subject+predicate withdrawn (never delete), then re-derive.
	if *retractSpec != "" {
		parts, err := splitFields(*retractSpec)
		if err != nil {
			log.Fatalf("-retract: %v", err)
		}
		if len(parts) != 3 {
			log.Fatalf("-retract needs 3 fields: source,subject,predicate")
		}
		n, err := store.Retract(parts[0], parts[1], parts[2])
		if err != nil {
			log.Fatalf("retract: %v", err)
		}
		if n > 0 {
			if err := store.DeriveSubject(parts[1]); err != nil {
				log.Fatalf("re-derive after retract: %v", err)
			}
		}
		fmt.Printf("retracted: %d assertions; subject re-derived\n", n)
		return
	}

	if *source == "" {
		log.Fatal("-source required (must be a registered source)")
	}
	if *version == "" {
		log.Fatal("-version required (dataset version the facts came from)")
	}

	if *batchID == "" {
		*batchID = fmt.Sprintf("batch-%d", time.Now().UnixNano())
	}

	// Read NDJSON: one assertion per line.
	var in io.Reader
	if *inPath == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(*inPath)
		if err != nil {
			log.Fatalf("open input: %v", err)
		}
		defer f.Close()
		in = f
	}

	var items []assertion.Assertion
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 || string(raw) == "\n" {
			continue
		}
		var a assertion.Assertion
		if err := json.Unmarshal(raw, &a); err != nil {
			log.Fatalf("line %d: %v", line, err)
		}
		if a.BatchID == "" {
			a.BatchID = *batchID
		}
		items = append(items, a)
	}
	if err := sc.Err(); err != nil {
		log.Fatalf("read input: %v", err)
	}
	if len(items) == 0 {
		log.Fatal("no assertions in input")
	}

	batch := assertion.Batch{ID: *batchID, Source: *source, Version: *version, Rule: *rule, Items: items}
	results, summary, err := store.Apply(batch)
	if err != nil {
		log.Fatalf("apply batch: %v", err)
	}

	// Stream per-item results (NDJSON out, P6 shape).
	enc := json.NewEncoder(os.Stdout)
	for _, r := range results {
		_ = enc.Encode(r)
	}
	// Terminal record closes the stream (R6.2).
	_ = enc.Encode(map[string]any{
		"done": true, "processed": len(items), "errors": summary.Rejected,
	})
	log.Printf("batch %s: applied=%d rejected=%d derived=%d",
		batch.ID, summary.Applied, summary.Rejected, summary.Derived)
}

// multiFlag is a repeatable string flag.
type multiFlag struct {
	values []string
}

func (m *multiFlag) String() string { return "" }
func (m *multiFlag) Set(v string) error {
	m.values = append(m.values, v)
	return nil
}

// splitFields splits a comma-separated field list, trimming spaces.
func splitFields(s string) ([]string, error) {
	var out []string
	cur := ""
	esc := false
	for _, r := range s {
		if esc {
			cur += string(r)
			esc = false
			continue
		}
		switch r {
		case '\\':
			esc = true
		case ',':
			out = append(out, cur)
			cur = ""
		default:
			cur += string(r)
		}
	}
	out = append(out, cur)
	return out, nil
}

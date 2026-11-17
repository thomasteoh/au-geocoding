package main

import (
	"go/token"
	"strings"
	"testing"
)

const sample = `package p

func f() {
	s.Log.Info("evt", "n", body)                    // BAD
	logger.Info("evt", "query", x)                  // BAD
	log.Printf("%s", r.URL)                         // BAD
	w.Log.Warn("evt", "e", req.URL.Query().Get("a")) // BAD
	fmt.Fprintln(os.Stderr, string(rawBody))        // BAD
	log.Info("evt", "raw", r.URL.RawQuery)          // BAD
	h.log.Error("evt", "v", q)                      // BAD
	log.Info("evt", "path", r.URL.Path, "n", len(body), "status", 200)
	log.Info("evt", "err", err.Error())
	fmt.Fprintf(w, "%s", body)
	cache.Info("evt", body)
	log.Info("evt", "q", q) // inv1:ok fixture text, reviewed
}
`

func TestLintFile(t *testing.T) {
	found, err := lintFile(token.NewFileSet(), "p.go", []byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(sample, "\n")
	bad := map[int]bool{}
	for i, l := range lines {
		if strings.Contains(l, "// BAD") {
			bad[i+1] = true
		}
	}
	got := map[int]bool{}
	for _, f := range found {
		got[f.pos.Line] = true
		if !bad[f.pos.Line] {
			t.Errorf("false positive at line %d: %s", f.pos.Line, f.msg)
		}
	}
	for l := range bad {
		if !got[l] {
			t.Errorf("missed violation at line %d: %s", l, strings.TrimSpace(lines[l-1]))
		}
	}
}

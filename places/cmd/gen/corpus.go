package main

import (
	"bufio"
	"os"
	"strings"
)

type corpusQuery struct {
	text string
	want string
}

func loadCorpus(path string) []corpusQuery {
	f, err := os.Open(path)
	if err != nil {
		// No corpus yet — return empty; gen handles it.
		return nil
	}
	defer f.Close()
	var out []corpusQuery
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// TSV: query<TAB>expected-pid
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		out = append(out, corpusQuery{text: parts[0], want: parts[1]})
	}
	return out
}

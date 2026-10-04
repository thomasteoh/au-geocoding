// Command keygen issues an API key into app.db. The raw key is printed exactly
// once and never stored (T6). Operator workflow — no HTTP issuance endpoint.
//
// Usage: keygen -app-db <path> [-label "name"] [-tier demo|standard|batch] [-scope search]
package main

import (
	"flag"
	"fmt"
	"os"

	"augeocoding/internal/publicapi"
)

func main() {
	db := flag.String("app-db", "data/app.db", "app.db path")
	label := flag.String("label", "key", "key label")
	tier := flag.String("tier", "demo", "quota tier: anonymous|demo|standard|batch")
	scope := flag.String("scope", "search", "comma-separated scopes")
	flag.Parse()

	s, err := publicapi.Open(*db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	id, raw, err := s.IssueKey(*label, publicapi.QuotaTier(*tier), splitScope(*scope))
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("key_id=%d\n", id)
	fmt.Printf("key=%s\n", raw)
	fmt.Printf("tier=%s\n", *tier)
	fmt.Printf("label=%s\n", *label)
}

func splitScope(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

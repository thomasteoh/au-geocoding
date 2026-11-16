// Command inv1lint is the CI check for INV-1: raw query text and request
// bodies are never logged. It parses Go sources (stdlib go/ast, no type
// information) and reports logging calls whose arguments reach request input:
//
//   - a selector .Body, .RawQuery, .Query, .Form, .PostForm, .RequestURI,
//     .RawPath, or a bare .URL (r.URL.Path is fine; r.URL is not);
//   - an identifier named like raw input (body, query, q, rawQuery, prefix,
//     input, payload, ...);
//   - a string-literal field key naming raw input ("query", "q", "body",
//     "prefix", ...).
//
// A logging call is a method call named Info/Warn/Error/Debug/Log/Print*/
// Fatal*/Panic* whose receiver expression mentions "log" (log, logger, s.Log,
// w.Log, slog, ...), or fmt.Print*/fmt.Fprint* to os.Stdout/os.Stderr.
// Arguments wrapped in len(...) are counts and are not inspected.
//
// A deliberate, reviewed exception can be marked with a trailing
// `// inv1:ok <reason>` comment on the call's line.
//
// Offline tools that never see request input (fixture generators) can be
// excluded with -skip, a comma-separated list of directories.
//
// Usage: go run ./cmd/inv1lint [-skip DIR,...] DIR...   (exit 1 on any finding)
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var logMethods = map[string]bool{
	"Info": true, "Warn": true, "Error": true, "Debug": true, "Log": true,
	"Print": true, "Printf": true, "Println": true,
	"Fatal": true, "Fatalf": true, "Fatalln": true,
	"Panic": true, "Panicf": true, "Panicln": true,
	"InfoContext": true, "WarnContext": true, "ErrorContext": true, "DebugContext": true,
}

var badSelectors = map[string]bool{
	"Body": true, "RawQuery": true, "Query": true, "Form": true, "PostForm": true,
	"RequestURI": true, "RawPath": true, "MultipartForm": true,
}

// badNames are identifier and field-key names (lower case, separators
// removed) that denote raw caller input.
var badNames = map[string]bool{
	"body": true, "rawbody": true, "reqbody": true, "requestbody": true,
	"q": true, "query": true, "rawquery": true, "querytext": true, "querystring": true,
	"prefix": true, "input": true, "rawinput": true, "payload": true,
}

func norm(s string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(s))
}

type finding struct {
	pos token.Position
	msg string
}

var skip = map[string]bool{}

func main() {
	skipList := flag.String("skip", "", "comma-separated directories to exclude (offline tools only)")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: inv1lint [-skip DIR,...] DIR...")
		os.Exit(2)
	}
	for _, d := range strings.Split(*skipList, ",") {
		if d = strings.TrimSpace(d); d != "" {
			skip[filepath.Clean(d)] = true
		}
	}
	var all []finding
	for _, root := range flag.Args() {
		found, err := lintTree(root)
		if err != nil {
			fmt.Fprintln(os.Stderr, "inv1lint:", err)
			os.Exit(2)
		}
		all = append(all, found...)
	}
	for _, f := range all {
		fmt.Printf("%s: INV-1: %s\n", f.pos, f.msg)
	}
	if len(all) > 0 {
		fmt.Printf("INV-1 violation: %d logging call(s) reach raw request input\n", len(all))
		os.Exit(1)
	}
	fmt.Println("INV-1 ok")
}

// lintTree checks every non-test .go file under root.
func lintTree(root string) ([]finding, error) {
	var out []finding
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "vendor" || skip[filepath.Clean(path)] || (strings.HasPrefix(n, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		found, err := lintFile(fset, path, src)
		out = append(out, found...)
		return err
	})
	return out, err
}

func lintFile(fset *token.FileSet, path string, src []byte) ([]finding, error) {
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	exempt := map[int]bool{}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(c.Text, "//")), "inv1:ok") {
				exempt[fset.Position(c.Pos()).Line] = true
			}
		}
	}
	var out []finding
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isLogCall(call) {
			return true
		}
		pos := fset.Position(call.Pos())
		if exempt[pos.Line] || exempt[fset.Position(call.End()).Line] {
			return true
		}
		for _, arg := range call.Args {
			if msg := badArg(arg); msg != "" {
				out = append(out, finding{pos: pos, msg: msg})
				break
			}
		}
		return true
	})
	return out, nil
}

func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.CallExpr:
		return exprString(t.Fun) + "()"
	case *ast.IndexExpr:
		return exprString(t.X) + "[]"
	case *ast.ParenExpr:
		return exprString(t.X)
	case *ast.StarExpr:
		return exprString(t.X)
	}
	return ""
}

func isLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	recv := exprString(sel.X)
	name := sel.Sel.Name
	if recv == "fmt" {
		if strings.HasPrefix(name, "Print") {
			return true
		}
		if strings.HasPrefix(name, "Fprint") && len(call.Args) > 0 {
			w := exprString(call.Args[0])
			return w == "os.Stderr" || w == "os.Stdout"
		}
		return false
	}
	return logMethods[name] && strings.Contains(strings.ToLower(recv), "log")
}

// badArg reports why arg reaches raw request input, or "" if it does not.
func badArg(arg ast.Expr) string {
	var msg string
	var visit func(n ast.Node, parent ast.Node) bool
	visit = func(n ast.Node, parent ast.Node) bool {
		if msg != "" || n == nil {
			return false
		}
		switch t := n.(type) {
		case *ast.CallExpr:
			if id, ok := t.Fun.(*ast.Ident); ok && (id.Name == "len" || id.Name == "cap") {
				return false // a count, not the content
			}
		case *ast.BasicLit:
			if t.Kind == token.STRING {
				if s, err := strconv.Unquote(t.Value); err == nil && badNames[norm(s)] {
					msg = fmt.Sprintf("field key %q names raw input", s)
				}
			}
		case *ast.SelectorExpr:
			if badSelectors[t.Sel.Name] {
				msg = fmt.Sprintf("argument reads %s", exprString(t))
				return false
			}
			if t.Sel.Name == "URL" {
				if _, deeper := parent.(*ast.SelectorExpr); !deeper {
					msg = fmt.Sprintf("argument logs the whole %s (includes the query string)", exprString(t))
					return false
				}
			}
			// Only the receiver side can hold input; the field name is
			// checked above.
			walk(t.X, t, visit)
			return false
		case *ast.Ident:
			if badNames[norm(t.Name)] {
				msg = fmt.Sprintf("argument uses %s", t.Name)
			}
		}
		return true
	}
	walk(arg, nil, visit)
	return msg
}

// walk is ast.Inspect with the parent node passed to the visitor.
func walk(n ast.Node, parent ast.Node, visit func(n, parent ast.Node) bool) {
	if !visit(n, parent) {
		return
	}
	ast.Inspect(n, func(c ast.Node) bool {
		if c == n || c == nil {
			return c == n
		}
		walk(c, n, visit)
		return false
	})
}

package console

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"augeocoding/internal/identity"
	"augeocoding/internal/oidcrp"
)

// Page is what every template receives.
type Page struct {
	Title  string
	Viewer *Viewer
	Org    *OrgContext
	Orgs   []identity.Membership // org switcher
	CSRF   string
	Flash  string
	Error  string
	Active string // nav highlight
	Data   any
}

func (s *Server) loadTemplates() error {
	funcs := template.FuncMap{
		"when": func(t any) string {
			switch x := t.(type) {
			case time.Time:
				if x.IsZero() {
					return "—"
				}
				return x.Local().Format("2 Jan 2006 15:04")
			case *time.Time:
				if x == nil || x.IsZero() {
					return "—"
				}
				return x.Local().Format("2 Jan 2006 15:04")
			}
			return "—"
		},
		"atLeast":   func(have identity.Role, want string) bool { return have >= identity.ParseRole(want) },
		"roles":     func() []identity.Role { return identity.AllRoles },
		"presets":   func() []string { return oidcrp.PresetOrder },
		"preset":    oidcrp.PresetFor,
		"join":      strings.Join,
		"pct":       func(n, d int64) int64 { return pct(n, d) },
		"hasPrefix": strings.HasPrefix,
	}
	s.pages = map[string]*template.Template{}
	layout, err := fs.ReadFile(assets, "templates/layout.html")
	if err != nil {
		return err
	}
	files, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	for _, f := range files {
		name := strings.TrimSuffix(path.Base(f), ".html")
		if name == "layout" {
			continue
		}
		body, err := fs.ReadFile(assets, f)
		if err != nil {
			return err
		}
		t, err := template.New("layout").Funcs(funcs).Parse(string(layout))
		if err != nil {
			return fmt.Errorf("layout: %w", err)
		}
		if _, err := t.Parse(string(body)); err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return nil
}

func pct(n, d int64) int64 {
	if d <= 0 {
		return 0
	}
	p := n * 100 / d
	if p > 100 {
		p = 100
	}
	return p
}

// render executes a page into a buffer first so a template error never
// sends half a page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p Page) {
	t, ok := s.pages[name]
	if !ok {
		s.Log.Error("template_missing", "name", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if p.Viewer == nil {
		p.Viewer = viewerFrom(r.Context())
	}
	if p.Org == nil {
		p.Org = orgFrom(r.Context())
	}
	if p.Viewer != nil {
		p.CSRF = p.Viewer.Session.CSRF
		if p.Orgs == nil {
			p.Orgs, _ = s.IDs.UserOrgs(r.Context(), p.Viewer.User.ID)
		}
	}
	if p.Flash == "" {
		p.Flash = takeFlash(w, r)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		s.Log.Error("template_failed", "name", name, "error", err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.render(w, r, status, "error", Page{Title: http.StatusText(status), Error: msg})
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Error("console_error", "path", r.URL.Path, "error", err.Error())
	s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Try again.")
}

package console

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"augeocoding/internal/appdb"
	"augeocoding/internal/authtest"
	"augeocoding/internal/identity"
	"augeocoding/internal/oidcrp"
	"augeocoding/internal/publicapi"
	"augeocoding/internal/secretbox"
	"ausystem/shared/slog"
)

// harness is a console behind a TLS test server with a fake IdP registered
// as the platform connection "test-idp".
type harness struct {
	t    *testing.T
	srv  *httptest.Server
	con  *Server
	ids  *identity.Store
	keys *publicapi.Store
	idp  *authtest.IdP
	conn identity.Connection
	ctx  context.Context
}

func newHarness(t *testing.T, policy identity.LoginPolicy) *harness {
	t.Helper()
	db, err := appdb.Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, _ := secretbox.New(bytes.Repeat([]byte{5}, 32))
	ids, err := identity.New(db, box)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := publicapi.New(db)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, ids: ids, keys: keys, ctx: context.Background()}
	h.idp = authtest.NewIdP(t)
	mux := http.NewServeMux()
	h.srv = httptest.NewUnstartedServer(mux)
	h.srv.StartTLS()
	t.Cleanup(h.srv.Close)
	rp := &oidcrp.RP{CallbackURL: h.srv.URL + "/auth/oidc/callback", HTTP: h.idp.Server.Client()}
	h.con, err = New(Config{PublicURL: h.srv.URL, Session: identity.SessionPolicy{Idle: time.Hour, Max: 24 * time.Hour}, Login: policy},
		ids, keys, rp, slog.New(io.Discard, slog.LevelError, nil), h.idp.Server.Client())
	if err != nil {
		t.Fatal(err)
	}
	h.con.LookupTXT = func(ctx context.Context, name string) ([]string, error) { return nil, nil }
	h.con.Register(mux)
	h.conn, err = ids.SaveConnection(h.ctx, identity.Connection{Slug: "test-idp", Kind: identity.KindOIDC, Preset: "generic", Name: "Test IdP",
		Enabled: true, Issuer: h.idp.Issuer, ClientID: h.idp.ClientID, ClientSecret: h.idp.ClientSecret})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// browser is a cookie-holding client that does not follow redirects, so
// tests can see each hop.
type browser struct {
	h      *harness
	c      *http.Client
	origin string
}

func (h *harness) browser() *browser {
	jar, _ := cookiejar.New(nil)
	// srv.Client() is shared; each browser needs its own jar.
	c := &http.Client{Transport: h.srv.Client().Transport, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &browser{h: h, c: c, origin: h.srv.URL}
}

type resp struct {
	Status   int
	Location string
	Body     string
}

func (b *browser) do(req *http.Request) resp {
	b.h.t.Helper()
	r, err := b.c.Do(req)
	if err != nil {
		b.h.t.Fatal(err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	return resp{Status: r.StatusCode, Location: r.Header.Get("Location"), Body: string(body)}
}

func (b *browser) get(u string) resp {
	b.h.t.Helper()
	if strings.HasPrefix(u, "/") {
		u = b.h.srv.URL + u
	}
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	return b.do(req)
}

// post sends a form with this site's Origin and, if csrf is true, the
// session's CSRF token scraped from the last console page.
func (b *browser) post(path string, form url.Values, csrf bool) resp {
	b.h.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if csrf {
		form.Set("csrf", b.csrf())
	}
	req, _ := http.NewRequest(http.MethodPost, b.h.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if b.origin != "" {
		req.Header.Set("Origin", b.origin)
	}
	return b.do(req)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (b *browser) csrf() string {
	b.h.t.Helper()
	r := b.get("/console/account")
	m := csrfRe.FindStringSubmatch(r.Body)
	if m == nil {
		b.h.t.Fatalf("no csrf token on account page (status %d)", r.Status)
	}
	return m[1]
}

// login signs the browser in through the fake IdP as u and returns the
// final redirect target.
func (b *browser) login(u authtest.User) resp {
	b.h.t.Helper()
	b.h.idp.SetUser(u)
	r := b.get("/auth/oidc/test-idp/start")
	if r.Status != http.StatusFound {
		b.h.t.Fatalf("start: %d %s", r.Status, r.Body)
	}
	r = b.get(r.Location) // IdP authorize → redirect to callback
	if r.Status != http.StatusFound {
		b.h.t.Fatalf("authorize: %d %s", r.Status, r.Body)
	}
	return b.get(r.Location) // callback
}

// mustLogin logs in and fails the test unless it lands in the console.
func (b *browser) mustLogin(u authtest.User) {
	b.h.t.Helper()
	r := b.login(u)
	if r.Status != http.StatusSeeOther || !strings.HasPrefix(r.Location, "/console") {
		b.h.t.Fatalf("login as %s: %d %s %s", u.Email, r.Status, r.Location, r.Body)
	}
}

// user creates an active user directly.
func (h *harness) user(email string) identity.User {
	h.t.Helper()
	u, err := h.ids.CreateUser(h.ctx, email, "")
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

// org creates an org owned by owner.
func (h *harness) org(slug string, owner identity.User) identity.Org {
	h.t.Helper()
	o, err := h.ids.CreateOrg(h.ctx, slug, slug, owner.ID, false, false)
	if err != nil {
		h.t.Fatal(err)
	}
	return o
}

// Package console is the web console and the browser side of sign-in:
// login page, OIDC/GitHub/SAML/passkey ceremonies, sessions, CSRF, and the
// org and platform admin pages (docs/auth.md).
//
// Route guards live here and only here: requireUser, requireOrg(minRole)
// and requirePlatformAdmin wrap every page, and every state-changing request
// passes checkCSRF. Handlers get the org from the request context, never
// from a form field, and pass its ID to org-scoped store methods (A5).
package console

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"augeocoding/internal/identity"
	"augeocoding/internal/oidcrp"
	"augeocoding/internal/publicapi"
	"ausystem/shared/slog"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Config is the console's deployment configuration.
type Config struct {
	PublicURL string // origin, no trailing slash
	Session   identity.SessionPolicy
	Login     identity.LoginPolicy
}

// Server serves the console.
type Server struct {
	Cfg  Config
	IDs  *identity.Store
	Keys *publicapi.Store
	RP   *oidcrp.RP
	Log  *slog.Logger
	// HTTP fetches admin-supplied URLs (SAML metadata). safehttp in
	// production.
	HTTP *http.Client
	// LookupTXT resolves DNS TXT records for domain verification.
	LookupTXT func(ctx context.Context, name string) ([]string, error)

	pages  map[string]*template.Template
	origin string
}

// New builds a console server.
func New(cfg Config, ids *identity.Store, keys *publicapi.Store, rp *oidcrp.RP, log *slog.Logger, httpClient *http.Client) (*Server, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("console: bad public URL %q", cfg.PublicURL)
	}
	s := &Server{Cfg: cfg, IDs: ids, Keys: keys, RP: rp, Log: log, HTTP: httpClient, origin: u.Scheme + "://" + u.Host,
		LookupTXT: net.DefaultResolver.LookupTXT}
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

// Register mounts the console, auth and SCIM-adjacent browser routes.
func (s *Server) Register(mux *http.ServeMux) {
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /console/static/", s.secure(http.StripPrefix("/console/static/", staticHandler(static))))

	// Sign-in.
	mux.Handle("GET /auth/login", s.secure(s.withViewer(http.HandlerFunc(s.handleLogin))))
	mux.Handle("POST /auth/discover", s.secure(s.checkOrigin(http.HandlerFunc(s.handleDiscover))))
	mux.Handle("GET /auth/oidc/{conn}/start", s.secure(http.HandlerFunc(s.handleOIDCStart)))
	mux.Handle("GET /auth/oidc/callback", s.secure(http.HandlerFunc(s.handleOIDCCallback)))
	mux.Handle("POST /auth/oidc/{conn}/backchannel-logout", http.HandlerFunc(s.handleBackchannelLogout))
	mux.Handle("GET /auth/saml/{conn}/metadata", http.HandlerFunc(s.handleSAMLMetadata))
	mux.Handle("GET /auth/saml/{conn}/start", s.secure(http.HandlerFunc(s.handleSAMLStart)))
	mux.Handle("POST /auth/oidc/{conn}/start", s.secure(s.checkOrigin(http.HandlerFunc(s.handleOIDCStart))))
	mux.Handle("POST /auth/saml/{conn}/start", s.secure(s.checkOrigin(http.HandlerFunc(s.handleSAMLStart))))
	mux.Handle("POST /auth/saml/{conn}/acs", s.secure(http.HandlerFunc(s.handleSAMLACS)))
	mux.Handle("POST /auth/passkey/login/begin", s.secure(s.checkOrigin(http.HandlerFunc(s.handlePasskeyLoginBegin))))
	mux.Handle("POST /auth/passkey/login/finish", s.secure(s.checkOrigin(http.HandlerFunc(s.handlePasskeyLoginFinish))))
	mux.Handle("POST /auth/logout", s.secure(s.withViewer(s.requireUser(s.checkCSRF(http.HandlerFunc(s.handleLogout))))))

	// Console.
	user := func(h http.HandlerFunc) http.Handler { return s.secure(s.withViewer(s.requireUser(h))) }
	userPost := func(h http.HandlerFunc) http.Handler { return user(s.checkCSRF(h).ServeHTTP) }
	mux.Handle("GET /console", user(s.handleHome))
	mux.Handle("GET /console/{$}", user(s.handleHome))
	mux.Handle("POST /console/orgs", userPost(s.handleCreateOrg))

	// Account.
	mux.Handle("GET /console/account", user(s.handleAccount))
	mux.Handle("POST /console/account/profile", userPost(s.handleAccountProfile))
	mux.Handle("POST /console/account/sessions/revoke", userPost(s.handleRevokeSession))
	mux.Handle("POST /console/account/sessions/revoke-others", userPost(s.handleRevokeOtherSessions))
	mux.Handle("POST /console/account/passkeys/register/begin", userPost(s.handlePasskeyRegisterBegin))
	mux.Handle("POST /console/account/passkeys/register/finish", userPost(s.handlePasskeyRegisterFinish))
	mux.Handle("POST /console/account/passkeys/{id}/delete", userPost(s.handlePasskeyDelete))

	s.registerOrgRoutes(mux)
	s.registerAdminRoutes(mux)
}

// orgRoute and orgPost guard /console/orgs/{org}/... pages with a minimum
// role.
func (s *Server) orgRoute(min identity.Role, h http.HandlerFunc) http.Handler {
	return s.secure(s.withViewer(s.requireUser(s.requireOrg(min, h))))
}

func (s *Server) orgPost(min identity.Role, h http.HandlerFunc) http.Handler {
	return s.secure(s.withViewer(s.requireUser(s.requireOrg(min, s.checkCSRF(h)))))
}

func (s *Server) adminRoute(h http.HandlerFunc) http.Handler {
	return s.secure(s.withViewer(s.requireUser(s.requirePlatformAdmin(h))))
}

func (s *Server) adminPost(h http.HandlerFunc) http.Handler {
	return s.secure(s.withViewer(s.requireUser(s.requirePlatformAdmin(s.checkCSRF(h)))))
}

// secure sets the headers every console and auth response carries.
func (s *Server) secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		// form-action allows https: because login and logout forms redirect
		// to IdPs, and Chrome applies form-action to the redirect chain.
		hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "+
			"form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		// Authorization codes and SAML relay states are in URLs on the way
		// back; never leak them to another origin.
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		if strings.HasPrefix(s.origin, "https://") {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

func staticHandler(fsys fs.FS) http.Handler {
	fh := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fh.ServeHTTP(w, r)
	})
}

// abs makes an absolute URL on the public origin.
func (s *Server) abs(path string) string { return s.Cfg.PublicURL + path }

// audit records an event; a failure is logged, never fatal.
func (s *Server) audit(r *http.Request, orgID int64, action, target, detail string) {
	e := identity.AuditEvent{OrgID: orgID, Action: action, Target: target, Detail: detail, Actor: "anonymous"}
	if v := viewerFrom(r.Context()); v != nil {
		e.ActorID, e.Actor = v.User.ID, v.User.Email
	}
	if err := s.IDs.Audit(r.Context(), e); err != nil {
		s.Log.Error("audit_failed", "action", action, "error", err.Error())
	}
}

const (
	sessionCookie = "__Host-augeo_session"
	flowCookie    = "__Host-augeo_flow"
	flashCookie   = "__Host-augeo_flash"
)

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration, sameSite http.SameSite) {
	c := &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: sameSite}
	switch {
	case maxAge > 0:
		c.MaxAge = int(maxAge.Seconds())
	case maxAge < 0:
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

func clearCookie(w http.ResponseWriter, name string, sameSite http.SameSite) {
	setCookie(w, name, "", -1, sameSite)
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

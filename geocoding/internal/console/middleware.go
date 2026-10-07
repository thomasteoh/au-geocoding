package console

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"augeocoding/internal/identity"
)

type ctxKey int

const (
	viewerKey ctxKey = iota
	orgKey
)

// Viewer is the signed-in person for this request.
type Viewer struct {
	User    identity.User
	Session identity.Session
}

// OrgContext is the org a /console/orgs/{org}/ request is about and the
// viewer's effective role in it.
type OrgContext struct {
	Org  identity.Org
	Role identity.Role
	// ViaPlatformAdmin is set when the role comes from platform admin rather
	// than membership (shown in the UI, recorded in the audit log).
	ViaPlatformAdmin bool
}

func withViewer(ctx context.Context, v *Viewer) context.Context {
	return context.WithValue(ctx, viewerKey, v)
}

func viewerFrom(ctx context.Context) *Viewer {
	v, _ := ctx.Value(viewerKey).(*Viewer)
	return v
}

func orgFrom(ctx context.Context) *OrgContext {
	o, _ := ctx.Value(orgKey).(*OrgContext)
	return o
}

// withViewer loads the session, if any.
func (s *Server) withViewer(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if raw := cookieValue(r, sessionCookie); raw != "" {
			sess, u, err := s.IDs.LookupSession(r.Context(), raw, s.Cfg.Session)
			if err == nil {
				r = r.WithContext(context.WithValue(r.Context(), viewerKey, &Viewer{User: u, Session: sess}))
			} else if errors.Is(err, identity.ErrNotFound) {
				clearCookie(w, sessionCookie, http.SameSiteLaxMode)
			}
		}
		h.ServeHTTP(w, r)
	})
}

// requireUser sends anonymous GETs to the login page and refuses other
// methods.
func (s *Server) requireUser(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if viewerFrom(r.Context()) == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			s.renderError(w, r, http.StatusUnauthorized, "Your session has ended. Sign in again.")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// requireOrg resolves {org} and checks the viewer's role. A non-member gets
// 404 so org slugs cannot be enumerated; a member below min gets 403.
func (s *Server) requireOrg(min identity.Role, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := viewerFrom(r.Context())
		org, err := s.IDs.OrgBySlug(r.Context(), r.PathValue("org"))
		if err != nil {
			s.renderError(w, r, http.StatusNotFound, "Not found.")
			return
		}
		role, err := s.IDs.Role(r.Context(), org.ID, v.User.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		oc := &OrgContext{Org: org, Role: role}
		general := s.IDs.SessionHasGeneralAccess(r.Context(), v.Session)
		if !general && !s.IDs.SessionSatisfiesOrg(r.Context(), v.Session.IDHash, org.ID, s.Cfg.Session.Max) {
			// This session came only through other orgs' IdPs; it does not
			// reach this org at all.
			s.renderError(w, r, http.StatusNotFound, "Not found. Sign in with your usual method to see your other organisations.")
			return
		}
		if v.User.PlatformAdmin && general && role < identity.RoleOwner {
			oc.Role, oc.ViaPlatformAdmin = identity.RoleOwner, true
		}
		if oc.Role == identity.RoleNone {
			s.renderError(w, r, http.StatusNotFound, "Not found.")
			return
		}
		if oc.Role < min {
			s.renderError(w, r, http.StatusForbidden, "You need the "+min.String()+" role for this.")
			return
		}
		if !s.ssoSatisfied(r, v, oc) {
			s.requireOrgSSO(w, r, oc)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), orgKey, oc)))
	})
}

func (s *Server) requirePlatformAdmin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := viewerFrom(r.Context()); v == nil || !v.User.PlatformAdmin || !s.IDs.SessionHasGeneralAccess(r.Context(), v.Session) {
			s.renderError(w, r, http.StatusNotFound, "Not found.")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// sameOrigin checks Origin (or, failing that, Referer) against the public
// origin. Browsers send Origin on every POST; a missing header is refused.
func (s *Server) sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return o == s.origin
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && u.Scheme+"://"+u.Host == s.origin
	}
	return false
}

// checkOrigin guards unauthenticated POSTs (discovery, passkey login).
func (s *Server) checkOrigin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.sameOrigin(r) {
			s.renderError(w, r, http.StatusForbidden, "Request blocked: it did not come from this site.")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// checkCSRF requires same origin and the session's CSRF token in the csrf
// form field or X-CSRF-Token header.
func (s *Server) checkCSRF(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := viewerFrom(r.Context())
		if r.Method != http.MethodPost {
			s.renderError(w, r, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		tok := r.Header.Get("X-CSRF-Token")
		if tok == "" {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				tok = r.PostFormValue("csrf")
			}
		}
		if v == nil || !s.sameOrigin(r) || !v.Session.CheckCSRF(tok) {
			s.renderError(w, r, http.StatusForbidden, "Request blocked: the form expired or did not come from this site. Reload and try again.")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// setFlash stores a one-time message shown on the next page.
func setFlash(w http.ResponseWriter, msg string) {
	setCookie(w, flashCookie, url.QueryEscape(msg), time.Minute, http.SameSiteLaxMode)
}

func takeFlash(w http.ResponseWriter, r *http.Request) string {
	v := cookieValue(r, flashCookie)
	if v == "" {
		return ""
	}
	clearCookie(w, flashCookie, http.SameSiteLaxMode)
	msg, _ := url.QueryUnescape(v)
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// redirectFlash finishes a POST with a message (post/redirect/get).
func redirectFlash(w http.ResponseWriter, r *http.Request, to, msg string) {
	if msg != "" {
		setFlash(w, msg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// safeReturn restricts post-login redirects to console paths (A4).
func safeReturn(p string) string {
	if p == "" || !strings.HasPrefix(p, "/console") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return "/console"
	}
	u, err := url.Parse(p)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/console"
	}
	return p
}

// ssoSatisfied applies per-org SSO enforcement (docs/auth.md "SSO
// enforcement"): when the org enforces SSO, the session must come from one
// of the org's own connections. An owner on a passkey session (break-glass)
// and platform admins are exempt.
func (s *Server) ssoSatisfied(r *http.Request, v *Viewer, oc *OrgContext) bool {
	if !oc.Org.SSOEnforced || (v.User.PlatformAdmin && s.IDs.SessionHasGeneralAccess(r.Context(), v.Session)) {
		return true
	}
	// Owners' passkey break-glass arrives as proofs granted at passkey
	// sign-in, only for orgs whose SSO the passkey was registered under.
	return s.IDs.SessionSatisfiesOrg(r.Context(), v.Session.IDHash, oc.Org.ID, s.Cfg.Session.Max)
}

// requireOrgSSO tells the person to sign in through the org's SSO. GETs
// get a page with the org's sign-in options; other methods are refused.
func (s *Server) requireOrgSSO(w http.ResponseWriter, r *http.Request, oc *OrgContext) {
	if r.Method != http.MethodGet {
		s.renderError(w, r, http.StatusForbidden, oc.Org.Name+" requires you to sign in with its single sign-on.")
		return
	}
	conns, _ := s.IDs.OrgLoginConnections(r.Context(), oc.Org.ID)
	s.render(w, r, http.StatusForbidden, "sso_required", Page{Title: "Single sign-on required", Data: struct {
		OrgName     string
		Connections []identity.Connection
		ReturnTo    string
	}{oc.Org.Name, conns, safeReturn(r.URL.RequestURI())}})
}

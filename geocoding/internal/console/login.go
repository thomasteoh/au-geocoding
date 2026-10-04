package console

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"augeocoding/internal/identity"
)

type loginData struct {
	Connections []identity.Connection
	ReturnTo    string
	Email       string
	OrgChoices  []identity.Connection // after discovery finds several
	SSOOrg      string
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request, status int, d loginData, errMsg string) {
	if d.Connections == nil {
		d.Connections, _ = s.IDs.LoginConnections(r.Context())
	}
	s.render(w, r, status, "login", Page{Title: "Sign in", Data: d, Error: errMsg})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ret := safeReturn(r.URL.Query().Get("return_to"))
	if viewerFrom(r.Context()) != nil {
		http.Redirect(w, r, ret, http.StatusSeeOther)
		return
	}
	s.loginPage(w, r, http.StatusOK, loginData{ReturnTo: ret}, "")
}

// handleDiscover is home-realm discovery: a work email leads to the org's
// own sign-in (docs/auth.md "Domain verification").
func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	email := identity.NormaliseEmail(r.PostFormValue("email"))
	ret := safeReturn(r.PostFormValue("return_to"))
	d := loginData{ReturnTo: ret, Email: email}
	if !identity.ValidEmail(email) {
		s.loginPage(w, r, http.StatusBadRequest, d, "Enter a valid email address.")
		return
	}
	org, err := s.IDs.OrgForDomain(r.Context(), identity.EmailDomain(email))
	if err != nil {
		s.loginPage(w, r, http.StatusOK, d, "Your organisation has not set up single sign-on here. Use one of the options above.")
		return
	}
	conns, err := s.IDs.OrgLoginConnections(r.Context(), org.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	switch len(conns) {
	case 0:
		s.loginPage(w, r, http.StatusOK, d, org.Name+" has not set up single sign-on yet. Use one of the options above.")
	case 1:
		http.Redirect(w, r, startPath(conns[0], ret), http.StatusSeeOther)
	default:
		d.OrgChoices = conns
		s.loginPage(w, r, http.StatusOK, d, "")
	}
}

func startPath(c identity.Connection, ret string) string {
	kind := "oidc"
	if c.Kind == identity.KindSAML {
		kind = "saml"
	}
	p := "/auth/" + kind + "/" + c.Slug + "/start"
	if ret != "" && ret != "/console" {
		p += "?return_to=" + url.QueryEscape(ret)
	}
	return p
}

// beginFlow stores a flow and sets the browser-binding cookie. SameSite=None
// because the SAML response arrives as a cross-site POST, which would not
// carry a Lax cookie; the cookie is only a random binding, useless alone.
func (s *Server) beginFlow(w http.ResponseWriter, r *http.Request, f identity.Flow) (state string, ok bool) {
	state, binding, err := s.IDs.StartFlow(r.Context(), f)
	if err != nil {
		s.serverError(w, r, err)
		return "", false
	}
	setCookie(w, flowCookie, binding, identity.FlowTTL, http.SameSiteNoneMode)
	return state, true
}

// takeFlow consumes the flow named by state, bound to this browser.
func (s *Server) takeFlow(w http.ResponseWriter, r *http.Request, state, kind string) (identity.Flow, bool) {
	f, err := s.IDs.TakeFlow(r.Context(), state, cookieValue(r, flowCookie))
	clearCookie(w, flowCookie, http.SameSiteNoneMode)
	if err != nil || f.Kind != kind {
		s.audit(r, 0, "login.failed", "", "flow_invalid")
		s.loginPage(w, r, http.StatusBadRequest, loginData{}, "That sign-in attempt expired or was started in another browser. Try again.")
		return identity.Flow{}, false
	}
	return f, true
}

// loginConnection loads an enabled connection by slug for a sign-in route.
func (s *Server) loginConnection(w http.ResponseWriter, r *http.Request, kinds ...string) (identity.Connection, bool) {
	c, err := s.IDs.ConnectionBySlug(r.Context(), r.PathValue("conn"))
	if err == nil && c.Enabled {
		for _, k := range kinds {
			if c.Kind == k {
				return c, true
			}
		}
	}
	s.loginPage(w, r, http.StatusNotFound, loginData{}, "That sign-in method is not available.")
	return identity.Connection{}, false
}

// confirmStart guards sign-in starts against login CSRF: a link on another
// site could send someone through an IdP whose account the attacker owns,
// leaving them signed in as the attacker. A start that did not come from
// this site (Sec-Fetch-Site) gets a page with a button that POSTs back,
// origin-checked. It reports whether the handler should continue.
func (s *Server) confirmStart(w http.ResponseWriter, r *http.Request, c identity.Connection) bool {
	if r.Method == http.MethodPost || r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return true
	}
	org := ""
	if !c.Platform() {
		if o, err := s.IDs.OrgByID(r.Context(), c.OrgID); err == nil {
			org = o.Name
		}
	}
	s.render(w, r, http.StatusOK, "login_confirm", Page{Title: "Continue to sign in", Data: struct {
		Conn     identity.Connection
		Org      string
		Action   string
		ReturnTo string
	}{c, org, r.URL.Path, safeReturn(r.FormValue("return_to"))}})
	return false
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loginConnection(w, r, identity.KindOIDC, identity.KindGitHub)
	if !ok || !s.confirmStart(w, r, c) {
		return
	}
	f := identity.Flow{Kind: "oidc", ConnectionID: c.ID, Nonce: identity.RandomToken(24), PKCEVerifier: identity.RandomToken(48),
		ReturnTo: safeReturn(r.FormValue("return_to"))}
	state, ok := s.beginFlow(w, r, f)
	if !ok {
		return
	}
	u, err := s.RP.AuthURL(r.Context(), c, state, f.Nonce, f.PKCEVerifier)
	if err != nil {
		s.Log.Warn("oidc_start_failed", "connection", c.Slug, "error", err.Error())
		s.loginPage(w, r, http.StatusBadGateway, loginData{}, "Could not reach "+c.Name+". Try again later.")
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f, ok := s.takeFlow(w, r, q.Get("state"), "oidc")
	if !ok {
		return
	}
	c, err := s.IDs.ConnectionByID(r.Context(), f.ConnectionID)
	if err != nil || !c.Enabled {
		s.loginPage(w, r, http.StatusBadRequest, loginData{}, "That sign-in method is not available.")
		return
	}
	a, err := s.RP.Callback(r.Context(), c, f, q)
	if err != nil {
		var d *identity.Denial
		if errors.As(err, &d) {
			s.denyLogin(w, r, c, d)
			return
		}
		s.Log.Warn("oidc_callback_failed", "connection", c.Slug, "error", err.Error())
		s.audit(r, c.OrgID, "login.failed", c.Slug, "oidc_callback")
		s.loginPage(w, r, http.StatusBadRequest, loginData{}, "Sign-in with "+c.Name+" did not complete. Try again.")
		return
	}
	s.completeLogin(w, r, a, f.ReturnTo, c.Kind)
}

// completeLogin resolves an assertion to a user and starts a session.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, a identity.Assertion, returnTo, method string) {
	res, err := s.IDs.ResolveLogin(r.Context(), a, s.Cfg.Login)
	if err != nil {
		var d *identity.Denial
		if errors.As(err, &d) {
			s.denyLogin(w, r, a.Connection, d)
			return
		}
		s.serverError(w, r, err)
		return
	}
	if !s.startSession(w, r, res.User, identity.NewSession{ConnectionID: a.Connection.ID, Method: method, IdPSID: a.IdPSID,
		IdPSub: a.Subject, IDToken: a.IDToken}) {
		return
	}
	detail := method + " via " + a.Connection.Slug
	if res.Created {
		detail += "; account created"
	}
	s.IDs.Audit(r.Context(), identity.AuditEvent{OrgID: a.Connection.OrgID, ActorID: res.User.ID, Actor: res.User.Email, Action: "login.success", Detail: detail})
	http.Redirect(w, r, safeReturn(returnTo), http.StatusSeeOther)
}

// startSession replaces any current session with a new one (new ID on every
// login, A1) and sets the cookie.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u identity.User, n identity.NewSession) bool {
	if old := cookieValue(r, sessionCookie); old != "" {
		s.IDs.DeleteSession(r.Context(), identity.HashToken(old))
	}
	n.UserID = u.ID
	n.UserAgent = r.UserAgent()
	raw, _, err := s.IDs.CreateSession(r.Context(), n, s.Cfg.Session)
	if err != nil {
		s.serverError(w, r, err)
		return false
	}
	setCookie(w, sessionCookie, raw, s.Cfg.Session.Max, http.SameSiteLaxMode)
	return true
}

func (s *Server) denyLogin(w http.ResponseWriter, r *http.Request, c identity.Connection, d *identity.Denial) {
	s.IDs.Audit(r.Context(), identity.AuditEvent{OrgID: c.OrgID, Actor: "anonymous", Action: "login.denied", Target: c.Slug, Detail: d.Code})
	ld := loginData{SSOOrg: d.SSOOrg}
	if d.SSOOrg != "" {
		if org, err := s.IDs.OrgBySlug(r.Context(), d.SSOOrg); err == nil {
			ld.OrgChoices, _ = s.IDs.OrgLoginConnections(r.Context(), org.ID)
		}
	}
	s.loginPage(w, r, http.StatusForbidden, ld, d.Message)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	s.IDs.DeleteSession(r.Context(), v.Session.IDHash)
	clearCookie(w, sessionCookie, http.SameSiteLaxMode)
	s.audit(r, 0, "logout", "", v.Session.Method)
	if v.Session.ConnectionID != 0 && (v.Session.Method == identity.KindOIDC) {
		if c, err := s.IDs.ConnectionByID(r.Context(), v.Session.ConnectionID); err == nil {
			if u, ok := s.RP.EndSessionURL(r.Context(), c, v.Session.IDToken, s.abs("/auth/login")); ok {
				http.Redirect(w, r, u, http.StatusSeeOther)
				return
			}
		}
	}
	redirectFlash(w, r, "/auth/login", "You have signed out.")
}

// handleBackchannelLogout implements OIDC back-channel logout (A6). Errors
// are 400 with no detail, as the spec asks.
func (s *Server) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	c, err := s.IDs.ConnectionBySlug(r.Context(), r.PathValue("conn"))
	if err != nil || c.Kind != identity.KindOIDC {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	lt, err := s.RP.VerifyLogoutToken(r.Context(), c, r.PostFormValue("logout_token"))
	if err != nil {
		s.Log.Warn("backchannel_logout_rejected", "connection", c.Slug, "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fresh, err := s.IDs.RecordLogoutJTI(r.Context(), c.ID, lt.JTI, lt.Expires)
	if err != nil || !fresh {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n, err := s.IDs.DeleteIdPSessions(r.Context(), c.ID, lt.SID, lt.Subject)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.IDs.Audit(r.Context(), identity.AuditEvent{OrgID: c.OrgID, Actor: "idp", Action: "logout.backchannel", Target: c.Slug,
		Detail: "sessions ended: " + strconv.FormatInt(n, 10)})
	w.WriteHeader(http.StatusOK)
}

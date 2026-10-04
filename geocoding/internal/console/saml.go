package console

import (
	"net/http"

	"augeocoding/internal/identity"
	"augeocoding/internal/samlsp"
)

// SAML 2.0 service provider routes (docs/auth.md "SAML 2.0").

// handleSAMLMetadata serves the SP metadata an admin gives the IdP. It is
// served for disabled connections too, since the IdP is set up before the
// connection is switched on.
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	c, err := s.IDs.ConnectionBySlug(r.Context(), r.PathValue("conn"))
	if err != nil || c.Kind != identity.KindSAML {
		http.NotFound(w, r)
		return
	}
	md, err := samlsp.Metadata(s.Cfg.PublicURL, c)
	if err != nil {
		s.Log.Warn("saml_metadata_failed", "connection", c.Slug, "error", err.Error())
		http.Error(w, "metadata unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(md)
}

func (s *Server) handleSAMLStart(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loginConnection(w, r, identity.KindSAML)
	if !ok {
		return
	}
	sp, err := samlsp.New(s.Cfg.PublicURL, c)
	if err != nil {
		s.Log.Warn("saml_start_failed", "connection", c.Slug, "error", err.Error())
		s.loginPage(w, r, http.StatusBadGateway, loginData{}, c.Name+" is not set up correctly. Ask an admin to check it.")
		return
	}
	req, err := samlsp.NewAuthnRequest(sp)
	if err != nil {
		s.Log.Warn("saml_start_failed", "connection", c.Slug, "error", err.Error())
		s.loginPage(w, r, http.StatusBadGateway, loginData{}, c.Name+" is not set up correctly. Ask an admin to check it.")
		return
	}
	state, ok := s.beginFlow(w, r, identity.Flow{Kind: "saml", ConnectionID: c.ID, RequestID: req.ID,
		ReturnTo: safeReturn(r.URL.Query().Get("return_to"))})
	if !ok {
		return
	}
	u, err := samlsp.RedirectURL(sp, req, state)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// handleSAMLACS consumes the IdP's HTTP-POST response. It arrives as a
// cross-site POST, so there is no Origin check; the flow cookie (SameSite
// None), single-use flow and InResponseTo binding stand in for it (A7).
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, samlsp.MaxResponseBytes)
	if err := r.ParseForm(); err != nil {
		s.loginPage(w, r, http.StatusBadRequest, loginData{}, "That sign-in response could not be read. Try again.")
		return
	}
	c, ok := s.loginConnection(w, r, identity.KindSAML)
	if !ok {
		return
	}
	relay := r.PostForm.Get("RelayState")
	if relay == "" {
		// IdP-initiated: no flow to bind to, so refuse (A7).
		s.audit(r, c.OrgID, "login.failed", c.Slug, "saml_idp_initiated")
		s.loginPage(w, r, http.StatusBadRequest, loginData{}, "Start sign-in from this site, not from your identity provider's portal.")
		return
	}
	f, ok := s.takeFlow(w, r, relay, "saml")
	if !ok {
		return
	}
	if f.ConnectionID != c.ID {
		s.audit(r, c.OrgID, "login.failed", c.Slug, "saml_wrong_connection")
		s.loginPage(w, r, http.StatusBadRequest, loginData{}, "Sign-in with "+c.Name+" did not complete. Try again.")
		return
	}
	sp, err := samlsp.New(s.Cfg.PublicURL, c)
	if err != nil {
		s.Log.Warn("saml_acs_failed", "connection", c.Slug, "error", err.Error())
		s.loginPage(w, r, http.StatusBadGateway, loginData{}, c.Name+" is not set up correctly. Ask an admin to check it.")
		return
	}
	sa, err := samlsp.ParseResponse(sp, r.PostForm, f.RequestID)
	if err != nil {
		// The detail names the failed check; it never includes the response.
		s.Log.Warn("saml_response_rejected", "connection", c.Slug, "error", err.Error())
		s.audit(r, c.OrgID, "login.failed", c.Slug, "saml_invalid")
		s.loginPage(w, r, http.StatusBadRequest, loginData{}, "Sign-in with "+c.Name+" did not complete. Try again.")
		return
	}
	s.completeLogin(w, r, samlsp.ToAssertion(c, sa), f.ReturnTo, identity.KindSAML)
}

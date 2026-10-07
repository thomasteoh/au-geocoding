package console

import (
	"errors"
	"net/http"
	"strconv"

	"augeocoding/internal/identity"
	"augeocoding/internal/samlsp"
)

// Linking sign-in methods (docs/auth.md "Linking sign-in methods"): a
// signed-in person completes a second IdP sign-in and the identity is
// attached to their account.

const flowLink = "link"

// linkFresh reports whether the session may add a sign-in method: the same
// rule as adding a passkey (a recent SSO sign-in), so a stolen or idle
// session cannot plant a way back in.
func linkFresh(sess identity.Session) bool {
	return sess.Method != "passkey" && passkeyNow().Sub(sess.Created) <= passkeyFreshness
}

// canAddMethod is linkFresh plus general access: a session scoped to one
// org's IdP must not add a sign-in method (a link or a passkey), or that
// org's IdP admin could turn a minted assertion into full account access.
func (s *Server) canAddMethod(r *http.Request, sess identity.Session) bool {
	return linkFresh(sess) && s.IDs.SessionHasGeneralAccess(r.Context(), sess)
}

func (s *Server) handleLinkStart(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	if !s.canAddMethod(r, v.Session) {
		redirectFlash(w, r, "/console/account", "Sign in again with single sign-on, then link the new method within 10 minutes.")
		return
	}
	conns, err := s.IDs.LinkableConnections(r.Context(), v.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var c identity.Connection
	for _, x := range conns {
		if x.Slug == r.PathValue("conn") {
			c = x
		}
	}
	if c.ID == 0 {
		redirectFlash(w, r, "/console/account", "That sign-in method is not available to link.")
		return
	}
	// Linkable connections come back without secrets; reload for the flow.
	if c, err = s.IDs.ConnectionByID(r.Context(), c.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	f := identity.Flow{Kind: flowLink, ConnectionID: c.ID, UserID: v.User.ID, ReturnTo: "/console/account"}
	switch c.Kind {
	case identity.KindSAML:
		sp, err := samlsp.New(s.Cfg.PublicURL, c)
		if err != nil {
			redirectFlash(w, r, "/console/account", c.Name+" is not set up correctly. Ask an admin to check it.")
			return
		}
		req, err := samlsp.NewAuthnRequest(sp)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		f.RequestID = req.ID
		state, ok := s.beginFlow(w, r, f)
		if !ok {
			return
		}
		u, err := samlsp.RedirectURL(sp, req, state)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		http.Redirect(w, r, u, http.StatusSeeOther)
	default:
		f.Nonce, f.PKCEVerifier = identity.RandomToken(24), identity.RandomToken(48)
		state, ok := s.beginFlow(w, r, f)
		if !ok {
			return
		}
		u, err := s.RP.AuthURL(r.Context(), c, state, f.Nonce, f.PKCEVerifier)
		if err != nil {
			s.Log.Warn("link_start_failed", "connection", c.Slug, "error", err.Error())
			redirectFlash(w, r, "/console/account", "Could not reach "+c.Name+". Try again later.")
			return
		}
		http.Redirect(w, r, u, http.StatusSeeOther)
	}
}

// finishLink completes a link flow after the IdP response was verified. The
// browser must still hold the session of the user who started it.
func (s *Server) finishLink(w http.ResponseWriter, r *http.Request, f identity.Flow, a identity.Assertion) {
	sess, u, err := s.IDs.LookupSession(r.Context(), cookieValue(r, sessionCookie), s.Cfg.Session)
	if err != nil || u.ID != f.UserID {
		s.audit(r, 0, "identity.link_failed", a.Connection.Slug, "session_mismatch")
		s.loginPage(w, r, http.StatusBadRequest, loginData{}, "Linking did not complete because you are no longer signed in as the person who started it.")
		return
	}
	r = r.WithContext(withViewer(r.Context(), &Viewer{User: u, Session: sess}))
	err = s.IDs.LinkIdentity(r.Context(), u.ID, a, s.Cfg.Login)
	var d *identity.Denial
	switch {
	case errors.As(err, &d):
		s.audit(r, a.Connection.OrgID, "identity.link_failed", a.Connection.Slug, d.Code)
		redirectFlash(w, r, "/console/account", d.Message)
	case errors.Is(err, identity.ErrLinkedElsewhere):
		s.audit(r, a.Connection.OrgID, "identity.link_failed", a.Connection.Slug, "linked_elsewhere")
		redirectFlash(w, r, "/console/account", "That "+a.Connection.Name+" account is already linked to another account here.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.audit(r, a.Connection.OrgID, "identity.link", a.Connection.Slug, "")
		redirectFlash(w, r, "/console/account", "Linked "+a.Connection.Name+". You can now sign in with it.")
	}
}

func (s *Server) handleUnlink(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		redirectFlash(w, r, "/console/account", "That sign-in method was not found.")
		return
	}
	c, err := s.IDs.UnlinkIdentity(r.Context(), v.User.ID, id)
	switch {
	case errors.Is(err, identity.ErrNotFound):
		redirectFlash(w, r, "/console/account", "That sign-in method was not found.")
	case errors.Is(err, identity.ErrLastMethod):
		redirectFlash(w, r, "/console/account", "You cannot remove your only way to sign in. Link another method or add a passkey first.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.audit(r, c.OrgID, "identity.unlink", c.Slug, "")
		if v.Session.ConnectionID == c.ID {
			clearCookie(w, sessionCookie, http.SameSiteLaxMode)
			redirectFlash(w, r, "/auth/login", "Removed "+c.Name+". Sign in again with another method.")
			return
		}
		redirectFlash(w, r, "/console/account", "Removed "+c.Name+".")
	}
}

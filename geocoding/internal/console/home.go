package console

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"augeocoding/internal/identity"
)

// handleHome lists the viewer's orgs; with one org it goes straight there.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	orgs, err := s.IDs.UserOrgs(r.Context(), v.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(orgs) == 1 && r.URL.Query().Get("all") == "" {
		http.Redirect(w, r, "/console/orgs/"+orgs[0].Org.Slug, http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "home", Page{Title: "Organisations", Orgs: orgs, Active: "home"})
}

// handleCreateOrg lets any signed-in user create an org they own.
func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	name := strings.TrimSpace(r.PostFormValue("name"))
	org, err := s.IDs.CreateOrg(r.Context(), name, identity.Slugify(name), v.User.ID, false, true)
	if errors.Is(err, identity.ErrInvalid) {
		redirectFlash(w, r, "/console?all=1", "Enter an organisation name of up to 100 characters.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, org.ID, "org.create", org.Slug, "")
	redirectFlash(w, r, "/console/orgs/"+org.Slug, "Created "+org.Name+".")
}

type accountData struct {
	Sessions   []sessionRow
	Passkeys   []identity.Passkey
	Identities []identity.LinkedIdentity
	Linkable   []identity.Connection // not yet linked
	CanLink    bool                  // session fresh enough to link
}

type sessionRow struct {
	identity.Session
	HashHex string
	Current bool
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	sessions, err := s.IDs.UserSessions(r.Context(), v.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var rows []sessionRow
	for _, x := range sessions {
		rows = append(rows, sessionRow{Session: x, HashHex: hex.EncodeToString(x.IDHash), Current: string(x.IDHash) == string(v.Session.IDHash)})
	}
	pks, err := s.IDs.Passkeys(r.Context(), v.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ids, err := s.IDs.LinkedIdentities(r.Context(), v.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	conns, err := s.IDs.LinkableConnections(r.Context(), v.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	linked := map[int64]bool{}
	for _, i := range ids {
		linked[i.Connection.ID] = true
	}
	var linkable []identity.Connection
	for _, c := range conns {
		if !linked[c.ID] {
			linkable = append(linkable, c)
		}
	}
	s.render(w, r, http.StatusOK, "account", Page{Title: "Your account", Active: "account", Data: accountData{Sessions: rows, Passkeys: pks,
		Identities: ids, Linkable: linkable, CanLink: s.canAddMethod(r, v.Session)}})
}

func (s *Server) handleAccountProfile(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	name := strings.TrimSpace(r.PostFormValue("name"))
	if len(name) > 100 {
		redirectFlash(w, r, "/console/account", "Names can be up to 100 characters.")
		return
	}
	if err := s.IDs.SetUserName(r.Context(), v.User.ID, name); err != nil {
		s.serverError(w, r, err)
		return
	}
	redirectFlash(w, r, "/console/account", "Saved.")
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	h, err := hex.DecodeString(r.PostFormValue("session"))
	if err != nil || len(h) != 32 {
		redirectFlash(w, r, "/console/account", "Unknown session.")
		return
	}
	if err := s.IDs.DeleteUserSession(r.Context(), v.User.ID, h); err != nil {
		redirectFlash(w, r, "/console/account", "Unknown session.")
		return
	}
	s.audit(r, 0, "session.revoke", "", "")
	if string(h) == string(v.Session.IDHash) {
		clearCookie(w, sessionCookie, http.SameSiteLaxMode)
		redirectFlash(w, r, "/auth/login", "You have signed out.")
		return
	}
	redirectFlash(w, r, "/console/account", "Session ended.")
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	n, err := s.IDs.DeleteUserSessions(r.Context(), v.User.ID, v.Session.IDHash)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, 0, "session.revoke_others", "", "")
	if n == 1 {
		redirectFlash(w, r, "/console/account", "Ended 1 other session.")
		return
	}
	redirectFlash(w, r, "/console/account", "Ended other sessions.")
}

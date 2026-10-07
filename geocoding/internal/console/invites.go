package console

import (
	"errors"
	"net/http"

	"augeocoding/internal/identity"
)

// Invites are accepted only by their recipient, explicitly, from the
// console home page (docs/auth.md "Invites"). Signing in never joins an org
// on its own, except for an org connection's own org.

func (s *Server) handleInviteAccept(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	org, role, err := s.IDs.AcceptInvite(r.Context(), v.User, id)
	if errors.Is(err, identity.ErrNotFound) {
		redirectFlash(w, r, "/console?all=1", "That invitation is no longer available.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, org.ID, "invite.accept", v.User.Email, "role="+role.String())
	redirectFlash(w, r, "/console/orgs/"+org.Slug, "You joined "+org.Name+" as "+role.String()+".")
}

func (s *Server) handleInviteDecline(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	org, err := s.IDs.DeclineInvite(r.Context(), v.User, id)
	if errors.Is(err, identity.ErrNotFound) {
		redirectFlash(w, r, "/console?all=1", "That invitation is no longer available.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, org.ID, "invite.decline", v.User.Email, "")
	redirectFlash(w, r, "/console?all=1", "Invitation declined.")
}

package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"augeocoding/internal/identity"
	"augeocoding/internal/passkey"
)

// Passkey (WebAuthn) routes (docs/auth.md "Passkeys"). The ceremonies are
// JSON over fetch from static/passkey.js; each begin stores the WebAuthn
// session data in a flow bound to the browser, and each finish consumes it.

const (
	// passkeyFreshness is how recent an SSO sign-in must be to add a passkey.
	passkeyFreshness = 10 * time.Minute
	maxPasskeyBody   = 64 << 10
)

// passkeyNow is replaceable in tests.
var passkeyNow = func() time.Time { return time.Now().UTC() }

func (s *Server) passkeyRP() (*passkey.RP, error) {
	return passkey.New(s.Cfg.PublicURL, s.IDs)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type passkeyFinish struct {
	State      string          `json:"state"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

// readPasskeyFinish decodes a bounded finish request body.
func readPasskeyFinish(w http.ResponseWriter, r *http.Request) (passkeyFinish, bool) {
	var req passkeyFinish
	r.Body = http.MaxBytesReader(w, r.Body, maxPasskeyBody)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.State == "" || len(req.Credential) == 0 {
		jsonError(w, http.StatusBadRequest, "The passkey response could not be read. Try again.")
		return req, false
	}
	return req, true
}

// beginPasskeyFlow stores the WebAuthn session data in a flow and answers
// with the state and the browser options.
func (s *Server) beginPasskeyFlow(w http.ResponseWriter, r *http.Request, f identity.Flow, opts passkey.Options) {
	state, binding, err := s.IDs.StartFlow(r.Context(), f)
	if errors.Is(err, identity.ErrTooManyFlows) {
		s.Log.Warn("auth_flows_full")
		w.Header().Set("Retry-After", "60")
		jsonError(w, http.StatusServiceUnavailable, "Sign-in is busy. Try again in a minute.")
		return
	}
	if err != nil {
		s.Log.Error("console_error", "path", r.URL.Path, "error", err.Error())
		jsonError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	setCookie(w, flowCookie, binding, identity.FlowTTL, http.SameSiteNoneMode)
	writeJSON(w, http.StatusOK, map[string]any{"state": state, "publicKey": opts})
}

// takePasskeyFlow is takeFlow for JSON callers.
func (s *Server) takePasskeyFlow(w http.ResponseWriter, r *http.Request, state, kind string) (identity.Flow, bool) {
	f, err := s.IDs.TakeFlow(r.Context(), state, cookieValue(r, flowCookie))
	clearCookie(w, flowCookie, http.SameSiteNoneMode)
	if err != nil || f.Kind != kind {
		return identity.Flow{}, false
	}
	return f, true
}

func (s *Server) passkeyServerError(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Error("console_error", "path", r.URL.Path, "error", err.Error())
	jsonError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
}

func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	if !s.canAddMethod(r, v.Session) {
		jsonError(w, http.StatusForbidden, "To add a passkey, sign out and sign in again with single sign-on, then add it within 10 minutes.")
		return
	}
	rp, err := s.passkeyRP()
	if err != nil {
		s.passkeyServerError(w, r, err)
		return
	}
	opts, sd, err := rp.BeginRegistration(r.Context(), v.User)
	if err != nil {
		s.passkeyServerError(w, r, err)
		return
	}
	s.beginPasskeyFlow(w, r, identity.Flow{Kind: "passkey-register", UserID: v.User.ID, Data: sd}, opts)
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	req, ok := readPasskeyFinish(w, r)
	if !ok {
		return
	}
	f, ok := s.takePasskeyFlow(w, r, req.State, "passkey-register")
	if !ok || f.UserID != v.User.ID {
		s.audit(r, 0, "passkey.register_failed", "", "flow_invalid")
		jsonError(w, http.StatusBadRequest, "That passkey request expired or was started in another browser. Try again.")
		return
	}
	rp, err := s.passkeyRP()
	if err != nil {
		s.passkeyServerError(w, r, err)
		return
	}
	pk, err := rp.FinishRegistration(r.Context(), v.User, f.Data, req.Credential)
	if err != nil {
		s.Log.Warn("passkey_register_failed", "user", v.User.ID, "error", err.Error())
		s.audit(r, 0, "passkey.register_failed", "", "invalid_response")
		jsonError(w, http.StatusBadRequest, "The passkey could not be verified. Try again.")
		return
	}
	pk.Name = req.Name
	id, err := s.IDs.AddPasskey(r.Context(), pk)
	if errors.Is(err, identity.ErrConflict) {
		jsonError(w, http.StatusConflict, "That passkey is already registered.")
		return
	}
	if err != nil {
		s.passkeyServerError(w, r, err)
		return
	}
	// Remember which org SSO sessions this passkey was registered under:
	// only those orgs' break-glass can be claimed with it.
	if err := s.IDs.RecordPasskeyProofs(r.Context(), id, v.Session.IDHash); err != nil {
		s.passkeyServerError(w, r, err)
		return
	}
	s.audit(r, 0, "passkey.register", strconv.FormatInt(id, 10), "")
	setFlash(w, "Passkey added.")
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/console/account"})
}

func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPasskeyBody)
	var req struct {
		ReturnTo string `json:"return_to"`
	}
	json.NewDecoder(r.Body).Decode(&req) // optional body
	rp, err := s.passkeyRP()
	if err != nil {
		s.passkeyServerError(w, r, err)
		return
	}
	opts, sd, err := rp.BeginLogin()
	if err != nil {
		s.passkeyServerError(w, r, err)
		return
	}
	s.beginPasskeyFlow(w, r, identity.Flow{Kind: "passkey-login", ReturnTo: safeReturn(req.ReturnTo), Data: sd}, opts)
}

// passkeyLoginFailed is the one answer every failed passkey login gets, so
// the response does not reveal which check failed.
func (s *Server) passkeyLoginFailed(w http.ResponseWriter, r *http.Request, u identity.User, code string) {
	e := identity.AuditEvent{Actor: "anonymous", Action: "login.failed", Target: "passkey", Detail: code}
	if u.ID != 0 {
		e.ActorID, e.Actor = u.ID, u.Email
	}
	if err := s.IDs.Audit(r.Context(), e); err != nil {
		s.Log.Error("audit_failed", "action", e.Action, "error", err.Error())
	}
	jsonError(w, http.StatusForbidden, "Sign-in with a passkey did not succeed. Try again, or use single sign-on.")
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	req, ok := readPasskeyFinish(w, r)
	if !ok {
		return
	}
	f, ok := s.takePasskeyFlow(w, r, req.State, "passkey-login")
	if !ok {
		s.passkeyLoginFailed(w, r, identity.User{}, "flow_invalid")
		return
	}
	rp, err := s.passkeyRP()
	if err != nil {
		s.passkeyServerError(w, r, err)
		return
	}
	u, pk, err := rp.FinishLogin(r.Context(), f.Data, req.Credential)
	switch {
	case errors.Is(err, passkey.ErrUnknownUser):
		s.passkeyLoginFailed(w, r, identity.User{}, "unknown_credential")
		return
	case errors.Is(err, passkey.ErrClone):
		s.Log.Warn("passkey_clone_warning", "user", u.ID)
		s.passkeyLoginFailed(w, r, u, "sign_count_regressed")
		return
	case err != nil:
		s.Log.Warn("passkey_login_failed", "user", u.ID, "error", err.Error())
		s.passkeyLoginFailed(w, r, u, "invalid_assertion")
		return
	}
	if !u.Active() {
		s.passkeyLoginFailed(w, r, u, "user_"+u.Status)
		return
	}
	if d := s.IDs.EnforcedSSO(r.Context(), u); d != nil {
		s.passkeyLoginFailed(w, r, u, d.Code)
		return
	}
	if err := s.IDs.UpdatePasskeyData(r.Context(), u.ID, pk.CredentialID, pk.Data); err != nil {
		s.passkeyServerError(w, r, err)
		return
	}
	sess, ok := s.startSessionWith(w, r, u, identity.NewSession{Method: "passkey"})
	if !ok {
		return
	}
	if err := s.IDs.GrantPasskeyProofs(r.Context(), sess.IDHash, u.ID, pk.CredentialID); err != nil {
		s.Log.Error("passkey_proofs_failed", "error", err.Error())
	}
	s.IDs.Audit(r.Context(), identity.AuditEvent{ActorID: u.ID, Actor: u.Email, Action: "login.success", Detail: "passkey"})
	writeJSON(w, http.StatusOK, map[string]string{"redirect": safeReturn(f.ReturnTo)})
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	v := viewerFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		redirectFlash(w, r, "/console/account", "That passkey was not found.")
		return
	}
	// Same freshness rule as registering: a stolen passkey session must not
	// be able to strip the owner's other passkeys.
	if !s.canAddMethod(r, v.Session) {
		redirectFlash(w, r, "/console/account", "Sign in again with single sign-on to remove a passkey.")
		return
	}
	if err := s.IDs.DeletePasskey(r.Context(), v.User.ID, id); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			redirectFlash(w, r, "/console/account", "That passkey was not found.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit(r, 0, "passkey.delete", strconv.FormatInt(id, 10), "")
	redirectFlash(w, r, "/console/account", "Passkey removed.")
}

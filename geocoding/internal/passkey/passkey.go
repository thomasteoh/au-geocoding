// Package passkey wraps go-webauthn for the console's passkey ceremonies
// (docs/auth.md "Passkeys"). It turns identity users and stored passkeys into
// WebAuthn users and credentials; policy (session freshness, SSO
// enforcement, account status) stays with the caller.
package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"augeocoding/internal/identity"
)

// DisplayName is the relying party name shown by authenticators.
const DisplayName = "au-geocoder"

// Errors from FinishLogin, so callers can audit a reason code.
var (
	ErrUnknownUser = errors.New("passkey: unknown user handle")
	ErrClone       = errors.New("passkey: sign count did not increase (possible cloned authenticator)")
)

// RP is the relying party for one public origin.
type RP struct {
	w   *webauthn.WebAuthn
	ids *identity.Store
}

// New builds a relying party whose ID is the host name of publicURL and
// whose only accepted origin is publicURL itself.
func New(publicURL string, ids *identity.Store) (*RP, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("passkey: bad public URL %q", publicURL)
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:                  u.Hostname(),
		RPDisplayName:         DisplayName,
		RPOrigins:             []string{u.Scheme + "://" + u.Host},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &RP{w: w, ids: ids}, nil
}

// user adapts an identity user and their stored passkeys to webauthn.User.
type user struct {
	u      identity.User
	handle []byte
	creds  []webauthn.Credential
}

func (u *user) WebAuthnID() []byte   { return u.handle }
func (u *user) WebAuthnName() string { return u.u.Email }
func (u *user) WebAuthnDisplayName() string {
	if u.u.Name != "" {
		return u.u.Name
	}
	return u.u.Email
}
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (rp *RP) loadUser(ctx context.Context, u identity.User, handle []byte) (*user, error) {
	if handle == nil {
		h, err := rp.ids.WebAuthnHandle(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		handle = h
	}
	pks, err := rp.ids.Passkeys(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	out := &user{u: u, handle: handle}
	for _, p := range pks {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(p.Data), &c); err != nil {
			return nil, fmt.Errorf("passkey %d: %w", p.ID, err)
		}
		out.creds = append(out.creds, c)
	}
	return out, nil
}

// Options is the publicKey member handed to navigator.credentials.
type Options = json.RawMessage

// BeginRegistration starts adding a passkey for u. It returns the creation
// options for the browser and the session data to keep server-side.
func (rp *RP) BeginRegistration(ctx context.Context, u identity.User) (Options, string, error) {
	wu, err := rp.loadUser(ctx, u, nil)
	if err != nil {
		return nil, "", err
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
	for _, c := range wu.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, sd, err := rp.w.BeginRegistration(wu, webauthn.WithExclusions(exclude),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	if err != nil {
		return nil, "", err
	}
	return marshalPair(creation.Response, sd)
}

// FinishRegistration verifies the browser's attestation response and returns
// the passkey to store (Name left for the caller).
func (rp *RP) FinishRegistration(ctx context.Context, u identity.User, session string, response []byte) (identity.Passkey, error) {
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(session), &sd); err != nil {
		return identity.Passkey{}, err
	}
	wu, err := rp.loadUser(ctx, u, nil)
	if err != nil {
		return identity.Passkey{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return identity.Passkey{}, err
	}
	cred, err := rp.w.CreateCredential(wu, sd, parsed)
	if err != nil {
		return identity.Passkey{}, err
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return identity.Passkey{}, err
	}
	return identity.Passkey{UserID: u.ID, CredentialID: cred.ID, Data: string(data)}, nil
}

// BeginLogin starts a discoverable (usernameless) login with user
// verification required.
func (rp *RP) BeginLogin() (Options, string, error) {
	assertion, sd, err := rp.w.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", err
	}
	return marshalPair(assertion.Response, sd)
}

// FinishLogin verifies an assertion and returns the user it belongs to and
// the credential with its updated sign count, ready to save. The user's
// status and SSO policy are not checked here.
func (rp *RP) FinishLogin(ctx context.Context, session string, response []byte) (identity.User, identity.Passkey, error) {
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(session), &sd); err != nil {
		return identity.User{}, identity.Passkey{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return identity.User{}, identity.Passkey{}, err
	}
	var found *user
	handler := func(rawID, handle []byte) (webauthn.User, error) {
		u, err := rp.ids.UserByWebAuthnHandle(ctx, handle)
		if err != nil {
			return nil, ErrUnknownUser
		}
		wu, err := rp.loadUser(ctx, u, handle)
		if err != nil {
			return nil, err
		}
		found = wu
		return wu, nil
	}
	_, cred, err := rp.w.ValidatePasskeyLogin(handler, sd, parsed)
	if err != nil {
		if found == nil {
			return identity.User{}, identity.Passkey{}, ErrUnknownUser
		}
		return found.u, identity.Passkey{}, err
	}
	if cred.Authenticator.CloneWarning {
		return found.u, identity.Passkey{}, ErrClone
	}
	if !bytes.Equal(cred.ID, parsed.RawID) {
		return found.u, identity.Passkey{}, errors.New("passkey: credential mismatch")
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return found.u, identity.Passkey{}, err
	}
	return found.u, identity.Passkey{UserID: found.u.ID, CredentialID: cred.ID, Data: string(data)}, nil
}

func marshalPair(options any, sd *webauthn.SessionData) (Options, string, error) {
	o, err := json.Marshal(options)
	if err != nil {
		return nil, "", err
	}
	s, err := json.Marshal(sd)
	if err != nil {
		return nil, "", err
	}
	return o, string(s), nil
}

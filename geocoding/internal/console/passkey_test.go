package console

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"augeocoding/internal/authtest"
	"augeocoding/internal/identity"
)

// authenticator is a minimal software passkey: one ES256 discoverable
// credential, "none" attestation, user verification always performed.
type authenticator struct {
	t       *testing.T
	key     *ecdsa.PrivateKey
	credID  []byte
	handle  []byte // user handle stored at registration
	rpID    string
	origin  string
	counter uint32
}

func newAuthenticator(t *testing.T, publicURL string) *authenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	u, _ := url.Parse(publicURL)
	return &authenticator{t: t, key: k, credID: id, rpID: u.Hostname(), origin: publicURL}
}

var b64 = base64.RawURLEncoding

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

func (a *authenticator) authData(flags byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, a.counter)
	return append(out, attested...)
}

func (a *authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func (a *authenticator) coseKey() []byte {
	x, y := make([]byte, 32), make([]byte, 32)
	a.key.PublicKey.X.FillBytes(x)
	a.key.PublicKey.Y.FillBytes(y)
	b, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}

// create answers navigator.credentials.create for the given options.
func (a *authenticator) create(opts map[string]any) json.RawMessage {
	a.t.Helper()
	if rp := opts["rp"].(map[string]any); rp["id"] != a.rpID {
		a.t.Fatalf("rp id %v, want %s", rp["id"], a.rpID)
	}
	if sel := opts["authenticatorSelection"].(map[string]any); sel["userVerification"] != "required" || sel["residentKey"] != "required" {
		a.t.Fatalf("authenticator selection: %v", sel)
	}
	handle, err := b64.DecodeString(opts["user"].(map[string]any)["id"].(string))
	if err != nil {
		a.t.Fatal(err)
	}
	a.handle = handle
	attested := make([]byte, 16) // zero AAGUID
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.credID)))
	attested = append(attested, a.credID...)
	attested = append(attested, a.coseKey()...)
	ao, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(flagUP|flagUV|flagAT, attested)})
	if err != nil {
		a.t.Fatal(err)
	}
	cd := a.clientData("webauthn.create", opts["challenge"].(string))
	b, _ := json.Marshal(map[string]any{"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(ao)}})
	return b
}

// get answers navigator.credentials.get, signing with the current counter.
func (a *authenticator) get(opts map[string]any) json.RawMessage {
	a.t.Helper()
	ad := a.authData(flagUP|flagUV, nil)
	cd := a.clientData("webauthn.get", opts["challenge"].(string))
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(a.handle)}})
	return b
}

// postJSON sends a JSON body with this site's Origin and, if csrf is set,
// the X-CSRF-Token header.
func (b *browser) postJSON(path string, body any, csrf string) (resp, map[string]any) {
	b.h.t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, b.h.srv.URL+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	r := b.do(req)
	var out map[string]any
	json.Unmarshal([]byte(r.Body), &out)
	return r, out
}

// registerPasskey runs both halves of registration and returns the finish
// response.
func (b *browser) registerPasskey(a *authenticator, name string) (resp, map[string]any) {
	b.h.t.Helper()
	tok := b.csrf()
	r, out := b.postJSON("/console/account/passkeys/register/begin", map[string]any{}, tok)
	if r.Status != http.StatusOK {
		return r, out
	}
	cred := a.create(out["publicKey"].(map[string]any))
	return b.postJSON("/console/account/passkeys/register/finish", map[string]any{"state": out["state"], "name": name, "credential": cred}, tok)
}

func (b *browser) mustRegisterPasskey(a *authenticator) {
	b.h.t.Helper()
	if r, _ := b.registerPasskey(a, "Test key"); r.Status != http.StatusOK {
		b.h.t.Fatalf("register: %d %s", r.Status, r.Body)
	}
}

// beginPasskeyLogin returns the state and options from login/begin.
func (b *browser) beginPasskeyLogin(returnTo string) (string, map[string]any) {
	b.h.t.Helper()
	r, out := b.postJSON("/auth/passkey/login/begin", map[string]any{"return_to": returnTo}, "")
	if r.Status != http.StatusOK {
		b.h.t.Fatalf("login begin: %d %s", r.Status, r.Body)
	}
	return out["state"].(string), out["publicKey"].(map[string]any)
}

func (b *browser) passkeyLogin(a *authenticator) (resp, map[string]any) {
	b.h.t.Helper()
	state, opts := b.beginPasskeyLogin("/console/account")
	return b.postJSON("/auth/passkey/login/finish", map[string]any{"state": state, "credential": a.get(opts)}, "")
}

func (h *harness) lastAudit(action string) identity.AuditEvent {
	h.t.Helper()
	events, _ := h.ids.AuditLog(h.ctx, 0, 0, 50)
	for _, e := range events {
		if e.Action == action {
			return e
		}
	}
	h.t.Fatalf("no %s audit event", action)
	return identity.AuditEvent{}
}

func (h *harness) mustUser(email string) identity.User {
	h.t.Helper()
	u, err := h.ids.UserByEmail(h.ctx, email)
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

func TestPasskeyRegisterAndLogin(t *testing.T) {
	h := newHarness(t, open)
	a := newAuthenticator(t, h.srv.URL)
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "s1", Email: "pk@example.com", EmailVerified: true})
	b.mustRegisterPasskey(a)
	u := h.mustUser("pk@example.com")
	pks, _ := h.ids.Passkeys(h.ctx, u.ID)
	if len(pks) != 1 || pks[0].Name != "Test key" || !bytes.Equal(pks[0].CredentialID, a.credID) {
		t.Fatalf("stored passkeys: %+v", pks)
	}
	h.lastAudit("passkey.register")

	if r := b.post("/auth/logout", nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("logout: %d", r.Status)
	}
	a.counter = 1
	r, out := b.passkeyLogin(a)
	if r.Status != http.StatusOK || out["redirect"] != "/console/account" {
		t.Fatalf("passkey login: %d %s", r.Status, r.Body)
	}
	if r := b.get("/console/account"); r.Status != http.StatusOK {
		t.Fatalf("account after passkey login: %d", r.Status)
	}
	sessions, _ := h.ids.UserSessions(h.ctx, u.ID)
	if len(sessions) != 1 || sessions[0].Method != "passkey" {
		t.Fatalf("sessions: %+v", sessions)
	}
	if e := h.lastAudit("login.success"); e.ActorID != u.ID || e.Detail != "passkey" {
		t.Fatalf("login audit: %+v", e)
	}
	pks, _ = h.ids.Passkeys(h.ctx, u.ID)
	if pks[0].LastUsed == nil {
		t.Fatal("last used not recorded")
	}

	// A passkey session cannot add another passkey.
	if r, _ := b.registerPasskey(newAuthenticator(t, h.srv.URL), "Second"); r.Status != http.StatusForbidden {
		t.Fatalf("register from passkey session: %d %s", r.Status, r.Body)
	}
}

func TestPasskeyRegistrationNeedsFreshSession(t *testing.T) {
	h := newHarness(t, open)
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "s1", Email: "stale@example.com", EmailVerified: true})
	passkeyNow = func() time.Time { return time.Now().UTC().Add(11 * time.Minute) }
	defer func() { passkeyNow = func() time.Time { return time.Now().UTC() } }()
	r, out := b.registerPasskey(newAuthenticator(t, h.srv.URL), "x")
	if r.Status != http.StatusForbidden || !strings.Contains(out["error"].(string), "sign in again") {
		t.Fatalf("stale register: %d %s", r.Status, r.Body)
	}
}

func TestPasskeySuspendedUserRefused(t *testing.T) {
	h := newHarness(t, open)
	a := newAuthenticator(t, h.srv.URL)
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "s1", Email: "sus@example.com", EmailVerified: true})
	b.mustRegisterPasskey(a)
	u := h.mustUser("sus@example.com")
	if err := h.ids.SetUserStatus(h.ctx, u.ID, identity.StatusSuspended); err != nil {
		t.Fatal(err)
	}
	other := h.browser()
	a.counter = 1
	if r, _ := other.passkeyLogin(a); r.Status != http.StatusForbidden {
		t.Fatalf("suspended login: %d %s", r.Status, r.Body)
	}
	if e := h.lastAudit("login.failed"); e.Detail != "user_suspended" {
		t.Fatalf("audit: %+v", e)
	}
	if other.get("/console").Status != http.StatusSeeOther {
		t.Fatal("suspended user got a session")
	}
}

func TestPasskeySSOEnforcement(t *testing.T) {
	h := newHarness(t, open)
	ownerKey, memberKey := newAuthenticator(t, h.srv.URL), newAuthenticator(t, h.srv.URL)
	ob, mb := h.browser(), h.browser()
	ob.mustLogin(authtest.User{Subject: "o", Email: "owner@acme.example", EmailVerified: true})
	ob.mustRegisterPasskey(ownerKey)
	mb.mustLogin(authtest.User{Subject: "m", Email: "dev@acme.example", EmailVerified: true})
	mb.mustRegisterPasskey(memberKey)

	owner, member := h.mustUser("owner@acme.example"), h.mustUser("dev@acme.example")
	org := h.org("acme", owner)
	if err := h.ids.SetMembership(h.ctx, org.ID, member.ID, identity.RoleViewer, "manual"); err != nil {
		t.Fatal(err)
	}
	d, _ := h.ids.AddDomain(h.ctx, org.ID, "acme.example")
	h.ids.MarkDomainVerified(h.ctx, org.ID, d.ID)
	h.ids.UpdateOrgSettings(h.ctx, org.ID, identity.OrgSettings{Name: "Acme", SSOEnforced: true, JITEnabled: true, DefaultRole: identity.RoleViewer})

	memberKey.counter = 1
	if r, _ := h.browser().passkeyLogin(memberKey); r.Status != http.StatusForbidden {
		t.Fatalf("enforced member: %d %s", r.Status, r.Body)
	}
	if e := h.lastAudit("login.failed"); e.Detail != "sso_required" {
		t.Fatalf("audit: %+v", e)
	}
	ownerKey.counter = 1
	if r, _ := h.browser().passkeyLogin(ownerKey); r.Status != http.StatusOK {
		t.Fatalf("owner break-glass: %d %s", r.Status, r.Body)
	}
}

func TestPasskeySignCountRegressionRefused(t *testing.T) {
	h := newHarness(t, open)
	a := newAuthenticator(t, h.srv.URL)
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "s1", Email: "clone@example.com", EmailVerified: true})
	b.mustRegisterPasskey(a)
	a.counter = 5
	if r, _ := h.browser().passkeyLogin(a); r.Status != http.StatusOK {
		t.Fatalf("first login: %d %s", r.Status, r.Body)
	}
	a.counter = 3
	c := h.browser()
	if r, _ := c.passkeyLogin(a); r.Status != http.StatusForbidden {
		t.Fatalf("regressed counter: %d %s", r.Status, r.Body)
	}
	if e := h.lastAudit("login.failed"); e.Detail != "sign_count_regressed" {
		t.Fatalf("audit: %+v", e)
	}
	if c.get("/console").Status != http.StatusSeeOther {
		t.Fatal("cloned authenticator got a session")
	}
}

func TestPasskeyFlowBoundToBrowser(t *testing.T) {
	h := newHarness(t, open)
	a := newAuthenticator(t, h.srv.URL)
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "s1", Email: "bind@example.com", EmailVerified: true})
	b.mustRegisterPasskey(a)
	a.counter = 1
	attacker, victim := h.browser(), h.browser()
	state, opts := attacker.beginPasskeyLogin("")
	victim.beginPasskeyLogin("") // the victim holds a flow cookie of its own
	r, _ := victim.postJSON("/auth/passkey/login/finish", map[string]any{"state": state, "credential": a.get(opts)}, "")
	if r.Status != http.StatusForbidden {
		t.Fatalf("cross-browser finish: %d %s", r.Status, r.Body)
	}
	if e := h.lastAudit("login.failed"); e.Detail != "flow_invalid" {
		t.Fatalf("audit: %+v", e)
	}
	// The state was consumed by the failed try.
	r, _ = attacker.postJSON("/auth/passkey/login/finish", map[string]any{"state": state, "credential": a.get(opts)}, "")
	if r.Status != http.StatusForbidden {
		t.Fatalf("reused state: %d", r.Status)
	}
	// Login needs a same-origin request.
	attacker.origin = "https://evil.example"
	if r, _ := attacker.postJSON("/auth/passkey/login/begin", map[string]any{}, ""); r.Status != http.StatusForbidden {
		t.Fatalf("cross-origin begin: %d", r.Status)
	}
}

func TestPasskeyDeleteOnlyOwn(t *testing.T) {
	h := newHarness(t, open)
	a := newAuthenticator(t, h.srv.URL)
	alice, bob := h.browser(), h.browser()
	alice.mustLogin(authtest.User{Subject: "a", Email: "alice@example.com", EmailVerified: true})
	alice.mustRegisterPasskey(a)
	bob.mustLogin(authtest.User{Subject: "b", Email: "bob@example.com", EmailVerified: true})
	au := h.mustUser("alice@example.com")
	pks, _ := h.ids.Passkeys(h.ctx, au.ID)
	path := "/console/account/passkeys/" + strconv.FormatInt(pks[0].ID, 10) + "/delete"
	if r := bob.post(path, nil, true); r.Status != http.StatusSeeOther || r.Location != "/console/account" {
		t.Fatalf("bob delete: %d %s", r.Status, r.Location)
	}
	if pks, _ := h.ids.Passkeys(h.ctx, au.ID); len(pks) != 1 {
		t.Fatal("bob deleted alice's passkey")
	}
	if r := alice.post(path, nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("alice delete: %d", r.Status)
	}
	if pks, _ := h.ids.Passkeys(h.ctx, au.ID); len(pks) != 0 {
		t.Fatal("alice's passkey survived deletion")
	}
	h.lastAudit("passkey.delete")
}

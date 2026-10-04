package identity

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"augeocoding/internal/appdb"
	"augeocoding/internal/secretbox"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := appdb.Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, _ := secretbox.New(bytes.Repeat([]byte{3}, 32))
	s, err := New(db, box)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var ctx = context.Background()

func platformConn(t *testing.T, s *Store, slug string, trust bool) Connection {
	t.Helper()
	c, err := s.SaveConnection(ctx, Connection{Slug: slug, Kind: KindOIDC, Preset: "generic", Name: slug, Enabled: true,
		Issuer: "https://idp.example/" + slug, ClientID: "cid", ClientSecret: "secret", TrustEmail: trust})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func denialCode(err error) string {
	var d *Denial
	if errors.As(err, &d) {
		return d.Code
	}
	if err != nil {
		return "error:" + err.Error()
	}
	return ""
}

func TestMigrateIdempotent(t *testing.T) {
	s := newStore(t)
	if err := migrate(s.db); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionSecretSealed(t *testing.T) {
	s := newStore(t)
	c := platformConn(t, s, "google", true)
	var raw string
	s.db.QueryRow(`SELECT client_secret_enc FROM connections WHERE id=?`, c.ID).Scan(&raw)
	if raw == "secret" || raw == "" {
		t.Fatalf("client secret stored as %q", raw)
	}
	if c.ClientSecret != "secret" {
		t.Fatalf("opened secret = %q", c.ClientSecret)
	}
	// Update with empty secret keeps the old one.
	c.ClientSecret = ""
	c.Name = "Google"
	c2, err := s.SaveConnection(ctx, c)
	if err != nil || c2.ClientSecret != "secret" || c2.Name != "Google" {
		t.Fatalf("update: %+v %v", c2, err)
	}
}

func TestPlatformSignupClosedAndOpen(t *testing.T) {
	s := newStore(t)
	c := platformConn(t, s, "google", true)
	a := Assertion{Connection: c, Subject: "1", Email: "a@example.com", EmailTrusted: true, Name: "A"}
	if code := denialCode(func() error { _, err := s.ResolveLogin(ctx, a, LoginPolicy{}); return err }()); code != "signup_closed" {
		t.Fatalf("closed signup: %s", code)
	}
	res, err := s.ResolveLogin(ctx, a, LoginPolicy{SignupOpen: true})
	if err != nil || !res.Created {
		t.Fatalf("open signup: %+v %v", res, err)
	}
	orgs, _ := s.UserOrgs(ctx, res.User.ID)
	if len(orgs) != 1 || !orgs[0].Org.Personal || orgs[0].Role != RoleOwner {
		t.Fatalf("personal org: %+v", orgs)
	}
	// Same subject again: known identity, no new user.
	res2, err := s.ResolveLogin(ctx, a, LoginPolicy{})
	if err != nil || res2.User.ID != res.User.ID || res2.Created {
		t.Fatalf("known identity: %+v %v", res2, err)
	}
}

func TestUntrustedEmailNeverLinksOrCreates(t *testing.T) {
	s := newStore(t)
	google := platformConn(t, s, "google", true)
	entra := platformConn(t, s, "entra", false)
	// Untrusted address cannot create an account even with open signup.
	_, err := s.ResolveLogin(ctx, Assertion{Connection: entra, Subject: "x", Email: "victim@example.com"}, LoginPolicy{SignupOpen: true})
	if denialCode(err) != "email_not_trusted" {
		t.Fatalf("untrusted create: %v", err)
	}
	// Victim signs up with Google.
	if _, err := s.ResolveLogin(ctx, Assertion{Connection: google, Subject: "g", Email: "victim@example.com", EmailTrusted: true}, LoginPolicy{SignupOpen: true}); err != nil {
		t.Fatal(err)
	}
	// Attacker presents the same address through an untrusted provider.
	_, err = s.ResolveLogin(ctx, Assertion{Connection: entra, Subject: "attacker", Email: "victim@example.com"}, LoginPolicy{SignupOpen: true})
	if denialCode(err) != "email_not_trusted" {
		t.Fatalf("untrusted link: %v", err)
	}
}

func TestBootstrapAdmin(t *testing.T) {
	s := newStore(t)
	c := platformConn(t, s, "google", true)
	res, err := s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "1", Email: "Boss@Example.com", EmailTrusted: true},
		LoginPolicy{BootstrapAdmins: []string{"boss@example.com"}})
	if err != nil || !res.User.PlatformAdmin {
		t.Fatalf("bootstrap: %+v %v", res.User, err)
	}
}

func setupOrgWithDomain(t *testing.T, s *Store, slug, domain string, jit bool) (Org, Connection, User) {
	t.Helper()
	owner, _ := s.CreateUser(ctx, "owner@"+domain, "Owner")
	org, err := s.CreateOrg(ctx, slug, slug, owner.ID, false, false)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.AddDomain(ctx, org.ID, domain)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDomainVerified(ctx, org.ID, d.ID); err != nil {
		t.Fatal(err)
	}
	if jit {
		if err := s.UpdateOrgSettings(ctx, org.ID, OrgSettings{Name: org.Name, JITEnabled: true, DefaultRole: RoleDeveloper}); err != nil {
			t.Fatal(err)
		}
	}
	c, err := s.SaveConnection(ctx, Connection{OrgID: org.ID, Slug: slug + "-okta", Kind: KindOIDC, Preset: "okta", Name: "Okta", Enabled: true,
		Issuer: "https://" + slug + ".okta.example", ClientID: "cid"})
	if err != nil {
		t.Fatal(err)
	}
	org, _ = s.OrgByID(ctx, org.ID)
	return org, c, owner
}

func TestOrgConnectionDomainAndJIT(t *testing.T) {
	s := newStore(t)
	org, c, _ := setupOrgWithDomain(t, s, "acme", "acme.example", false)
	// Wrong domain.
	_, err := s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "1", Email: "x@other.example"}, LoginPolicy{})
	if denialCode(err) != "domain_not_verified" {
		t.Fatalf("wrong domain: %v", err)
	}
	// Right domain, JIT off, no invite.
	_, err = s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "1", Email: "dev@acme.example"}, LoginPolicy{})
	if denialCode(err) != "not_provisioned" {
		t.Fatalf("jit off: %v", err)
	}
	// Invite then login.
	if err := s.CreateInvite(ctx, org.ID, "dev@acme.example", RoleAdmin, 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	res, err := s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "1", Email: "dev@acme.example"}, LoginPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Role(ctx, org.ID, res.User.ID); r != RoleAdmin {
		t.Fatalf("invite role = %v", r)
	}
	// JIT on.
	s.UpdateOrgSettings(ctx, org.ID, OrgSettings{Name: org.Name, JITEnabled: true, DefaultRole: RoleDeveloper})
	res, err = s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "2", Email: "new@acme.example"}, LoginPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Role(ctx, org.ID, res.User.ID); r != RoleDeveloper {
		t.Fatalf("jit role = %v", r)
	}
}

func TestGroupMappingsFollowGroups(t *testing.T) {
	s := newStore(t)
	org, c, _ := setupOrgWithDomain(t, s, "acme", "acme.example", false)
	if _, err := s.AddGroupMapping(ctx, GroupMapping{OrgID: org.ID, Source: SourceSSO, ConnectionID: c.ID, Group: "geo-admins", Role: RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	s.CreateInvite(ctx, org.ID, "g@acme.example", RoleViewer, 0, time.Hour)
	a := Assertion{Connection: c, Subject: "g", Email: "g@acme.example", Groups: []string{"geo-admins"}}
	res, err := s.ResolveLogin(ctx, a, LoginPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Role(ctx, org.ID, res.User.ID); r != RoleAdmin {
		t.Fatalf("mapped role = %v", r)
	}
	// Removed from the group at the IdP: the group-sourced role goes away.
	a.Groups = nil
	_, err = s.ResolveLogin(ctx, a, LoginPolicy{})
	if denialCode(err) != "not_member" {
		t.Fatalf("after group removal: %v", err)
	}
	if r, _ := s.Role(ctx, org.ID, res.User.ID); r != RoleNone {
		t.Fatalf("role kept after group removal: %v", r)
	}
}

func TestSSOEnforcementBlocksPlatformLogin(t *testing.T) {
	s := newStore(t)
	org, _, owner := setupOrgWithDomain(t, s, "acme", "acme.example", false)
	google := platformConn(t, s, "google", true)
	member, _ := s.CreateUser(ctx, "m@acme.example", "")
	s.SetMembership(ctx, org.ID, member.ID, RoleDeveloper, "manual")
	s.UpdateOrgSettings(ctx, org.ID, OrgSettings{Name: org.Name, SSOEnforced: true, DefaultRole: RoleViewer})
	_, err := s.ResolveLogin(ctx, Assertion{Connection: google, Subject: "m", Email: "m@acme.example", EmailTrusted: true}, LoginPolicy{SignupOpen: true})
	var d *Denial
	if !errors.As(err, &d) || d.Code != "sso_required" || d.SSOOrg != "acme" {
		t.Fatalf("member via google: %v", err)
	}
	// Owner keeps break-glass access.
	if _, err := s.ResolveLogin(ctx, Assertion{Connection: google, Subject: "o", Email: owner.Email, EmailTrusted: true}, LoginPolicy{}); err != nil {
		t.Fatalf("owner via google: %v", err)
	}
}

func TestSuspendedUserDeniedAndSessionsDropped(t *testing.T) {
	s := newStore(t)
	c := platformConn(t, s, "google", true)
	res, _ := s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "1", Email: "a@example.com", EmailTrusted: true}, LoginPolicy{SignupOpen: true})
	p := SessionPolicy{Idle: time.Hour, Max: 24 * time.Hour}
	raw, _, err := s.CreateSession(ctx, NewSession{UserID: res.User.ID, ConnectionID: c.ID, Method: "oidc"}, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LookupSession(ctx, raw, p); err != nil {
		t.Fatal(err)
	}
	s.SetUserStatus(ctx, res.User.ID, StatusSuspended)
	if _, _, err := s.LookupSession(ctx, raw, p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("suspended session: %v", err)
	}
	_, err = s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "1", Email: "a@example.com", EmailTrusted: true}, LoginPolicy{})
	if denialCode(err) != "user_suspended" {
		t.Fatalf("suspended login: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateUser(ctx, "a@example.com", "")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock = func() time.Time { return base }
	defer func() { clock = func() time.Time { return time.Now().UTC() } }()
	p := SessionPolicy{Idle: time.Hour, Max: 3 * time.Hour}
	raw, _, _ := s.CreateSession(ctx, NewSession{UserID: u.ID, Method: "passkey"}, p)
	for _, step := range []time.Duration{50 * time.Minute, 100 * time.Minute, 150 * time.Minute} {
		clock = func() time.Time { return base.Add(step) }
		if _, _, err := s.LookupSession(ctx, raw, p); err != nil {
			t.Fatalf("at %v: %v", step, err)
		}
	}
	clock = func() time.Time { return base.Add(181 * time.Minute) }
	if _, _, err := s.LookupSession(ctx, raw, p); !errors.Is(err, ErrNotFound) {
		t.Fatal("absolute expiry not enforced")
	}
	raw, _, _ = s.CreateSession(ctx, NewSession{UserID: u.ID, Method: "passkey"}, p)
	clock = func() time.Time { return base.Add(181*time.Minute + 2*time.Hour) }
	if _, _, err := s.LookupSession(ctx, raw, p); !errors.Is(err, ErrNotFound) {
		t.Fatal("idle expiry not enforced")
	}
}

func TestFlowBindingAndSingleUse(t *testing.T) {
	s := newStore(t)
	state, binding, err := s.StartFlow(ctx, Flow{Kind: "oidc", Nonce: "n", ReturnTo: "/console"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeFlow(ctx, state, "wrong"); !errors.Is(err, ErrNotFound) {
		t.Fatal("wrong binding accepted")
	}
	// The wrong-binding attempt consumed it.
	if _, err := s.TakeFlow(ctx, state, binding); !errors.Is(err, ErrNotFound) {
		t.Fatal("flow reusable after failed attempt")
	}
	state, binding, _ = s.StartFlow(ctx, Flow{Kind: "oidc", Nonce: "n2"})
	f, err := s.TakeFlow(ctx, state, binding)
	if err != nil || f.Nonce != "n2" {
		t.Fatalf("take: %+v %v", f, err)
	}
	if _, err := s.TakeFlow(ctx, state, binding); !errors.Is(err, ErrNotFound) {
		t.Fatal("flow replayed")
	}
}

func TestTenantScoping(t *testing.T) {
	s := newStore(t)
	a, ca, _ := setupOrgWithDomain(t, s, "alpha", "alpha.example", false)
	b, _, _ := setupOrgWithDomain(t, s, "beta", "beta.example", false)
	if _, err := s.OrgConnection(ctx, b.ID, ca.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("connection visible across orgs")
	}
	if err := s.DeleteConnection(ctx, b.ID, ca.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("connection deletable across orgs")
	}
	ca.OrgID = b.ID
	ca.Name = "hijack"
	if _, err := s.SaveConnection(ctx, ca); !errors.Is(err, ErrNotFound) {
		t.Fatalf("connection updatable across orgs: %v", err)
	}
	doms, _ := s.Domains(ctx, a.ID)
	if err := s.DeleteDomain(ctx, b.ID, doms[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("domain deletable across orgs")
	}
	if _, err := s.AddGroupMapping(ctx, GroupMapping{OrgID: b.ID, Source: SourceSSO, ConnectionID: ca.ID, Group: "g", Role: RoleOwner}); !errors.Is(err, ErrNotFound) {
		t.Fatal("mapping onto another org's connection")
	}
	tok, _, _ := s.CreateSCIMToken(ctx, a.ID, "okta")
	if err := s.RevokeSCIMToken(ctx, b.ID, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("scim token revocable across orgs")
	}
	iss, err := s.SaveJWTIssuer(ctx, JWTIssuer{OrgID: a.ID, Issuer: "https://auth.alpha.example/", Audience: "augeo", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteJWTIssuer(ctx, b.ID, iss.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("issuer deletable across orgs")
	}
}

func TestDomainVerifiedByOneOrgOnly(t *testing.T) {
	s := newStore(t)
	setupOrgWithDomain(t, s, "alpha", "shared.example", false)
	u, _ := s.CreateUser(ctx, "x@b.example", "")
	b, _ := s.CreateOrg(ctx, "beta", "beta", u.ID, false, false)
	d, err := s.AddDomain(ctx, b.ID, "shared.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDomainVerified(ctx, b.ID, d.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("second verification: %v", err)
	}
}

func TestLastOwnerProtected(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateUser(ctx, "o@example.com", "")
	org, _ := s.CreateOrg(ctx, "Org", "", u.ID, false, false)
	if err := s.SetMembership(ctx, org.ID, u.ID, RoleAdmin, "manual"); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("demote last owner: %v", err)
	}
	if err := s.RemoveMember(ctx, org.ID, u.ID); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("remove last owner: %v", err)
	}
	v, _ := s.CreateUser(ctx, "v@example.com", "")
	s.SetMembership(ctx, org.ID, v.ID, RoleOwner, "manual")
	if err := s.SetMembership(ctx, org.ID, u.ID, RoleAdmin, "manual"); err != nil {
		t.Fatalf("demote with another owner: %v", err)
	}
}

func TestSCIMTokenAuth(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateUser(ctx, "o@example.com", "")
	org, _ := s.CreateOrg(ctx, "Org", "", u.ID, false, false)
	tok, raw, err := s.CreateSCIMToken(ctx, org.ID, "okta")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.AuthenticateSCIM(ctx, raw); err != nil || got != org.ID {
		t.Fatalf("auth: %d %v", got, err)
	}
	s.RevokeSCIMToken(ctx, org.ID, tok.ID)
	if _, err := s.AuthenticateSCIM(ctx, raw); err == nil {
		t.Fatal("revoked token accepted")
	}
}

func TestLogoutJTIReplay(t *testing.T) {
	s := newStore(t)
	ok, err := s.RecordLogoutJTI(ctx, 1, "j1", time.Now().Add(time.Hour))
	if !ok || err != nil {
		t.Fatalf("first: %v %v", ok, err)
	}
	ok, err = s.RecordLogoutJTI(ctx, 1, "j1", time.Now().Add(time.Hour))
	if ok || err != nil {
		t.Fatalf("replay: %v %v", ok, err)
	}
}

func TestSlugify(t *testing.T) {
	for in, want := range map[string]string{"Acme Pty Ltd": "acme-pty-ltd", "  --": "org", "Ünïcode Co": "n-code-co"} {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

package identity

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

func sessionExists(t *testing.T, s *Store, h []byte) bool {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id_hash=?`, h).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// SCIM deactivation ends access to the org whatever the membership's source
// (here an SSO group mapping rewrote it to "group"), deletes sessions
// created through the org's connections, drops the org from other sessions'
// proofs, keeps sessions that never touched the org, and keeps the user
// active while other orgs remain.
func TestSCIMDeactivateEndsOrgAccess(t *testing.T) {
	s := newStore(t)
	org, c, _ := setupOrgWithDomain(t, s, "acme", "acme.example", true)
	plat := platformConn(t, s, "google", true)
	if _, err := s.AddGroupMapping(ctx, GroupMapping{OrgID: org.ID, Source: SourceSSO, ConnectionID: c.ID, Group: "geo-admins", Role: RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	// JIT user, then linked by SCIM, then their role comes from a group.
	res, err := s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "u1", Email: "u@acme.example"}, LoginPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	u := res.User
	su, err := s.CreateSCIMUser(ctx, org.ID, SCIMUserInput{Email: u.Email, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "u1", Email: u.Email, Groups: []string{"geo-admins"}}, LoginPolicy{}); err != nil {
		t.Fatal(err)
	}
	if _, src, _ := s.membership(ctx, org.ID, u.ID); src != "group" {
		t.Fatalf("source = %q, want group", src)
	}
	other, _ := s.CreateOrg(ctx, "Other", "other", 0, false, false)
	s.SetMembership(ctx, other.ID, u.ID, RoleViewer, "manual")

	p := SessionPolicy{Idle: time.Hour, Max: time.Hour}
	_, viaOrg, _ := s.CreateSession(ctx, NewSession{UserID: u.ID, ConnectionID: c.ID, Method: "oidc"}, p)
	_, proved, _ := s.CreateSession(ctx, NewSession{UserID: u.ID, ConnectionID: plat.ID, Method: "oidc"}, p)
	s.AddSessionProofs(ctx, proved.IDHash, c.ID)
	_, elsewhere, _ := s.CreateSession(ctx, NewSession{UserID: u.ID, ConnectionID: plat.ID, Method: "oidc"}, p)

	if _, _, err := s.ReplaceSCIMUser(ctx, org.ID, su.SCIMID, SCIMUserInput{Email: u.Email, Active: false}); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Role(ctx, org.ID, u.ID); r != RoleNone {
		t.Fatalf("group-sourced membership survived deactivation: %v", r)
	}
	if sessionExists(t, s, viaOrg.IDHash) {
		t.Fatal("session created through the org's connection survived")
	}
	if !sessionExists(t, s, proved.IDHash) || s.SessionSatisfiesOrg(ctx, proved.IDHash, org.ID, 0) {
		t.Fatal("other session should stay but lose the org's proof")
	}
	if !sessionExists(t, s, elsewhere.IDHash) {
		t.Fatal("session that never touched the org was deleted")
	}
	if got, _ := s.UserByID(ctx, u.ID); got.Status != StatusActive {
		t.Fatalf("user with another org deprovisioned: %s", got.Status)
	}
	// SSO and JIT cannot bring them back while SCIM says inactive.
	_, err = s.ResolveLogin(ctx, Assertion{Connection: c, Subject: "u1", Email: u.Email, Groups: []string{"geo-admins"}}, LoginPolicy{})
	if denialCode(err) != "scim_inactive" {
		t.Fatalf("relogin after deactivate: %v", err)
	}
	if r, _ := s.Role(ctx, org.ID, u.ID); r != RoleNone {
		t.Fatalf("relogin restored membership: %v", r)
	}
	// SCIM reactivation restores it.
	if _, _, err := s.ReplaceSCIMUser(ctx, org.ID, su.SCIMID, SCIMUserInput{Email: u.Email, Active: true}); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Role(ctx, org.ID, u.ID); r == RoleNone {
		t.Fatal("reactivation did not restore membership")
	}
	// Delete with no other org left: deprovisioned and signed out everywhere.
	s.RemoveMember(ctx, other.ID, u.ID)
	if _, err := s.DeleteSCIMUser(ctx, org.ID, su.SCIMID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByID(ctx, u.ID); got.Status != StatusDeprovisioned {
		t.Fatalf("status after delete = %s", got.Status)
	}
	if sessionExists(t, s, elsewhere.IDHash) || sessionExists(t, s, proved.IDHash) {
		t.Fatal("deprovisioned user kept sessions")
	}
}

// Signing in never joins an org on its own: invites wait in the console
// until the recipient accepts one.
func TestInvitesNeedExplicitAccept(t *testing.T) {
	s := newStore(t)
	plat := platformConn(t, s, "google", true)
	attacker, _ := s.CreateUser(ctx, "eve@evil.example", "")
	evil, _ := s.CreateOrg(ctx, "Evil", "evil", attacker.ID, false, false)
	if err := s.CreateInvite(ctx, evil.ID, "victim@corp.example", RoleOwner, attacker.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	res, err := s.ResolveLogin(ctx, Assertion{Connection: plat, Subject: "v", Email: "victim@corp.example", EmailTrusted: true}, LoginPolicy{SignupOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	v := res.User
	if r, _ := s.Role(ctx, evil.ID, v.ID); r != RoleNone {
		t.Fatalf("platform sign-in accepted an invite: %v", r)
	}
	if orgs, _ := s.UserOrgs(ctx, v.ID); len(orgs) != 0 {
		t.Fatalf("invitee got a personal workspace before deciding: %+v", orgs)
	}
	// Still linkable by their employer's IdP: nothing joined.
	if ok, _ := s.orgLinkable(ctx, v, 999); !ok {
		t.Fatal("pending invite made the account unlinkable")
	}
	pending, err := s.UserInvites(ctx, v)
	if err != nil || len(pending) != 1 || pending[0].OrgName != "Evil" || pending[0].InvitedBy != attacker.Email {
		t.Fatalf("pending: %+v %v", pending, err)
	}
	// Someone else cannot accept it.
	if _, _, err := s.AcceptInvite(ctx, attacker, pending[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("accepted another address's invite: %v", err)
	}
	if _, err := s.DeclineInvite(ctx, attacker, pending[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("declined another address's invite: %v", err)
	}
	if _, err := s.DeclineInvite(ctx, v, pending[0].ID); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.UserInvites(ctx, v); len(p) != 0 {
		t.Fatal("decline left the invite")
	}
	// Accept is explicit and single use.
	s.CreateInvite(ctx, evil.ID, v.Email, RoleDeveloper, attacker.ID, time.Hour)
	pending, _ = s.UserInvites(ctx, v)
	org, role, err := s.AcceptInvite(ctx, v, pending[0].ID)
	if err != nil || org.ID != evil.ID || role != RoleDeveloper {
		t.Fatalf("accept: %+v %v %v", org, role, err)
	}
	if _, _, err := s.AcceptInvite(ctx, v, pending[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second accept: %v", err)
	}
	// Expired invites cannot be accepted.
	other, _ := s.CreateOrg(ctx, "Other", "other", attacker.ID, false, false)
	s.CreateInvite(ctx, other.ID, v.Email, RoleViewer, attacker.ID, -time.Minute)
	var id int64
	s.db.QueryRowContext(ctx, `SELECT id FROM invites WHERE org_id=?`, other.ID).Scan(&id)
	if _, _, err := s.AcceptInvite(ctx, v, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired accept: %v", err)
	}
}

func TestOrgCreationLimitAndTier(t *testing.T) {
	s := newStore(t)
	s.DefaultOrgTier = "standard"
	u, _ := s.CreateUser(ctx, "u@example.com", "")
	if _, err := s.CreateOrg(ctx, "Personal", "personal", u.ID, true, false); err != nil {
		t.Fatal(err)
	}
	var made []Org
	for i := 0; i < 2; i++ {
		o, err := s.CreateOrgLimited(ctx, fmt.Sprintf("Org %d", i), "", u.ID, 2)
		if err != nil {
			t.Fatal(err)
		}
		if o.Tier != "standard" {
			t.Fatalf("tier = %s", o.Tier)
		}
		made = append(made, o)
	}
	if _, err := s.CreateOrgLimited(ctx, "One too many", "", u.ID, 2); !errors.Is(err, ErrOrgLimit) {
		t.Fatalf("third org: %v", err)
	}
	if _, err := s.OrgBySlug(ctx, "one-too-many"); !errors.Is(err, ErrNotFound) {
		t.Fatal("refused org was created")
	}
	// Deleting one frees a slot; platform admins are exempt.
	if err := s.DeleteOrg(ctx, made[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrgLimited(ctx, "Replacement", "", u.ID, 2); err != nil {
		t.Fatal(err)
	}
	s.SetPlatformAdmin(ctx, u.ID, true)
	if _, err := s.CreateOrgLimited(ctx, "Admin extra", "", u.ID, 2); err != nil {
		t.Fatalf("platform admin limited: %v", err)
	}
	s.DefaultOrgTier = "bogus"
	if o, _ := s.CreateOrg(ctx, "Fallback", "", u.ID, false, false); o.Tier != "demo" {
		t.Fatalf("unknown default tier gave %q", o.Tier)
	}
}

func TestInviteMailSenderLimit(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateUser(ctx, "u@example.com", "")
	var orgs []Org
	for i := 0; i < 3; i++ {
		o, _ := s.CreateOrg(ctx, fmt.Sprintf("O%d", i), "", u.ID, false, false)
		orgs = append(orgs, o)
	}
	// Spread over several orgs and recipients, so only the per-sender cap
	// applies.
	for i := 0; i < MailSenderPerDay; i++ {
		if err := s.EnqueueInviteMailFrom(ctx, orgs[i%3].ID, u.ID, fmt.Sprintf("r%d@example.com", i), "s", "b"); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if err := s.EnqueueInviteMailFrom(ctx, orgs[0].ID, u.ID, "late@example.com", "s", "b"); !errors.Is(err, ErrMailRateLimited) {
		t.Fatalf("over the sender cap: %v", err)
	}
	other, _ := s.CreateUser(ctx, "o@example.com", "")
	if err := s.EnqueueInviteMailFrom(ctx, orgs[0].ID, other.ID, "late@example.com", "s", "b"); err != nil {
		t.Fatalf("another inviter limited: %v", err)
	}
}

func TestDeleteOrgWithRunsInTx(t *testing.T) {
	s := newStore(t)
	o, _ := s.CreateOrg(ctx, "Acme", "acme", 0, false, false)
	boom := errors.New("boom")
	if err := s.DeleteOrgWith(ctx, o.ID, func(tx *sql.Tx) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.OrgByID(ctx, o.ID); err != nil {
		t.Fatal("org deleted although the transaction failed")
	}
	if err := s.DeleteOrgWith(ctx, o.ID, func(tx *sql.Tx) error { return OrgExistsTx(ctx, tx, o.ID) }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("org visible inside its own delete: %v", err)
	}
	if err := s.DeleteOrgWith(ctx, o.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteOrgWith(ctx, o.ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

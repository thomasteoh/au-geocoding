package identity

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
)

func TestLastPlatformAdminGuard(t *testing.T) {
	s := newStore(t)
	a, _ := s.CreateUser(ctx, "a@example.com", "")
	b, _ := s.CreateUser(ctx, "b@example.com", "")
	plain, _ := s.CreateUser(ctx, "plain@example.com", "")
	s.SetPlatformAdmin(ctx, a.ID, true)
	s.SetPlatformAdmin(ctx, b.ID, true)

	// Two admins: suspending one is fine; the other is then the last.
	if err := s.SetUserStatusGuarded(ctx, b.ID, StatusSuspended); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserStatusGuarded(ctx, a.ID, StatusSuspended); !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("suspend last: %v", err)
	}
	if err := s.SetUserStatusGuarded(ctx, a.ID, StatusDeprovisioned); !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("deprovision last: %v", err)
	}
	if err := s.RevokePlatformAdmin(ctx, a.ID); !errors.Is(err, ErrLastPlatformAdmin) {
		t.Fatalf("revoke last: %v", err)
	}
	if u, _ := s.UserByID(ctx, a.ID); !u.Active() || !u.PlatformAdmin {
		t.Fatalf("last admin changed: %+v", u)
	}
	// A suspended admin is not counted and can be demoted; reactivating is
	// always allowed; non-admins are unaffected.
	if err := s.RevokePlatformAdmin(ctx, b.ID); err != nil {
		t.Fatalf("revoke suspended: %v", err)
	}
	if err := s.SetUserStatusGuarded(ctx, b.ID, StatusActive); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserStatusGuarded(ctx, plain.ID, StatusSuspended); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePlatformAdmin(ctx, plain.ID); err != nil {
		t.Fatalf("revoke non-admin: %v", err)
	}
	if err := s.RevokePlatformAdmin(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	if err := s.SetUserStatusGuarded(ctx, 9999, StatusSuspended); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	if err := s.SetUserStatusGuarded(ctx, a.ID, "bogus"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad status: %v", err)
	}
}

// Two admins demoting each other at once must leave one admin.
func TestLastPlatformAdminGuardConcurrent(t *testing.T) {
	s := newStore(t)
	for round := 0; round < 20; round++ {
		a, _ := s.CreateUser(ctx, fmt.Sprintf("a%d@example.com", round), "")
		b, _ := s.CreateUser(ctx, fmt.Sprintf("b%d@example.com", round), "")
		s.db.ExecContext(ctx, `UPDATE users SET platform_admin=0`)
		s.SetPlatformAdmin(ctx, a.ID, true)
		s.SetPlatformAdmin(ctx, b.ID, true)
		errs := make(chan error, 2)
		go func() { errs <- s.RevokePlatformAdmin(ctx, a.ID) }()
		go func() { errs <- s.SetUserStatusGuarded(ctx, b.ID, StatusSuspended) }()
		<-errs
		<-errs
		if n, _ := s.CountPlatformAdmins(ctx); n != 1 {
			t.Fatalf("round %d: %d active admins", round, n)
		}
	}
}

func TestListUsersPaging(t *testing.T) {
	s := newStore(t)
	var ids []int64
	for i := 0; i < 25; i++ {
		u, _ := s.CreateUser(ctx, fmt.Sprintf("u%02d@example.com", i), "")
		ids = append(ids, u.ID)
	}
	s.CreateUser(ctx, "other@elsewhere.test", "")
	first, _ := s.ListUsers(ctx, "example.com", 0, 0, 10)
	if len(first) != 10 || first[0].ID != ids[24] || first[9].ID != ids[15] {
		t.Fatalf("first page: %v", userIDs(first))
	}
	older, _ := s.ListUsers(ctx, "example.com", first[9].ID, 0, 10)
	if len(older) != 10 || older[0].ID != ids[14] {
		t.Fatalf("older: %v", userIDs(older))
	}
	newer, _ := s.ListUsers(ctx, "example.com", 0, older[0].ID, 10)
	if len(newer) != 10 || newer[0].ID != ids[24] || newer[9].ID != ids[15] {
		t.Fatalf("newer (newest first): %v", userIDs(newer))
	}
	if all, _ := s.ListUsers(ctx, "", 0, 0, 100); len(all) != 26 {
		t.Fatalf("unfiltered: %d", len(all))
	}
}

func userIDs(us []User) []int64 {
	var out []int64
	for _, u := range us {
		out = append(out, u.ID)
	}
	return out
}

func TestSetOrgTierWithRollsBack(t *testing.T) {
	s := newStore(t)
	o, err := s.CreateOrg(ctx, "Acme", "acme", 0, false, false)
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("key update failed")
	var sawTx bool
	err = s.SetOrgTierWith(ctx, o.ID, "batch", func(tx *sql.Tx) error {
		var tier string
		tx.QueryRow(`SELECT tier FROM orgs WHERE id=?`, o.ID).Scan(&tier)
		sawTx = tier == "batch"
		return boom
	})
	if !errors.Is(err, boom) || !sawTx {
		t.Fatalf("err=%v sawTx=%v", err, sawTx)
	}
	if got, _ := s.OrgByID(ctx, o.ID); got.Tier != o.Tier {
		t.Fatalf("tier not rolled back: %s", got.Tier)
	}
	if err := s.SetOrgTierWith(ctx, o.ID, "anonymous", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid tier: %v", err)
	}
	if err := s.SetOrgTierWith(ctx, 9999, "batch", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing org: %v", err)
	}
	if err := s.SetOrgTierWith(ctx, o.ID, "batch", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.OrgByID(ctx, o.ID); got.Tier != "batch" {
		t.Fatalf("tier: %s", got.Tier)
	}
}

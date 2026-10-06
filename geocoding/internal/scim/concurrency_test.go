package scim

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"augeocoding/internal/identity"
)

// Concurrent PATCHes each add one member; with read-modify-write outside a
// transaction some adds were lost.
func TestConcurrentGroupPatch(t *testing.T) {
	f := setup(t)
	const n = 16
	ids := make([]string, n)
	for i := range ids {
		ids[i] = f.createUser(t, f.tokA, fmt.Sprintf("u%d@acme.example", i))
	}
	r := f.do(t, f.tokA, "POST", "/Groups", map[string]any{"displayName": "Team"})
	f.mustCode(t, r, 201)
	grp := r.body["id"].(string)

	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = f.do(t, f.tokA, "PATCH", "/Groups/"+grp, patch(
				map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": ids[i]}}},
			)).code
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != 204 {
			t.Fatalf("patch %d: status %d", i, c)
		}
	}
	g := f.do(t, f.tokA, "GET", "/Groups/"+grp, nil)
	if got := len(g.body["members"].([]any)); got != n {
		t.Fatalf("members after %d concurrent adds: %d", n, got)
	}
}

// Concurrent PATCHes of different attributes of one user all stick.
func TestConcurrentUserPatch(t *testing.T) {
	f := setup(t)
	id := f.createUser(t, f.tokA, "eve@acme.example")
	attrs := map[string]string{
		"displayName":          "Eve S",
		"externalId":           "ext-1",
		"name.givenName":       "Eve",
		"name.familyName":      "Smith",
		"name.middleName":      "M",
		"name.honorificPrefix": "Dr",
	}
	var wg sync.WaitGroup
	for path, v := range attrs {
		wg.Add(1)
		go func(path, v string) {
			defer wg.Done()
			if c := f.do(t, f.tokA, "PATCH", "/Users/"+id, patch(map[string]any{"op": "replace", "path": path, "value": v})).code; c != 200 {
				t.Errorf("patch %s: %d", path, c)
			}
		}(path, v)
	}
	wg.Wait()
	r := f.do(t, f.tokA, "GET", "/Users/"+id, nil)
	name, _ := r.body["name"].(map[string]any)
	got := map[string]any{"displayName": r.body["displayName"], "externalId": r.body["externalId"], "name.givenName": name["givenName"],
		"name.familyName": name["familyName"], "name.middleName": name["middleName"], "name.honorificPrefix": name["honorificPrefix"]}
	for k, want := range attrs {
		if got[k] != want {
			t.Errorf("%s = %v, want %q (lost update)", k, got[k], want)
		}
	}
}

// A mutate error leaves the user unchanged.
func TestPatchSCIMUserMutateError(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := f.createUser(t, f.tokA, "eve@acme.example")
	boom := errors.New("boom")
	_, _, _, err := f.ids.PatchSCIMUser(ctx, f.orgA.ID, id, func(cur identity.SCIMUser) (identity.SCIMUserInput, error) {
		return identity.SCIMUserInput{}, boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, _, _, err := f.ids.PatchSCIMUser(ctx, f.orgB.ID, id, func(identity.SCIMUser) (identity.SCIMUserInput, error) {
		t.Fatal("mutate called for another org's user")
		return identity.SCIMUserInput{}, nil
	}); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("cross-org patch: %v", err)
	}
}

// Adding or removing a SCIM mapping recomputes SCIM members' roles at once;
// manual memberships and the last owner are respected.
func TestMappingChangeRecomputesRoles(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	alice := f.createUser(t, f.tokA, "alice@acme.example")
	// A manual member who is also provisioned keeps the console's role.
	dev, _ := f.ids.CreateUser(ctx, "dev@acme.example", "")
	f.ids.SetMembership(ctx, f.orgA.ID, dev.ID, identity.RoleDeveloper, "manual")
	devID := f.createUser(t, f.tokA, "dev@acme.example")
	r := f.do(t, f.tokA, "POST", "/Groups", map[string]any{"displayName": "Geo Admins",
		"members": []any{map[string]any{"value": alice}, map[string]any{"value": devID}}})
	f.mustCode(t, r, 201)
	// The same group name in another org must not be affected.
	bob := f.createUser(t, f.tokB, "bob@beta.example")
	f.mustCode(t, f.do(t, f.tokB, "POST", "/Groups", map[string]any{"displayName": "Geo Admins",
		"members": []any{map[string]any{"value": bob}}}), 201)

	if f.role(t, f.orgA.ID, "alice@acme.example") != identity.RoleViewer {
		t.Fatal("alice should start at the default role")
	}
	m, err := f.ids.AddGroupMapping(ctx, identity.GroupMapping{OrgID: f.orgA.ID, Source: identity.SourceSCIM, Group: "Geo Admins", Role: identity.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if f.role(t, f.orgA.ID, "alice@acme.example") != identity.RoleAdmin {
		t.Fatal("adding a mapping did not promote alice")
	}
	if f.role(t, f.orgA.ID, "dev@acme.example") != identity.RoleDeveloper {
		t.Fatal("manual membership changed")
	}
	if f.role(t, f.orgB.ID, "bob@beta.example") != identity.RoleViewer {
		t.Fatal("other org changed")
	}
	if err := f.ids.DeleteGroupMapping(ctx, f.orgA.ID, m.ID); err != nil {
		t.Fatal(err)
	}
	if f.role(t, f.orgA.ID, "alice@acme.example") != identity.RoleViewer {
		t.Fatal("removing the mapping did not demote alice")
	}

	// Alice becomes the only owner through a mapping; removing the mapping
	// is refused and nothing changes.
	m, err = f.ids.AddGroupMapping(ctx, identity.GroupMapping{OrgID: f.orgA.ID, Source: identity.SourceSCIM, Group: "Geo Admins", Role: identity.RoleOwner})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.ids.RemoveMember(ctx, f.orgA.ID, f.ownerA.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.ids.DeleteGroupMapping(ctx, f.orgA.ID, m.ID); !errors.Is(err, identity.ErrLastOwner) {
		t.Fatalf("want ErrLastOwner, got %v", err)
	}
	if f.role(t, f.orgA.ID, "alice@acme.example") != identity.RoleOwner {
		t.Fatal("refused change was applied")
	}
	if ms, _ := f.ids.GroupMappings(ctx, f.orgA.ID); len(ms) != 1 {
		t.Fatalf("refused delete removed the mapping: %+v", ms)
	}
}

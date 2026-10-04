package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"augeocoding/internal/appdb"
	"augeocoding/internal/identity"
	"ausystem/shared/slog"
)

const base = "https://geo.example/scim/v2"

type fixture struct {
	ids    *identity.Store
	srv    *Server
	orgA   identity.Org
	orgB   identity.Org
	ownerA identity.User
	tokA   string
	tokB   string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	db, err := appdb.Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ids, err := identity.New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f := &fixture{ids: ids, srv: &Server{IDs: ids, Log: slog.New(io.Discard, slog.LevelError, nil), BaseURL: base}}
	f.ownerA, _ = ids.CreateUser(ctx, "owner@acme.example", "Owner")
	ownerB, _ := ids.CreateUser(ctx, "owner@beta.example", "")
	if f.orgA, err = ids.CreateOrg(ctx, "Acme", "acme", f.ownerA.ID, false, false); err != nil {
		t.Fatal(err)
	}
	if f.orgB, err = ids.CreateOrg(ctx, "Beta", "beta", ownerB.ID, false, false); err != nil {
		t.Fatal(err)
	}
	for org, dom := range map[int64]string{f.orgA.ID: "acme.example", f.orgB.ID: "beta.example"} {
		d, err := ids.AddDomain(ctx, org, dom)
		if err != nil {
			t.Fatal(err)
		}
		if err := ids.MarkDomainVerified(ctx, org, d.ID); err != nil {
			t.Fatal(err)
		}
	}
	// Added but never verified.
	if _, err := ids.AddDomain(ctx, f.orgA.ID, "pending.example"); err != nil {
		t.Fatal(err)
	}
	if _, f.tokA, err = ids.CreateSCIMToken(ctx, f.orgA.ID, "okta"); err != nil {
		t.Fatal(err)
	}
	if _, f.tokB, err = ids.CreateSCIMToken(ctx, f.orgB.ID, "entra"); err != nil {
		t.Fatal(err)
	}
	return f
}

type resp struct {
	code int
	body map[string]any
	hdr  http.Header
}

func (f *fixture) do(t *testing.T, tok, method, path string, body any) resp {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, "/scim/v2"+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	r := resp{code: rec.Code, hdr: rec.Header()}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &r.body); err != nil {
			t.Fatalf("%s %s: bad JSON %q", method, path, rec.Body.String())
		}
	}
	return r
}

func (f *fixture) mustCode(t *testing.T, r resp, want int) {
	t.Helper()
	if r.code != want {
		t.Fatalf("status %d, want %d: %v", r.code, want, r.body)
	}
}

func userBody(email string, extra map[string]any) map[string]any {
	b := map[string]any{
		"schemas":  []string{schemaUser},
		"userName": email,
		"name":     map[string]any{"givenName": "Ada", "familyName": "Lovelace"},
		"emails":   []any{map[string]any{"value": email, "type": "work", "primary": true}},
		"active":   true,
	}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func (f *fixture) createUser(t *testing.T, tok, email string) string {
	t.Helper()
	r := f.do(t, tok, "POST", "/Users", userBody(email, nil))
	f.mustCode(t, r, http.StatusCreated)
	return r.body["id"].(string)
}

func patch(ops ...map[string]any) map[string]any {
	return map[string]any{"schemas": []string{schemaPatch}, "Operations": ops}
}

func (f *fixture) role(t *testing.T, org int64, email string) identity.Role {
	t.Helper()
	u, err := f.ids.UserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.ids.Role(context.Background(), org, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAuth(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	_, revoked, _ := f.ids.CreateSCIMToken(ctx, f.orgA.ID, "old")
	toks, _ := f.ids.SCIMTokens(ctx, f.orgA.ID)
	f.ids.RevokeSCIMToken(ctx, f.orgA.ID, toks[0].ID)

	for _, tc := range []struct{ name, header string }{
		{"missing", ""},
		{"basic scheme", "Basic " + f.tokA},
		{"bogus token", "Bearer augscim_nope"},
		{"wrong prefix", "Bearer " + strings.TrimPrefix(f.tokA, "augscim_")},
		{"revoked", "Bearer " + revoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			f.srv.ServeHTTP(rec, req)
			var body map[string]any
			json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != 401 || body["status"] != "401" || rec.Header().Get("Content-Type") != contentType {
				t.Fatalf("got %d %v", rec.Code, body)
			}
		})
	}
	// Lower-case scheme is accepted.
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "bearer "+f.tokA)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("lower-case bearer: %d", rec.Code)
	}
}

func TestDiscovery(t *testing.T) {
	f := setup(t)
	r := f.do(t, f.tokA, "GET", "/ServiceProviderConfig", nil)
	f.mustCode(t, r, 200)
	if r.body["patch"].(map[string]any)["supported"] != true || r.body["bulk"].(map[string]any)["supported"] != false {
		t.Fatalf("spc %v", r.body)
	}
	for _, p := range []string{"/ResourceTypes", "/ResourceTypes/User", "/Schemas", "/Schemas/" + schemaGroup} {
		f.mustCode(t, f.do(t, f.tokA, "GET", p, nil), 200)
	}
	f.mustCode(t, f.do(t, f.tokA, "GET", "/Schemas/nope", nil), 404)
	f.mustCode(t, f.do(t, f.tokA, "GET", "/Nope", nil), 404)
}

func TestCreateGetUser(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	r := f.do(t, f.tokA, "POST", "/Users", userBody("Ada@Acme.example", map[string]any{"externalId": "00u1", "displayName": "Ada L"}))
	f.mustCode(t, r, 201)
	id := r.body["id"].(string)
	u, _ := f.ids.UserByEmail(ctx, "ada@acme.example")
	if id == strconv.FormatInt(u.ID, 10) || len(id) != 36 {
		t.Fatalf("SCIM id %q must be a UUID, not the DB id", id)
	}
	if r.hdr.Get("Location") != base+"/Users/"+id || r.body["meta"].(map[string]any)["location"] != base+"/Users/"+id {
		t.Fatalf("location %v", r.body["meta"])
	}
	if r.body["userName"] != "Ada@Acme.example" || r.body["externalId"] != "00u1" || r.body["active"] != true {
		t.Fatalf("round trip %v", r.body)
	}
	if u.Name != "Ada L" {
		t.Fatalf("users.name = %q", u.Name)
	}
	if got := f.role(t, f.orgA.ID, "ada@acme.example"); got != identity.RoleViewer {
		t.Fatalf("role %v", got)
	}
	ms, _ := f.ids.Members(ctx, f.orgA.ID)
	for _, m := range ms {
		if m.User.ID == u.ID && m.Source != "scim" {
			t.Fatalf("source %q", m.Source)
		}
	}

	g := f.do(t, f.tokA, "GET", "/Users/"+id, nil)
	f.mustCode(t, g, 200)
	if g.body["name"].(map[string]any)["givenName"] != "Ada" || g.body["meta"].(map[string]any)["resourceType"] != "User" {
		t.Fatalf("get %v", g.body)
	}

	for _, tc := range []struct {
		name   string
		body   any
		code   int
		scimTy string
	}{
		{"duplicate", userBody("ada@acme.example", nil), 409, "uniqueness"},
		{"unverified domain", userBody("x@pending.example", nil), 400, "invalidValue"},
		{"foreign domain", userBody("x@beta.example", nil), 400, "invalidValue"},
		{"not an email", userBody("ada", nil), 400, "invalidValue"},
		{"missing userName", map[string]any{"active": true}, 400, "invalidValue"},
		{"bad json", "{", 400, "invalidSyntax"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.do(t, f.tokA, "POST", "/Users", tc.body)
			if r.code != tc.code || r.body["scimType"] != tc.scimTy || r.body["status"] != strconv.Itoa(tc.code) {
				t.Fatalf("got %d %v", r.code, r.body)
			}
		})
	}
	if _, err := f.ids.UserByEmail(ctx, "x@beta.example"); err == nil {
		t.Fatal("refused create still made a user")
	}
	f.mustCode(t, f.do(t, f.tokA, "GET", "/Users/"+strconv.FormatInt(u.ID, 10), nil), 404)

	// Wrong content type.
	req := httptest.NewRequest("POST", "/scim/v2/Users", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+f.tokA)
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	if rec.Code != 415 {
		t.Fatalf("content type: %d", rec.Code)
	}
	// Oversized body.
	big := `{"userName":"big@acme.example","displayName":"` + strings.Repeat("x", maxBody) + `"}`
	f.mustCode(t, f.do(t, f.tokA, "POST", "/Users", big), 413)
}

func TestListFilterPaginate(t *testing.T) {
	f := setup(t)
	for i := 1; i <= 5; i++ {
		f.do(t, f.tokA, "POST", "/Users", userBody("u"+strconv.Itoa(i)+"@acme.example", map[string]any{"externalId": "ext" + strconv.Itoa(i)}))
	}
	f.createUser(t, f.tokB, "other@beta.example")

	for _, tc := range []struct {
		filter string
		total  int
		code   int
	}{
		{"", 5, 200},
		{`userName eq "u2@acme.example"`, 1, 200},
		{`USERNAME Eq "U2@ACME.EXAMPLE"`, 1, 200},
		{`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "u2@acme.example"`, 1, 200},
		{`externalId eq "ext3"`, 1, 200},
		{`externalId eq "EXT3"`, 0, 200},
		{`emails.value eq "u4@acme.example"`, 1, 200},
		{`emails[type eq "work"].value eq "u5@acme.example"`, 1, 200},
		{`userName eq "u1@acme.example" or userName eq "u2@acme.example"`, 2, 200},
		{`userName eq "u1@acme.example" and externalId eq "ext1"`, 1, 200},
		{`userName eq "u1@acme.example" and externalId eq "ext2"`, 0, 200},
		{`(userName eq "u1@acme.example" or userName eq "u2@acme.example") and externalId eq "ext2"`, 1, 200},
		{`userName eq "other@beta.example"`, 0, 200},
		{`userName co "u"`, 0, 400},
		{`displayName eq "x"`, 0, 400},
		{`userName eq`, 0, 400},
		{`title eq "x"`, 0, 400},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			r := f.do(t, f.tokA, "GET", "/Users?filter="+urlq(tc.filter), nil)
			f.mustCode(t, r, tc.code)
			if tc.code == 200 && int(r.body["totalResults"].(float64)) != tc.total {
				t.Fatalf("total %v want %d", r.body["totalResults"], tc.total)
			}
			if tc.code == 400 && r.body["scimType"] != "invalidFilter" {
				t.Fatalf("scimType %v", r.body["scimType"])
			}
		})
	}

	r := f.do(t, f.tokA, "GET", "/Users?startIndex=2&count=2", nil)
	f.mustCode(t, r, 200)
	res := r.body["Resources"].([]any)
	if len(res) != 2 || r.body["startIndex"].(float64) != 2 || r.body["itemsPerPage"].(float64) != 2 || r.body["totalResults"].(float64) != 5 {
		t.Fatalf("page %v", r.body)
	}
	if res[0].(map[string]any)["userName"] != "u2@acme.example" {
		t.Fatalf("page order %v", res[0])
	}
	r = f.do(t, f.tokA, "GET", "/Users?count=0", nil)
	if len(r.body["Resources"].([]any)) != 0 || r.body["totalResults"].(float64) != 5 {
		t.Fatalf("count=0 %v", r.body)
	}
	r = f.do(t, f.tokA, "GET", "/Users?count=100000", nil)
	if len(r.body["Resources"].([]any)) != 5 {
		t.Fatalf("count cap %v", r.body)
	}
}

func urlq(s string) string {
	return strings.NewReplacer(" ", "%20", `"`, "%22", "[", "%5B", "]", "%5D", "(", "%28", ")", "%29").Replace(s)
}

func TestLinkExistingUser(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// A user with an acme.example address who already belongs to org B.
	u, _ := f.ids.CreateUser(ctx, "shared@acme.example", "Original")
	f.ids.SetMembership(ctx, f.orgB.ID, u.ID, identity.RoleDeveloper, "manual")
	r := f.do(t, f.tokA, "POST", "/Users", userBody("shared@acme.example", map[string]any{"displayName": "From IdP"}))
	f.mustCode(t, r, 201)
	id := r.body["id"].(string)
	got, _ := f.ids.UserByEmail(ctx, "shared@acme.example")
	if got.ID != u.ID || got.Name != "Original" {
		t.Fatalf("linked user changed globally: %+v", got)
	}
	if f.role(t, f.orgA.ID, u.Email) != identity.RoleViewer || f.role(t, f.orgB.ID, u.Email) != identity.RoleDeveloper {
		t.Fatal("memberships wrong")
	}
	// userName change on a shared user is refused.
	r = f.do(t, f.tokA, "PATCH", "/Users/"+id, patch(map[string]any{"op": "replace", "path": "userName", "value": "renamed@acme.example"}))
	if r.code != 400 || r.body["scimType"] != "mutability" {
		t.Fatalf("rename shared: %d %v", r.code, r.body)
	}
	// Deactivating leaves the user active (still in org B).
	f.mustCode(t, f.do(t, f.tokA, "PATCH", "/Users/"+id, patch(map[string]any{"op": "replace", "value": map[string]any{"active": false}})), 200)
	got, _ = f.ids.UserByEmail(ctx, "shared@acme.example")
	if got.Status != identity.StatusActive || f.role(t, f.orgA.ID, u.Email) != identity.RoleNone || f.role(t, f.orgB.ID, u.Email) != identity.RoleDeveloper {
		t.Fatalf("deactivate shared: %+v", got)
	}
}

func TestPatchOktaDeactivateReactivate(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := f.createUser(t, f.tokA, "bob@acme.example")
	u, _ := f.ids.UserByEmail(ctx, "bob@acme.example")
	f.ids.CreateSession(ctx, identity.NewSession{UserID: u.ID, Method: "oidc"}, identity.SessionPolicy{Idle: time.Hour, Max: time.Hour})

	r := f.do(t, f.tokA, "PATCH", "/Users/"+id, patch(
		map[string]any{"op": "replace", "value": map[string]any{"active": false}},
	))
	f.mustCode(t, r, 200)
	if r.body["active"] != false {
		t.Fatalf("active %v", r.body["active"])
	}
	u, _ = f.ids.UserByEmail(ctx, "bob@acme.example")
	sess, _ := f.ids.UserSessions(ctx, u.ID)
	if u.Status != identity.StatusDeprovisioned || len(sess) != 0 || f.role(t, f.orgA.ID, u.Email) != identity.RoleNone {
		t.Fatalf("deactivate: status %s sessions %d", u.Status, len(sess))
	}

	r = f.do(t, f.tokA, "PATCH", "/Users/"+id, patch(
		map[string]any{"op": "replace", "value": map[string]any{"active": true, "name": map[string]any{"givenName": "Robert"}}},
	))
	f.mustCode(t, r, 200)
	u, _ = f.ids.UserByEmail(ctx, "bob@acme.example")
	if u.Status != identity.StatusActive || f.role(t, f.orgA.ID, u.Email) != identity.RoleViewer {
		t.Fatalf("reactivate: %+v", u)
	}
	nm := r.body["name"].(map[string]any)
	if nm["givenName"] != "Robert" || nm["familyName"] != "Lovelace" {
		t.Fatalf("name merge %v", nm)
	}

	// PUT replaces the resource.
	r = f.do(t, f.tokA, "PUT", "/Users/"+id, map[string]any{"userName": "bob@acme.example", "displayName": "Bob", "active": true})
	f.mustCode(t, r, 200)
	if r.body["name"] != nil || r.body["displayName"] != "Bob" || r.body["emails"] != nil {
		t.Fatalf("put %v", r.body)
	}

	// Audit trail: actor scim, never the token.
	evs, _ := f.ids.AuditLog(ctx, f.orgA.ID, 0, 100)
	seen := map[string]bool{}
	for _, e := range evs {
		if e.Actor == "scim" {
			seen[e.Action] = true
		}
		if strings.Contains(e.Detail+e.Target, f.tokA) {
			t.Fatal("token in audit log")
		}
	}
	for _, a := range []string{"scim.user.create", "scim.user.deactivate", "scim.user.reactivate", "scim.user.update"} {
		if !seen[a] {
			t.Fatalf("missing audit %s in %v", a, seen)
		}
	}
}

func TestPatchEntra(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := f.createUser(t, f.tokA, "eve@acme.example")
	r := f.do(t, f.tokA, "PATCH", "/Users/"+id, patch(
		map[string]any{"op": "Replace", "path": "name.givenName", "value": "Evelyn"},
		map[string]any{"op": "Add", "path": `emails[type eq "work"].value`, "value": "eve.w@acme.example"},
		map[string]any{"op": "Add", "path": `emails[type eq "home"].value`, "value": "eve@home.example"},
		map[string]any{"op": "Replace", "path": "displayName", "value": "Evelyn W"},
		map[string]any{"op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Ops"},
		map[string]any{"op": "Replace", "path": "title", "value": "Boss"},
		map[string]any{"op": "Replace", "path": "externalId", "value": "aad-1"},
	))
	f.mustCode(t, r, 200)
	emails := r.body["emails"].([]any)
	if len(emails) != 2 || emails[0].(map[string]any)["value"] != "eve.w@acme.example" || r.body["name"].(map[string]any)["givenName"] != "Evelyn" || r.body["externalId"] != "aad-1" {
		t.Fatalf("entra patch %v", r.body)
	}
	if u, _ := f.ids.UserByEmail(ctx, "eve@acme.example"); u.Name != "Evelyn W" {
		t.Fatalf("name %q", u.Name)
	}
	// Filter by the new work email.
	l := f.do(t, f.tokA, "GET", "/Users?filter="+urlq(`emails[type eq "work"].value eq "eve.w@acme.example"`), nil)
	if l.body["totalResults"].(float64) != 1 {
		t.Fatalf("filter work email %v", l.body)
	}
	// Remove the home email, then deactivate with Entra's string boolean.
	r = f.do(t, f.tokA, "PATCH", "/Users/"+id, patch(
		map[string]any{"op": "Remove", "path": `emails[type eq "home"]`},
		map[string]any{"op": "Replace", "path": "active", "value": "False"},
	))
	f.mustCode(t, r, 200)
	if r.body["active"] != false || len(r.body["emails"].([]any)) != 1 {
		t.Fatalf("entra deactivate %v", r.body)
	}
	if f.role(t, f.orgA.ID, "eve@acme.example") != identity.RoleNone {
		t.Fatal("membership kept")
	}
	// Bad ops.
	for _, body := range []any{
		patch(map[string]any{"op": "move", "path": "active", "value": true}),
		patch(map[string]any{"op": "remove"}),
		patch(map[string]any{"op": "replace", "path": "active", "value": "maybe"}),
		map[string]any{"Operations": []any{}},
	} {
		if r := f.do(t, f.tokA, "PATCH", "/Users/"+id, body); r.code != 400 {
			t.Fatalf("bad op %v: %d", body, r.code)
		}
	}
	// Renaming to an address in an unverified domain is refused.
	r = f.do(t, f.tokA, "PATCH", "/Users/"+id, patch(map[string]any{"op": "replace", "path": "userName", "value": "eve@pending.example"}))
	if r.code != 400 || r.body["scimType"] != "invalidValue" {
		t.Fatalf("rename unverified %d %v", r.code, r.body)
	}
	// Renaming within a verified domain works for a user only in this org.
	r = f.do(t, f.tokA, "PATCH", "/Users/"+id, patch(map[string]any{"op": "replace", "path": "userName", "value": "evelyn@acme.example"}))
	f.mustCode(t, r, 200)
	if _, err := f.ids.UserByEmail(ctx, "evelyn@acme.example"); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteUser(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := f.createUser(t, f.tokA, "del@acme.example")
	f.mustCode(t, f.do(t, f.tokA, "DELETE", "/Users/"+id, nil), 204)
	f.mustCode(t, f.do(t, f.tokA, "GET", "/Users/"+id, nil), 404)
	f.mustCode(t, f.do(t, f.tokA, "DELETE", "/Users/"+id, nil), 404)
	u, _ := f.ids.UserByEmail(ctx, "del@acme.example")
	if u.Status != identity.StatusDeprovisioned || f.role(t, f.orgA.ID, u.Email) != identity.RoleNone {
		t.Fatalf("delete: %+v", u)
	}
	// Re-provisioning reactivates.
	f.createUser(t, f.tokA, "del@acme.example")
	u, _ = f.ids.UserByEmail(ctx, "del@acme.example")
	if u.Status != identity.StatusActive || f.role(t, f.orgA.ID, u.Email) != identity.RoleViewer {
		t.Fatalf("recreate: %+v", u)
	}
}

func TestGroupsAndRoles(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.ids.AddGroupMapping(ctx, identity.GroupMapping{OrgID: f.orgA.ID, Source: identity.SourceSCIM, Group: "Geo Admins", Role: identity.RoleAdmin})
	f.ids.AddGroupMapping(ctx, identity.GroupMapping{OrgID: f.orgA.ID, Source: identity.SourceSCIM, Group: "Geo Devs", Role: identity.RoleDeveloper})
	alice := f.createUser(t, f.tokA, "alice@acme.example")
	bob := f.createUser(t, f.tokA, "bob@acme.example")

	r := f.do(t, f.tokA, "POST", "/Groups", map[string]any{"schemas": []string{schemaGroup}, "displayName": "Geo Admins", "externalId": "g1",
		"members": []any{map[string]any{"value": alice}}})
	f.mustCode(t, r, 201)
	admins := r.body["id"].(string)
	if len(r.body["members"].([]any)) != 1 || f.role(t, f.orgA.ID, "alice@acme.example") != identity.RoleAdmin {
		t.Fatalf("create group %v", r.body)
	}
	f.mustCode(t, f.do(t, f.tokA, "POST", "/Groups", map[string]any{"displayName": "Geo Admins"}), 409)

	r = f.do(t, f.tokA, "POST", "/Groups", map[string]any{"displayName": "Geo Devs"})
	f.mustCode(t, r, 201)
	devs := r.body["id"].(string)

	// Entra-style add with a value array; Alice keeps her highest role.
	f.mustCode(t, f.do(t, f.tokA, "PATCH", "/Groups/"+devs, patch(
		map[string]any{"op": "Add", "path": "members", "value": []any{map[string]any{"value": alice}, map[string]any{"value": bob}}},
	)), 204)
	if f.role(t, f.orgA.ID, "alice@acme.example") != identity.RoleAdmin || f.role(t, f.orgA.ID, "bob@acme.example") != identity.RoleDeveloper {
		t.Fatal("roles after dev add")
	}
	// Okta-style remove by filter path.
	f.mustCode(t, f.do(t, f.tokA, "PATCH", "/Groups/"+admins, patch(
		map[string]any{"op": "remove", "path": `members[value eq "` + alice + `"]`},
	)), 204)
	if f.role(t, f.orgA.ID, "alice@acme.example") != identity.RoleDeveloper {
		t.Fatal("alice should drop to developer")
	}
	// Entra-style remove with value array.
	f.mustCode(t, f.do(t, f.tokA, "PATCH", "/Groups/"+devs, patch(
		map[string]any{"op": "Remove", "path": "members", "value": []any{map[string]any{"value": bob}}},
	)), 204)
	if f.role(t, f.orgA.ID, "bob@acme.example") != identity.RoleViewer {
		t.Fatal("bob should fall back to the default role")
	}
	// Renaming a group re-evaluates mappings.
	f.mustCode(t, f.do(t, f.tokA, "PATCH", "/Groups/"+devs, patch(
		map[string]any{"op": "replace", "value": map[string]any{"id": devs, "displayName": "Geo Admins 2"}},
	)), 204)
	if f.role(t, f.orgA.ID, "alice@acme.example") != identity.RoleViewer {
		t.Fatal("rename should drop alice to default")
	}
	f.mustCode(t, f.do(t, f.tokA, "PUT", "/Groups/"+devs, map[string]any{"displayName": "Geo Admins", "members": []any{}}), 409)

	// List with filter and excludedAttributes.
	r = f.do(t, f.tokA, "GET", "/Groups?filter="+urlq(`displayName eq "Geo Admins"`)+"&excludedAttributes=members", nil)
	f.mustCode(t, r, 200)
	res := r.body["Resources"].([]any)
	if r.body["totalResults"].(float64) != 1 || res[0].(map[string]any)["members"] != nil {
		t.Fatalf("group list %v", r.body)
	}
	r = f.do(t, f.tokA, "GET", "/Groups?filter="+urlq(`externalId eq "g1"`), nil)
	if r.body["totalResults"].(float64) != 1 {
		t.Fatalf("externalId filter %v", r.body)
	}
	f.mustCode(t, f.do(t, f.tokA, "GET", "/Groups?filter="+urlq(`userName eq "x"`), nil), 400)

	// PUT replaces members; GET shows them.
	r = f.do(t, f.tokA, "PUT", "/Groups/"+admins, map[string]any{"displayName": "Geo Admins", "members": []any{map[string]any{"value": bob}}})
	f.mustCode(t, r, 200)
	if f.role(t, f.orgA.ID, "bob@acme.example") != identity.RoleAdmin {
		t.Fatal("put members")
	}
	g := f.do(t, f.tokA, "GET", "/Groups/"+admins, nil)
	mem := g.body["members"].([]any)
	if len(mem) != 1 || mem[0].(map[string]any)["value"] != bob || mem[0].(map[string]any)["display"] != "bob@acme.example" {
		t.Fatalf("members %v", g.body)
	}
	// Deactivating a group member, then deleting the group.
	f.mustCode(t, f.do(t, f.tokA, "DELETE", "/Groups/"+admins, nil), 204)
	if f.role(t, f.orgA.ID, "bob@acme.example") != identity.RoleViewer {
		t.Fatal("delete group should reset role")
	}
	f.mustCode(t, f.do(t, f.tokA, "GET", "/Groups/"+admins, nil), 404)

	// Unknown member.
	r = f.do(t, f.tokA, "POST", "/Groups", map[string]any{"displayName": "X", "members": []any{map[string]any{"value": "nope"}}})
	if r.code != 400 || r.body["scimType"] != "invalidValue" {
		t.Fatalf("unknown member %d %v", r.code, r.body)
	}
}

func TestManualMembershipNotChanged(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.ids.AddGroupMapping(ctx, identity.GroupMapping{OrgID: f.orgA.ID, Source: identity.SourceSCIM, Group: "Admins", Role: identity.RoleAdmin})
	u, _ := f.ids.CreateUser(ctx, "dev@acme.example", "")
	f.ids.SetMembership(ctx, f.orgA.ID, u.ID, identity.RoleDeveloper, "manual")
	id := f.createUser(t, f.tokA, "dev@acme.example")
	owner := f.createUser(t, f.tokA, "owner@acme.example")
	f.mustCode(t, f.do(t, f.tokA, "POST", "/Groups", map[string]any{"displayName": "Admins",
		"members": []any{map[string]any{"value": id}, map[string]any{"value": owner}}}), 201)
	if f.role(t, f.orgA.ID, "dev@acme.example") != identity.RoleDeveloper || f.role(t, f.orgA.ID, "owner@acme.example") != identity.RoleOwner {
		t.Fatal("manual memberships must not follow SCIM groups")
	}
}

func TestLastOwner(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// Linking the org's only owner and deactivating them is refused.
	owner := f.createUser(t, f.tokA, "owner@acme.example")
	r := f.do(t, f.tokA, "PATCH", "/Users/"+owner, patch(map[string]any{"op": "replace", "path": "active", "value": false}))
	if r.code != 400 || !strings.Contains(r.body["detail"].(string), "owner") {
		t.Fatalf("last owner deactivate %d %v", r.code, r.body)
	}
	f.mustCode(t, f.do(t, f.tokA, "DELETE", "/Users/"+owner, nil), 400)
	if f.role(t, f.orgA.ID, "owner@acme.example") != identity.RoleOwner {
		t.Fatal("owner removed")
	}
	if g := f.do(t, f.tokA, "GET", "/Users/"+owner, nil); g.body["active"] != true {
		t.Fatal("refused deactivate was persisted")
	}

	// A SCIM-mapped owner becomes the last owner; removing them from the
	// group is refused and changes nothing.
	f.ids.AddGroupMapping(ctx, identity.GroupMapping{OrgID: f.orgA.ID, Source: identity.SourceSCIM, Group: "Owners", Role: identity.RoleOwner})
	carol := f.createUser(t, f.tokA, "carol@acme.example")
	r = f.do(t, f.tokA, "POST", "/Groups", map[string]any{"displayName": "Owners", "members": []any{map[string]any{"value": carol}}})
	f.mustCode(t, r, 201)
	grp := r.body["id"].(string)
	if f.role(t, f.orgA.ID, "carol@acme.example") != identity.RoleOwner {
		t.Fatal("carol should be owner")
	}
	if err := f.ids.RemoveMember(ctx, f.orgA.ID, f.ownerA.ID); err != nil {
		t.Fatal(err)
	}
	r = f.do(t, f.tokA, "PATCH", "/Groups/"+grp, patch(map[string]any{"op": "remove", "path": "members"}))
	if r.code != 400 {
		t.Fatalf("last owner group remove %d %v", r.code, r.body)
	}
	g := f.do(t, f.tokA, "GET", "/Groups/"+grp, nil)
	if len(g.body["members"].([]any)) != 1 || f.role(t, f.orgA.ID, "carol@acme.example") != identity.RoleOwner {
		t.Fatal("refused group change was persisted")
	}
}

func TestCrossOrgIsolation(t *testing.T) {
	f := setup(t)
	userA := f.createUser(t, f.tokA, "a1@acme.example")
	r := f.do(t, f.tokA, "POST", "/Groups", map[string]any{"displayName": "A team", "members": []any{map[string]any{"value": userA}}})
	f.mustCode(t, r, 201)
	groupA := r.body["id"].(string)
	userB := f.createUser(t, f.tokB, "b1@beta.example")
	r = f.do(t, f.tokB, "POST", "/Groups", map[string]any{"displayName": "B team"})
	f.mustCode(t, r, 201)
	groupB := r.body["id"].(string)

	for _, tc := range []struct {
		name, method, path string
		body               any
		code               int
	}{
		{"get user", "GET", "/Users/" + userA, nil, 404},
		{"put user", "PUT", "/Users/" + userA, userBody("a1@acme.example", nil), 404},
		{"patch user", "PATCH", "/Users/" + userA, patch(map[string]any{"op": "replace", "path": "active", "value": false}), 404},
		{"delete user", "DELETE", "/Users/" + userA, nil, 404},
		{"get group", "GET", "/Groups/" + groupA, nil, 404},
		{"patch group", "PATCH", "/Groups/" + groupA, patch(map[string]any{"op": "remove", "path": "members"}), 404},
		{"delete group", "DELETE", "/Groups/" + groupA, nil, 404},
		{"add A user to B group", "PATCH", "/Groups/" + groupB, patch(map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": userA}}}), 400},
		{"create B group with A user", "POST", "/Groups", map[string]any{"displayName": "sneaky", "members": []any{map[string]any{"value": userA}}}, 400},
		{"provision A-domain user", "POST", "/Users", userBody("a2@acme.example", nil), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.mustCode(t, f.do(t, f.tokB, tc.method, tc.path, tc.body), tc.code)
		})
	}
	for _, p := range []string{"/Users", "/Groups", "/Users?filter=" + urlq(`userName eq "a1@acme.example"`), "/Groups?filter=" + urlq(`id eq "`+groupA+`"`)} {
		r := f.do(t, f.tokB, "GET", p, nil)
		for _, res := range r.body["Resources"].([]any) {
			id := res.(map[string]any)["id"]
			if id == userA || id == groupA {
				t.Fatalf("%s leaked org A resource", p)
			}
		}
	}
	// Org A is untouched.
	if f.role(t, f.orgA.ID, "a1@acme.example") != identity.RoleViewer {
		t.Fatal("org A membership changed")
	}
	g := f.do(t, f.tokA, "GET", "/Groups/"+groupA, nil)
	if len(g.body["members"].([]any)) != 1 {
		t.Fatal("org A group changed")
	}
	f.mustCode(t, f.do(t, f.tokA, "GET", "/Users/"+userB, nil), 404)
}

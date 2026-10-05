// Package scim is the SCIM 2.0 provisioning server (docs/auth.md "SCIM 2.0").
//
// It implements the parts of RFC 7643/7644 that Okta, Microsoft Entra ID and
// OneLogin use: discovery, Users and Groups with create, get, filtered list,
// replace, patch and delete. Every request is authenticated by an org SCIM
// token and every store call is scoped to that org.
package scim

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"augeocoding/internal/identity"
	"ausystem/shared/slog"
)

// Server serves /scim/v2/.
type Server struct {
	IDs     *identity.Store
	Log     *slog.Logger
	BaseURL string // absolute, e.g. https://geo.example.com/scim/v2
}

const (
	schemaUser      = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup     = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaEnterpris = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	schemaList      = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaPatch     = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaError     = "urn:ietf:params:scim:api:messages:2.0:Error"
	contentType     = "application/scim+json"

	maxBody     = 1 << 20
	maxCount    = 200
	defCount    = 100
	maxOps      = 1000
	maxMembers  = 10000
	maxFilter   = 1000
	mountPrefix = "/scim/v2"
)

// scimError is an RFC 7644 §3.12 error.
type scimError struct {
	status   int
	scimType string
	detail   string
}

func (e *scimError) Error() string { return e.detail }

func errBad(scimType, detail string) *scimError {
	return &scimError{status: http.StatusBadRequest, scimType: scimType, detail: detail}
}

var (
	errNotFound     = &scimError{status: http.StatusNotFound, detail: "resource not found"}
	errUnauthorized = &scimError{status: http.StatusUnauthorized, detail: "invalid or missing bearer token"}
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if i := strings.Index(path, mountPrefix); i >= 0 {
		path = path[i+len(mountPrefix):]
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")

	orgID, err := s.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		s.writeErr(w, errUnauthorized)
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		if ct := r.Header.Get("Content-Type"); ct != "" {
			mt, _, err := mime.ParseMediaType(ct)
			if err != nil || (mt != contentType && mt != "application/json") {
				s.writeErr(w, &scimError{status: http.StatusUnsupportedMediaType, detail: "content type must be application/scim+json"})
				return
			}
		}
	}

	c := &call{s: s, w: w, r: r, org: orgID}
	switch {
	case len(parts) == 1 && parts[0] == "ServiceProviderConfig" && r.Method == http.MethodGet:
		c.write(http.StatusOK, serviceProviderConfig(s.BaseURL))
	case len(parts) >= 1 && parts[0] == "ResourceTypes" && r.Method == http.MethodGet:
		c.discovery(resourceTypes(s.BaseURL), parts[1:])
	case len(parts) >= 1 && parts[0] == "Schemas" && r.Method == http.MethodGet:
		c.discovery(schemas(s.BaseURL), parts[1:])
	case parts[0] == "Users" && len(parts) <= 2:
		c.users(parts[1:])
	case parts[0] == "Groups" && len(parts) <= 2:
		c.groups(parts[1:])
	default:
		s.writeErr(w, errNotFound)
	}
}

func (s *Server) authenticate(r *http.Request) (int64, error) {
	h := r.Header.Get("Authorization")
	const p = "bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return 0, errUnauthorized
	}
	return s.IDs.AuthenticateSCIM(r.Context(), strings.TrimSpace(h[len(p):]))
}

// call is one authenticated request.
type call struct {
	s   *Server
	w   http.ResponseWriter
	r   *http.Request
	org int64
}

func (c *call) write(status int, v any) {
	c.w.Header().Set("Content-Type", contentType)
	c.w.WriteHeader(status)
	json.NewEncoder(c.w).Encode(v)
}

func (c *call) fail(err error) { c.s.writeErr(c.w, err) }

func (s *Server) writeErr(w http.ResponseWriter, err error) {
	var se *scimError
	if !errors.As(err, &se) {
		se = mapStoreErr(err)
		if se.status == http.StatusInternalServerError && s.Log != nil {
			s.Log.Error("scim_error", "err", err.Error())
		}
	}
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(se.status), "detail": se.detail}
	if se.scimType != "" {
		body["scimType"] = se.scimType
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(se.status)
	json.NewEncoder(w).Encode(body)
}

func mapStoreErr(err error) *scimError {
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		return &scimError{status: http.StatusRequestEntityTooLarge, detail: "request body too large"}
	case errors.Is(err, identity.ErrNotFound):
		return errNotFound
	case errors.Is(err, identity.ErrConflict):
		return &scimError{status: http.StatusConflict, scimType: "uniqueness", detail: "a resource with this identifier already exists"}
	case errors.Is(err, identity.ErrLastOwner):
		return errBad("invalidValue", "an org must keep at least one owner; assign another owner first")
	case errors.Is(err, identity.ErrSCIMDomain):
		return errBad("invalidValue", identity.ErrSCIMDomain.Error())
	case errors.Is(err, identity.ErrSCIMForeign):
		return errBad("invalidValue", identity.ErrSCIMForeign.Error())
	case errors.Is(err, identity.ErrSCIMShared):
		return errBad("mutability", identity.ErrSCIMShared.Error())
	case errors.Is(err, identity.ErrSCIMMember):
		return errBad("invalidValue", identity.ErrSCIMMember.Error())
	case errors.Is(err, identity.ErrInvalid):
		return errBad("invalidValue", "invalid value")
	}
	return &scimError{status: http.StatusInternalServerError, detail: "internal error"}
}

func (c *call) audit(action, target, detail string) {
	if err := c.s.IDs.Audit(c.r.Context(), identity.AuditEvent{OrgID: c.org, Actor: "scim", Action: action, Target: target, Detail: detail}); err != nil && c.s.Log != nil {
		c.s.Log.Error("scim_audit_failed", "action", action, "err", err.Error())
	}
}

// decode reads a JSON object body.
func (c *call) decode() (map[string]any, error) {
	var m map[string]any
	dec := json.NewDecoder(c.r.Body)
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, err
		}
		return nil, errBad("invalidSyntax", "request body is not a JSON object")
	}
	if m == nil {
		return nil, errBad("invalidSyntax", "request body is not a JSON object")
	}
	return m, nil
}

// page parses startIndex and count (RFC 7644 §3.4.2.4).
func (c *call) page() (offset, limit, start int) {
	q := c.r.URL.Query()
	start, err := strconv.Atoi(q.Get("startIndex"))
	if err != nil || start < 1 {
		start = 1
	}
	if start > 1<<30 {
		start = 1 << 30
	}
	limit = defCount
	if v := q.Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = max(n, 0)
		}
	}
	return start - 1, min(limit, maxCount), start
}

func (c *call) filter() (*identity.SCIMCond, error) {
	f := strings.TrimSpace(c.r.URL.Query().Get("filter"))
	if f == "" {
		return nil, nil
	}
	if len(f) > maxFilter {
		return nil, errBad("invalidFilter", "filter too long")
	}
	cond, err := parseFilter(f)
	if err != nil {
		return nil, errBad("invalidFilter", err.Error())
	}
	return &cond, nil
}

func listResponse(total, start int, res []any) map[string]any {
	if res == nil {
		res = []any{}
	}
	return map[string]any{"schemas": []string{schemaList}, "totalResults": total, "startIndex": start, "itemsPerPage": len(res), "Resources": res}
}

func meta(resourceType, location string, created, updated time.Time) map[string]any {
	return map[string]any{
		"resourceType": resourceType,
		"created":      created.UTC().Format(time.RFC3339),
		"lastModified": updated.UTC().Format(time.RFC3339),
		"location":     location,
	}
}

// excluded reports whether attr is in excludedAttributes.
func (c *call) excluded(attr string) bool {
	for _, a := range strings.Split(c.r.URL.Query().Get("excludedAttributes"), ",") {
		if strings.EqualFold(strings.TrimSpace(a), attr) {
			return true
		}
	}
	return false
}

// --- generic JSON helpers (SCIM attribute names are case-insensitive) ---

func get(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func getStr(m map[string]any, key string) string {
	v, _ := get(m, key)
	return str(v)
}

// boolean accepts JSON booleans and Entra's "True"/"False" strings.
func boolean(v any) (bool, error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		if b, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(t))); err == nil {
			return b, nil
		}
	}
	return false, errBad("invalidValue", "expected a boolean")
}

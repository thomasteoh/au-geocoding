package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"augeocoding/internal/identity"
)

const maxEmails = 20

type userName struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

func (n *userName) set(sub string, v string) {
	switch strings.ToLower(sub) {
	case "formatted":
		n.Formatted = v
	case "familyname":
		n.FamilyName = v
	case "givenname":
		n.GivenName = v
	case "middlename":
		n.MiddleName = v
	case "honorificprefix":
		n.HonorificPrefix = v
	case "honorificsuffix":
		n.HonorificSuffix = v
	}
}

func (n userName) empty() bool { return n == userName{} }

type userEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// userData is the round-trip JSON kept in scim_users.data. userName keeps
// the IdP's casing; the users table holds the normalised email.
type userData struct {
	UserName    string      `json:"userName,omitempty"`
	Name        *userName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []userEmail `json:"emails,omitempty"`
}

// scimUser is the working state of a User resource.
type scimUser struct {
	externalID string
	active     bool
	d          userData
}

func (u *scimUser) input() (identity.SCIMUserInput, error) {
	if strings.TrimSpace(u.d.UserName) == "" {
		return identity.SCIMUserInput{}, errBad("invalidValue", "userName is required")
	}
	if !identity.ValidEmail(identity.NormaliseEmail(u.d.UserName)) {
		return identity.SCIMUserInput{}, errBad("invalidValue", "userName must be an email address")
	}
	if len(u.d.Emails) > maxEmails {
		return identity.SCIMUserInput{}, errBad("invalidValue", "too many emails")
	}
	if len(u.externalID) > 256 {
		return identity.SCIMUserInput{}, errBad("invalidValue", "externalId too long")
	}
	if u.d.Name != nil && u.d.Name.empty() {
		u.d.Name = nil
	}
	data, err := json.Marshal(u.d)
	if err != nil {
		return identity.SCIMUserInput{}, err
	}
	return identity.SCIMUserInput{Email: u.d.UserName, Name: u.displayName(), ExternalID: u.externalID, Active: u.active, Data: string(data)}, nil
}

func (u *scimUser) displayName() string {
	if u.d.DisplayName != "" {
		return u.d.DisplayName
	}
	if u.d.Name == nil {
		return ""
	}
	if u.d.Name.Formatted != "" {
		return u.d.Name.Formatted
	}
	return strings.TrimSpace(u.d.Name.GivenName + " " + u.d.Name.FamilyName)
}

func fromStored(su identity.SCIMUser) scimUser {
	u := scimUser{externalID: su.ExternalID, active: su.Active}
	json.Unmarshal([]byte(su.Data), &u.d)
	if !strings.EqualFold(u.d.UserName, su.Email) {
		u.d.UserName = su.Email
	}
	return u
}

// parseUser reads a full User resource (POST, PUT). Unknown attributes,
// including extension schemas, are ignored.
func parseUser(m map[string]any) (scimUser, error) {
	u := scimUser{active: true}
	u.d.UserName = strings.TrimSpace(getStr(m, "userName"))
	u.externalID = getStr(m, "externalId")
	u.d.DisplayName = getStr(m, "displayName")
	if v, ok := get(m, "active"); ok && v != nil {
		b, err := boolean(v)
		if err != nil {
			return u, err
		}
		u.active = b
	}
	if v, ok := get(m, "name"); ok {
		if nm, ok := v.(map[string]any); ok {
			n := &userName{}
			for k, sv := range nm {
				n.set(k, str(sv))
			}
			u.d.Name = n
		}
	}
	if v, ok := get(m, "emails"); ok {
		es, err := parseEmails(v)
		if err != nil {
			return u, err
		}
		u.d.Emails = es
	}
	return u, nil
}

func parseEmails(v any) ([]userEmail, error) {
	var items []any
	switch t := v.(type) {
	case []any:
		items = t
	case map[string]any:
		items = []any{t}
	case nil:
		return nil, nil
	default:
		return nil, errBad("invalidValue", "emails must be an array")
	}
	if len(items) > maxEmails {
		return nil, errBad("invalidValue", "too many emails")
	}
	var out []userEmail
	for _, it := range items {
		em, ok := it.(map[string]any)
		if !ok {
			return nil, errBad("invalidValue", "emails must hold objects")
		}
		e := userEmail{Value: strings.TrimSpace(getStr(em, "value")), Type: getStr(em, "type")}
		if p, ok := get(em, "primary"); ok && p != nil {
			e.Primary, _ = boolean(p)
		}
		if e.Value != "" {
			out = append(out, e)
		}
	}
	return out, nil
}

// --- PATCH ---

type patchOp struct {
	op    string // add, replace, remove
	path  string
	value any
}

func parsePatch(m map[string]any) ([]patchOp, error) {
	v, _ := get(m, "Operations")
	items, ok := v.([]any)
	if !ok || len(items) == 0 {
		return nil, errBad("invalidSyntax", "Operations must be a non-empty array")
	}
	if len(items) > maxOps {
		return nil, errBad("invalidSyntax", "too many operations")
	}
	var out []patchOp
	for _, it := range items {
		om, ok := it.(map[string]any)
		if !ok {
			return nil, errBad("invalidSyntax", "operation must be an object")
		}
		op := patchOp{op: strings.ToLower(getStr(om, "op")), path: strings.TrimSpace(getStr(om, "path"))}
		op.value, _ = get(om, "value")
		switch op.op {
		case "add", "replace":
			if op.path == "" {
				if _, ok := op.value.(map[string]any); !ok {
					return nil, errBad("invalidValue", "an operation without a path needs an object value")
				}
			}
		case "remove":
			if op.path == "" {
				return nil, errBad("noTarget", "remove needs a path")
			}
		default:
			return nil, errBad("invalidSyntax", "unknown op "+op.op)
		}
		out = append(out, op)
	}
	return out, nil
}

// attrPath is a parsed PATCH path: attr[filterAttr eq "filterVal"].sub.
type attrPath struct {
	attr, filterAttr, filterVal, sub string
	ignore                           bool // extension or unsupported schema
}

var pathRe = regexp.MustCompile(`^([A-Za-z][\w$-]*)(?:\[\s*([A-Za-z][\w$-]*)\s+(?i:eq)\s+"((?:[^"\\]|\\.)*)"\s*\])?(?:\.([A-Za-z][\w$-]*))?$`)

func parsePath(p string) (attrPath, error) {
	p = stripSchema(p)
	if strings.HasPrefix(strings.ToLower(p), "urn:") {
		return attrPath{ignore: true}, nil
	}
	m := pathRe.FindStringSubmatch(p)
	if m == nil {
		return attrPath{}, errBad("invalidPath", "unsupported path")
	}
	return attrPath{attr: strings.ToLower(m[1]), filterAttr: strings.ToLower(m[2]), filterVal: m[3], sub: strings.ToLower(m[4])}, nil
}

// expand turns a path-less add/replace into one op per attribute.
func expand(op patchOp) []patchOp {
	if op.path != "" {
		return []patchOp{op}
	}
	var out []patchOp
	for k, v := range op.value.(map[string]any) {
		out = append(out, patchOp{op: op.op, path: k, value: v})
	}
	return out
}

func (u *scimUser) apply(ops []patchOp) error {
	for _, raw := range ops {
		for _, op := range expand(raw) {
			if err := u.applyOne(op); err != nil {
				return err
			}
		}
	}
	if len(u.d.Emails) > maxEmails {
		return errBad("invalidValue", "too many emails")
	}
	return nil
}

func (u *scimUser) applyOne(op patchOp) error {
	p, err := parsePath(op.path)
	if err != nil || p.ignore {
		return err
	}
	remove := op.op == "remove"
	switch p.attr {
	case "username":
		if remove {
			return errBad("mutability", "userName cannot be removed")
		}
		u.d.UserName = strings.TrimSpace(str(op.value))
	case "externalid":
		u.externalID = ""
		if !remove {
			u.externalID = str(op.value)
		}
	case "displayname":
		u.d.DisplayName = ""
		if !remove {
			u.d.DisplayName = str(op.value)
		}
	case "active":
		if remove {
			return nil
		}
		b, err := boolean(op.value)
		if err != nil {
			return err
		}
		u.active = b
	case "name":
		if u.d.Name == nil {
			u.d.Name = &userName{}
		}
		switch {
		case p.sub != "" && remove:
			u.d.Name.set(p.sub, "")
		case p.sub != "":
			u.d.Name.set(p.sub, str(op.value))
		case remove:
			u.d.Name = nil
		default:
			nm, ok := op.value.(map[string]any)
			if !ok {
				return errBad("invalidValue", "name must be an object")
			}
			for k, v := range nm {
				u.d.Name.set(k, str(v))
			}
		}
	case "emails":
		return u.applyEmails(op, p)
	}
	return nil
}

func (u *scimUser) applyEmails(op patchOp, p attrPath) error {
	remove := op.op == "remove"
	if p.filterAttr != "" {
		if p.filterAttr != "type" && p.filterAttr != "value" {
			return errBad("invalidFilter", "unsupported emails filter")
		}
		match := func(e userEmail) bool {
			if p.filterAttr == "type" {
				return strings.EqualFold(e.Type, p.filterVal)
			}
			return strings.EqualFold(e.Value, p.filterVal)
		}
		if remove {
			kept := u.d.Emails[:0]
			for _, e := range u.d.Emails {
				if !match(e) {
					kept = append(kept, e)
				}
			}
			u.d.Emails = kept
			return nil
		}
		val := ""
		switch p.sub {
		case "value":
			val = strings.TrimSpace(str(op.value))
		case "":
			if em, ok := op.value.(map[string]any); ok {
				val = strings.TrimSpace(getStr(em, "value"))
			}
		default:
			return nil // primary, display: not round-tripped
		}
		if val == "" {
			return errBad("invalidValue", "email value required")
		}
		for i := range u.d.Emails {
			if match(u.d.Emails[i]) {
				u.d.Emails[i].Value = val
				return nil
			}
		}
		e := userEmail{Value: val, Primary: len(u.d.Emails) == 0}
		if p.filterAttr == "type" {
			e.Type = p.filterVal
		}
		u.d.Emails = append(u.d.Emails, e)
		return nil
	}
	if remove {
		u.d.Emails = nil
		return nil
	}
	if p.sub == "value" {
		val := strings.TrimSpace(str(op.value))
		if len(u.d.Emails) == 0 {
			u.d.Emails = []userEmail{{Value: val, Primary: true}}
		} else {
			u.d.Emails[0].Value = val
		}
		return nil
	}
	es, err := parseEmails(op.value)
	if err != nil {
		return err
	}
	if op.op == "replace" {
		u.d.Emails = es
		return nil
	}
	for _, e := range es {
		dup := false
		for i := range u.d.Emails {
			if strings.EqualFold(u.d.Emails[i].Value, e.Value) {
				u.d.Emails[i] = e
				dup = true
			}
		}
		if !dup {
			u.d.Emails = append(u.d.Emails, e)
		}
	}
	return nil
}

// --- handlers ---

func (c *call) userJSON(su identity.SCIMUser) map[string]any {
	u := fromStored(su)
	loc := c.s.BaseURL + "/Users/" + su.SCIMID
	out := map[string]any{
		"schemas":  []string{schemaUser},
		"id":       su.SCIMID,
		"userName": u.d.UserName,
		"active":   su.Active,
		"meta":     meta("User", loc, su.Created, su.Updated),
	}
	if su.ExternalID != "" {
		out["externalId"] = su.ExternalID
	}
	if u.d.Name != nil {
		out["name"] = u.d.Name
	}
	if u.d.DisplayName != "" {
		out["displayName"] = u.d.DisplayName
	}
	if len(u.d.Emails) > 0 {
		out["emails"] = u.d.Emails
	}
	return out
}

func (c *call) users(rest []string) {
	if len(rest) == 0 {
		switch c.r.Method {
		case http.MethodGet:
			c.listUsers()
		case http.MethodPost:
			c.createUser()
		default:
			c.fail(&scimError{status: http.StatusMethodNotAllowed, detail: "method not allowed"})
		}
		return
	}
	id := rest[0]
	switch c.r.Method {
	case http.MethodGet:
		su, err := c.s.IDs.SCIMUserByID(c.r.Context(), c.org, id)
		if err != nil {
			c.fail(err)
			return
		}
		c.write(http.StatusOK, c.userJSON(su))
	case http.MethodPut:
		c.replaceUser(id, nil)
	case http.MethodPatch:
		m, err := c.decode()
		if err != nil {
			c.fail(err)
			return
		}
		ops, err := parsePatch(m)
		if err != nil {
			c.fail(err)
			return
		}
		c.replaceUser(id, ops)
	case http.MethodDelete:
		su, err := c.s.IDs.DeleteSCIMUser(c.r.Context(), c.org, id)
		if err != nil {
			c.fail(err)
			return
		}
		c.audit("scim.user.delete", su.Email, "scim_id="+su.SCIMID)
		c.w.WriteHeader(http.StatusNoContent)
	default:
		c.fail(&scimError{status: http.StatusMethodNotAllowed, detail: "method not allowed"})
	}
}

func (c *call) listUsers() {
	cond, err := c.filter()
	if err != nil {
		c.fail(err)
		return
	}
	offset, limit, start := c.page()
	list, total, err := c.s.IDs.SCIMUsers(c.r.Context(), c.org, cond, offset, limit)
	if errors.Is(err, identity.ErrInvalid) {
		err = errBad("invalidFilter", "unsupported filter attribute for Users")
	}
	if err != nil {
		c.fail(err)
		return
	}
	res := make([]any, 0, len(list))
	for _, su := range list {
		res = append(res, c.userJSON(su))
	}
	c.write(http.StatusOK, listResponse(total, start, res))
}

func (c *call) createUser() {
	m, err := c.decode()
	if err != nil {
		c.fail(err)
		return
	}
	u, err := parseUser(m)
	if err != nil {
		c.fail(err)
		return
	}
	in, err := u.input()
	if err != nil {
		c.fail(err)
		return
	}
	su, err := c.s.IDs.CreateSCIMUser(c.r.Context(), c.org, in)
	if err != nil {
		c.fail(err)
		return
	}
	c.audit("scim.user.create", su.Email, "scim_id="+su.SCIMID+activeDetail(su.Active))
	c.w.Header().Set("Location", c.s.BaseURL+"/Users/"+su.SCIMID)
	c.write(http.StatusCreated, c.userJSON(su))
}

// replaceUser handles PUT (ops nil: the body is the full resource) and
// PATCH (ops applied to the stored resource). The read, the patch and the
// write run in one store transaction, so concurrent PATCHes cannot lose
// each other's changes.
func (c *call) replaceUser(id string, ops []patchOp) {
	ctx := c.r.Context()
	var put scimUser
	if ops == nil {
		m, err := c.decode()
		if err != nil {
			c.fail(err)
			return
		}
		if put, err = parseUser(m); err != nil {
			c.fail(err)
			return
		}
	}
	cur, su, changed, err := c.s.IDs.PatchSCIMUser(ctx, c.org, id, func(cur identity.SCIMUser) (identity.SCIMUserInput, error) {
		u := put
		if ops != nil {
			u = fromStored(cur)
			if err := u.apply(ops); err != nil {
				return identity.SCIMUserInput{}, err
			}
		}
		return u.input()
	})
	if err != nil {
		c.fail(err)
		return
	}
	action := "scim.user.update"
	switch changed {
	case 1:
		action = "scim.user.reactivate"
	case -1:
		action = "scim.user.deactivate"
	}
	detail := "scim_id=" + su.SCIMID
	if su.Email != cur.Email {
		detail += " previous=" + cur.Email
	}
	c.audit(action, su.Email, detail)
	c.write(http.StatusOK, c.userJSON(su))
}

func activeDetail(active bool) string {
	if active {
		return ""
	}
	return " active=false"
}

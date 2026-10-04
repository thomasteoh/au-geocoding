package scim

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"augeocoding/internal/identity"
)

// scimGroup is the working state of a Group resource. members holds SCIM
// user IDs in order, without duplicates.
type scimGroup struct {
	displayName string
	externalID  string
	members     []string
}

func (g *scimGroup) has(id string) bool {
	for _, m := range g.members {
		if m == id {
			return true
		}
	}
	return false
}

func (g *scimGroup) add(ids []string) error {
	for _, id := range ids {
		if !g.has(id) {
			g.members = append(g.members, id)
		}
	}
	if len(g.members) > maxMembers {
		return errBad("invalidValue", "too many members")
	}
	return nil
}

func (g *scimGroup) remove(ids []string) {
	drop := make(map[string]bool, len(ids))
	for _, id := range ids {
		drop[id] = true
	}
	kept := g.members[:0]
	for _, m := range g.members {
		if !drop[m] {
			kept = append(kept, m)
		}
	}
	g.members = kept
}

// memberIDs reads [{"value": "id"}, ...] or a single object.
func memberIDs(v any) ([]string, error) {
	var items []any
	switch t := v.(type) {
	case []any:
		items = t
	case map[string]any:
		items = []any{t}
	case nil:
		return nil, nil
	default:
		return nil, errBad("invalidValue", "members must be an array")
	}
	if len(items) > maxMembers {
		return nil, errBad("invalidValue", "too many members")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			return nil, errBad("invalidValue", "members must hold objects")
		}
		id := strings.TrimSpace(getStr(m, "value"))
		if id == "" {
			return nil, errBad("invalidValue", "member value required")
		}
		out = append(out, id)
	}
	return out, nil
}

func parseGroup(m map[string]any) (scimGroup, error) {
	g := scimGroup{displayName: strings.TrimSpace(getStr(m, "displayName")), externalID: getStr(m, "externalId")}
	if g.displayName == "" {
		return g, errBad("invalidValue", "displayName is required")
	}
	v, _ := get(m, "members")
	ids, err := memberIDs(v)
	if err != nil {
		return g, err
	}
	return g, g.add(ids)
}

func (g *scimGroup) apply(ops []patchOp) error {
	for _, raw := range ops {
		for _, op := range expand(raw) {
			if err := g.applyOne(op); err != nil {
				return err
			}
		}
	}
	if g.displayName == "" {
		return errBad("invalidValue", "displayName is required")
	}
	return nil
}

func (g *scimGroup) applyOne(op patchOp) error {
	p, err := parsePath(op.path)
	if err != nil || p.ignore {
		return err
	}
	remove := op.op == "remove"
	switch p.attr {
	case "displayname":
		if remove {
			return errBad("mutability", "displayName cannot be removed")
		}
		g.displayName = strings.TrimSpace(str(op.value))
	case "externalid":
		g.externalID = ""
		if !remove {
			g.externalID = str(op.value)
		}
	case "members":
		if p.filterAttr != "" {
			if p.filterAttr != "value" || !remove {
				return errBad("invalidPath", "only remove supports a members filter")
			}
			g.remove([]string{p.filterVal})
			return nil
		}
		ids, err := memberIDs(op.value)
		if err != nil {
			return err
		}
		switch op.op {
		case "add":
			return g.add(ids)
		case "replace":
			g.members = nil
			return g.add(ids)
		case "remove":
			if op.value == nil {
				g.members = nil
			} else {
				g.remove(ids)
			}
		}
	}
	return nil
}

func (c *call) groupJSON(g identity.SCIMGroup, withMembers bool) map[string]any {
	loc := c.s.BaseURL + "/Groups/" + g.SCIMID
	out := map[string]any{
		"schemas":     []string{schemaGroup},
		"id":          g.SCIMID,
		"displayName": g.DisplayName,
		"meta":        meta("Group", loc, g.Created, g.Updated),
	}
	if g.ExternalID != "" {
		out["externalId"] = g.ExternalID
	}
	if withMembers {
		ms := make([]map[string]any, 0, len(g.Members))
		for _, m := range g.Members {
			ms = append(ms, map[string]any{"value": m.SCIMID, "display": m.Email, "$ref": c.s.BaseURL + "/Users/" + m.SCIMID})
		}
		out["members"] = ms
	}
	return out
}

func (c *call) groups(rest []string) {
	withMembers := !c.excluded("members")
	if len(rest) == 0 {
		switch c.r.Method {
		case http.MethodGet:
			c.listGroups(withMembers)
		case http.MethodPost:
			c.createGroup()
		default:
			c.fail(&scimError{status: http.StatusMethodNotAllowed, detail: "method not allowed"})
		}
		return
	}
	id := rest[0]
	switch c.r.Method {
	case http.MethodGet:
		g, err := c.s.IDs.SCIMGroupByID(c.r.Context(), c.org, id, withMembers)
		if err != nil {
			c.fail(err)
			return
		}
		c.write(http.StatusOK, c.groupJSON(g, withMembers))
	case http.MethodPut, http.MethodPatch:
		c.replaceGroup(id)
	case http.MethodDelete:
		g, err := c.s.IDs.DeleteSCIMGroup(c.r.Context(), c.org, id)
		if err != nil {
			c.fail(err)
			return
		}
		c.audit("scim.group.delete", g.DisplayName, "scim_id="+g.SCIMID)
		c.w.WriteHeader(http.StatusNoContent)
	default:
		c.fail(&scimError{status: http.StatusMethodNotAllowed, detail: "method not allowed"})
	}
}

func (c *call) listGroups(withMembers bool) {
	cond, err := c.filter()
	if err != nil {
		c.fail(err)
		return
	}
	offset, limit, start := c.page()
	list, total, err := c.s.IDs.SCIMGroups(c.r.Context(), c.org, cond, offset, limit, withMembers)
	if errors.Is(err, identity.ErrInvalid) {
		err = errBad("invalidFilter", "unsupported filter attribute for Groups")
	}
	if err != nil {
		c.fail(err)
		return
	}
	res := make([]any, 0, len(list))
	for _, g := range list {
		res = append(res, c.groupJSON(g, withMembers))
	}
	c.write(http.StatusOK, listResponse(total, start, res))
}

func (c *call) createGroup() {
	m, err := c.decode()
	if err != nil {
		c.fail(err)
		return
	}
	g, err := parseGroup(m)
	if err != nil {
		c.fail(err)
		return
	}
	sg, err := c.s.IDs.CreateSCIMGroup(c.r.Context(), c.org, g.displayName, g.externalID, g.members)
	if err != nil {
		c.fail(err)
		return
	}
	c.audit("scim.group.create", sg.DisplayName, fmt.Sprintf("scim_id=%s members=%d", sg.SCIMID, len(sg.Members)))
	c.w.Header().Set("Location", c.s.BaseURL+"/Groups/"+sg.SCIMID)
	c.write(http.StatusCreated, c.groupJSON(sg, true))
}

// replaceGroup handles PUT (full resource) and PATCH (ops on the stored
// group). PATCH answers 204, as Okta and Entra expect; PUT returns the group.
func (c *call) replaceGroup(id string) {
	ctx := c.r.Context()
	cur, err := c.s.IDs.SCIMGroupByID(ctx, c.org, id, true)
	if err != nil {
		c.fail(err)
		return
	}
	m, err := c.decode()
	if err != nil {
		c.fail(err)
		return
	}
	var g scimGroup
	if c.r.Method == http.MethodPut {
		if g, err = parseGroup(m); err != nil {
			c.fail(err)
			return
		}
	} else {
		ops, err := parsePatch(m)
		if err != nil {
			c.fail(err)
			return
		}
		g = scimGroup{displayName: cur.DisplayName, externalID: cur.ExternalID}
		for _, mem := range cur.Members {
			g.members = append(g.members, mem.SCIMID)
		}
		if err := g.apply(ops); err != nil {
			c.fail(err)
			return
		}
	}
	sg, err := c.s.IDs.ReplaceSCIMGroup(ctx, c.org, id, g.displayName, g.externalID, g.members)
	if err != nil {
		c.fail(err)
		return
	}
	added, removed := memberDiff(cur.Members, sg.Members)
	detail := fmt.Sprintf("scim_id=%s added=%d removed=%d", sg.SCIMID, added, removed)
	if sg.DisplayName != cur.DisplayName {
		detail += " previous=" + cur.DisplayName
	}
	c.audit("scim.group.update", sg.DisplayName, detail)
	if c.r.Method == http.MethodPatch {
		c.w.WriteHeader(http.StatusNoContent)
		return
	}
	c.write(http.StatusOK, c.groupJSON(sg, !c.excluded("members")))
}

func memberDiff(before, after []identity.SCIMMember) (added, removed int) {
	b := make(map[string]bool, len(before))
	for _, m := range before {
		b[m.SCIMID] = true
	}
	a := make(map[string]bool, len(after))
	for _, m := range after {
		a[m.SCIMID] = true
		if !b[m.SCIMID] {
			added++
		}
	}
	for id := range b {
		if !a[id] {
			removed++
		}
	}
	return added, removed
}

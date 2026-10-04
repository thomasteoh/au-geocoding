package scim

import "net/http"

// Static discovery documents (RFC 7643 §5-7, RFC 7644 §4).

func serviceProviderConfig(base string) map[string]any {
	return map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": maxCount},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "Org SCIM token sent as Authorization: Bearer",
			"primary":     true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": base + "/ServiceProviderConfig"},
	}
}

func resourceTypes(base string) []map[string]any {
	return []map[string]any{
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "User",
			"name":        "User",
			"endpoint":    "/Users",
			"description": "User account",
			"schema":      schemaUser,
			"schemaExtensions": []map[string]any{
				{"schema": schemaEnterpris, "required": false},
			},
			"meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/User"},
		},
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"description": "Group",
			"schema":      schemaGroup,
			"meta":        map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/Group"},
		},
	}
}

func attr(name, typ string, required bool, extra ...map[string]any) map[string]any {
	a := map[string]any{
		"name": name, "type": typ, "multiValued": false, "required": required,
		"caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none",
	}
	for _, e := range extra {
		for k, v := range e {
			a[k] = v
		}
	}
	return a
}

func schemas(base string) []map[string]any {
	sub := func(names ...string) []map[string]any {
		var out []map[string]any
		for _, n := range names {
			out = append(out, attr(n, "string", false))
		}
		return out
	}
	user := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		"id":          schemaUser,
		"name":        "User",
		"description": "User account; userName is the email address",
		"attributes": []map[string]any{
			attr("userName", "string", true, map[string]any{"uniqueness": "server"}),
			attr("externalId", "string", false, map[string]any{"caseExact": true}),
			attr("name", "complex", false, map[string]any{"subAttributes": sub("formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix")}),
			attr("displayName", "string", false),
			attr("active", "boolean", false),
			attr("emails", "complex", false, map[string]any{"multiValued": true, "subAttributes": []map[string]any{
				attr("value", "string", false), attr("type", "string", false), attr("primary", "boolean", false),
			}}),
		},
		"meta": map[string]any{"resourceType": "Schema", "location": base + "/Schemas/" + schemaUser},
	}
	group := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		"id":          schemaGroup,
		"name":        "Group",
		"description": "Group; displayName matches SCIM group mappings",
		"attributes": []map[string]any{
			attr("displayName", "string", true, map[string]any{"uniqueness": "server"}),
			attr("externalId", "string", false, map[string]any{"caseExact": true}),
			attr("members", "complex", false, map[string]any{"multiValued": true, "subAttributes": []map[string]any{
				attr("value", "string", false, map[string]any{"mutability": "immutable"}),
				attr("display", "string", false, map[string]any{"mutability": "readOnly"}),
				attr("$ref", "reference", false, map[string]any{"mutability": "immutable", "referenceTypes": []string{"User"}}),
			}}),
		},
		"meta": map[string]any{"resourceType": "Schema", "location": base + "/Schemas/" + schemaGroup},
	}
	return []map[string]any{user, group}
}

// discovery serves a ListResponse of docs, or one doc by id.
func (c *call) discovery(docs []map[string]any, rest []string) {
	if len(rest) == 0 {
		res := make([]any, 0, len(docs))
		for _, d := range docs {
			res = append(res, d)
		}
		c.write(http.StatusOK, listResponse(len(res), 1, res))
		return
	}
	for _, d := range docs {
		if d["id"] == rest[0] {
			c.write(http.StatusOK, d)
			return
		}
	}
	c.fail(errNotFound)
}

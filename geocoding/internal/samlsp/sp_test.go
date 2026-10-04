package samlsp

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	"augeocoding/internal/identity"
)

func assertion(nameID, format string, attrs ...saml.Attribute) *saml.Assertion {
	return &saml.Assertion{
		Subject:             &saml.Subject{NameID: &saml.NameID{Value: nameID, Format: format}},
		AuthnStatements:     []saml.AuthnStatement{{SessionIndex: "idx-9"}},
		AttributeStatements: []saml.AttributeStatement{{Attributes: attrs}},
	}
}

func attr(name, friendly string, vals ...string) saml.Attribute {
	a := saml.Attribute{Name: name, FriendlyName: friendly}
	for _, v := range vals {
		a.Values = append(a.Values, saml.AttributeValue{Value: v})
	}
	return a
}

const (
	azureEmail  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	azureGroups = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
)

func TestToAssertion(t *testing.T) {
	persistent := string(saml.PersistentNameIDFormat)
	cases := []struct {
		name   string
		conn   identity.Connection
		in     *saml.Assertion
		email  string
		dname  string
		groups []string
	}{
		{"email NameID format", identity.Connection{}, assertion("ada@example.com", string(saml.EmailAddressNameIDFormat)),
			"ada@example.com", "", nil},
		{"unspecified NameID with @", identity.Connection{}, assertion("ada@example.com", "",
			attr("email", "", "other@example.com")), "ada@example.com", "", nil},
		{"opaque NameID falls back to attributes", identity.Connection{}, assertion("00u1", persistent,
			attr(azureEmail, "", "ada@example.com"), attr("displayName", "", "Ada L"), attr(azureGroups, "", "g1", "g2")),
			"ada@example.com", "Ada L", []string{"g1", "g2"}},
		{"OID mail by friendly name", identity.Connection{}, assertion("00u1", persistent,
			attr("urn:oid:0.9.2342.19200300.100.1.3", "mail", "ada@example.com"), attr("givenName", "", "Ada"), attr("sn", "", "Lovelace"),
			attr("memberOf", "", "cn=admins")), "ada@example.com", "Ada Lovelace", []string{"cn=admins"}},
		{"configured attributes win", identity.Connection{SAMLEmailAttr: "work_email", SAMLNameAttr: "full", SAMLGroupsAttr: "roles"},
			assertion("ada@example.com", string(saml.EmailAddressNameIDFormat), attr("work_email", "", "ada@corp.example"),
				attr("full", "", "Ada"), attr("displayName", "", "Ignored"), attr("roles", "", "r1"), attr("groups", "", "ignored")),
			"ada@corp.example", "Ada", []string{"r1"}},
		{"configured attribute missing gives no email", identity.Connection{SAMLEmailAttr: "work_email"},
			assertion("ada@example.com", string(saml.EmailAddressNameIDFormat), attr("email", "", "ada@example.com")), "", "", nil},
		{"empty values skipped", identity.Connection{}, assertion("00u1", persistent, attr("email", "", " ", "ada@example.com")),
			"ada@example.com", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.conn.TrustEmail = true
			a := ToAssertion(tc.conn, tc.in)
			if a.Subject != tc.in.Subject.NameID.Value || a.Email != tc.email || a.Name != tc.dname ||
				!reflect.DeepEqual(a.Groups, tc.groups) || a.IdPSID != "idx-9" || !a.EmailTrusted {
				t.Fatalf("got %+v", a)
			}
		})
	}
	if a := ToAssertion(identity.Connection{}, assertion("x@y", "")); a.EmailTrusted {
		t.Fatal("email trusted without TrustEmail")
	}
}

func testConn(t *testing.T) identity.Connection {
	t.Helper()
	k, c, err := NewKeyPair("sp")
	if err != nil {
		t.Fatal(err)
	}
	return identity.Connection{Slug: "corp", Kind: identity.KindSAML, SAMLSPKey: k, SAMLSPCert: c}
}

func TestMetadataHasNoPrivateKey(t *testing.T) {
	md, err := Metadata("https://augeo.example", testConn(t))
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	if strings.Contains(s, "PRIVATE") || !strings.Contains(s, `entityID="https://augeo.example/auth/saml/corp/metadata"`) ||
		!strings.Contains(s, "https://augeo.example/auth/saml/corp/acs") || strings.Contains(s, saml.HTTPArtifactBinding) {
		t.Fatalf("metadata:\n%s", s)
	}
	if _, err := Metadata("https://augeo.example", identity.Connection{Slug: "x", Kind: identity.KindOIDC}); err == nil {
		t.Fatal("metadata for an OIDC connection")
	}
}

func TestParseResponseGuards(t *testing.T) {
	sp, err := base("https://augeo.example", testConn(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResponse(sp, url.Values{"SAMLResponse": {"PHg+"}}, ""); err == nil {
		t.Fatal("accepted with no request ID")
	}
	if _, err := ParseResponse(sp, url.Values{"SAMLart": {"AAQ"}}, "id-1"); err == nil {
		t.Fatal("accepted artifact")
	}
	if _, err := ParseResponse(sp, url.Values{"SAMLResponse": {"%%%"}}, "id-1"); err == nil {
		t.Fatal("accepted bad base64")
	}
}

func TestNewRequiresKeyAndIdP(t *testing.T) {
	c := testConn(t)
	if _, err := New("https://augeo.example", c); err == nil {
		t.Fatal("built without IdP metadata")
	}
	other := testConn(t)
	c.SAMLSPCert = other.SAMLSPCert
	if _, err := base("https://augeo.example", c); err == nil {
		t.Fatal("accepted key and certificate that do not match")
	}
}

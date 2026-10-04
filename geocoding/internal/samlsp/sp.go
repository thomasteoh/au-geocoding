package samlsp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"augeocoding/internal/identity"
)

// MaxResponseBytes bounds the ACS POST body.
const MaxResponseBytes = 1 << 20

// Clock skew and replay windows are crewjam's package defaults:
// saml.MaxClockSkew (180s) on NotBefore/NotOnOrAfter and saml.MaxIssueDelay
// (90s) between IssueInstant and receipt.

// MetadataURL is a connection's SP entity ID, which is also where its SP
// metadata is served.
func MetadataURL(publicURL, slug string) string {
	return publicURL + "/auth/saml/" + url.PathEscape(slug) + "/metadata"
}

// ACSURL is a connection's assertion consumer service URL.
func ACSURL(publicURL, slug string) string {
	return publicURL + "/auth/saml/" + url.PathEscape(slug) + "/acs"
}

// New builds the service provider for a SAML connection: SP-initiated sign-in
// only, single logout in both directions, signed AuthnRequests, signed assertions (or a signed response) required.
func New(publicURL string, c identity.Connection) (*saml.ServiceProvider, error) {
	sp, err := base(publicURL, c)
	if err != nil {
		return nil, err
	}
	if sp.Key == nil || sp.Certificate == nil {
		return nil, errors.New("connection has no SP key pair")
	}
	if sp.IDPMetadata, err = ParseIdPMetadata(c.SAMLIdPMetadata); err != nil {
		return nil, err
	}
	return sp, nil
}

// Metadata renders the SP metadata for a connection. It carries only the
// public certificate; it does not need the IdP metadata, so an admin can
// hand it to the IdP before finishing the connection.
func Metadata(publicURL string, c identity.Connection) ([]byte, error) {
	sp, err := base(publicURL, c)
	if err != nil {
		return nil, err
	}
	ed := sp.Metadata()
	// Only the HTTP-POST binding is accepted at the ACS; never advertise
	// artifact resolution.
	for i := range ed.SPSSODescriptors {
		var acs []saml.IndexedEndpoint
		for _, e := range ed.SPSSODescriptors[i].AssertionConsumerServices {
			if e.Binding == saml.HTTPPostBinding {
				acs = append(acs, e)
			}
		}
		ed.SPSSODescriptors[i].AssertionConsumerServices = acs
	}
	b, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}

func base(publicURL string, c identity.Connection) (*saml.ServiceProvider, error) {
	if c.Kind != identity.KindSAML {
		return nil, errors.New("not a SAML connection")
	}
	md, err := url.Parse(MetadataURL(publicURL, c.Slug))
	if err != nil {
		return nil, err
	}
	acs, err := url.Parse(ACSURL(publicURL, c.Slug))
	if err != nil {
		return nil, err
	}
	slo, err := url.Parse(SLOURL(publicURL, c.Slug))
	if err != nil {
		return nil, err
	}
	sp := &saml.ServiceProvider{
		EntityID:    md.String(),
		MetadataURL: *md,
		AcsURL:      *acs,
		SloURL:      *slo,
		// Advertised in metadata; inbound logout messages are handled by
		// ParseLogout (slo.go).
		LogoutBindings: []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding},
		// Ask for no particular format; the IdP's configured persistent or
		// email NameID is used. crewjam's default (transient) is useless as
		// a stable subject.
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
		AllowIDPInitiated: false,
		SignatureMethod:   dsig.RSASHA256SignatureMethod,
		// No artifact binding, so no outbound requests; set anyway so a
		// future code path cannot fall back to http.DefaultClient.
		HTTPClient: &http.Client{Transport: noTransport{}},
	}
	if c.SAMLSPCert != "" {
		if sp.Certificate, err = parseCertPEM(c.SAMLSPCert); err != nil {
			return nil, err
		}
	}
	if c.SAMLSPKey != "" {
		key, err := parseKeyPEM(c.SAMLSPKey)
		if err != nil {
			return nil, err
		}
		if sp.Certificate != nil && !key.PublicKey.Equal(sp.Certificate.PublicKey) {
			return nil, errors.New("SP key does not match certificate")
		}
		sp.Key = key
	}
	return sp, nil
}

type noTransport struct{}

func (noTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("samlsp: outbound requests are disabled")
}

func parseCertPEM(s string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("SP certificate is not PEM")
	}
	return x509.ParseCertificate(b.Bytes)
}

func parseKeyPEM(s string) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("SP key is not PEM")
	}
	switch b.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(b.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
	}
	return nil, errors.New("SP key is not an RSA private key")
}

// NewAuthnRequest makes an AuthnRequest for the IdP's HTTP-Redirect SSO
// endpoint. Its ID is what the response's InResponseTo must match; store it
// in the flow before redirecting with RedirectURL.
func NewAuthnRequest(sp *saml.ServiceProvider) (*saml.AuthnRequest, error) {
	loc := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if loc == "" {
		return nil, errors.New("IdP has no HTTP-Redirect SSO endpoint")
	}
	return sp.MakeAuthenticationRequest(loc, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
}

// RedirectURL encodes req for the HTTP-Redirect binding, signing the query
// with the SP key.
func RedirectURL(sp *saml.ServiceProvider, req *saml.AuthnRequest, relayState string) (string, error) {
	// crewjam appends RelayState to the signed query unescaped.
	u, err := req.Redirect(url.QueryEscape(relayState), sp)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// ParseResponse validates the SAMLResponse in a parsed ACS POST form against
// the AuthnRequest ID it must answer. crewjam checks the signature (on the
// response, or else on every assertion), issuer, destination, recipient,
// audience, InResponseTo and validity windows. Errors are for logs only.
func ParseResponse(sp *saml.ServiceProvider, form url.Values, requestID string) (*saml.Assertion, error) {
	if requestID == "" {
		// An empty ID would match an assertion with no InResponseTo.
		return nil, errors.New("no request ID to match")
	}
	if form.Get("SAMLart") != "" {
		return nil, errors.New("artifact binding is not supported")
	}
	raw, err := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
	if err != nil || len(raw) == 0 {
		return nil, errors.New("SAMLResponse is missing or not base64")
	}
	a, err := sp.ParseXMLResponse(raw, []string{requestID}, sp.AcsURL)
	if err != nil {
		// The InvalidResponseError carries the raw response; keep only the
		// reason.
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			return nil, fmt.Errorf("invalid response: %w", ire.PrivateErr)
		}
		return nil, err
	}
	if a.Subject == nil || a.Subject.NameID == nil || strings.TrimSpace(a.Subject.NameID.Value) == "" {
		return nil, errors.New("assertion has no NameID")
	}
	// crewjam checks InResponseTo on each bearer confirmation present;
	// insist there is one, so the assertion itself is bound to the request.
	if len(a.Subject.SubjectConfirmations) == 0 {
		return nil, errors.New("assertion has no SubjectConfirmation")
	}
	if a.Subject.NameID.Format == string(saml.TransientNameIDFormat) {
		return nil, errors.New("transient NameID cannot identify a returning user")
	}
	return a, nil
}

// Common attribute names, tried in order when the connection does not name
// one.
var (
	emailAttrs = []string{"email", "mail", "emailaddress",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"}
	nameAttrs = []string{"displayName", "name", "http://schemas.microsoft.com/identity/claims/displayname",
		"urn:oid:2.16.840.1.113730.3.1.241", "cn", "urn:oid:2.5.4.3"}
	givenAttrs   = []string{"givenName", "firstName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "urn:oid:2.5.4.42"}
	surnameAttrs = []string{"surname", "sn", "lastName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "urn:oid:2.5.4.4"}
	groupAttrs   = []string{"groups", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", "memberOf"}
)

// ToAssertion maps a validated SAML assertion to the protocol-neutral
// identity.Assertion using the connection's attribute mapping.
func ToAssertion(c identity.Connection, a *saml.Assertion) identity.Assertion {
	out := identity.Assertion{Connection: c, EmailTrusted: c.TrustEmail}
	if a.Subject != nil && a.Subject.NameID != nil {
		out.Subject = strings.TrimSpace(a.Subject.NameID.Value)
	}
	for _, st := range a.AuthnStatements {
		if st.SessionIndex != "" {
			out.IdPSID = st.SessionIndex
			break
		}
	}

	switch {
	case c.SAMLEmailAttr != "":
		out.Email = first(a, c.SAMLEmailAttr)
	case nameIDIsEmail(a):
		out.Email = out.Subject
	default:
		out.Email = first(a, emailAttrs...)
	}

	if c.SAMLNameAttr != "" {
		out.Name = first(a, c.SAMLNameAttr)
	} else if out.Name = first(a, nameAttrs...); out.Name == "" {
		out.Name = strings.TrimSpace(first(a, givenAttrs...) + " " + first(a, surnameAttrs...))
	}

	if c.SAMLGroupsAttr != "" {
		out.Groups = values(a, c.SAMLGroupsAttr)
	} else {
		for _, n := range groupAttrs {
			if out.Groups = values(a, n); len(out.Groups) > 0 {
				break
			}
		}
	}
	return out
}

func nameIDIsEmail(a *saml.Assertion) bool {
	if a.Subject == nil || a.Subject.NameID == nil {
		return false
	}
	return a.Subject.NameID.Format == string(saml.EmailAddressNameIDFormat) || strings.Contains(a.Subject.NameID.Value, "@")
}

// first returns the first non-empty value of the first attribute present,
// trying names in order.
func first(a *saml.Assertion, names ...string) string {
	for _, n := range names {
		if v := values(a, n); len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// values returns the non-empty values of the attribute whose Name or
// FriendlyName is name (case-insensitive).
func values(a *saml.Assertion, name string) []string {
	var out []string
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			if !strings.EqualFold(at.Name, name) && !strings.EqualFold(at.FriendlyName, name) {
				continue
			}
			for _, v := range at.Values {
				if s := strings.TrimSpace(v.Value); s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

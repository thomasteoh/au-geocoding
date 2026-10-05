package console

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"augeocoding/internal/identity"
	"augeocoding/internal/samlsp"
)

// samlIdP is an in-process crewjam identity provider. It never serves
// HTTP: tests hand it the AuthnRequest redirect URL and post the response
// it builds to the ACS, as a browser would.
type samlIdP struct {
	t   *testing.T
	idp *saml.IdentityProvider
	sp  *saml.EntityDescriptor // SP metadata, fetched from the console
}

func newSAMLIdP(t *testing.T) *samlIdP {
	t.Helper()
	keyPEM, certPEM, err := samlsp.NewKeyPair("test-saml-idp")
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	p := &samlIdP{t: t}
	md, _ := url.Parse("https://idp.example/metadata")
	sso, _ := url.Parse("https://idp.example/sso")
	p.idp = &saml.IdentityProvider{Key: key, Certificate: cert, SignatureMethod: dsig.RSASHA256SignatureMethod,
		MetadataURL: *md, SSOURL: *sso, ServiceProviderProvider: p}
	return p
}

func (p *samlIdP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if p.sp == nil || p.sp.EntityID != id {
		return nil, os.ErrNotExist
	}
	return p.sp, nil
}

func (p *samlIdP) metadataXML() string {
	b, err := xml.Marshal(p.idp.Metadata())
	if err != nil {
		p.t.Fatal(err)
	}
	return string(b)
}

// samlUser is who the IdP says signed in, plus ways to spoil the response.
type samlUser struct {
	NameID       string
	NameIDFormat string // default persistent
	Attrs        map[string][]string
	SessionIndex string

	Unsigned       bool   // no signature on response or assertion
	TamperAssert   bool   // signed assertion edited, response unsigned
	TamperResponse bool   // fully signed, then the NameID edited
	InResponseTo   string // overrides the request ID
}

// respond plays the IdP for the AuthnRequest in authURL and returns the
// form the browser would post to the ACS.
func (p *samlIdP) respond(authURL string, u samlUser) url.Values {
	p.t.Helper()
	req, err := saml.NewIdpAuthnRequest(p.idp, httptest.NewRequest(http.MethodGet, authURL, nil))
	if err != nil {
		p.t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		p.t.Fatalf("IdP rejected AuthnRequest: %v", err)
	}
	if u.InResponseTo != "" {
		req.Request.ID = u.InResponseTo
	}
	if u.NameIDFormat == "" {
		u.NameIDFormat = string(saml.PersistentNameIDFormat)
	}
	sess := &saml.Session{NameID: u.NameID, NameIDFormat: u.NameIDFormat, Index: u.SessionIndex, CreateTime: time.Now()}
	for name, vals := range u.Attrs {
		a := saml.Attribute{Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"}
		for _, v := range vals {
			a.Values = append(a.Values, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		sess.CustomAttributes = append(sess.CustomAttributes, a)
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, sess); err != nil {
		p.t.Fatal(err)
	}
	switch {
	case u.Unsigned:
		req.AssertionEl = req.Assertion.Element()
		req.ResponseEl = p.unsignedResponse(req)
	case u.TamperAssert:
		req.SPSSODescriptor.KeyDescriptors = nil // plaintext, so it can be edited
		if err := req.MakeAssertionEl(); err != nil {
			p.t.Fatal(err)
		}
		tamperNameID(p.t, req.AssertionEl)
		req.ResponseEl = p.unsignedResponse(req)
	case u.TamperResponse:
		req.SPSSODescriptor.KeyDescriptors = nil
		if err := req.MakeResponse(); err != nil {
			p.t.Fatal(err)
		}
		tamperNameID(p.t, req.ResponseEl)
	default:
		// Signed assertion, encrypted to the SP, inside a signed response.
		if err := req.MakeResponse(); err != nil {
			p.t.Fatal(err)
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	b, err := doc.WriteToBytes()
	if err != nil {
		p.t.Fatal(err)
	}
	return url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(b)}, "RelayState": {req.RelayState}}
}

func (p *samlIdP) unsignedResponse(req *saml.IdpAuthnRequest) *etree.Element {
	r := &saml.Response{Destination: req.ACSEndpoint.Location, ID: fmt.Sprintf("id-r%d", time.Now().UnixNano()), InResponseTo: req.Request.ID,
		IssueInstant: req.Now, Version: "2.0", Issuer: &saml.Issuer{Value: p.idp.MetadataURL.String()},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
	el := r.Element()
	el.AddChild(req.AssertionEl)
	return el
}

func tamperNameID(t *testing.T, el *etree.Element) {
	t.Helper()
	n := el.FindElement(".//NameID")
	if n == nil {
		t.Fatal("no NameID to tamper with")
	}
	n.SetText("someone-else")
}

// samlConn registers a SAML connection for idp (org 0 = platform) and points
// the IdP at the console's SP metadata.
func (h *harness) samlConn(orgID int64, slug string, idp *samlIdP, trust bool) identity.Connection {
	h.t.Helper()
	key, cert, err := samlsp.NewKeyPair(slug)
	if err != nil {
		h.t.Fatal(err)
	}
	c, err := h.ids.SaveConnection(h.ctx, identity.Connection{OrgID: orgID, Slug: slug, Kind: identity.KindSAML, Name: "SAML " + slug,
		Enabled: true, TrustEmail: trust, SAMLIdPMetadata: idp.metadataXML(), SAMLSPKey: key, SAMLSPCert: cert})
	if err != nil {
		h.t.Fatal(err)
	}
	r := h.browser().get("/auth/saml/" + slug + "/metadata")
	if r.Status != http.StatusOK {
		h.t.Fatalf("sp metadata: %d", r.Status)
	}
	idp.sp = &saml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(r.Body), idp.sp); err != nil {
		h.t.Fatal(err)
	}
	return c
}

// samlStart begins SP-initiated sign-in and returns the IdP redirect URL.
func (b *browser) samlStart(path string) string {
	b.h.t.Helper()
	r := b.get(path)
	if r.Status != http.StatusFound || !strings.HasPrefix(r.Location, "https://idp.example/sso?") {
		b.h.t.Fatalf("saml start: %d %s %s", r.Status, r.Location, r.Body)
	}
	return r.Location
}

// samlPost posts a response to the ACS as the IdP's auto-submitting form
// would: a cross-site POST.
func (b *browser) samlPost(slug string, form url.Values) resp {
	b.h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.h.srv.URL+"/auth/saml/"+slug+"/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.example")
	return b.do(req)
}

func (b *browser) signedIn() bool {
	return b.get("/console/account").Status == http.StatusOK
}

func (h *harness) latestAudit(orgID int64) identity.AuditEvent {
	h.t.Helper()
	ev, err := h.ids.AuditLog(h.ctx, orgID, 0, 1)
	if err != nil || len(ev) == 0 {
		h.t.Fatalf("audit: %v %v", ev, err)
	}
	return ev[0]
}

var adaSAML = samlUser{NameID: "ada-0001", SessionIndex: "idx-1", Attrs: map[string][]string{
	"email": {"ada@example.com"}, "displayName": {"Ada Lovelace"}}}

func TestSAMLLoginEndToEnd(t *testing.T) {
	h := newHarness(t, open)
	idp := newSAMLIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	b := h.browser()

	auth := b.samlStart("/auth/saml/corp-saml/start?return_to=/console/account")
	q, _ := url.Parse(auth)
	if q.Query().Get("SigAlg") != dsig.RSASHA256SignatureMethod || q.Query().Get("Signature") == "" || q.Query().Get("RelayState") == "" {
		t.Fatalf("AuthnRequest not signed or missing RelayState: %s", auth)
	}
	r := b.samlPost("corp-saml", idp.respond(auth, adaSAML))
	if r.Status != http.StatusSeeOther || r.Location != "/console/account" {
		t.Fatalf("acs: %d %s %s", r.Status, r.Location, r.Body)
	}
	if !b.signedIn() {
		t.Fatal("no session after SAML login")
	}
	u, err := h.ids.UserByEmail(h.ctx, "ada@example.com")
	if err != nil || u.Name != "Ada Lovelace" {
		t.Fatalf("user: %+v %v", u, err)
	}
	if e := h.latestAudit(0); e.Action != "login.success" || !strings.Contains(e.Detail, "saml via corp-saml") {
		t.Fatalf("audit: %+v", e)
	}

	// The same IdP subject signs in again to the same account.
	b2 := h.browser()
	r = b2.samlPost("corp-saml", idp.respond(b2.samlStart("/auth/saml/corp-saml/start"), adaSAML))
	if r.Status != http.StatusSeeOther || r.Location != "/console" || !b2.signedIn() {
		t.Fatalf("second login: %d %s", r.Status, r.Location)
	}
}

func TestSAMLOrgConnectionJIT(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	d, _ := h.ids.AddDomain(h.ctx, org.ID, "acme.example")
	h.ids.MarkDomainVerified(h.ctx, org.ID, d.ID)
	h.ids.UpdateOrgSettings(h.ctx, org.ID, identity.OrgSettings{Name: "Acme", JITEnabled: true, DefaultRole: identity.RoleViewer})
	idp := newSAMLIdP(t)
	h.samlConn(org.ID, "acme-saml", idp, false)

	b := h.browser()
	auth := b.samlStart("/auth/saml/acme-saml/start")
	// Email from an emailAddress-format NameID.
	r := b.samlPost("acme-saml", idp.respond(auth, samlUser{NameID: "grace@acme.example",
		NameIDFormat: string(saml.EmailAddressNameIDFormat), SessionIndex: "s1"}))
	if r.Status != http.StatusSeeOther || !b.signedIn() {
		t.Fatalf("acs: %d %s %s", r.Status, r.Location, r.Body)
	}
	u, err := h.ids.UserByEmail(h.ctx, "grace@acme.example")
	if err != nil {
		t.Fatalf("JIT user not created: %v", err)
	}
	ms, _ := h.ids.Members(h.ctx, org.ID)
	found := false
	for _, m := range ms {
		found = found || m.User.ID == u.ID
	}
	if !found {
		t.Fatalf("JIT user not a member of the org: %+v", ms)
	}

	// An address outside the verified domain is refused.
	b = h.browser()
	r = b.samlPost("acme-saml", idp.respond(b.samlStart("/auth/saml/acme-saml/start"),
		samlUser{NameID: "x1", Attrs: map[string][]string{"email": {"eve@evil.example"}}}))
	if r.Status != http.StatusForbidden || b.signedIn() {
		t.Fatalf("foreign domain: %d", r.Status)
	}
}

func TestSAMLRejectsBadSignatures(t *testing.T) {
	for name, u := range map[string]samlUser{
		"unsigned":        {Unsigned: true},
		"tampered":        {TamperAssert: true},
		"tamperedSignedR": {TamperResponse: true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, open)
			idp := newSAMLIdP(t)
			h.samlConn(0, "corp-saml", idp, true)
			b := h.browser()
			u.NameID, u.Attrs = adaSAML.NameID, adaSAML.Attrs
			r := b.samlPost("corp-saml", idp.respond(b.samlStart("/auth/saml/corp-saml/start"), u))
			if r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "did not complete") || b.signedIn() {
				t.Fatalf("accepted: %d %s", r.Status, r.Location)
			}
			if e := h.latestAudit(0); e.Action != "login.failed" || e.Detail != "saml_invalid" {
				t.Fatalf("audit: %+v", e)
			}
			if _, err := h.ids.UserByEmail(h.ctx, "ada@example.com"); err == nil {
				t.Fatal("user created")
			}
		})
	}
}

func TestSAMLRejectsWrongRequestAndReplay(t *testing.T) {
	h := newHarness(t, open)
	idp := newSAMLIdP(t)
	h.samlConn(0, "corp-saml", idp, true)

	// A response to some other request.
	b := h.browser()
	u := adaSAML
	u.InResponseTo = "id-not-ours"
	r := b.samlPost("corp-saml", idp.respond(b.samlStart("/auth/saml/corp-saml/start"), u))
	if r.Status != http.StatusBadRequest || b.signedIn() {
		t.Fatalf("wrong InResponseTo: %d %s", r.Status, r.Location)
	}

	// A good response, then the same POST again.
	b = h.browser()
	form := idp.respond(b.samlStart("/auth/saml/corp-saml/start"), adaSAML)
	if r = b.samlPost("corp-saml", form); r.Status != http.StatusSeeOther {
		t.Fatalf("first use: %d %s", r.Status, r.Body)
	}
	b2 := h.browser()
	b2.samlStart("/auth/saml/corp-saml/start") // has a flow cookie, but not for that state
	if r = b2.samlPost("corp-saml", form); r.Status != http.StatusBadRequest || b2.signedIn() {
		t.Fatalf("replay: %d %s", r.Status, r.Location)
	}
	// The old response under a fresh flow's RelayState fails InResponseTo.
	b3 := h.browser()
	fresh, _ := url.Parse(b3.samlStart("/auth/saml/corp-saml/start"))
	form.Set("RelayState", fresh.Query().Get("RelayState"))
	if r = b3.samlPost("corp-saml", form); r.Status != http.StatusBadRequest || b3.signedIn() {
		t.Fatalf("replay under new flow: %d %s", r.Status, r.Location)
	}
	if e := h.latestAudit(0); e.Detail != "saml_invalid" {
		t.Fatalf("audit: %+v", e)
	}
}

func TestSAMLRejectsIdPInitiated(t *testing.T) {
	h := newHarness(t, open)
	idp := newSAMLIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	b := h.browser()
	form := idp.respond(b.samlStart("/auth/saml/corp-saml/start"), adaSAML)
	form.Del("RelayState")
	r := b.samlPost("corp-saml", form)
	if r.Status != http.StatusBadRequest || b.signedIn() {
		t.Fatalf("idp-initiated: %d %s", r.Status, r.Location)
	}
	if e := h.latestAudit(0); e.Detail != "saml_idp_initiated" {
		t.Fatalf("audit: %+v", e)
	}
}

func TestSAMLACSBoundToBrowser(t *testing.T) {
	h := newHarness(t, open)
	idp := newSAMLIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	attacker, victim := h.browser(), h.browser()
	form := idp.respond(attacker.samlStart("/auth/saml/corp-saml/start"),
		samlUser{NameID: "m1", Attrs: map[string][]string{"email": {"mallory@example.com"}}})
	r := victim.samlPost("corp-saml", form)
	if r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "expired or was started in another browser") || victim.signedIn() {
		t.Fatalf("cross-browser ACS: %d %s", r.Status, r.Location)
	}
}

func TestSAMLFlowBoundToConnection(t *testing.T) {
	h := newHarness(t, open)
	idp := newSAMLIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	other := newSAMLIdP(t)
	h.samlConn(0, "other-saml", other, true)
	b := h.browser()
	form := idp.respond(b.samlStart("/auth/saml/corp-saml/start"), adaSAML)
	r := b.samlPost("other-saml", form)
	if r.Status != http.StatusBadRequest || b.signedIn() {
		t.Fatalf("flow used at another connection: %d %s", r.Status, r.Location)
	}
	if e := h.latestAudit(0); e.Detail != "saml_wrong_connection" {
		t.Fatalf("audit: %+v", e)
	}
}

func TestSAMLMetadata(t *testing.T) {
	h := newHarness(t, open)
	idp := newSAMLIdP(t)
	c := h.samlConn(0, "corp-saml", idp, true)
	b := h.browser()
	res, err := b.c.Get(h.srv.URL + "/auth/saml/corp-saml/metadata")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if ct := res.Header.Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Fatalf("content type %q", ct)
	}
	r := b.get("/auth/saml/corp-saml/metadata")
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal([]byte(r.Body), &ed); err != nil {
		t.Fatal(err)
	}
	want := h.srv.URL + "/auth/saml/corp-saml/metadata"
	if ed.EntityID != want || len(ed.SPSSODescriptors) != 1 {
		t.Fatalf("entity: %q", ed.EntityID)
	}
	spd := ed.SPSSODescriptors[0]
	if len(spd.AssertionConsumerServices) != 1 || spd.AssertionConsumerServices[0].Location != h.srv.URL+"/auth/saml/corp-saml/acs" ||
		spd.AssertionConsumerServices[0].Binding != saml.HTTPPostBinding {
		t.Fatalf("acs: %+v", spd.AssertionConsumerServices)
	}
	if spd.AuthnRequestsSigned == nil || !*spd.AuthnRequestsSigned || spd.WantAssertionsSigned == nil || !*spd.WantAssertionsSigned {
		t.Fatal("signing flags not set")
	}
	kb, _ := pem.Decode([]byte(c.SAMLSPKey))
	key, _ := x509.ParsePKCS1PrivateKey(kb.Bytes)
	for _, secret := range []string{"PRIVATE", base64.StdEncoding.EncodeToString(kb.Bytes)[:40], key.D.String()} {
		if strings.Contains(r.Body, secret) {
			t.Fatal("metadata leaks private key material")
		}
	}

	if r := b.get("/auth/saml/nope/metadata"); r.Status != http.StatusNotFound {
		t.Fatalf("unknown connection: %d", r.Status)
	}
	if r := b.get("/auth/saml/test-idp/metadata"); r.Status != http.StatusNotFound {
		t.Fatalf("OIDC connection: %d", r.Status)
	}
}

func TestSAMLStartUnknownConnection(t *testing.T) {
	h := newHarness(t, open)
	if r := h.browser().get("/auth/saml/test-idp/start"); r.Status != http.StatusNotFound {
		t.Fatalf("start on OIDC connection: %d", r.Status)
	}
}

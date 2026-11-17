package console

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"augeocoding/internal/identity"
	"augeocoding/internal/samlsp"
)

// samlConnMetadata is samlConn with the IdP metadata given explicitly.
func (h *harness) samlConnMetadata(slug string, idp *samlIdP, md string) identity.Connection {
	h.t.Helper()
	key, cert, err := samlsp.NewKeyPair(slug)
	if err != nil {
		h.t.Fatal(err)
	}
	c, err := h.ids.SaveConnection(h.ctx, identity.Connection{Slug: slug, Kind: identity.KindSAML, Name: "SAML " + slug,
		Enabled: true, TrustEmail: true, SAMLIdPMetadata: md, SAMLSPKey: key, SAMLSPCert: cert})
	if err != nil {
		h.t.Fatal(err)
	}
	r := h.browser().get("/auth/saml/" + slug + "/metadata")
	idp.sp = &saml.EntityDescriptor{}
	if err := xml.Unmarshal([]byte(r.Body), idp.sp); err != nil {
		h.t.Fatal(err)
	}
	return c
}

// postOnlyMetadata is the IdP's metadata with only an HTTP-POST SLO
// endpoint.
func (p *samlIdP) postOnlyMetadata() string {
	ed := p.idp.Metadata()
	ed.IDPSSODescriptors[0].SingleLogoutServices = []saml.Endpoint{{Binding: saml.HTTPPostBinding, Location: idpSLO}}
	b, err := xml.Marshal(ed)
	if err != nil {
		p.t.Fatal(err)
	}
	return string(b)
}

var (
	formActionRe = regexp.MustCompile(`<form id="saml-autosubmit" method="post" action="([^"]*)">`)
	hiddenRe     = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
)

// readPostPage plays the browser on our HTTP-POST binding page and the IdP
// receiving it: it checks the page, verifies the enveloped signature with
// the SP certificate and returns the signed element and RelayState.
func (p *samlIdP) readPostPage(r resp, param string) (*etree.Element, string) {
	p.t.Helper()
	if r.Status != http.StatusOK {
		p.t.Fatalf("POST binding page: %d %s", r.Status, r.Location)
	}
	if m := formActionRe.FindStringSubmatch(r.Body); m == nil || html.UnescapeString(m[1]) != idpSLO {
		p.t.Fatalf("form does not post to the IdP SLO endpoint: %s", r.Body)
	}
	if !strings.Contains(r.Body, `<script src="/console/static/autosubmit.js"></script>`) ||
		!strings.Contains(r.Body, `<button type="submit">Continue</button>`) {
		p.t.Fatal("POST page lacks the autosubmit script or the Continue button")
	}
	if strings.Contains(r.Body, "<script>") {
		p.t.Fatal("POST page has an inline script")
	}
	if strings.Contains(r.Body, `action="/auth/logout"`) {
		p.t.Fatal("POST page renders the signed-in header")
	}
	fields := map[string]string{}
	for _, m := range hiddenRe.FindAllStringSubmatch(r.Body, -1) {
		fields[m[1]] = html.UnescapeString(m[2])
	}
	raw, err := base64.StdEncoding.DecodeString(fields[param])
	if err != nil || len(raw) == 0 {
		p.t.Fatalf("no %s in form: %v", param, fields)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		p.t.Fatal(err)
	}
	root := doc.Root()
	// Schema order: Signature follows Issuer.
	if kids := root.ChildElements(); len(kids) < 2 || kids[0].Tag != "Issuer" || kids[1].Tag != "Signature" {
		p.t.Fatalf("Signature is not right after Issuer: %s", raw)
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{p.spSigningCert()}})
	vc.IdAttribute = "ID"
	el, err := vc.Validate(root)
	if err != nil {
		p.t.Fatalf("SP enveloped signature does not verify: %v", err)
	}
	return el, fields["RelayState"]
}

func unmarshalEl(t *testing.T, el *etree.Element, v any) {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	b, _ := doc.WriteToBytes()
	if err := xml.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

// postSLO posts a message to the SLO URL with an enveloped signature by s.
func (b *browser) postSLO(slug, param string, s *saml.ServiceProvider, el *etree.Element) resp {
	b.h.t.Helper()
	sc, err := saml.GetSigningContext(s)
	if err != nil {
		b.h.t.Fatal(err)
	}
	signed, err := sc.SignEnveloped(el)
	if err != nil {
		b.h.t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	xb, _ := doc.WriteToBytes()
	form := url.Values{param: {base64.StdEncoding.EncodeToString(xb)}}
	req, _ := http.NewRequest(http.MethodPost, b.h.sloURL(slug), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.example")
	return b.do(req)
}

func (p *samlIdP) logoutResponse(h *harness, slug, id, inResponseTo string) *saml.LogoutResponse {
	return &saml.LogoutResponse{ID: id, InResponseTo: inResponseTo, Version: "2.0", IssueInstant: saml.TimeNow(),
		Destination: h.sloURL(slug), Issuer: &saml.Issuer{Value: p.idp.MetadataURL.String()},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
}

func checkQualifiers(t *testing.T, lr *saml.LogoutRequest, idp *samlIdP) {
	t.Helper()
	n := lr.NameID
	if n == nil || n.Format != string(saml.PersistentNameIDFormat) || n.NameQualifier != idp.idp.MetadataURL.String() ||
		n.SPNameQualifier != idp.sp.EntityID {
		t.Fatalf("NameID qualifiers not echoed: %+v", n)
	}
}

func TestSAMLLogoutRequestNameIDQualifiers(t *testing.T) {
	h := newHarness(t, open)
	idp := newSLOIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	b := h.browser()
	b.samlLogin("corp-saml", idp, adaSAML)

	// Stored with the session.
	u, err := h.ids.UserByEmail(h.ctx, "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := h.ids.UserSessions(h.ctx, u.ID)
	want := identity.NameIDQualifiers{Format: string(saml.PersistentNameIDFormat), NameQualifier: idp.idp.MetadataURL.String(),
		SPNameQualifier: idp.sp.EntityID}
	if len(ss) != 1 || ss[0].IdPSubQual != want {
		t.Fatalf("session qualifiers: %+v", ss)
	}

	r := b.post("/auth/logout", nil, true)
	x, _ := idp.readRedirect(r.Location, "SAMLRequest")
	var lr saml.LogoutRequest
	if err := xml.Unmarshal(x, &lr); err != nil {
		t.Fatal(err)
	}
	checkQualifiers(t, &lr, idp)
}

func TestSAMLLogoutPOSTBinding(t *testing.T) {
	h := newHarness(t, open)
	idp := newSAMLIdP(t)
	h.samlConnMetadata("corp-saml", idp, idp.postOnlyMetadata())
	b := h.browser()
	b.samlLogin("corp-saml", idp, adaSAML)

	// SP-initiated: an auto-submitting form carrying a signed request.
	el, relay := idp.readPostPage(b.post("/auth/logout", nil, true), "SAMLRequest")
	var lr saml.LogoutRequest
	unmarshalEl(t, el, &lr)
	if lr.NameID == nil || lr.NameID.Value != adaSAML.NameID || lr.SessionIndex == nil || lr.SessionIndex.Value != adaSAML.SessionIndex ||
		lr.Destination != idpSLO || lr.Issuer == nil || lr.Issuer.Value != idp.sp.EntityID || relay != "" {
		t.Fatalf("LogoutRequest: %+v", lr)
	}
	checkQualifiers(t, &lr, idp)
	if b.signedIn() {
		t.Fatal("local session survived logout")
	}
	r := b.postSLO("corp-saml", "SAMLResponse", idp.signer(), idp.logoutResponse(h, "corp-saml", "id-pr-1", lr.ID).Element())
	if r.Status != http.StatusSeeOther || r.Location != "/auth/login" {
		t.Fatalf("logout response: %d %s %s", r.Status, r.Location, r.Body)
	}

	// IdP-initiated: our response goes back by POST too.
	bob := h.browser()
	bob.samlLogin("corp-saml", idp, bobSAML)
	req := idp.logoutRequest(h, "corp-saml", bobSAML.NameID, bobSAML.SessionIndex)
	u := redirectMsg(t, idp.signer(), h.sloURL("corp-saml"), "SAMLRequest", req.Element(), "relay-p")
	el, relay = idp.readPostPage(bob.get(u), "SAMLResponse")
	var resp saml.LogoutResponse
	unmarshalEl(t, el, &resp)
	if resp.InResponseTo != req.ID || resp.Status.StatusCode.Value != saml.StatusSuccess || resp.Destination != idpSLO ||
		resp.Issuer == nil || resp.Issuer.Value != idp.sp.EntityID || relay != "relay-p" {
		t.Fatalf("LogoutResponse: %+v relay=%q", resp, relay)
	}
	if bob.signedIn() {
		t.Fatal("bob's session survived IdP logout")
	}

	// The script the page loads is served.
	if r := h.browser().get("/console/static/autosubmit.js"); r.Status != http.StatusOK || !strings.Contains(r.Body, "saml-autosubmit") {
		t.Fatalf("autosubmit.js: %d", r.Status)
	}
}

func TestSAMLLogoutResponseCorrelation(t *testing.T) {
	h := newHarness(t, open)
	idp := newSLOIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	slo := h.sloURL("corp-saml")
	respURL := func(id, inResponseTo string) string {
		return redirectMsg(t, idp.signer(), slo, "SAMLResponse", idp.logoutResponse(h, "corp-saml", id, inResponseTo).Element(), "")
	}
	rejected := func(r resp, code string) {
		t.Helper()
		if r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "could not be verified") {
			t.Fatalf("accepted: %d %s", r.Status, r.Location)
		}
		if e := h.latestAudit(0); e.Action != "logout.saml_rejected" || e.Target != "corp-saml" || e.Detail != code {
			t.Fatalf("audit: %+v", e)
		}
	}

	// Unsolicited: no request was ever sent.
	rejected(h.browser().get(respURL("id-r0", "id-never-sent")), "unsolicited_response")

	b := h.browser()
	b.samlLogin("corp-saml", idp, adaSAML)
	x, _ := idp.readRedirect(b.post("/auth/logout", nil, true).Location, "SAMLRequest")
	var lr saml.LogoutRequest
	if err := xml.Unmarshal(x, &lr); err != nil {
		t.Fatal(err)
	}

	// Wrong InResponseTo, and the right one from another browser, are
	// refused. The latter consumes the request.
	rejected(b.get(respURL("id-r1", "id-other")), "unsolicited_response")
	b2 := h.browser()
	b2.samlLogin("corp-saml", idp, adaSAML)
	x, _ = idp.readRedirect(b2.post("/auth/logout", nil, true).Location, "SAMLRequest")
	var lr2 saml.LogoutRequest
	if err := xml.Unmarshal(x, &lr2); err != nil {
		t.Fatal(err)
	}
	rejected(h.browser().get(respURL("id-r2", lr2.ID)), "unsolicited_response")
	rejected(b2.get(respURL("id-r3", lr2.ID)), "unsolicited_response")

	// The first browser's request is still pending (the wrong-ID attempt
	// cleared its cookie, so log out again to get a fresh one).
	b.samlLogin("corp-saml", idp, adaSAML)
	x, _ = idp.readRedirect(b.post("/auth/logout", nil, true).Location, "SAMLRequest")
	if err := xml.Unmarshal(x, &lr); err != nil {
		t.Fatal(err)
	}
	if r := b.get(respURL("id-r4", lr.ID)); r.Status != http.StatusSeeOther || r.Location != "/auth/login" {
		t.Fatalf("matching response: %d %s %s", r.Status, r.Location, r.Body)
	}
	// Used once only.
	rejected(b.get(respURL("id-r5", lr.ID)), "unsolicited_response")
}

func TestSAMLLogoutRejectedAudit(t *testing.T) {
	h := newHarness(t, open)
	idp := newSLOIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	slo := h.sloURL("corp-saml")
	other := newSAMLIdP(t)
	lr := idp.logoutRequest(h, "corp-saml", adaSAML.NameID, "")
	wrongIssuer := idp.logoutRequest(h, "corp-saml", adaSAML.NameID, "x")
	wrongIssuer.Issuer.Value = "https://evil.example/metadata"
	good := redirectMsg(t, idp.signer(), slo, "SAMLRequest", lr.Element(), "")

	for _, tc := range []struct {
		name, url, code string
	}{
		{"unsigned", redirectMsg(t, nil, slo, "SAMLRequest", lr.Element(), ""), "unsigned"},
		{"otherKey", redirectMsg(t, other.signer(), slo, "SAMLRequest", lr.Element(), ""), "bad_signature"},
		{"wrongIssuer", redirectMsg(t, idp.signer(), slo, "SAMLRequest", wrongIssuer.Element(), ""), "wrong_issuer"},
		{"garbage", slo + "?SAMLRequest=%21%21", "malformed"},
		{"first", good, ""},
		{"replay", good, "replay"},
	} {
		r := h.browser().get(tc.url)
		if tc.code == "" {
			if r.Status != http.StatusFound {
				t.Fatalf("%s: %d", tc.name, r.Status)
			}
			continue
		}
		if r.Status != http.StatusBadRequest {
			t.Fatalf("%s: %d", tc.name, r.Status)
		}
		e := h.latestAudit(0)
		if e.Action != "logout.saml_rejected" || e.Detail != tc.code || strings.Contains(e.Detail, "<") {
			t.Fatalf("%s: audit %+v", tc.name, e)
		}
	}
}

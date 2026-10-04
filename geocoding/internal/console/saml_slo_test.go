package console

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

const idpSLO = "https://idp.example/slo"

// newSLOIdP is a test IdP whose metadata publishes an HTTP-Redirect SLO
// endpoint.
func newSLOIdP(t *testing.T) *samlIdP {
	p := newSAMLIdP(t)
	u, _ := url.Parse(idpSLO)
	p.idp.LogoutURL = *u
	return p
}

// samlLogin signs b in through idp as u.
func (b *browser) samlLogin(slug string, idp *samlIdP, u samlUser) {
	b.h.t.Helper()
	r := b.samlPost(slug, idp.respond(b.samlStart("/auth/saml/"+slug+"/start"), u))
	if r.Status != http.StatusSeeOther || !b.signedIn() {
		b.h.t.Fatalf("saml login: %d %s %s", r.Status, r.Location, r.Body)
	}
}

// spSigningCert is the SP certificate from the metadata the IdP holds.
func (p *samlIdP) spSigningCert() *x509.Certificate {
	p.t.Helper()
	for _, kd := range p.sp.SPSSODescriptors[0].KeyDescriptors {
		if kd.Use == "signing" {
			der, _ := base64.StdEncoding.DecodeString(kd.KeyInfo.X509Data.X509Certificates[0].Data)
			c, err := x509.ParseCertificate(der)
			if err != nil {
				p.t.Fatal(err)
			}
			return c
		}
	}
	p.t.Fatal("SP metadata has no signing certificate")
	return nil
}

// readRedirect plays the IdP receiving a redirect-binding message from the
// SP: it checks the query signature against the SP certificate and returns
// the decoded XML and RelayState.
func (p *samlIdP) readRedirect(loc, param string) ([]byte, string) {
	p.t.Helper()
	if !strings.HasPrefix(loc, idpSLO+"?") {
		p.t.Fatalf("not a redirect to the IdP SLO endpoint: %s", loc)
	}
	u, _ := url.Parse(loc)
	raw := map[string]string{}
	for _, kv := range strings.Split(u.RawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		raw[k] = v
	}
	q := u.Query()
	if q.Get("SigAlg") != dsig.RSASHA256SignatureMethod || q.Get("Signature") == "" {
		p.t.Fatalf("message not signed: %s", loc)
	}
	signed := param + "=" + raw[param]
	if _, ok := raw["RelayState"]; ok {
		signed += "&RelayState=" + raw["RelayState"]
	}
	signed += "&SigAlg=" + raw["SigAlg"]
	sig, _ := base64.StdEncoding.DecodeString(q.Get("Signature"))
	d := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(p.spSigningCert().PublicKey.(*rsa.PublicKey), crypto.SHA256, d[:], sig); err != nil {
		p.t.Fatalf("SP signature does not verify: %v", err)
	}
	z, _ := base64.StdEncoding.DecodeString(q.Get(param))
	x, err := io.ReadAll(flate.NewReader(bytes.NewReader(z)))
	if err != nil {
		p.t.Fatal(err)
	}
	if bytes.Contains(x, []byte("Signature")) {
		p.t.Fatal("redirect-binding message carries an XML signature")
	}
	return x, q.Get("RelayState")
}

// signer signs with key as if it were the IdP's.
func signer(key *rsa.PrivateKey, cert *x509.Certificate) *saml.ServiceProvider {
	return &saml.ServiceProvider{Key: key, Certificate: cert, SignatureMethod: dsig.RSASHA256SignatureMethod}
}

// redirectMsg encodes el for the HTTP-Redirect binding to dest, signing the
// query with s (nil: unsigned).
func redirectMsg(t *testing.T, s *saml.ServiceProvider, dest, param string, el *etree.Element, relay string) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	x, _ := doc.WriteToBytes()
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, 9)
	fw.Write(x)
	fw.Close()
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	if s != nil {
		q += "&SigAlg=" + url.QueryEscape(s.SignatureMethod)
		sc, err := saml.GetSigningContext(s)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := sc.SignString(q)
		if err != nil {
			t.Fatal(err)
		}
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return dest + "?" + q
}

func (h *harness) sloURL(slug string) string { return h.srv.URL + "/auth/saml/" + slug + "/slo" }

func (p *samlIdP) logoutRequest(h *harness, slug, nameID, sessionIndex string) *saml.LogoutRequest {
	req := &saml.LogoutRequest{ID: "id-lr-" + nameID + sessionIndex, Version: "2.0", IssueInstant: saml.TimeNow(), Destination: h.sloURL(slug),
		Issuer: &saml.Issuer{Value: p.idp.MetadataURL.String()}, NameID: &saml.NameID{Value: nameID}}
	if sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}
	return req
}

func (p *samlIdP) signer() *saml.ServiceProvider {
	return signer(p.idp.Key.(*rsa.PrivateKey), p.idp.Certificate)
}

var bobSAML = samlUser{NameID: "bob-0002", SessionIndex: "idx-2", Attrs: map[string][]string{
	"email": {"bob@example.com"}, "displayName": {"Bob"}}}

func TestSAMLSPInitiatedLogout(t *testing.T) {
	h := newHarness(t, open)
	idp := newSLOIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	b := h.browser()
	b.samlLogin("corp-saml", idp, adaSAML)

	r := b.post("/auth/logout", nil, true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("logout: %d %s", r.Status, r.Body)
	}
	x, _ := idp.readRedirect(r.Location, "SAMLRequest")
	var lr saml.LogoutRequest
	if err := xml.Unmarshal(x, &lr); err != nil {
		t.Fatal(err)
	}
	if lr.NameID == nil || lr.NameID.Value != adaSAML.NameID || lr.SessionIndex == nil || lr.SessionIndex.Value != adaSAML.SessionIndex ||
		lr.Destination != idpSLO || lr.Issuer == nil || lr.Issuer.Value != idp.sp.EntityID || lr.ID == "" {
		t.Fatalf("LogoutRequest: %s", x)
	}
	if b.signedIn() {
		t.Fatal("local session survived logout")
	}

	// The IdP answers; the browser lands on the login page.
	resp := &saml.LogoutResponse{ID: "id-resp-1", InResponseTo: lr.ID, Version: "2.0", IssueInstant: saml.TimeNow(),
		Destination: h.sloURL("corp-saml"), Issuer: &saml.Issuer{Value: idp.idp.MetadataURL.String()},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
	r = b.get(redirectMsg(t, idp.signer(), h.sloURL("corp-saml"), "SAMLResponse", resp.Element(), ""))
	if r.Status != http.StatusSeeOther || r.Location != "/auth/login" {
		t.Fatalf("logout response: %d %s %s", r.Status, r.Location, r.Body)
	}
	if r = b.get("/auth/login"); !strings.Contains(r.Body, "You have signed out.") {
		t.Fatal("no sign-out flash")
	}

	// A response signed by someone else is refused with a generic message.
	other := newSAMLIdP(t)
	r = b.get(redirectMsg(t, other.signer(), h.sloURL("corp-saml"), "SAMLResponse", resp.Element(), ""))
	if r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "could not be verified") {
		t.Fatalf("forged logout response: %d %s", r.Status, r.Location)
	}
}

func TestSAMLLogoutWithoutIdPSLO(t *testing.T) {
	h := newHarness(t, open)
	idp := newSAMLIdP(t) // no SLO endpoint in its metadata
	h.samlConn(0, "corp-saml", idp, true)
	b := h.browser()
	b.samlLogin("corp-saml", idp, adaSAML)
	if r := b.post("/auth/logout", nil, true); r.Status != http.StatusSeeOther || r.Location != "/auth/login" {
		t.Fatalf("logout: %d %s", r.Status, r.Location)
	}
	if b.signedIn() {
		t.Fatal("local session survived logout")
	}
}

func TestSAMLIdPInitiatedLogout(t *testing.T) {
	h := newHarness(t, open)
	idp := newSLOIdP(t)
	c := h.samlConn(0, "corp-saml", idp, true)
	ada, bob := h.browser(), h.browser()
	ada.samlLogin("corp-saml", idp, adaSAML)
	bob.samlLogin("corp-saml", idp, bobSAML)

	// Redirect binding, signed query, by SessionIndex.
	lr := idp.logoutRequest(h, "corp-saml", adaSAML.NameID, adaSAML.SessionIndex)
	u := redirectMsg(t, idp.signer(), h.sloURL("corp-saml"), "SAMLRequest", lr.Element(), "relay-1")
	r := ada.get(u)
	if r.Status != http.StatusFound {
		t.Fatalf("idp logout: %d %s %s", r.Status, r.Location, r.Body)
	}
	x, relay := idp.readRedirect(r.Location, "SAMLResponse")
	var resp saml.LogoutResponse
	if err := xml.Unmarshal(x, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.InResponseTo != lr.ID || resp.Status.StatusCode.Value != saml.StatusSuccess || resp.Destination != idpSLO ||
		resp.Issuer == nil || resp.Issuer.Value != idp.sp.EntityID || relay != "relay-1" {
		t.Fatalf("LogoutResponse: %s relay=%q", x, relay)
	}
	if ada.signedIn() {
		t.Fatal("ada's session survived IdP logout")
	}
	if !bob.signedIn() {
		t.Fatal("bob's session was ended too")
	}
	if e := h.latestAudit(0); e.Action != "logout.saml_slo" || e.Target != c.Slug || e.Detail != "sessions ended: 1" {
		t.Fatalf("audit: %+v", e)
	}

	// The same request again is refused.
	if r := h.browser().get(u); r.Status != http.StatusBadRequest {
		t.Fatalf("replay: %d", r.Status)
	}

	// POST binding, enveloped XML signature, NameID only.
	lr = idp.logoutRequest(h, "corp-saml", bobSAML.NameID, "")
	sc, _ := saml.GetSigningContext(idp.signer())
	el, err := sc.SignEnveloped(lr.Element())
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	xb, _ := doc.WriteToBytes()
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(xb)}}
	req, _ := http.NewRequest(http.MethodPost, h.sloURL("corp-saml"), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.example")
	if r := bob.do(req); r.Status != http.StatusFound || !strings.HasPrefix(r.Location, idpSLO+"?SAMLResponse=") {
		t.Fatalf("idp logout (POST): %d %s %s", r.Status, r.Location, r.Body)
	}
	if bob.signedIn() {
		t.Fatal("bob's session survived NameID logout")
	}
}

func TestSAMLIdPLogoutRejected(t *testing.T) {
	h := newHarness(t, open)
	idp := newSLOIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	ada, bob := h.browser(), h.browser()
	ada.samlLogin("corp-saml", idp, adaSAML)
	bob.samlLogin("corp-saml", idp, bobSAML)
	slo := h.sloURL("corp-saml")
	good := func() *saml.LogoutRequest { return idp.logoutRequest(h, "corp-saml", adaSAML.NameID, "") }

	other := newSAMLIdP(t)
	wrongIssuer := good()
	wrongIssuer.Issuer.Value = "https://evil.example/metadata"
	wrongDest := good()
	wrongDest.Destination = h.srv.URL + "/auth/saml/other/slo"
	expired := good()
	past := time.Now().Add(-time.Hour)
	expired.NotOnOrAfter = &past
	stale := good()
	stale.IssueInstant = past

	tampered := redirectMsg(t, idp.signer(), slo, "SAMLRequest", good().Element(), "")
	swapped := idp.logoutRequest(h, "corp-saml", bobSAML.NameID, "")
	pu, _ := url.Parse(redirectMsg(t, nil, slo, "SAMLRequest", swapped.Element(), ""))
	tu, _ := url.Parse(tampered)
	tq := tu.Query()
	tq.Set("SAMLRequest", pu.Query().Get("SAMLRequest"))
	tu.RawQuery = tq.Encode()

	for name, u := range map[string]string{
		"unsigned":     redirectMsg(t, nil, slo, "SAMLRequest", good().Element(), ""),
		"otherKey":     redirectMsg(t, other.signer(), slo, "SAMLRequest", good().Element(), ""),
		"wrongIssuer":  redirectMsg(t, idp.signer(), slo, "SAMLRequest", wrongIssuer.Element(), ""),
		"wrongDest":    redirectMsg(t, idp.signer(), slo, "SAMLRequest", wrongDest.Element(), ""),
		"expired":      redirectMsg(t, idp.signer(), slo, "SAMLRequest", expired.Element(), ""),
		"staleIssue":   redirectMsg(t, idp.signer(), slo, "SAMLRequest", stale.Element(), ""),
		"swappedQuery": tu.String(),
	} {
		t.Run(name, func(t *testing.T) {
			if r := h.browser().get(u); r.Status != http.StatusBadRequest {
				t.Fatalf("accepted: %d %s", r.Status, r.Location)
			}
		})
	}

	// POST with an unsigned body, and with a signed body edited afterwards.
	post := func(xb []byte) int {
		form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(xb)}}
		req, _ := http.NewRequest(http.MethodPost, slo, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return h.browser().do(req).Status
	}
	doc := etree.NewDocument()
	doc.SetRoot(good().Element())
	xb, _ := doc.WriteToBytes()
	if s := post(xb); s != http.StatusBadRequest {
		t.Fatalf("unsigned POST: %d", s)
	}
	sc, _ := saml.GetSigningContext(idp.signer())
	el, _ := sc.SignEnveloped(good().Element())
	el.FindElement(".//NameID").SetText(bobSAML.NameID)
	doc = etree.NewDocument()
	doc.SetRoot(el)
	xb, _ = doc.WriteToBytes()
	if s := post(xb); s != http.StatusBadRequest {
		t.Fatalf("tampered POST: %d", s)
	}

	if !ada.signedIn() || !bob.signedIn() {
		t.Fatal("a rejected logout request ended a session")
	}
	if ev, _ := h.ids.AuditLog(h.ctx, 0, 0, 50); len(ev) > 0 {
		for _, e := range ev {
			if e.Action == "logout.saml_slo" {
				t.Fatalf("rejected request audited as logout: %+v", e)
			}
		}
	}
}

func TestSAMLMetadataSLO(t *testing.T) {
	h := newHarness(t, open)
	idp := newSAMLIdP(t)
	h.samlConn(0, "corp-saml", idp, true)
	got := map[string]string{}
	for _, e := range idp.sp.SPSSODescriptors[0].SingleLogoutServices {
		got[e.Binding] = e.Location
	}
	want := h.sloURL("corp-saml")
	if got[saml.HTTPRedirectBinding] != want || got[saml.HTTPPostBinding] != want || len(got) != 2 {
		t.Fatalf("SLO endpoints: %v", got)
	}
	if r := h.browser().get("/auth/saml/test-idp/slo"); r.Status != http.StatusNotFound {
		t.Fatalf("SLO on OIDC connection: %d", r.Status)
	}
}

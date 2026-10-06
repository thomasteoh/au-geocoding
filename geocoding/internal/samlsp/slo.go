package samlsp

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"augeocoding/internal/identity"
)

// SAML single logout (docs/auth.md "SAML 2.0"). crewjam v0.5.1 signs
// redirect-binding logout messages inside the XML and cannot verify a
// signature carried in the query string, which is what most IdPs send, so
// the bindings are done here; crewjam supplies the schema types and signing
// context.

const protocolNS = "urn:oasis:names:tc:SAML:2.0:protocol"

// maxRelayState bounds an echoed RelayState (the spec says 80 bytes).
const maxRelayState = 1024

// SLOURL is a connection's single logout service URL.
func SLOURL(publicURL, slug string) string {
	return publicURL + "/auth/saml/" + url.PathEscape(slug) + "/slo"
}

// idpSLO returns the IdP's single logout endpoint: HTTP-Redirect if the
// metadata publishes one, else HTTP-POST. respLoc is where it wants
// responses (ResponseLocation, else Location).
func idpSLO(sp *saml.ServiceProvider) (binding, loc, respLoc string) {
	if sp.IDPMetadata == nil {
		return "", "", ""
	}
	for _, want := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		for _, d := range sp.IDPMetadata.IDPSSODescriptors {
			for _, e := range d.SingleLogoutServices {
				if e.Binding == want && e.Location != "" {
					respLoc = e.ResponseLocation
					if respLoc == "" {
						respLoc = e.Location
					}
					return want, e.Location, respLoc
				}
			}
		}
	}
	return "", "", ""
}

// HasSLO reports whether the IdP publishes an HTTP-Redirect or HTTP-POST
// SLO endpoint.
func HasSLO(sp *saml.ServiceProvider) bool {
	_, loc, _ := idpSLO(sp)
	return loc != ""
}

func newID() string {
	b := make([]byte, 20)
	rand.Read(b)
	return "id-" + hex.EncodeToString(b)
}

func spIssuer(sp *saml.ServiceProvider) *saml.Issuer {
	return &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: sp.EntityID}
}

// Outbound is a signed logout message ready to send to the IdP.
//
// For HTTP-Redirect, URL is the full IdP URL with the message signed in the
// query. For HTTP-POST, URL is the form action and Param (SAMLRequest or
// SAMLResponse), Value (base64 XML with an enveloped signature) and
// RelayState are the form fields.
type Outbound struct {
	ID         string
	Binding    string
	URL        string
	Param      string
	Value      string
	RelayState string
}

// LogoutRequest builds a signed LogoutRequest for nameID, carrying the
// NameID format and qualifiers from the assertion (strict IdPs such as ADFS
// match on them) and sessionIndex, if known. Its ID is what the IdP's
// LogoutResponse must answer.
func LogoutRequest(sp *saml.ServiceProvider, nameID string, q identity.NameIDQualifiers, sessionIndex string) (*Outbound, error) {
	binding, loc, _ := idpSLO(sp)
	if loc == "" {
		return nil, errors.New("IdP has no single logout endpoint")
	}
	if nameID == "" {
		return nil, errors.New("no NameID to log out")
	}
	req := &saml.LogoutRequest{ID: newID(), Version: "2.0", IssueInstant: saml.TimeNow(), Destination: loc,
		Issuer: spIssuer(sp), NameID: &saml.NameID{Value: nameID, Format: q.Format,
			NameQualifier: q.NameQualifier, SPNameQualifier: q.SPNameQualifier}}
	if sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}
	return outbound(sp, binding, loc, "SAMLRequest", req.ID, req.Element(), "")
}

// LogoutResponse builds a signed, successful LogoutResponse to the request
// inResponseTo, echoing relayState.
func LogoutResponse(sp *saml.ServiceProvider, inResponseTo, relayState string) (*Outbound, error) {
	binding, _, loc := idpSLO(sp)
	if loc == "" {
		return nil, errors.New("IdP has no single logout endpoint")
	}
	resp := &saml.LogoutResponse{ID: newID(), InResponseTo: inResponseTo, Version: "2.0", IssueInstant: saml.TimeNow(),
		Destination: loc, Issuer: spIssuer(sp), Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
	return outbound(sp, binding, loc, "SAMLResponse", resp.ID, resp.Element(), relayState)
}

func outbound(sp *saml.ServiceProvider, binding, loc, param, id string, el *etree.Element, relayState string) (*Outbound, error) {
	out := &Outbound{ID: id, Binding: binding}
	var err error
	if binding == saml.HTTPRedirectBinding {
		out.URL, err = redirectURL(sp, loc, param, el, relayState)
		return out, err
	}
	// The console CSP allows form posts to https: only.
	u, err := url.Parse(loc)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("IdP HTTP-POST single logout URL is not https")
	}
	if out.Value, err = postValue(sp, el); err != nil {
		return nil, err
	}
	out.URL, out.Param, out.RelayState = loc, param, relayState
	return out, nil
}

// postValue signs el with an enveloped XML signature for the HTTP-POST
// binding (bindings 3.5.4) and returns it base64-encoded. The Signature is
// moved to follow Issuer, where the schema puts it; the enveloped-signature
// transform makes its position irrelevant to the digest.
func postValue(sp *saml.ServiceProvider, el *etree.Element) (string, error) {
	sc, err := saml.GetSigningContext(sp)
	if err != nil {
		return "", err
	}
	signed, err := sc.SignEnveloped(el)
	if err != nil {
		return "", err
	}
	if n := len(signed.Child); n > 0 {
		if sig, ok := signed.Child[n-1].(*etree.Element); ok && sig.Tag == "Signature" {
			if iss := signed.FindElement("./Issuer"); iss != nil {
				signed.RemoveChildAt(n - 1)
				signed.InsertChildAt(iss.Index()+1, sig)
			}
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// redirectURL encodes el for the HTTP-Redirect binding (DEFLATE, base64) and
// signs the query (SAML bindings 3.4.4.1).
func redirectURL(sp *saml.ServiceProvider, dest, param string, el *etree.Element, relayState string) (string, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	fw.Write(raw)
	if err := fw.Close(); err != nil {
		return "", err
	}
	u, err := url.Parse(dest)
	if err != nil {
		return "", err
	}
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	q += "&SigAlg=" + url.QueryEscape(sp.SignatureMethod)
	sc, err := saml.GetSigningContext(sp)
	if err != nil {
		return "", err
	}
	sig, err := sc.SignString(q)
	if err != nil {
		return "", err
	}
	q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	if u.RawQuery != "" {
		q = u.RawQuery + "&" + q
	}
	u.RawQuery = q
	return u.String(), nil
}

// RejectError is why ParseLogout refused a message: Code is a short reason
// for the audit log; the message is for logs. Neither includes the XML.
type RejectError struct {
	Code string
	msg  string
}

func (e *RejectError) Error() string { return e.msg }

func reject(code, msg string) error { return &RejectError{Code: code, msg: msg} }

// RejectCode returns the reason code of a ParseLogout error ("invalid" if
// it has none).
func RejectCode(err error) string {
	var re *RejectError
	if errors.As(err, &re) {
		return re.Code
	}
	return "invalid"
}

// LogoutMessage is a verified logout message from the IdP: exactly one of
// Request (IdP-initiated) and Response (to an SP-initiated request) is set.
type LogoutMessage struct {
	Request    *saml.LogoutRequest
	Response   *saml.LogoutResponse
	RelayState string
}

// ParseLogout verifies a logout message arriving at the SLO URL by
// HTTP-Redirect (GET) or HTTP-POST. The caller bounds the body. The message
// must be signed by one of the IdP's signing certificates, in the query
// (redirect) or as an enveloped XML signature; its issuer, destination and
// times are checked. A LogoutResponse must report success. Errors are for
// logs only and never include the message.
func ParseLogout(sp *saml.ServiceProvider, r *http.Request) (*LogoutMessage, error) {
	certs, err := idpSigningCerts(sp.IDPMetadata)
	if err != nil {
		return nil, err
	}
	var raw []byte
	var querySigned bool
	m := &LogoutMessage{}
	switch r.Method {
	case http.MethodGet:
		q, err := rawQuery(r.URL.RawQuery)
		if err != nil {
			return nil, err
		}
		param := "SAMLRequest"
		if _, ok := q["SAMLResponse"]; ok {
			param = "SAMLResponse"
		}
		if _, ok := q["SAMLRequest"]; ok == (param == "SAMLResponse") {
			return nil, reject("malformed", "need exactly one of SAMLRequest and SAMLResponse")
		}
		if m.RelayState, err = url.QueryUnescape(q["RelayState"]); err != nil {
			return nil, reject("malformed", "bad RelayState")
		}
		if _, ok := q["Signature"]; ok {
			if err := verifyQuery(certs, q, param); err != nil {
				return nil, err
			}
			querySigned = true
		}
		v, err := url.QueryUnescape(q[param])
		if err != nil {
			return nil, reject("malformed", "bad message encoding")
		}
		if raw, err = inflate(v); err != nil {
			return nil, err
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return nil, reject("malformed", "unreadable form")
		}
		v := r.PostForm.Get("SAMLRequest")
		if r.PostForm.Get("SAMLResponse") != "" {
			if v != "" {
				return nil, reject("malformed", "need exactly one of SAMLRequest and SAMLResponse")
			}
			v = r.PostForm.Get("SAMLResponse")
		}
		m.RelayState = r.PostForm.Get("RelayState")
		if raw, err = base64.StdEncoding.DecodeString(v); err != nil || len(raw) == 0 {
			return nil, reject("malformed", "message is missing or not base64")
		}
	default:
		return nil, reject("method", "method not allowed")
	}
	if len(m.RelayState) > maxRelayState {
		return nil, reject("malformed", "RelayState too long")
	}

	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, reject("malformed", "message XML does not round-trip")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return nil, reject("malformed", "message is not XML")
	}
	el := doc.Root()
	if !querySigned {
		// Unmarshal only what the signature covers.
		if el, err = verifyXML(certs, el); err != nil {
			return nil, err
		}
	}
	ns := el.NamespaceURI()
	if ns != protocolNS {
		return nil, reject("malformed", "not a SAML protocol message")
	}
	b, err := elementBytes(el)
	if err != nil {
		return nil, err
	}
	now := saml.TimeNow()
	switch el.Tag {
	case "LogoutRequest":
		var req saml.LogoutRequest
		if err := xml.Unmarshal(b, &req); err != nil {
			return nil, reject("malformed", "malformed LogoutRequest")
		}
		if err := checkCommon(sp, req.Version, req.Issuer, req.Destination, req.IssueInstant, now); err != nil {
			return nil, err
		}
		if req.ID == "" {
			return nil, reject("malformed", "LogoutRequest has no ID")
		}
		if req.NotOnOrAfter != nil && !now.Before(req.NotOnOrAfter.Add(saml.MaxClockSkew)) {
			return nil, reject("expired", "LogoutRequest has expired (NotOnOrAfter)")
		}
		if req.NameID == nil || strings.TrimSpace(req.NameID.Value) == "" {
			return nil, reject("malformed", "LogoutRequest has no NameID")
		}
		m.Request = &req
	case "LogoutResponse":
		var resp saml.LogoutResponse
		if err := xml.Unmarshal(b, &resp); err != nil {
			return nil, reject("malformed", "malformed LogoutResponse")
		}
		if err := checkCommon(sp, resp.Version, resp.Issuer, resp.Destination, resp.IssueInstant, now); err != nil {
			return nil, err
		}
		if resp.Status.StatusCode.Value != saml.StatusSuccess {
			return nil, reject("status_not_success", fmt.Sprintf("logout status %q", resp.Status.StatusCode.Value))
		}
		m.Response = &resp
	default:
		return nil, reject("malformed", "not a logout message")
	}
	return m, nil
}

func checkCommon(sp *saml.ServiceProvider, version string, iss *saml.Issuer, dest string, issued, now time.Time) error {
	if version != "2.0" {
		return reject("malformed", "not SAML 2.0")
	}
	if iss == nil || strings.TrimSpace(iss.Value) != sp.IDPMetadata.EntityID {
		return reject("wrong_issuer", "issuer is not the IdP")
	}
	// Signed messages must carry a Destination (bindings 3.4.5.2, 3.5.5.2).
	if dest != sp.SloURL.String() {
		return reject("wrong_destination", "destination is not this SLO URL")
	}
	if issued.IsZero() || issued.After(now.Add(saml.MaxClockSkew)) ||
		issued.Add(saml.MaxIssueDelay+saml.MaxClockSkew).Before(now) {
		return reject("stale", "IssueInstant out of range")
	}
	return nil
}

// rawQuery splits a query string keeping each value exactly as sent, since
// the redirect signature covers the encoded form. Repeated keys are refused.
func rawQuery(q string) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range strings.Split(q, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		k, err := url.QueryUnescape(k)
		if err != nil {
			return nil, reject("malformed", "bad query")
		}
		if _, dup := out[k]; dup {
			return nil, reject("malformed", "repeated query parameter")
		}
		out[k] = v
	}
	return out, nil
}

var sigHashes = map[string]crypto.Hash{
	dsig.RSASHA256SignatureMethod: crypto.SHA256,
	dsig.RSASHA384SignatureMethod: crypto.SHA384,
	dsig.RSASHA512SignatureMethod: crypto.SHA512,
}

// verifyQuery checks an HTTP-Redirect binding signature (bindings 3.4.4.1)
// over the parameters in their received encoding.
func verifyQuery(certs []*x509.Certificate, q map[string]string, param string) error {
	alg, err := url.QueryUnescape(q["SigAlg"])
	if err != nil {
		return reject("bad_signature", "bad SigAlg")
	}
	h, ok := sigHashes[alg]
	if !ok {
		return reject("bad_signature", "unsupported or missing SigAlg")
	}
	sigB64, err := url.QueryUnescape(q["Signature"])
	if err != nil {
		return reject("bad_signature", "bad Signature")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) == 0 {
		return reject("bad_signature", "bad Signature")
	}
	signed := param + "=" + q[param]
	if rs, ok := q["RelayState"]; ok {
		signed += "&RelayState=" + rs
	}
	signed += "&SigAlg=" + q["SigAlg"]
	hh := h.New()
	hh.Write([]byte(signed))
	digest := hh.Sum(nil)
	for _, c := range certs {
		if pk, ok := c.PublicKey.(*rsa.PublicKey); ok && rsa.VerifyPKCS1v15(pk, h, digest, sig) == nil {
			return nil
		}
	}
	return reject("bad_signature", "query signature does not verify against the IdP's certificates")
}

// verifyXML checks an enveloped signature on the root element and returns
// the verified element.
func verifyXML(certs []*x509.Certificate, el *etree.Element) (*etree.Element, error) {
	if el.FindElement("./Signature") == nil {
		return nil, reject("unsigned", "message is not signed")
	}
	// As crewjam does: with no certificate in KeyInfo, drop KeyInfo so the
	// metadata certificates are used.
	if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
		if sigEl := el.FindElement("./Signature"); sigEl != nil {
			if ki := sigEl.FindElement("KeyInfo"); ki != nil {
				sigEl.RemoveChild(ki)
			}
		}
	}
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err == nil {
		ctx, err = ctx.SubContext(el)
	}
	if err == nil {
		el, err = etreeutils.NSDetatch(ctx, el)
	}
	if err != nil {
		return nil, reject("bad_signature", "bad XML namespaces")
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	vc.IdAttribute = "ID"
	if saml.Clock != nil {
		vc.Clock = saml.Clock
	}
	out, err := vc.Validate(el)
	if err != nil {
		return nil, reject("bad_signature", "XML signature: "+err.Error())
	}
	return out, nil
}

func inflate(b64 string) ([]byte, error) {
	z, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(z) == 0 {
		return nil, reject("malformed", "message is missing or not base64")
	}
	raw, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(z)), MaxResponseBytes+1))
	if err != nil {
		return nil, reject("malformed", "message is not DEFLATE")
	}
	if len(raw) > MaxResponseBytes {
		return nil, reject("malformed", "message too large")
	}
	return raw, nil
}

func elementBytes(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	return doc.WriteToBytes()
}

var spaceRe = regexp.MustCompile(`\s+`)

// idpSigningCerts returns the IdP's signing certificates from its metadata.
func idpSigningCerts(ed *saml.EntityDescriptor) ([]*x509.Certificate, error) {
	if ed == nil {
		return nil, reject("idp_metadata", "no IdP metadata")
	}
	var certs []*x509.Certificate
	for _, d := range ed.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(spaceRe.ReplaceAllString(xc.Data, ""))
				if err != nil {
					return nil, reject("idp_metadata", "bad IdP certificate")
				}
				c, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, reject("idp_metadata", "bad IdP certificate")
				}
				certs = append(certs, c)
			}
		}
	}
	if len(certs) == 0 {
		return nil, reject("idp_metadata", "IdP metadata has no signing certificate")
	}
	return certs, nil
}

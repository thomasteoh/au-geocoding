package samlsp

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/crewjam/saml"
)

// MaxMetadataBytes bounds IdP metadata documents.
const MaxMetadataBytes = 1 << 20

// ParseIdPMetadata parses IdP metadata XML and checks it is usable: an
// IDPSSODescriptor with an HTTP-Redirect SSO endpoint and a signing
// certificate.
func ParseIdPMetadata(doc string) (*saml.EntityDescriptor, error) {
	if len(doc) == 0 || len(doc) > MaxMetadataBytes {
		return nil, errors.New("metadata is empty or too large")
	}
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal([]byte(doc), &ed); err != nil {
		// Some IdPs publish an EntitiesDescriptor wrapping one entity.
		var eds saml.EntitiesDescriptor
		if err2 := xml.Unmarshal([]byte(doc), &eds); err2 != nil || len(eds.EntityDescriptors) != 1 {
			return nil, fmt.Errorf("metadata is not a SAML EntityDescriptor: %w", err)
		}
		ed = eds.EntityDescriptors[0]
	}
	if ed.EntityID == "" || len(ed.IDPSSODescriptors) == 0 {
		return nil, errors.New("metadata has no identity provider (IDPSSODescriptor)")
	}
	idp := ed.IDPSSODescriptors[0]
	redirect := false
	for _, s := range idp.SingleSignOnServices {
		redirect = redirect || s.Binding == saml.HTTPRedirectBinding
	}
	if !redirect {
		return nil, errors.New("metadata has no HTTP-Redirect single sign-on endpoint")
	}
	signing := false
	for _, kd := range idp.KeyDescriptors {
		if (kd.Use == "" || kd.Use == "signing") && len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
			signing = true
		}
	}
	if !signing {
		return nil, errors.New("metadata has no signing certificate")
	}
	return &ed, nil
}

// ValidateIdPMetadata reports whether doc is usable IdP metadata.
func ValidateIdPMetadata(doc string) error {
	_, err := ParseIdPMetadata(doc)
	return err
}

// FetchIdPMetadata downloads IdP metadata from an admin-supplied https URL
// with client (safehttp in production) and validates it.
func FetchIdPMetadata(ctx context.Context, client *http.Client, url string) (string, error) {
	if !strings.HasPrefix(url, "https://") {
		return "", errors.New("metadata URL must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch metadata: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxMetadataBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > MaxMetadataBytes {
		return "", errors.New("metadata is too large")
	}
	doc := string(b)
	if err := ValidateIdPMetadata(doc); err != nil {
		return "", err
	}
	return doc, nil
}

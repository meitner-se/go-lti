package platform

import (
	"errors"
	"fmt"
	"strings"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
)

// Config describes the platform: its issuer, its endpoints and how it names itself to tools.
// It holds no keys, so code that only builds URLs or documents can use it.
type Config struct {
	// Issuer is the iss of every platform message, an https URL.
	Issuer    string
	Endpoints Endpoints
	// Product is the platform's product, for the tool_platform claim and the platform configuration.
	Product Product
	// Scopes are the service scopes the platform offers tools.
	Scopes []lti.Scope
	// Variables are the substitution variables the platform offers in custom parameters.
	Variables []lti.Variable
}

// Endpoints are the platform's absolute https URLs.
type Endpoints struct {
	// Authorization is the OIDC authorization endpoint tools send the authentication request to.
	Authorization string
	// JWKS is where the platform's public keys are published.
	JWKS string
	// Registration is the Dynamic Registration endpoint. Optional.
	Registration string
	// Token is the OAuth 2.0 token endpoint for LTI services. Optional.
	Token string
	// DeepLinkReturn is where tools post Deep Linking responses by default. Optional.
	DeepLinkReturn string
}

// Product is the platform's product (LTI 1.3 §5.4.2).
type Product struct {
	// GUID identifies this platform instance to tools, stable for the issuer. At most 255 characters.
	GUID         string
	Name         string
	FamilyCode   string
	Version      string
	ContactEmail string
	URL          string
}

// Validate checks that the issuer, the authorization and JWKS endpoints and the product GUID are
// set, and that every endpoint is an absolute https URL.
func (c Config) Validate() error {
	// Security Framework §5.1.2: the issuer is an https URL with no query or fragment.
	if u, ok := urlcheck.ParseHTTPS(c.Issuer); !ok || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(c.Issuer, "#") {
		return errors.New("lti: config issuer must be an absolute https url without a query or fragment")
	}

	required := map[string]string{"authorization": c.Endpoints.Authorization, "jwks": c.Endpoints.JWKS}
	for name, endpoint := range required {
		if !urlcheck.IsHTTPS(endpoint) {
			return fmt.Errorf("lti: config %s endpoint must be an absolute https url", name)
		}
	}

	optional := map[string]string{
		"registration":     c.Endpoints.Registration,
		"token":            c.Endpoints.Token,
		"deep link return": c.Endpoints.DeepLinkReturn,
	}
	for name, endpoint := range optional {
		if endpoint != "" && !urlcheck.IsHTTPS(endpoint) {
			return fmt.Errorf("lti: config %s endpoint must be an absolute https url", name)
		}
	}

	if c.Product.GUID == "" || len(c.Product.GUID) > maxIdentifierLength {
		return errors.New("lti: config product guid must be set and at most 255 characters")
	}

	return nil
}

// Tool is the platform's record of a registered tool. Every flow takes the same type.
type Tool struct {
	// ClientID is the tool's OAuth client_id: the aud of our messages and the iss of the tool's.
	ClientID string
	// InitiateLoginURI is the tool's OIDC third-party login initiation URL.
	InitiateLoginURI string
	// RedirectURIs are the URIs the platform may post an id_token to, matched exactly.
	RedirectURIs []string
	// TargetLinkURI is the tool's default launch URL.
	TargetLinkURI string
	// JWKSURI is where the tool publishes its public keys.
	JWKSURI string
	// Domains are the tool's domain and secondary domains. OnToolDomains checks a URL against them;
	// Verify doesn't, since Deep Linking content may live anywhere.
	Domains []string
}

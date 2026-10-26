package platform

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
)

// Config describes the platform: its issuer, its token endpoint and how it names itself to tools.
// It holds no keys, so code that only builds URLs or documents can use it.
type Config struct {
	// Issuer is the iss of every platform message, an https URL. The platform's endpoints are the
	// issuer plus Paths (see Endpoints), and NewHandler serves them.
	Issuer string
	// Paths are where the platform's endpoints are under the issuer. Required.
	Paths Paths
	// TokenEndpoint is the OAuth 2.0 token endpoint for LTI services, an absolute https URL. It
	// isn't under the issuer, since a platform usually shares it with other OAuth clients.
	// Optional, but Dynamic Registration needs it.
	TokenEndpoint string
	// Product is the platform's product, for the tool_platform claim and the platform configuration.
	Product Product
	// Scopes are the service scopes the platform offers tools.
	Scopes []lti.Scope
	// Variables are the substitution variables the platform offers in custom parameters.
	Variables []lti.Variable
}

// PathOpenIDConfiguration is where the platform's OpenID configuration is under its issuer. OpenID
// Connect Discovery 1.0 §4 fixes it, so it isn't one of Paths.
const PathOpenIDConfiguration = "/.well-known/openid-configuration"

// Paths are where the platform's endpoints are under its issuer, such as "/register". Each is
// required, starts with "/" and is unique. Tools learn the URLs from the OpenID configuration, a
// Dynamic Registration or a launch, and keep them once registered, so a path must not change after
// tools have registered.
type Paths struct {
	Authorization  string
	JWKS           string
	Registration   string
	DeepLinkReturn string
}

// Endpoints are the platform's absolute https URLs.
type Endpoints struct {
	// OpenIDConfiguration is the platform's OpenID configuration, the openid_configuration of a
	// Dynamic Registration.
	OpenIDConfiguration string
	// Authorization is the OIDC authorization endpoint tools send the authentication request to.
	Authorization string
	// JWKS is where the platform's public keys are published.
	JWKS string
	// Registration is the Dynamic Registration endpoint.
	Registration string
	// Token is the OAuth 2.0 token endpoint for LTI services: Config.TokenEndpoint.
	Token string
	// DeepLinkReturn is where tools post Deep Linking responses by default.
	DeepLinkReturn string
}

// Endpoints returns the platform's endpoints: the issuer plus each endpoint's path, and the token
// endpoint as configured.
func (c Config) Endpoints() Endpoints {
	issuer := strings.TrimSuffix(c.Issuer, "/")

	return Endpoints{
		OpenIDConfiguration: issuer + PathOpenIDConfiguration,
		Authorization:       issuer + c.Paths.Authorization,
		JWKS:                issuer + c.Paths.JWKS,
		Registration:        issuer + c.Paths.Registration,
		Token:               c.TokenEndpoint,
		DeepLinkReturn:      issuer + c.Paths.DeepLinkReturn,
	}
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

// Validate checks that the issuer is an https URL without a query or fragment, that every path is
// set, clean and unique, that the token endpoint, when set, is an absolute https URL, and that the
// product GUID is set.
func (c Config) Validate() error {
	// Security Framework §5.1.2: the issuer is an https URL with no query or fragment.
	if u, ok := urlcheck.ParseHTTPS(c.Issuer); !ok || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(c.Issuer, "#") {
		return errors.New("lti: config issuer must be an absolute https url without a query or fragment")
	}

	if err := c.Paths.validate(); err != nil {
		return err
	}

	if c.TokenEndpoint != "" && !urlcheck.IsHTTPS(c.TokenEndpoint) {
		return errors.New("lti: config token endpoint must be an absolute https url")
	}

	if c.Product.GUID == "" || len(c.Product.GUID) > maxIdentifierLength {
		return errors.New("lti: config product guid must be set and at most 255 characters")
	}

	return nil
}

// validate checks that each path starts with "/", is clean (no trailing slash, no "." or ".."
// segments), has no query, fragment, braces or spaces, and differs from the others and from
// PathOpenIDConfiguration.
func (p Paths) validate() error {
	seen := map[string]string{PathOpenIDConfiguration: "the openid configuration"}

	for _, named := range []struct{ name, path string }{
		{"authorization", p.Authorization},
		{"jwks", p.JWKS},
		{"registration", p.Registration},
		{"deep link return", p.DeepLinkReturn},
	} {
		if named.path == "" || named.path == "/" || !strings.HasPrefix(named.path, "/") || path.Clean(named.path) != named.path ||
			strings.ContainsAny(named.path, "?#{} \t\n") {
			return fmt.Errorf("lti: config %s path must be a clean path such as /register", named.name)
		}

		if other, ok := seen[named.path]; ok {
			return fmt.Errorf("lti: config %s path is the same as %s", named.name, other)
		}

		seen[named.path] = named.name + " path"
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

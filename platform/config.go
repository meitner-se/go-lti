package platform

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
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
	// NoticeTypes are the notice types the platform sends with the LTI Platform Notification
	// Service, named Lti…Notice, such as LtiAssetProcessorSubmissionNotice, in the order a tool
	// sees them. A tool may register a handler only for one of them. The OpenID configuration lists
	// them whenever the platform offers the service, as an empty array when there are none.
	NoticeTypes []lti.NoticeType
}

// PathOpenIDConfiguration is where the platform's OpenID configuration is under its issuer. OpenID
// Connect Discovery 1.0 §4 fixes it, so it isn't one of Paths.
const PathOpenIDConfiguration = "/.well-known/openid-configuration"

// Paths are where the platform's endpoints are under its issuer, such as "/register". Each starts
// with "/" and is unique, and each is required except ContextMemberships, ContextLineItems,
// NoticeHandlers and RegistrationClient; the first two may share a prefix. Tools learn the URLs from
// the OpenID configuration, a Dynamic Registration or a launch, and keep them once registered, so
// a path must not change after tools have registered.
type Paths struct {
	Authorization  string
	JWKS           string
	Registration   string
	DeepLinkReturn string
	// ContextMemberships is the prefix of each context's Names and Role Provisioning Services
	// endpoint, such as "/contexts": a context's members are at the prefix plus
	// "/{context}/memberships" (see Config.ContextMembershipsURL). Empty when the platform offers
	// none.
	ContextMemberships string
	// ContextLineItems is the prefix of each context's Assignment and Grade Services line items,
	// such as "/contexts": a context's line item container is at the prefix plus
	// "/{context}/lineitems" (see Config.LineItemsURL). It may be ContextMemberships. Empty when the
	// platform offers none.
	ContextLineItems string
	// NoticeHandlers is the prefix of each deployment's LTI Platform Notification Service endpoint,
	// such as "/notice-handlers": a deployment's notice handlers are at the prefix plus
	// "/{deployment}" (see Config.NoticeHandlersURL). Empty when the platform offers none.
	NoticeHandlers string
	// RegistrationClient is the prefix of each Dynamic Registration's client configuration
	// endpoint (LTI Dynamic Registration 1.0 §4), such as "/registrations": a tool reads and
	// updates its registration at the prefix plus "/{client_id}" (see Config.RegistrationClientURL),
	// the registration_client_uri of its registration response. Empty when the platform offers
	// none.
	RegistrationClient string
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

// ContextMembershipsURL returns where a tool reads the members of the context with contextID, the
// ContextMembershipsURL of a launch to it: the issuer plus Paths.ContextMemberships plus
// "/{context}/memberships", with contextID path-escaped. NewHandler serves it. It fails without
// Paths.ContextMemberships, and for a contextID that is empty, "." or "..", which no URL path can
// carry.
func (c Config) ContextMembershipsURL(contextID string) (string, error) {
	if c.Paths.ContextMemberships == "" {
		return "", errors.New("lti: config has no context memberships path")
	}

	if !isPathSegment(contextID) {
		return "", errors.New(`lti: a context memberships url needs a context id other than "", "." or ".."`)
	}

	return strings.TrimSuffix(c.Issuer, "/") + c.Paths.ContextMemberships + "/" + url.PathEscape(contextID) + "/memberships", nil
}

// LineItemsURL returns the line item container of the context with contextID, the LineItems of a
// launch's AGSEndpoint: the issuer plus Paths.ContextLineItems plus "/{context}/lineitems", with
// contextID path-escaped. NewHandler serves it. It fails without Paths.ContextLineItems, and for a
// contextID that is empty, "." or "..".
func (c Config) LineItemsURL(contextID string) (string, error) {
	if c.Paths.ContextLineItems == "" {
		return "", errors.New("lti: config has no context line items path")
	}

	if !isPathSegment(contextID) {
		return "", errors.New(`lti: a line items url needs a context id other than "", "." or ".."`)
	}

	return strings.TrimSuffix(c.Issuer, "/") + c.Paths.ContextLineItems + "/" + url.PathEscape(contextID) + "/lineitems", nil
}

// LineItemURL returns the URL of the line item with lineItemID in the context with contextID, which
// is the line item's id and the LineItem of a launch's AGSEndpoint: LineItemsURL plus
// "/{lineitem}", with lineItemID path-escaped. NewHandler serves it. It fails as LineItemsURL does,
// and for a lineItemID that is empty, "." or "..".
func (c Config) LineItemURL(contextID, lineItemID string) (string, error) {
	lineItems, err := c.LineItemsURL(contextID)
	if err != nil {
		return "", err
	}

	if !isPathSegment(lineItemID) {
		return "", errors.New(`lti: a line item url needs a line item id other than "", "." or ".."`)
	}

	return lineItems + "/" + url.PathEscape(lineItemID), nil
}

// NoticeHandlersURL returns where a tool reads and replaces its notice handlers for the deployment
// with deploymentID, the URL of the Platform Notification Service claim: the issuer plus
// Paths.NoticeHandlers plus "/{deployment}", with deploymentID path-escaped. NewHandler serves it.
// It fails without Paths.NoticeHandlers, and for a deploymentID that is empty, "." or "..".
func (c Config) NoticeHandlersURL(deploymentID string) (string, error) {
	if c.Paths.NoticeHandlers == "" {
		return "", errors.New("lti: config has no notice handlers path")
	}

	if !isPathSegment(deploymentID) {
		return "", errors.New(`lti: a notice handlers url needs a deployment id other than "", "." or ".."`)
	}

	return strings.TrimSuffix(c.Issuer, "/") + c.Paths.NoticeHandlers + "/" + url.PathEscape(deploymentID), nil
}

// RegistrationClientURL returns where the tool with clientID reads and updates its Dynamic
// Registration, the registration_client_uri of its registration response (LTI Dynamic
// Registration 1.0 §2.3, §4): the issuer plus Paths.RegistrationClient plus "/{client_id}", with
// clientID path-escaped. NewHandler serves it. It fails without Paths.RegistrationClient, and for a
// clientID that is empty, "." or "..".
func (c Config) RegistrationClientURL(clientID string) (string, error) {
	if c.Paths.RegistrationClient == "" {
		return "", errors.New("lti: config has no registration client path")
	}

	if !isPathSegment(clientID) {
		return "", errors.New(`lti: a registration client url needs a client id other than "", "." or ".."`)
	}

	return strings.TrimSuffix(c.Issuer, "/") + c.Paths.RegistrationClient + "/" + url.PathEscape(clientID), nil
}

// scopesSupported returns the service scopes the platform offers: Scopes, plus
// lti.ScopeRegistrationReadOnly and lti.ScopeRegistration when it serves the client configuration
// endpoint, each once.
func (c Config) scopesSupported() []lti.Scope {
	scopes := slices.Clone(c.Scopes)

	if c.Paths.RegistrationClient != "" {
		for _, scope := range []lti.Scope{lti.ScopeRegistrationReadOnly, lti.ScopeRegistration} {
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
	}

	return scopes
}

// PlatformNotificationService returns the Platform Notification Service claim for a launch in the
// deployment with deploymentID, the PlatformNotificationService of its lti.Common: the
// deployment's NoticeHandlersURL and the platform's NoticeTypes. It fails as NoticeHandlersURL does.
func (c Config) PlatformNotificationService(deploymentID string) (*lti.PlatformNotificationService, error) {
	handlers, err := c.NoticeHandlersURL(deploymentID)
	if err != nil {
		return nil, err
	}

	return &lti.PlatformNotificationService{URL: handlers, NoticeTypesSupported: slices.Clone(c.NoticeTypes)}, nil
}

// isPathSegment reports whether id, path-escaped, can be a URL path's segment.
func isPathSegment(id string) bool {
	return id != "" && id != "." && id != ".."
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
// PathOpenIDConfiguration. An empty ContextMemberships, ContextLineItems, NoticeHandlers or
// RegistrationClient is left out. ContextMemberships and ContextLineItems may be the same, but no
// two of the four prefixes may be one under the other, whose routes would overlap.
func (p Paths) validate() error {
	seen := map[string]string{PathOpenIDConfiguration: "the openid configuration"}

	for _, named := range []struct {
		name, path string
		optional   bool
	}{
		{"authorization", p.Authorization, false},
		{"jwks", p.JWKS, false},
		{"registration", p.Registration, false},
		{"deep link return", p.DeepLinkReturn, false},
		{"context memberships", p.ContextMemberships, true},
		{"context line items", p.ContextLineItems, true},
		{"notice handlers", p.NoticeHandlers, true},
		{"registration client", p.RegistrationClient, true},
	} {
		if named.optional && named.path == "" {
			continue
		}

		// The two services' routes differ after the context, so they can share a prefix.
		if named.path == p.ContextMemberships && named.name == "context line items" {
			continue
		}

		if named.path == "" || named.path == "/" || !strings.HasPrefix(named.path, "/") || path.Clean(named.path) != named.path ||
			strings.ContainsAny(named.path, "?#{} \t\n") {
			return fmt.Errorf("lti: config %s path must be a clean path such as /register", named.name)
		}

		if other, ok := seen[named.path]; ok {
			return fmt.Errorf("lti: config %s path is the same as %s", named.name, other)
		}

		seen[named.path] = named.name + " path"
	}

	if m, l := p.ContextMemberships, p.ContextLineItems; m != "" && l != "" && (strings.HasPrefix(m, l+"/") || strings.HasPrefix(l, m+"/")) {
		return errors.New("lti: config context memberships and context line items paths must be the same or neither under the other")
	}

	for _, prefix := range []string{p.ContextMemberships, p.ContextLineItems} {
		if n := p.NoticeHandlers; n != "" && prefix != "" && (strings.HasPrefix(n, prefix+"/") || strings.HasPrefix(prefix, n+"/")) {
			return errors.New("lti: config notice handlers path must not be under a context path, nor a context path under it")
		}
	}

	for _, prefix := range []string{p.ContextMemberships, p.ContextLineItems, p.NoticeHandlers} {
		if c := p.RegistrationClient; c != "" && prefix != "" && (strings.HasPrefix(c, prefix+"/") || strings.HasPrefix(prefix, c+"/")) {
			return errors.New("lti: config registration client path must not be under another service's path, nor another service's path under it")
		}
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
	// Domains are the tool's domain, first, and its secondary domains, as Registration.Tool sets
	// them. OnToolDomains checks a URL against them; Verify doesn't, since Deep Linking content may
	// live anywhere.
	Domains []string
}

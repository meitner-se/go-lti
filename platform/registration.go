package platform

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
)

// MaxRegistrationBytes caps the size of a Dynamic Registration request body.
const MaxRegistrationBytes = 1 << 20

// Claims a tool can ask for that reveal who the user is, by name or by email address.
var (
	nameClaims  = []string{"name", "given_name", "family_name", "middle_name", "nickname", "preferred_username"}
	emailClaims = []string{"email"}
)

// Registration is a tool's Dynamic Registration request: OpenID Connect client metadata with the
// LTI tool configuration (LTI Dynamic Registration 1.0 §3.1).
//
//nolint:tagliatelle // RFC 7591 and LTI Dynamic Registration 1.0 define snake_case keys
type Registration struct {
	ApplicationType  string   `json:"application_type,omitempty"`
	ResponseTypes    []string `json:"response_types"`
	GrantTypes       []string `json:"grant_types"`
	InitiateLoginURI string   `json:"initiate_login_uri"`
	RedirectURIs     []string `json:"redirect_uris"`
	ClientName       string   `json:"client_name"`
	// ClientNames are the localized client_name#<language tag> variants, keyed by tag such as "sv".
	ClientNames             map[string]string `json:"-"`
	JWKSURI                 string            `json:"jwks_uri"`
	LogoURI                 string            `json:"logo_uri,omitempty"`
	TokenEndpointAuthMethod string            `json:"token_endpoint_auth_method"`
	Scope                   string            `json:"scope,omitempty"`
	Contacts                []string          `json:"contacts,omitempty"`
	ClientURI               string            `json:"client_uri,omitempty"`
	TOSURI                  string            `json:"tos_uri,omitempty"`
	PolicyURI               string            `json:"policy_uri,omitempty"`
	ToolConfiguration       ToolConfiguration `json:"https://purl.imsglobal.org/spec/lti-tool-configuration"`
}

// ToolConfiguration is the LTI part of a registration (LTI Dynamic Registration 1.0 §3.2).
//
//nolint:tagliatelle // LTI Dynamic Registration 1.0 defines snake_case keys
type ToolConfiguration struct {
	Domain           string            `json:"domain"`
	SecondaryDomains []string          `json:"secondary_domains,omitempty"`
	DeploymentID     string            `json:"deployment_id,omitempty"`
	TargetLinkURI    string            `json:"target_link_uri"`
	CustomParameters map[string]string `json:"custom_parameters,omitempty"`
	Description      string            `json:"description,omitempty"`
	Messages         []ToolMessage     `json:"messages,omitempty"`
	Claims           []string          `json:"claims,omitempty"`
}

// ToolMessage is a message type the tool supports, and where it wants it (LTI Dynamic Registration 1.0 §3.2.1).
//
//nolint:tagliatelle // LTI Dynamic Registration 1.0 defines snake_case keys
type ToolMessage struct {
	Type             lti.MessageType   `json:"type"`
	TargetLinkURI    string            `json:"target_link_uri,omitempty"`
	Label            string            `json:"label,omitempty"`
	IconURI          string            `json:"icon_uri,omitempty"`
	CustomParameters map[string]string `json:"custom_parameters,omitempty"`
	Placements       []string          `json:"placements,omitempty"`
	Roles            []lti.Role        `json:"roles,omitempty"`
}

// Domains returns the tool's domain and secondary domains.
func (r *Registration) Domains() []string {
	return append([]string{r.ToolConfiguration.Domain}, r.ToolConfiguration.SecondaryDomains...)
}

// Scopes returns the scopes the tool asks for.
func (r *Registration) Scopes() []lti.Scope {
	fields := strings.Fields(r.Scope)
	scopes := make([]lti.Scope, 0, len(fields))

	for _, field := range fields {
		scopes = append(scopes, lti.Scope(field))
	}

	return scopes
}

// Tool returns the tool the registration describes, once the platform has given it clientID.
func (r *Registration) Tool(clientID string) Tool {
	return Tool{
		ClientID:         clientID,
		InitiateLoginURI: r.InitiateLoginURI,
		RedirectURIs:     slices.Clone(r.RedirectURIs),
		TargetLinkURI:    r.ToolConfiguration.TargetLinkURI,
		JWKSURI:          r.JWKSURI,
		Domains:          r.Domains(),
	}
}

// ParseRegistration decodes and validates a tool's Dynamic Registration request.
//
// It checks the OpenID Connect metadata LTI requires (an id_token response type, implicit and
// client_credentials grants, private_key_jwt client authentication), that the domains are host
// names and not public suffixes, and that every URL the platform sends users or tokens to is https
// on the tool's domain or secondary domains. The jwks_uri only has to be https. The optional
// logo_uri, client_uri, policy_uri and tos_uri are dropped unless they are https.
//
// A rejection is an *lti.Error with code invalid_redirect_uri or invalid_client_metadata
// (RFC 7591 §3.2.2), whose description is safe to send to the tool.
func ParseRegistration(body []byte) (*Registration, error) {
	if len(body) > MaxRegistrationBytes {
		return nil, invalidMetadata("registration request is larger than 1 MiB", nil)
	}

	var reg Registration
	if err := json.Unmarshal(body, &reg); err != nil {
		return nil, invalidMetadata("registration request is not valid client metadata json", err)
	}

	names, err := parseLocalizedClientNames(body)
	if err != nil {
		return nil, err
	}

	reg.ClientNames = names

	reg.ToolConfiguration.Domain = urlcheck.NormalizeDomain(reg.ToolConfiguration.Domain)
	for i, domain := range reg.ToolConfiguration.SecondaryDomains {
		reg.ToolConfiguration.SecondaryDomains[i] = urlcheck.NormalizeDomain(domain)
	}

	// These are only shown to admins and stored with the tool; an unusable one is dropped rather
	// than failing the registration.
	for _, uri := range []*string{&reg.LogoURI, &reg.ClientURI, &reg.TOSURI, &reg.PolicyURI} {
		if !urlcheck.IsHTTPS(*uri) {
			*uri = ""
		}
	}

	if err := reg.validate(); err != nil {
		return nil, err
	}

	return &reg, nil
}

// parseLocalizedClientNames returns the client_name#<language tag> members of body (RFC 7591 §2.2).
func parseLocalizedClientNames(body []byte) (map[string]string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, invalidMetadata("registration request is not valid client metadata json", err)
	}

	names := map[string]string{}
	for key, raw := range members {
		tag, ok := strings.CutPrefix(key, "client_name#")
		if !ok {
			continue
		}

		var name string
		if err := json.Unmarshal(raw, &name); err != nil || !isLanguageTag(tag) {
			return nil, invalidMetadata("client_name#<language tag> must be a string under a language tag such as client_name#sv", nil)
		}

		if name = strings.TrimSpace(name); name != "" {
			names[tag] = name
		}
	}

	return names, nil
}

// isLanguageTag loosely checks a BCP 47 tag: hyphen-separated alphanumeric subtags of 1 to 8 characters.
func isLanguageTag(tag string) bool {
	if tag == "" {
		return false
	}

	for subtag := range strings.SplitSeq(tag, "-") {
		if subtag == "" || len(subtag) > 8 {
			return false
		}

		for _, r := range subtag {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
				return false
			}
		}
	}

	return true
}

func (r *Registration) validate() error {
	switch {
	case r.ApplicationType != "" && r.ApplicationType != "web":
		return invalidMetadata("application_type must be web", nil)
	case !slices.Contains(r.ResponseTypes, "id_token"):
		return invalidMetadata("response_types must include id_token", nil)
	case !slices.Contains(r.GrantTypes, "implicit") || !slices.Contains(r.GrantTypes, "client_credentials"):
		return invalidMetadata("grant_types must include implicit and client_credentials", nil)
	case r.TokenEndpointAuthMethod != "private_key_jwt":
		return invalidMetadata("token_endpoint_auth_method must be private_key_jwt", nil)
	case !urlcheck.IsHTTPS(r.JWKSURI):
		return invalidMetadata("jwks_uri must be an absolute https url", nil)
	}

	tool := r.ToolConfiguration
	if !urlcheck.IsDomain(tool.Domain) {
		return invalidMetadata("domain must be a host name such as tool.example.com", nil)
	}

	for _, domain := range tool.SecondaryDomains {
		if !urlcheck.IsDomain(domain) {
			return invalidMetadata("secondary_domains must be host names such as tool.example.com", nil)
		}
	}

	domains := r.Domains()

	if !urlcheck.OnDomains(r.InitiateLoginURI, domains) {
		return invalidMetadata("initiate_login_uri must be an https url on the tool's domain", nil)
	}

	if len(r.RedirectURIs) == 0 {
		return lti.NewError(lti.ErrorInvalidRedirectURI, "redirect_uris must have at least one url", nil)
	}

	for _, uri := range r.RedirectURIs {
		if !urlcheck.OnDomains(uri, domains) || strings.Contains(uri, "#") {
			return lti.NewError(lti.ErrorInvalidRedirectURI, "redirect_uris must be https urls on the tool's domain, without a fragment", nil)
		}
	}

	if !urlcheck.OnDomains(tool.TargetLinkURI, domains) {
		return invalidMetadata("target_link_uri must be an https url on the tool's domain", nil)
	}

	for _, message := range tool.Messages {
		if message.Type == "" {
			return invalidMetadata("every message must have a type", nil)
		}

		if message.TargetLinkURI != "" && !urlcheck.OnDomains(message.TargetLinkURI, domains) {
			return invalidMetadata("a message's target_link_uri must be an https url on the tool's domain", nil)
		}
	}

	return nil
}

func invalidMetadata(description string, cause error) *lti.Error {
	return lti.NewError(lti.ErrorInvalidClientMetadata, description, cause)
}

// RegistrationReview is what an admin sees before activating a tool that registered itself.
type RegistrationReview struct {
	ClientName string
	// ClientNames are the tool's localized names, keyed by language tag.
	ClientNames map[string]string
	Description string
	LogoURI     string
	// Domains are the tool's domain and secondary domains: where users will be sent, and where the
	// content it returns must live.
	Domains   []string
	Contacts  []string
	ClientURI string
	TOSURI    string
	PolicyURI string
	Messages  []ReviewMessage
	// RequestedClaims are the claims the tool asks to receive.
	RequestedClaims []string
	// RequestsName and RequestsEmail say whether the tool asks for the user's name or email address.
	RequestsName  bool
	RequestsEmail bool
	// RequestedScopes are the service scopes the tool asks for; UnsupportedScopes are the ones the
	// platform doesn't offer.
	RequestedScopes   []lti.Scope
	UnsupportedScopes []lti.Scope
}

// ReviewMessage is one message type the tool registered for.
type ReviewMessage struct {
	Type          lti.MessageType
	Label         string
	TargetLinkURI string
	// Supported is false for message types this package never sends.
	Supported bool
}

// Review summarises the registration for the admin who decides whether to activate the tool on
// the platform cfg describes. ClientName falls back to the tool's domain.
func (r *Registration) Review(cfg Config) RegistrationReview {
	name := strings.TrimSpace(r.ClientName)
	if name == "" {
		name = r.ToolConfiguration.Domain
	}

	messages := make([]ReviewMessage, 0, len(r.ToolConfiguration.Messages))
	for _, message := range r.ToolConfiguration.Messages {
		messages = append(messages, ReviewMessage{
			Type:          message.Type,
			Label:         message.Label,
			TargetLinkURI: message.TargetLinkURI,
			Supported:     message.Type == lti.MessageTypeResourceLinkRequest || message.Type == lti.MessageTypeDeepLinkingRequest,
		})
	}

	scopes := r.Scopes()

	var unsupported []lti.Scope
	for _, scope := range scopes {
		if !slices.Contains(cfg.Scopes, scope) {
			unsupported = append(unsupported, scope)
		}
	}

	return RegistrationReview{
		ClientName:        name,
		ClientNames:       r.ClientNames,
		Description:       r.ToolConfiguration.Description,
		LogoURI:           r.LogoURI,
		Domains:           r.Domains(),
		Contacts:          r.Contacts,
		ClientURI:         r.ClientURI,
		TOSURI:            r.TOSURI,
		PolicyURI:         r.PolicyURI,
		Messages:          messages,
		RequestedClaims:   r.ToolConfiguration.Claims,
		RequestsName:      containsAny(r.ToolConfiguration.Claims, nameClaims),
		RequestsEmail:     containsAny(r.ToolConfiguration.Claims, emailClaims),
		RequestedScopes:   scopes,
		UnsupportedScopes: unsupported,
	}
}

// RegistrationGrant is what the platform registered for a tool.
type RegistrationGrant struct {
	ClientID     string
	DeploymentID string
	// Scopes are the service scopes granted. Ones the tool didn't ask for are left out of the response.
	Scopes []lti.Scope
	// Claims are the claims the platform will send. Ones the tool didn't ask for are left out of the
	// response.
	Claims []string
}

// RegistrationResponse is the client information response to a registration (RFC 7591 §3.2.1):
// the registered metadata with the tool's client_id and deployment_id.
//
//nolint:tagliatelle // RFC 7591 §3.2.1 defines snake_case keys
type RegistrationResponse struct {
	ClientID string `json:"client_id"`
	Registration
}

// Response returns the response to send the tool once grant is registered. Its scope and claims
// are what the tool asked for narrowed to what grant allows, so it never learns of more access
// than it has.
func (r *Registration) Response(grant RegistrationGrant) RegistrationResponse {
	granted := make([]string, 0, len(grant.Scopes))
	for _, scope := range intersect(r.Scopes(), grant.Scopes) {
		granted = append(granted, string(scope))
	}

	registered := *r
	registered.Scope = strings.Join(granted, " ")
	registered.ToolConfiguration.DeploymentID = grant.DeploymentID
	registered.ToolConfiguration.Claims = intersect(r.ToolConfiguration.Claims, grant.Claims)

	return RegistrationResponse{ClientID: grant.ClientID, Registration: registered}
}

func containsAny(values, wanted []string) bool {
	return slices.ContainsFunc(values, func(v string) bool { return slices.Contains(wanted, v) })
}

// intersect returns the values in a that are also in b, in a's order.
func intersect[T comparable](a, b []T) []T {
	out := []T{}
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}

	return out
}

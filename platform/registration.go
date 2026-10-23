package platform

import (
	"encoding/json"
	"errors"
	"maps"
	"net/url"
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
// LTI tool configuration (LTI Dynamic Registration 1.0 §2.2.1 and §3.5.2).
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

// ToolConfiguration is the LTI part of a registration (LTI Dynamic Registration 1.0 §2.2.2).
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

// ToolMessage is a message type the tool supports, and where it wants it (LTI Dynamic Registration 1.0 §2.2.3).
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

// RegistrationInitiationURL returns where the platform sends the admin's browser to start a
// Dynamic Registration: the tool's registration URL with openid_configuration and, when set,
// registration_token added (LTI Dynamic Registration 1.0 §3.3). The token is opaque to the package;
// the platform decides what it is and checks it at its registration endpoint.
func RegistrationInitiationURL(toolRegistrationURL, openIDConfigurationURL, registrationToken string) (string, error) {
	u, ok := urlcheck.ParseHTTPS(strings.TrimSpace(toolRegistrationURL))
	if !ok {
		return "", lti.NewError(lti.ErrorInvalidRequest, "the tool's registration url must be an absolute https url", nil)
	}

	if !urlcheck.IsHTTPS(openIDConfigurationURL) {
		return "", errors.New("lti: the openid configuration url must be an absolute https url")
	}

	query := u.Query()
	query.Set("openid_configuration", openIDConfigurationURL)

	if registrationToken != "" {
		query.Set("registration_token", registrationToken)
	}

	u.RawQuery = query.Encode()

	return u.String(), nil
}

// ParseRegistration decodes and validates a tool's Dynamic Registration request.
//
// It checks what LTI Dynamic Registration 1.0 §2.2 and OpenID Connect Registration require: an
// id_token response type, implicit and client_credentials grants, private_key_jwt client
// authentication, an https jwks_uri and initiate_login_uri, https redirect_uris without a fragment
// or localhost, an https target_link_uri (LTI 1.3 §3.5), and a domain given as a host name without
// a protocol. The optional logo_uri, client_uri, policy_uri, tos_uri and each message's icon_uri
// are dropped unless they are https.
//
// It doesn't require the URIs to be on the tool's domains, since the spec doesn't; Review lists
// the ones that aren't for the admin to judge. Note that the spec's own examples spell the grant
// "implict", which is refused.
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
	uris := []*string{&reg.LogoURI, &reg.ClientURI, &reg.TOSURI, &reg.PolicyURI}
	for i := range reg.ToolConfiguration.Messages {
		uris = append(uris, &reg.ToolConfiguration.Messages[i].IconURI)
	}

	for _, uri := range uris {
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

	// Dynamic Registration §2.2.2: the domain is a host name, "protocol must not be included".
	if !isHostName(tool.Domain) {
		return invalidMetadata("domain must be a host name such as tool.example.com, without the protocol", nil)
	}

	for _, domain := range tool.SecondaryDomains {
		if !isHostName(domain) {
			return invalidMetadata("secondary_domains must be host names such as tool.example.com, without the protocol", nil)
		}
	}

	if !urlcheck.IsHTTPS(r.InitiateLoginURI) {
		return invalidMetadata("initiate_login_uri must be an absolute https url", nil)
	}

	if len(r.RedirectURIs) == 0 {
		return lti.NewError(lti.ErrorInvalidRedirectURI, "redirect_uris must have at least one url", nil)
	}

	// OpenID Connect Registration §2: web clients using the implicit grant register only https
	// redirect URIs and never localhost. RFC 6749 §3.1.2: no fragment.
	for _, uri := range r.RedirectURIs {
		u, ok := urlcheck.ParseHTTPS(uri)
		if !ok || u.Fragment != "" || strings.Contains(uri, "#") || strings.EqualFold(u.Hostname(), "localhost") {
			return lti.NewError(lti.ErrorInvalidRedirectURI, "redirect_uris must be https urls, without a fragment or localhost", nil)
		}
	}

	if !urlcheck.IsHTTPS(tool.TargetLinkURI) {
		return invalidMetadata("target_link_uri must be an absolute https url", nil)
	}

	for _, message := range tool.Messages {
		if message.Type == "" {
			return invalidMetadata("every message must have a type", nil)
		}

		if message.TargetLinkURI != "" && !urlcheck.IsHTTPS(message.TargetLinkURI) {
			return invalidMetadata("a message's target_link_uri must be an absolute https url", nil)
		}
	}

	return nil
}

// isHostName reports whether domain is a bare host name, with no scheme, path, port or wildcard.
func isHostName(domain string) bool {
	if domain == "" || strings.ContainsAny(domain, ":/?#@*") {
		return false
	}

	u, err := url.Parse("https://" + domain)

	return err == nil && u.Host == domain && urlcheck.IsHTTPS("https://"+domain)
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
	// RequestsName and RequestsEmail say whether the tool asks for the user's name or email address,
	// in its claims or through custom parameter substitution.
	RequestsName  bool
	RequestsEmail bool
	// PersonalDataVariables are the substitution variables about the user, such as
	// $Person.email.primary, that the tool's or its messages' custom parameters ask for.
	PersonalDataVariables []lti.Variable
	// RequestedScopes are the service scopes the tool asks for; UnsupportedScopes are the ones the
	// platform doesn't offer.
	RequestedScopes   []lti.Scope
	UnsupportedScopes []lti.Scope
	// OffDomainURIs are the login, redirect and launch URIs that aren't on the tool's domain or
	// secondary domains. The spec allows them, but they send users or tokens elsewhere.
	OffDomainURIs []string
	// PublicSuffixDomains are the domain and secondary domains that are public suffixes, such as
	// github.io. They cover sites run by others, so OnToolDomains never matches them.
	PublicSuffixDomains []string
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

	variables := r.personalDataVariables()
	scopes := r.Scopes()

	var unsupported []lti.Scope
	for _, scope := range scopes {
		if !slices.Contains(cfg.Scopes, scope) {
			unsupported = append(unsupported, scope)
		}
	}

	return RegistrationReview{
		ClientName:            name,
		ClientNames:           r.ClientNames,
		Description:           r.ToolConfiguration.Description,
		LogoURI:               r.LogoURI,
		Domains:               r.Domains(),
		Contacts:              r.Contacts,
		ClientURI:             r.ClientURI,
		TOSURI:                r.TOSURI,
		PolicyURI:             r.PolicyURI,
		Messages:              messages,
		RequestedClaims:       r.ToolConfiguration.Claims,
		RequestsName:          containsAny(r.ToolConfiguration.Claims, nameClaims) || slices.ContainsFunc(variables, isNameVariable),
		RequestsEmail:         containsAny(r.ToolConfiguration.Claims, emailClaims) || slices.ContainsFunc(variables, isEmailVariable),
		PersonalDataVariables: variables,
		RequestedScopes:       scopes,
		UnsupportedScopes:     unsupported,
		OffDomainURIs:         r.offDomainURIs(),
		PublicSuffixDomains:   r.publicSuffixDomains(),
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

// RegistrationResponse is the client information response to a registration (LTI Dynamic
// Registration 1.0 §3.6.1, RFC 7591 §3.2.1):
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

// personalDataVariables returns the $Person.* and $User.username variables in the tool's and its
// messages' custom parameters, in order and without repeats (LTI 1.3 §5.4.6).
func (r *Registration) personalDataVariables() []lti.Variable {
	params := make([]map[string]string, 0, 1+len(r.ToolConfiguration.Messages))
	params = append(params, r.ToolConfiguration.CustomParameters)

	for _, message := range r.ToolConfiguration.Messages {
		params = append(params, message.CustomParameters)
	}

	var variables []lti.Variable
	for _, custom := range params {
		for _, key := range slices.Sorted(maps.Keys(custom)) {
			variable, ok := strings.CutPrefix(custom[key], "$")
			if !ok || !isPersonalDataVariable(lti.Variable(variable)) || slices.Contains(variables, lti.Variable(variable)) {
				continue
			}

			variables = append(variables, lti.Variable(variable))
		}
	}

	return variables
}

func isPersonalDataVariable(v lti.Variable) bool {
	return strings.HasPrefix(string(v), "Person.") || v == lti.VariableUserUsername
}

func isNameVariable(v lti.Variable) bool {
	return strings.HasPrefix(string(v), "Person.name.") || v == lti.VariableUserUsername
}

func isEmailVariable(v lti.Variable) bool {
	return strings.HasPrefix(string(v), "Person.email.")
}

func (r *Registration) offDomainURIs() []string {
	uris := append([]string{r.InitiateLoginURI, r.ToolConfiguration.TargetLinkURI}, r.RedirectURIs...)
	for _, message := range r.ToolConfiguration.Messages {
		if message.TargetLinkURI != "" {
			uris = append(uris, message.TargetLinkURI)
		}
	}

	var off []string
	for _, uri := range uris {
		if !urlcheck.OnDomains(uri, r.Domains()) && !slices.Contains(off, uri) {
			off = append(off, uri)
		}
	}

	return off
}

func (r *Registration) publicSuffixDomains() []string {
	var suffixes []string
	for _, domain := range r.Domains() {
		if urlcheck.IsPublicSuffix(domain) {
			suffixes = append(suffixes, domain)
		}
	}

	return suffixes
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

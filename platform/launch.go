// Package platform implements the platform side of LTI 1.3: signing the id_token a tool is
// launched with, verifying Deep Linking responses, Dynamic Registration and the OpenID
// configuration.
package platform

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/jose"
	"github.com/meitner-se/go-lti/internal/urlcheck"
	"github.com/meitner-se/go-lti/jwks"
)

// IDTokenTTL is how long an id_token is valid. The tool redeems it within seconds of the launch.
const IDTokenTTL = 5 * time.Minute

const maxIdentifierLength = 255

// reservedClaims are set by this package and can't be overridden by an extension.
var reservedClaims = map[string]bool{
	"iss": true, "aud": true, "azp": true, "sub": true, "iat": true, "exp": true, "nonce": true,
	"name": true, "given_name": true, "family_name": true, "email": true,
	lti.ClaimMessageType: true, lti.ClaimVersion: true, lti.ClaimDeploymentID: true,
	lti.ClaimTargetLinkURI: true, lti.ClaimRoles: true, lti.ClaimContext: true,
	lti.ClaimResourceLink: true, lti.ClaimLaunchPresentation: true, lti.ClaimToolPlatform: true,
	lti.ClaimCustom: true, lti.ClaimDeepLinkingSettings: true,
}

// Option configures a Launcher or a DeepLinkingVerifier.
type Option func(*options)

type options struct {
	now func() time.Time
}

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

func newOptions(opts []Option) options {
	o := options{now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}

	return o
}

// Launcher signs the id_tokens the platform launches tools with, and publishes its keys.
type Launcher struct {
	config Config
	keys   lti.Keys
	now    func() time.Time
}

// NewLauncher returns a Launcher for the platform cfg describes, signing with keys. It fails when
// cfg is invalid.
func NewLauncher(cfg Config, keys lti.Keys, opts ...Option) (*Launcher, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if keys == nil {
		return nil, errors.New("lti: launcher needs keys")
	}

	return &Launcher{config: cfg, keys: keys, now: newOptions(opts).now}, nil
}

// JWKS returns the document to serve at Endpoints().JWKS.
func (l *Launcher) JWKS(ctx context.Context) (jwks.Set, error) {
	keys, err := l.keys.PublicKeys(ctx)
	if err != nil {
		return jwks.Set{}, fmt.Errorf("lti: cannot list public keys: %w", err)
	}

	// Security Framework §6.3: every published key needs a kid.
	for _, key := range keys {
		if key.ID == "" || key.PublicKey == nil || key.PublicKey.N == nil {
			return jwks.Set{}, errors.New("lti: a published key has no kid or no public key")
		}
	}

	return jwks.NewSet(keys...), nil
}

// idToken returns the signed id_token that launches tool with msg, answering the authentication
// request that carried nonce.
func (l *Launcher) idToken(ctx context.Context, tool Tool, nonce string, msg lti.Message) (string, error) {
	claims, err := l.idTokenClaims(tool, nonce, msg, l.now())
	if err != nil {
		return "", err
	}

	key, err := l.keys.SigningKey(ctx)
	if err != nil {
		return "", fmt.Errorf("lti: cannot get signing key: %w", err)
	}

	public, err := key.PublicKey()
	if err != nil {
		return "", err
	}

	token, err := jose.SignRS256(public.ID, key.Signer, claims)
	if err != nil {
		return "", fmt.Errorf("lti: cannot sign id_token: %w", err)
	}

	return token, nil
}

// idTokenClaims lays msg out as id_token claims (LTI 1.3 §5), issued at now. A message that is
// incomplete or breaks the spec's limits is an error: it is the caller's mistake, not the tool's.
func (l *Launcher) idTokenClaims(tool Tool, nonce string, msg lti.Message, now time.Time) (map[string]any, error) {
	if tool.ClientID == "" {
		return nil, errors.New("lti: launch needs the tool's client_id")
	}

	if nonce == "" {
		return nil, errors.New("lti: launch needs the nonce from the authentication request")
	}

	claims := map[string]any{}

	var (
		common lti.Common
		link   *lti.ResourceLink
	)

	switch m := msg.(type) {
	case *lti.ResourceLinkRequest:
		if m == nil {
			return nil, errors.New("lti: launch needs a message")
		}

		if m.ResourceLink.ID == "" || len(m.ResourceLink.ID) > maxIdentifierLength {
			return nil, errors.New("lti: resource link launch needs a resource link id of at most 255 characters")
		}

		common = m.Common
		link = &m.ResourceLink
		claims[lti.ClaimResourceLink] = m.ResourceLink
	case *lti.DeepLinkingRequest:
		if m == nil {
			return nil, errors.New("lti: launch needs a message")
		}

		settings, err := deepLinkingSettingsClaim(m.Settings, l.config.Endpoints().DeepLinkReturn)
		if err != nil {
			return nil, err
		}

		common = m.Common
		claims[lti.ClaimDeepLinkingSettings] = settings
	default:
		return nil, errors.New("lti: launch message must be a *ResourceLinkRequest or a *DeepLinkingRequest")
	}

	targetLinkURI := common.TargetLinkURI
	if targetLinkURI == "" {
		targetLinkURI = tool.TargetLinkURI
	}

	if err := validateCommon(common, targetLinkURI); err != nil {
		return nil, err
	}

	roles := common.Roles
	if roles == nil {
		roles = []lti.Role{}
	}

	claims["iss"] = l.config.Issuer
	claims["aud"] = tool.ClientID
	claims["azp"] = tool.ClientID
	claims["sub"] = common.Subject
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(IDTokenTTL).Unix()
	claims["nonce"] = nonce
	claims[lti.ClaimMessageType] = msg.MessageType()
	claims[lti.ClaimVersion] = lti.Version
	claims[lti.ClaimDeploymentID] = common.DeploymentID
	claims[lti.ClaimTargetLinkURI] = targetLinkURI
	claims[lti.ClaimRoles] = roles
	claims[lti.ClaimToolPlatform] = toolPlatformClaim(l.config.Product)

	if common.Presentation != (lti.Presentation{}) {
		claims[lti.ClaimLaunchPresentation] = common.Presentation
	}

	if common.Context != nil {
		claims[lti.ClaimContext] = *common.Context
	}

	if len(common.Custom) > 0 {
		claims[lti.ClaimCustom] = lti.Substitute(common.Custom, substitutionValues(common, link), common.Sharing)
	}

	if common.Sharing.Name {
		setIfNotEmpty(claims, "name", common.User.Name)
		setIfNotEmpty(claims, "given_name", common.User.GivenName)
		setIfNotEmpty(claims, "family_name", common.User.FamilyName)
	}

	if common.Sharing.Email {
		setIfNotEmpty(claims, "email", common.User.Email)
	}

	for _, extension := range common.Extensions {
		if extension == nil {
			return nil, errors.New("lti: an extension claim is nil")
		}

		name := extension.ClaimName()
		if !strings.Contains(name, "://") || reservedClaims[name] {
			return nil, fmt.Errorf("lti: extension claim %q must be a fully qualified url that the package doesn't set", name)
		}

		if _, ok := claims[name]; ok {
			return nil, fmt.Errorf("lti: extension claim %q is set twice", name)
		}

		claims[name] = extension
	}

	return claims, nil
}

// LaunchVariables returns the substitution variables a launch supports, for Config.Variables. Each
// takes the message's value, else the one in Common.Variables, else "" (LTI 1.3 Appendix B).
func LaunchVariables() []lti.Variable {
	return []lti.Variable{
		lti.VariableUserID,
		lti.VariablePersonNameFull, lti.VariablePersonNameGiven, lti.VariablePersonNameFamily, lti.VariablePersonEmailPrimary,
		lti.VariableContextID, lti.VariableContextTitle, lti.VariableContextLabel,
		lti.VariableResourceLinkID, lti.VariableResourceLinkTitle, lti.VariableResourceLinkDescription,
		lti.VariableMessageLocale,
	}
}

// substitutionValues returns the variable values for common's custom parameters: "" for each of
// LaunchVariables, overridden by common.Variables, overridden by the values the message carries.
// link is the resource link, if the message has one.
func substitutionValues(common lti.Common, link *lti.ResourceLink) map[lti.Variable]string {
	values := map[lti.Variable]string{}
	for _, variable := range LaunchVariables() {
		values[variable] = ""
	}

	maps.Copy(values, common.Variables)

	// An empty value is one the message doesn't carry, so it doesn't override Variables.
	set := func(variable lti.Variable, value string) {
		if value != "" {
			values[variable] = value
		}
	}

	set(lti.VariableUserID, common.Subject)
	set(lti.VariablePersonNameFull, common.User.Name)
	set(lti.VariablePersonNameGiven, common.User.GivenName)
	set(lti.VariablePersonNameFamily, common.User.FamilyName)
	set(lti.VariablePersonEmailPrimary, common.User.Email)
	set(lti.VariableMessageLocale, common.Presentation.Locale)

	if common.Context != nil {
		set(lti.VariableContextID, common.Context.ID)
		set(lti.VariableContextTitle, common.Context.Title)
		set(lti.VariableContextLabel, common.Context.Label)
	}

	if link != nil {
		set(lti.VariableResourceLinkID, link.ID)
		set(lti.VariableResourceLinkTitle, link.Title)
		set(lti.VariableResourceLinkDescription, link.Description)
	}

	return values
}

func validateCommon(c lti.Common, targetLinkURI string) error {
	switch {
	case c.DeploymentID == "" || len(c.DeploymentID) > maxIdentifierLength:
		return errors.New("lti: launch needs a deployment_id of at most 255 characters")
	case c.Subject == "" || len(c.Subject) > maxIdentifierLength:
		return errors.New("lti: launch needs a sub of at most 255 characters")
	case !urlcheck.IsHTTPS(targetLinkURI):
		return errors.New("lti: launch target_link_uri must be an absolute https url")
	case c.Context != nil && (c.Context.ID == "" || len(c.Context.ID) > maxIdentifierLength):
		return errors.New("lti: launch context needs an id of at most 255 characters")
	}

	// LTI 1.3 §5.4.4: return_url is a fully qualified https url.
	if c.Presentation.ReturnURL != "" && !urlcheck.IsHTTPS(c.Presentation.ReturnURL) {
		return errors.New("lti: launch presentation return_url must be an absolute https url")
	}

	// LTI 1.3 §5.4.4: embed is a Deep Linking target, not a launch's.
	switch c.Presentation.DocumentTarget {
	case "", lti.DocumentTargetFrame, lti.DocumentTargetIframe, lti.DocumentTargetWindow:
		return nil
	default:
		return errors.New("lti: launch document_target must be frame, iframe or window")
	}
}

//nolint:tagliatelle // LTI 1.3 §5.4.2 defines snake_case keys
type toolPlatform struct {
	GUID              string `json:"guid"`
	Name              string `json:"name,omitempty"`
	Version           string `json:"version,omitempty"`
	ProductFamilyCode string `json:"product_family_code,omitempty"`
	ContactEmail      string `json:"contact_email,omitempty"`
	URL               string `json:"url,omitempty"`
}

func toolPlatformClaim(p Product) toolPlatform {
	return toolPlatform{
		GUID:              p.GUID,
		Name:              p.Name,
		Version:           p.Version,
		ProductFamilyCode: p.FamilyCode,
		ContactEmail:      p.ContactEmail,
		URL:               p.URL,
	}
}

//nolint:tagliatelle // LTI Deep Linking 2.0 §4.4.1 defines snake_case keys
type deepLinkingSettings struct {
	DeepLinkReturnURL                 string                `json:"deep_link_return_url"`
	AcceptTypes                       []lti.ContentItemType `json:"accept_types"`
	AcceptPresentationDocumentTargets []lti.DocumentTarget  `json:"accept_presentation_document_targets"`
	AcceptMediaTypes                  string                `json:"accept_media_types,omitempty"`
	AcceptMultiple                    bool                  `json:"accept_multiple"`
	AcceptLineItem                    bool                  `json:"accept_lineitem,omitempty"`
	AutoCreate                        bool                  `json:"auto_create,omitempty"`
	Title                             string                `json:"title,omitempty"`
	Text                              string                `json:"text,omitempty"`
	Data                              string                `json:"data,omitempty"`
}

func deepLinkingSettingsClaim(s lti.DeepLinkingSettings, defaultReturnURL string) (deepLinkingSettings, error) {
	returnURL := s.ReturnURL
	if returnURL == "" {
		returnURL = defaultReturnURL
	}

	switch {
	case !urlcheck.IsHTTPS(returnURL):
		return deepLinkingSettings{}, errors.New("lti: deep linking needs a return url, an absolute https url")
	case len(s.AcceptTypes) == 0:
		return deepLinkingSettings{}, errors.New("lti: deep linking needs at least one accepted type")
	}

	// Deep Linking 2.0 §4.4.1 requires the member, but it may be empty: §4.6.2 maps Deep Linking
	// 1.0's "none" to an empty array.
	targets := s.AcceptPresentationDocumentTargets
	if targets == nil {
		targets = []lti.DocumentTarget{}
	}

	// §4.4.1 and §4.6.2: embed, iframe or window. frame is only a launch's document_target.
	for _, target := range targets {
		switch target {
		case lti.DocumentTargetEmbed, lti.DocumentTargetIframe, lti.DocumentTargetWindow:
		default:
			return deepLinkingSettings{}, errors.New("lti: deep linking document targets must be embed, iframe or window")
		}
	}

	return deepLinkingSettings{
		DeepLinkReturnURL:                 returnURL,
		AcceptTypes:                       s.AcceptTypes,
		AcceptPresentationDocumentTargets: targets,
		AcceptMediaTypes:                  strings.Join(s.AcceptMediaTypes, ","),
		AcceptMultiple:                    s.AcceptMultiple,
		AcceptLineItem:                    s.AcceptLineItem,
		AutoCreate:                        s.AutoCreate,
		Title:                             s.Title,
		Text:                              s.Text,
		Data:                              s.Data,
	}, nil
}

func setIfNotEmpty(claims map[string]any, name, value string) {
	if value != "" {
		claims[name] = value
	}
}

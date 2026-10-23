package platform

import (
	"errors"

	"github.com/meitner-se/go-lti"
)

// OpenIDConfiguration is the platform's OpenID configuration document, which Dynamic Registration
// hands to the tool (LTI Dynamic Registration 1.0 §3.4.1).
//
//nolint:tagliatelle // OpenID Connect Discovery 1.0 §3 defines snake_case keys
type OpenIDConfiguration struct {
	Issuer                                     string                `json:"issuer"`
	AuthorizationEndpoint                      string                `json:"authorization_endpoint"`
	RegistrationEndpoint                       string                `json:"registration_endpoint"`
	JWKSURI                                    string                `json:"jwks_uri"`
	TokenEndpoint                              string                `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string              `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string              `json:"token_endpoint_auth_signing_alg_values_supported"`
	ScopesSupported                            []string              `json:"scopes_supported"`
	ResponseTypesSupported                     []string              `json:"response_types_supported"`
	SubjectTypesSupported                      []string              `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string              `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                            []string              `json:"claims_supported"`
	PlatformConfiguration                      PlatformConfiguration `json:"https://purl.imsglobal.org/spec/lti-platform-configuration"`
}

// PlatformConfiguration is the LTI part of the OpenID configuration (LTI Dynamic Registration 1.0 §3.4.2).
//
//nolint:tagliatelle // LTI Dynamic Registration 1.0 defines snake_case keys
type PlatformConfiguration struct {
	ProductFamilyCode string             `json:"product_family_code"`
	Version           string             `json:"version"`
	MessagesSupported []SupportedMessage `json:"messages_supported"`
	Variables         []lti.Variable     `json:"variables,omitempty"`
}

// SupportedMessage is a message type the platform sends.
type SupportedMessage struct {
	Type lti.MessageType `json:"type"`
}

// OpenIDConfiguration returns the platform's OpenID configuration document. It fails when the
// config is invalid or has no registration or token endpoint, which Dynamic Registration requires.
func (c Config) OpenIDConfiguration() (OpenIDConfiguration, error) {
	if err := c.Validate(); err != nil {
		return OpenIDConfiguration{}, err
	}

	if c.Endpoints.Registration == "" || c.Endpoints.Token == "" {
		return OpenIDConfiguration{}, errors.New("lti: the openid configuration needs registration and token endpoints")
	}

	scopes := []string{"openid"}
	for _, scope := range c.Scopes {
		scopes = append(scopes, string(scope))
	}

	return OpenIDConfiguration{
		Issuer:                            c.Issuer,
		AuthorizationEndpoint:             c.Endpoints.Authorization,
		RegistrationEndpoint:              c.Endpoints.Registration,
		JWKSURI:                           c.Endpoints.JWKS,
		TokenEndpoint:                     c.Endpoints.Token,
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  scopes,
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ClaimsSupported:                  []string{"iss", "sub", "aud", "azp", "iat", "exp", "nonce", "name", "given_name", "family_name", "email"},
		PlatformConfiguration: PlatformConfiguration{
			ProductFamilyCode: c.Product.FamilyCode,
			Version:           c.Product.Version,
			MessagesSupported: []SupportedMessage{
				{Type: lti.MessageTypeResourceLinkRequest},
				{Type: lti.MessageTypeDeepLinkingRequest},
			},
			Variables: c.Variables,
		},
	}, nil
}

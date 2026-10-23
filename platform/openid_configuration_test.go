package platform

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
)

// ============================================================================
// Tests
// ============================================================================

func TestConfig_OpenIDConfiguration(t *testing.T) {
	t.Parallel()

	configuration, err := createTestConfig().OpenIDConfiguration()
	require.NoError(t, err)

	body, _ := json.Marshal(configuration)

	assert.JSONEq(t, `{
		"issuer": "https://platform.example.com/lti",
		"authorization_endpoint": "https://platform.example.com/lti/authorize",
		"registration_endpoint": "https://platform.example.com/lti/register",
		"jwks_uri": "https://platform.example.com/lti/jwks",
		"token_endpoint": "https://platform.example.com/oauth/token",
		"token_endpoint_auth_methods_supported": ["private_key_jwt"],
		"token_endpoint_auth_signing_alg_values_supported": ["RS256"],
		"scopes_supported": ["openid"],
		"response_types_supported": ["id_token"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["RS256"],
		"claims_supported": ["iss", "sub", "aud", "azp", "iat", "exp", "nonce", "name", "given_name", "family_name", "email"],
		"https://purl.imsglobal.org/spec/lti-platform-configuration": {
			"product_family_code": "example",
			"version": "1.0.0",
			"messages_supported": [
				{"type": "LtiResourceLinkRequest"},
				{"type": "LtiDeepLinkingRequest"}
			]
		}
	}`, string(body))
}

func TestConfig_OpenIDConfiguration_AdvertisesScopesAndVariables(t *testing.T) {
	t.Parallel()

	cfg := createTestConfig()
	cfg.Scopes = []lti.Scope{lti.ScopeAGSScore}
	cfg.Variables = []lti.Variable{lti.VariableContextID, lti.VariableResourceLinkID}

	configuration, err := cfg.OpenIDConfiguration()
	require.NoError(t, err)

	assert.Equal(t, []string{"openid", "https://purl.imsglobal.org/spec/lti-ags/scope/score"}, configuration.ScopesSupported)
	assert.Equal(t, []lti.Variable{"Context.id", "ResourceLink.id"}, configuration.PlatformConfiguration.Variables)
}

func TestConfig_OpenIDConfiguration_Rejects(t *testing.T) {
	t.Parallel()

	for _, change := range []func(cfg *Config){
		func(cfg *Config) { cfg.Issuer = "" },
		func(cfg *Config) { cfg.Endpoints.Registration = "" },
		func(cfg *Config) { cfg.Endpoints.Token = "" },
		func(cfg *Config) { cfg.Product.FamilyCode = "" },
		func(cfg *Config) { cfg.Product.Version = "" },
	} {
		cfg := createTestConfig()
		change(&cfg)

		_, err := cfg.OpenIDConfiguration()
		require.Error(t, err)
	}
}

package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Tests
// ============================================================================

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	require.NoError(t, createTestConfig().Validate())

	tests := []struct {
		name   string
		change func(cfg *Config)
	}{
		{name: "no issuer", change: func(cfg *Config) { cfg.Issuer = "" }},
		{name: "an http issuer", change: func(cfg *Config) { cfg.Issuer = "http://platform.example.com/lti" }},
		{name: "an http token endpoint", change: func(cfg *Config) { cfg.TokenEndpoint = "http://platform.example.com/oauth/token" }},
		{name: "a relative token endpoint", change: func(cfg *Config) { cfg.TokenEndpoint = "/oauth/token" }},
		{name: "no product guid", change: func(cfg *Config) { cfg.Product.GUID = "" }},
		{name: "a product guid over 255 characters", change: func(cfg *Config) { cfg.Product.GUID = string(make([]byte, 256)) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := createTestConfig()
			tt.change(&cfg)

			require.Error(t, cfg.Validate())
		})
	}
}

func TestConfig_Validate_TokenEndpointIsOptional(t *testing.T) {
	t.Parallel()

	cfg := createTestConfig()
	cfg.TokenEndpoint = ""

	require.NoError(t, cfg.Validate())
}

func TestConfig_Endpoints(t *testing.T) {
	t.Parallel()

	for _, issuer := range []string{"https://platform.example.com/lti", "https://platform.example.com/lti/"} {
		cfg := createTestConfig()
		cfg.Issuer = issuer

		assert.Equal(t, Endpoints{
			OpenIDConfiguration: "https://platform.example.com/lti/.well-known/openid-configuration",
			Authorization:       "https://platform.example.com/lti/authorize",
			JWKS:                "https://platform.example.com/lti/jwks",
			Registration:        "https://platform.example.com/lti/register",
			Token:               "https://platform.example.com/oauth/token",
			DeepLinkReturn:      "https://platform.example.com/lti/deep-link-return",
		}, cfg.Endpoints(), issuer)
	}
}

func TestRegression_IssuerHasNoQueryOrFragment(t *testing.T) {
	t.Parallel()

	for _, issuer := range []string{"https://platform.example.com/lti?x=1", "https://platform.example.com/lti#frag", "https://platform.example.com/lti?"} {
		cfg := createTestConfig()
		cfg.Issuer = issuer

		require.Error(t, cfg.Validate(), issuer)
	}
}

package platform

import (
	"testing"

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
		{name: "no authorization endpoint", change: func(cfg *Config) { cfg.Endpoints.Authorization = "" }},
		{name: "no jwks endpoint", change: func(cfg *Config) { cfg.Endpoints.JWKS = "" }},
		{name: "an http token endpoint", change: func(cfg *Config) { cfg.Endpoints.Token = "http://platform.example.com/oauth/token" }},
		{name: "a relative deep link return", change: func(cfg *Config) { cfg.Endpoints.DeepLinkReturn = "/lti/deep-link-return" }},
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

func TestConfig_Validate_OptionalEndpoints(t *testing.T) {
	t.Parallel()

	cfg := createTestConfig()
	cfg.Endpoints.Registration = ""
	cfg.Endpoints.Token = ""
	cfg.Endpoints.DeepLinkReturn = ""

	require.NoError(t, cfg.Validate())
}

func TestRegression_IssuerHasNoQueryOrFragment(t *testing.T) {
	t.Parallel()

	for _, issuer := range []string{"https://platform.example.com/lti?x=1", "https://platform.example.com/lti#frag", "https://platform.example.com/lti?"} {
		cfg := createTestConfig()
		cfg.Issuer = issuer

		require.Error(t, cfg.Validate(), issuer)
	}
}

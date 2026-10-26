package platform

import (
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/ltitest"
)

// ============================================================================
// Test helper functions
// ============================================================================

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type registrationVector struct {
	Description      string          `json:"description"`
	Request          json.RawMessage `json:"request"`
	Valid            bool            `json:"valid"`
	ErrorCode        lti.ErrorCode   `json:"error_code"`
	ErrorDescription string          `json:"error_description"`
	Expect           struct {
		Domains             []string          `json:"domains"`
		RequestsName        bool              `json:"requests_name"`
		RequestsEmail       bool              `json:"requests_email"`
		ClientNames         map[string]string `json:"client_names"`
		OffDomainURIs       []string          `json:"off_domain_uris"`
		PublicSuffixDomains []string          `json:"public_suffix_domains"`
	} `json:"expect"`
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type deepLinkingVector struct {
	Description string `json:"description"`
	Session     struct {
		AcceptTypes    []lti.ContentItemType `json:"accept_types"`
		AcceptMultiple bool                  `json:"accept_multiple"`
		Data           string                `json:"data"`
	} `json:"session"`
	PlatformIssuer   string         `json:"platform_issuer"`
	ClientID         string         `json:"client_id"`
	DeploymentID     string         `json:"deployment_id"`
	Claims           map[string]any `json:"claims"`
	IATOffsetSeconds *int64         `json:"iat_offset_seconds"`
	EXPOffsetSeconds *int64         `json:"exp_offset_seconds"`
	Valid            bool           `json:"valid"`
	Items            int            `json:"items"`
	ErrorCode        lti.ErrorCode  `json:"error_code"`
	ErrorDescription string         `json:"error_description"`
}

func loadVectors[T any](tb testing.TB, kind string) map[string]T {
	tb.Helper()

	fsys := os.DirFS(filepath.Join("..", "testdata", "vectors", kind))

	names, err := fs.Glob(fsys, "*.json")
	require.NoError(tb, err)
	require.NotEmpty(tb, names)

	vectors := map[string]T{}
	for _, name := range names {
		body, err := fs.ReadFile(fsys, name)
		require.NoError(tb, err)

		var v T
		require.NoError(tb, json.Unmarshal(body, &v))

		vectors[name] = v
	}

	return vectors
}

// ============================================================================
// Tests
// ============================================================================

func TestParseRegistration_Vectors(t *testing.T) {
	t.Parallel()

	for name, v := range loadVectors[registrationVector](t, "registration") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reg, err := ParseRegistration(v.Request)
			if !v.Valid {
				requireRegistrationRejection(t, err, v.ErrorCode, v.ErrorDescription)

				return
			}

			require.NoError(t, err, v.Description)

			review := reg.Review(createTestConfig())
			assert.Equal(t, v.Expect.Domains, review.Domains)
			assert.Equal(t, v.Expect.RequestsName, review.RequestsName)
			assert.Equal(t, v.Expect.RequestsEmail, review.RequestsEmail)
			assert.Equal(t, v.Expect.ClientNames, review.ClientNames)
			assert.ElementsMatch(t, v.Expect.OffDomainURIs, review.OffDomainURIs)
			assert.ElementsMatch(t, v.Expect.PublicSuffixDomains, review.PublicSuffixDomains)
		})
	}
}

func TestDeepLinkingVerifier_Verify_Vectors(t *testing.T) {
	t.Parallel()

	tool := ltitest.NewSigningKey(t)
	server := ltitest.NewJWKSServer(t, tool)
	now := time.Now()
	fetcher := newTestFetcher(t, server.Client())

	for name, v := range loadVectors[deepLinkingVector](t, "deep_linking") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := createTestConfig()
			session := DeepLinkingSession{
				Tool:         Tool{ClientID: "client-1", JWKSURI: server.URL, Domains: []string{"tool.example.com"}},
				DeploymentID: "deployment-1",
				Settings: lti.DeepLinkingSettings{
					AcceptTypes:    v.Session.AcceptTypes,
					AcceptMultiple: v.Session.AcceptMultiple,
					Data:           v.Session.Data,
				},
			}

			// A vector taken from the spec carries the spec's own identifiers.
			if v.PlatformIssuer != "" {
				cfg.Issuer = v.PlatformIssuer
				session.Tool.ClientID = v.ClientID
				session.DeploymentID = v.DeploymentID
			}

			verifier, err := NewDeepLinkingVerifier(cfg, fetcher, ltitest.NewNonceStore(t), WithClock(func() time.Time { return now }))
			require.NoError(t, err)

			claims := v.Claims
			if v.IATOffsetSeconds != nil {
				claims["iat"] = now.Unix() + *v.IATOffsetSeconds
			}

			if v.EXPOffsetSeconds != nil {
				claims["exp"] = now.Unix() + *v.EXPOffsetSeconds
			}

			response, err := verifier.Verify(t.Context(), ltitest.Sign(t, tool, claims), session)
			if !v.Valid {
				require.Error(t, err, v.Description)

				rejection, ok := lti.AsError(err)
				require.True(t, ok, v.Description)
				assert.Equal(t, v.ErrorCode, rejection.Code)
				assert.Contains(t, rejection.Description, v.ErrorDescription, "the vector must fail for its own reason")

				return
			}

			require.NoError(t, err, v.Description)
			assert.Len(t, response.Items, v.Items)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type authenticationRequestVector struct {
	Description      string        `json:"description"`
	Form             url.Values    `json:"form"`
	Valid            bool          `json:"valid"`
	ErrorCode        lti.ErrorCode `json:"error_code"`
	ErrorDescription string        `json:"error_description"`
}

func TestParseAuthenticationRequest_Vectors(t *testing.T) {
	t.Parallel()

	for name, v := range loadVectors[authenticationRequestVector](t, "authentication_request") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseAuthenticationRequest(v.Form)
			if v.Valid {
				require.NoError(t, err, v.Description)

				return
			}

			rejection, ok := lti.AsError(err)
			require.True(t, ok, v.Description)
			assert.Equal(t, v.ErrorCode, rejection.Code, v.Description)
			assert.Contains(t, rejection.Description, v.ErrorDescription, "the vector must fail for its own reason")
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type substitutionVector struct {
	Description  string             `json:"description"`
	MessageType  lti.MessageType    `json:"message_type"`
	Subject      string             `json:"sub"`
	Context      *lti.LaunchContext `json:"context"`
	ResourceLink lti.ResourceLink   `json:"resource_link"`
	Locale       string             `json:"locale"`
	User         struct {
		Name       string `json:"name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
		Email      string `json:"email"`
	} `json:"user"`
	Sharing struct {
		Name  bool `json:"name"`
		Email bool `json:"email"`
	} `json:"sharing"`
	Variables    map[lti.Variable]string `json:"variables"`
	Custom       map[string]string       `json:"custom"`
	ExpectCustom map[string]string       `json:"expect_custom"`
}

func TestLauncher_SubstitutesCustom_Vectors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for name, v := range loadVectors[substitutionVector](t, "substitution") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			common := lti.Common{
				DeploymentID: "deployment-1",
				Subject:      v.Subject,
				Context:      v.Context,
				Presentation: lti.Presentation{Locale: v.Locale},
				Custom:       v.Custom,
				Variables:    v.Variables,
				User:         lti.User(v.User),
				Sharing:      lti.Sharing(v.Sharing),
			}

			var msg lti.Message

			switch v.MessageType {
			case lti.MessageTypeResourceLinkRequest:
				msg = &lti.ResourceLinkRequest{Common: common, ResourceLink: v.ResourceLink}
			case lti.MessageTypeDeepLinkingRequest:
				msg = &lti.DeepLinkingRequest{Common: common, Settings: createTestDeepLinkingSettings()}
			default:
				t.Fatalf("unknown message_type %q", v.MessageType)
			}

			claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
			require.NoError(t, err, v.Description)
			assert.Equal(t, v.ExpectCustom, claims[lti.ClaimCustom], v.Description)
		})
	}
}

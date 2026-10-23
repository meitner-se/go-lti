package platform

import (
	"encoding/json"
	"io/fs"
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
	Description string          `json:"description"`
	Request     json.RawMessage `json:"request"`
	Valid       bool            `json:"valid"`
	ErrorCode   lti.ErrorCode   `json:"error_code"`
	Expect      struct {
		Domains       []string          `json:"domains"`
		RequestsName  bool              `json:"requests_name"`
		RequestsEmail bool              `json:"requests_email"`
		ClientNames   map[string]string `json:"client_names"`
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
	Claims           map[string]any `json:"claims"`
	IATOffsetSeconds *int64         `json:"iat_offset_seconds"`
	EXPOffsetSeconds *int64         `json:"exp_offset_seconds"`
	Valid            bool           `json:"valid"`
	Items            int            `json:"items"`
	ErrorCode        lti.ErrorCode  `json:"error_code"`
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
				requireRegistrationRejection(t, err, v.ErrorCode, "")

				return
			}

			require.NoError(t, err, v.Description)

			review := reg.Review(createTestConfig())
			assert.Equal(t, v.Expect.Domains, review.Domains)
			assert.Equal(t, v.Expect.RequestsName, review.RequestsName)
			assert.Equal(t, v.Expect.RequestsEmail, review.RequestsEmail)
			assert.Equal(t, v.Expect.ClientNames, review.ClientNames)
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

			verifier, err := NewDeepLinkingVerifier(createTestConfig(), fetcher, ltitest.NewNonceStore(), WithClock(func() time.Time { return now }))
			require.NoError(t, err)

			claims := v.Claims
			if v.IATOffsetSeconds != nil {
				claims["iat"] = now.Unix() + *v.IATOffsetSeconds
			}

			if v.EXPOffsetSeconds != nil {
				claims["exp"] = now.Unix() + *v.EXPOffsetSeconds
			}

			session := DeepLinkingSession{
				Tool: Tool{
					ClientID: "client-1",
					JWKSURI:  server.URL,
					Domains:  []string{"tool.example.com"},
				},
				DeploymentID: "deployment-1",
				Settings: lti.DeepLinkingSettings{
					AcceptTypes:    v.Session.AcceptTypes,
					AcceptMultiple: v.Session.AcceptMultiple,
					Data:           v.Session.Data,
				},
			}

			response, err := verifier.Verify(t.Context(), ltitest.Sign(t, tool, claims), session)
			if !v.Valid {
				require.Error(t, err, v.Description)

				rejection, ok := lti.AsError(err)
				require.True(t, ok, v.Description)
				assert.Equal(t, v.ErrorCode, rejection.Code)

				return
			}

			require.NoError(t, err, v.Description)
			assert.Len(t, response.Items, v.Items)
		})
	}
}

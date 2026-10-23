package platform

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/jwks"
	"github.com/meitner-se/go-lti/ltitest"
)

// ============================================================================
// Test helper functions
// ============================================================================

func createTestDeepLinkingSession() DeepLinkingSession {
	return DeepLinkingSession{
		Tool:         createTestTool(),
		DeploymentID: "deployment-1",
		Settings:     createTestDeepLinkingSettings(),
	}
}

func createTestDeepLinkingResponseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":   "client-1",
		"aud":   "https://platform.example.com/lti",
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"nonce": "tool-nonce-1",
		"https://purl.imsglobal.org/spec/lti/claim/message_type":  "LtiDeepLinkingResponse",
		"https://purl.imsglobal.org/spec/lti/claim/version":       "1.3.0",
		"https://purl.imsglobal.org/spec/lti/claim/deployment_id": "deployment-1",
		"https://purl.imsglobal.org/spec/lti-dl/claim/data":       "request-1",
		"https://purl.imsglobal.org/spec/lti-dl/claim/msg":        "Added 1 item",
		"https://purl.imsglobal.org/spec/lti-dl/claim/content_items": []any{
			map[string]any{
				"type":      "ltiResourceLink",
				"title":     "Cell quiz",
				"url":       "https://tool.example.com/launch/quiz-1",
				"thumbnail": map[string]any{"url": "https://cdn.example.net/quiz-1.png", "width": 90, "height": 90},
				"iframe":    map[string]any{"width": 800, "height": 600},
				"custom":    map[string]any{"quiz_id": "quiz-1"},
				"lineItem":  map[string]any{"scoreMaximum": 10},
			},
		},
	}
}

func setContentItems(claims map[string]any, items ...map[string]any) {
	list := make([]any, 0, len(items))
	for _, item := range items {
		list = append(list, item)
	}

	claims["https://purl.imsglobal.org/spec/lti-dl/claim/content_items"] = list
}

var allContentItemTypes = []lti.ContentItemType{
	lti.ContentItemTypeLTIResourceLink, lti.ContentItemTypeLink, lti.ContentItemTypeFile, lti.ContentItemTypeImage, lti.ContentItemTypeHTML,
}

type deepLinkingTestSetup struct {
	verifier *DeepLinkingVerifier
	tool     lti.SigningKey
	nonces   *ltitest.NonceStore
	now      time.Time
}

func createTestDeepLinkingSetup(t *testing.T) deepLinkingTestSetup {
	t.Helper()

	tool := ltitest.NewSigningKey(t)
	toolKey := ltitest.PublicKey(t, tool)
	now := time.Now()
	nonces := ltitest.NewNonceStore()

	keys := &mockKeySource{KeyFunc: func(_ context.Context, jwksURI, kid string) (*rsa.PublicKey, error) {
		if jwksURI != "https://tool.example.com/jwks" || kid != toolKey.ID {
			return nil, jwks.ErrKeyNotFound
		}

		return toolKey.PublicKey, nil
	}}

	verifier, err := NewDeepLinkingVerifier(createTestConfig(), keys, nonces, WithClock(func() time.Time { return now }))
	require.NoError(t, err)

	return deepLinkingTestSetup{verifier: verifier, tool: tool, nonces: nonces, now: now}
}

func (s deepLinkingTestSetup) sign(t *testing.T, claims map[string]any) string {
	t.Helper()

	return ltitest.Sign(t, s.tool, claims)
}

func requireRejection(t *testing.T, err error, message string) {
	t.Helper()

	require.Error(t, err)

	rejection, ok := lti.AsError(err)
	require.True(t, ok, "want an *lti.Error, got %v", err)
	assert.Equal(t, lti.ErrorInvalidRequest, rejection.Code)
	assert.Contains(t, rejection.Description, message)
}

// ============================================================================
// Tests
// ============================================================================

func TestNewDeepLinkingVerifier_Rejects(t *testing.T) {
	t.Parallel()

	keys := &mockKeySource{}
	nonces := ltitest.NewNonceStore()

	_, err := NewDeepLinkingVerifier(Config{}, keys, nonces)
	require.Error(t, err)

	_, err = NewDeepLinkingVerifier(createTestConfig(), nil, nonces)
	require.Error(t, err)

	_, err = NewDeepLinkingVerifier(createTestConfig(), keys, nil)
	require.Error(t, err)
}

func TestDeepLinkingVerifier_Verify_AcceptsAValidResponse(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	raw := setup.sign(t, createTestDeepLinkingResponseClaims(setup.now))

	response, err := setup.verifier.Verify(t.Context(), raw, createTestDeepLinkingSession())
	require.NoError(t, err)

	require.Len(t, response.Items, 1)
	item := response.Items[0]
	assert.Equal(t, lti.ContentItemTypeLTIResourceLink, item.Type)
	assert.Equal(t, "Cell quiz", item.Title)
	assert.Equal(t, "https://tool.example.com/launch/quiz-1", item.URL)
	assert.Equal(t, &lti.Image{URL: "https://cdn.example.net/quiz-1.png", Width: 90, Height: 90}, item.Thumbnail)
	assert.Equal(t, &lti.Iframe{Width: 800, Height: 600}, item.Iframe)
	assert.Equal(t, map[string]string{"quiz_id": "quiz-1"}, item.Custom)
	assert.JSONEq(t, `{"scoreMaximum":10}`, string(item.LineItem))
	assert.Contains(t, string(item.Raw), `"title":"Cell quiz"`)
	assert.Equal(t, "Added 1 item", response.Message)
	assert.Equal(t, 1, setup.nonces.Len())
}

func TestDeepLinkingVerifier_Verify_AcceptsACancelledPick(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	claims := createTestDeepLinkingResponseClaims(setup.now)
	delete(claims, "https://purl.imsglobal.org/spec/lti-dl/claim/content_items")

	response, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), createTestDeepLinkingSession())
	require.NoError(t, err)

	assert.Empty(t, response.Items)
}

func TestDeepLinkingVerifier_Verify_AcceptsMultipleItemsWhenAllowed(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	claims := createTestDeepLinkingResponseClaims(setup.now)
	setContentItems(claims,
		map[string]any{"type": "ltiResourceLink", "url": "https://tool.example.com/a"},
		map[string]any{"type": "ltiResourceLink", "url": "https://sub.tool.example.com/b"},
	)

	session := createTestDeepLinkingSession()
	session.Settings.AcceptMultiple = true

	response, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), session)
	require.NoError(t, err)

	assert.Len(t, response.Items, 2)
}

func TestDeepLinkingVerifier_Verify_AcceptsEveryItemTypeWithWhatItRequires(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	claims := createTestDeepLinkingResponseClaims(setup.now)
	setContentItems(claims,
		map[string]any{"type": "ltiResourceLink"},
		map[string]any{"type": "link", "url": "https://tool.example.com/article", "window": map[string]any{"targetName": "_blank"}},
		map[string]any{"type": "file", "url": "https://cdn.example.net/worksheet.pdf", "mediaType": "application/pdf"},
		map[string]any{"type": "image", "url": "https://cdn.example.net/diagram.png"},
		map[string]any{"type": "html", "html": "<p>Hello</p>"},
	)

	session := createTestDeepLinkingSession()
	session.Settings.AcceptMultiple = true
	session.Settings.AcceptTypes = allContentItemTypes

	response, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), session)
	require.NoError(t, err)

	require.Len(t, response.Items, 5)
	assert.Equal(t, "application/pdf", response.Items[2].MediaType)
	assert.Equal(t, "<p>Hello</p>", response.Items[4].HTML)
}

func TestDeepLinkingVerifier_Verify_Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		claims  func(c map[string]any, now time.Time)
		session func(s *DeepLinkingSession)
		message string
	}{
		{
			name:    "the wrong iss",
			claims:  func(c map[string]any, _ time.Time) { c["iss"] = "client-2" },
			message: "not a valid jwt",
		},
		{
			name:    "the wrong aud",
			claims:  func(c map[string]any, _ time.Time) { c["aud"] = "https://other-platform.example.com" },
			message: "not a valid jwt",
		},
		{
			name:    "an expired token",
			claims:  func(c map[string]any, now time.Time) { c["exp"] = now.Add(-2 * time.Minute).Unix() },
			message: "not a valid jwt",
		},
		{
			name:    "no exp",
			claims:  func(c map[string]any, _ time.Time) { delete(c, "exp") },
			message: "not a valid jwt",
		},
		{
			name:    "an iat in the future",
			claims:  func(c map[string]any, now time.Time) { c["iat"] = now.Add(10 * time.Minute).Unix() },
			message: "not a valid jwt",
		},
		{
			name:    "no iat",
			claims:  func(c map[string]any, _ time.Time) { delete(c, "iat") },
			message: "has no iat",
		},
		{
			name:    "an exp more than an hour away",
			claims:  func(c map[string]any, now time.Time) { c["exp"] = now.Add(2 * time.Hour).Unix() },
			message: "more than an hour",
		},
		{
			name: "an old response with a fresh exp",
			claims: func(c map[string]any, now time.Time) {
				c["iat"] = now.Add(-90 * 24 * time.Hour).Unix()
				c["exp"] = now.Add(5 * time.Minute).Unix()
			},
			message: "more than an hour",
		},
		{
			name:    "the wrong message type",
			claims:  func(c map[string]any, _ time.Time) { c[lti.ClaimMessageType] = "LtiResourceLinkRequest" },
			message: "wrong message_type",
		},
		{
			name:    "the wrong lti version",
			claims:  func(c map[string]any, _ time.Time) { c[lti.ClaimVersion] = "1.1" },
			message: "wrong lti version",
		},
		{
			name:    "the wrong deployment_id",
			claims:  func(c map[string]any, _ time.Time) { c[lti.ClaimDeploymentID] = "deployment-2" },
			message: "wrong deployment_id",
		},
		{
			name:    "no deployment_id",
			claims:  func(c map[string]any, _ time.Time) { delete(c, lti.ClaimDeploymentID) },
			message: "wrong deployment_id",
		},
		{
			name:    "changed data",
			claims:  func(c map[string]any, _ time.Time) { c[lti.ClaimDeepLinkingData] = "request-2" },
			message: "data does not match",
		},
		{
			name:    "missing data",
			claims:  func(c map[string]any, _ time.Time) { delete(c, lti.ClaimDeepLinkingData) },
			message: "data does not match",
		},
		{
			name:    "data the request didn't send",
			claims:  func(c map[string]any, _ time.Time) { c[lti.ClaimDeepLinkingData] = "injected" },
			session: func(s *DeepLinkingSession) { s.Settings.Data = "" },
			message: "data does not match",
		},
		{
			name: "two items when the request accepted one",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c,
					map[string]any{"type": "ltiResourceLink", "url": "https://tool.example.com/a"},
					map[string]any{"type": "ltiResourceLink", "url": "https://tool.example.com/b"},
				)
			},
			message: "more than one item",
		},
		{
			name: "an item type the request didn't accept",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "html", "html": "<script>alert(1)</script>"})
			},
			message: "type the request didn't accept",
		},
		{
			name: "an item url on another domain",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "ltiResourceLink", "url": "https://evil.example.org/launch"})
			},
			message: "url that isn't https on the tool's domain",
		},
		{
			name: "an item url on a look-alike domain",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "ltiResourceLink", "url": "https://eviltool.example.com/launch"})
			},
			message: "url that isn't https on the tool's domain",
		},
		{
			name: "an http item url",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "ltiResourceLink", "url": "http://tool.example.com/launch"})
			},
			message: "url that isn't https on the tool's domain",
		},
		{
			name: "an icon on another domain",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "ltiResourceLink", "icon": map[string]any{"url": "https://tracker.example.org/pixel.png"}})
			},
			message: "url that isn't https on the tool's domain",
		},
		{
			name: "an iframe src on another domain",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "ltiResourceLink", "iframe": map[string]any{"src": "https://evil.example.org/"}})
			},
			message: "url that isn't https on the tool's domain",
		},
		{
			name: "a malformed item",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "ltiResourceLink", "custom": map[string]any{"nested": map[string]any{}}})
			},
			message: "malformed content item",
		},
		{
			name: "a link without a url",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "link", "title": "Article"})
			},
			session: func(s *DeepLinkingSession) { s.Settings.AcceptTypes = allContentItemTypes },
			message: "without a url",
		},
		{
			name: "a file without a url",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "file", "title": "Worksheet"})
			},
			session: func(s *DeepLinkingSession) { s.Settings.AcceptTypes = allContentItemTypes },
			message: "without a url",
		},
		{
			name: "an image without a url",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "image", "title": "Diagram"})
			},
			session: func(s *DeepLinkingSession) { s.Settings.AcceptTypes = allContentItemTypes },
			message: "without a url",
		},
		{
			name: "an html item without html",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "html", "title": "Snippet"})
			},
			session: func(s *DeepLinkingSession) { s.Settings.AcceptTypes = allContentItemTypes },
			message: "without html",
		},
		{
			name: "an item url under a public suffix the tool registered",
			claims: func(c map[string]any, _ time.Time) {
				setContentItems(c, map[string]any{"type": "ltiResourceLink", "url": "https://someone-else.github.io/launch"})
			},
			session: func(s *DeepLinkingSession) { s.Tool.Domains = []string{"tool.example.com", "github.io"} },
			message: "url that isn't https on the tool's domain",
		},
		{
			name:    "no nonce",
			claims:  func(c map[string]any, _ time.Time) { delete(c, "nonce") },
			message: "has no nonce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			setup := createTestDeepLinkingSetup(t)
			claims := createTestDeepLinkingResponseClaims(setup.now)
			tt.claims(claims, setup.now)

			session := createTestDeepLinkingSession()
			if tt.session != nil {
				tt.session(&session)
			}

			_, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), session)
			requireRejection(t, err, tt.message)
			assert.Zero(t, setup.nonces.Len(), "a rejected response must not use up its nonce")
		})
	}
}

func TestDeepLinkingVerifier_Verify_RejectsAReplayedResponse(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	raw := setup.sign(t, createTestDeepLinkingResponseClaims(setup.now))

	_, err := setup.verifier.Verify(t.Context(), raw, createTestDeepLinkingSession())
	require.NoError(t, err)

	_, err = setup.verifier.Verify(t.Context(), raw, createTestDeepLinkingSession())
	requireRejection(t, err, "nonce was already used")
}

func TestDeepLinkingVerifier_Verify_FailsWhenTheNonceStoreFails(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	nonces := &mockNonceStore{ClaimFunc: func(context.Context, string, string, time.Time) (bool, error) {
		return false, errors.New("store unavailable")
	}}

	verifier, err := NewDeepLinkingVerifier(createTestConfig(), setup.verifier.keys, nonces, WithClock(func() time.Time { return setup.now }))
	require.NoError(t, err)

	_, err = verifier.Verify(t.Context(), setup.sign(t, createTestDeepLinkingResponseClaims(setup.now)), createTestDeepLinkingSession())
	require.Error(t, err)

	_, isRejection := lti.AsError(err)
	assert.False(t, isRejection, "a store failure is the platform's error, not the tool's")
}

func TestDeepLinkingVerifier_Verify_FailsWhenTheToolsKeysCantBeFetched(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	keys := &mockKeySource{KeyFunc: func(context.Context, string, string) (*rsa.PublicKey, error) {
		return nil, errors.New("jwks returned status 503")
	}}

	verifier, err := NewDeepLinkingVerifier(createTestConfig(), keys, setup.nonces)
	require.NoError(t, err)

	_, err = verifier.Verify(t.Context(), setup.sign(t, createTestDeepLinkingResponseClaims(time.Now())), createTestDeepLinkingSession())
	require.Error(t, err)

	_, isRejection := lti.AsError(err)
	assert.False(t, isRejection, "an unreachable jwks is the platform's error, not the tool's")
}

func TestDeepLinkingVerifier_Verify_RejectsBadSignatures(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	claims := createTestDeepLinkingResponseClaims(setup.now)

	// Signed by a key the tool doesn't publish.
	unknownKid := ltitest.Sign(t, ltitest.NewSigningKey(t), claims)

	hmac := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	hmac.Header["kid"] = setup.tool.ID
	hmacSigned, err := hmac.SignedString([]byte("secret"))
	require.NoError(t, err)

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(claims))
	unsigned.Header["kid"] = setup.tool.ID
	unsignedRaw, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	rs512 := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims(claims))
	rs512.Header["kid"] = setup.tool.ID
	rs512Signed, err := rs512.SignedString(setup.tool.Signer)
	require.NoError(t, err)

	valid := setup.sign(t, claims)
	tampered := valid[:len(valid)-4] + "AAAA"

	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "not a jwt", raw: "not-a-jwt"},
		{name: "a key the tool doesn't publish", raw: unknownKid},
		{name: "a tampered signature", raw: tampered},
		{name: "hs256", raw: hmacSigned},
		{name: "alg none", raw: unsignedRaw},
		{name: "rs512 with the tool's own key", raw: rs512Signed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := setup.verifier.Verify(t.Context(), tt.raw, createTestDeepLinkingSession())
			requireRejection(t, err, "deep linking response")
			assert.Zero(t, setup.nonces.Len())
		})
	}
}

func TestDeepLinkingVerifier_Verify_FailsClosedOnAnIncompleteSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		session func(s *DeepLinkingSession)
	}{
		{name: "no client_id", session: func(s *DeepLinkingSession) { s.Tool.ClientID = "" }},
		{name: "no deployment_id", session: func(s *DeepLinkingSession) { s.DeploymentID = "" }},
		{name: "no jwks uri", session: func(s *DeepLinkingSession) { s.Tool.JWKSURI = "" }},
		{name: "no domains", session: func(s *DeepLinkingSession) { s.Tool.Domains = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			setup := createTestDeepLinkingSetup(t)
			claims := createTestDeepLinkingResponseClaims(setup.now)
			claims["iss"] = ""
			claims[lti.ClaimDeploymentID] = ""

			session := createTestDeepLinkingSession()
			tt.session(&session)

			_, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), session)
			require.Error(t, err)
			assert.Zero(t, setup.nonces.Len())
		})
	}
}

func TestDeepLinkingVerifier_Verify_FetchesTheToolsJWKS(t *testing.T) {
	t.Parallel()

	tool := ltitest.NewSigningKey(t)
	server := ltitest.NewJWKSServer(t, tool)
	now := time.Now()

	verifier, err := NewDeepLinkingVerifier(
		createTestConfig(),
		newTestFetcher(t, server.Client()),
		ltitest.NewNonceStore(),
		WithClock(func() time.Time { return now }),
	)
	require.NoError(t, err)

	session := createTestDeepLinkingSession()
	session.Tool.JWKSURI = server.URL

	response, err := verifier.Verify(t.Context(), ltitest.Sign(t, tool, createTestDeepLinkingResponseClaims(now)), session)
	require.NoError(t, err)
	assert.Len(t, response.Items, 1)
}

func TestContentItem_JSONKeepsSpecNames(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(lti.ContentItem{Type: lti.ContentItemTypeLink, URL: "https://tool.example.com", Window: &lti.Window{TargetName: "_blank"}})
	require.NoError(t, err)

	assert.JSONEq(t, `{"type":"link","url":"https://tool.example.com","window":{"targetName":"_blank"}}`, string(body))
}

// ============================================================================
// Mock implementations
// ============================================================================

type mockKeySource struct {
	KeyFunc func(ctx context.Context, jwksURI, kid string) (*rsa.PublicKey, error)
}

func (m *mockKeySource) Key(ctx context.Context, jwksURI, kid string) (*rsa.PublicKey, error) {
	return m.KeyFunc(ctx, jwksURI, kid)
}

type mockNonceStore struct {
	ClaimFunc func(ctx context.Context, issuer, nonce string, expiresAt time.Time) (bool, error)
}

func (m *mockNonceStore) Claim(ctx context.Context, issuer, nonce string, expiresAt time.Time) (bool, error) {
	return m.ClaimFunc(ctx, issuer, nonce, expiresAt)
}

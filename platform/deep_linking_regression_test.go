package platform

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// signWithHeader signs claims with the tool's key under a custom JWS header.
func signWithHeader(t *testing.T, key lti.SigningKey, header, claims map[string]any) string {
	t.Helper()

	encode := func(v any) string {
		body, err := json.Marshal(v)
		require.NoError(t, err)

		return base64.RawURLEncoding.EncodeToString(body)
	}

	input := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(input))

	signature, err := key.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func setRawContentItems(claims map[string]any, items ...string) {
	claims[lti.ClaimContentItems] = json.RawMessage("[" + strings.Join(items, ",") + "]")
}

func verifyItems(t *testing.T, setup deepLinkingTestSetup, items ...string) (*lti.DeepLinkingResponse, error) {
	t.Helper()

	claims := createTestDeepLinkingResponseClaims(setup.now)
	setRawContentItems(claims, items...)

	session := createTestDeepLinkingSession()
	session.Settings.AcceptTypes = append(allContentItemTypes, "https://www.example.com/custom_type")
	session.Settings.AcceptMultiple = true

	return setup.verifier.Verify(t.Context(), setup.sign(t, claims), session)
}

// recordingNonceStore remembers every claim it is asked for.
type recordingNonceStore struct {
	mu     sync.Mutex
	claims []recordedClaim
}

type recordedClaim struct {
	issuer, nonce string
	expiresAt     time.Time
}

func (s *recordingNonceStore) Claim(_ context.Context, issuer, nonce string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.claims = append(s.claims, recordedClaim{issuer: issuer, nonce: nonce, expiresAt: expiresAt})

	return true, nil
}

// ============================================================================
// Tests
// ============================================================================

func TestRegression_CriticalHeaderIsRejected(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": setup.tool.ID, "crit": []string{"x-must-understand"}, "x-must-understand": true}

	_, err := setup.verifier.Verify(t.Context(), signWithHeader(t, setup.tool, header, createTestDeepLinkingResponseClaims(setup.now)), createTestDeepLinkingSession())
	requireRejection(t, err, "not a valid jwt")
}

func TestRegression_AudiencesMustAllBeThePlatform(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)

	claims := createTestDeepLinkingResponseClaims(setup.now)
	claims["aud"] = []string{"https://other-platform.example.org", "https://platform.example.com/lti"}

	_, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), createTestDeepLinkingSession())
	requireRejection(t, err, "audience other than the platform")

	claims = createTestDeepLinkingResponseClaims(setup.now)
	claims["aud"] = []string{"https://platform.example.com/lti"}
	claims["azp"] = "client-1"

	_, err = setup.verifier.Verify(t.Context(), setup.sign(t, claims), createTestDeepLinkingSession())
	require.NoError(t, err, "a one-element audience array is fine, and azp is the tool's as in Deep Linking 2.0 Appendix B")
}

func TestRegression_AKeySourceReturningNoKeyIsARejection(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	keys := &mockKeySource{KeyFunc: func(context.Context, string, string) (*rsa.PublicKey, error) { return nil, nil }}

	verifier, err := NewDeepLinkingVerifier(createTestConfig(), keys, setup.nonces)
	require.NoError(t, err)

	_, err = verifier.Verify(t.Context(), setup.sign(t, createTestDeepLinkingResponseClaims(time.Now())), createTestDeepLinkingSession())
	requireRejection(t, err, "not a valid jwt")
}

func TestRegression_HugeToolKeyIsRefusedQuickly(t *testing.T) {
	t.Parallel()

	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 1<<16))
	require.NoError(t, err)
	n.SetBit(n, 1<<16, 1)
	n.SetBit(n, 0, 1)

	body, err := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "big", "n": base64.RawURLEncoding.EncodeToString(n.Bytes()), "e": "AQAB"}}})
	require.NoError(t, err)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	verifier, err := NewDeepLinkingVerifier(createTestConfig(), newTestFetcher(t, server.Client()), ltitest.NewNonceStore(t))
	require.NoError(t, err)

	session := createTestDeepLinkingSession()
	session.Tool.JWKSURI = server.URL

	header := map[string]any{"alg": "RS256", "kid": "big"}
	claims, err := json.Marshal(createTestDeepLinkingResponseClaims(time.Now()))
	require.NoError(t, err)

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	token := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, len(n.Bytes())))

	_, err = verifier.Verify(t.Context(), token, session)

	_, isRejection := lti.AsError(err)
	require.Error(t, err)
	assert.False(t, isRejection, "a set with only an oversized key has no usable key, so the tool's jwks fails to load")
}

func TestRegression_ContentItemKeysMustNotCollide(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)

	for name, item := range map[string]string{
		"url in two cases":               `{"type":"link","url":"https://evil.example.net/phish","URL":"https://tool.example.com/ok"}`,
		"thumbnail url in two cases":     `{"type":"link","url":"https://a.example.com/","thumbnail":{"url":"https://evil.example.net/t.png","URL":"https://a.example.com/t.png"}}`,
		"type in two cases":              `{"type":"link","Type":"html","url":"https://a.example.com/","html":"<b>x</b>"}`,
		"a duplicate url":                `{"type":"link","url":"https://a.example.com/","url":"https://evil.example.net/"}`,
		"a duplicate custom key":         `{"type":"ltiResourceLink","custom":{"a":"1","a":"2"}}`,
		"type in the wrong case alone":   `{"Type":"ltiResourceLink"}`,
		"url in the wrong case alone":    `{"type":"link","URL":"https://a.example.com/"}`,
		"a nested key in the wrong case": `{"type":"link","url":"https://a.example.com/","iframe":{"Src":"https://a.example.com/e"}}`,
	} {
		_, err := verifyItems(t, setup, item)
		requireRejection(t, err, "duplicate or miscased keys")
		assert.Zero(t, setup.nonces.Len(), name)
	}

	_, err := verifyItems(t, setup, `{"type":"ltiResourceLink","custom":{"Quiz":"1","quiz":"2"}}`)
	require.NoError(t, err, "custom parameter names that differ in case are different parameters")
}

func TestRegression_ContentMayLiveOffTheToolsDomains(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)

	response, err := verifyItems(t, setup,
		`{"type":"link","url":"https://www.youtube.com/watch?v=corV3-WsIro","iframe":{"src":"https://www.youtube.com/embed/corV3-WsIro","width":560,"height":315}}`,
		`{"type":"ltiResourceLink","url":"https://tool.example.com/launch","thumbnail":{"url":"https://i.ytimg.com/t.jpg"}}`,
	)
	require.NoError(t, err)
	require.Len(t, response.Items, 2)

	tool := createTestTool()
	assert.False(t, OnToolDomains(tool, response.Items[0].URL), "a host that wants the domain rule can apply it")
	assert.True(t, OnToolDomains(tool, response.Items[1].URL))
	assert.True(t, OnToolDomains(tool, "https://cdn.example.net/a.png"))
	assert.False(t, OnToolDomains(Tool{Domains: []string{"github.io"}}, "https://someone.github.io/"))
}

func TestRegression_EveryItemURLMustBeHTTPS(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)

	for name, item := range map[string]string{
		"url":        `{"type":"link","url":"http://a.example.com/"}`,
		"icon":       `{"type":"link","url":"https://a.example.com/","icon":{"url":"http://a.example.com/i.png"}}`,
		"thumbnail":  `{"type":"ltiResourceLink","thumbnail":{"url":"http://a.example.com/t.png"}}`,
		"iframe src": `{"type":"link","url":"https://a.example.com/","iframe":{"src":"http://a.example.com/e"}}`,
		"javascript": `{"type":"link","url":"javascript:alert(1)"}`,
	} {
		_, err := verifyItems(t, setup, item)
		require.Error(t, err, name)
		requireRejection(t, err, "")
	}
}

func TestRegression_ItemsCarryWhatTheSpecRequires(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)

	tests := map[string]struct {
		item    string
		message string
	}{
		"a link iframe without src":       {item: `{"type":"link","url":"https://a.example.com/","iframe":{"width":100}}`, message: "iframe has no src"},
		"a link embed without html":       {item: `{"type":"link","url":"https://a.example.com/","embed":{}}`, message: "embed has no html"},
		"an icon without url":             {item: `{"type":"link","url":"https://a.example.com/","icon":{"width":10}}`, message: "icon or thumbnail without a url"},
		"a null custom value":             {item: `{"type":"ltiResourceLink","custom":{"a":null}}`, message: "null, not a string"},
		"a line item without a maximum":   {item: `{"type":"ltiResourceLink","lineItem":{"label":"Quiz"}}`, message: "positive scoreMaximum"},
		"a line item with a zero maximum": {item: `{"type":"ltiResourceLink","lineItem":{"scoreMaximum":0}}`, message: "positive scoreMaximum"},
		"a fractional width":              {item: `{"type":"link","url":"https://a.example.com/","iframe":{"src":"https://a.example.com/e","width":100.5}}`, message: "malformed content item"},
		"a width beyond an int32":         {item: `{"type":"link","url":"https://a.example.com/","window":{"width":1e10}}`, message: "malformed content item"},
		"a width as a string":             {item: `{"type":"link","url":"https://a.example.com/","window":{"width":"100"}}`, message: "malformed content item"},
	}

	for name, tt := range tests {
		_, err := verifyItems(t, setup, tt.item)
		require.Error(t, err, name)
		requireRejection(t, err, tt.message)
	}

	response, err := verifyItems(t, setup,
		`{"type":"link","url":"https://a.example.com/","iframe":{"src":"https://a.example.com/e","width":100.0},"embed":{"html":"<iframe></iframe>"}}`,
		`{"type":"ltiResourceLink","lineItem":{"scoreMaximum":87.5},"custom":{"a":""}}`,
		`{"type":"https://www.example.com/custom_type","data":"somedata"}`,
	)
	require.NoError(t, err)
	assert.Equal(t, 100, response.Items[0].Iframe.Width)
	assert.Equal(t, "<iframe></iframe>", response.Items[0].Embed.HTML)
}

func TestRegression_DataIsOnlyComparedWhenTheRequestSentIt(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	session := createTestDeepLinkingSession()
	session.Settings.Data = ""

	_, err := setup.verifier.Verify(t.Context(), setup.sign(t, createTestDeepLinkingResponseClaims(setup.now)), session)
	require.NoError(t, err, "Deep Linking 2.0 §4.5.5 only requires data when the request sent it")
}

func TestRegression_LifetimeBoundAllowsClockSkew(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)

	claims := createTestDeepLinkingResponseClaims(setup.now)
	claims["iat"] = setup.now.Add(30 * time.Second).Unix()
	claims["exp"] = setup.now.Add(30*time.Second + time.Hour).Unix()

	_, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), createTestDeepLinkingSession())
	require.NoError(t, err, "a tool 30 s ahead may still use the full hour")

	claims = createTestDeepLinkingResponseClaims(setup.now)
	claims["nonce"] = "backwards"
	claims["iat"] = setup.now.Add(30 * time.Second).Unix()
	claims["exp"] = setup.now.Add(10 * time.Second).Unix()

	_, err = setup.verifier.Verify(t.Context(), setup.sign(t, claims), createTestDeepLinkingSession())
	requireRejection(t, err, "expires before it is issued")
}

func TestRegression_ResponseSizesAreCapped(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)

	claims := createTestDeepLinkingResponseClaims(setup.now)
	claims["nonce"] = strings.Repeat("n", 1025)

	_, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), createTestDeepLinkingSession())
	requireRejection(t, err, "one over 1 KiB")

	_, err = setup.verifier.Verify(t.Context(), strings.Repeat("a", MaxDeepLinkingResponseBytes+1), createTestDeepLinkingSession())
	requireRejection(t, err, "larger than 1 MiB")

	_, err = setup.verifier.Verify(t.Context(), "", createTestDeepLinkingSession())
	requireRejection(t, err, "deep linking response is missing")
}

func TestRegression_NonceIsClaimedForTheToolUntilExpiryPlusSkew(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	nonces := &recordingNonceStore{}

	verifier, err := NewDeepLinkingVerifier(createTestConfig(), setup.verifier.keys, nonces, WithClock(func() time.Time { return setup.now }))
	require.NoError(t, err)

	claims := createTestDeepLinkingResponseClaims(setup.now)

	_, err = verifier.Verify(t.Context(), setup.sign(t, claims), createTestDeepLinkingSession())
	require.NoError(t, err)

	require.Len(t, nonces.claims, 1)
	assert.Equal(t, "client-1", nonces.claims[0].issuer)
	assert.Equal(t, "tool-nonce-1", nonces.claims[0].nonce)
	assert.Equal(t, time.Unix(setup.now.Add(5*time.Minute).Unix(), 0).Add(time.Minute), nonces.claims[0].expiresAt)
}

func TestRegression_VerifyUsesTheInjectedClock(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	past := testNow

	verifier, err := NewDeepLinkingVerifier(createTestConfig(), setup.verifier.keys, ltitest.NewNonceStore(t), WithClock(func() time.Time { return past }))
	require.NoError(t, err)

	_, err = verifier.Verify(t.Context(), setup.sign(t, createTestDeepLinkingResponseClaims(past)), createTestDeepLinkingSession())
	require.NoError(t, err, "a response valid at the injected time is accepted, whatever the wall clock says")

	claims := createTestDeepLinkingResponseClaims(past)
	claims["nonce"] = "within-skew"
	claims["iat"] = past.Add(-10 * time.Minute).Unix()
	claims["exp"] = past.Add(-30 * time.Second).Unix()

	_, err = verifier.Verify(t.Context(), setup.sign(t, claims), createTestDeepLinkingSession())
	require.NoError(t, err, "expired 30 s ago is within the minute of skew")

	claims["nonce"] = "beyond-skew"
	claims["exp"] = past.Add(-90 * time.Second).Unix()

	_, err = verifier.Verify(t.Context(), setup.sign(t, claims), createTestDeepLinkingSession())
	requireRejection(t, err, "not a valid jwt")
}

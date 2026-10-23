package ltitest_test

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti/jwks"
	"github.com/meitner-se/go-lti/ltitest"
)

// ============================================================================
// Tests
// ============================================================================

func TestNewSigningKey(t *testing.T) {
	t.Parallel()

	first := ltitest.NewSigningKey(t)
	second := ltitest.NewSigningKey(t)

	public := ltitest.PublicKey(t, first)
	assert.Equal(t, first.ID, public.ID)
	assert.Equal(t, 2048, public.PublicKey.N.BitLen())
	assert.NotEqual(t, first.ID, second.ID)
}

func TestSignVerifiesAgainstTheJWKSServer(t *testing.T) {
	t.Parallel()

	key := ltitest.NewSigningKey(t)
	server := ltitest.NewJWKSServer(t, key, ltitest.NewSigningKey(t))

	fetcher, err := jwks.NewFetcher(jwks.WithHTTPClient(server.Client()))
	require.NoError(t, err)

	token := ltitest.Sign(t, key, map[string]any{"sub": "tool", "exp": time.Now().Add(time.Minute).Unix()})

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)

		return fetcher.Key(t.Context(), server.URL+"/any/path", kid)
	}, jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err)
	assert.Equal(t, "tool", claims["sub"])
}

func TestNewKeys(t *testing.T) {
	t.Parallel()

	key := ltitest.NewSigningKey(t)
	keys := ltitest.NewKeys(t, key)

	signing, err := keys.SigningKey(t.Context())
	require.NoError(t, err)
	assert.Equal(t, key.ID, signing.ID)

	public, err := keys.PublicKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, public, 1)

	rsaKey, ok := key.Signer.Public().(*rsa.PublicKey)
	require.True(t, ok)
	assert.True(t, rsaKey.Equal(public[0].PublicKey))
}

func TestNonceStore(t *testing.T) {
	t.Parallel()

	store := ltitest.NewNonceStore(t)
	expiry := time.Now().Add(time.Minute)

	fresh, err := store.Claim(t.Context(), "tool-1", "nonce-1", expiry)
	require.NoError(t, err)
	assert.True(t, fresh)

	fresh, err = store.Claim(t.Context(), "tool-1", "nonce-1", expiry)
	require.NoError(t, err)
	assert.False(t, fresh, "a nonce is claimed once")

	fresh, err = store.Claim(t.Context(), "tool-2", "nonce-1", expiry)
	require.NoError(t, err)
	assert.True(t, fresh, "nonces are per issuer")

	assert.Equal(t, 2, store.Len())
}

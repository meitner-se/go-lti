package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test helper functions
// ============================================================================

// pssSigner signs with PSS whatever it is asked for, like a misconfigured KMS key.
type pssSigner struct{ key *rsa.PrivateKey }

func (s pssSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s pssSigner) Sign(r io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPSS(r, s.key, crypto.SHA256, digest, nil)
}

// ============================================================================
// Tests
// ============================================================================

func TestSignRS256(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token, err := SignRS256(`kid-"1"`, key, map[string]any{"sub": "user-1"})
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	assert.JSONEq(t, `{"alg":"RS256","typ":"JWT","kid":"kid-\"1\""}`, string(header))

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]string
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, "user-1", claims["sub"])

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))
}

func TestSignRS256_RefusesSignersThatDontProduceRS256(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, err = SignRS256("kid", pssSigner{key: key}, map[string]any{})
	require.Error(t, err, "a pss signature is not rs256")

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = SignRS256("kid", ec, map[string]any{})
	require.Error(t, err, "an ec key can't sign rs256")

	_, err = SignRS256("kid", key, map[string]any{"bad": make(chan int)})
	require.Error(t, err, "a payload that isn't json")
}

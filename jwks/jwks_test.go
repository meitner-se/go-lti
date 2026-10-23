package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test helper functions
// ============================================================================

func createTestKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	return key
}

func createTestSetJSON(t *testing.T, keys ...JWK) []byte {
	t.Helper()

	body, _ := json.Marshal(Set{Keys: keys})

	return body
}

// ============================================================================
// Tests
// ============================================================================

func TestNewSet_PublishesRS256SigningKeys(t *testing.T) {
	t.Parallel()

	key := createTestKey(t, 2048)

	set := NewSet(Key{ID: "kid-1", PublicKey: &key.PublicKey})

	require.Len(t, set.Keys, 1)
	assert.Equal(t, "RSA", set.Keys[0].Kty)
	assert.Equal(t, "sig", set.Keys[0].Use)
	assert.Equal(t, "RS256", set.Keys[0].Alg)
	assert.Equal(t, "kid-1", set.Keys[0].Kid)
	assert.Equal(t, "AQAB", set.Keys[0].E)
}

func TestParseSet_RoundTripsNewSet(t *testing.T) {
	t.Parallel()

	first := createTestKey(t, 2048)
	second := createTestKey(t, 3072)

	body, _ := json.Marshal(NewSet(
		Key{ID: "first", PublicKey: &first.PublicKey},
		Key{ID: "second", PublicKey: &second.PublicKey},
	))

	keys, err := ParseSet(body)
	require.NoError(t, err)

	require.Len(t, keys, 2)
	assert.Equal(t, "first", keys[0].ID)
	assert.True(t, first.PublicKey.Equal(keys[0].PublicKey))
	assert.Equal(t, "second", keys[1].ID)
	assert.True(t, second.PublicKey.Equal(keys[1].PublicKey))
}

func TestParseSet_SkipsKeysThatCannotVerifyRS256(t *testing.T) {
	t.Parallel()

	key := createTestKey(t, 2048)
	signing := NewSet(Key{ID: "signing", PublicKey: &key.PublicKey}).Keys[0]

	encryption := signing
	encryption.Kid = "encryption"
	encryption.Use = "enc"

	otherAlg := signing
	otherAlg.Kid = "ps256"
	otherAlg.Alg = "PS256"

	rs512 := signing
	rs512.Kid = "rs512"
	rs512.Alg = "RS512"

	ec := JWK{Kty: "EC", Kid: "ec", Use: "sig"}

	keys, err := ParseSet(createTestSetJSON(t, ec, encryption, otherAlg, rs512, signing))
	require.NoError(t, err)

	require.Len(t, keys, 1)
	assert.Equal(t, "signing", keys[0].ID)
}

func TestParseSet_Rejects(t *testing.T) {
	t.Parallel()

	short := createTestKey(t, 1024)
	key := createTestKey(t, 2048)
	valid := NewSet(Key{ID: "kid", PublicKey: &key.PublicKey}).Keys[0]

	badModulus := valid
	badModulus.N = "not base64!"

	evenExponent := valid
	evenExponent.E = base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x00})

	tests := []struct {
		name string
		body []byte
	}{
		{name: "invalid json", body: []byte(`{"keys":`)},
		{name: "no keys", body: []byte(`{"keys":[]}`)},
		{name: "only non-rsa keys", body: createTestSetJSON(t, JWK{Kty: "EC", Kid: "ec"})},
		{name: "rsa key shorter than 2048 bits", body: createTestSetJSON(t, NewSet(Key{ID: "short", PublicKey: &short.PublicKey}).Keys[0])},
		{name: "malformed modulus", body: createTestSetJSON(t, badModulus)},
		{name: "even exponent", body: createTestSetJSON(t, evenExponent)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseSet(tt.body)
			require.Error(t, err)
		})
	}
}

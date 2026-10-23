package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Tests
// ============================================================================

func TestThumbprint_RFC7638Example(t *testing.T) {
	t.Parallel()

	// RFC 7638 §3.1.
	n, err := base64.RawURLEncoding.DecodeString(
		"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	)
	require.NoError(t, err)

	key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}

	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Thumbprint(key))
}

func TestThumbprint_DiffersPerKey(t *testing.T) {
	t.Parallel()

	first := createTestKey(t, 2048)
	second := createTestKey(t, 2048)

	assert.NotEqual(t, Thumbprint(&first.PublicKey), Thumbprint(&second.PublicKey))
}

package lti_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/ltitest"
)

// ============================================================================
// Tests
// ============================================================================

func TestError(t *testing.T) {
	t.Parallel()

	cause := errors.New("signature mismatch")
	err := lti.NewError(lti.ErrorInvalidRequest, "the response is not signed by the tool", cause)

	assert.Equal(t, "lti: invalid_request: the response is not signed by the tool: signature mismatch", err.Error())
	assert.Equal(t, http.StatusBadRequest, err.StatusCode())
	require.ErrorIs(t, err, cause)

	got, ok := lti.AsError(errors.Join(errors.New("context"), err))
	require.True(t, ok)
	assert.Same(t, err, got)

	assert.Equal(t, http.StatusUnauthorized, lti.NewError(lti.ErrorInvalidClient, "unknown client", nil).StatusCode())
	assert.Equal(t, http.StatusUnauthorized, lti.NewError(lti.ErrorInvalidToken, "expired", nil).StatusCode())

	_, ok = lti.AsError(errors.New("ours"))
	assert.False(t, ok)
}

func TestStaticKeys(t *testing.T) {
	t.Parallel()

	current := ltitest.NewSigningKey(t)
	next := ltitest.NewSigningKey(t)

	keys, err := lti.StaticKeys(current, ltitest.PublicKey(t, next), ltitest.PublicKey(t, current))
	require.NoError(t, err)

	signing, err := keys.SigningKey(t.Context())
	require.NoError(t, err)
	assert.Equal(t, current.ID, signing.ID)

	public, err := keys.PublicKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, public, 2, "the current key is published once")
	assert.Equal(t, current.ID, public[0].ID)
	assert.Equal(t, next.ID, public[1].ID)
}

func TestStaticKeys_Rejects(t *testing.T) {
	t.Parallel()

	short, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	valid := ltitest.NewSigningKey(t)

	tests := []struct {
		name string
		key  lti.SigningKey
	}{
		{name: "no kid", key: lti.SigningKey{Signer: valid.Signer}},
		{name: "no signer", key: lti.SigningKey{ID: "kid"}},
		{name: "a key under 2048 bits", key: lti.SigningKey{ID: "kid", Signer: short}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := lti.StaticKeys(tt.key)
			require.Error(t, err)
		})
	}
}

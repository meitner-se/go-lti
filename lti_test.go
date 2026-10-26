package lti_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/jwks"
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
	assert.Equal(t, http.StatusInternalServerError, lti.NewError(lti.ErrorServerError, "try again", nil).StatusCode())

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

func TestStaticKeys_KidDefaultsToTheThumbprint(t *testing.T) {
	t.Parallel()

	key := ltitest.NewSigningKey(t)
	key.ID = ""

	keys, err := lti.StaticKeys(key)
	require.NoError(t, err)

	signing, err := keys.SigningKey(t.Context())
	require.NoError(t, err)

	public, err := keys.PublicKeys(t.Context())
	require.NoError(t, err)

	rsaKey, ok := key.Signer.Public().(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, jwks.Thumbprint(rsaKey), signing.ID)
	assert.Equal(t, signing.ID, public[0].ID)
}

func TestParseRSAPrivateKeyPEM(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	for name, block := range map[string]*pem.Block{
		"pkcs #1": {Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
		"pkcs #8": {Type: "PRIVATE KEY", Bytes: pkcs8},
	} {
		parsed, err := lti.ParseRSAPrivateKeyPEM(pem.EncodeToMemory(block))
		require.NoError(t, err, name)
		assert.True(t, key.Equal(parsed), name)
	}
}

func TestParseRSAPrivateKeyPEM_Rejects(t *testing.T) {
	t.Parallel()

	short, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ec)
	require.NoError(t, err)

	valid, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	validPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(valid)})

	tests := map[string][]byte{
		"empty":                 nil,
		"not pem":               []byte("not a key"),
		"a key under 2048 bits": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(short)}),
		"an ec key":             pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8}),
		"a public key":          pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}}),
		"an encrypted key":      pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"two keys":              append(append([]byte{}, validPEM...), validPEM...),
		"a corrupt key":         pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
	}

	for name, data := range tests {
		_, err := lti.ParseRSAPrivateKeyPEM(data)
		require.Error(t, err, name)
	}
}

func TestSubstitute(t *testing.T) {
	t.Parallel()

	got := lti.Substitute(map[string]string{
		"context":   "$Context.id",
		"user":      "$User.id",
		"unknown":   "$Context.id.history",
		"embedded":  "course $Context.id",
		"literal":   "BIO1",
		"dollar":    "$",
		"unoffered": "$ResourceLink.title",
	}, map[lti.Variable]string{
		lti.VariableContextID: "course-1",
		lti.VariableUserID:    "user-1",
	}, lti.Sharing{})

	assert.Equal(t, map[string]string{
		"context":   "course-1",
		"user":      "user-1",
		"unknown":   "$Context.id.history",
		"embedded":  "course $Context.id",
		"literal":   "BIO1",
		"dollar":    "$",
		"unoffered": "$ResourceLink.title",
	}, got)

	assert.Nil(t, lti.Substitute(nil, nil, lti.Sharing{}))
}

func TestRegression_SubstituteWithholdsPersonalDataUnlessShared(t *testing.T) {
	t.Parallel()

	custom := map[string]string{
		"email":    "$Person.email.primary",
		"name":     "$Person.name.full",
		"username": "$User.username",
		"phone":    "$Person.phone.mobile",
		"home":     "$Person.phone.home",
		"course":   "$Context.id",
	}
	values := map[lti.Variable]string{
		lti.VariablePersonEmailPrimary: "student@school.example",
		lti.VariablePersonNameFull:     "Ada Lovelace",
		lti.VariableUserUsername:       "ada",
		"Person.phone.mobile":          "+46700000000",
		lti.VariableContextID:          "course-1",
	}

	assert.Equal(t, map[string]string{
		"email":    "",
		"name":     "",
		"username": "",
		"phone":    "",
		"home":     "$Person.phone.home",
		"course":   "course-1",
	}, lti.Substitute(custom, values, lti.Sharing{}), "nothing about the user is shared by default; an unsupported variable stays as it is")

	assert.Equal(t, map[string]string{
		"email":    "",
		"name":     "Ada Lovelace",
		"username": "ada",
		"phone":    "",
		"home":     "$Person.phone.home",
		"course":   "course-1",
	}, lti.Substitute(custom, values, lti.Sharing{Name: true}))

	assert.Equal(t, map[string]string{
		"email":    "student@school.example",
		"name":     "Ada Lovelace",
		"username": "ada",
		"phone":    "",
		"home":     "$Person.phone.home",
		"course":   "course-1",
	}, lti.Substitute(custom, values, lti.Sharing{Name: true, Email: true}), "other personal data has no sharing setting, so it is never shared")
}

func TestStaticKeys_Rejects(t *testing.T) {
	t.Parallel()

	short, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	tests := []struct {
		name string
		key  lti.SigningKey
	}{
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

func TestRegression_StaticKeysRefusesAKidForTwoKeys(t *testing.T) {
	t.Parallel()

	current := ltitest.NewSigningKey(t)
	next := ltitest.PublicKey(t, ltitest.NewSigningKey(t))

	impostor := ltitest.PublicKey(t, ltitest.NewSigningKey(t))
	impostor.ID = current.ID

	_, err := lti.StaticKeys(current, impostor)
	require.Error(t, err, "a different key under the current kid")

	_, err = lti.StaticKeys(current, next, next)
	require.NoError(t, err, "the same key twice is harmless")

	twin := ltitest.PublicKey(t, ltitest.NewSigningKey(t))
	twin.ID = next.ID

	_, err = lti.StaticKeys(current, next, twin)
	require.Error(t, err, "two different published keys under one kid")
}

func TestRegression_StaticKeysValidatesPublishedKeys(t *testing.T) {
	t.Parallel()

	current := ltitest.NewSigningKey(t)

	short, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	noKid := ltitest.PublicKey(t, ltitest.NewSigningKey(t))
	noKid.ID = ""

	for name, key := range map[string]jwks.Key{
		"no kid":           noKid,
		"no public key":    {ID: "next"},
		"a key under 2048": {ID: "next", PublicKey: &short.PublicKey},
		"an empty rsa key": {ID: "next", PublicKey: &rsa.PublicKey{}},
	} {
		_, err := lti.StaticKeys(current, key)
		require.Error(t, err, name)
	}
}

func TestRegression_StaticKeysPublicKeysIsACopy(t *testing.T) {
	t.Parallel()

	keys, err := lti.StaticKeys(ltitest.NewSigningKey(t), ltitest.PublicKey(t, ltitest.NewSigningKey(t)))
	require.NoError(t, err)

	first, err := keys.PublicKeys(t.Context())
	require.NoError(t, err)

	first[0] = jwks.Key{}

	second, err := keys.PublicKeys(t.Context())
	require.NoError(t, err)
	assert.NotEmpty(t, second[0].ID)
}

func TestRegression_NilErrorDoesNotPanic(t *testing.T) {
	t.Parallel()

	var err *lti.Error

	assert.Equal(t, "lti: <nil>", err.Error())
}

// Package ltitest provides test doubles for go-lti: RSA signing keys generated in memory, a JWKS
// server, an in-memory nonce store and a way to sign a tool's messages. Nothing here is fit for
// production.
package ltitest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/jose"
	"github.com/meitner-se/go-lti/jwks"
)

// NewSigningKey generates a 2048-bit RSA signing key with a random kid. It serves both as the
// platform's key and as a tool's.
func NewSigningKey(tb testing.TB) lti.SigningKey {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("ltitest: cannot generate rsa key: %v", err)
	}

	kid := make([]byte, 16)
	if _, err := rand.Read(kid); err != nil {
		tb.Fatalf("ltitest: cannot generate kid: %v", err)
	}

	return lti.SigningKey{ID: hex.EncodeToString(kid), Signer: privateKey}
}

// NewKeys returns static lti.Keys that sign with key.
func NewKeys(tb testing.TB, key lti.SigningKey) lti.Keys {
	tb.Helper()

	keys, err := lti.StaticKeys(key)
	if err != nil {
		tb.Fatalf("ltitest: cannot build keys: %v", err)
	}

	return keys
}

// PublicKey returns the public half of key.
func PublicKey(tb testing.TB, key lti.SigningKey) jwks.Key {
	tb.Helper()

	public, err := key.PublicKey()
	if err != nil {
		tb.Fatalf("ltitest: invalid signing key: %v", err)
	}

	return public
}

// Sign returns claims as a compact RS256 JWT signed with key, as a tool signs its messages.
func Sign(tb testing.TB, key lti.SigningKey, claims map[string]any) string {
	tb.Helper()

	token, err := jose.SignRS256(key.ID, key.Signer, claims)
	if err != nil {
		tb.Fatalf("ltitest: cannot sign: %v", err)
	}

	return token
}

// NewJWKSServer starts an https server that publishes the keys' public halves as a JWKS on every
// path. Fetch from it with jwks.WithHTTPClient(server.Client()), since it listens on loopback.
func NewJWKSServer(tb testing.TB, keys ...lti.SigningKey) *httptest.Server {
	tb.Helper()

	public := make([]jwks.Key, 0, len(keys))
	for _, key := range keys {
		public = append(public, PublicKey(tb, key))
	}

	body, err := json.Marshal(jwks.NewSet(public...)) //nolint:errchkjson // errcheck requires the check outside _test.go files
	if err != nil {
		tb.Fatalf("ltitest: cannot encode jwks: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if _, err := w.Write(body); err != nil {
			tb.Errorf("ltitest: cannot write jwks: %v", err)
		}
	}))
	tb.Cleanup(server.Close)

	return server
}

// NonceStore is an in-memory lti.NonceStore for tests. It never forgets and isn't shared between
// processes, so it can't protect a real platform against replays.
type NonceStore struct {
	mu   sync.Mutex
	used map[string]bool
}

// NewNonceStore returns an empty NonceStore. It takes tb so that it is only made in tests.
func NewNonceStore(tb testing.TB) *NonceStore {
	tb.Helper()

	return &NonceStore{used: map[string]bool{}}
}

// Claim marks nonce as used by issuer and returns false when it was already used.
func (s *NonceStore) Claim(_ context.Context, issuer, nonce string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := issuer + "\x00" + nonce
	if s.used[key] {
		return false, nil
	}

	s.used[key] = true

	return true, nil
}

// Len returns how many nonces have been claimed.
func (s *NonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.used)
}

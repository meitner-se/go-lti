package jwks

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
)

// Thumbprint returns the RFC 7638 JWK thumbprint of an RSA public key: the base64url SHA-256 of its
// required members in lexicographic order. It makes a stable kid that can't collide by accident.
func Thumbprint(publicKey *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())

	// Both values are base64url, so they need no JSON escaping.
	digest := sha256.Sum256([]byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`))

	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// Package jwks publishes and fetches JSON Web Key Sets (RFC 7517) of RS256 signing keys.
//
// A platform publishes its own keys with NewSet. Keys that tools publish are fetched with a
// Fetcher, which caches them and only connects to public https hosts.
package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

const (
	keyTypeRSA = "RSA"
	useSig     = "sig"
	algRS256   = "RS256"

	// MinRSABits is the smallest RSA modulus accepted. RFC 7518 §3.3 requires 2048 bits for RS256.
	MinRSABits = 2048
	// MaxRSABits is the largest RSA modulus accepted. Verifying with a key costs time that grows with
	// the square of its size, so a tool must not be able to publish one large enough to stall us.
	MaxRSABits = 4096
)

// ErrNoSigningKeys is returned by ParseSet when a set has no usable RS256 signing key.
var ErrNoSigningKeys = errors.New("jwks: no usable rs256 signing keys")

// Key is an RSA public signing key and the kid that JWT headers refer to it by.
type Key struct {
	ID        string
	PublicKey *rsa.PublicKey
}

// Set is a JSON Web Key Set document (RFC 7517 §5).
type Set struct {
	Keys []JWK `json:"keys"`
}

// JWK is one RSA public key in a Set (RFC 7517 §4, RFC 7518 §6.3.1).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// NewSet returns the Set that publishes keys as RS256 signing keys.
func NewSet(keys ...Key) Set {
	set := Set{Keys: make([]JWK, 0, len(keys))}
	for _, key := range keys {
		set.Keys = append(set.Keys, JWK{
			Kty: keyTypeRSA,
			Use: useSig,
			Alg: algRS256,
			Kid: key.ID,
			N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		})
	}

	return set
}

// ParseSet decodes a JWKS document and returns its usable RS256 signing keys.
//
// Keys it can't use are skipped, as RFC 7517 §5 asks: other key types, encryption keys, keys
// declared for other algorithms, and RS256 keys that are malformed, outside 2048 to 4096 bits, or
// have an invalid exponent. A Key carries no algorithm, so only RS256 keys may pass: a key declared
// for RS512 must not verify an RS256 token. Members must be base64url without padding (RFC 7515
// §2), so a padded n or e makes its key unusable. ParseSet fails when the document isn't a JWK set
// or no usable key remains.
func ParseSet(data []byte) ([]Key, error) {
	var set Set
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("jwks: cannot decode set: %w", err)
	}

	keys := make([]Key, 0, len(set.Keys))
	for _, jwk := range set.Keys {
		if !jwk.isRS256SigningKey() {
			continue
		}

		publicKey, err := jwk.rsaPublicKey()
		if err != nil {
			continue
		}

		keys = append(keys, Key{ID: jwk.Kid, PublicKey: publicKey})
	}

	if len(keys) == 0 {
		return nil, ErrNoSigningKeys
	}

	return keys, nil
}

func (j JWK) isRS256SigningKey() bool {
	if j.Kty != keyTypeRSA {
		return false
	}

	if j.Use != "" && j.Use != useSig {
		return false
	}

	return j.Alg == "" || j.Alg == algRS256
}

func (j JWK) rsaPublicKey() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("jwks: cannot decode modulus: %w", err)
	}

	e, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("jwks: cannot decode exponent: %w", err)
	}

	modulus := new(big.Int).SetBytes(n)
	if modulus.BitLen() < MinRSABits || modulus.BitLen() > MaxRSABits {
		return nil, errors.New("jwks: rsa modulus is not between 2048 and 4096 bits")
	}

	exponent := new(big.Int).SetBytes(e)
	if !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() >= 1<<31 || exponent.Bit(0) == 0 {
		return nil, errors.New("jwks: rsa exponent is invalid")
	}

	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

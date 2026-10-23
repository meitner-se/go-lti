package lti

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/meitner-se/go-lti/jwks"
)

// SigningKey is the platform's private key. Signer is any crypto.Signer over an RSA key of at
// least 2048 bits that signs PKCS #1 v1.5 when asked for crypto.SHA256: an *rsa.PrivateKey loaded
// from secret storage, or a KMS or HSM client.
type SigningKey struct {
	// ID is the kid in the JWT header and the published JWKS.
	ID     string
	Signer crypto.Signer
}

// PublicKey returns the key to publish, checking that it is an RSA key of at least 2048 bits.
func (k SigningKey) PublicKey() (jwks.Key, error) {
	if k.ID == "" {
		return jwks.Key{}, errors.New("lti: signing key has no kid")
	}

	if k.Signer == nil {
		return jwks.Key{}, errors.New("lti: signing key has no signer")
	}

	publicKey, ok := k.Signer.Public().(*rsa.PublicKey)
	if !ok {
		return jwks.Key{}, errors.New("lti: signing key is not an rsa key")
	}

	if publicKey.N.BitLen() < jwks.MinRSABits {
		return jwks.Key{}, errors.New("lti: signing key is shorter than 2048 bits")
	}

	return jwks.Key{ID: k.ID, PublicKey: publicKey}, nil
}

// Keys supplies the key to sign with and the public keys to publish. An implementation may re-read
// secret storage on each call, so a rotation needs no restart.
type Keys interface {
	SigningKey(ctx context.Context) (SigningKey, error)
	// PublicKeys returns every key whose kid a verifier may meet: the current key, and the
	// previous and next ones during a rotation.
	PublicKeys(ctx context.Context) ([]jwks.Key, error)
}

// StaticKeys returns Keys that sign with current and publish it along with publish, such as the
// next key in a rotation. Each published key needs a kid and an RSA key of at least 2048 bits, and
// no two keys may share a kid. The current key may be listed in publish too.
func StaticKeys(current SigningKey, publish ...jwks.Key) (Keys, error) {
	currentPublic, err := current.PublicKey()
	if err != nil {
		return nil, err
	}

	public := []jwks.Key{currentPublic}
	for _, key := range publish {
		if key.ID == "" || key.PublicKey == nil || key.PublicKey.N == nil || key.PublicKey.N.BitLen() < jwks.MinRSABits {
			return nil, errors.New("lti: published keys need a kid and an rsa key of at least 2048 bits")
		}

		if existing := findPublished(public, key.ID); existing != nil {
			if existing.Equal(key.PublicKey) {
				continue
			}

			return nil, fmt.Errorf("lti: two different published keys share the kid %q", key.ID)
		}

		public = append(public, key)
	}

	return staticKeys{current: current, public: public}, nil
}

type staticKeys struct {
	current SigningKey
	public  []jwks.Key
}

func (k staticKeys) SigningKey(context.Context) (SigningKey, error) {
	return k.current, nil
}

func (k staticKeys) PublicKeys(context.Context) ([]jwks.Key, error) {
	return append([]jwks.Key(nil), k.public...), nil
}

// KeySource resolves a tool's public signing key by kid. *jwks.Fetcher implements it.
type KeySource interface {
	// Key returns the key, or an error wrapping jwks.ErrKeyNotFound when the tool has no such key.
	Key(ctx context.Context, jwksURI, kid string) (*rsa.PublicKey, error)
}

// NonceStore remembers which nonces a tool has used, to reject replayed messages. It must be
// shared by every replica that verifies the tool's messages.
type NonceStore interface {
	// Claim marks nonce as used by issuer until expiresAt. It returns false when it was already used.
	Claim(ctx context.Context, issuer, nonce string, expiresAt time.Time) (bool, error)
}

func findPublished(keys []jwks.Key, kid string) *rsa.PublicKey {
	for _, key := range keys {
		if key.ID == kid {
			return key.PublicKey
		}
	}

	return nil
}

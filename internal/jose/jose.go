// Package jose builds RS256 JSON Web Signatures with a crypto.Signer, so a platform key can live
// in a KMS or HSM.
package jose

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// SignRS256 returns payload, marshalled as JSON, as a compact JWS (RFC 7515 §7.1) with RS256 and
// kid in the header. It checks the signature against the signer's public key, so a signer that
// signs with another padding fails here rather than at the tool.
func SignRS256(kid string, signer crypto.Signer, payload any) (string, error) {
	publicKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return "", errors.New("jose: signer is not an rsa key")
	}

	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}) //nolint:errchkjson // errcheck requires the check outside _test.go files
	if err != nil {
		return "", fmt.Errorf("jose: cannot encode header: %w", err)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("jose: cannot encode payload: %w", err)
	}

	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))

	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("jose: cannot sign: %w", err)
	}

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return "", fmt.Errorf("jose: signer did not produce an rs256 signature: %w", err)
	}

	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

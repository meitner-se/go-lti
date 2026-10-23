package platform

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
	"github.com/meitner-se/go-lti/jwks"
)

const (
	// deepLinkingClockSkew is how far the tool's clock may be off from ours.
	deepLinkingClockSkew = time.Minute
	// maxDeepLinkingResponseLifetime bounds exp, and with it how long a nonce has to be remembered.
	maxDeepLinkingResponseLifetime = time.Hour
)

// DeepLinkingVerifier verifies the LtiDeepLinkingResponse a tool posts back to the platform.
type DeepLinkingVerifier struct {
	config Config
	keys   lti.KeySource
	nonces lti.NonceStore
	now    func() time.Time
}

// NewDeepLinkingVerifier returns a verifier for the platform cfg describes that resolves tools'
// keys with keys, such as a *jwks.Fetcher, and rejects replays with nonces. It fails when cfg is
// invalid.
func NewDeepLinkingVerifier(cfg Config, keys lti.KeySource, nonces lti.NonceStore, opts ...Option) (*DeepLinkingVerifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if keys == nil || nonces == nil {
		return nil, errors.New("lti: deep linking verifier needs a key source and a nonce store")
	}

	return &DeepLinkingVerifier{config: cfg, keys: keys, nonces: nonces, now: newOptions(opts).now}, nil
}

// DeepLinkingSession is what the platform sent in the LtiDeepLinkingRequest.
type DeepLinkingSession struct {
	Tool         Tool
	DeploymentID string
	Settings     lti.DeepLinkingSettings
}

//nolint:tagliatelle // LTI 1.3 and Deep Linking 2.0 define the claim names
type deepLinkingResponseClaims struct {
	jwt.RegisteredClaims

	Nonce        string            `json:"nonce"`
	MessageType  string            `json:"https://purl.imsglobal.org/spec/lti/claim/message_type"`
	Version      string            `json:"https://purl.imsglobal.org/spec/lti/claim/version"`
	DeploymentID string            `json:"https://purl.imsglobal.org/spec/lti/claim/deployment_id"`
	Data         string            `json:"https://purl.imsglobal.org/spec/lti-dl/claim/data"`
	ContentItems []json.RawMessage `json:"https://purl.imsglobal.org/spec/lti-dl/claim/content_items"`
	Message      string            `json:"https://purl.imsglobal.org/spec/lti-dl/claim/msg"`
	Log          string            `json:"https://purl.imsglobal.org/spec/lti-dl/claim/log"`
	ErrorMessage string            `json:"https://purl.imsglobal.org/spec/lti-dl/claim/errormsg"`
	ErrorLog     string            `json:"https://purl.imsglobal.org/spec/lti-dl/claim/errorlog"`
}

// Verify checks the JWT a tool posted in the DeepLinkingResponseField and returns its content.
//
// The JWT must be signed with RS256 by a key in the tool's JWKS, issued by the tool's client_id to
// the platform's issuer, unexpired, valid for at most an hour, with a fresh nonce, for the session's
// deployment, and carry back the session's data unchanged. Its items must be of accepted types, at
// most one unless the session accepted multiple, carry what their type requires, and have every URL
// on the tool's domains. The nonce is claimed last, so a rejected response doesn't use it up.
//
// A rejection is an *lti.Error. Any other error, such as a tool JWKS that can't be fetched or a
// nonce store failure, is the platform's.
func (v *DeepLinkingVerifier) Verify(ctx context.Context, rawJWT string, s DeepLinkingSession) (*lti.DeepLinkingResponse, error) {
	tool := s.Tool

	// The jwt parser skips the iss check for an empty expected issuer, so an incomplete session fails closed.
	if tool.ClientID == "" || tool.JWKSURI == "" || len(tool.Domains) == 0 || s.DeploymentID == "" {
		return nil, errors.New("lti: deep linking session needs the tool's client_id, jwks_uri and domains, and the deployment_id")
	}

	if rawJWT == "" {
		return nil, reject("deep linking response is missing", nil)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(tool.ClientID),
		jwt.WithAudience(v.config.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(deepLinkingClockSkew),
		jwt.WithTimeFunc(v.now),
	)

	var keyErr error

	var claims deepLinkingResponseClaims
	if _, err := parser.ParseWithClaims(rawJWT, &claims, func(token *jwt.Token) (any, error) {
		kid := ""
		if value, ok := token.Header["kid"].(string); ok {
			kid = value
		}

		key, err := v.keys.Key(ctx, tool.JWKSURI, kid)
		keyErr = err

		return key, err
	}); err != nil {
		if keyErr != nil && !errors.Is(keyErr, jwks.ErrKeyNotFound) {
			return nil, fmt.Errorf("lti: cannot get the tool's key: %w", keyErr)
		}

		return nil, reject("deep linking response is not a valid jwt from the tool", err)
	}

	if claims.IssuedAt == nil {
		return nil, reject("deep linking response has no iat", nil)
	}

	// Bounding exp against iat too keeps an old response with a fresh-looking exp out.
	expiresAt := claims.ExpiresAt.Time
	if expiresAt.After(v.now().Add(maxDeepLinkingResponseLifetime)) || expiresAt.Sub(claims.IssuedAt.Time) > maxDeepLinkingResponseLifetime {
		return nil, reject("deep linking response is valid for more than an hour", nil)
	}

	if claims.MessageType != string(lti.MessageTypeDeepLinkingResponse) {
		return nil, reject("deep linking response has the wrong message_type", nil)
	}

	if claims.Version != lti.Version {
		return nil, reject("deep linking response has the wrong lti version", nil)
	}

	if claims.DeploymentID != s.DeploymentID {
		return nil, reject("deep linking response has the wrong deployment_id", nil)
	}

	if subtle.ConstantTimeCompare([]byte(claims.Data), []byte(s.Settings.Data)) != 1 {
		return nil, reject("deep linking response data does not match the request", nil)
	}

	items, err := parseContentItems(claims.ContentItems, tool.Domains, s.Settings)
	if err != nil {
		return nil, err
	}

	if claims.Nonce == "" {
		return nil, reject("deep linking response has no nonce", nil)
	}

	fresh, err := v.nonces.Claim(ctx, tool.ClientID, claims.Nonce, expiresAt.Add(deepLinkingClockSkew))
	if err != nil {
		return nil, fmt.Errorf("lti: cannot check deep linking response nonce: %w", err)
	}

	if !fresh {
		return nil, reject("deep linking response nonce was already used", nil)
	}

	return &lti.DeepLinkingResponse{
		Items:        items,
		Message:      claims.Message,
		Log:          claims.Log,
		ErrorMessage: claims.ErrorMessage,
		ErrorLog:     claims.ErrorLog,
	}, nil
}

func parseContentItems(raw []json.RawMessage, domains []string, settings lti.DeepLinkingSettings) ([]lti.ContentItem, error) {
	if len(raw) > 1 && !settings.AcceptMultiple {
		return nil, reject("deep linking response has more than one item but the request accepted one", nil)
	}

	items := make([]lti.ContentItem, 0, len(raw))
	for _, r := range raw {
		var item lti.ContentItem
		if err := json.Unmarshal(r, &item); err != nil {
			return nil, reject("deep linking response has a malformed content item", err)
		}

		item.Raw = r

		if !slices.Contains(settings.AcceptTypes, item.Type) {
			return nil, reject("deep linking response has a content item of a type the request didn't accept", nil)
		}

		if err := validateRequired(item); err != nil {
			return nil, err
		}

		for _, u := range itemURLs(item) {
			if !urlcheck.OnDomains(u, domains) {
				return nil, reject("deep linking response has a content item url that isn't https on the tool's domain", nil)
			}
		}

		items = append(items, item)
	}

	return items, nil
}

// validateRequired checks the properties Deep Linking 2.0 §3 requires for the item's type. An
// ltiResourceLink may leave out url, since it then launches the tool's registered target link URI.
func validateRequired(item lti.ContentItem) error {
	switch item.Type {
	case lti.ContentItemTypeLink, lti.ContentItemTypeFile, lti.ContentItemTypeImage:
		if item.URL == "" {
			return reject("deep linking response has a link, file or image content item without a url", nil)
		}
	case lti.ContentItemTypeHTML:
		if item.HTML == "" {
			return reject("deep linking response has an html content item without html", nil)
		}
	case lti.ContentItemTypeLTIResourceLink:
	}

	return nil
}

// itemURLs returns every URL in the item that the platform would load or send the user to.
func itemURLs(item lti.ContentItem) []string {
	var urls []string

	if item.URL != "" {
		urls = append(urls, item.URL)
	}

	if item.Icon != nil {
		urls = append(urls, item.Icon.URL)
	}

	if item.Thumbnail != nil {
		urls = append(urls, item.Thumbnail.URL)
	}

	if item.Iframe != nil && item.Iframe.Src != "" {
		urls = append(urls, item.Iframe.Src)
	}

	return urls
}

func reject(description string, cause error) *lti.Error {
	return lti.NewError(lti.ErrorInvalidRequest, description, cause)
}

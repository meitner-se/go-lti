package platform

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
	"github.com/meitner-se/go-lti/jwks"
)

const (
	// deepLinkingClockSkew is how far the tool's clock may be off from ours.
	deepLinkingClockSkew = time.Minute
	// maxDeepLinkingResponseLifetime bounds exp against iat, and with it how long a nonce has to be
	// remembered.
	maxDeepLinkingResponseLifetime = time.Hour
	// maxNonceLength bounds what a tool can make the NonceStore keep.
	maxNonceLength = 1024
)

// MaxDeepLinkingResponseBytes caps the size of a Deep Linking response JWT.
const MaxDeepLinkingResponseBytes = 1 << 20

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

// DeepLinkingSession is what the platform sent in the LtiDeepLinkingRequest. Load it from the
// platform's own state for this browser, such as the record behind the session cookie, never from
// the posted response: that is read before it is verified.
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
// The JWT must be signed with RS256 by a key in the tool's JWKS, without critical header extensions,
// issued by the tool's client_id with the platform's issuer as its only audience, unexpired, valid
// for at most an hour after iat, with a fresh nonce, for the session's deployment, and, when the
// request sent data, carry it back unchanged. Its items must be of accepted types, at most one
// unless the session accepted multiple, carry what Deep Linking 2.0 §3 requires for their type, and
// have https URLs (LTI 1.3 §3.5). The nonce is claimed last, so a rejected response doesn't use it
// up.
//
// Verify doesn't require items to be on the tool's domains, since the spec doesn't; OnToolDomains
// checks that for a platform that wants it. It doesn't sanitize html or check media types or
// presentation either: those are the platform's to decide.
//
// A rejection is an *lti.Error. Any other error, such as a tool JWKS that can't be fetched or a
// nonce store failure, is the platform's.
func (v *DeepLinkingVerifier) Verify(ctx context.Context, rawJWT string, s DeepLinkingSession) (*lti.DeepLinkingResponse, error) {
	tool := s.Tool

	// The jwt parser skips the iss check for an empty expected issuer, so an incomplete session fails closed.
	if tool.ClientID == "" || s.DeploymentID == "" || !urlcheck.IsHTTPS(tool.JWKSURI) {
		return nil, errors.New("lti: deep linking session needs the tool's client_id and https jwks_uri, and the deployment_id")
	}

	if rawJWT == "" {
		return nil, reject("deep linking response is missing", nil)
	}

	if len(rawJWT) > MaxDeepLinkingResponseBytes {
		return nil, reject("deep linking response is larger than 1 MiB", nil)
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
		// RFC 7515 §4.1.11: extensions listed in crit must be understood, and we understand none.
		if _, ok := token.Header["crit"]; ok {
			return nil, errCritical
		}

		kid := ""
		if value, ok := token.Header["kid"].(string); ok {
			kid = value
		}

		key, err := v.keys.Key(ctx, tool.JWKSURI, kid)
		if err == nil && key == nil {
			err = fmt.Errorf("lti: the key source returned no key: %w", jwks.ErrKeyNotFound)
		}

		keyErr = err

		return key, err
	}); err != nil {
		if keyErr != nil && !errors.Is(keyErr, jwks.ErrKeyNotFound) {
			return nil, fmt.Errorf("lti: cannot get the tool's key: %w", keyErr)
		}

		return nil, reject("deep linking response is not a valid jwt from the tool", err)
	}

	// Security Framework §5.2.3: reject a JWT whose audiences include any we don't trust.
	for _, audience := range claims.Audience {
		if audience != v.config.Issuer {
			return nil, reject("deep linking response has an audience other than the platform", nil)
		}
	}

	if claims.IssuedAt == nil {
		return nil, reject("deep linking response has no iat", nil)
	}

	// iat may be at most the clock skew ahead, so this also bounds exp to an hour and the skew from now.
	expiresAt := claims.ExpiresAt.Time
	if lifetime := expiresAt.Sub(claims.IssuedAt.Time); lifetime < 0 || lifetime > maxDeepLinkingResponseLifetime {
		return nil, reject("deep linking response is valid for more than an hour, or expires before it is issued", nil)
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

	// Deep Linking 2.0 §4.5.5: data must come back when the request sent it. Without it, there's nothing to match.
	if s.Settings.Data != "" && subtle.ConstantTimeCompare([]byte(claims.Data), []byte(s.Settings.Data)) != 1 {
		return nil, reject("deep linking response data does not match the request", nil)
	}

	items, err := parseContentItems(claims.ContentItems, s.Settings)
	if err != nil {
		return nil, err
	}

	if claims.Nonce == "" || len(claims.Nonce) > maxNonceLength {
		return nil, reject("deep linking response has no nonce, or one over 1 KiB", nil)
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

// OnToolDomains reports whether rawURL is an https URL on one of the tool's domains or a subdomain
// of one, for a platform that only places content from the tool itself. Domains that are public
// suffixes never match.
func OnToolDomains(tool Tool, rawURL string) bool {
	return urlcheck.OnDomains(rawURL, tool.Domains)
}

var errCritical = errors.New("lti: the jwt has critical header extensions")

func parseContentItems(raw []json.RawMessage, settings lti.DeepLinkingSettings) ([]lti.ContentItem, error) {
	if len(raw) > 1 && !settings.AcceptMultiple {
		return nil, reject("deep linking response has more than one item but the request accepted one", nil)
	}

	items := make([]lti.ContentItem, 0, len(raw))
	for _, r := range raw {
		// Go matches JSON keys case-insensitively, so {"url":a,"URL":b} would validate one and keep the
		// other in Raw. Refuse keys that collide instead.
		if err := checkKeys(r); err != nil {
			return nil, reject("deep linking response has a content item with duplicate or miscased keys", err)
		}

		var item lti.ContentItem
		if err := json.Unmarshal(r, &item); err != nil {
			return nil, reject("deep linking response has a malformed content item", err)
		}

		item.Raw = r

		if !slices.Contains(settings.AcceptTypes, item.Type) {
			return nil, reject("deep linking response has a content item of a type the request didn't accept", nil)
		}

		if err := validateRequired(item, r); err != nil {
			return nil, err
		}

		// LTI 1.3 §3.5: all URLs to resources included in messages must use https.
		for _, u := range itemURLs(item) {
			if !urlcheck.IsHTTPS(u) {
				return nil, reject("deep linking response has a content item url that isn't https", nil)
			}
		}

		items = append(items, item)
	}

	return items, nil
}

// validateRequired checks the properties Deep Linking 2.0 §3 requires for the item's type. An
// ltiResourceLink may leave out url, since it then launches the tool's registered target link URI.
// Items of types the spec doesn't define have no required properties.
func validateRequired(item lti.ContentItem, raw json.RawMessage) error {
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
		if err := validateResourceLink(raw); err != nil {
			return err
		}
	}

	if item.Type == lti.ContentItemTypeLink {
		// §3.1: an iframe needs its src, and an embed its html.
		if item.Iframe != nil && item.Iframe.Src == "" {
			return reject("deep linking response has a link whose iframe has no src", nil)
		}

		if item.Embed != nil && item.Embed.HTML == "" {
			return reject("deep linking response has a link whose embed has no html", nil)
		}
	}

	for _, image := range []*lti.Image{item.Icon, item.Thumbnail} {
		if image != nil && image.URL == "" {
			return reject("deep linking response has an icon or thumbnail without a url", nil)
		}
	}

	return nil
}

// validateResourceLink checks an ltiResourceLink's custom values and line item (Deep Linking 2.0 §3.2).
func validateResourceLink(raw json.RawMessage) error {
	var probe struct {
		Custom   map[string]*string `json:"custom"`
		LineItem *struct {
			ScoreMaximum *float64 `json:"scoreMaximum"`
		} `json:"lineItem"`
	}

	if err := json.Unmarshal(raw, &probe); err != nil {
		return reject("deep linking response has a malformed ltiResourceLink", err)
	}

	for _, value := range probe.Custom {
		if value == nil {
			return reject("deep linking response has a custom parameter that is null, not a string", nil)
		}
	}

	if probe.LineItem != nil && (probe.LineItem.ScoreMaximum == nil || *probe.LineItem.ScoreMaximum <= 0) {
		return reject("deep linking response has a line item without a positive scoreMaximum", nil)
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

// checkKeys refuses a JSON value with an object that repeats a key, or, in the objects Go decodes
// into structs (the item and its icon, thumbnail, window, iframe and embed), a key that differs
// only in case from another key or from a field the struct models. Go matches keys by Unicode case
// folding, so either would let Raw disagree with what was checked.
func checkKeys(raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))

	return walkKeys(dec, itemFields)
}

// Fields of the structs a content item decodes into, by the member that holds them.
var (
	itemFields   = fieldSet("type", "title", "text", "url", "icon", "thumbnail", "window", "iframe", "custom", "mediaType", "html", "embed", "lineItem")
	memberFields = map[string]map[string]string{
		"icon":      fieldSet("url", "width", "height"),
		"thumbnail": fieldSet("url", "width", "height"),
		"window":    fieldSet("targetName", "width", "height", "windowFeatures"),
		"iframe":    fieldSet("src", "width", "height"),
		"embed":     fieldSet("html"),
	}
)

// fieldSet maps each field's folded name to its spelling.
func fieldSet(fields ...string) map[string]string {
	set := make(map[string]string, len(fields))
	for _, field := range fields {
		set[foldKey(field)] = field
	}

	return set
}

// foldKey folds key the way encoding/json matches it to a struct field: by Unicode simple folding,
// so ſ (U+017F) matches s and the Kelvin sign matches k. Each rune becomes the smallest in its orbit.
func foldKey(key string) string {
	var b strings.Builder

	for _, r := range key {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			r = min(r, f)
		}

		b.WriteRune(r)
	}

	return b.String()
}

// walkKeys checks the next JSON value. fields is the struct the value decodes into, or nil when it
// isn't decoded case-insensitively.
func walkKeys(dec *json.Decoder, fields map[string]string) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '[':
		for dec.More() {
			if err := walkKeys(dec, nil); err != nil {
				return err
			}
		}
	case '{':
		seen := map[string]bool{}

		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}

			key, ok := keyToken.(string)
			if !ok {
				return errors.New("lti: object key is not a string")
			}

			seenKey := key
			if fields != nil {
				seenKey = foldKey(key)

				if field, known := fields[seenKey]; known && field != key {
					return fmt.Errorf("lti: key %q should be %q", key, field)
				}
			}

			if seen[seenKey] {
				return fmt.Errorf("lti: key %q appears more than once", key)
			}

			seen[seenKey] = true

			var nested map[string]string
			if fields != nil {
				nested = memberFields[key]
			}

			if err := walkKeys(dec, nested); err != nil {
				return err
			}
		}
	default:
		return nil
	}

	_, err = dec.Token()

	return err
}

func reject(description string, cause error) *lti.Error {
	return lti.NewError(lti.ErrorInvalidRequest, description, cause)
}

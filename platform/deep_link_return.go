package platform

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/meitner-se/go-lti"
)

// maxDeepLinkReturnFormBytes caps the form a tool posts to Paths.DeepLinkReturn, leaving room for
// the encoding around the largest response Verify accepts.
const maxDeepLinkReturnFormBytes = MaxDeepLinkingResponseBytes + 64<<10

// ErrDeepLinkingSessionNotFound is what FindDeepLinkingSession returns, or wraps, for a response
// whose request the platform doesn't know, that has expired or that was already answered. The
// browser gets a 400 error page.
var ErrDeepLinkingSessionNotFound = lti.NewError(lti.ErrorInvalidRequest, "the deep linking request is unknown, has expired or was already answered", nil)

// UnverifiedDeepLinkingResponse holds claims of a Deep Linking response read before its signature
// is checked. Anyone can post any of them, so they only serve to look up the DeepLinkingSession
// that the response is then verified against. Each is empty when the JWT doesn't have it as a
// string, or, for Audience, a string or an array of strings.
type UnverifiedDeepLinkingResponse struct {
	// Issuer is iss: the client_id of the tool that claims to have sent the response.
	Issuer string
	// Audience is aud.
	Audience []string
	// DeploymentID is the deployment_id claim.
	DeploymentID string
	// Data is the data claim, which the tool must send back when the request had it (Deep Linking
	// 2.0 §4.5.5). An empty string counts as missing.
	Data string
}

// ParseUnverifiedDeepLinkingResponse reads iss, aud, deployment_id and data from the payload of
// rawJWT without checking its signature or anything else. It refuses a JWT that is missing, larger
// than MaxDeepLinkingResponseBytes, not three dot-separated parts or without a JSON object as its
// payload; the error is an *lti.Error.
func ParseUnverifiedDeepLinkingResponse(rawJWT string) (UnverifiedDeepLinkingResponse, error) {
	if rawJWT == "" {
		return UnverifiedDeepLinkingResponse{}, reject("deep linking response is missing", nil)
	}

	if len(rawJWT) > MaxDeepLinkingResponseBytes {
		return UnverifiedDeepLinkingResponse{}, reject("deep linking response is larger than 1 MiB", nil)
	}

	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return UnverifiedDeepLinkingResponse{}, reject("deep linking response is not a jwt", nil)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return UnverifiedDeepLinkingResponse{}, reject("deep linking response is not a jwt", err)
	}

	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil || claims == nil {
		return UnverifiedDeepLinkingResponse{}, reject("deep linking response is not a jwt", err)
	}

	return UnverifiedDeepLinkingResponse{
		Issuer:       stringClaim(claims["iss"]),
		Audience:     audienceClaim(claims["aud"]),
		DeploymentID: stringClaim(claims[lti.ClaimDeploymentID]),
		Data:         stringClaim(claims[lti.ClaimDeepLinkingData]),
	}, nil
}

// stringClaim returns raw as a string, or "" when it isn't one.
func stringClaim(raw json.RawMessage) string {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}

	return value
}

// audienceClaim returns raw as a list of strings: a single string (RFC 7519 §4.1.3) or an array of
// them. It returns nil for anything else.
func audienceClaim(raw json.RawMessage) []string {
	if single := stringClaim(raw); single != "" {
		return []string{single}
	}

	var list []string
	if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
		return nil
	}

	return list
}

// DeepLinkingResult is what HandleDeepLinkingResponse gets for a response whose session was found.
type DeepLinkingResult struct {
	// Session is what FindDeepLinkingSession returned. It is set even when Err is.
	Session DeepLinkingSession
	// Unverified are the claims Session was looked up by. Only trust them once Err is nil, and
	// prefer Session's values even then.
	Unverified UnverifiedDeepLinkingResponse
	// Response is the verified response, or nil when Err is set.
	Response *lti.DeepLinkingResponse
	// Err is Verify's error, as it returned it: an *lti.Error rejects the response, and any other
	// error, such as a tool JWKS that can't be fetched or a nonce store failure, is the platform's.
	Err error
}

// deepLinkReturn answers a Deep Linking response a tool posted (Deep Linking 2.0 §4.2). It reads
// the JWT form field from a body of at most maxDeepLinkReturnFormBytes, looks up the session by
// the unverified claims, verifies the response against it and hands the result to
// HandleDeepLinkingResponse. A response that has no session gets an error page.
func (e *endpoints) deepLinkReturn(w http.ResponseWriter, r *http.Request) {
	form, err := postedForm(w, r, maxDeepLinkReturnFormBytes)
	if err != nil {
		e.failDeepLinkReturn(w, r, lti.NewError(lti.ErrorInvalidRequest, "the request could not be read", err))

		return
	}

	rawJWT := form.Get(lti.DeepLinkingResponseField)

	unverified, err := ParseUnverifiedDeepLinkingResponse(rawJWT)
	if err != nil {
		e.failDeepLinkReturn(w, r, err)

		return
	}

	if unverified.Issuer == "" && unverified.DeploymentID == "" && unverified.Data == "" {
		e.failDeepLinkReturn(w, r, ErrDeepLinkingSessionNotFound)

		return
	}

	session, err := e.handlers.FindDeepLinkingSession(r, unverified)
	if err != nil {
		e.failDeepLinkReturn(w, r, err)

		return
	}

	response, err := e.verifier.Verify(r.Context(), rawJWT, session)
	if err != nil {
		e.report(r, err)
	}

	e.handlers.HandleDeepLinkingResponse(w, r, DeepLinkingResult{Session: session, Unverified: unverified, Response: response, Err: err})
}

func (e *endpoints) failDeepLinkReturn(w http.ResponseWriter, r *http.Request, err error) {
	e.report(r, err)
	writeErrorPage(w, err, "The content could not be added", "Start again.")
}

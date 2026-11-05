package platform

import (
	"errors"
	"net/http"
	"slices"

	"github.com/meitner-se/go-lti"
)

// errServiceTokenMissing is reported for a service request without a Bearer token. The tool gets a
// challenge without an error code, as RFC 6750 §3.1 asks.
var errServiceTokenMissing = lti.NewError(lti.ErrorInvalidToken, "the access token is missing", nil)

// errServiceScopeMissing answers a service request whose access token wasn't granted the scope the
// service needs.
var errServiceScopeMissing = lti.NewError(lti.ErrorInsufficientScope, "the access token wasn't granted the scope this service needs", nil)

// ServiceClient is the tool a request to one of the platform's LTI services comes from, as
// AuthorizeService identified it by its access token.
type ServiceClient struct {
	// ClientID is the tool's OAuth client_id, the one the access token was issued to. Required.
	ClientID string
	// Scopes are the scopes the access token was granted. A request to a service whose scope isn't
	// among them is refused as insufficient_scope.
	Scopes []lti.Scope
}

// authorizeService reads the request's Bearer token, has AuthorizeService check it, and refuses a
// client whose token was granted neither scope nor any of also. It answers a request it refuses
// itself and returns false.
func (e *endpoints) authorizeService(w http.ResponseWriter, r *http.Request, scope lti.Scope, also ...lti.Scope) (ServiceClient, bool) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		e.report(r, errServiceTokenMissing)
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, errServiceTokenMissing.Description, http.StatusUnauthorized)

		return ServiceClient{}, false
	}

	client, err := e.handlers.AuthorizeService(r, token, scope)
	if err == nil && client.ClientID == "" {
		err = errors.New("lti: AuthorizeService returned no client and no error")
	}

	if err == nil && !slices.ContainsFunc(client.Scopes, func(granted lti.Scope) bool { return granted == scope || slices.Contains(also, granted) }) {
		err = errServiceScopeMissing
	}

	if err != nil {
		e.failService(w, r, scope, err)

		return ServiceClient{}, false
	}

	return client, true
}

// failService answers a service request that failed: a rejection with OAuth 2.0's error response
// and its StatusCode, plus RFC 6750 §3's challenge for invalid_token and insufficient_scope; any
// other error with a 500 that says nothing more. A body over its limit is a 413. scope is the scope
// the service needs.
func (e *endpoints) failService(w http.ResponseWriter, r *http.Request, scope lti.Scope, err error) {
	e.report(r, err)

	var tooLarge *http.MaxBytesError
	if rejection, ok := lti.AsError(err); ok && errors.As(err, &tooLarge) {
		writeErrorResponse(w, http.StatusRequestEntityTooLarge, rejection)

		return
	}

	rejection, ok := lti.AsError(err)
	if !ok || rejection.Code == lti.ErrorServerError {
		http.Error(w, "the request could not be answered; try again", http.StatusInternalServerError)

		return
	}

	switch rejection.Code {
	case lti.ErrorInvalidToken:
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	case lti.ErrorInsufficientScope:
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+string(scope)+`"`)
	}

	writeErrorResponse(w, rejection.StatusCode(), rejection)
}

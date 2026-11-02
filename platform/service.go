package platform

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/meitner-se/go-lti"
)

// errServiceTokenMissing is reported for a service request without a Bearer token. The tool gets a
// challenge without an error code, as RFC 6750 §3.1 asks.
var errServiceTokenMissing = lti.NewError(lti.ErrorInvalidToken, "the access token is missing", nil)

// ServiceClient is the tool a request to one of the platform's LTI services comes from, as
// AuthorizeService identified it by its access token.
type ServiceClient struct {
	// ClientID is the tool's OAuth client_id, the one the access token was issued to. Required.
	ClientID string
}

// authorizeService reads the request's Bearer token and has AuthorizeService check it for scope.
// It answers a request it refuses itself and returns false.
func (e *endpoints) authorizeService(w http.ResponseWriter, r *http.Request, scope lti.Scope) (ServiceClient, bool) {
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

	if err != nil {
		e.failService(w, r, scope, err)

		return ServiceClient{}, false
	}

	return client, true
}

// failService answers a service request that failed: a rejection with OAuth 2.0's error response
// and its StatusCode, plus RFC 6750 §3's challenge for invalid_token and insufficient_scope; any
// other error with a 500 that says nothing more. scope is the scope the service needs.
func (e *endpoints) failService(w http.ResponseWriter, r *http.Request, scope lti.Scope, err error) {
	e.report(r, err)

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

	body, _ := json.Marshal(errorResponse{Error: rejection.Code, ErrorDescription: rejection.Description}) //nolint:errcheck // errchkjson: two strings always encode
	writeJSON(w, rejection.StatusCode(), body)
}

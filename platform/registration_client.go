package platform

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/meitner-se/go-lti"
)

// ErrRegistrationNotFound is what ReadRegistration or UpdateRegistration returns, or wraps, for a
// client that has no Dynamic Registration, such as one the platform deleted or one added without
// Dynamic Registration. The tool gets a 404 with OAuth 2.0's error response, as it does for another
// client's configuration endpoint.
var ErrRegistrationNotFound = lti.NewError(lti.ErrorInvalidRequest, "the client is unknown", nil)

// ErrRegistrationForbidden is what ReadRegistration or UpdateRegistration returns, or wraps, for a
// tool the platform doesn't let read or update its registration, such as a disabled one. The tool
// gets a 403 with OAuth 2.0's error response.
var ErrRegistrationForbidden = lti.NewError(lti.ErrorAccessDenied, "the tool may not manage its registration", nil)

// errRegistrationClientID refuses an update whose client_id isn't the client's own: a platform
// never changes a registration's client_id (LTI Dynamic Registration 1.0 §4.1).
var errRegistrationClientID = invalidMetadata("client_id must be the client's own; a registration's client_id never changes", nil)

// readRegistration answers a tool's GET of its client configuration endpoint (LTI Dynamic
// Registration 1.0 §4.1) with its registration as ReadRegistration returns it, any pending update
// applied, in the registration response's shape.
func (e *endpoints) readRegistration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	// A read asks for the read-only scope, which the read-write one also allows (§4.2).
	scope := lti.ScopeRegistrationReadOnly

	client, ok := e.authorizeService(w, r, scope, lti.ScopeRegistration)
	if !ok {
		return
	}

	if !e.ownRegistration(w, r, scope, client) {
		return
	}

	response, err := e.handlers.ReadRegistration(r, client)
	e.answerRegistration(w, r, scope, client, response, err)
}

// updateRegistration answers a tool's PUT of its client configuration endpoint (LTI Dynamic
// Registration 1.0 §4.1). It checks the body as ParseRegistration checks a registration, refuses a
// client_id other than the client's, hands the update to UpdateRegistration, and answers with the
// registration it returns, reflecting the pending update.
func (e *endpoints) updateRegistration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeRegistration

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	if !e.ownRegistration(w, r, scope, client) {
		return
	}

	// One byte over the cap, so ParseRegistration sees an oversized body and refuses it.
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRegistrationBytes+1))
	if err != nil {
		e.failService(w, r, scope, invalidMetadata("the registration request could not be read", err))

		return
	}

	reg, err := ParseRegistration(body)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	if err := checkRegistrationClientID(body, client.ClientID); err != nil {
		e.failService(w, r, scope, err)

		return
	}

	response, err := e.handlers.UpdateRegistration(r, client, reg)
	e.answerRegistration(w, r, scope, client, response, err)
}

// ownRegistration checks that the path's client ID is the client's own. It answers any other one,
// as for an unknown client, with a 404 that doesn't tell whether that client exists, and returns
// false.
func (e *endpoints) ownRegistration(w http.ResponseWriter, r *http.Request, scope lti.Scope, client ServiceClient) bool {
	if r.PathValue("client") != client.ClientID {
		e.failRegistrationClient(w, r, scope, ErrRegistrationNotFound)

		return false
	}

	return true
}

// checkRegistrationClientID refuses an update whose body has a client_id other than clientID. One
// without a client_id updates the client's own registration.
func checkRegistrationClientID(body []byte, clientID string) error {
	// ParseRegistration has decoded body as a JSON object.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return invalidMetadata("registration request is not valid client metadata json", err)
	}

	raw, ok := members["client_id"]
	if !ok {
		return nil
	}

	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		return invalidMetadata("client_id must be a string", err)
	}

	if got != clientID {
		return errRegistrationClientID
	}

	return nil
}

// answerRegistration answers with a hook's registration, with the client's client_id and its
// registration_client_uri, or with the hook's error.
func (e *endpoints) answerRegistration(w http.ResponseWriter, r *http.Request, scope lti.Scope, client ServiceClient, response RegistrationResponse, err error) {
	if err == nil && response.ClientID != "" && response.ClientID != client.ClientID {
		// The hook should have answered the client's own registration; never let another through.
		err = ErrRegistrationForbidden
	}

	if err != nil {
		e.failRegistrationClient(w, r, scope, err)

		return
	}

	response.ClientID = client.ClientID

	response.RegistrationClientURI, err = e.config.RegistrationClientURL(client.ClientID)
	if err != nil {
		// A client ID no URL path can carry has no configuration endpoint.
		e.failRegistrationClient(w, r, scope, ErrRegistrationNotFound)

		return
	}

	e.writeService(w, r, scope, http.StatusOK, "application/json", response)
}

// failRegistrationClient answers ErrRegistrationNotFound with a 404 and ErrRegistrationForbidden
// with a 403, and any other error as failService does.
func (e *endpoints) failRegistrationClient(w http.ResponseWriter, r *http.Request, scope lti.Scope, err error) {
	for _, answer := range []struct {
		target *lti.Error
		status int
	}{
		{ErrRegistrationNotFound, http.StatusNotFound},
		{ErrRegistrationForbidden, http.StatusForbidden},
	} {
		if errors.Is(err, answer.target) {
			e.report(r, err)
			writeErrorResponse(w, answer.status, answer.target)

			return
		}
	}

	e.failService(w, r, scope, err)
}

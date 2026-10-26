package platform

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/meitner-se/go-lti"
)

// OpenIDConfigurationPath is where an issuer serves its OpenID configuration (OpenID Connect
// Discovery 1.0 §4). The issuer plus this path is the openid_configuration to pass to
// RegistrationInitiationURL.
const OpenIDConfigurationPath = "/.well-known/openid-configuration"

// errRegistrationNotSaved answers a registration the Registrar failed to save for a reason of its own.
var errRegistrationNotSaved = lti.NewError(lti.ErrorServerError, "the registration could not be saved; try again", nil)

// OpenIDConfigurationHandler returns a handler that serves the platform's OpenID configuration to
// any origin, cacheable for five minutes. It fails when the config can't make one.
func (c Config) OpenIDConfigurationHandler() (http.Handler, error) {
	document, err := c.OpenIDConfiguration()
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(document) //nolint:errchkjson // errcheck requires the check outside _test.go files
	if err != nil {
		return nil, err
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		header := w.Header()
		header.Set("Cache-Control", "public, max-age=300")
		header.Set("Access-Control-Allow-Origin", "*")
		writeJSON(w, http.StatusOK, body)
	}), nil
}

// Registrar saves a tool that sent a valid Dynamic Registration.
type Registrar interface {
	// Register saves the tool reg describes and returns what the platform granted it. token is the
	// registration token the tool sent as a Bearer token, or "" when it sent none. An *lti.Error,
	// such as lti.ErrorInvalidToken for a refused token, is sent to the tool as it is; any other
	// error is answered as a server_error that says nothing more.
	Register(ctx context.Context, token string, reg *Registration) (RegistrationGrant, error)
}

// RegistrationEndpoint serves the registration endpoint of LTI Dynamic Registration 1.0 §3.5–§3.6.
type RegistrationEndpoint struct {
	Registrar Registrar
	// OnError, when set, is called with every error the tool is answered with, for logging.
	OnError func(r *http.Request, err error)
}

// ServeHTTP answers a POSTed registration. It reads the registration token from the
// Authorization header's Bearer scheme, refuses a body over MaxRegistrationBytes, checks the body
// with ParseRegistration and hands it to the Registrar. A saved registration is answered 201
// Created (OpenID Connect Registration §3.2) with Response(grant); a rejection with RFC 7591
// §3.2.2's error response, plus a Bearer challenge for invalid_token (RFC 6750 §3). Every answer
// has Cache-Control: no-store.
func (e *RegistrationEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	// One byte over the cap, so ParseRegistration sees an oversized body and refuses it.
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRegistrationBytes+1))
	if err != nil {
		e.fail(w, r, lti.NewError(lti.ErrorInvalidClientMetadata, "the registration request could not be read", err))

		return
	}

	reg, err := ParseRegistration(body)
	if err != nil {
		e.fail(w, r, err)

		return
	}

	grant, err := e.Registrar.Register(r.Context(), bearerToken(r.Header.Get("Authorization")), reg)
	if err != nil {
		e.fail(w, r, err)

		return
	}

	encoded, err := json.Marshal(reg.Response(grant))
	if err != nil {
		e.fail(w, r, err)

		return
	}

	writeJSON(w, http.StatusCreated, encoded)
}

// registrationError is RFC 7591 §3.2.2's error response.
//
//nolint:tagliatelle // RFC 7591 §3.2.2 defines snake_case keys
type registrationError struct {
	Error            lti.ErrorCode `json:"error"`
	ErrorDescription string        `json:"error_description"`
}

func (e *RegistrationEndpoint) fail(w http.ResponseWriter, r *http.Request, err error) {
	if e.OnError != nil {
		e.OnError(r, err)
	}

	rejection, ok := lti.AsError(err)
	if !ok {
		rejection = errRegistrationNotSaved
	}

	if rejection.Code == lti.ErrorInvalidToken {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}

	body, _ := json.Marshal(registrationError{Error: rejection.Code, ErrorDescription: rejection.Description}) //nolint:errcheck // errchkjson: two strings always encode
	writeJSON(w, rejection.StatusCode(), body)
}

// bearerToken returns the token of an Authorization header with the Bearer scheme, whose name is
// case-insensitive (RFC 7235 §2.1), or "" without one.
func bearerToken(header string) string {
	scheme, token, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}

	return strings.TrimSpace(token)
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body) //nolint:errcheck // the response has started; there is nothing left to report a write error to
}

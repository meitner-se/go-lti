package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/meitner-se/go-lti"
)

// errRegistrationNotSaved answers a registration the Registrar failed to save for a reason of its own.
var errRegistrationNotSaved = lti.NewError(lti.ErrorServerError, "the registration could not be saved; try again", nil)

// Handlers are the platform's own parts of the endpoints NewHandler serves.
type Handlers struct {
	// Registrar saves the tools that register through Dynamic Registration. Required.
	Registrar Registrar
	// OnError, when set, is called with every error a tool is answered with, for logging.
	OnError func(r *http.Request, err error)
}

// Registrar saves a tool that sent a valid Dynamic Registration.
type Registrar interface {
	// Register saves the tool reg describes and returns what the platform granted it. token is the
	// registration token the tool sent as a Bearer token, or "" when it sent none. An *lti.Error,
	// such as lti.ErrorInvalidToken for a refused token, is sent to the tool as it is; any other
	// error is answered as a server_error that says nothing more.
	Register(ctx context.Context, token string, reg *Registration) (RegistrationGrant, error)
}

// NewHandler returns an http.Handler that serves the platform's endpoints at the issuer's path
// plus each endpoint's path, as Config.Endpoints lists them:
//
//   - GET PathOpenIDConfiguration: the OpenID configuration, to any origin, cacheable for five
//     minutes.
//   - POST PathRegistration: Dynamic Registration (LTI Dynamic Registration 1.0 §3.5–§3.6).
//
// Mount it to receive every request under the issuer's path, with the path unchanged. Any other
// path is a 404 and any other method a 405. It fails when cfg can't make an OpenID configuration
// or h has no Registrar.
func NewHandler(cfg Config, h Handlers) (http.Handler, error) {
	if h.Registrar == nil {
		return nil, errors.New("lti: the handler needs a registrar")
	}

	document, err := cfg.OpenIDConfiguration()
	if err != nil {
		return nil, err
	}

	discovery, err := json.Marshal(document) //nolint:errchkjson // errcheck requires the check outside _test.go files
	if err != nil {
		return nil, err
	}

	issuer, err := url.Parse(strings.TrimSuffix(cfg.Issuer, "/"))
	if err != nil {
		return nil, err
	}

	// A ServeMux pattern gives braces a meaning of their own.
	if strings.ContainsAny(issuer.Path, "{}") {
		return nil, errors.New("lti: the issuer's path must not contain braces")
	}

	mux := http.NewServeMux()
	mux.Handle("GET "+issuer.Path+PathOpenIDConfiguration, openIDConfigurationHandler(discovery))
	mux.Handle("POST "+issuer.Path+PathRegistration, &registrationEndpoint{registrar: h.Registrar, onError: h.OnError})

	return mux, nil
}

func openIDConfigurationHandler(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		header := w.Header()
		header.Set("Cache-Control", "public, max-age=300")
		header.Set("Access-Control-Allow-Origin", "*")
		writeJSON(w, http.StatusOK, body)
	})
}

// registrationEndpoint answers a POSTed registration. It reads the registration token from the
// Authorization header's Bearer scheme, refuses a body over MaxRegistrationBytes, checks the body
// with ParseRegistration and hands it to the Registrar. A saved registration is answered 201
// Created (OpenID Connect Registration §3.2) with Response(grant); a rejection with RFC 7591
// §3.2.2's error response, plus a Bearer challenge for invalid_token (RFC 6750 §3). Every answer
// has Cache-Control: no-store.
type registrationEndpoint struct {
	registrar Registrar
	onError   func(r *http.Request, err error)
}

func (e *registrationEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

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

	grant, err := e.registrar.Register(r.Context(), bearerToken(r.Header.Get("Authorization")), reg)
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

func (e *registrationEndpoint) fail(w http.ResponseWriter, r *http.Request, err error) {
	if e.onError != nil {
		e.onError(r, err)
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

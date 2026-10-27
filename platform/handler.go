package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/meitner-se/go-lti"
)

// maxAuthenticationFormBytes caps a POSTed authentication request; ParseAuthenticationRequest caps
// each parameter at 4 KiB.
const maxAuthenticationFormBytes = 64 << 10

var (
	// errRegistrationTokenMissing answers a registration without a Bearer token when the platform
	// requires one.
	errRegistrationTokenMissing = lti.NewError(lti.ErrorInvalidToken, "the registration token is missing", nil)
	// errRegistrationNotSaved answers a registration Register failed to save for a reason of its own.
	errRegistrationNotSaved = lti.NewError(lti.ErrorServerError, "the registration could not be saved; try again", nil)
	// errMessageHintMissing answers an authentication request without an lti_message_hint, which a
	// platform can't tie to a launch.
	errMessageHintMissing = lti.NewError(lti.ErrorInvalidRequest, "lti_message_hint is missing", nil)
)

// Handlers are the platform's own parts of the endpoints NewHandler serves.
type Handlers struct {
	// Register saves a tool that sent a valid Dynamic Registration and returns what the platform
	// granted it. token is the registration token the tool sent as a Bearer token, or "" when it
	// sent none. An *lti.Error, such as lti.ErrorInvalidToken for a refused token, is sent to the
	// tool as it is; any other error is answered as a server_error that says nothing more. Required.
	Register func(ctx context.Context, token string, reg *Registration) (RegistrationGrant, error)
	// RequireToken refuses a registration without a Bearer token as invalid_token, before Register
	// is called. The spec leaves the token to the platform, so it is off by default.
	RequireToken bool
	// Keys sign the id_tokens of launches and are published at Paths.JWKS. Set Keys and Launch
	// together to serve the authorization and JWKS endpoints.
	Keys lti.Keys
	// Launch returns the launch an authentication request is for. The platform redeems
	// req.MessageHint with its own state, and checks that a session in r, when there is one,
	// belongs to the launch's user (1EdTech Security Framework §5.1.1.3). req always has an
	// lti_message_hint, but may have failed ParseAuthenticationRequest's other checks: the launch
	// tells where that error can be sent.
	//
	// Return a nil *Launch with an error for a hint that can't be redeemed, such as an
	// *lti.Error with lti.ErrorLoginRequired for one that expired or was already used; the browser
	// gets an error page. Return the launch together with an error, such as one for a session that
	// belongs to another user, to send the error to the launch's tool.
	Launch func(r *http.Request, req *AuthenticationRequest) (*Launch, error)
	// ToolKeys resolve the keys tools sign Deep Linking responses with, such as a *jwks.Fetcher.
	// Set ToolKeys, Nonces, FindDeepLinkingSession and HandleDeepLinkingResponse together to serve
	// the Deep Linking return.
	ToolKeys lti.KeySource
	// Nonces reject replayed Deep Linking responses, such as an *lti.MemoryNonceStore.
	Nonces lti.NonceStore
	// FindDeepLinkingSession returns the session a posted Deep Linking response answers, from the
	// platform's own state, such as the request it stored under the data value it sent, or the
	// record behind the browser's session cookie in r. Nothing in unverified has been checked yet,
	// so use it only as a lookup key; data is optional in the spec, so don't rely on it alone.
	//
	// Return an error that is or wraps ErrDeepLinkingSessionNotFound for a request that is unknown,
	// has expired or was already answered; the browser gets a 400 error page. Any other error, such
	// as the platform's storage being down, gets a 500 error page.
	FindDeepLinkingSession func(r *http.Request, unverified UnverifiedDeepLinkingResponse) (DeepLinkingSession, error)
	// HandleDeepLinkingResponse answers the browser once a session was found: with the verified
	// response, or with the session and Verify's error, so that the platform can record the error
	// and still send the user back to where they started. It writes the response itself; a redirect
	// should carry Cache-Control: no-store, as go-lti's own answers do.
	//
	// Verify only checks what the specs require. A platform with policies of its own, such as
	// items only from the tool's domains (see OnToolDomains), applies them here.
	HandleDeepLinkingResponse func(w http.ResponseWriter, r *http.Request, result DeepLinkingResult)
	// Logger, when set, logs every error a tool or browser is answered with: a rejection at Warn
	// with its code, any other error at Error.
	Logger *slog.Logger
	// OnError, when set, is called with every error a tool or browser is answered with.
	OnError func(r *http.Request, err error)
}

// NewHandler returns an http.Handler that serves the platform's endpoints at the issuer's path
// plus each endpoint's path, as Config.Endpoints lists them:
//
//   - GET PathOpenIDConfiguration: the OpenID configuration, to any origin, cacheable for five
//     minutes.
//   - POST Paths.Registration: Dynamic Registration (LTI Dynamic Registration 1.0 §3.5–§3.6).
//   - GET and POST Paths.Authorization: the OIDC authentication request of a launch (1EdTech
//     Security Framework §5.1.1.2), answered with a signed id_token. Served with Keys and Launch.
//   - GET Paths.JWKS: the platform's public keys, to any origin, cacheable for five minutes.
//     Served with Keys and Launch.
//   - POST Paths.DeepLinkReturn: the Deep Linking response a tool posts back (Deep Linking 2.0
//     §4.2), verified and handed to HandleDeepLinkingResponse. Served with ToolKeys, Nonces,
//     FindDeepLinkingSession and HandleDeepLinkingResponse.
//
// Mount it to receive every request under the issuer's path, with the path unchanged. Any other
// path is a 404 and any other method a 405. An error page sent to a browser is plain text with
// Cache-Control: no-store and a Content-Security-Policy that allows nothing. It fails when cfg
// can't make an OpenID configuration, h has no Register, h has only one of Keys and Launch, or h
// has only some of the Deep Linking fields.
func NewHandler(cfg Config, h Handlers) (http.Handler, error) {
	if h.Register == nil {
		return nil, errors.New("lti: the handler needs a Register function")
	}

	if (h.Keys == nil) != (h.Launch == nil) {
		return nil, errors.New("lti: the handler needs both Keys and Launch to serve launches, or neither")
	}

	deepLinking := []bool{h.ToolKeys != nil, h.Nonces != nil, h.FindDeepLinkingSession != nil, h.HandleDeepLinkingResponse != nil}
	if slices.Contains(deepLinking, true) && slices.Contains(deepLinking, false) {
		return nil, errors.New("lti: the handler needs all of ToolKeys, Nonces, FindDeepLinkingSession and HandleDeepLinkingResponse to serve the deep linking return, or none")
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

	e := &endpoints{handlers: h, launcher: nil, verifier: nil}

	mux := http.NewServeMux()
	mux.Handle("GET "+issuer.Path+PathOpenIDConfiguration, openIDConfigurationHandler(discovery))
	mux.HandleFunc("POST "+issuer.Path+cfg.Paths.Registration, e.register)

	if h.Keys != nil {
		e.launcher, err = NewLauncher(cfg, h.Keys)
		if err != nil {
			return nil, err
		}

		mux.HandleFunc("GET "+issuer.Path+cfg.Paths.Authorization, e.authorize)
		mux.HandleFunc("POST "+issuer.Path+cfg.Paths.Authorization, e.authorize)
		mux.HandleFunc("GET "+issuer.Path+cfg.Paths.JWKS, e.jwks)
	}

	if h.ToolKeys != nil {
		e.verifier, err = NewDeepLinkingVerifier(cfg, h.ToolKeys, h.Nonces)
		if err != nil {
			return nil, err
		}

		mux.HandleFunc("POST "+issuer.Path+cfg.Paths.DeepLinkReturn, e.deepLinkReturn)
	}

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

type endpoints struct {
	handlers Handlers
	launcher *Launcher
	verifier *DeepLinkingVerifier
}

// register answers a POSTed registration. It reads the registration token from the
// Authorization header's Bearer scheme, refuses a body over MaxRegistrationBytes, checks the body
// with ParseRegistration and hands it to Register. A saved registration is answered 201
// Created (OpenID Connect Registration §3.2) with Response(grant); a rejection with RFC 7591
// §3.2.2's error response, plus a Bearer challenge for invalid_token (RFC 6750 §3). Every answer
// has Cache-Control: no-store.
func (e *endpoints) register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	// One byte over the cap, so ParseRegistration sees an oversized body and refuses it.
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRegistrationBytes+1))
	if err != nil {
		e.failRegistration(w, r, lti.NewError(lti.ErrorInvalidClientMetadata, "the registration request could not be read", err))

		return
	}

	reg, err := ParseRegistration(body)
	if err != nil {
		e.failRegistration(w, r, err)

		return
	}

	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" && e.handlers.RequireToken {
		e.failRegistration(w, r, errRegistrationTokenMissing)

		return
	}

	grant, err := e.handlers.Register(r.Context(), token, reg)
	if err != nil {
		e.failRegistration(w, r, err)

		return
	}

	encoded, err := json.Marshal(reg.Response(grant))
	if err != nil {
		e.failRegistration(w, r, err)

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

func (e *endpoints) failRegistration(w http.ResponseWriter, r *http.Request, err error) {
	e.report(r, err)

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

// authorize answers a tool's OIDC authentication request with a form that posts the signed
// id_token to the tool's redirect_uri. A GET carries the request in the query, a POST in the form
// body; a POST's query is ignored, so no parameter can come from both.
//
// Launch runs once for every request with an lti_message_hint, even one that is otherwise
// invalid, so that the error can go to a redirect_uri the launch has registered. An error the tool
// can't be told about gets an error page.
func (e *endpoints) authorize(w http.ResponseWriter, r *http.Request) {
	form, err := authenticationForm(w, r)
	if err != nil {
		e.failLaunch(w, r, nil, nil, lti.NewError(lti.ErrorInvalidRequest, "the request could not be read", err))

		return
	}

	req, parseErr := ParseAuthenticationRequest(form)
	if req.MessageHint == "" {
		e.failLaunch(w, r, req, nil, cmpErr(parseErr, errMessageHintMissing))

		return
	}

	launch, err := e.handlers.Launch(r, req)
	if launch == nil {
		e.failLaunch(w, r, req, nil, cmpErr(err, errors.New("lti: Launch returned no launch and no error")))

		return
	}

	if err = cmpErr(err, parseErr); err != nil {
		e.failLaunch(w, r, req, &launch.Tool, err)

		return
	}

	response, err := e.launcher.Respond(r.Context(), req, *launch)
	if err != nil {
		e.failLaunch(w, r, req, &launch.Tool, err)

		return
	}

	response.ServeHTTP(w, r)
}

// failLaunch answers a launch that failed at the tool's redirect_uri when tool is known and the
// request's client_id and redirect_uri are registered for it, and with an error page otherwise.
func (e *endpoints) failLaunch(w http.ResponseWriter, r *http.Request, req *AuthenticationRequest, tool *Tool, err error) {
	e.report(r, err)

	if tool != nil {
		if response, ok := e.launcher.RespondError(req, *tool, err); ok {
			response.ServeHTTP(w, r)

			return
		}
	}

	writeErrorPage(w, err, "The launch could not be completed", "Start it again.")
}

// writeErrorPage answers a browser with a plain-text page that says what failed: with a
// rejection's description and status, or, for any other error, with nothing more than retry and a
// 500. It can't be cached or load anything.
func writeErrorPage(w http.ResponseWriter, err error, what, retry string) {
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")

	if rejection, ok := lti.AsError(err); ok && rejection.Code != lti.ErrorServerError {
		http.Error(w, fmt.Sprintf("%s: %s.", what, rejection.Description), rejection.StatusCode())

		return
	}

	http.Error(w, what+". "+retry, http.StatusInternalServerError)
}

// jwks serves the platform's public keys: the current signing key and, during a rotation, the next.
func (e *endpoints) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := e.launcher.JWKS(r.Context())
	if err != nil {
		e.report(r, err)
		http.Error(w, "the keys could not be listed", http.StatusInternalServerError)

		return
	}

	body, err := json.Marshal(set) //nolint:errchkjson // errcheck requires the check outside _test.go files
	if err != nil {
		e.report(r, err)
		http.Error(w, "the keys could not be listed", http.StatusInternalServerError)

		return
	}

	header := w.Header()
	header.Set("Cache-Control", "public, max-age=300")
	header.Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, body)
}

// report hands err to the Logger and OnError.
func (e *endpoints) report(r *http.Request, err error) {
	if logger := e.handlers.Logger; logger != nil {
		if rejection, ok := lti.AsError(err); ok && rejection.Code != lti.ErrorServerError {
			logger.WarnContext(
				r.Context(), "lti request rejected",
				slog.String("path", r.URL.Path),
				slog.String("code", string(rejection.Code)),
				slog.Any("error", err),
			)
		} else {
			logger.ErrorContext(
				r.Context(), "lti request failed",
				slog.String("path", r.URL.Path),
				slog.Any("error", err),
			)
		}
	}

	if e.handlers.OnError != nil {
		e.handlers.OnError(r, err)
	}
}

// authenticationForm reads the authentication request from the query of a GET or the body of a
// POST.
func authenticationForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if r.Method == http.MethodGet {
		return r.URL.Query(), nil
	}

	return postedForm(w, r, maxAuthenticationFormBytes)
}

// postedForm reads the form in the body of a POST of at most limit bytes, ignoring the query.
func postedForm(w http.ResponseWriter, r *http.Request, limit int64) (url.Values, error) {
	// ParseForm also parses the query, so a malformed query would reject a valid body; parse a copy without it.
	bodyOnly := r.Clone(r.Context())
	bodyOnly.URL.RawQuery = ""
	bodyOnly.Body = http.MaxBytesReader(w, r.Body, limit)

	if err := bodyOnly.ParseForm(); err != nil {
		return nil, err
	}

	return bodyOnly.PostForm, nil
}

// cmpErr returns the first of errs that isn't nil.
func cmpErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	return nil
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

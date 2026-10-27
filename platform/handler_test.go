package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/jwks"
	"github.com/meitner-se/go-lti/ltitest"
)

// granting grants client-1 to registrations with token-1 and refuses every other token. It
// records the tokens it was called with.
func granting(tokens *[]string) func(context.Context, string, *Registration) (RegistrationGrant, error) {
	return func(_ context.Context, token string, _ *Registration) (RegistrationGrant, error) {
		*tokens = append(*tokens, token)

		if token != "token-1" {
			return RegistrationGrant{}, lti.NewError(lti.ErrorInvalidToken, "the registration token is unknown or used", nil)
		}

		return RegistrationGrant{ClientID: "client-1", DeploymentID: "", Scopes: nil, Claims: []string{"iss", "sub"}}, nil
	}
}

func newTestHandler(t *testing.T, h Handlers) http.Handler {
	t.Helper()

	handler, err := NewHandler(createTestConfig(), h)
	require.NoError(t, err)

	return handler
}

func serve(t *testing.T, handler http.Handler, method, path, authorization, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	return w
}

func postRegistration(t *testing.T, handler http.Handler, authorization, body string) *httptest.ResponseRecorder {
	t.Helper()

	return serve(t, handler, http.MethodPost, "/lti/register", authorization, body)
}

func requireRegistrationErrorResponse(t *testing.T, w *httptest.ResponseRecorder, status int, code lti.ErrorCode, description string) {
	t.Helper()

	require.Equal(t, status, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, map[string]any{"error": string(code), "error_description": description}, got)
}

func TestNewHandler(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, Handlers{Register: granting(&[]string{}), OnError: nil})

	t.Run("serves the OpenID configuration under the issuer's path", func(t *testing.T) {
		t.Parallel()

		w := serve(t, handler, http.MethodGet, "/lti"+PathOpenIDConfiguration, "", "")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "public, max-age=300", w.Header().Get("Cache-Control"))

		want, err := createTestConfig().OpenIDConfiguration()
		require.NoError(t, err)

		var got OpenIDConfiguration
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, want, got)
		assert.Equal(t, "https://platform.example.com/lti/register", got.RegistrationEndpoint)
	})

	t.Run("answers HEAD for the OpenID configuration", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, http.StatusOK, serve(t, handler, http.MethodHead, "/lti"+PathOpenIDConfiguration, "", "").Code)
	})

	t.Run("refuses other methods", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, http.StatusMethodNotAllowed, serve(t, handler, http.MethodPost, "/lti"+PathOpenIDConfiguration, "", "").Code)
		assert.Equal(t, http.StatusMethodNotAllowed, serve(t, handler, http.MethodGet, "/lti/register", "", "").Code)
	})

	t.Run("serves nothing else", func(t *testing.T) {
		t.Parallel()

		for _, path := range []string{"/register", PathOpenIDConfiguration, "/lti", "/lti/unknown", "/other/register"} {
			assert.Equal(t, http.StatusNotFound, serve(t, handler, http.MethodGet, path, "", "").Code, path)
		}
	})

	t.Run("serves registration at the configured path", func(t *testing.T) {
		t.Parallel()

		cfg := createTestConfig()
		cfg.Paths.Registration = "/dynamic-registration"

		var tokens []string

		customHandler, err := NewHandler(cfg, Handlers{Register: granting(&tokens), OnError: nil})
		require.NoError(t, err)

		body := string(encodeRegistration(t, createTestRegistrationJSON()))
		assert.Equal(t, http.StatusCreated, serve(t, customHandler, http.MethodPost, "/lti/dynamic-registration", "Bearer token-1", body).Code)
		assert.Equal(t, http.StatusNotFound, serve(t, customHandler, http.MethodPost, "/lti/register", "Bearer token-1", body).Code)
		assert.Equal(t, []string{"token-1"}, tokens)
	})

	t.Run("serves at the root for an issuer without a path", func(t *testing.T) {
		t.Parallel()

		cfg := createTestConfig()
		cfg.Issuer = "https://platform.example.com/"

		rootHandler, err := NewHandler(cfg, Handlers{Register: granting(&[]string{}), OnError: nil})
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, serve(t, rootHandler, http.MethodGet, PathOpenIDConfiguration, "", "").Code)
	})

	t.Run("fails without Register or a token endpoint, or with braces in the issuer's path", func(t *testing.T) {
		t.Parallel()

		_, err := NewHandler(createTestConfig(), Handlers{Register: nil, OnError: nil})
		require.Error(t, err)

		noToken := createTestConfig()
		noToken.TokenEndpoint = ""
		_, err = NewHandler(noToken, Handlers{Register: granting(&[]string{}), OnError: nil})
		require.Error(t, err)

		braces := createTestConfig()
		braces.Issuer = "https://platform.example.com/{lti}"
		_, err = NewHandler(braces, Handlers{Register: granting(&[]string{}), OnError: nil})
		require.Error(t, err)
	})
}

func TestNewHandler_Registration(t *testing.T) {
	t.Parallel()

	t.Run("a registration is answered 201 with what was granted", func(t *testing.T) {
		t.Parallel()

		var tokens []string

		handler := newTestHandler(t, Handlers{Register: granting(&tokens), OnError: nil})

		w := postRegistration(t, handler, "bearer token-1", string(encodeRegistration(t, createTestRegistrationJSON())))

		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Equal(t, []string{"token-1"}, tokens)

		var got map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, "client-1", got["client_id"])
		assert.Equal(t, "Virtuell trädgård", got["client_name#sv"])
		assert.NotContains(t, got, "scope", "no scope was granted")
	})

	t.Run("a refused token is invalid_token with a Bearer challenge", func(t *testing.T) {
		t.Parallel()

		handler := newTestHandler(t, Handlers{Register: granting(&[]string{}), OnError: nil})

		w := postRegistration(t, handler, "Bearer used", string(encodeRegistration(t, createTestRegistrationJSON())))

		requireRegistrationErrorResponse(t, w, http.StatusUnauthorized, lti.ErrorInvalidToken, "the registration token is unknown or used")
		assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
	})

	t.Run("a registration without a Bearer token reaches Register with an empty token", func(t *testing.T) {
		t.Parallel()

		for _, authorization := range []string{"", "Basic dXNlcjpwYXNz", "Bearer", "token-1"} {
			var tokens []string

			handler := newTestHandler(t, Handlers{Register: granting(&tokens), OnError: nil})

			w := postRegistration(t, handler, authorization, string(encodeRegistration(t, createTestRegistrationJSON())))

			assert.Equal(t, http.StatusUnauthorized, w.Code, authorization)
			assert.Equal(t, []string{""}, tokens, authorization)
		}
	})

	t.Run("an invalid registration is refused without calling Register", func(t *testing.T) {
		t.Parallel()

		var (
			tokens []string
			logged []error
		)

		handler := newTestHandler(t, Handlers{
			Register: granting(&tokens),
			OnError:  func(_ *http.Request, err error) { logged = append(logged, err) },
		})

		body := createTestRegistrationJSON()
		body["grant_types"] = []string{"implict", "client_credentials"}

		w := postRegistration(t, handler, "Bearer token-1", string(encodeRegistration(t, body)))

		requireRegistrationErrorResponse(t, w, http.StatusBadRequest, lti.ErrorInvalidClientMetadata, "grant_types must include implicit and client_credentials")
		assert.Empty(t, w.Header().Get("WWW-Authenticate"))
		assert.Empty(t, tokens)
		require.Len(t, logged, 1)
	})

	t.Run("a body over MaxRegistrationBytes is refused", func(t *testing.T) {
		t.Parallel()

		var tokens []string

		handler := newTestHandler(t, Handlers{Register: granting(&tokens), OnError: nil})

		body := createTestRegistrationJSON()
		body["contacts"] = []string{strings.Repeat("a", MaxRegistrationBytes)}

		w := postRegistration(t, handler, "Bearer token-1", string(encodeRegistration(t, body)))

		requireRegistrationErrorResponse(t, w, http.StatusBadRequest, lti.ErrorInvalidClientMetadata, "registration request is larger than 1 MiB")
		assert.Empty(t, tokens)
	})

	t.Run("RequireToken refuses a registration without a token before Register", func(t *testing.T) {
		t.Parallel()

		var tokens []string

		handler := newTestHandler(t, Handlers{Register: granting(&tokens), RequireToken: true})
		body := string(encodeRegistration(t, createTestRegistrationJSON()))

		w := postRegistration(t, handler, "", body)

		requireRegistrationErrorResponse(t, w, http.StatusUnauthorized, lti.ErrorInvalidToken, "the registration token is missing")
		assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
		assert.Empty(t, tokens)

		assert.Equal(t, http.StatusCreated, postRegistration(t, handler, "Bearer token-1", body).Code)
		assert.Equal(t, []string{"token-1"}, tokens)
	})

	t.Run("Logger logs rejections at warn and failures at error", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer

		handler := newTestHandler(t, Handlers{
			Register: func(_ context.Context, token string, _ *Registration) (RegistrationGrant, error) {
				if token == "broken" {
					return RegistrationGrant{}, errors.New("database down")
				}

				return RegistrationGrant{}, lti.NewError(lti.ErrorInvalidToken, "unknown token", nil)
			},
			Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
		})
		body := string(encodeRegistration(t, createTestRegistrationJSON()))

		postRegistration(t, handler, "Bearer unknown", body)
		postRegistration(t, handler, "Bearer broken", body)

		lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
		require.Len(t, lines, 2)

		var rejected, failed map[string]any
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &rejected))
		require.NoError(t, json.Unmarshal([]byte(lines[1]), &failed))

		assert.Equal(t, "WARN", rejected["level"])
		assert.Equal(t, "lti request rejected", rejected["msg"])
		assert.Equal(t, "invalid_token", rejected["code"])
		assert.Equal(t, "/lti/register", rejected["path"])

		assert.Equal(t, "ERROR", failed["level"])
		assert.Equal(t, "lti request failed", failed["msg"])
		assert.Equal(t, "database down", failed["error"])
	})

	t.Run("a Register failure is a server_error that says nothing more", func(t *testing.T) {
		t.Parallel()

		var logged []error

		failure := errors.New("database connection refused at 10.0.0.12")
		handler := newTestHandler(t, Handlers{
			Register: func(context.Context, string, *Registration) (RegistrationGrant, error) {
				return RegistrationGrant{}, failure
			},
			OnError: func(_ *http.Request, err error) { logged = append(logged, err) },
		})

		w := postRegistration(t, handler, "Bearer token-1", string(encodeRegistration(t, createTestRegistrationJSON())))

		requireRegistrationErrorResponse(t, w, http.StatusInternalServerError, lti.ErrorServerError, "the registration could not be saved; try again")
		assert.Equal(t, []error{failure}, logged)
	})
}

// launchHandler serves launches with launch, recording the message hints it was called with.
func launchHandler(t *testing.T, hints *[]string, launch func(r *http.Request, req *AuthenticationRequest) (*Launch, error)) http.Handler {
	t.Helper()

	return newTestHandler(t, Handlers{
		Register: granting(&[]string{}),
		Keys:     ltitest.NewKeys(t, ltitest.NewSigningKey(t)),
		Launch: func(r *http.Request, req *AuthenticationRequest) (*Launch, error) {
			*hints = append(*hints, req.MessageHint)

			return launch(r, req)
		},
	})
}

func launchingTestLaunch(*http.Request, *AuthenticationRequest) (*Launch, error) {
	launch := createTestLaunch()

	return &launch, nil
}

// postedFields returns the hidden fields of an auto-submitting form page and the URL it posts to.
func postedFields(t *testing.T, w *httptest.ResponseRecorder) (string, map[string]string) {
	t.Helper()

	action := regexp.MustCompile(`<form method="post" action="([^"]*)">`).FindStringSubmatch(w.Body.String())
	require.Len(t, action, 2, w.Body.String())

	fields := map[string]string{}
	for _, input := range hiddenInput.FindAllStringSubmatch(w.Body.String(), -1) {
		fields[input[1]] = html.UnescapeString(input[2])
	}

	return html.UnescapeString(action[1]), fields
}

func TestNewHandler_Launch(t *testing.T) {
	t.Parallel()

	t.Run("a GET authentication request is answered with a signed id_token posted to the tool", func(t *testing.T) {
		t.Parallel()

		var hints []string

		handler := launchHandler(t, &hints, launchingTestLaunch)

		w := serve(t, handler, http.MethodGet, "/lti/authorize?"+createTestAuthenticationForm().Encode(), "", "")

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

		action, fields := postedFields(t, w)
		assert.Equal(t, "https://tool.example.com/launch", action)
		assert.Equal(t, "state-1", fields["state"])
		assert.NotEmpty(t, fields["id_token"])
		assert.Equal(t, []string{"launch-hint-1"}, hints)
	})

	t.Run("a POSTed authentication request is read from the body, not the query", func(t *testing.T) {
		t.Parallel()

		var hints []string

		handler := launchHandler(t, &hints, launchingTestLaunch)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/lti/authorize", strings.NewReader(createTestAuthenticationForm().Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		_, fields := postedFields(t, w)
		assert.NotEmpty(t, fields["id_token"])

		queryOnly := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/lti/authorize?"+createTestAuthenticationForm().Encode(), http.NoBody)
		queryOnly.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w = httptest.NewRecorder()
		handler.ServeHTTP(w, queryOnly)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "client_id is missing")
		assert.Equal(t, []string{"launch-hint-1"}, hints, "a POST's query never reaches Launch")
	})

	t.Run("a malformed query doesn't reject a POSTed request", func(t *testing.T) {
		t.Parallel()

		for _, query := range []string{"a;b", "%ZZ"} {
			var hints []string

			handler := launchHandler(t, &hints, launchingTestLaunch)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/lti/authorize?"+query, strings.NewReader(createTestAuthenticationForm().Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code, query+": "+w.Body.String())
			_, fields := postedFields(t, w)
			assert.NotEmpty(t, fields["id_token"], query)
		}
	})

	t.Run("a POSTed body over the limit gets a 413 page and never reaches Launch", func(t *testing.T) {
		t.Parallel()

		var hints []string

		handler := launchHandler(t, &hints, launchingTestLaunch)

		form := createTestAuthenticationForm()
		form.Set("padding", strings.Repeat("a", maxAuthenticationFormBytes))

		w := postForm(t, handler, "/lti/authorize", form)

		requireErrorPage(t, w, http.StatusRequestEntityTooLarge, fmt.Sprintf("The launch could not be completed: the request is larger than %d bytes.", maxAuthenticationFormBytes))
		assert.Empty(t, hints)
	})

	t.Run("a request without a message hint gets an error page and never reaches Launch", func(t *testing.T) {
		t.Parallel()

		var hints []string

		handler := launchHandler(t, &hints, launchingTestLaunch)

		form := createTestAuthenticationForm()
		form.Del("lti_message_hint")

		w := serve(t, handler, http.MethodGet, "/lti/authorize?"+form.Encode(), "", "")

		requireErrorPage(t, w, http.StatusBadRequest, "The launch could not be completed: lti_message_hint is missing.")
		assert.Empty(t, hints)
	})

	t.Run("a hint that can't be redeemed gets an error page", func(t *testing.T) {
		t.Parallel()

		var hints []string

		handler := launchHandler(t, &hints, func(*http.Request, *AuthenticationRequest) (*Launch, error) {
			return nil, lti.NewError(lti.ErrorLoginRequired, "the launch has expired", nil)
		})

		w := serve(t, handler, http.MethodGet, "/lti/authorize?"+createTestAuthenticationForm().Encode(), "", "")

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "The launch could not be completed: the launch has expired.")
		assert.NotContains(t, w.Body.String(), "<form")
	})

	t.Run("a platform failure without a launch gets an error page that says nothing more", func(t *testing.T) {
		t.Parallel()

		var hints []string

		handler := launchHandler(t, &hints, func(*http.Request, *AuthenticationRequest) (*Launch, error) {
			return nil, errors.New("database down at 10.0.0.12")
		})

		w := serve(t, handler, http.MethodGet, "/lti/authorize?"+createTestAuthenticationForm().Encode(), "", "")

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.NotContains(t, w.Body.String(), "10.0.0.12")
	})

	t.Run("an error returned with the launch goes to the tool", func(t *testing.T) {
		t.Parallel()

		var hints []string

		handler := launchHandler(t, &hints, func(*http.Request, *AuthenticationRequest) (*Launch, error) {
			launch := createTestLaunch()

			return &launch, lti.NewError(lti.ErrorLoginRequired, "the signed-in user is not the one the launch was started for", nil)
		})

		w := serve(t, handler, http.MethodGet, "/lti/authorize?"+createTestAuthenticationForm().Encode(), "", "")

		require.Equal(t, http.StatusOK, w.Code)
		action, fields := postedFields(t, w)
		assert.Equal(t, "https://tool.example.com/launch", action)
		assert.Equal(t, map[string]string{
			"error":             "login_required",
			"error_description": "the signed-in user is not the one the launch was started for",
			"state":             "state-1",
		}, fields)
	})

	t.Run("an invalid request with a hint still reaches Launch, and its error goes to the tool", func(t *testing.T) {
		t.Parallel()

		var hints []string

		handler := launchHandler(t, &hints, launchingTestLaunch)

		form := createTestAuthenticationForm()
		form.Set("prompt", "login")

		w := serve(t, handler, http.MethodGet, "/lti/authorize?"+form.Encode(), "", "")

		require.Equal(t, http.StatusOK, w.Code)
		_, fields := postedFields(t, w)
		assert.Equal(t, "invalid_request", fields["error"])
		assert.Equal(t, "prompt must be none", fields["error_description"])
		assert.Equal(t, []string{"launch-hint-1"}, hints)
	})

	t.Run("a redirect_uri the tool hasn't registered never receives an answer", func(t *testing.T) {
		t.Parallel()

		var hints []string

		handler := launchHandler(t, &hints, launchingTestLaunch)

		form := createTestAuthenticationForm()
		form.Set("redirect_uri", "https://attacker.example.net/collect")

		w := serve(t, handler, http.MethodGet, "/lti/authorize?"+form.Encode(), "", "")

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.NotContains(t, w.Body.String(), "attacker.example.net")
		assert.NotContains(t, w.Body.String(), "<form")
	})

	t.Run("Logger and OnError see launch errors", func(t *testing.T) {
		t.Parallel()

		var (
			logs   bytes.Buffer
			logged []error
		)

		handler := newTestHandler(t, Handlers{
			Register: granting(&[]string{}),
			Keys:     ltitest.NewKeys(t, ltitest.NewSigningKey(t)),
			Launch: func(*http.Request, *AuthenticationRequest) (*Launch, error) {
				return nil, lti.NewError(lti.ErrorLoginRequired, "the launch has expired", nil)
			},
			Logger:  slog.New(slog.NewJSONHandler(&logs, nil)),
			OnError: func(_ *http.Request, err error) { logged = append(logged, err) },
		})

		serve(t, handler, http.MethodGet, "/lti/authorize?"+createTestAuthenticationForm().Encode(), "", "")

		require.Len(t, logged, 1)
		assert.Contains(t, logs.String(), `"code":"login_required"`)
		assert.Contains(t, logs.String(), `"path":"/lti/authorize"`)
	})
}

func TestNewHandler_JWKS(t *testing.T) {
	t.Parallel()

	key := ltitest.NewSigningKey(t)
	handler := newTestHandler(t, Handlers{
		Register: granting(&[]string{}),
		Keys:     ltitest.NewKeys(t, key),
		Launch:   launchingTestLaunch,
	})

	w := serve(t, handler, http.MethodGet, "/lti/jwks", "", "")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "public, max-age=300", w.Header().Get("Cache-Control"))

	keys, err := jwks.ParseSet(w.Body.Bytes())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, key.ID, keys[0].ID)
}

func TestNewHandler_LaunchEndpointsNeedKeysAndLaunch(t *testing.T) {
	t.Parallel()

	_, err := NewHandler(createTestConfig(), Handlers{Register: granting(&[]string{}), Keys: ltitest.NewKeys(t, ltitest.NewSigningKey(t))})
	require.Error(t, err)

	_, err = NewHandler(createTestConfig(), Handlers{Register: granting(&[]string{}), Launch: launchingTestLaunch})
	require.Error(t, err)

	handler := newTestHandler(t, Handlers{Register: granting(&[]string{})})

	assert.Equal(t, http.StatusNotFound, serve(t, handler, http.MethodGet, "/lti/jwks", "", "").Code)
	assert.Equal(t, http.StatusNotFound, serve(t, handler, http.MethodGet, "/lti/authorize", "", "").Code)
}

package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
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

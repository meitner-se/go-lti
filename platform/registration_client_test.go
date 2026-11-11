package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
)

// registrationClientServer is a platform's Dynamic Registrations: its access tokens and the client
// and scopes each was issued for, and each client's registration and grant. An update replaces the
// registration as a pending one, which ReadRegistration then answers. It records the updates
// UpdateRegistration got.
type registrationClientServer struct {
	tokens        map[string]ServiceClient
	registrations map[string]*Registration
	grants        map[string]RegistrationGrant
	updates       []*Registration
	readErr       error
	updateErr     error
	// answerAs, when set, is the client ID the hooks answer with, as a buggy hook might.
	answerAs string
}

const registrationClientURL = "https://platform.example.com/lti/registrations/client-1"

func newRegistrationClientServer(t *testing.T) *registrationClientServer {
	t.Helper()

	return &registrationClientServer{
		tokens: map[string]ServiceClient{
			"token-read":    {ClientID: "client-1", Scopes: []lti.Scope{lti.ScopeRegistrationReadOnly}},
			"token-write":   {ClientID: "client-1", Scopes: []lti.Scope{lti.ScopeAGSScore, lti.ScopeRegistration}},
			"token-scores":  {ClientID: "client-1", Scopes: []lti.Scope{lti.ScopeAGSScore}},
			"token-other":   {ClientID: "client-2", Scopes: []lti.Scope{lti.ScopeRegistration}},
			"token-unknown": {ClientID: "client-3", Scopes: []lti.Scope{lti.ScopeRegistration}},
		},
		registrations: map[string]*Registration{
			"client-1": parseTestRegistration(t),
			"client-2": parseTestRegistration(t),
		},
		grants: map[string]RegistrationGrant{
			"client-1": {ClientID: "client-1", DeploymentID: "deployment-1", Scopes: []lti.Scope{lti.ScopeAGSScore}, Claims: []string{"iss", "sub"}},
			"client-2": {ClientID: "client-2", DeploymentID: "deployment-2"},
		},
	}
}

func (s *registrationClientServer) authorize(_ *http.Request, token string, _ lti.Scope) (ServiceClient, error) {
	client, ok := s.tokens[token]
	if !ok {
		return ServiceClient{}, lti.NewError(lti.ErrorInvalidToken, "the access token is unknown or expired", nil)
	}

	return client, nil
}

func (s *registrationClientServer) answer(clientID string) (RegistrationResponse, error) {
	reg, ok := s.registrations[clientID]
	if !ok {
		return RegistrationResponse{}, fmt.Errorf("looking up %q: %w", clientID, ErrRegistrationNotFound)
	}

	grant := s.grants[clientID]
	if s.answerAs != "" {
		grant.ClientID = s.answerAs
	}

	return reg.Response(grant), nil
}

func (s *registrationClientServer) read(_ *http.Request, client ServiceClient) (RegistrationResponse, error) {
	if s.readErr != nil {
		return RegistrationResponse{}, s.readErr
	}

	return s.answer(client.ClientID)
}

func (s *registrationClientServer) update(_ *http.Request, client ServiceClient, reg *Registration) (RegistrationResponse, error) {
	if s.updateErr != nil {
		return RegistrationResponse{}, s.updateErr
	}

	if _, ok := s.registrations[client.ClientID]; !ok {
		return RegistrationResponse{}, ErrRegistrationNotFound
	}

	s.updates = append(s.updates, reg)
	s.registrations[client.ClientID] = reg

	return s.answer(client.ClientID)
}

func (s *registrationClientServer) handlers() Handlers {
	return Handlers{
		Register:           granting(&[]string{}),
		AuthorizeService:   s.authorize,
		ReadRegistration:   s.read,
		UpdateRegistration: s.update,
	}
}

func createRegistrationClientTestConfig() Config {
	cfg := createTestConfig()
	cfg.Paths.RegistrationClient = "/registrations"

	return cfg
}

func newRegistrationClientTestHandler(t *testing.T, s *registrationClientServer) http.Handler {
	t.Helper()

	handler, err := NewHandler(createRegistrationClientTestConfig(), s.handlers())
	require.NoError(t, err)

	return handler
}

// updatedRegistrationJSON is the test registration with a new name and target_link_uri, and
// changes to fields when given.
func updatedRegistrationJSON(t *testing.T, changes map[string]any) string {
	t.Helper()

	body := createTestRegistrationJSON()
	body["client_name"] = "Virtual Garden 2"
	toolConfiguration(body)["target_link_uri"] = "https://client.example.org/lti/v2"

	for key, value := range changes {
		if value == nil {
			delete(body, key)
		} else {
			body[key] = value
		}
	}

	return string(encodeRegistration(t, body))
}

// ============================================================================
// Tests
// ============================================================================

func TestNewHandler_GetRegistration(t *testing.T) {
	t.Parallel()

	for _, token := range []string{"token-read", "token-write"} {
		t.Run(token, func(t *testing.T) {
			t.Parallel()

			handler := newRegistrationClientTestHandler(t, newRegistrationClientServer(t))

			w := callAGS(t, handler, http.MethodGet, registrationClientURL, token, "")
			got, ok := requireAGSBody(t, w, http.StatusOK, "application/json").(map[string]any)
			require.True(t, ok)

			assert.Equal(t, "client-1", got["client_id"])
			assert.Equal(t, registrationClientURL, got["registration_client_uri"])
			assert.Equal(t, "Virtual Garden", got["client_name"])
			assert.Equal(t, "Virtuell trädgård", got["client_name#sv"])
			assert.Equal(t, "https://purl.imsglobal.org/spec/lti-ags/scope/score", got["scope"], "narrowed to what was granted, as in the registration response")

			config, ok := got["https://purl.imsglobal.org/spec/lti-tool-configuration"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "deployment-1", config["deployment_id"])
			assert.Equal(t, []any{"iss", "sub"}, config["claims"])
		})
	}
}

func TestNewHandler_PutRegistration(t *testing.T) {
	t.Parallel()

	s := newRegistrationClientServer(t)
	handler := newRegistrationClientTestHandler(t, s)

	w := callAGS(t, handler, http.MethodPut, registrationClientURL, "token-write", updatedRegistrationJSON(t, map[string]any{"client_id": "client-1"}))
	got, ok := requireAGSBody(t, w, http.StatusOK, "application/json").(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "client-1", got["client_id"])
	assert.Equal(t, registrationClientURL, got["registration_client_uri"])
	assert.Equal(t, "Virtual Garden 2", got["client_name"], "the answer reflects the pending update")

	require.Len(t, s.updates, 1)
	assert.Equal(t, "Virtual Garden 2", s.updates[0].ClientName)
	assert.Equal(t, "https://client.example.org/lti/v2", s.updates[0].ToolConfiguration.TargetLinkURI)
	assert.Equal(t, "Virtuell trädgård", s.updates[0].ClientNames["sv"], "parsed as a registration is")

	w = callAGS(t, handler, http.MethodGet, registrationClientURL, "token-read", "")
	got, ok = requireAGSBody(t, w, http.StatusOK, "application/json").(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Virtual Garden 2", got["client_name"], "a read reflects the pending update too")
}

func TestNewHandler_PutRegistrationWithoutClientID(t *testing.T) {
	t.Parallel()

	s := newRegistrationClientServer(t)
	handler := newRegistrationClientTestHandler(t, s)

	w := callAGS(t, handler, http.MethodPut, registrationClientURL, "token-write", updatedRegistrationJSON(t, nil))
	got, ok := requireAGSBody(t, w, http.StatusOK, "application/json").(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "client-1", got["client_id"])
	assert.Len(t, s.updates, 1)
}

func TestNewHandler_PutRegistrationRefusesAnInvalidBodyAsARegistrationIs(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"not json":                  `{"client_name": `,
		"a client secret":           updatedRegistrationJSON(t, map[string]any{"token_endpoint_auth_method": "client_secret_basic"}),
		"an http jwks_uri":          updatedRegistrationJSON(t, map[string]any{"jwks_uri": "http://client.example.org/jwks"}),
		"no implicit grant":         updatedRegistrationJSON(t, map[string]any{"grant_types": []string{"client_credentials"}}),
		"a redirect uri fragment":   updatedRegistrationJSON(t, map[string]any{"redirect_uris": []string{"https://client.example.org/cb#x"}}),
		"no redirect uris":          updatedRegistrationJSON(t, map[string]any{"redirect_uris": nil}),
		"a bad localized name":      updatedRegistrationJSON(t, map[string]any{"client_name#": "Garden"}),
		"a body over 1 MiB":         `{"client_name": "` + strings.Repeat("a", MaxRegistrationBytes) + `"}`,
		"a client_id of the client": `{"client_id": "client-1"}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, parseErr := ParseRegistration([]byte(body))
			want, ok := lti.AsError(parseErr)
			require.True(t, ok, "the body must be one ParseRegistration refuses")

			s := newRegistrationClientServer(t)
			handler := newRegistrationClientTestHandler(t, s)

			w := callAGS(t, handler, http.MethodPut, registrationClientURL, "token-write", body)
			requireRegistrationErrorResponse(t, w, http.StatusBadRequest, want.Code, want.Description)
			assert.Empty(t, s.updates)
		})
	}
}

func TestNewHandler_PutRegistrationRefusesAnotherClientID(t *testing.T) {
	t.Parallel()

	for name, clientID := range map[string]any{
		"another client's": "client-2",
		"an empty one":     "",
		"not a string":     1,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newRegistrationClientServer(t)
			handler := newRegistrationClientTestHandler(t, s)

			w := callAGS(t, handler, http.MethodPut, registrationClientURL, "token-write", updatedRegistrationJSON(t, map[string]any{"client_id": clientID}))
			requireAGSError(t, w, http.StatusBadRequest, lti.ErrorInvalidClientMetadata, "")
			assert.Empty(t, s.updates)
		})
	}
}

func TestNewHandler_RegistrationClientAnswersOtherClientsAsUnknown(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method, target, token string
		readErr, updateErr    error
		answerAs              string
		status                int
		code                  lti.ErrorCode
	}{
		"another client's endpoint": {
			method: http.MethodGet, target: "https://platform.example.com/lti/registrations/client-2", token: "token-write",
			status: http.StatusNotFound, code: lti.ErrorInvalidRequest,
		},
		"another client's endpoint, on a PUT": {
			method: http.MethodPut, target: "https://platform.example.com/lti/registrations/client-2", token: "token-write",
			status: http.StatusNotFound, code: lti.ErrorInvalidRequest,
		},
		"an endpoint of no client": {
			method: http.MethodGet, target: "https://platform.example.com/lti/registrations/client-9", token: "token-write",
			status: http.StatusNotFound, code: lti.ErrorInvalidRequest,
		},
		"an escaped dot": {
			method: http.MethodGet, target: "https://platform.example.com/lti/registrations/%2E", token: "token-write",
			status: http.StatusNotFound, code: lti.ErrorInvalidRequest,
		},
		"a client without a registration": {
			method: http.MethodGet, target: "https://platform.example.com/lti/registrations/client-3", token: "token-unknown",
			status: http.StatusNotFound, code: lti.ErrorInvalidRequest,
		},
		"a client without a registration, on a PUT": {
			method: http.MethodPut, target: "https://platform.example.com/lti/registrations/client-3", token: "token-unknown",
			status: http.StatusNotFound, code: lti.ErrorInvalidRequest,
		},
		"a read the platform refuses": {
			method: http.MethodGet, target: registrationClientURL, token: "token-read",
			readErr: fmt.Errorf("checking the tool: %w", ErrRegistrationForbidden),
			status:  http.StatusForbidden, code: lti.ErrorAccessDenied,
		},
		"an update the platform refuses": {
			method: http.MethodPut, target: registrationClientURL, token: "token-write",
			updateErr: fmt.Errorf("checking the tool: %w", ErrRegistrationForbidden),
			status:    http.StatusForbidden, code: lti.ErrorAccessDenied,
		},
		"another client's registration that the hook let through": {
			method: http.MethodGet, target: registrationClientURL, token: "token-read", answerAs: "client-2",
			status: http.StatusForbidden, code: lti.ErrorAccessDenied,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newRegistrationClientServer(t)
			s.readErr, s.updateErr, s.answerAs = tt.readErr, tt.updateErr, tt.answerAs
			handler := newRegistrationClientTestHandler(t, s)

			body := ""
			if tt.method == http.MethodPut {
				body = updatedRegistrationJSON(t, nil)
			}

			w := callAGS(t, handler, tt.method, tt.target, tt.token, body)
			requireAGSError(t, w, tt.status, tt.code, "")
			assert.Empty(t, s.updates)
			assert.NotContains(t, w.Body.String(), "client-2")
		})
	}
}

func TestNewHandler_RegistrationClientServesAnEscapedClientID(t *testing.T) {
	t.Parallel()

	s := newRegistrationClientServer(t)
	s.tokens["token-escaped"] = ServiceClient{ClientID: "client 1/a", Scopes: []lti.Scope{lti.ScopeRegistration}}
	s.registrations["client 1/a"] = parseTestRegistration(t)
	handler := newRegistrationClientTestHandler(t, s)

	target, err := createRegistrationClientTestConfig().RegistrationClientURL("client 1/a")
	require.NoError(t, err)

	w := callAGS(t, handler, http.MethodGet, target, "token-escaped", "")
	got, ok := requireAGSBody(t, w, http.StatusOK, "application/json").(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "client 1/a", got["client_id"])
	assert.Equal(t, target, got["registration_client_uri"])
}

func TestNewHandler_RegistrationClientRefusesTokens(t *testing.T) {
	t.Parallel()

	readOnly := `Bearer error="insufficient_scope", scope="https://purl.imsglobal.org/spec/lti-reg/scope/registration.readonly"`
	readWrite := `Bearer error="insufficient_scope", scope="https://purl.imsglobal.org/spec/lti-reg/scope/registration"`

	tests := map[string]struct {
		method, token string
		status        int
		challenge     string
	}{
		"no token":                      {method: http.MethodGet, token: "", status: http.StatusUnauthorized, challenge: "Bearer"},
		"no token, on a PUT":            {method: http.MethodPut, token: "", status: http.StatusUnauthorized, challenge: "Bearer"},
		"unknown token":                 {method: http.MethodGet, token: "token-nobody", status: http.StatusUnauthorized, challenge: `Bearer error="invalid_token"`},
		"a token without either scope":  {method: http.MethodGet, token: "token-scores", status: http.StatusForbidden, challenge: readOnly},
		"a token without the PUT scope": {method: http.MethodPut, token: "token-scores", status: http.StatusForbidden, challenge: readWrite},
		"a read-only token on a PUT":    {method: http.MethodPut, token: "token-read", status: http.StatusForbidden, challenge: readWrite},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newRegistrationClientServer(t)
			handler := newRegistrationClientTestHandler(t, s)

			w := callAGS(t, handler, tt.method, registrationClientURL, tt.token, updatedRegistrationJSON(t, nil))
			assert.Equal(t, tt.status, w.Code)
			assert.Equal(t, tt.challenge, w.Header().Get("WWW-Authenticate"))
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Empty(t, s.updates)
		})
	}
}

func TestNewHandler_RegistrationClientHookErrors(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		s := newRegistrationClientServer(t)
		s.readErr = errors.New("database is down")
		s.updateErr = s.readErr
		handler := newRegistrationClientTestHandler(t, s)

		w := callAGS(t, handler, method, registrationClientURL, "token-write", updatedRegistrationJSON(t, nil))
		assert.Equal(t, http.StatusInternalServerError, w.Code, method)
		assert.NotContains(t, w.Body.String(), "database", method)
	}

	s := newRegistrationClientServer(t)
	s.updateErr = lti.NewError(lti.ErrorInvalidClientMetadata, "the domain can't change", nil)
	handler := newRegistrationClientTestHandler(t, s)

	w := callAGS(t, handler, http.MethodPut, registrationClientURL, "token-write", updatedRegistrationJSON(t, nil))
	requireRegistrationErrorResponse(t, w, http.StatusBadRequest, lti.ErrorInvalidClientMetadata, "the domain can't change")
}

func TestNewHandler_RegistrationClientMethods(t *testing.T) {
	t.Parallel()

	handler := newRegistrationClientTestHandler(t, newRegistrationClientServer(t))

	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch} {
		w := callAGS(t, handler, method, registrationClientURL, "token-write", "")
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, method)
	}
}

func TestNewHandler_RegistrationClientConfiguration(t *testing.T) {
	t.Parallel()

	all := newRegistrationClientServer(t).handlers()

	for name, remove := range map[string]func(h *Handlers){
		"ReadRegistration":   func(h *Handlers) { h.ReadRegistration = nil },
		"UpdateRegistration": func(h *Handlers) { h.UpdateRegistration = nil },
	} {
		h := all
		remove(&h)

		_, err := NewHandler(createRegistrationClientTestConfig(), h)
		require.ErrorContains(t, err, "needs all of Paths.RegistrationClient, ReadRegistration and UpdateRegistration", "without "+name)
	}

	_, err := NewHandler(createTestConfig(), all)
	require.ErrorContains(t, err, "needs all of Paths.RegistrationClient", "the hooks without the path")

	h := all
	h.AuthorizeService = nil
	_, err = NewHandler(createRegistrationClientTestConfig(), h)
	require.ErrorContains(t, err, "needs AuthorizeService")

	handler := newTestHandler(t, Handlers{Register: all.Register})
	w := serve(t, handler, http.MethodGet, "/lti/registrations/client-1", "Bearer token-read", "")
	assert.Equal(t, http.StatusNotFound, w.Code, "not served without the registration hooks")
}

func TestNewHandler_RegistrationResponseHasTheClientConfigurationEndpoint(t *testing.T) {
	t.Parallel()

	body := string(encodeRegistration(t, createTestRegistrationJSON()))

	served := newRegistrationClientTestHandler(t, newRegistrationClientServer(t))
	w := postRegistration(t, served, "Bearer token-1", body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "client-1", got["client_id"])
	assert.Equal(t, registrationClientURL, got["registration_client_uri"])
	assert.NotContains(t, got, "registration_access_token", "the tool gets its access token from the token endpoint")

	notServed := newTestHandler(t, Handlers{Register: granting(&[]string{})})
	w = postRegistration(t, notServed, "Bearer token-1", body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "registration_client_uri")
}

func TestRegistrationResponse_RegistrationClientURI(t *testing.T) {
	t.Parallel()

	response := parseTestRegistration(t).Response(RegistrationGrant{ClientID: "client-1"})

	body, err := json.Marshal(response)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "registration_client_uri", "left out when empty")

	response.RegistrationClientURI = registrationClientURL
	body, err = json.Marshal(response)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, registrationClientURL, got["registration_client_uri"])
	assert.Equal(t, "Virtuell trädgård", got["client_name#sv"], "with the localized names still")
}

func TestConfig_RegistrationClientURL(t *testing.T) {
	t.Parallel()

	cfg := createRegistrationClientTestConfig()

	got, err := cfg.RegistrationClientURL("client-1")
	require.NoError(t, err)
	assert.Equal(t, registrationClientURL, got)

	got, err = cfg.RegistrationClientURL("a b/c?")
	require.NoError(t, err)
	assert.Equal(t, "https://platform.example.com/lti/registrations/a%20b%2Fc%3F", got)

	for _, clientID := range []string{"", ".", ".."} {
		_, err := cfg.RegistrationClientURL(clientID)
		require.Error(t, err, clientID)
	}

	_, err = createTestConfig().RegistrationClientURL("client-1")
	require.ErrorContains(t, err, "no registration client path")
}

func TestPaths_ValidateRegistrationClient(t *testing.T) {
	t.Parallel()

	for name, change := range map[string]func(p *Paths){
		"not clean":                     func(p *Paths) { p.RegistrationClient = "/registrations/" },
		"with braces":                   func(p *Paths) { p.RegistrationClient = "/registrations/{id}" },
		"the registration path":         func(p *Paths) { p.RegistrationClient = "/register" },
		"the notice handlers path":      func(p *Paths) { p.NoticeHandlers, p.RegistrationClient = "/tools", "/tools" },
		"under the context path":        func(p *Paths) { p.ContextMemberships, p.RegistrationClient = "/contexts", "/contexts/registrations" },
		"over the line items path":      func(p *Paths) { p.ContextLineItems, p.RegistrationClient = "/tools/contexts", "/tools" },
		"under the notice handler path": func(p *Paths) { p.NoticeHandlers, p.RegistrationClient = "/tools", "/tools/registrations" },
	} {
		cfg := createRegistrationClientTestConfig()
		change(&cfg.Paths)

		require.Error(t, cfg.Validate(), name)
	}

	cfg := createRegistrationClientTestConfig()
	cfg.Paths.NoticeHandlers = "/tools/notice-handlers"
	cfg.Paths.RegistrationClient = "/tools/registrations"
	require.NoError(t, cfg.Validate(), "siblings under one prefix")
}

func TestConfig_OpenIDConfiguration_AdvertisesTheRegistrationScopes(t *testing.T) {
	t.Parallel()

	cfg := createRegistrationClientTestConfig()
	cfg.Scopes = []lti.Scope{lti.ScopeAGSScore, lti.ScopeRegistration}

	configuration, err := cfg.OpenIDConfiguration()
	require.NoError(t, err)

	assert.Equal(t, []string{
		"openid",
		"https://purl.imsglobal.org/spec/lti-ags/scope/score",
		"https://purl.imsglobal.org/spec/lti-reg/scope/registration",
		"https://purl.imsglobal.org/spec/lti-reg/scope/registration.readonly",
	}, configuration.ScopesSupported, "each once, when the platform serves the endpoint")

	configuration, err = createTestConfig().OpenIDConfiguration()
	require.NoError(t, err)
	assert.Equal(t, []string{"openid"}, configuration.ScopesSupported, "not when it doesn't")
}

func TestRegistration_ReviewCountsTheRegistrationScopesAsSupportedWhenServed(t *testing.T) {
	t.Parallel()

	body := createTestRegistrationJSON()
	body["scope"] = "https://purl.imsglobal.org/spec/lti-reg/scope/registration https://purl.imsglobal.org/spec/lti-ags/scope/score"

	reg, err := ParseRegistration(encodeRegistration(t, body))
	require.NoError(t, err)

	assert.Equal(t, []lti.Scope{lti.ScopeRegistration, lti.ScopeAGSScore}, reg.Review(createTestConfig()).UnsupportedScopes)
	assert.Equal(t, []lti.Scope{lti.ScopeAGSScore}, reg.Review(createRegistrationClientTestConfig()).UnsupportedScopes)
}

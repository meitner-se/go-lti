package platform

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
)

// noticeHandlersServer is a platform's notice handlers: its access tokens and their scopes, and each
// deployment's tool and handlers. It records the registrations ReplaceNoticeHandler got.
type noticeHandlersServer struct {
	tokens        map[string][]lti.Scope
	deployments   map[string]*DeploymentNoticeHandlers
	registrations []lti.NoticeHandlerRegistration
	replaceErr    error
}

const (
	helloWorldNotice = lti.NoticeType("LtiHelloWorldNotice")
	submissionNotice = lti.NoticeType("LtiAssetProcessorSubmissionNotice")
	noticeHandlerURL = "https://platform.example.com/lti/notice-handlers/deployment-1"
)

func newNoticeHandlersServer() *noticeHandlersServer {
	tool := createTestTool()

	other := createTestTool()
	other.ClientID = "client-2"

	return &noticeHandlersServer{
		tokens: map[string][]lti.Scope{
			"token-1":      {lti.ScopeNRPSMembershipRead, lti.ScopeNoticeHandlers},
			"token-scores": {lti.ScopeAGSScore},
		},
		deployments: map[string]*DeploymentNoticeHandlers{
			"deployment-1": {Tool: tool, Handlers: []lti.NoticeHandler{{NoticeType: submissionNotice, Handler: "https://tool.example.com/notices"}}},
			// Another tool's deployment, which client-1 may not manage.
			"deployment-2": {Tool: other, Handlers: nil},
			// A deployment whose record names another tool, as a buggy hook might return it.
			"deployment-mixed-up": {Tool: other, Handlers: nil},
		},
	}
}

func (s *noticeHandlersServer) authorize(_ *http.Request, token string, _ lti.Scope) (ServiceClient, error) {
	granted, ok := s.tokens[token]
	if !ok {
		return ServiceClient{}, lti.NewError(lti.ErrorInvalidToken, "the access token is unknown or expired", nil)
	}

	return ServiceClient{ClientID: "client-1", Scopes: granted}, nil
}

func (s *noticeHandlersServer) read(_ *http.Request, client ServiceClient, deploymentID string) (DeploymentNoticeHandlers, error) {
	deployment, ok := s.deployments[deploymentID]
	if !ok {
		return DeploymentNoticeHandlers{}, fmt.Errorf("looking up %q: %w", deploymentID, ErrDeploymentNotFound)
	}

	if deploymentID == "deployment-2" && deployment.Tool.ClientID != client.ClientID {
		return DeploymentNoticeHandlers{}, ErrNoticeHandlersForbidden
	}

	return *deployment, nil
}

func (s *noticeHandlersServer) replace(_ *http.Request, _ ServiceClient, deploymentID string, registration lti.NoticeHandlerRegistration) error {
	if s.replaceErr != nil {
		return s.replaceErr
	}

	s.registrations = append(s.registrations, registration)

	deployment := s.deployments[deploymentID]
	handlers := []lti.NoticeHandler{}

	for _, h := range deployment.Handlers {
		if h.NoticeType != registration.NoticeType {
			handlers = append(handlers, h)
		}
	}

	if registration.Handler != "" {
		handlers = append(handlers, lti.NoticeHandler{NoticeType: registration.NoticeType, Handler: registration.Handler})
	}

	deployment.Handlers = handlers

	return nil
}

func (s *noticeHandlersServer) handlers() Handlers {
	return Handlers{
		Register:             granting(&[]string{}),
		AuthorizeService:     s.authorize,
		ReadNoticeHandlers:   s.read,
		ReplaceNoticeHandler: s.replace,
	}
}

func createNoticeHandlersTestConfig() Config {
	cfg := createTestConfig()
	cfg.Paths.NoticeHandlers = "/notice-handlers"
	cfg.NoticeTypes = []lti.NoticeType{helloWorldNotice, submissionNotice}

	return cfg
}

func newNoticeHandlersTestHandler(t *testing.T, s *noticeHandlersServer) http.Handler {
	t.Helper()

	handler, err := NewHandler(createNoticeHandlersTestConfig(), s.handlers())
	require.NoError(t, err)

	return handler
}

// ============================================================================
// Tests
// ============================================================================

func TestNewHandler_GetNoticeHandlers(t *testing.T) {
	t.Parallel()

	handler := newNoticeHandlersTestHandler(t, newNoticeHandlersServer())

	w := callAGS(t, handler, http.MethodGet, noticeHandlerURL, "token-1", "")
	got := requireAGSBody(t, w, http.StatusOK, "application/json")

	assert.Equal(t, map[string]any{
		"client_id":     "client-1",
		"deployment_id": "deployment-1",
		"notice_handlers": []any{
			map[string]any{"notice_type": string(helloWorldNotice), "handler": ""},
			map[string]any{"notice_type": string(submissionNotice), "handler": "https://tool.example.com/notices"},
		},
	}, got)
}

func TestNewHandler_GetNoticeHandlersWithoutNoticeTypes(t *testing.T) {
	t.Parallel()

	cfg := createNoticeHandlersTestConfig()
	cfg.NoticeTypes = nil

	handler, err := NewHandler(cfg, newNoticeHandlersServer().handlers())
	require.NoError(t, err)

	w := callAGS(t, handler, http.MethodGet, noticeHandlerURL, "token-1", "")
	got := requireAGSBody(t, w, http.StatusOK, "application/json")
	assert.Equal(t, []any{}, got.(map[string]any)["notice_handlers"])
}

func TestNewHandler_PutNoticeHandler(t *testing.T) {
	t.Parallel()

	s := newNoticeHandlersServer()
	handler := newNoticeHandlersTestHandler(t, s)

	w := callAGS(t, handler, http.MethodPut, noticeHandlerURL, "token-1",
		`{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/hello", "max_batch_size": 10}`)
	got := requireAGSBody(t, w, http.StatusOK, "application/json")
	assert.Equal(t, map[string]any{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/hello"}, got)

	require.Len(t, s.registrations, 1)
	assert.Equal(t, lti.NoticeHandlerRegistration{NoticeType: helloWorldNotice, Handler: "https://tool.example.com/hello", MaxBatchSize: 10}, s.registrations[0])

	w = callAGS(t, handler, http.MethodGet, noticeHandlerURL, "token-1", "")
	got = requireAGSBody(t, w, http.StatusOK, "application/json")
	assert.Equal(t, []any{
		map[string]any{"notice_type": string(helloWorldNotice), "handler": "https://tool.example.com/hello"},
		map[string]any{"notice_type": string(submissionNotice), "handler": "https://tool.example.com/notices"},
	}, got.(map[string]any)["notice_handlers"])
}

func TestNewHandler_PutNoticeHandlerEmptyRemovesIt(t *testing.T) {
	t.Parallel()

	s := newNoticeHandlersServer()
	handler := newNoticeHandlersTestHandler(t, s)

	w := callAGS(t, handler, http.MethodPut, noticeHandlerURL, "token-1", `{"notice_type": "LtiAssetProcessorSubmissionNotice", "handler": ""}`)
	got := requireAGSBody(t, w, http.StatusOK, "application/json")
	assert.Equal(t, map[string]any{"notice_type": string(submissionNotice), "handler": ""}, got)

	w = callAGS(t, handler, http.MethodGet, noticeHandlerURL, "token-1", "")
	got = requireAGSBody(t, w, http.StatusOK, "application/json")
	assert.Equal(t, []any{
		map[string]any{"notice_type": string(helloWorldNotice), "handler": ""},
		map[string]any{"notice_type": string(submissionNotice), "handler": ""},
	}, got.(map[string]any)["notice_handlers"])
}

func TestNewHandler_PutNoticeHandlerRefuses(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body        string
		description string
	}{
		"an unsupported type":       {`{"notice_type": "LtiUnknownNotice", "handler": "https://tool.example.com/notices"}`, "the platform doesn't support the notice type"},
		"no type":                   {`{"handler": "https://tool.example.com/notices"}`, "the platform doesn't support the notice type"},
		"an http handler":           {`{"notice_type": "LtiHelloWorldNotice", "handler": "http://tool.example.com/notices"}`, errNoticeHandlerURL.Description},
		"a handler on another host": {`{"notice_type": "LtiHelloWorldNotice", "handler": "https://cdn.example.net/notices"}`, errNoticeHandlerURL.Description},
		"a handler on a subdomain":  {`{"notice_type": "LtiHelloWorldNotice", "handler": "https://hooks.tool.example.com/notices"}`, errNoticeHandlerURL.Description},
		"a handler with credentials": {
			`{"notice_type": "LtiHelloWorldNotice", "handler": "https://user:secret@tool.example.com/notices"}`, errNoticeHandlerURL.Description,
		},
		"a zero batch size":       {`{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/notices", "max_batch_size": 0}`, "max_batch_size must be a positive integer"},
		"a negative batch size":   {`{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/notices", "max_batch_size": -5}`, "max_batch_size must be a positive integer"},
		"a fractional batch size": {`{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/notices", "max_batch_size": 1.5}`, "max_batch_size must be a positive integer"},
		"a body that isn't JSON":  {`notice_type=LtiHelloWorldNotice`, "the notice handler is not valid JSON of its media type"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newNoticeHandlersServer()
			handler := newNoticeHandlersTestHandler(t, s)

			w := callAGS(t, handler, http.MethodPut, noticeHandlerURL, "token-1", tt.body)
			requireAGSError(t, w, http.StatusBadRequest, lti.ErrorInvalidRequest, tt.description)
			assert.Empty(t, s.registrations, "ReplaceNoticeHandler isn't called")
		})
	}
}

func TestNewHandler_PutNoticeHandlerLetsThePlatformRefuseABatchSize(t *testing.T) {
	t.Parallel()

	s := newNoticeHandlersServer()
	s.replaceErr = lti.NewError(lti.ErrorInvalidRequest, "max_batch_size must be at most 100", nil)
	handler := newNoticeHandlersTestHandler(t, s)

	w := callAGS(t, handler, http.MethodPut, noticeHandlerURL, "token-1", `{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/notices", "max_batch_size": 1000}`)
	requireAGSError(t, w, http.StatusBadRequest, lti.ErrorInvalidRequest, "max_batch_size must be at most 100")
}

func TestNewHandler_NoticeHandlersAnswersDeploymentsTheToolMayNotManage(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method, target, body string
		replaceErr           error
		status               int
		code                 lti.ErrorCode
	}{
		"an unknown deployment": {
			method: http.MethodGet, target: "https://platform.example.com/lti/notice-handlers/deployment-unknown",
			status: http.StatusNotFound, code: lti.ErrorInvalidRequest,
		},
		"an escaped dot": {
			method: http.MethodGet, target: "https://platform.example.com/lti/notice-handlers/%2E",
			status: http.StatusNotFound, code: lti.ErrorInvalidRequest,
		},
		"another tool's deployment": {
			method: http.MethodGet, target: "https://platform.example.com/lti/notice-handlers/deployment-2",
			status: http.StatusForbidden, code: lti.ErrorAccessDenied,
		},
		"another tool's deployment, on a PUT": {
			method: http.MethodPut, target: "https://platform.example.com/lti/notice-handlers/deployment-2",
			body:   `{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/notices"}`,
			status: http.StatusForbidden, code: lti.ErrorAccessDenied,
		},
		"a record of another tool that the hook let through": {
			method: http.MethodGet, target: "https://platform.example.com/lti/notice-handlers/deployment-mixed-up",
			status: http.StatusForbidden, code: lti.ErrorAccessDenied,
		},
		"a replacement the platform refuses": {
			method: http.MethodPut, target: noticeHandlerURL,
			body:       `{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/notices"}`,
			replaceErr: fmt.Errorf("checking permissions: %w", ErrNoticeHandlersForbidden),
			status:     http.StatusForbidden, code: lti.ErrorAccessDenied,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newNoticeHandlersServer()
			s.replaceErr = tt.replaceErr
			handler := newNoticeHandlersTestHandler(t, s)

			w := callAGS(t, handler, tt.method, tt.target, "token-1", tt.body)
			requireAGSError(t, w, tt.status, tt.code, "")
			assert.Empty(t, s.registrations)
		})
	}
}

func TestNewHandler_NoticeHandlersRefusesTokens(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		token     string
		status    int
		challenge string
	}{
		"no token":      {token: "", status: http.StatusUnauthorized, challenge: "Bearer"},
		"unknown token": {token: "token-unknown", status: http.StatusUnauthorized, challenge: `Bearer error="invalid_token"`},
		"a token without the scope": {
			token: "token-scores", status: http.StatusForbidden,
			challenge: `Bearer error="insufficient_scope", scope="https://purl.imsglobal.org/spec/lti/scope/noticehandlers"`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, method := range []string{http.MethodGet, http.MethodPut} {
				s := newNoticeHandlersServer()
				handler := newNoticeHandlersTestHandler(t, s)

				w := callAGS(t, handler, method, noticeHandlerURL, tt.token, `{"notice_type": "LtiHelloWorldNotice", "handler": ""}`)
				assert.Equal(t, tt.status, w.Code, method)
				assert.Equal(t, tt.challenge, w.Header().Get("WWW-Authenticate"), method)
				assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), method)
				assert.Empty(t, s.registrations, method)
			}
		})
	}
}

func TestNewHandler_NoticeHandlersHookErrors(t *testing.T) {
	t.Parallel()

	s := newNoticeHandlersServer()
	s.replaceErr = errors.New("database is down")
	handler := newNoticeHandlersTestHandler(t, s)

	w := callAGS(t, handler, http.MethodPut, noticeHandlerURL, "token-1", `{"notice_type": "LtiHelloWorldNotice", "handler": ""}`)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "database")
}

func TestNewHandler_NoticeHandlersMethods(t *testing.T) {
	t.Parallel()

	handler := newNoticeHandlersTestHandler(t, newNoticeHandlersServer())

	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch} {
		w := callAGS(t, handler, method, noticeHandlerURL, "token-1", "")
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, method)
	}
}

func TestNewHandler_NoticeHandlersConfiguration(t *testing.T) {
	t.Parallel()

	all := newNoticeHandlersServer().handlers()

	for name, remove := range map[string]func(h *Handlers){
		"ReadNoticeHandlers":   func(h *Handlers) { h.ReadNoticeHandlers = nil },
		"ReplaceNoticeHandler": func(h *Handlers) { h.ReplaceNoticeHandler = nil },
	} {
		h := all
		remove(&h)

		_, err := NewHandler(createNoticeHandlersTestConfig(), h)
		require.ErrorContains(t, err, "needs all of Paths.NoticeHandlers, ReadNoticeHandlers and ReplaceNoticeHandler", "without "+name)
	}

	_, err := NewHandler(createTestConfig(), all)
	require.ErrorContains(t, err, "needs all of Paths.NoticeHandlers", "the hooks without the path")

	h := all
	h.AuthorizeService = nil
	_, err = NewHandler(createNoticeHandlersTestConfig(), h)
	require.ErrorContains(t, err, "needs AuthorizeService")

	handler := newTestHandler(t, Handlers{Register: all.Register})
	w := serve(t, handler, http.MethodGet, "/lti/notice-handlers/deployment-1", "Bearer token-1", "")
	assert.Equal(t, http.StatusNotFound, w.Code, "not served without the notice handler hooks")
}

func TestOnToolHosts(t *testing.T) {
	t.Parallel()

	tool := createTestTool()
	tool.RedirectURIs = []string{"https://tool.example.com/launch", "https://Assets.Example.org:8443/lti", "not a url"}

	for rawURL, want := range map[string]bool{
		"https://tool.example.com/notices":        true,
		"https://tool.example.com:9443/notices":   true,
		"https://TOOL.example.com./notices":       true,
		"https://assets.example.org/notices?x=1":  true,
		"http://tool.example.com/notices":         false,
		"https://hooks.tool.example.com/notices":  false,
		"https://example.com/notices":             false,
		"https://cdn.example.net/notices":         false,
		"https://user@tool.example.com/notices":   false,
		"/notices":                                false,
		"":                                        false,
		"https://tool.example.com.attacker.net/x": false,
		"https://tool.example.com%2F.attacker/x":  false,
		"javascript:alert(1)//tool.example.com/x": false,
	} {
		assert.Equal(t, want, OnToolHosts(tool, rawURL), rawURL)
	}
}

func TestConfig_NoticeHandlersURL(t *testing.T) {
	t.Parallel()

	cfg := createNoticeHandlersTestConfig()

	got, err := cfg.NoticeHandlersURL("deployment 1/a")
	require.NoError(t, err)
	assert.Equal(t, "https://platform.example.com/lti/notice-handlers/deployment%201%2Fa", got)

	for _, id := range []string{"", ".", ".."} {
		_, err = cfg.NoticeHandlersURL(id)
		require.Error(t, err, id)
	}

	_, err = createTestConfig().NoticeHandlersURL("deployment-1")
	require.ErrorContains(t, err, "no notice handlers path")
}

func TestConfig_NoticeHandlersURLRoundTrips(t *testing.T) {
	t.Parallel()

	s := newNoticeHandlersServer()
	s.deployments["deployment 1/a"] = s.deployments["deployment-1"]
	handler := newNoticeHandlersTestHandler(t, s)

	target, err := createNoticeHandlersTestConfig().NoticeHandlersURL("deployment 1/a")
	require.NoError(t, err)

	w := callAGS(t, handler, http.MethodGet, target, "token-1", "")
	got := requireAGSBody(t, w, http.StatusOK, "application/json")
	assert.Equal(t, "deployment 1/a", got.(map[string]any)["deployment_id"])
}

func TestConfig_PlatformNotificationService(t *testing.T) {
	t.Parallel()

	cfg := createNoticeHandlersTestConfig()

	got, err := cfg.PlatformNotificationService("deployment-1")
	require.NoError(t, err)
	assert.Equal(t, &lti.PlatformNotificationService{URL: noticeHandlerURL, NoticeTypesSupported: []lti.NoticeType{helloWorldNotice, submissionNotice}}, got)

	got.NoticeTypesSupported[0] = "changed"
	assert.Equal(t, helloWorldNotice, cfg.NoticeTypes[0], "the claim has its own copy of the types")

	_, err = createTestConfig().PlatformNotificationService("deployment-1")
	require.Error(t, err)
}

func TestPaths_ValidateNoticeHandlers(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		paths func(p *Paths)
		err   string
	}{
		"its own prefix":           {func(p *Paths) { p.NoticeHandlers = "/notice-handlers" }, ""},
		"next to the context ones": {func(p *Paths) { p.ContextMemberships, p.NoticeHandlers = "/contexts", "/notices" }, ""},
		"not clean":                {func(p *Paths) { p.NoticeHandlers = "/notice-handlers/" }, "notice handlers path must be a clean path"},
		"the same as another":      {func(p *Paths) { p.NoticeHandlers = "/jwks" }, "notice handlers path is the same as jwks path"},
		"the same as a context":    {func(p *Paths) { p.ContextLineItems, p.NoticeHandlers = "/contexts", "/contexts" }, "the same as context line items path"},
		"under a context":          {func(p *Paths) { p.ContextMemberships, p.NoticeHandlers = "/contexts", "/contexts/notices" }, "must not be under a context path"},
		"over a context":           {func(p *Paths) { p.ContextLineItems, p.NoticeHandlers = "/lti/contexts", "/lti" }, "must not be under a context path"},
	} {
		cfg := createTestConfig()
		tt.paths(&cfg.Paths)

		err := cfg.Validate()
		if tt.err == "" {
			require.NoError(t, err, name)
		} else {
			require.ErrorContains(t, err, tt.err, name)
		}
	}
}

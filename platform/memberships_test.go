package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
)

// membershipsServer is a platform's memberships: its access tokens and each context's members,
// served a page of pageSize members at a time with the next member's index as the page token. It
// records the requests ListContextMembers got.
type membershipsServer struct {
	tokens   map[string][]lti.Scope
	contexts map[string][]lti.Member
	pageSize int
	requests []MembershipsRequest
	scopes   []lti.Scope
}

func newMembershipsServer() *membershipsServer {
	return &membershipsServer{
		tokens: map[string][]lti.Scope{
			"token-1":      {lti.ScopeNRPSMembershipRead},
			"token-scores": {lti.ScopeAGSScore},
		},
		contexts: map[string][]lti.Member{
			"course-1": {
				{Status: lti.MembershipStatusActive, UserID: "user-1", Roles: []lti.Role{lti.RoleInstructor}},
				{Status: lti.MembershipStatusActive, UserID: "user-2", Roles: []lti.Role{lti.RoleLearner}},
				{Status: lti.MembershipStatusInactive, UserID: "user-3", Roles: []lti.Role{lti.RoleLearner}},
			},
			"workspace:a b/c": {{UserID: "user-1", Roles: []lti.Role{lti.RoleLearner}}},
		},
		pageSize: 2,
	}
}

func (s *membershipsServer) authorize(_ *http.Request, token string, scope lti.Scope) (ServiceClient, error) {
	s.scopes = append(s.scopes, scope)

	granted, ok := s.tokens[token]
	if !ok {
		return ServiceClient{}, lti.NewError(lti.ErrorInvalidToken, "the access token is unknown or expired", nil)
	}

	for _, g := range granted {
		if g == scope {
			return ServiceClient{ClientID: "client-1"}, nil
		}
	}

	return ServiceClient{}, lti.NewError(lti.ErrorInsufficientScope, "the access token can't read memberships", nil)
}

func (s *membershipsServer) list(_ *http.Request, client ServiceClient, req MembershipsRequest) (MembershipsPage, error) {
	s.requests = append(s.requests, req)

	members, ok := s.contexts[req.ContextID]
	if !ok || client.ClientID != "client-1" {
		return MembershipsPage{}, fmt.Errorf("looking up %q: %w", req.ContextID, ErrContextNotFound)
	}

	start := 0
	if req.PageToken != "" {
		if _, err := fmt.Sscan(req.PageToken, &start); err != nil || start >= len(members) {
			return MembershipsPage{}, lti.NewError(lti.ErrorInvalidRequest, "the page is unknown", err)
		}
	}

	size := s.pageSize
	if req.Limit > 0 && req.Limit < size {
		size = req.Limit
	}

	end := min(start+size, len(members))

	page := MembershipsPage{Context: lti.MembershipContext{ID: req.ContextID, Title: "Biology 1"}, Members: members[start:end]}
	if end < len(members) {
		page.NextPageToken = fmt.Sprint(end)
	}

	return page, nil
}

func createMembershipsTestConfig() Config {
	cfg := createTestConfig()
	cfg.Paths.ContextMemberships = "/contexts"

	return cfg
}

func newMembershipsTestHandler(t *testing.T, s *membershipsServer) http.Handler {
	t.Helper()

	handler, err := NewHandler(createMembershipsTestConfig(), Handlers{
		Register:           granting(&[]string{}),
		AuthorizeService:   s.authorize,
		ListContextMembers: s.list,
	})
	require.NoError(t, err)

	return handler
}

// getMemberships asks handler for target, an absolute URL, with token as the Bearer token, or
// with no Authorization header when token is "".
func getMemberships(t *testing.T, handler http.Handler, target, token string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	req.Header.Set("Accept", lti.MembershipContainerMediaType)

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	return w
}

func requireMembershipContainer(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, lti.MembershipContainerMediaType, w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

	return got
}

// ============================================================================
// Tests
// ============================================================================

func TestAddMembershipLinks(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	require.NoError(t, AddMembershipLinks(h, MembershipLinks{
		Next:        "https://platform.example.com/lti/memberships?page=2",
		Differences: "https://platform.example.com/lti/memberships?since=abc",
	}))

	assert.Equal(t, []string{
		`<https://platform.example.com/lti/memberships?page=2>; rel="next"`,
		`<https://platform.example.com/lti/memberships?since=abc>; rel="differences"`,
	}, h.Values("Link"))
}

func TestAddMembershipLinks_LeavesOutEmptyURLs(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	require.NoError(t, AddMembershipLinks(h, MembershipLinks{}))
	assert.Empty(t, h.Values("Link"), "the last page has no next link")

	require.NoError(t, AddMembershipLinks(h, MembershipLinks{Next: "https://platform.example.com/lti/memberships?page=2"}))
	assert.Equal(t, []string{`<https://platform.example.com/lti/memberships?page=2>; rel="next"`}, h.Values("Link"))
}

func TestAddMembershipLinks_Rejects(t *testing.T) {
	t.Parallel()

	for _, link := range []string{
		"http://platform.example.com/lti/memberships?page=2",
		"/lti/memberships?page=2",
		"https://platform.example.com/lti/memberships?page=2>; rel=\"differences\"",
		"https://platform.example.com/lti/memberships?page=<2>",
		"https://platform.example.com/lti/memberships?page= 2",
		"https://platform.example.com/lti/memberships?page=2\r\nSet-Cookie: a=b",
	} {
		h := http.Header{}
		require.Error(t, AddMembershipLinks(h, MembershipLinks{Next: link}), link)
		require.Error(t, AddMembershipLinks(h, MembershipLinks{
			Next:        "https://platform.example.com/lti/memberships?page=2",
			Differences: link,
		}), link)
		assert.Empty(t, h.Values("Link"), "nothing is added on an error")
	}
}

func TestNewHandler_ContextMemberships(t *testing.T) {
	t.Parallel()

	s := newMembershipsServer()
	handler := newMembershipsTestHandler(t, s)

	w := getMemberships(t, handler, "https://platform.example.com/lti/contexts/course-1/memberships", "token-1")

	got := requireMembershipContainer(t, w)
	assert.Equal(t, map[string]any{
		"id":      "https://platform.example.com/lti/contexts/course-1/memberships",
		"context": map[string]any{"id": "course-1", "title": "Biology 1"},
		"members": []any{
			map[string]any{"status": "Active", "user_id": "user-1", "roles": []any{string(lti.RoleInstructor)}},
			map[string]any{"status": "Active", "user_id": "user-2", "roles": []any{string(lti.RoleLearner)}},
		},
	}, got)
	assert.Equal(t, []string{`<https://platform.example.com/lti/contexts/course-1/memberships?page=2>; rel="next"`}, w.Header().Values("Link"))

	assert.Equal(t, []lti.Scope{lti.ScopeNRPSMembershipRead}, s.scopes)
	assert.Equal(t, []MembershipsRequest{{ContextID: "course-1", Role: "", Limit: 0, PageToken: "", ResourceLinkID: ""}}, s.requests)
}

func TestNewHandler_ContextMembershipsKeepsTheQueryInTheIDAndTheNextLink(t *testing.T) {
	t.Parallel()

	s := newMembershipsServer()
	handler := newMembershipsTestHandler(t, s)

	w := getMemberships(t, handler, "https://platform.example.com/lti/contexts/course-1/memberships?role=Learner&limit=1&rlid=link%201&unknown=x", "token-1")

	got := requireMembershipContainer(t, w)
	assert.Equal(t, "https://platform.example.com/lti/contexts/course-1/memberships?limit=1&rlid=link+1&role=Learner", got["id"])
	assert.Equal(t, []string{`<https://platform.example.com/lti/contexts/course-1/memberships?limit=1&page=1&rlid=link+1&role=Learner>; rel="next"`}, w.Header().Values("Link"))

	// The tool follows the next link.
	w = getMemberships(t, handler, "https://platform.example.com/lti/contexts/course-1/memberships?limit=1&page=1&rlid=link+1&role=Learner", "token-1")

	got = requireMembershipContainer(t, w)
	assert.Equal(t, "https://platform.example.com/lti/contexts/course-1/memberships?limit=1&page=1&rlid=link+1&role=Learner", got["id"])
	assert.Equal(t, []string{`<https://platform.example.com/lti/contexts/course-1/memberships?limit=1&page=2&rlid=link+1&role=Learner>; rel="next"`}, w.Header().Values("Link"))

	assert.Equal(t, []MembershipsRequest{
		{ContextID: "course-1", Role: "Learner", Limit: 1, PageToken: "", ResourceLinkID: "link 1"},
		{ContextID: "course-1", Role: "Learner", Limit: 1, PageToken: "1", ResourceLinkID: "link 1"},
	}, s.requests)
}

func TestNewHandler_ContextMembershipsLastPageHasNoNextLink(t *testing.T) {
	t.Parallel()

	handler := newMembershipsTestHandler(t, newMembershipsServer())

	w := getMemberships(t, handler, "https://platform.example.com/lti/contexts/course-1/memberships?page=2", "token-1")

	got := requireMembershipContainer(t, w)
	assert.Equal(t, "https://platform.example.com/lti/contexts/course-1/memberships?page=2", got["id"])
	assert.Len(t, got["members"], 1)
	assert.Empty(t, w.Header().Values("Link"), "the last page has no next link")
}

func TestNewHandler_ContextMembershipsWithoutMembers(t *testing.T) {
	t.Parallel()

	s := newMembershipsServer()
	s.contexts["empty"] = nil
	handler := newMembershipsTestHandler(t, s)

	w := getMemberships(t, handler, "https://platform.example.com/lti/contexts/empty/memberships", "token-1")

	got := requireMembershipContainer(t, w)
	assert.Equal(t, []any{}, got["members"])
	assert.Empty(t, w.Header().Values("Link"))
}

func TestNewHandler_ContextMembershipsFillsInTheContextID(t *testing.T) {
	t.Parallel()

	handler, err := NewHandler(createMembershipsTestConfig(), Handlers{
		Register:         granting(&[]string{}),
		AuthorizeService: newMembershipsServer().authorize,
		ListContextMembers: func(*http.Request, ServiceClient, MembershipsRequest) (MembershipsPage, error) {
			return MembershipsPage{}, nil
		},
	})
	require.NoError(t, err)

	got := requireMembershipContainer(t, getMemberships(t, handler, "https://platform.example.com/lti/contexts/course-1/memberships", "token-1"))
	assert.Equal(t, map[string]any{"id": "course-1"}, got["context"])
}

func TestNewHandler_ContextMembershipsUnescapesTheContextID(t *testing.T) {
	t.Parallel()

	s := newMembershipsServer()
	handler := newMembershipsTestHandler(t, s)

	w := getMemberships(t, handler, "https://platform.example.com/lti/contexts/workspace:a%20b%2Fc/memberships", "token-1")

	got := requireMembershipContainer(t, w)
	assert.Equal(t, "https://platform.example.com/lti/contexts/workspace:a%20b%2Fc/memberships", got["id"])
	assert.Equal(t, map[string]any{"id": "workspace:a b/c", "title": "Biology 1"}, got["context"])
	require.Len(t, s.requests, 1)
	assert.Equal(t, "workspace:a b/c", s.requests[0].ContextID)
}

func TestNewHandler_ContextMembershipsURLRoundTrips(t *testing.T) {
	t.Parallel()

	cfg := createMembershipsTestConfig()

	for _, contextID := range []string{"course-1", "workspace:a b/c", "a/../b", "a//b", "a%2Fb", "x?y#z", "a;b", "kurs-åäö", "..."} {
		var got string

		handler, err := NewHandler(cfg, Handlers{
			Register:         granting(&[]string{}),
			AuthorizeService: newMembershipsServer().authorize,
			ListContextMembers: func(_ *http.Request, _ ServiceClient, req MembershipsRequest) (MembershipsPage, error) {
				got = req.ContextID

				return MembershipsPage{}, nil
			},
		})
		require.NoError(t, err)

		membershipsURL, err := cfg.ContextMembershipsURL(contextID)
		require.NoError(t, err, contextID)

		container := requireMembershipContainer(t, getMemberships(t, handler, membershipsURL, "token-1"))
		assert.Equal(t, contextID, got)
		assert.Equal(t, membershipsURL, container["id"], "the container's id is the launch's url")
	}
}

func TestNewHandler_ContextMembershipsRefusesAMissingToken(t *testing.T) {
	t.Parallel()

	s := newMembershipsServer()
	handler := newMembershipsTestHandler(t, s)

	for _, authorization := range []string{"", "Basic Y2xpZW50OnNlY3JldA==", "Bearer ", "Bearer"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://platform.example.com/lti/contexts/course-1/memberships", http.NoBody)
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code, authorization)
		assert.Equal(t, "Bearer", w.Header().Get("WWW-Authenticate"), "no error code without a token (RFC 6750 §3.1)")
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	}

	assert.Empty(t, s.scopes, "AuthorizeService isn't called without a token")
	assert.Empty(t, s.requests)
}

func TestNewHandler_ContextMembershipsRefusesTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		token     string
		status    int
		challenge string
		code      lti.ErrorCode
	}{
		{name: "an unknown token", token: "token-unknown", status: http.StatusUnauthorized, challenge: `Bearer error="invalid_token"`, code: lti.ErrorInvalidToken},
		{
			name: "a token without the memberships scope", token: "token-scores", status: http.StatusForbidden,
			challenge: `Bearer error="insufficient_scope", scope="https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"`,
			code:      lti.ErrorInsufficientScope,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := newMembershipsServer()
			handler := newMembershipsTestHandler(t, s)

			w := getMemberships(t, handler, "https://platform.example.com/lti/contexts/course-1/memberships", tt.token)

			require.Equal(t, tt.status, w.Code, w.Body.String())
			assert.Equal(t, tt.challenge, w.Header().Get("WWW-Authenticate"))
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var got map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			assert.Equal(t, string(tt.code), got["error"])
			assert.Empty(t, s.requests, "ListContextMembers isn't called for a refused token")
		})
	}
}

func TestNewHandler_ContextMembershipsAnswersAnUnknownContextWith404(t *testing.T) {
	t.Parallel()

	var reported []error

	s := newMembershipsServer()
	handler, err := NewHandler(createMembershipsTestConfig(), Handlers{
		Register:           granting(&[]string{}),
		AuthorizeService:   s.authorize,
		ListContextMembers: s.list,
		OnError:            func(_ *http.Request, err error) { reported = append(reported, err) },
	})
	require.NoError(t, err)

	w := getMemberships(t, handler, "https://platform.example.com/lti/contexts/course-2/memberships", "token-1")

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Empty(t, w.Header().Values("Link"))
	require.Len(t, reported, 1)
	require.ErrorIs(t, reported[0], ErrContextNotFound)
}

func TestNewHandler_ContextMembershipsErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		target    string
		authorize func(*http.Request, string, lti.Scope) (ServiceClient, error)
		list      func(*http.Request, ServiceClient, MembershipsRequest) (MembershipsPage, error)
		status    int
		code      lti.ErrorCode
	}{
		{name: "a limit that isn't a number", target: "?limit=ten", status: http.StatusBadRequest, code: lti.ErrorInvalidRequest},
		{name: "a limit of zero", target: "?limit=0", status: http.StatusBadRequest, code: lti.ErrorInvalidRequest},
		{name: "a negative limit", target: "?limit=-1", status: http.StatusBadRequest, code: lti.ErrorInvalidRequest},
		{name: "a rejection from ListContextMembers", target: "?page=9", status: http.StatusBadRequest, code: lti.ErrorInvalidRequest},
		{
			name: "a failure of ListContextMembers",
			list: func(*http.Request, ServiceClient, MembershipsRequest) (MembershipsPage, error) {
				return MembershipsPage{}, errors.New("the database is down")
			},
			status: http.StatusInternalServerError,
		},
		{
			name: "a server_error from AuthorizeService",
			authorize: func(*http.Request, string, lti.Scope) (ServiceClient, error) {
				return ServiceClient{}, lti.NewError(lti.ErrorServerError, "the token store is down", nil)
			},
			status: http.StatusInternalServerError,
		},
		{
			name: "no client and no error from AuthorizeService",
			authorize: func(*http.Request, string, lti.Scope) (ServiceClient, error) {
				return ServiceClient{}, nil
			},
			status: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := newMembershipsServer()
			h := Handlers{Register: granting(&[]string{}), AuthorizeService: s.authorize, ListContextMembers: s.list}

			if tt.authorize != nil {
				h.AuthorizeService = tt.authorize
			}

			if tt.list != nil {
				h.ListContextMembers = tt.list
			}

			handler, err := NewHandler(createMembershipsTestConfig(), h)
			require.NoError(t, err)

			w := getMemberships(t, handler, "https://platform.example.com/lti/contexts/course-1/memberships"+tt.target, "token-1")

			require.Equal(t, tt.status, w.Code, w.Body.String())
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

			if tt.code != "" {
				var got map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
				assert.Equal(t, string(tt.code), got["error"])
				assert.Empty(t, w.Header().Get("WWW-Authenticate"), "only token refusals carry a challenge")
			}

			if tt.status == http.StatusInternalServerError {
				assert.NotContains(t, w.Body.String(), "down", "a failure says nothing more")
			}
		})
	}
}

func TestNewHandler_ContextMembershipsMethods(t *testing.T) {
	t.Parallel()

	handler := newMembershipsTestHandler(t, newMembershipsServer())

	w := serve(t, handler, http.MethodPost, "/lti/contexts/course-1/memberships", "Bearer token-1", "")
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	w = serve(t, handler, http.MethodGet, "/lti/contexts/course-1/members", "Bearer token-1", "")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestNewHandler_ContextMembershipsNeedsItsPathAndBothHandlers(t *testing.T) {
	t.Parallel()

	s := newMembershipsServer()

	for name, without := range map[string]func(*Config, *Handlers){
		"Paths.ContextMemberships": func(cfg *Config, _ *Handlers) { cfg.Paths.ContextMemberships = "" },
		"AuthorizeService":         func(_ *Config, h *Handlers) { h.AuthorizeService = nil },
		"ListContextMembers":       func(_ *Config, h *Handlers) { h.ListContextMembers = nil },
		"the handlers": func(_ *Config, h *Handlers) {
			h.AuthorizeService = nil
			h.ListContextMembers = nil
		},
		"the path and AuthorizeService": func(cfg *Config, h *Handlers) {
			cfg.Paths.ContextMemberships = ""
			h.AuthorizeService = nil
		},
	} {
		cfg := createMembershipsTestConfig()
		h := Handlers{Register: granting(&[]string{}), AuthorizeService: s.authorize, ListContextMembers: s.list}
		without(&cfg, &h)

		_, err := NewHandler(cfg, h)
		require.Error(t, err, "without "+name)
	}

	handler := newTestHandler(t, Handlers{Register: granting(&[]string{})})

	w := serve(t, handler, http.MethodGet, "/lti/contexts/course-1/memberships", "Bearer token-1", "")
	assert.Equal(t, http.StatusNotFound, w.Code, "not served without the memberships handlers")
}

func TestConfig_ContextMembershipsURL(t *testing.T) {
	t.Parallel()

	for _, issuer := range []string{"https://platform.example.com/lti", "https://platform.example.com/lti/"} {
		cfg := createMembershipsTestConfig()
		cfg.Issuer = issuer

		got, err := cfg.ContextMembershipsURL("workspace:a b/c")
		require.NoError(t, err)
		assert.Equal(t, "https://platform.example.com/lti/contexts/workspace:a%20b%2Fc/memberships", got)
	}

	cfg := createMembershipsTestConfig()
	for _, contextID := range []string{"", ".", ".."} {
		_, err := cfg.ContextMembershipsURL(contextID)
		require.Error(t, err, contextID)
	}

	_, err := createTestConfig().ContextMembershipsURL("course-1")
	require.Error(t, err, "without Paths.ContextMemberships")
}

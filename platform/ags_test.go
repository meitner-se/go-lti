package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
)

// agsServer is a platform's gradebook: its access tokens and their scopes, each context's line
// items, and each line item's results and the timestamp of its users' last scores. Line items and
// results are served a page of pageSize at a time with the next index as the page token. It
// records what the hooks got.
type agsServer struct {
	tokens     map[string][]lti.Scope
	contexts   map[string][]lti.LineItem
	results    map[LineItemRequest][]lti.Result
	timestamps map[string]time.Time
	nextID     int
	pageSize   int

	scopes   []lti.Scope
	listed   []LineItemsRequest
	created  []lti.LineItem
	updated  []lti.LineItem
	deleted  []LineItemRequest
	scores   []lti.Score
	resulted []ResultsRequest
}

func newAGSServer() *agsServer {
	return &agsServer{
		tokens: map[string][]lti.Scope{
			"token-1":         {lti.ScopeAGSLineItem, lti.ScopeAGSResultReadOnly, lti.ScopeAGSScore},
			"token-lineitem":  {lti.ScopeAGSLineItem},
			"token-readonly":  {lti.ScopeAGSLineItemReadOnly},
			"token-score":     {lti.ScopeAGSScore},
			"token-results":   {lti.ScopeAGSResultReadOnly},
			"token-nrps":      {lti.ScopeNRPSMembershipRead},
			"token-suspended": {lti.ScopeAGSLineItem, lti.ScopeAGSResultReadOnly, lti.ScopeAGSScore},
		},
		contexts: map[string][]lti.LineItem{
			"course-1": {
				{ID: "1", Label: "Chapter 1", ScoreMaximum: 10, ResourceLinkID: "link-1", Tag: "quiz"},
				{ID: "2", Label: "Chapter 2", ScoreMaximum: 20, ResourceID: "essay-2"},
				{ID: "3", Label: "Chapter 3", ScoreMaximum: 30, ResourceLinkID: "link-1"},
			},
			"course:a b/c": {{ID: "item/1 ?", Label: "Escaped", ScoreMaximum: 1}},
		},
		results: map[LineItemRequest][]lti.Result{
			{ContextID: "course-1", LineItemID: "1"}: {
				{UserID: "user-1", ResultScore: ptr(8.0), ResultMaximum: 10, Comment: "Good"},
				{UserID: "user-2"},
				{UserID: "user-3", ResultScore: ptr(0.0), ResultMaximum: 10},
			},
		},
		timestamps: map[string]time.Time{"user-1": time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)},
		nextID:     4,
		pageSize:   2,
	}
}

func ptr[T any](v T) *T { return &v }

func (s *agsServer) authorize(_ *http.Request, token string, scope lti.Scope) (ServiceClient, error) {
	s.scopes = append(s.scopes, scope)

	granted, ok := s.tokens[token]
	if !ok {
		return ServiceClient{}, lti.NewError(lti.ErrorInvalidToken, "the access token is unknown or expired", nil)
	}

	if token == "token-suspended" {
		return ServiceClient{}, lti.NewError(lti.ErrorInsufficientScope, "the tool is suspended", nil)
	}

	return ServiceClient{ClientID: "client-1", Scopes: granted}, nil
}

func (s *agsServer) find(req LineItemRequest) (int, error) {
	items, ok := s.contexts[req.ContextID]
	if !ok {
		return 0, fmt.Errorf("looking up %q: %w", req.ContextID, ErrContextNotFound)
	}

	i := slices.IndexFunc(items, func(item lti.LineItem) bool { return item.ID == req.LineItemID })
	if i < 0 {
		return 0, fmt.Errorf("looking up %q: %w", req.LineItemID, ErrLineItemNotFound)
	}

	return i, nil
}

// page returns the page of n items that token starts.
func (s *agsServer) page(n, limit int, token string) (start, end int, next string, err error) {
	if token != "" {
		if _, err := fmt.Sscan(token, &start); err != nil || start >= n {
			return 0, 0, "", lti.NewError(lti.ErrorInvalidRequest, "the page is unknown", err)
		}
	}

	size := s.pageSize
	if limit > 0 && limit < size {
		size = limit
	}

	end = min(start+size, n)
	if end < n {
		next = fmt.Sprint(end)
	}

	return start, end, next, nil
}

func (s *agsServer) handlers() Handlers {
	return Handlers{
		Register:         granting(&[]string{}),
		AuthorizeService: s.authorize,
		ListLineItems: func(_ *http.Request, _ ServiceClient, req LineItemsRequest) (LineItemsPage, error) {
			s.listed = append(s.listed, req)

			items, ok := s.contexts[req.ContextID]
			if !ok {
				return LineItemsPage{}, ErrContextNotFound
			}

			items = slices.DeleteFunc(slices.Clone(items), func(item lti.LineItem) bool {
				return req.ResourceLinkID != "" && item.ResourceLinkID != req.ResourceLinkID ||
					req.ResourceID != "" && item.ResourceID != req.ResourceID ||
					req.Tag != "" && item.Tag != req.Tag
			})

			start, end, next, err := s.page(len(items), req.Limit, req.PageToken)
			if err != nil {
				return LineItemsPage{}, err
			}

			return LineItemsPage{LineItems: items[start:end], NextPageToken: next}, nil
		},
		GetLineItem: func(_ *http.Request, _ ServiceClient, req LineItemRequest) (lti.LineItem, error) {
			i, err := s.find(req)
			if err != nil {
				return lti.LineItem{}, err
			}

			return s.contexts[req.ContextID][i], nil
		},
		CreateLineItem: func(_ *http.Request, _ ServiceClient, contextID string, item lti.LineItem) (lti.LineItem, error) {
			s.created = append(s.created, item)

			if _, ok := s.contexts[contextID]; !ok {
				return lti.LineItem{}, ErrContextNotFound
			}

			item.ID = fmt.Sprint(s.nextID)
			s.nextID++
			s.contexts[contextID] = append(s.contexts[contextID], item)

			return item, nil
		},
		UpdateLineItem: func(_ *http.Request, _ ServiceClient, req LineItemRequest, item lti.LineItem) (lti.LineItem, error) {
			s.updated = append(s.updated, item)

			i, err := s.find(req)
			if err != nil {
				return lti.LineItem{}, err
			}

			s.contexts[req.ContextID][i] = item

			return item, nil
		},
		DeleteLineItem: func(_ *http.Request, _ ServiceClient, req LineItemRequest) error {
			s.deleted = append(s.deleted, req)

			i, err := s.find(req)
			if err != nil {
				return err
			}

			s.contexts[req.ContextID] = slices.Delete(s.contexts[req.ContextID], i, i+1)

			return nil
		},
		PostScore: func(_ *http.Request, _ ServiceClient, req LineItemRequest, score lti.Score) error {
			s.scores = append(s.scores, score)

			if _, err := s.find(req); err != nil {
				return err
			}

			if last, ok := s.timestamps[score.UserID]; ok && !score.Timestamp.After(last) {
				return fmt.Errorf("scoring %q: %w", score.UserID, ErrStaleScore)
			}

			s.timestamps[score.UserID] = score.Timestamp

			return nil
		},
		ListResults: func(_ *http.Request, _ ServiceClient, req ResultsRequest) (ResultsPage, error) {
			s.resulted = append(s.resulted, req)

			if _, err := s.find(req.LineItemRequest); err != nil {
				return ResultsPage{}, err
			}

			results := slices.DeleteFunc(slices.Clone(s.results[req.LineItemRequest]), func(result lti.Result) bool {
				return req.UserID != "" && result.UserID != req.UserID
			})

			start, end, next, err := s.page(len(results), req.Limit, req.PageToken)
			if err != nil {
				return ResultsPage{}, err
			}

			return ResultsPage{Results: results[start:end], NextPageToken: next}, nil
		},
	}
}

func createAGSTestConfig() Config {
	cfg := createTestConfig()
	cfg.Paths.ContextLineItems = "/contexts"

	return cfg
}

func newAGSTestHandler(t *testing.T, s *agsServer) http.Handler {
	t.Helper()

	handler, err := NewHandler(createAGSTestConfig(), s.handlers())
	require.NoError(t, err)

	return handler
}

// callAGS sends method to target, an absolute URL, with body as JSON when it isn't "" and token
// as the Bearer token when it isn't "".
func callAGS(t *testing.T, handler http.Handler, method, target, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	return w
}

// requireAGSBody checks an answer's status, media type and Cache-Control, and decodes its body.
func requireAGSBody(t *testing.T, w *httptest.ResponseRecorder, status int, mediaType string) any {
	t.Helper()

	require.Equal(t, status, w.Code, w.Body.String())
	assert.Equal(t, mediaType, w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	var got any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

	return got
}

// requireAGSError checks an error answer's status, Cache-Control and OAuth 2.0 error response.
func requireAGSError(t *testing.T, w *httptest.ResponseRecorder, status int, code lti.ErrorCode, description string) {
	t.Helper()

	require.Equal(t, status, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, string(code), got["error"])

	if description != "" {
		assert.Equal(t, description, got["error_description"])
	}
}

const (
	lineItemsURL = "https://platform.example.com/lti/contexts/course-1/lineitems"
	lineItemURL  = lineItemsURL + "/1"
	validScore   = `{"userId": "user-2", "scoreGiven": 7, "scoreMaximum": 10, "timestamp": "2026-11-05T10:00:00.123+0000", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`
)

// ============================================================================
// Tests
// ============================================================================

func TestNewHandler_ListLineItems(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	w := callAGS(t, handler, http.MethodGet, lineItemsURL, "token-readonly", "")

	got := requireAGSBody(t, w, http.StatusOK, lti.LineItemContainerMediaType)
	assert.Equal(t, []any{
		map[string]any{"id": lineItemsURL + "/1", "label": "Chapter 1", "scoreMaximum": 10.0, "resourceLinkId": "link-1", "tag": "quiz"},
		map[string]any{"id": lineItemsURL + "/2", "label": "Chapter 2", "scoreMaximum": 20.0, "resourceId": "essay-2"},
	}, got)
	assert.Equal(t, []string{`<` + lineItemsURL + `?page=2>; rel="next"`}, w.Header().Values("Link"))

	assert.Equal(t, []lti.Scope{lti.ScopeAGSLineItemReadOnly}, s.scopes)
	assert.Equal(t, []LineItemsRequest{{ContextID: "course-1"}}, s.listed)
}

func TestNewHandler_ListLineItemsKeepsTheFiltersInTheNextLink(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	w := callAGS(t, handler, http.MethodGet, lineItemsURL+"?resource_link_id=link-1&limit=1&unknown=x", "token-1", "")

	got := requireAGSBody(t, w, http.StatusOK, lti.LineItemContainerMediaType)
	require.Len(t, got, 1)
	assert.Equal(t, []string{`<` + lineItemsURL + `?limit=1&page=1&resource_link_id=link-1>; rel="next"`}, w.Header().Values("Link"))

	// The tool follows the next link to the last page.
	w = callAGS(t, handler, http.MethodGet, lineItemsURL+"?limit=1&page=1&resource_link_id=link-1", "token-1", "")

	got = requireAGSBody(t, w, http.StatusOK, lti.LineItemContainerMediaType)
	assert.Equal(t, []any{map[string]any{"id": lineItemsURL + "/3", "label": "Chapter 3", "scoreMaximum": 30.0, "resourceLinkId": "link-1"}}, got)
	assert.Empty(t, w.Header().Values("Link"), "the last page has no next link")

	w = callAGS(t, handler, http.MethodGet, lineItemsURL+"?resource_id=essay-2&tag=x%20y", "token-1", "")
	assert.Equal(t, []any{}, requireAGSBody(t, w, http.StatusOK, lti.LineItemContainerMediaType), "an empty container is []")

	assert.Equal(t, []LineItemsRequest{
		{ContextID: "course-1", ResourceLinkID: "link-1", Limit: 1},
		{ContextID: "course-1", ResourceLinkID: "link-1", Limit: 1, PageToken: "1"},
		{ContextID: "course-1", ResourceID: "essay-2", Tag: "x y"},
	}, s.listed)
}

func TestNewHandler_CreateLineItem(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	body := `{"id": "https://tool.example.com/ignored", "scoreMaximum": 60, "label": "Chapter 5 Test", "resourceId": "quiz-231", "tag": "grade", ` +
		`"startDateTime": "2026-11-03T08:00:00Z", "endDateTime": "2026-11-10T16:00:00+0100"}`
	w := callAGS(t, handler, http.MethodPost, lineItemsURL, "token-lineitem", body)

	got := requireAGSBody(t, w, http.StatusCreated, lti.LineItemMediaType)
	assert.Equal(t, map[string]any{
		"id": lineItemsURL + "/4", "scoreMaximum": 60.0, "label": "Chapter 5 Test", "resourceId": "quiz-231", "tag": "grade",
		"startDateTime": "2026-11-03T08:00:00.000Z", "endDateTime": "2026-11-10T16:00:00.000+01:00",
	}, got)
	assert.Equal(t, lineItemsURL+"/4", w.Header().Get("Location"))

	require.Len(t, s.created, 1)
	assert.Empty(t, s.created[0].ID, "CreateLineItem gets no id")
	assert.Equal(t, "Chapter 5 Test", s.created[0].Label)
	assert.Equal(t, []lti.Scope{lti.ScopeAGSLineItem}, s.scopes)

	// The new line item is served at its id.
	w = callAGS(t, handler, http.MethodGet, lineItemsURL+"/4", "token-1", "")
	assert.Equal(t, got, requireAGSBody(t, w, http.StatusOK, lti.LineItemMediaType))
}

func TestNewHandler_CreateLineItemRefusesAnInvalidLineItem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		description string
	}{
		{name: "no label", body: `{"scoreMaximum": 10}`, description: "the line item's label is missing"},
		{name: "a blank label", body: `{"scoreMaximum": 10, "label": "  "}`, description: "the line item's label is missing"},
		{name: "no scoreMaximum", body: `{"label": "Quiz"}`, description: "the line item's scoreMaximum must be greater than 0"},
		{name: "a scoreMaximum of 0", body: `{"label": "Quiz", "scoreMaximum": 0}`, description: "the line item's scoreMaximum must be greater than 0"},
		{name: "a negative scoreMaximum", body: `{"label": "Quiz", "scoreMaximum": -1}`, description: "the line item's scoreMaximum must be greater than 0"},
		{
			name: "an end before the start", body: `{"label": "Quiz", "scoreMaximum": 1, "startDateTime": "2026-11-10T00:00:00Z", "endDateTime": "2026-11-03T00:00:00Z"}`,
			description: "the line item's endDateTime is before its startDateTime",
		},
		{name: "a scoreMaximum that isn't a number", body: `{"label": "Quiz", "scoreMaximum": "10"}`, description: "the line item is not valid JSON of its media type"},
		{name: "a time without a zone", body: `{"label": "Quiz", "scoreMaximum": 1, "startDateTime": "2026-11-10T00:00:00"}`, description: "the line item is not valid JSON of its media type"},
		{name: "no body", body: ``, description: "the line item is not valid JSON of its media type"},
		{name: "an array", body: `[]`, description: "the line item is not valid JSON of its media type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := newAGSServer()
			handler := newAGSTestHandler(t, s)

			requireAGSError(t, callAGS(t, handler, http.MethodPost, lineItemsURL, "token-1", tt.body), http.StatusBadRequest, lti.ErrorInvalidRequest, tt.description)
			requireAGSError(t, callAGS(t, handler, http.MethodPut, lineItemURL, "token-1", tt.body), http.StatusBadRequest, lti.ErrorInvalidRequest, tt.description)
			assert.Empty(t, s.created)
			assert.Empty(t, s.updated)
		})
	}
}

func TestNewHandler_LineItemBodyOverItsLimit(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	body := `{"label": "Quiz", "scoreMaximum": 1, "tag": "` + strings.Repeat("a", maxServiceBodyBytes) + `"}`

	requireAGSError(t, callAGS(t, handler, http.MethodPost, lineItemsURL, "token-1", body), http.StatusRequestEntityTooLarge, lti.ErrorInvalidRequest, "the line item is larger than 65536 bytes")
	requireAGSError(t, callAGS(t, handler, http.MethodPost, lineItemURL+"/scores", "token-1", body), http.StatusRequestEntityTooLarge, lti.ErrorInvalidRequest, "the score is larger than 65536 bytes")
	assert.Empty(t, s.created)
	assert.Empty(t, s.scores)
}

func TestNewHandler_GetLineItem(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	got := requireAGSBody(t, callAGS(t, handler, http.MethodGet, lineItemURL, "token-lineitem", ""), http.StatusOK, lti.LineItemMediaType)
	assert.Equal(t, map[string]any{"id": lineItemURL, "label": "Chapter 1", "scoreMaximum": 10.0, "resourceLinkId": "link-1", "tag": "quiz"}, got)
	assert.Equal(t, []lti.Scope{lti.ScopeAGSLineItemReadOnly}, s.scopes)
}

func TestNewHandler_UpdateLineItem(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	body := `{"id": "` + lineItemsURL + `/2", "label": "Chapter 1 (retake)", "scoreMaximum": 12, "resourceLinkId": "link-1", "gradesReleased": true}`
	got := requireAGSBody(t, callAGS(t, handler, http.MethodPut, lineItemURL, "token-lineitem", body), http.StatusOK, lti.LineItemMediaType)

	assert.Equal(t, map[string]any{"id": lineItemURL, "label": "Chapter 1 (retake)", "scoreMaximum": 12.0, "resourceLinkId": "link-1", "gradesReleased": true}, got,
		"the URL names the line item, not the body's id")
	require.Len(t, s.updated, 1)
	assert.Empty(t, s.updated[0].ID, "UpdateLineItem gets no id")
	assert.Equal(t, []lti.Scope{lti.ScopeAGSLineItem}, s.scopes)
}

func TestNewHandler_DeleteLineItem(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	w := callAGS(t, handler, http.MethodDelete, lineItemURL, "token-lineitem", "")
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Empty(t, w.Body.String())
	assert.Equal(t, []LineItemRequest{{ContextID: "course-1", LineItemID: "1"}}, s.deleted)

	requireAGSError(t, callAGS(t, handler, http.MethodGet, lineItemURL, "token-lineitem", ""), http.StatusNotFound, lti.ErrorInvalidRequest, "the line item is unknown")
}

func TestNewHandler_PostScore(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	w := callAGS(t, handler, http.MethodPost, lineItemURL+"/scores", "token-score", validScore)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Empty(t, w.Body.String())

	require.Len(t, s.scores, 1)
	assert.Equal(t, "user-2", s.scores[0].UserID)
	assert.Equal(t, ptr(7.0), s.scores[0].ScoreGiven)
	assert.True(t, time.Date(2026, 11, 5, 10, 0, 0, 123_000_000, time.UTC).Equal(s.scores[0].Timestamp), "a +0000 offset is read")
	assert.Equal(t, lti.GradingProgressFullyGraded, s.scores[0].GradingProgress)
	assert.Equal(t, []lti.Scope{lti.ScopeAGSScore}, s.scopes)

	// A score without scoreGiven clears it, and needs no scoreMaximum.
	w = callAGS(t, handler, http.MethodPost, lineItemURL+"/scores", "token-score",
		`{"userId": "user-3", "timestamp": "2026-11-05T10:00:00Z", "activityProgress": "Initialized", "gradingProgress": "NotReady"}`)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
}

func TestNewHandler_PostScoreAnswersAStaleScoreWith409(t *testing.T) {
	t.Parallel()

	var reported []error

	s := newAGSServer()
	h := s.handlers()
	h.OnError = func(_ *http.Request, err error) { reported = append(reported, err) }

	handler, err := NewHandler(createAGSTestConfig(), h)
	require.NoError(t, err)

	// user-1's last score was at 10:00:00 UTC, the same time as this one.
	stale := `{"userId": "user-1", "scoreGiven": 1, "scoreMaximum": 10, "timestamp": "2026-11-05T11:00:00+01:00", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`

	w := callAGS(t, handler, http.MethodPost, lineItemURL+"/scores", "token-score", stale)
	requireAGSError(t, w, http.StatusConflict, lti.ErrorInvalidRequest, "a score with the same or a later timestamp was already received")
	assert.Empty(t, w.Header().Get("WWW-Authenticate"))
	require.Len(t, reported, 1)
	require.ErrorIs(t, reported[0], ErrStaleScore)
}

func TestNewHandler_PostScoreRefusesAnInvalidScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		description string
	}{
		{name: "no userId", body: `{"timestamp": "2026-11-05T10:00:00Z", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`, description: "the score's userId is missing"},
		{name: "a blank userId", body: `{"userId": " ", "timestamp": "2026-11-05T10:00:00Z", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`, description: "the score's userId is missing"},
		{name: "no timestamp", body: `{"userId": "user-2", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`, description: "the score's timestamp is missing"},
		{name: "a blank timestamp", body: `{"userId": "user-2", "timestamp": "", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`, description: "the score's timestamp is missing"},
		{name: "a null timestamp", body: `{"userId": "user-2", "timestamp": null, "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`, description: "the score's timestamp is missing"},
		{name: "a timestamp without a zone", body: `{"userId": "user-2", "timestamp": "2026-11-05T10:00:00", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`, description: "the score is not valid JSON of its media type"},
		{name: "no activityProgress", body: `{"userId": "user-2", "timestamp": "2026-11-05T10:00:00Z", "gradingProgress": "FullyGraded"}`, description: "the score's activityProgress is missing or unknown"},
		{name: "an unknown activityProgress", body: `{"userId": "user-2", "timestamp": "2026-11-05T10:00:00Z", "activityProgress": "completed", "gradingProgress": "FullyGraded"}`, description: "the score's activityProgress is missing or unknown"},
		{name: "no gradingProgress", body: `{"userId": "user-2", "timestamp": "2026-11-05T10:00:00Z", "activityProgress": "Completed"}`, description: "the score's gradingProgress is missing or unknown"},
		{name: "an unknown gradingProgress", body: `{"userId": "user-2", "timestamp": "2026-11-05T10:00:00Z", "activityProgress": "Completed", "gradingProgress": "Graded"}`, description: "the score's gradingProgress is missing or unknown"},
		{name: "a negative scoreGiven", body: `{"userId": "user-2", "scoreGiven": -1, "scoreMaximum": 10, "timestamp": "2026-11-05T10:00:00Z", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`, description: "the score's scoreGiven must be 0 or more"},
		{name: "a scoreGiven without scoreMaximum", body: `{"userId": "user-2", "scoreGiven": 1, "timestamp": "2026-11-05T10:00:00Z", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`, description: "the score's scoreMaximum must be greater than 0"},
		{name: "a negative scoreMaximum", body: `{"userId": "user-2", "scoreMaximum": -10, "timestamp": "2026-11-05T10:00:00Z", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`, description: "the score's scoreMaximum must be greater than 0"},
		{name: "not JSON", body: `userId=user-2`, description: "the score is not valid JSON of its media type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := newAGSServer()
			handler := newAGSTestHandler(t, s)

			requireAGSError(t, callAGS(t, handler, http.MethodPost, lineItemURL+"/scores", "token-score", tt.body), http.StatusBadRequest, lti.ErrorInvalidRequest, tt.description)
			assert.Empty(t, s.scores, "PostScore isn't called for an invalid score")
		})
	}
}

func TestNewHandler_PostScoreAcceptsAScoreOverTheMaximum(t *testing.T) {
	t.Parallel()

	handler := newAGSTestHandler(t, newAGSServer())

	body := `{"userId": "user-2", "scoreGiven": 12, "scoreMaximum": 10, "timestamp": "2026-11-05T10:00:00Z", "activityProgress": "Completed", "gradingProgress": "FullyGraded"}`
	assert.Equal(t, http.StatusNoContent, callAGS(t, handler, http.MethodPost, lineItemURL+"/scores", "token-score", body).Code)
}

func TestNewHandler_ListResults(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	w := callAGS(t, handler, http.MethodGet, lineItemURL+"/results", "token-results", "")

	got := requireAGSBody(t, w, http.StatusOK, lti.ResultContainerMediaType)
	assert.Equal(t, []any{
		map[string]any{"id": lineItemURL + "/results?user_id=user-1", "scoreOf": lineItemURL, "userId": "user-1", "resultScore": 8.0, "resultMaximum": 10.0, "comment": "Good"},
		map[string]any{"id": lineItemURL + "/results?user_id=user-2", "scoreOf": lineItemURL, "userId": "user-2"},
	}, got)
	assert.Equal(t, []string{`<` + lineItemURL + `/results?page=2>; rel="next"`}, w.Header().Values("Link"))
	assert.Equal(t, []lti.Scope{lti.ScopeAGSResultReadOnly}, s.scopes)

	// A result's id is served: the results filtered to its user.
	w = callAGS(t, handler, http.MethodGet, lineItemURL+"/results?user_id=user-1", "token-results", "")
	assert.Equal(t, []any{got.([]any)[0]}, requireAGSBody(t, w, http.StatusOK, lti.ResultContainerMediaType))
	assert.Empty(t, w.Header().Values("Link"))

	w = callAGS(t, handler, http.MethodGet, lineItemURL+"/results?user_id=user%203&limit=1", "token-results", "")
	assert.Equal(t, []any{}, requireAGSBody(t, w, http.StatusOK, lti.ResultContainerMediaType))

	assert.Equal(t, []ResultsRequest{
		{LineItemRequest: LineItemRequest{ContextID: "course-1", LineItemID: "1"}},
		{LineItemRequest: LineItemRequest{ContextID: "course-1", LineItemID: "1"}, UserID: "user-1"},
		{LineItemRequest: LineItemRequest{ContextID: "course-1", LineItemID: "1"}, UserID: "user 3", Limit: 1},
	}, s.resulted)
}

func TestNewHandler_ListResultsKeepsTheFiltersInTheNextLink(t *testing.T) {
	t.Parallel()

	handler := newAGSTestHandler(t, newAGSServer())

	w := callAGS(t, handler, http.MethodGet, lineItemURL+"/results?limit=1&page=1", "token-results", "")

	got := requireAGSBody(t, w, http.StatusOK, lti.ResultContainerMediaType)
	assert.Len(t, got, 1)
	assert.Equal(t, []string{`<` + lineItemURL + `/results?limit=1&page=2>; rel="next"`}, w.Header().Values("Link"))
}

func TestNewHandler_AGSUnescapesTheIDs(t *testing.T) {
	t.Parallel()

	s := newAGSServer()
	handler := newAGSTestHandler(t, s)

	cfg := createAGSTestConfig()
	itemURL, err := cfg.LineItemURL("course:a b/c", "item/1 ?")
	require.NoError(t, err)
	assert.Equal(t, "https://platform.example.com/lti/contexts/course:a%20b%2Fc/lineitems/item%2F1%20%3F", itemURL)

	got := requireAGSBody(t, callAGS(t, handler, http.MethodGet, itemURL, "token-1", ""), http.StatusOK, lti.LineItemMediaType)
	assert.Equal(t, itemURL, got.(map[string]any)["id"])

	got = requireAGSBody(t, callAGS(t, handler, http.MethodGet, "https://platform.example.com/lti/contexts/course:a%20b%2Fc/lineitems", "token-1", ""),
		http.StatusOK, lti.LineItemContainerMediaType)
	assert.Equal(t, itemURL, got.([]any)[0].(map[string]any)["id"])

	w := callAGS(t, handler, http.MethodPost, itemURL+"/scores", "token-1", validScore)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
}

func TestNewHandler_AGSURLsRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := createAGSTestConfig()

	for _, id := range []string{"course-1", "course:a b/c", "a/../b", "a//b", "a%2Fb", "x?y#z", "a;b", "course-åäö", "..."} {
		var got []LineItemRequest

		h := newAGSServer().handlers()
		h.GetLineItem = func(_ *http.Request, _ ServiceClient, req LineItemRequest) (lti.LineItem, error) {
			got = append(got, req)

			return lti.LineItem{Label: "Quiz", ScoreMaximum: 1}, nil
		}
		h.ListLineItems = func(_ *http.Request, _ ServiceClient, req LineItemsRequest) (LineItemsPage, error) {
			got = append(got, LineItemRequest{ContextID: req.ContextID})

			return LineItemsPage{LineItems: []lti.LineItem{{ID: id, Label: "Quiz", ScoreMaximum: 1}}}, nil
		}

		handler, err := NewHandler(cfg, h)
		require.NoError(t, err)

		containerURL, err := cfg.LineItemsURL(id)
		require.NoError(t, err, id)

		itemURL, err := cfg.LineItemURL(id, id)
		require.NoError(t, err, id)

		container := requireAGSBody(t, callAGS(t, handler, http.MethodGet, containerURL, "token-1", ""), http.StatusOK, lti.LineItemContainerMediaType)
		assert.Equal(t, itemURL, container.([]any)[0].(map[string]any)["id"], id)

		item := requireAGSBody(t, callAGS(t, handler, http.MethodGet, itemURL, "token-1", ""), http.StatusOK, lti.LineItemMediaType)
		assert.Equal(t, itemURL, item.(map[string]any)["id"], "a line item's id is the launch's url")

		assert.Equal(t, []LineItemRequest{{ContextID: id}, {ContextID: id, LineItemID: id}}, got)
	}
}

// agsRoutes are the AGS routes on course-1's line item 1, with a valid body and the scopes that
// allow each.
var agsRoutes = []struct {
	method, target, body string
	allowed              []lti.Scope
	status               int
}{
	{http.MethodGet, lineItemsURL, "", []lti.Scope{lti.ScopeAGSLineItem, lti.ScopeAGSLineItemReadOnly}, http.StatusOK},
	{http.MethodPost, lineItemsURL, `{"label": "Quiz", "scoreMaximum": 1}`, []lti.Scope{lti.ScopeAGSLineItem}, http.StatusCreated},
	{http.MethodGet, lineItemURL, "", []lti.Scope{lti.ScopeAGSLineItem, lti.ScopeAGSLineItemReadOnly}, http.StatusOK},
	{http.MethodPut, lineItemURL, `{"label": "Quiz", "scoreMaximum": 1}`, []lti.Scope{lti.ScopeAGSLineItem}, http.StatusOK},
	{http.MethodDelete, lineItemURL, "", []lti.Scope{lti.ScopeAGSLineItem}, http.StatusNoContent},
	{http.MethodPost, lineItemURL + "/scores", validScore, []lti.Scope{lti.ScopeAGSScore}, http.StatusNoContent},
	{http.MethodGet, lineItemURL + "/results", "", []lti.Scope{lti.ScopeAGSResultReadOnly}, http.StatusOK},
}

func TestNewHandler_AGSScopes(t *testing.T) {
	t.Parallel()

	tokens := map[string]lti.Scope{
		"token-lineitem": lti.ScopeAGSLineItem,
		"token-readonly": lti.ScopeAGSLineItemReadOnly,
		"token-score":    lti.ScopeAGSScore,
		"token-results":  lti.ScopeAGSResultReadOnly,
		"token-nrps":     lti.ScopeNRPSMembershipRead,
	}

	for _, route := range agsRoutes {
		for token, scope := range tokens {
			t.Run(route.method+" "+route.target+" with "+token, func(t *testing.T) {
				t.Parallel()

				s := newAGSServer()
				handler := newAGSTestHandler(t, s)

				w := callAGS(t, handler, route.method, route.target, token, route.body)

				// AuthorizeService gets the narrowest scope that allows the route.
				assert.Equal(t, []lti.Scope{route.allowed[len(route.allowed)-1]}, s.scopes)

				if slices.Contains(route.allowed, scope) {
					assert.Equal(t, route.status, w.Code, w.Body.String())

					return
				}

				requireAGSError(t, w, http.StatusForbidden, lti.ErrorInsufficientScope, "")
				assert.Equal(t, `Bearer error="insufficient_scope", scope="`+string(route.allowed[len(route.allowed)-1])+`"`, w.Header().Get("WWW-Authenticate"))
				assert.Empty(t, s.listed)
				assert.Empty(t, s.created)
				assert.Empty(t, s.deleted)
				assert.Empty(t, s.scores)
				assert.Empty(t, s.resulted)
			})
		}
	}
}

func TestNewHandler_AGSRefusesTokens(t *testing.T) {
	t.Parallel()

	for _, route := range agsRoutes {
		t.Run(route.method+" "+route.target, func(t *testing.T) {
			t.Parallel()

			s := newAGSServer()
			handler := newAGSTestHandler(t, s)

			for _, authorization := range []string{"", "Basic Y2xpZW50OnNlY3JldA==", "Bearer "} {
				req := httptest.NewRequestWithContext(t.Context(), route.method, route.target, strings.NewReader(route.body))
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

			w := callAGS(t, handler, route.method, route.target, "token-unknown", route.body)
			requireAGSError(t, w, http.StatusUnauthorized, lti.ErrorInvalidToken, "")
			assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))

			w = callAGS(t, handler, route.method, route.target, "token-suspended", route.body)
			requireAGSError(t, w, http.StatusForbidden, lti.ErrorInsufficientScope, "the tool is suspended")

			assert.Empty(t, s.listed)
			assert.Empty(t, s.created)
			assert.Empty(t, s.deleted)
			assert.Empty(t, s.scores)
			assert.Empty(t, s.resulted)
		})
	}
}

func TestNewHandler_AGSAnswersUnknownContextsAndLineItemsWith404(t *testing.T) {
	t.Parallel()

	for _, route := range agsRoutes {
		for _, target := range []string{
			strings.Replace(route.target, "course-1", "course-2", 1),
			strings.Replace(route.target, "lineitems/1", "lineitems/9", 1),
			strings.Replace(route.target, "lineitems/1", "lineitems/%2E%2E", 1),
		} {
			if target == route.target {
				continue
			}

			t.Run(route.method+" "+target, func(t *testing.T) {
				t.Parallel()

				var reported []error

				h := newAGSServer().handlers()
				h.OnError = func(_ *http.Request, err error) { reported = append(reported, err) }

				handler, err := NewHandler(createAGSTestConfig(), h)
				require.NoError(t, err)

				w := callAGS(t, handler, route.method, target, "token-1", route.body)

				require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
				assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
				assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
				assert.Empty(t, w.Header().Get("WWW-Authenticate"))
				assert.Empty(t, w.Header().Values("Link"))
				assert.Empty(t, w.Header().Get("Location"))
				require.Len(t, reported, 1)

				if strings.Contains(target, "course-2") && !strings.Contains(target, "lineitems/") {
					assert.JSONEq(t, `{"error":"invalid_request","error_description":"the context is unknown"}`, w.Body.String())
					require.ErrorIs(t, reported[0], ErrContextNotFound)

					return
				}

				assert.Contains(t, []string{
					`{"error":"invalid_request","error_description":"the line item is unknown"}`,
					`{"error":"invalid_request","error_description":"the context is unknown"}`,
				}, strings.TrimSpace(w.Body.String()))
			})
		}
	}
}

func TestNewHandler_AGSErrors(t *testing.T) {
	t.Parallel()

	failing := func(h *Handlers, err error) {
		h.ListLineItems = func(*http.Request, ServiceClient, LineItemsRequest) (LineItemsPage, error) {
			return LineItemsPage{}, err
		}
		h.CreateLineItem = func(*http.Request, ServiceClient, string, lti.LineItem) (lti.LineItem, error) {
			return lti.LineItem{}, err
		}
		h.GetLineItem = func(*http.Request, ServiceClient, LineItemRequest) (lti.LineItem, error) { return lti.LineItem{}, err }
		h.UpdateLineItem = func(*http.Request, ServiceClient, LineItemRequest, lti.LineItem) (lti.LineItem, error) {
			return lti.LineItem{}, err
		}
		h.DeleteLineItem = func(*http.Request, ServiceClient, LineItemRequest) error { return err }
		h.PostScore = func(*http.Request, ServiceClient, LineItemRequest, lti.Score) error { return err }
		h.ListResults = func(*http.Request, ServiceClient, ResultsRequest) (ResultsPage, error) { return ResultsPage{}, err }
	}

	tests := []struct {
		name   string
		change func(h *Handlers)
		status int
		code   lti.ErrorCode
	}{
		{name: "a failure of the hook", change: func(h *Handlers) { failing(h, errors.New("the database is down")) }, status: http.StatusInternalServerError},
		{name: "a server_error from the hook", change: func(h *Handlers) { failing(h, lti.NewError(lti.ErrorServerError, "the database is down", nil)) }, status: http.StatusInternalServerError},
		{name: "a rejection from the hook", change: func(h *Handlers) { failing(h, lti.NewError(lti.ErrorInvalidRequest, "the tool may not", nil)) }, status: http.StatusBadRequest, code: lti.ErrorInvalidRequest},
		{
			name: "a server_error from AuthorizeService",
			change: func(h *Handlers) {
				h.AuthorizeService = func(*http.Request, string, lti.Scope) (ServiceClient, error) {
					return ServiceClient{}, lti.NewError(lti.ErrorServerError, "the token store is down", nil)
				}
			},
			status: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		for _, route := range agsRoutes {
			t.Run(tt.name+" for "+route.method+" "+route.target, func(t *testing.T) {
				t.Parallel()

				h := newAGSServer().handlers()
				tt.change(&h)

				handler, err := NewHandler(createAGSTestConfig(), h)
				require.NoError(t, err)

				w := callAGS(t, handler, route.method, route.target, "token-1", route.body)

				require.Equal(t, tt.status, w.Code, w.Body.String())
				assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
				assert.Empty(t, w.Header().Get("Location"))

				if tt.code != "" {
					requireAGSError(t, w, tt.status, tt.code, "the tool may not")
				}

				if tt.status == http.StatusInternalServerError {
					assert.NotContains(t, w.Body.String(), "down", "a failure says nothing more")
				}
			})
		}
	}
}

func TestNewHandler_AGSHooksThatReturnTooLittle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method, target string
		body           string
		change         func(h *Handlers)
	}{
		{
			name: "a listed line item without an id", method: http.MethodGet, target: lineItemsURL,
			change: func(h *Handlers) {
				h.ListLineItems = func(*http.Request, ServiceClient, LineItemsRequest) (LineItemsPage, error) {
					return LineItemsPage{LineItems: []lti.LineItem{{Label: "Quiz", ScoreMaximum: 1}}}, nil
				}
			},
		},
		{
			name: "a created line item without an id", method: http.MethodPost, target: lineItemsURL, body: `{"label": "Quiz", "scoreMaximum": 1}`,
			change: func(h *Handlers) {
				h.CreateLineItem = func(_ *http.Request, _ ServiceClient, _ string, item lti.LineItem) (lti.LineItem, error) {
					return item, nil
				}
			},
		},
		{
			name: "a result without a user id", method: http.MethodGet, target: lineItemURL + "/results",
			change: func(h *Handlers) {
				h.ListResults = func(*http.Request, ServiceClient, ResultsRequest) (ResultsPage, error) {
					return ResultsPage{Results: []lti.Result{{ResultScore: ptr(1.0)}}}, nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newAGSServer().handlers()
			tt.change(&h)

			handler, err := NewHandler(createAGSTestConfig(), h)
			require.NoError(t, err)

			w := callAGS(t, handler, tt.method, tt.target, "token-1", tt.body)
			require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
			assert.Empty(t, w.Header().Values("Link"))
			assert.Empty(t, w.Header().Get("Location"))
		})
	}
}

func TestNewHandler_AGSLimits(t *testing.T) {
	t.Parallel()

	for _, target := range []string{lineItemsURL, lineItemURL + "/results"} {
		for _, limit := range []string{"ten", "0", "-1", "1.5"} {
			s := newAGSServer()
			handler := newAGSTestHandler(t, s)

			w := callAGS(t, handler, http.MethodGet, target+"?limit="+limit, "token-1", "")
			requireAGSError(t, w, http.StatusBadRequest, lti.ErrorInvalidRequest, "limit must be a positive integer")
			assert.Empty(t, s.listed)
			assert.Empty(t, s.resulted)
		}

		// A page token the platform doesn't know is its own rejection.
		w := callAGS(t, newAGSTestHandler(t, newAGSServer()), http.MethodGet, target+"?page=9", "token-1", "")
		requireAGSError(t, w, http.StatusBadRequest, lti.ErrorInvalidRequest, "the page is unknown")
	}
}

func TestNewHandler_AGSMethods(t *testing.T) {
	t.Parallel()

	handler := newAGSTestHandler(t, newAGSServer())

	for _, call := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPut, "/lti/contexts/course-1/lineitems", http.StatusMethodNotAllowed},
		{http.MethodPatch, "/lti/contexts/course-1/lineitems/1", http.StatusMethodNotAllowed},
		{http.MethodGet, "/lti/contexts/course-1/lineitems/1/scores", http.StatusMethodNotAllowed},
		{http.MethodPost, "/lti/contexts/course-1/lineitems/1/results", http.StatusMethodNotAllowed},
		{http.MethodGet, "/lti/contexts/course-1/lineitems/1/results/user-1", http.StatusNotFound},
		{http.MethodGet, "/lti/contexts/course-1/memberships", http.StatusNotFound},
	} {
		w := serve(t, handler, call.method, call.path, "Bearer token-1", "")
		assert.Equal(t, call.status, w.Code, call.method+" "+call.path)
	}
}

func TestNewHandler_AGSConfiguration(t *testing.T) {
	t.Parallel()

	all := newAGSServer().handlers()
	without := map[string]func(h *Handlers){
		"ListLineItems":  func(h *Handlers) { h.ListLineItems = nil },
		"GetLineItem":    func(h *Handlers) { h.GetLineItem = nil },
		"CreateLineItem": func(h *Handlers) { h.CreateLineItem = nil },
		"UpdateLineItem": func(h *Handlers) { h.UpdateLineItem = nil },
		"DeleteLineItem": func(h *Handlers) { h.DeleteLineItem = nil },
		"PostScore":      func(h *Handlers) { h.PostScore = nil },
		"ListResults":    func(h *Handlers) { h.ListResults = nil },
	}

	for name, remove := range without {
		h := all
		remove(&h)

		_, err := NewHandler(createAGSTestConfig(), h)
		require.ErrorContains(t, err, "needs all of Paths.ContextLineItems, ListLineItems", "without "+name)
	}

	_, err := NewHandler(createTestConfig(), all)
	require.ErrorContains(t, err, "needs all of Paths.ContextLineItems", "the hooks without the path")

	_, err = NewHandler(createAGSTestConfig(), Handlers{Register: all.Register, AuthorizeService: all.AuthorizeService})
	require.ErrorContains(t, err, "needs all of Paths.ContextLineItems", "the path without the hooks")

	h := all
	h.AuthorizeService = nil
	_, err = NewHandler(createAGSTestConfig(), h)
	require.ErrorContains(t, err, "needs AuthorizeService")

	_, err = NewHandler(createTestConfig(), Handlers{Register: all.Register})
	require.NoError(t, err, "none of them")

	handler := newTestHandler(t, Handlers{Register: all.Register})
	w := serve(t, handler, http.MethodGet, "/lti/contexts/course-1/lineitems", "Bearer token-1", "")
	assert.Equal(t, http.StatusNotFound, w.Code, "not served without the line item handlers")
}

func TestNewHandler_AGSAndMembershipsShareAPrefix(t *testing.T) {
	t.Parallel()

	m := newMembershipsServer()
	m.tokens["token-1"] = append(m.tokens["token-1"], lti.ScopeAGSLineItem)

	cfg := createAGSTestConfig()
	cfg.Paths.ContextMemberships = cfg.Paths.ContextLineItems

	h := newAGSServer().handlers()
	h.AuthorizeService = m.authorize
	h.ListContextMembers = m.list

	handler, err := NewHandler(cfg, h)
	require.NoError(t, err)

	requireMembershipContainer(t, getMemberships(t, handler, "https://platform.example.com/lti/contexts/course-1/memberships", "token-1"))
	requireAGSBody(t, callAGS(t, handler, http.MethodGet, lineItemsURL, "token-1", ""), http.StatusOK, lti.LineItemContainerMediaType)
}

func TestConfig_LineItemURLs(t *testing.T) {
	t.Parallel()

	for _, issuer := range []string{"https://platform.example.com/lti", "https://platform.example.com/lti/"} {
		cfg := createAGSTestConfig()
		cfg.Issuer = issuer

		got, err := cfg.LineItemsURL("course:a b/c")
		require.NoError(t, err)
		assert.Equal(t, "https://platform.example.com/lti/contexts/course:a%20b%2Fc/lineitems", got)

		got, err = cfg.LineItemURL("course:a b/c", "1/2")
		require.NoError(t, err)
		assert.Equal(t, "https://platform.example.com/lti/contexts/course:a%20b%2Fc/lineitems/1%2F2", got)
	}

	cfg := createAGSTestConfig()
	for _, id := range []string{"", ".", ".."} {
		_, err := cfg.LineItemsURL(id)
		require.Error(t, err, id)

		_, err = cfg.LineItemURL(id, "1")
		require.Error(t, err, id)

		_, err = cfg.LineItemURL("course-1", id)
		require.Error(t, err, id)
	}

	_, err := createTestConfig().LineItemsURL("course-1")
	require.Error(t, err, "without Paths.ContextLineItems")

	_, err = createTestConfig().LineItemURL("course-1", "1")
	require.Error(t, err, "without Paths.ContextLineItems")
}

func TestConfig_Validate_ContextLineItems(t *testing.T) {
	t.Parallel()

	cfg := createTestConfig()
	require.NoError(t, cfg.Validate(), "it is optional")

	cfg.Paths.ContextLineItems = "/contexts"
	require.NoError(t, cfg.Validate())

	cfg.Paths.ContextMemberships = "/contexts"
	require.NoError(t, cfg.Validate(), "it may share the memberships prefix")

	for _, paths := range []struct{ memberships, lineItems string }{
		{"/contexts", "/contexts/ags"},
		{"/contexts/nrps", "/contexts"},
		{"", "/"},
		{"", "/contexts/"},
		{"", "/{tenant}/contexts"},
		{"", "/my contexts"},
		{"", "/jwks"},
		{"", PathOpenIDConfiguration},
	} {
		cfg := createTestConfig()
		cfg.Paths.ContextMemberships = paths.memberships
		cfg.Paths.ContextLineItems = paths.lineItems

		require.Error(t, cfg.Validate(), paths.memberships+" and "+paths.lineItems)
	}
}

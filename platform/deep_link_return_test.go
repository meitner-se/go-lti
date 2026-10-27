package platform

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/jwks"
	"github.com/meitner-se/go-lti/ltitest"
)

// ============================================================================
// Test helper functions
// ============================================================================

// deepLinkReturnTest serves the Deep Linking return for a tool that signs with tool, and records
// the lookups and results.
type deepLinkReturnTest struct {
	handler http.Handler
	tool    lti.SigningKey
	lookups []UnverifiedDeepLinkingResponse
	results []DeepLinkingResult
	logged  []error
}

type deepLinkReturnOptions struct {
	find    func(*http.Request, UnverifiedDeepLinkingResponse) (DeepLinkingSession, error)
	keysErr error
	logger  *slog.Logger
}

func findingTestDeepLinkingSession(*http.Request, UnverifiedDeepLinkingResponse) (DeepLinkingSession, error) {
	return createTestDeepLinkingSession(), nil
}

func newDeepLinkReturnTest(t *testing.T, opts deepLinkReturnOptions) *deepLinkReturnTest {
	t.Helper()

	if opts.find == nil {
		opts.find = findingTestDeepLinkingSession
	}

	test := &deepLinkReturnTest{tool: ltitest.NewSigningKey(t)}
	toolKey := ltitest.PublicKey(t, test.tool)

	keys := &mockKeySource{KeyFunc: func(_ context.Context, jwksURI, kid string) (*rsa.PublicKey, error) {
		if opts.keysErr != nil {
			return nil, opts.keysErr
		}

		if jwksURI != "https://tool.example.com/jwks" || kid != toolKey.ID {
			return nil, jwks.ErrKeyNotFound
		}

		return toolKey.PublicKey, nil
	}}

	test.handler = newTestHandler(t, Handlers{
		Register: granting(&[]string{}),
		ToolKeys: keys,
		Nonces:   lti.NewMemoryNonceStore(),
		FindDeepLinkingSession: func(r *http.Request, unverified UnverifiedDeepLinkingResponse) (DeepLinkingSession, error) {
			test.lookups = append(test.lookups, unverified)

			return opts.find(r, unverified)
		},
		HandleDeepLinkingResponse: func(w http.ResponseWriter, r *http.Request, result DeepLinkingResult) {
			test.results = append(test.results, result)

			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, "https://platform.example.com/done", http.StatusSeeOther)
		},
		Logger:  opts.logger,
		OnError: func(_ *http.Request, err error) { test.logged = append(test.logged, err) },
	})

	return test
}

func (d *deepLinkReturnTest) sign(t *testing.T, claims map[string]any) string {
	t.Helper()

	return ltitest.Sign(t, d.tool, claims)
}

func (d *deepLinkReturnTest) post(t *testing.T, rawJWT string) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{}
	if rawJWT != "" {
		form.Set(lti.DeepLinkingResponseField, rawJWT)
	}

	return postForm(t, d.handler, "/lti/deep-link-return", form)
}

func postForm(t *testing.T, handler http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	return w
}

func requireErrorPage(t *testing.T, w *httptest.ResponseRecorder, status int, message string) {
	t.Helper()

	require.Equal(t, status, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "default-src 'none'; style-src 'unsafe-inline'", w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), message)
}

// unsignedJWT returns a JWT with payload as its claims and a signature that isn't one.
func unsignedJWT(payload string) string {
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

// ============================================================================
// Tests
// ============================================================================

func TestNewHandler_DeepLinkReturn(t *testing.T) {
	t.Parallel()

	const (
		resultVerified = "verified"
		resultRejected = "rejected"
		resultFailed   = "failed"
	)

	tests := []struct {
		name string
		opts deepLinkReturnOptions
		// jwt returns the JWT to post, or "" to post none.
		jwt         func(t *testing.T, d *deepLinkReturnTest) string
		wantStatus  int
		wantPage    string
		wantLookups int
		wantResult  string
		wantErr     string
	}{
		{
			name: "a valid response reaches HandleDeepLinkingResponse verified",
			jwt: func(t *testing.T, d *deepLinkReturnTest) string {
				return d.sign(t, createTestDeepLinkingResponseClaims(time.Now()))
			},
			wantStatus:  http.StatusSeeOther,
			wantLookups: 1,
			wantResult:  resultVerified,
		},
		{
			name: "a response signed by another key reaches it rejected, with its session",
			jwt: func(t *testing.T, _ *deepLinkReturnTest) string {
				return ltitest.Sign(t, ltitest.NewSigningKey(t), createTestDeepLinkingResponseClaims(time.Now()))
			},
			wantStatus:  http.StatusSeeOther,
			wantLookups: 1,
			wantResult:  resultRejected,
			wantErr:     "not a valid jwt from the tool",
		},
		{
			name: "a response for another audience reaches it rejected",
			jwt: func(t *testing.T, d *deepLinkReturnTest) string {
				claims := createTestDeepLinkingResponseClaims(time.Now())
				claims["aud"] = "https://other-platform.example.com"

				return d.sign(t, claims)
			},
			wantStatus:  http.StatusSeeOther,
			wantLookups: 1,
			wantResult:  resultRejected,
			wantErr:     "not a valid jwt from the tool",
		},
		{
			name: "a tool key that can't be fetched reaches it as the platform's failure",
			opts: deepLinkReturnOptions{keysErr: errors.New("jwks fetch timed out")},
			jwt: func(t *testing.T, d *deepLinkReturnTest) string {
				return d.sign(t, createTestDeepLinkingResponseClaims(time.Now()))
			},
			wantStatus:  http.StatusSeeOther,
			wantLookups: 1,
			wantResult:  resultFailed,
			wantErr:     "jwks fetch timed out",
		},
		{
			name:       "a missing JWT gets an error page",
			jwt:        func(*testing.T, *deepLinkReturnTest) string { return "" },
			wantStatus: http.StatusBadRequest,
			wantPage:   "The content could not be added: deep linking response is missing.",
		},
		{
			name: "an oversized JWT gets an error page",
			jwt: func(*testing.T, *deepLinkReturnTest) string {
				return strings.Repeat("a", MaxDeepLinkingResponseBytes+1)
			},
			wantStatus: http.StatusBadRequest,
			wantPage:   "deep linking response is larger than 1 MiB",
		},
		{
			name:       "a JWT that isn't one gets an error page",
			jwt:        func(*testing.T, *deepLinkReturnTest) string { return "not-a-jwt" },
			wantStatus: http.StatusBadRequest,
			wantPage:   "deep linking response is not a jwt",
		},
		{
			name: "a JWT without iss, deployment_id or data gets the no-session page",
			jwt: func(*testing.T, *deepLinkReturnTest) string {
				return unsignedJWT(`{"aud":"https://platform.example.com/lti","https://purl.imsglobal.org/spec/lti-dl/claim/data":""}`)
			},
			wantStatus: http.StatusBadRequest,
			wantPage:   "the deep linking request is unknown, has expired or was already answered",
		},
		{
			name: "a request the platform doesn't know gets the no-session page",
			opts: deepLinkReturnOptions{find: func(*http.Request, UnverifiedDeepLinkingResponse) (DeepLinkingSession, error) {
				return DeepLinkingSession{}, fmt.Errorf("request-1: %w", ErrDeepLinkingSessionNotFound)
			}},
			jwt: func(t *testing.T, d *deepLinkReturnTest) string {
				return d.sign(t, createTestDeepLinkingResponseClaims(time.Now()))
			},
			wantStatus:  http.StatusBadRequest,
			wantPage:    "the deep linking request is unknown, has expired or was already answered",
			wantLookups: 1,
		},
		{
			name: "a lookup that fails gets a 500 page that says nothing more",
			opts: deepLinkReturnOptions{find: func(*http.Request, UnverifiedDeepLinkingResponse) (DeepLinkingSession, error) {
				return DeepLinkingSession{}, errors.New("database down at 10.0.0.12")
			}},
			jwt: func(t *testing.T, d *deepLinkReturnTest) string {
				return d.sign(t, createTestDeepLinkingResponseClaims(time.Now()))
			},
			wantStatus:  http.StatusInternalServerError,
			wantPage:    "The content could not be added. Start again.",
			wantLookups: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newDeepLinkReturnTest(t, tc.opts)

			w := d.post(t, tc.jwt(t, d))

			assert.Len(t, d.lookups, tc.wantLookups)

			if tc.wantPage != "" {
				requireErrorPage(t, w, tc.wantStatus, tc.wantPage)
				assert.NotContains(t, w.Body.String(), "10.0.0.12")
				assert.Empty(t, d.results)
				assert.Len(t, d.logged, 1, "OnError sees the error the browser got")

				return
			}

			require.Equal(t, tc.wantStatus, w.Code, w.Body.String())
			require.Len(t, d.results, 1)

			result := d.results[0]
			assert.Equal(t, createTestDeepLinkingSession(), result.Session, "the session reaches the callback whatever the outcome")
			assert.Equal(t, "request-1", result.Unverified.Data)

			switch tc.wantResult {
			case resultVerified:
				require.NoError(t, result.Err)
				require.NotNil(t, result.Response)
				require.Len(t, result.Response.Items, 1)
				assert.Equal(t, "https://tool.example.com/launch/quiz-1", result.Response.Items[0].URL)
				assert.Empty(t, d.logged)
			case resultRejected:
				assert.Nil(t, result.Response)

				rejection, ok := lti.AsError(result.Err)
				require.True(t, ok, "want an *lti.Error, got %v", result.Err)
				assert.Contains(t, rejection.Description, tc.wantErr)
				assert.Equal(t, []error{result.Err}, d.logged)
			case resultFailed:
				assert.Nil(t, result.Response)
				require.Error(t, result.Err)

				_, ok := lti.AsError(result.Err)
				assert.False(t, ok, "a platform failure is not a rejection")
				require.ErrorContains(t, result.Err, tc.wantErr)
				assert.Equal(t, []error{result.Err}, d.logged)
			}
		})
	}
}

func TestNewHandler_DeepLinkReturnRefusesAReplayedNonce(t *testing.T) {
	t.Parallel()

	d := newDeepLinkReturnTest(t, deepLinkReturnOptions{})
	raw := d.sign(t, createTestDeepLinkingResponseClaims(time.Now()))

	assert.Equal(t, http.StatusSeeOther, d.post(t, raw).Code)
	assert.Equal(t, http.StatusSeeOther, d.post(t, raw).Code)

	require.Len(t, d.results, 2)
	require.NoError(t, d.results[0].Err)

	rejection, ok := lti.AsError(d.results[1].Err)
	require.True(t, ok)
	assert.Contains(t, rejection.Description, "nonce was already used")
	assert.Equal(t, createTestDeepLinkingSession(), d.results[1].Session)
}

func TestNewHandler_DeepLinkReturnLooksUpByTheUnverifiedClaims(t *testing.T) {
	t.Parallel()

	t.Run("the lookup gets iss, aud, deployment_id and data", func(t *testing.T) {
		t.Parallel()

		d := newDeepLinkReturnTest(t, deepLinkReturnOptions{})
		d.post(t, d.sign(t, createTestDeepLinkingResponseClaims(time.Now())))

		assert.Equal(t, []UnverifiedDeepLinkingResponse{{
			Issuer:       "client-1",
			Audience:     []string{"https://platform.example.com/lti"},
			DeploymentID: "deployment-1",
			Data:         "request-1",
		}}, d.lookups)
	})

	t.Run("a response without data is looked up by its other claims", func(t *testing.T) {
		t.Parallel()

		d := newDeepLinkReturnTest(t, deepLinkReturnOptions{find: func(*http.Request, UnverifiedDeepLinkingResponse) (DeepLinkingSession, error) {
			session := createTestDeepLinkingSession()
			session.Settings.Data = ""

			return session, nil
		}})

		claims := createTestDeepLinkingResponseClaims(time.Now())
		delete(claims, lti.ClaimDeepLinkingData)

		assert.Equal(t, http.StatusSeeOther, d.post(t, d.sign(t, claims)).Code)

		require.Len(t, d.lookups, 1)
		assert.Equal(t, "client-1", d.lookups[0].Issuer)
		assert.Empty(t, d.lookups[0].Data)
		require.Len(t, d.results, 1)
		require.NoError(t, d.results[0].Err)
	})
}

func TestNewHandler_DeepLinkReturnLogsLikeTheOtherEndpoints(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer

	d := newDeepLinkReturnTest(t, deepLinkReturnOptions{logger: slog.New(slog.NewJSONHandler(&logs, nil))})

	d.post(t, "")
	d.post(t, ltitest.Sign(t, ltitest.NewSigningKey(t), createTestDeepLinkingResponseClaims(time.Now())))

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], `"code":"invalid_request"`)
	assert.Contains(t, lines[0], `"path":"/lti/deep-link-return"`)
	assert.Contains(t, lines[1], "not a valid jwt from the tool")
	assert.Len(t, d.logged, 2)
}

func TestNewHandler_DeepLinkReturnMethods(t *testing.T) {
	t.Parallel()

	d := newDeepLinkReturnTest(t, deepLinkReturnOptions{})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		w := serve(t, d.handler, method, "/lti/deep-link-return", "", "")

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, method)
		assert.Equal(t, "POST", w.Header().Get("Allow"), method)
	}

	assert.Empty(t, d.lookups)
}

func TestNewHandler_DeepLinkReturnNeedsAllItsHandlers(t *testing.T) {
	t.Parallel()

	complete := Handlers{
		Register:                  granting(&[]string{}),
		ToolKeys:                  &mockKeySource{},
		Nonces:                    lti.NewMemoryNonceStore(),
		FindDeepLinkingSession:    findingTestDeepLinkingSession,
		HandleDeepLinkingResponse: func(http.ResponseWriter, *http.Request, DeepLinkingResult) {},
	}

	for name, without := range map[string]func(*Handlers){
		"ToolKeys":                  func(h *Handlers) { h.ToolKeys = nil },
		"Nonces":                    func(h *Handlers) { h.Nonces = nil },
		"FindDeepLinkingSession":    func(h *Handlers) { h.FindDeepLinkingSession = nil },
		"HandleDeepLinkingResponse": func(h *Handlers) { h.HandleDeepLinkingResponse = nil },
	} {
		h := complete
		without(&h)

		_, err := NewHandler(createTestConfig(), h)
		require.Error(t, err, "without "+name)
	}

	handler := newTestHandler(t, Handlers{Register: granting(&[]string{})})

	w := postForm(t, handler, "/lti/deep-link-return", url.Values{lti.DeepLinkingResponseField: {"a.b.c"}})
	assert.Equal(t, http.StatusNotFound, w.Code, "not served without the deep linking handlers")
}

func TestParseUnverifiedDeepLinkingResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		jwt  string
		want UnverifiedDeepLinkingResponse
	}{
		{
			name: "every claim",
			jwt: unsignedJWT(`{"iss":"client-1","aud":"https://platform.example.com/lti",` +
				`"https://purl.imsglobal.org/spec/lti/claim/deployment_id":"deployment-1",` +
				`"https://purl.imsglobal.org/spec/lti-dl/claim/data":"request-1"}`),
			want: UnverifiedDeepLinkingResponse{Issuer: "client-1", Audience: []string{"https://platform.example.com/lti"}, DeploymentID: "deployment-1", Data: "request-1"},
		},
		{
			name: "an audience array",
			jwt:  unsignedJWT(`{"iss":"client-1","aud":["https://platform.example.com/lti","https://other.example.com"]}`),
			want: UnverifiedDeepLinkingResponse{Issuer: "client-1", Audience: []string{"https://platform.example.com/lti", "https://other.example.com"}},
		},
		{
			name: "claims that aren't strings count as missing",
			jwt: unsignedJWT(`{"iss":1,"aud":{"a":"b"},` +
				`"https://purl.imsglobal.org/spec/lti/claim/deployment_id":["deployment-1"],` +
				`"https://purl.imsglobal.org/spec/lti-dl/claim/data":{"id":"request-1"}}`),
			want: UnverifiedDeepLinkingResponse{},
		},
		{
			name: "empty data counts as missing",
			jwt:  unsignedJWT(`{"iss":"client-1","https://purl.imsglobal.org/spec/lti-dl/claim/data":""}`),
			want: UnverifiedDeepLinkingResponse{Issuer: "client-1"},
		},
		{
			name: "no claims",
			jwt:  unsignedJWT(`{}`),
			want: UnverifiedDeepLinkingResponse{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseUnverifiedDeepLinkingResponse(tc.jwt)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseUnverifiedDeepLinkingResponse_Rejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		jwt     string
		message string
	}{
		"missing":                               {"", "is missing"},
		"oversized, checked before it is split": {strings.Repeat(".", MaxDeepLinkingResponseBytes+1), "larger than 1 MiB"},
		"two parts":                             {"eyJhbGciOiJSUzI1NiJ9.e30", "not a jwt"},
		"four parts":                            {unsignedJWT(`{}`) + ".x", "not a jwt"},
		"a payload that isn't base64url":        {"eyJhbGciOiJSUzI1NiJ9.e30=.c2ln", "not a jwt"},
		"a payload that isn't json":             {unsignedJWT(`not json`), "not a jwt"},
		"a payload that is an array":            {unsignedJWT(`[]`), "not a jwt"},
		"a payload that is null":                {unsignedJWT(`null`), "not a jwt"},
		"a payload that is a string":            {unsignedJWT(`"claims"`), "not a jwt"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseUnverifiedDeepLinkingResponse(tc.jwt)
			requireRejection(t, err, tc.message)
		})
	}
}

package platform

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/ltitest"
	"github.com/meitner-se/go-lti/safehttp"
)

func createTestNotice() Notice {
	return Notice{
		DeploymentID: "deployment-1",
		ID:           "3d5c8e2a-0b1f-4c6d-9e7a-2f4b6d8a0c1e",
		Type:         contextCopyNotice,
		Timestamp:    time.Date(2026, 11, 10, 13, 45, 12, 0, time.FixedZone("CET", 3600)),
	}
}

type testSubmissionClaim struct {
	ID string `json:"id"`
}

func (testSubmissionClaim) ClaimName() string {
	return "https://purl.imsglobal.org/spec/lti/claim/submission"
}

// verifyNotice verifies token as a tool would, against the platform's published JWKS, and returns
// its claims.
func verifyNotice(t *testing.T, launcher *Launcher, token string) (*jwt.Token, jwt.MapClaims) {
	t.Helper()

	set, err := launcher.JWKS(t.Context())
	require.NoError(t, err)

	body := mustJSON(t, set)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	fetcher := newTestFetcher(t, server.Client())
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)

		return fetcher.Key(t.Context(), server.URL, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer("https://platform.example.com/lti"),
		jwt.WithAudience("client-1"),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	require.NoError(t, err)

	return parsed, claims
}

// ============================================================================
// Tests
// ============================================================================

func TestLauncher_SignNotice_VerifiesAgainstThePublishedJWKS(t *testing.T) {
	t.Parallel()

	key := ltitest.NewSigningKey(t)
	launcher, err := NewLauncher(createTestConfig(), ltitest.NewKeys(t, key))
	require.NoError(t, err)

	notice := createTestNotice()
	notice.Subject = "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b"
	notice.Context = &lti.LaunchContext{ID: "course-1"}
	notice.Custom = map[string]string{"course": "biology"}
	notice.Claims = []lti.Claim{testSubmissionClaim{ID: "submission-1"}}

	token, err := launcher.SignNotice(t.Context(), createTestTool(), notice)
	require.NoError(t, err)

	parsed, claims := verifyNotice(t, launcher, token)

	assert.Equal(t, key.ID, parsed.Header["kid"])
	assert.Equal(t, "JWT", parsed.Header["typ"])
	assert.NotEmpty(t, claims["nonce"])
	assert.InDelta(t, NoticeTTL.Seconds(), claims["exp"].(float64)-claims["iat"].(float64), 0)
	assert.Equal(t, "1.3.0", claims[lti.ClaimVersion])
	assert.Equal(t, "deployment-1", claims[lti.ClaimDeploymentID])
	assert.Equal(t, "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b", claims["sub"])
	assert.Equal(t, map[string]any{
		"id":        "3d5c8e2a-0b1f-4c6d-9e7a-2f4b6d8a0c1e",
		"timestamp": "2026-11-10T13:45:12.000+01:00",
		"type":      "LtiContextCopyNotice",
	}, claims[lti.ClaimNotice])
	assert.Equal(t, map[string]any{"id": "course-1"}, claims[lti.ClaimContext])
	assert.Equal(t, map[string]any{"course": "biology"}, claims[lti.ClaimCustom])
	assert.Equal(t, map[string]any{"guid": "platform-1", "name": "Example LMS", "version": "1.0.0", "product_family_code": "example"}, claims[lti.ClaimToolPlatform])
	assert.Equal(t, map[string]any{"id": "submission-1"}, claims["https://purl.imsglobal.org/spec/lti/claim/submission"])
	assert.NotContains(t, claims, lti.ClaimMessageType, "a notice isn't a launch")
}

func TestLauncher_SignNotice_DoesNotVerifyAgainstAnotherKey(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	server := ltitest.NewJWKSServer(t, ltitest.NewSigningKey(t))

	token, err := launcher.SignNotice(t.Context(), createTestTool(), createTestNotice())
	require.NoError(t, err)

	fetcher := newTestFetcher(t, server.Client())
	_, err = jwt.Parse(token, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)

		return fetcher.Key(t.Context(), server.URL, kid)
	}, jwt.WithValidMethods([]string{"RS256"}))
	require.Error(t, err)
}

func TestLauncher_SignNotice_AResendIsSignedAgain(t *testing.T) {
	t.Parallel()

	now := testNow
	launcher, err := NewLauncher(createTestConfig(), ltitest.NewKeys(t, ltitest.NewSigningKey(t)), WithClock(func() time.Time { return now }))
	require.NoError(t, err)

	first, err := launcher.SignNotice(t.Context(), createTestTool(), createTestNotice())
	require.NoError(t, err)

	now = now.Add(time.Minute)

	resend, err := launcher.SignNotice(t.Context(), createTestTool(), createTestNotice())
	require.NoError(t, err)

	parse := func(token string) jwt.MapClaims {
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(token, claims)
		require.NoError(t, err)

		return claims
	}

	a, b := parse(first), parse(resend)
	assert.NotEqual(t, a["nonce"], b["nonce"], "a new nonce")
	assert.InDelta(t, 60, b["iat"].(float64)-a["iat"].(float64), 0, "a new iat")
	assert.InDelta(t, 60, b["exp"].(float64)-a["exp"].(float64), 0, "a new exp")
	assert.Equal(t, a[lti.ClaimNotice], b[lti.ClaimNotice], "the same notice id, timestamp and type")
}

func TestLauncher_SignNotice_CarriesRolesAndServiceClaims(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	notice := createTestNotice()
	notice.Subject = "teacher-1"
	notice.Roles = []lti.Role{lti.RoleInstructor}
	notice.Context = &lti.LaunchContext{ID: "course-1"}
	notice.ContextMembershipsURL = "https://platform.example.com/lti/contexts/course-1/memberships"
	notice.AGSEndpoint = &lti.AGSEndpoint{Scopes: []lti.Scope{lti.ScopeAGSScore}, LineItems: "https://platform.example.com/lti/contexts/course-1/lineitems"}

	claims, err := launcher.noticeClaims(createTestTool(), notice, "nonce-1", testNow)
	require.NoError(t, err)

	got := claimsJSON(t, map[string]any{
		lti.ClaimRoles:            claims[lti.ClaimRoles],
		lti.ClaimNamesRoleService: claims[lti.ClaimNamesRoleService],
		lti.ClaimAGSEndpoint:      claims[lti.ClaimAGSEndpoint],
	})
	assert.JSONEq(t, `{
		"https://purl.imsglobal.org/spec/lti/claim/roles": ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
		"https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
			"context_memberships_url": "https://platform.example.com/lti/contexts/course-1/memberships",
			"service_versions": ["2.0"]
		},
		"https://purl.imsglobal.org/spec/lti-ags/claim/endpoint": {
			"scope": ["https://purl.imsglobal.org/spec/lti-ags/scope/score"],
			"lineitems": "https://platform.example.com/lti/contexts/course-1/lineitems"
		}
	}`, got)
}

func TestLauncher_SignNotice_LeavesOutWhatTheNoticeHasNot(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	claims, err := launcher.noticeClaims(createTestTool(), createTestNotice(), "nonce-1", testNow)
	require.NoError(t, err)

	for _, name := range []string{"sub", lti.ClaimRoles, lti.ClaimContext, lti.ClaimCustom, lti.ClaimNamesRoleService, lti.ClaimAGSEndpoint} {
		assert.NotContains(t, claims, name)
	}
}

func TestLauncher_SignNotice_Rejects(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	long := string(make([]byte, 256))

	tests := map[string]struct {
		tool   func(*Tool)
		notice func(*Notice)
		err    string
	}{
		"no client_id":            {tool: func(tool *Tool) { tool.ClientID = "" }, err: "client_id"},
		"no deployment":           {notice: func(n *Notice) { n.DeploymentID = "" }, err: "deployment_id"},
		"a long deployment":       {notice: func(n *Notice) { n.DeploymentID = long }, err: "deployment_id"},
		"no id":                   {notice: func(n *Notice) { n.ID = "" }, err: "id"},
		"a long id":               {notice: func(n *Notice) { n.ID = long }, err: "id"},
		"no type":                 {notice: func(n *Notice) { n.Type = "" }, err: "type"},
		"no timestamp":            {notice: func(n *Notice) { n.Timestamp = time.Time{} }, err: "timestamp"},
		"a long sub":              {notice: func(n *Notice) { n.Subject = long }, err: "sub"},
		"a context without an id": {notice: func(n *Notice) { n.Context = &lti.LaunchContext{} }, err: "context"},
		"memberships without a context": {notice: func(n *Notice) {
			n.ContextMembershipsURL = "https://platform.example.com/lti/contexts/course-1/memberships"
		}, err: "needs a context"},
		"an http memberships url": {notice: func(n *Notice) {
			n.Context = &lti.LaunchContext{ID: "course-1"}
			n.ContextMembershipsURL = "http://platform.example.com/lti/contexts/course-1/memberships"
		}, err: "https"},
		"an ags endpoint without a context": {notice: func(n *Notice) {
			n.AGSEndpoint = &lti.AGSEndpoint{Scopes: []lti.Scope{lti.ScopeAGSScore}, LineItems: "https://platform.example.com/lti/contexts/course-1/lineitems"}
		}, err: "needs a context"},
		"a nil claim":              {notice: func(n *Notice) { n.Claims = []lti.Claim{nil} }, err: "nil"},
		"a claim that isn't a url": {notice: func(n *Notice) { n.Claims = []lti.Claim{testNamedClaim{name: "submission"}} }, err: "fully qualified"},
		"a roles claim":            {notice: func(n *Notice) { n.Claims = []lti.Claim{testNamedClaim{name: lti.ClaimRoles}} }, err: "fully qualified"},
		"a claim the package sets": {notice: func(n *Notice) { n.Claims = []lti.Claim{testNamedClaim{name: lti.ClaimNotice}} }, err: "fully qualified"},
		"a launch claim":           {notice: func(n *Notice) { n.Claims = []lti.Claim{testNamedClaim{name: lti.ClaimContext}} }, err: "fully qualified"},
		"the same claim twice":     {notice: func(n *Notice) { n.Claims = []lti.Claim{testSubmissionClaim{}, testSubmissionClaim{}} }, err: "set twice"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tool := createTestTool()
			if tt.tool != nil {
				tt.tool(&tool)
			}

			notice := createTestNotice()
			if tt.notice != nil {
				tt.notice(&notice)
			}

			_, err := launcher.SignNotice(t.Context(), tool, notice)
			require.ErrorContains(t, err, tt.err)
		})
	}
}

func TestPostNotices(t *testing.T) {
	t.Parallel()

	var (
		gotBody        []byte
		gotContentType string
	)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)

		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	err := PostNotices(t.Context(), server.Client(), server.URL+"/notices", lti.NewNoticeEnvelope("eyJ.a.b", "eyJ.c.d"))
	require.NoError(t, err)

	assert.Equal(t, "application/json", gotContentType)
	assert.JSONEq(t, `{"notices": [{"jwt": "eyJ.a.b"}, {"jwt": "eyJ.c.d"}]}`, string(gotBody))
}

func TestPostNotices_AnswersOtherThan2xxAreErrors(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusGone, http.StatusInternalServerError, http.StatusFound} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if status == http.StatusFound {
				w.Header().Set("Location", "/elsewhere")
			}

			w.WriteHeader(status)
		}))

		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		err := PostNotices(t.Context(), client, server.URL, lti.NewNoticeEnvelope("eyJ.a.b"))
		server.Close()

		var delivery *NoticeDeliveryError
		require.ErrorAs(t, err, &delivery, status)
		assert.Equal(t, status, delivery.StatusCode)
	}
}

func TestPostNotices_Rejects(t *testing.T) {
	t.Parallel()

	envelope := lti.NewNoticeEnvelope("eyJ.a.b")

	for _, handler := range []string{"http://tool.example.com/notices", "/notices", "https://user:secret@tool.example.com/notices", "", "https://"} {
		err := PostNotices(t.Context(), http.DefaultClient, handler, envelope)
		require.ErrorContains(t, err, "absolute https url", handler)
	}

	err := PostNotices(t.Context(), http.DefaultClient, "https://tool.example.com/notices", lti.NewNoticeEnvelope())
	require.ErrorContains(t, err, "at least one notice")
}

func TestPostNotices_TheDefaultClientRefusesPrivateAddresses(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	t.Cleanup(server.Close)

	err := PostNotices(t.Context(), nil, server.URL+"/notices", lti.NewNoticeEnvelope("eyJ.a.b"))
	require.ErrorIs(t, err, safehttp.ErrNonPublicAddress)
	assert.False(t, called)

	var delivery *NoticeDeliveryError
	assert.False(t, errors.As(err, &delivery), "a connection failure isn't a delivery answer")
}

func TestPostNotices_SignedNoticesRoundTrip(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	token, err := launcher.SignNotice(t.Context(), createTestTool(), createTestNotice())
	require.NoError(t, err)

	var got lti.NoticeEnvelope

	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&got))
	}))
	t.Cleanup(server.Close)

	require.NoError(t, PostNotices(t.Context(), server.Client(), server.URL, lti.NewNoticeEnvelope(token)))
	require.Len(t, got.Notices, 1)
	assert.Equal(t, token, got.Notices[0].JWT)
}

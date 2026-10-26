package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/jwks"
	"github.com/meitner-se/go-lti/ltitest"
)

// ============================================================================
// Test helper functions
// ============================================================================

var testNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func createTestConfig() Config {
	return Config{
		Issuer:        "https://platform.example.com/lti",
		Paths:         Paths{Authorization: "/authorize", JWKS: "/jwks", Registration: "/register", DeepLinkReturn: "/deep-link-return"},
		TokenEndpoint: "https://platform.example.com/oauth/token",
		Product:       Product{GUID: "platform-1", Name: "Example LMS", FamilyCode: "example", Version: "1.0.0"},
	}
}

func createTestTool() Tool {
	return Tool{
		ClientID:         "client-1",
		InitiateLoginURI: "https://tool.example.com/login",
		RedirectURIs:     []string{"https://tool.example.com/launch"},
		TargetLinkURI:    "https://tool.example.com/launch",
		JWKSURI:          "https://tool.example.com/jwks",
		Domains:          []string{"tool.example.com", "cdn.example.net"},
	}
}

func createTestCommon() lti.Common {
	return lti.Common{
		DeploymentID: "deployment-1",
		Subject:      "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
		Roles:        []lti.Role{lti.RoleLearner},
		Context:      &lti.LaunchContext{ID: "course-1", Title: "Biology 1", Types: []lti.ContextType{lti.ContextTypeCourseOffering}},
		Presentation: lti.Presentation{DocumentTarget: lti.DocumentTargetIframe, Locale: "sv"},
		User:         lti.User{Name: "Ada Lovelace", GivenName: "Ada", FamilyName: "Lovelace", Email: "ada@example.com"},
	}
}

func createTestResourceLinkRequest() *lti.ResourceLinkRequest {
	return &lti.ResourceLinkRequest{
		Common:       createTestCommon(),
		ResourceLink: lti.ResourceLink{ID: "link-1", Title: "Cell quiz"},
	}
}

func createTestDeepLinkingSettings() lti.DeepLinkingSettings {
	return lti.DeepLinkingSettings{
		AcceptTypes:                       []lti.ContentItemType{lti.ContentItemTypeLTIResourceLink},
		AcceptPresentationDocumentTargets: []lti.DocumentTarget{lti.DocumentTargetIframe, lti.DocumentTargetWindow},
		Data:                              "request-1",
	}
}

func createTestDeepLinkingRequest() *lti.DeepLinkingRequest {
	common := createTestCommon()
	common.TargetLinkURI = "https://tool.example.com/deep-link"
	common.Roles = []lti.Role{lti.RoleInstructor}

	return &lti.DeepLinkingRequest{Common: common, Settings: createTestDeepLinkingSettings()}
}

func createTestLauncher(t *testing.T, key lti.SigningKey) *Launcher {
	t.Helper()

	launcher, err := NewLauncher(createTestConfig(), ltitest.NewKeys(t, key), WithClock(func() time.Time { return testNow }))
	require.NoError(t, err)

	return launcher
}

func newTestFetcher(t *testing.T, client *http.Client) *jwks.Fetcher {
	t.Helper()

	fetcher, err := jwks.NewFetcher(jwks.WithHTTPClient(client))
	require.NoError(t, err)

	return fetcher
}

func claimsJSON(t *testing.T, claims map[string]any) string {
	t.Helper()

	body, err := json.Marshal(claims)
	require.NoError(t, err)

	return string(body)
}

type testEndpointClaim struct {
	URL string `json:"url"`
}

func (testEndpointClaim) ClaimName() string {
	return "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"
}

type testNamedClaim struct{ name string }

func (c testNamedClaim) ClaimName() string { return c.name }

// ============================================================================
// Tests
// ============================================================================

func TestNewLauncher_RejectsAnInvalidPlatform(t *testing.T) {
	t.Parallel()

	key := ltitest.NewSigningKey(t)

	_, err := NewLauncher(Config{}, ltitest.NewKeys(t, key))
	require.Error(t, err)

	_, err = NewLauncher(createTestConfig(), nil)
	require.Error(t, err)
}

func TestLauncher_IDTokenClaims_ResourceLinkRequest(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.Custom = map[string]string{"course": "$Context.id", "quiz": "$ResourceLink.title", "name": "$Person.name.full"}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"iss": "https://platform.example.com/lti",
		"aud": "client-1",
		"azp": "client-1",
		"sub": "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
		"iat": 1792670400,
		"exp": 1792670700,
		"nonce": "nonce-1",
		"https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
		"https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
		"https://purl.imsglobal.org/spec/lti/claim/deployment_id": "deployment-1",
		"https://purl.imsglobal.org/spec/lti/claim/target_link_uri": "https://tool.example.com/launch",
		"https://purl.imsglobal.org/spec/lti/claim/roles": ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
		"https://purl.imsglobal.org/spec/lti/claim/context": {
			"id": "course-1",
			"title": "Biology 1",
			"type": ["http://purl.imsglobal.org/vocab/lis/v2/course#CourseOffering"]
		},
		"https://purl.imsglobal.org/spec/lti/claim/resource_link": {"id": "link-1", "title": "Cell quiz"},
		"https://purl.imsglobal.org/spec/lti/claim/launch_presentation": {"document_target": "iframe", "locale": "sv"},
		"https://purl.imsglobal.org/spec/lti/claim/custom": {"course": "course-1", "quiz": "Cell quiz", "name": ""},
		"https://purl.imsglobal.org/spec/lti/claim/tool_platform": {
			"guid": "platform-1",
			"name": "Example LMS",
			"version": "1.0.0",
			"product_family_code": "example"
		}
	}`, claimsJSON(t, claims))
}

func TestLauncher_IDTokenClaims_DeepLinkingRequest(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestDeepLinkingRequest()
	msg.Custom = map[string]string{"course_code": "BIO1"}
	msg.Settings.AcceptMediaTypes = []string{"image/*", "text/html"}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, lti.MessageTypeDeepLinkingRequest, claims[lti.ClaimMessageType])
	assert.Equal(t, "https://tool.example.com/deep-link", claims[lti.ClaimTargetLinkURI])
	assert.NotContains(t, claims, lti.ClaimResourceLink)
	assert.Equal(t, map[string]string{"course_code": "BIO1"}, claims[lti.ClaimCustom])

	settings, err := json.Marshal(claims[lti.ClaimDeepLinkingSettings])
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"deep_link_return_url": "https://platform.example.com/lti/deep-link-return",
		"accept_types": ["ltiResourceLink"],
		"accept_presentation_document_targets": ["iframe", "window"],
		"accept_media_types": "image/*,text/html",
		"accept_multiple": false,
		"data": "request-1"
	}`, string(settings))
}

func TestLauncher_IDTokenClaims_TargetLinkURIDefaultsToTheTools(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.TargetLinkURI = ""

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, "https://tool.example.com/launch", claims[lti.ClaimTargetLinkURI])
}

func TestLauncher_IDTokenClaims_AnonymousLaunchHasEmptyRoles(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.Roles = nil

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Contains(t, claimsJSON(t, claims), `"https://purl.imsglobal.org/spec/lti/claim/roles":[]`)
}

func TestLauncher_IDTokenClaims_SharesPersonalDataOnlyWhenAllowed(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	tests := []struct {
		name    string
		sharing lti.Sharing
		want    map[string]string
	}{
		{name: "nothing by default", sharing: lti.Sharing{}, want: map[string]string{}},
		{
			name:    "name only",
			sharing: lti.Sharing{Name: true},
			want:    map[string]string{"name": "Ada Lovelace", "given_name": "Ada", "family_name": "Lovelace"},
		},
		{name: "email only", sharing: lti.Sharing{Email: true}, want: map[string]string{"email": "ada@example.com"}},
		{
			name:    "name and email",
			sharing: lti.Sharing{Name: true, Email: true},
			want:    map[string]string{"name": "Ada Lovelace", "given_name": "Ada", "family_name": "Lovelace", "email": "ada@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			msg := createTestResourceLinkRequest()
			msg.Sharing = tt.sharing

			claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
			require.NoError(t, err)

			got := map[string]string{}
			for _, name := range []string{"name", "given_name", "family_name", "email"} {
				if value, ok := claims[name].(string); ok {
					got[name] = value
				}
			}

			assert.Equal(t, tt.want, got)
			assert.Equal(t, "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b", claims["sub"])
		})
	}
}

func TestLauncher_IDTokenClaims_SubstitutesCustomFromTheMessage(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.Context.Label = "BIO1"
	msg.ResourceLink.Description = "Ten questions"
	msg.Sharing = lti.Sharing{Name: true, Email: true}
	msg.Custom = map[string]string{
		"user":        "$User.id",
		"full":        "$Person.name.full",
		"given":       "$Person.name.given",
		"family":      "$Person.name.family",
		"email":       "$Person.email.primary",
		"context":     "$Context.id",
		"title":       "$Context.title",
		"label":       "$Context.label",
		"link":        "$ResourceLink.id",
		"link_title":  "$ResourceLink.title",
		"description": "$ResourceLink.description",
		"locale":      "$Message.locale",
		"literal":     "BIO1",
	}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"user":        "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
		"full":        "Ada Lovelace",
		"given":       "Ada",
		"family":      "Lovelace",
		"email":       "ada@example.com",
		"context":     "course-1",
		"title":       "Biology 1",
		"label":       "BIO1",
		"link":        "link-1",
		"link_title":  "Cell quiz",
		"description": "Ten questions",
		"locale":      "sv",
		"literal":     "BIO1",
	}, claims[lti.ClaimCustom])
	assert.Equal(t, "$Context.id", msg.Custom["context"], "the message's template is left as it was")
}

func TestLauncher_IDTokenClaims_SuppliedVariables(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.Sharing = lti.Sharing{Name: true}
	msg.Custom = map[string]string{
		"username": "$User.username",
		"term":     "$CourseSection.timeFrame.begin",
		"context":  "$Context.id",
		"label":    "$Context.label",
		"history":  "$Context.id.history",
	}
	msg.Variables = map[lti.Variable]string{
		lti.VariableUserUsername:        "ada",
		"CourseSection.timeFrame.begin": "2026-08-17",
		lti.VariableContextID:           "another-course",
		lti.VariableContextLabel:        "BIO",
	}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"username": "ada",
		"term":     "2026-08-17",
		"context":  "course-1",
		"label":    "BIO",
		"history":  "$Context.id.history",
	}, claims[lti.ClaimCustom], "the message's own values win; the rest come from Variables or stay as they are")
}

func TestRegression_LaunchWithholdsPersonalVariablesUnlessShared(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.Custom = map[string]string{
		"name":     "$Person.name.full",
		"given":    "$Person.name.given",
		"email":    "$Person.email.primary",
		"username": "$User.username",
		"phone":    "$Person.phone.mobile",
		"home":     "$Person.phone.home",
		"user":     "$User.id",
	}
	msg.Variables = map[lti.Variable]string{lti.VariableUserUsername: "ada", "Person.phone.mobile": "+46700000000"}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"name":     "",
		"given":    "",
		"email":    "",
		"username": "",
		"phone":    "",
		"home":     "$Person.phone.home",
		"user":     "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
	}, claims[lti.ClaimCustom], "nothing about the user is shared by default")

	msg.Sharing = lti.Sharing{Email: true}

	claims, err = launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"name":     "",
		"given":    "",
		"email":    "ada@example.com",
		"username": "",
		"phone":    "",
		"home":     "$Person.phone.home",
		"user":     "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
	}, claims[lti.ClaimCustom])
}

func TestRegression_LaunchWithholdsASuppliedNameUnlessShared(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.User = lti.User{}
	msg.Custom = map[string]string{"name": "$Person.name.full"}
	msg.Variables = map[lti.Variable]string{lti.VariablePersonNameFull: "Ada Lovelace"}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"name": ""}, claims[lti.ClaimCustom])
}

func TestRegression_LaunchResolvesSupportedVariablesWithoutAValueToEmpty(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestDeepLinkingRequest()
	msg.Context = nil
	msg.Presentation.Locale = ""
	msg.Custom = map[string]string{
		"context": "$Context.id",
		"link":    "$ResourceLink.id",
		"locale":  "$Message.locale",
		"user":    "$User.id",
		"history": "$Context.id.history",
		"term":    "$CourseSection.timeFrame.begin",
	}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"context": "",
		"link":    "",
		"locale":  "",
		"user":    "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
		"history": "$Context.id.history",
		"term":    "$CourseSection.timeFrame.begin",
	}, claims[lti.ClaimCustom], "a supported variable without a value is empty; only an unsupported one stays as it is")
}

func TestLaunchVariables_AreTheOnesALaunchFills(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.Context.Label = "BIO1"
	msg.ResourceLink.Description = "Ten questions"
	msg.Sharing = lti.Sharing{Name: true, Email: true}
	msg.Custom = map[string]string{}

	for _, variable := range LaunchVariables() {
		msg.Custom[string(variable)] = "$" + string(variable)
	}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	custom, ok := claims[lti.ClaimCustom].(map[string]string)
	require.True(t, ok)

	for name, value := range custom {
		assert.NotEqual(t, "$"+name, value, "a launch fills %s", name)
	}
}

func TestLauncher_IDTokenClaims_AddsExtensions(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.Extensions = []lti.Claim{testEndpointClaim{URL: "https://platform.example.com/lti/lineitems"}}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Contains(t, claimsJSON(t, claims), `"https://purl.imsglobal.org/spec/lti-ags/claim/endpoint":{"url":"https://platform.example.com/lti/lineitems"}`)
}

func TestLauncher_IDTokenClaims_RejectsExtensionsThatOverrideClaims(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for _, name := range []string{"email", "sub", lti.ClaimRoles, lti.ClaimContext, "not-a-url", ""} {
		msg := createTestResourceLinkRequest()
		msg.Extensions = []lti.Claim{testNamedClaim{name: name}}

		_, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
		require.Error(t, err, name)
	}

	msg := createTestResourceLinkRequest()
	msg.Extensions = []lti.Claim{testEndpointClaim{}, testEndpointClaim{}}

	_, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.Error(t, err, "the same extension twice")
}

func TestLauncher_IDTokenClaims_Rejects(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	tests := []struct {
		name  string
		tool  func(tool *Tool)
		nonce string
		msg   func(m *lti.ResourceLinkRequest)
	}{
		{name: "no client_id", tool: func(tool *Tool) { tool.ClientID = "" }},
		{name: "no nonce", nonce: "-"},
		{name: "no deployment_id", msg: func(m *lti.ResourceLinkRequest) { m.DeploymentID = "" }},
		{name: "deployment_id over 255 characters", msg: func(m *lti.ResourceLinkRequest) { m.DeploymentID = strings.Repeat("a", 256) }},
		{name: "no sub", msg: func(m *lti.ResourceLinkRequest) { m.Subject = "" }},
		{name: "sub over 255 characters", msg: func(m *lti.ResourceLinkRequest) { m.Subject = strings.Repeat("a", 256) }},
		{name: "an http target_link_uri", msg: func(m *lti.ResourceLinkRequest) { m.TargetLinkURI = "http://tool.example.com/launch" }},
		{name: "no target_link_uri anywhere", tool: func(tool *Tool) { tool.TargetLinkURI = "" }, msg: func(m *lti.ResourceLinkRequest) { m.TargetLinkURI = "" }},
		{name: "an unknown document target", msg: func(m *lti.ResourceLinkRequest) { m.Presentation.DocumentTarget = "popup" }},
		{name: "a context without id", msg: func(m *lti.ResourceLinkRequest) { m.Context = &lti.LaunchContext{} }},
		{name: "a resource link without id", msg: func(m *lti.ResourceLinkRequest) { m.ResourceLink = lti.ResourceLink{Title: "Quiz"} }},
		{name: "a resource link id over 255 characters", msg: func(m *lti.ResourceLinkRequest) { m.ResourceLink.ID = strings.Repeat("a", 256) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tool := createTestTool()
			if tt.tool != nil {
				tt.tool(&tool)
			}

			nonce := "nonce-1"
			if tt.nonce == "-" {
				nonce = ""
			}

			msg := createTestResourceLinkRequest()
			if tt.msg != nil {
				tt.msg(msg)
			}

			_, err := launcher.idTokenClaims(tool, nonce, msg, testNow)
			require.Error(t, err)
		})
	}
}

func TestLauncher_IDTokenClaims_RejectsIncompleteDeepLinking(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		platform func(cfg *Config)
		settings func(s *lti.DeepLinkingSettings)
	}{
		{name: "an http return url", settings: func(s *lti.DeepLinkingSettings) { s.ReturnURL = "http://platform.example.com/lti/deep-link-return" }},
		{name: "no accepted types", settings: func(s *lti.DeepLinkingSettings) { s.AcceptTypes = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := createTestConfig()
			if tt.platform != nil {
				tt.platform(&cfg)
			}

			launcher, err := NewLauncher(cfg, ltitest.NewKeys(t, ltitest.NewSigningKey(t)))
			require.NoError(t, err)

			msg := createTestDeepLinkingRequest()
			if tt.settings != nil {
				tt.settings(&msg.Settings)
			}

			_, err = launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
			require.Error(t, err)
		})
	}
}

func TestLauncher_IDTokenClaims_RejectsNilAndForeignMessages(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	var nilResourceLink *lti.ResourceLinkRequest
	var nilDeepLinking *lti.DeepLinkingRequest

	for _, msg := range []lti.Message{nil, nilResourceLink, nilDeepLinking} {
		_, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
		require.Error(t, err)
	}
}

func TestLauncher_IDToken_VerifiesAgainstThePublishedJWKS(t *testing.T) {
	t.Parallel()

	key := ltitest.NewSigningKey(t)
	launcher, err := NewLauncher(createTestConfig(), ltitest.NewKeys(t, key))
	require.NoError(t, err)

	set, err := launcher.JWKS(t.Context())
	require.NoError(t, err)

	body, _ := json.Marshal(set)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	idToken, err := launcher.idToken(t.Context(), createTestTool(), "nonce-1", createTestResourceLinkRequest())
	require.NoError(t, err)

	// Verify as a tool would: fetch the platform's JWKS and check the token against it.
	fetcher := newTestFetcher(t, server.Client())
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)

		return fetcher.Key(t.Context(), server.URL, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer("https://platform.example.com/lti"),
		jwt.WithAudience("client-1"),
		jwt.WithExpirationRequired(),
	)
	require.NoError(t, err)

	assert.Equal(t, key.ID, token.Header["kid"])
	assert.Equal(t, "JWT", token.Header["typ"])
	assert.Equal(t, "nonce-1", claims["nonce"])
	assert.Equal(t, "deployment-1", claims[lti.ClaimDeploymentID])
}

func TestLauncher_IDToken_DoesNotVerifyAgainstAnotherKey(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	server := ltitest.NewJWKSServer(t, ltitest.NewSigningKey(t))

	idToken, err := launcher.idToken(t.Context(), createTestTool(), "nonce-1", createTestResourceLinkRequest())
	require.NoError(t, err)

	fetcher := newTestFetcher(t, server.Client())
	_, err = jwt.Parse(idToken, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)

		return fetcher.Key(t.Context(), server.URL, kid)
	}, jwt.WithValidMethods([]string{"RS256"}))
	require.Error(t, err)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()

	body, err := json.Marshal(v)
	require.NoError(t, err)

	return body
}

func TestRegression_ExtensionsCantSetReservedClaimsTheMessageLeavesOut(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for _, name := range []string{lti.ClaimContext, lti.ClaimCustom, lti.ClaimLaunchPresentation, lti.ClaimDeepLinkingSettings} {
		msg := createTestResourceLinkRequest()
		msg.Context = nil
		msg.Custom = nil
		msg.Presentation = lti.Presentation{}
		msg.Extensions = []lti.Claim{testNamedClaim{name: name}}

		_, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
		require.Error(t, err, name)
	}
}

func TestRegression_NilExtensionIsAnError(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestResourceLinkRequest()
	msg.Extensions = []lti.Claim{nil}

	_, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.Error(t, err)
}

func TestRegression_JWKSRefusesKeysWithoutKidOrPublicKey(t *testing.T) {
	t.Parallel()

	signing := ltitest.NewSigningKey(t)

	for name, published := range map[string][]jwks.Key{
		"no kid":        {{PublicKey: ltitest.PublicKey(t, signing).PublicKey}},
		"no public key": {{ID: "kid-1"}},
	} {
		launcher, err := NewLauncher(createTestConfig(), &mockKeys{signing: signing, public: published})
		require.NoError(t, err)

		_, err = launcher.JWKS(t.Context())
		require.Error(t, err, name)
	}
}

type mockKeys struct {
	signing lti.SigningKey
	public  []jwks.Key
}

func (m *mockKeys) SigningKey(context.Context) (lti.SigningKey, error) { return m.signing, nil }

func (m *mockKeys) PublicKeys(context.Context) ([]jwks.Key, error) { return m.public, nil }

func TestRegression_EmptyDocumentTargetsAreSentAsAnEmptyArray(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	msg := createTestDeepLinkingRequest()
	msg.Settings.AcceptTypes = []lti.ContentItemType{lti.ContentItemTypeFile}
	msg.Settings.AcceptPresentationDocumentTargets = nil

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err, "Deep Linking 2.0 §4.6.2: a platform that only takes files accepts no document targets")

	settings, err := json.Marshal(claims[lti.ClaimDeepLinkingSettings])
	require.NoError(t, err)
	assert.Contains(t, string(settings), `"accept_presentation_document_targets":[]`)
}

func TestRegression_ReturnURLMustBeHTTPS(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for _, returnURL := range []string{"javascript:alert(1)", "http://platform.example.com/back", "/back"} {
		msg := createTestResourceLinkRequest()
		msg.Presentation.ReturnURL = returnURL

		_, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
		require.Error(t, err, returnURL)
	}

	msg := createTestResourceLinkRequest()
	msg.Presentation.ReturnURL = "https://platform.example.com/back"

	_, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)
}

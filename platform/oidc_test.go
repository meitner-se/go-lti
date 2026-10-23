package platform

import (
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

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

func createTestLoginInitiation() LoginInitiation {
	return LoginInitiation{DeploymentID: "deployment-1", LoginHint: "user-hint-1", MessageHint: "launch-hint-1"}
}

// createTestAuthenticationForm is the authentication request a tool sends after login initiation.
func createTestAuthenticationForm() url.Values {
	return url.Values{
		"scope":            {"openid"},
		"response_type":    {"id_token"},
		"response_mode":    {"form_post"},
		"prompt":           {"none"},
		"client_id":        {"client-1"},
		"redirect_uri":     {"https://tool.example.com/launch"},
		"login_hint":       {"user-hint-1"},
		"lti_message_hint": {"launch-hint-1"},
		"nonce":            {"nonce-1"},
		"state":            {"state-1"},
	}
}

func createTestLaunch() Launch {
	return Launch{Tool: createTestTool(), Initiation: createTestLoginInitiation(), Message: createTestResourceLinkRequest()}
}

func parseTestAuthenticationRequest(t *testing.T) *AuthenticationRequest {
	t.Helper()

	req, err := ParseAuthenticationRequest(createTestAuthenticationForm())
	require.NoError(t, err)

	return req
}

func fieldsOf(form *FormPost) map[string]string {
	fields := map[string]string{}
	for _, field := range form.Fields {
		fields[field.Name] = field.Value
	}

	return fields
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)

// ============================================================================
// Tests
// ============================================================================

func TestLoginInitiationURL(t *testing.T) {
	t.Parallel()

	tool := createTestTool()
	tool.InitiateLoginURI = "https://tool.example.com/login?tenant=acme"

	raw, err := createTestConfig().LoginInitiationURL(tool, createTestLoginInitiation())
	require.NoError(t, err)

	u, err := url.Parse(raw)
	require.NoError(t, err)

	assert.Equal(t, "tool.example.com", u.Host)
	assert.Equal(t, "/login", u.Path)
	assert.Equal(t, url.Values{
		"tenant":            {"acme"},
		"iss":               {"https://platform.example.com/lti"},
		"login_hint":        {"user-hint-1"},
		"lti_message_hint":  {"launch-hint-1"},
		"target_link_uri":   {"https://tool.example.com/launch"},
		"client_id":         {"client-1"},
		"lti_deployment_id": {"deployment-1"},
	}, u.Query())
}

func TestLoginInitiationURL_OverridesTheTargetAndOmitsAnEmptyMessageHint(t *testing.T) {
	t.Parallel()

	li := createTestLoginInitiation()
	li.MessageHint = ""
	li.TargetLinkURI = "https://tool.example.com/deep-link"

	raw, err := createTestConfig().LoginInitiationURL(createTestTool(), li)
	require.NoError(t, err)

	u, err := url.Parse(raw)
	require.NoError(t, err)

	assert.Equal(t, "https://tool.example.com/deep-link", u.Query().Get("target_link_uri"))
	assert.NotContains(t, u.Query(), "lti_message_hint")
}

func TestLoginInitiationURL_Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		platform func(cfg *Config)
		tool     func(tool *Tool)
		li       func(li *LoginInitiation)
	}{
		{name: "no issuer", platform: func(cfg *Config) { cfg.Issuer = "" }},
		{name: "an http login uri", tool: func(tool *Tool) { tool.InitiateLoginURI = "http://tool.example.com/login" }},
		{name: "no client_id", tool: func(tool *Tool) { tool.ClientID = "" }},
		{name: "no target link uri", tool: func(tool *Tool) { tool.TargetLinkURI = "" }},
		{name: "no login_hint", li: func(li *LoginInitiation) { li.LoginHint = "" }},
		{name: "no deployment_id", li: func(li *LoginInitiation) { li.DeploymentID = "" }},
		{name: "a deployment_id over 255 characters", li: func(li *LoginInitiation) { li.DeploymentID = strings.Repeat("a", 256) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := createTestConfig()
			if tt.platform != nil {
				tt.platform(&cfg)
			}

			tool := createTestTool()
			if tt.tool != nil {
				tt.tool(&tool)
			}

			li := createTestLoginInitiation()
			if tt.li != nil {
				tt.li(&li)
			}

			_, err := cfg.LoginInitiationURL(tool, li)
			require.Error(t, err)
		})
	}
}

func TestParseAuthenticationRequest(t *testing.T) {
	t.Parallel()

	assert.Equal(t, &AuthenticationRequest{
		ClientID:    "client-1",
		RedirectURI: "https://tool.example.com/launch",
		LoginHint:   "user-hint-1",
		MessageHint: "launch-hint-1",
		Nonce:       "nonce-1",
		State:       "state-1",
		parsed:      true,
	}, parseTestAuthenticationRequest(t))
}

func TestParseAuthenticationRequest_AcceptsMoreScopesAndNoState(t *testing.T) {
	t.Parallel()

	form := createTestAuthenticationForm()
	form.Set("scope", "openid profile")
	form.Del("state")
	form.Del("lti_message_hint")

	req, err := ParseAuthenticationRequest(form)
	require.NoError(t, err)
	assert.Empty(t, req.State)
}

func TestParseAuthenticationRequest_Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(form url.Values)
		code   lti.ErrorCode
	}{
		{name: "no client_id", change: func(f url.Values) { f.Del("client_id") }, code: lti.ErrorInvalidRequest},
		{name: "no redirect_uri", change: func(f url.Values) { f.Del("redirect_uri") }, code: lti.ErrorInvalidRequest},
		{name: "a code response type", change: func(f url.Values) { f.Set("response_type", "code") }, code: lti.ErrorUnsupportedResponseType},
		{name: "no openid scope", change: func(f url.Values) { f.Set("scope", "profile") }, code: lti.ErrorInvalidScope},
		{name: "a fragment response mode", change: func(f url.Values) { f.Set("response_mode", "fragment") }, code: lti.ErrorInvalidRequest},
		{name: "a login prompt", change: func(f url.Values) { f.Set("prompt", "login") }, code: lti.ErrorInvalidRequest},
		{name: "no login_hint", change: func(f url.Values) { f.Del("login_hint") }, code: lti.ErrorInvalidRequest},
		{name: "no nonce", change: func(f url.Values) { f.Del("nonce") }, code: lti.ErrorInvalidRequest},
		{name: "a repeated nonce", change: func(f url.Values) { f.Add("nonce", "nonce-2") }, code: lti.ErrorInvalidRequest},
		{name: "a repeated redirect_uri", change: func(f url.Values) { f.Add("redirect_uri", "https://evil.example.org/") }, code: lti.ErrorInvalidRequest},
		{name: "a parameter over 4 KiB", change: func(f url.Values) { f.Set("lti_message_hint", strings.Repeat("a", 4097)) }, code: lti.ErrorInvalidRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			form := createTestAuthenticationForm()
			tt.change(form)

			req, err := ParseAuthenticationRequest(form)
			require.Error(t, err)

			rejection, ok := lti.AsError(err)
			require.True(t, ok)
			assert.Equal(t, tt.code, rejection.Code)
			require.NotNil(t, req, "the partial request is returned so the tool can be answered")
			assert.Equal(t, "state-1", req.State)
		})
	}
}

func TestLauncher_Respond(t *testing.T) {
	t.Parallel()

	key := ltitest.NewSigningKey(t)
	launcher := createTestLauncher(t, key)

	form, err := launcher.Respond(t.Context(), parseTestAuthenticationRequest(t), createTestLaunch())
	require.NoError(t, err)

	assert.Equal(t, "https://tool.example.com/launch", form.Action)

	fields := fieldsOf(form)
	assert.Equal(t, "state-1", fields["state"])

	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(fields["id_token"], claims)
	require.NoError(t, err)
	assert.Equal(t, "nonce-1", claims["nonce"])
	assert.Equal(t, "client-1", claims["aud"])
}

func TestLauncher_Respond_LeavesOutAnEmptyState(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	req := parseTestAuthenticationRequest(t)
	req.State = ""

	form, err := launcher.Respond(t.Context(), req, createTestLaunch())
	require.NoError(t, err)

	assert.NotContains(t, fieldsOf(form), "state")
}

func TestLauncher_Respond_Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(req *AuthenticationRequest)
		code   lti.ErrorCode
	}{
		{name: "another client_id", change: func(r *AuthenticationRequest) { r.ClientID = "client-2" }, code: lti.ErrorUnauthorizedClient},
		{name: "an unregistered redirect_uri", change: func(r *AuthenticationRequest) { r.RedirectURI = "https://evil.example.org/launch" }, code: lti.ErrorInvalidRequest},
		{name: "a redirect_uri that only starts like a registered one", change: func(r *AuthenticationRequest) {
			r.RedirectURI = "https://tool.example.com/launch/../evil"
		}, code: lti.ErrorInvalidRequest},
		{name: "another login_hint", change: func(r *AuthenticationRequest) { r.LoginHint = "user-hint-2" }, code: lti.ErrorLoginRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
			req := parseTestAuthenticationRequest(t)
			tt.change(req)

			_, err := launcher.Respond(t.Context(), req, createTestLaunch())
			require.Error(t, err)

			rejection, ok := lti.AsError(err)
			require.True(t, ok)
			assert.Equal(t, tt.code, rejection.Code)
		})
	}
}

func TestLauncher_Respond_FailsOnAnIncompleteLaunch(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	launch := createTestLaunch()
	launch.Initiation.LoginHint = ""

	_, err := launcher.Respond(t.Context(), parseTestAuthenticationRequest(t), launch)
	require.Error(t, err)

	_, err = launcher.Respond(t.Context(), nil, createTestLaunch())
	require.Error(t, err)

	launch = createTestLaunch()
	launch.Message = nil

	_, err = launcher.Respond(t.Context(), parseTestAuthenticationRequest(t), launch)
	require.Error(t, err)

	_, isRejection := lti.AsError(err)
	assert.False(t, isRejection, "an incomplete message is the platform's mistake")
}

func TestLauncher_RespondError(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	req := parseTestAuthenticationRequest(t)

	form, ok := launcher.RespondError(req, createTestTool(), lti.NewError(lti.ErrorLoginRequired, "the launch has expired", nil))
	require.True(t, ok)
	assert.Equal(t, "https://tool.example.com/launch", form.Action)
	assert.Equal(t, map[string]string{"error": "login_required", "error_description": "the launch has expired", "state": "state-1"}, fieldsOf(form))

	form, ok = launcher.RespondError(req, createTestTool(), errors.New("database password is hunter2"))
	require.True(t, ok)
	assert.Equal(t, map[string]string{
		"error":             "server_error",
		"error_description": "the platform could not complete the launch",
		"state":             "state-1",
	}, fieldsOf(form), "the platform's own error is not sent to the tool")
}

func TestLauncher_RespondError_OnlyToARegisteredRedirectURI(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	rejection := lti.NewError(lti.ErrorInvalidRequest, "nonce is missing", nil)

	unregistered := parseTestAuthenticationRequest(t)
	unregistered.RedirectURI = "https://evil.example.org/launch"

	otherClient := parseTestAuthenticationRequest(t)
	otherClient.ClientID = "client-2"

	for name, req := range map[string]*AuthenticationRequest{
		"no request":                 nil,
		"an unregistered redirect":   unregistered,
		"another client's request":   otherClient,
		"a request without a client": {RedirectURI: "https://tool.example.com/launch"},
	} {
		_, ok := launcher.RespondError(req, createTestTool(), rejection)
		assert.False(t, ok, name)
	}

	noClient := createTestTool()
	noClient.ClientID = ""

	_, ok := launcher.RespondError(&AuthenticationRequest{RedirectURI: "https://tool.example.com/launch"}, noClient, rejection)
	assert.False(t, ok, "a tool without a client_id")
}

func TestFormPost_ServeHTTP(t *testing.T) {
	t.Parallel()

	form := &FormPost{
		Action: "https://tool.example.com/launch?a=1&b=2",
		Fields: []FormField{{Name: "id_token", Value: "eyJ.token"}, {Name: "state", Value: `"><script>alert(1)</script>`}},
	}

	recorder := httptest.NewRecorder()
	form.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "text/html; charset=utf-8", recorder.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	assert.Equal(t, "no-referrer", recorder.Header().Get("Referrer-Policy"))
	assert.Equal(t, "nosniff", recorder.Header().Get("X-Content-Type-Options"))

	body := recorder.Body.String()
	assert.Contains(t, body, `<form method="post" action="https://tool.example.com/launch?a=1&amp;b=2">`)
	assert.NotContains(t, body, `<script>alert(1)</script>`, "field values are escaped")
	assert.Contains(t, body, "<noscript><button type=\"submit\">Continue</button></noscript>")

	inputs := hiddenInput.FindAllStringSubmatch(body, -1)
	require.Len(t, inputs, 2)
	assert.Equal(t, "eyJ.token", html.UnescapeString(inputs[0][2]))
	assert.Equal(t, `"><script>alert(1)</script>`, html.UnescapeString(inputs[1][2]))

	// The CSP allows exactly the page's one inline script, by hash.
	csp := recorder.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'none'")
	assert.Contains(t, csp, "script-src '"+formPostScriptHash+"'")
	assert.Equal(t, 1, strings.Count(body, "<script>"))
	assert.Contains(t, body, "<script>"+formPostScript+"</script>")
}

func TestLaunch_EndToEnd(t *testing.T) {
	t.Parallel()

	cfg := createTestConfig()
	tool := createTestTool()

	launcher, err := NewLauncher(cfg, ltitest.NewKeys(t, ltitest.NewSigningKey(t)))
	require.NoError(t, err)

	// 1. The platform sends the browser to the tool's login initiation URL.
	loginURL, err := cfg.LoginInitiationURL(tool, createTestLoginInitiation())
	require.NoError(t, err)

	initiation, err := url.Parse(loginURL)
	require.NoError(t, err)

	// 2. The tool answers with an authentication request built from what it received.
	got := initiation.Query()
	form := url.Values{
		"scope":            {"openid"},
		"response_type":    {"id_token"},
		"response_mode":    {"form_post"},
		"prompt":           {"none"},
		"client_id":        {got.Get("client_id")},
		"redirect_uri":     {got.Get("target_link_uri")},
		"login_hint":       {got.Get("login_hint")},
		"lti_message_hint": {got.Get("lti_message_hint")},
		"nonce":            {"tool-nonce"},
		"state":            {"tool-state"},
	}

	req, err := ParseAuthenticationRequest(form)
	require.NoError(t, err)

	// 3. The platform redeems the message hint (not go-lti's job) and responds with the id_token.
	assert.Equal(t, "launch-hint-1", req.MessageHint)

	post, err := launcher.Respond(t.Context(), req, Launch{Tool: tool, Initiation: createTestLoginInitiation(), Message: createTestResourceLinkRequest()})
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	post.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/lti/authorize", http.NoBody))

	posted := map[string]string{}
	for _, input := range hiddenInput.FindAllStringSubmatch(recorder.Body.String(), -1) {
		posted[input[1]] = html.UnescapeString(input[2])
	}

	assert.Equal(t, "tool-state", posted["state"])

	// 4. The tool verifies the id_token against the platform's published keys.
	set, err := launcher.JWKS(t.Context())
	require.NoError(t, err)
	require.Len(t, set.Keys, 1)

	keys, err := jwks.ParseSet(mustJSON(t, set))
	require.NoError(t, err)

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(posted["id_token"], claims, func(*jwt.Token) (any, error) { return keys[0].PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(tool.ClientID),
		jwt.WithExpirationRequired(),
	)
	require.NoError(t, err)
	assert.Equal(t, "tool-nonce", claims["nonce"])
	assert.Equal(t, "LtiResourceLinkRequest", claims[lti.ClaimMessageType])
}

func TestRegistrationInitiationURL(t *testing.T) {
	t.Parallel()

	raw, err := createTestConfig().RegistrationInitiationURL(
		"https://tool.example.com/register?lang=sv",
		"https://platform.example.com/lti/.well-known/openid-configuration",
		"token-1",
	)
	require.NoError(t, err)

	u, err := url.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, url.Values{
		"lang":                 {"sv"},
		"openid_configuration": {"https://platform.example.com/lti/.well-known/openid-configuration"},
		"registration_token":   {"token-1"},
	}, u.Query())

	raw, err = createTestConfig().RegistrationInitiationURL("https://tool.example.com/register", "https://platform.example.com/lti/.well-known/openid-configuration", "")
	require.NoError(t, err)
	assert.NotContains(t, raw, "registration_token")
}

func TestRegistrationInitiationURL_Rejects(t *testing.T) {
	t.Parallel()

	_, err := createTestConfig().RegistrationInitiationURL("http://tool.example.com/register", "https://platform.example.com/lti/.well-known/openid-configuration", "")
	rejection, ok := lti.AsError(err)
	require.True(t, ok, "a bad tool url is the admin's input")
	assert.Equal(t, lti.ErrorInvalidRequest, rejection.Code)

	_, err = createTestConfig().RegistrationInitiationURL("https://tool.example.com/register", "/lti/.well-known/openid-configuration", "")
	require.Error(t, err)
}

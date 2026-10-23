package platform

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/ltitest"
)

// ============================================================================
// Tests
// ============================================================================

func TestRegression_RespondRefusesAMessageThatDisagreesWithItsLogin(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	tests := map[string]func(l *Launch){
		"another deployment": func(l *Launch) {
			msg := createTestResourceLinkRequest()
			msg.DeploymentID = "deployment-2"
			l.Message = msg
		},
		"another target link uri": func(l *Launch) {
			msg := createTestResourceLinkRequest()
			msg.TargetLinkURI = "https://tool.example.com/elsewhere"
			l.Message = msg
		},
		"a target the login didn't send": func(l *Launch) {
			l.Initiation.TargetLinkURI = "https://tool.example.com/deep-link"
		},
	}

	for name, change := range tests {
		launch := createTestLaunch()
		change(&launch)

		_, err := launcher.Respond(t.Context(), parseTestAuthenticationRequest(t), launch)
		require.Error(t, err, name)

		_, isRejection := lti.AsError(err)
		assert.False(t, isRejection, "%s is the platform's mistake", name)
	}

	launch := createTestLaunch()
	launch.Initiation.TargetLinkURI = "https://tool.example.com/deep-link"
	msg := createTestDeepLinkingRequest()
	launch.Message = msg

	_, err := launcher.Respond(t.Context(), parseTestAuthenticationRequest(t), launch)
	require.NoError(t, err, "a message whose target matches the one sent is fine")
}

func TestRegression_RespondChecksTheMessageHint(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	req := parseTestAuthenticationRequest(t)
	req.MessageHint = "another-launch"

	_, err := launcher.Respond(t.Context(), req, createTestLaunch())
	require.Error(t, err)

	rejection, ok := lti.AsError(err)
	require.True(t, ok)
	assert.Equal(t, lti.ErrorInvalidRequest, rejection.Code)
}

func TestRegression_RespondNeedsAParsedRequest(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	handmade := &AuthenticationRequest{ClientID: "client-1", RedirectURI: "https://tool.example.com/launch", LoginHint: "user-hint-1", MessageHint: "launch-hint-1", Nonce: "n"}

	_, err := launcher.Respond(t.Context(), handmade, createTestLaunch())
	require.Error(t, err)

	_, isRejection := lti.AsError(err)
	assert.False(t, isRejection)

	// A request that failed to parse isn't accepted either, though RespondError may answer it.
	form := createTestAuthenticationForm()
	form.Set("prompt", "login")

	partial, parseErr := ParseAuthenticationRequest(form)
	require.Error(t, parseErr)

	_, err = launcher.Respond(t.Context(), partial, createTestLaunch())
	require.Error(t, err)
}

func TestRegression_RespondGuardsArePlatformErrors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for name, change := range map[string]func(l *Launch){
		"no login_hint sent": func(l *Launch) { l.Initiation.LoginHint = "" },
		"no client_id":       func(l *Launch) { l.Tool.ClientID = "" },
	} {
		launch := createTestLaunch()
		change(&launch)

		req := parseTestAuthenticationRequest(t)
		req.LoginHint = launch.Initiation.LoginHint
		req.ClientID = launch.Tool.ClientID

		_, err := launcher.Respond(t.Context(), req, launch)
		require.Error(t, err, name)

		_, isRejection := lti.AsError(err)
		assert.False(t, isRejection, name)
	}
}

func TestRegression_RegistrationInitiationURLNeedsAnOpenIDConfigurationUnderTheIssuer(t *testing.T) {
	t.Parallel()

	cfg := createTestConfig()

	for _, openID := range []string{
		"https://attacker.example/openid",
		"https://platform.example.com/other/.well-known/openid-configuration",
		"https://platform.example.com/ltix/.well-known/openid-configuration",
		"https://platform.example.com/lti/.well-known/openid-configuration#frag",
		"http://platform.example.com/lti/.well-known/openid-configuration",
		"https://platform.example.com/lti",
	} {
		_, err := cfg.RegistrationInitiationURL("https://tool.example.com/register", openID, "")
		require.Error(t, err, openID)
	}

	_, err := cfg.RegistrationInitiationURL("https://tool.example.com/register", "https://platform.example.com/lti/.well-known/openid-configuration", "")
	require.NoError(t, err)
}

func TestRegression_ScopeMustContainOpenIDAsAWord(t *testing.T) {
	t.Parallel()

	form := createTestAuthenticationForm()
	form.Set("scope", "notopenid")

	_, err := ParseAuthenticationRequest(form)

	rejection, ok := lti.AsError(err)
	require.True(t, ok)
	assert.Equal(t, lti.ErrorInvalidScope, rejection.Code)
}

func TestRegression_RespondErrorDoesNotAnswerARepeatedRedirectURI(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	form := createTestAuthenticationForm()
	form.Add("redirect_uri", "https://evil.example.org/")

	req, err := ParseAuthenticationRequest(form)
	require.Error(t, err)

	_, ok := launcher.RespondError(req, createTestTool(), err)
	assert.False(t, ok, "the first redirect_uri is registered, but the request is ambiguous")
}

func TestRegression_OversizedStateIsNotEchoed(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	form := createTestAuthenticationForm()
	form.Set("state", strings.Repeat("s", 4097))

	req, err := ParseAuthenticationRequest(form)
	require.Error(t, err)

	errorForm, ok := launcher.RespondError(req, createTestTool(), err)
	require.True(t, ok)
	assert.NotContains(t, fieldsOf(errorForm), "state")
}

func TestRegression_FormPostHardening(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	(&FormPost{Action: "https://tool.example.com/launch", Fields: []FormField{{Name: "id_token", Value: "x"}}}).ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))

	csp := recorder.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "form-action https:")
	assert.Contains(t, csp, "base-uri 'none'")
	assert.Equal(t, "no-cache", recorder.Header().Get("Pragma"))
	assert.Contains(t, recorder.Body.String(), `<meta name="referrer" content="no-referrer">`)

	recorder = httptest.NewRecorder()
	(&FormPost{Action: "javascript:alert(1)"}).ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	assert.Contains(t, recorder.Body.String(), `action="#ZgotmplZ"`, "html/template neutralises a script url")
}

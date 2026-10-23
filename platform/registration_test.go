package platform

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
)

// ============================================================================
// Test helper functions
// ============================================================================

// createTestRegistrationJSON is the example request from LTI Dynamic Registration 1.0 §3.5.1
// (with Swedish instead of Japanese translations), with a scope for grade return and a request for the user's name and email.
func createTestRegistrationJSON() map[string]any {
	return map[string]any{
		"application_type":           "web",
		"response_types":             []string{"id_token"},
		"grant_types":                []string{"implicit", "client_credentials"},
		"initiate_login_uri":         "https://client.example.org/lti",
		"redirect_uris":              []string{"https://client.example.org/callback", "https://client.example.org/callback2"},
		"client_name":                "Virtual Garden",
		"client_name#sv":             "Virtuell trädgård",
		"client_name#de-DE":          "Virtueller Garten",
		"jwks_uri":                   "https://client.example.org/.well-known/jwks.json",
		"logo_uri":                   "https://client.example.org/logo.png",
		"client_uri":                 "https://client.example.org",
		"policy_uri":                 "https://client.example.org/privacy",
		"tos_uri":                    "https://client.example.org/tos",
		"token_endpoint_auth_method": "private_key_jwt",
		"contacts":                   []string{"ve7jtb@example.org", "mary@example.org"},
		"scope":                      "https://purl.imsglobal.org/spec/lti-ags/scope/score https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
		"https://purl.imsglobal.org/spec/lti-tool-configuration": map[string]any{
			"domain":            "client.example.org",
			"secondary_domains": []string{"cdn.example.com"},
			"description":       "Learn botany by tending to your little (virtual) garden.",
			"description#sv":    "Lär dig botanik genom att sköta din lilla (virtuella) trädgård.",
			"target_link_uri":   "https://client.example.org/lti",
			"custom_parameters": map[string]any{"context_history": "$Context.id.history"},
			"claims":            []string{"iss", "sub", "name", "given_name", "family_name", "email"},
			"messages": []any{
				map[string]any{
					"type":            "LtiDeepLinkingRequest",
					"target_link_uri": "https://client.example.org/lti/dl",
					"label":           "Add a virtual garden",
					"label#sv":        "Lägg till en virtuell trädgård",
				},
				map[string]any{"type": "LtiSubmissionReviewRequest"},
			},
		},
	}
}

func encodeRegistration(t *testing.T, body map[string]any) []byte {
	t.Helper()

	encoded, err := json.Marshal(body)
	require.NoError(t, err)

	return encoded
}

func toolConfiguration(body map[string]any) map[string]any {
	config, _ := body["https://purl.imsglobal.org/spec/lti-tool-configuration"].(map[string]any)

	return config
}

func parseTestRegistration(t *testing.T) *Registration {
	t.Helper()

	req, err := ParseRegistration(encodeRegistration(t, createTestRegistrationJSON()))
	require.NoError(t, err)

	return req
}

func requireRegistrationRejection(t *testing.T, err error, code lti.ErrorCode, message string) {
	t.Helper()

	require.Error(t, err)

	rejection, ok := lti.AsError(err)
	require.True(t, ok, "want an *lti.Error, got %v", err)
	assert.Equal(t, code, rejection.Code)
	assert.Contains(t, rejection.Description, message)
}

// ============================================================================
// Tests
// ============================================================================

func TestRegistration_Tool(t *testing.T) {
	t.Parallel()

	assert.Equal(t, Tool{
		ClientID:         "client-1",
		InitiateLoginURI: "https://client.example.org/lti",
		RedirectURIs:     []string{"https://client.example.org/callback", "https://client.example.org/callback2"},
		TargetLinkURI:    "https://client.example.org/lti",
		JWKSURI:          "https://client.example.org/.well-known/jwks.json",
		Domains:          []string{"client.example.org", "cdn.example.com"},
	}, parseTestRegistration(t).Tool("client-1"))
}

func TestParseRegistration_ParsesTheSpecExample(t *testing.T) {
	t.Parallel()

	req := parseTestRegistration(t)

	assert.Equal(t, "Virtual Garden", req.ClientName)
	assert.Equal(t, "https://client.example.org/lti", req.InitiateLoginURI)
	assert.Equal(t, []string{"https://client.example.org/callback", "https://client.example.org/callback2"}, req.RedirectURIs)
	assert.Equal(t, "https://client.example.org/.well-known/jwks.json", req.JWKSURI)
	assert.Equal(t, []string{"client.example.org", "cdn.example.com"}, req.Domains())
	assert.Equal(t, "https://client.example.org/lti", req.ToolConfiguration.TargetLinkURI)
	assert.Equal(t, map[string]string{"context_history": "$Context.id.history"}, req.ToolConfiguration.CustomParameters)
	require.Len(t, req.ToolConfiguration.Messages, 2)
	assert.Equal(t, "https://client.example.org/lti/dl", req.ToolConfiguration.Messages[0].TargetLinkURI)
}

func TestParseRegistration_NormalisesDomains(t *testing.T) {
	t.Parallel()

	body := createTestRegistrationJSON()
	toolConfiguration(body)["domain"] = "Client.Example.ORG"

	req, err := ParseRegistration(encodeRegistration(t, body))
	require.NoError(t, err)

	assert.Equal(t, "client.example.org", req.ToolConfiguration.Domain)
}

func TestParseRegistration_KeepsTheToolsMetadata(t *testing.T) {
	t.Parallel()

	req := parseTestRegistration(t)

	assert.Equal(t, map[string]string{"sv": "Virtuell trädgård", "de-DE": "Virtueller Garten"}, req.ClientNames)
	assert.Equal(t, "https://client.example.org/logo.png", req.LogoURI)
	assert.Equal(t, "https://client.example.org", req.ClientURI)
	assert.Equal(t, "https://client.example.org/privacy", req.PolicyURI)
	assert.Equal(t, "https://client.example.org/tos", req.TOSURI)
	assert.Equal(t, "Learn botany by tending to your little (virtual) garden.", req.ToolConfiguration.Description)
}

func TestParseRegistration_MetadataIsOptional(t *testing.T) {
	t.Parallel()

	body := createTestRegistrationJSON()
	for _, key := range []string{"client_name#sv", "client_name#de-DE", "logo_uri", "client_uri", "policy_uri", "tos_uri"} {
		delete(body, key)
	}

	delete(toolConfiguration(body), "description")

	req, err := ParseRegistration(encodeRegistration(t, body))
	require.NoError(t, err)

	assert.Empty(t, req.ClientNames)
	assert.Empty(t, req.LogoURI)
	assert.Empty(t, req.ToolConfiguration.Description)
}

func TestParseRegistration_DropsNonHTTPSMetadataURLs(t *testing.T) {
	t.Parallel()

	body := createTestRegistrationJSON()
	body["logo_uri"] = "http://client.example.org/logo.png"
	body["client_uri"] = "javascript:alert(1)"
	body["policy_uri"] = "http://client.example.org/privacy"
	body["tos_uri"] = "/tos"

	req, err := ParseRegistration(encodeRegistration(t, body))
	require.NoError(t, err)

	assert.Empty(t, req.LogoURI)
	assert.Empty(t, req.ClientURI)
	assert.Empty(t, req.PolicyURI)
	assert.Empty(t, req.TOSURI)
}

func TestParseRegistration_SkipsEmptyLocalizedNames(t *testing.T) {
	t.Parallel()

	body := createTestRegistrationJSON()
	body["client_name#fi"] = "  "

	req, err := ParseRegistration(encodeRegistration(t, body))
	require.NoError(t, err)

	assert.NotContains(t, req.ClientNames, "fi")
}

func TestParseRegistration_RejectsBadLocalizedNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value any
	}{
		{name: "a non-string name", key: "client_name#sv", value: 42},
		{name: "an empty language tag", key: "client_name#", value: "Garden"},
		{name: "a language tag with spaces", key: "client_name#s v", value: "Garden"},
		{name: "a subtag over 8 characters", key: "client_name#abcdefghi", value: "Garden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := createTestRegistrationJSON()
			body[tt.key] = tt.value

			_, err := ParseRegistration(encodeRegistration(t, body))
			requireRegistrationRejection(t, err, lti.ErrorInvalidClientMetadata, "client_name#")
		})
	}
}

func TestParseRegistration_Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		change  func(body map[string]any)
		message string
	}{
		{name: "a native application", change: func(b map[string]any) { b["application_type"] = "native" }, message: "application_type"},
		{name: "no id_token response type", change: func(b map[string]any) { b["response_types"] = []string{"code"} }, message: "response_types"},
		{name: "no implicit grant", change: func(b map[string]any) { b["grant_types"] = []string{"client_credentials"} }, message: "grant_types"},
		{name: "no client_credentials grant", change: func(b map[string]any) { b["grant_types"] = []string{"implicit"} }, message: "grant_types"},
		{name: "client secret authentication", change: func(b map[string]any) { b["token_endpoint_auth_method"] = "client_secret_basic" }, message: "token_endpoint_auth_method"},
		{name: "an http jwks_uri", change: func(b map[string]any) { b["jwks_uri"] = "http://client.example.org/jwks" }, message: "jwks_uri"},
		{name: "no jwks_uri", change: func(b map[string]any) { delete(b, "jwks_uri") }, message: "jwks_uri"},
		{name: "no domain", change: func(b map[string]any) { delete(toolConfiguration(b), "domain") }, message: "domain"},
		{name: "a domain with a path", change: func(b map[string]any) { toolConfiguration(b)["domain"] = "client.example.org/lti" }, message: "domain"},
		{name: "a top-level domain", change: func(b map[string]any) { toolConfiguration(b)["domain"] = "org" }, message: "domain"},
		{name: "a public suffix domain", change: func(b map[string]any) { toolConfiguration(b)["domain"] = "co.uk" }, message: "domain"},
		{name: "a private public suffix domain", change: func(b map[string]any) { toolConfiguration(b)["domain"] = "github.io" }, message: "domain"},
		{name: "a public suffix secondary domain", change: func(b map[string]any) { toolConfiguration(b)["secondary_domains"] = []string{"github.io"} }, message: "secondary_domains"},
		{name: "a bad secondary domain", change: func(b map[string]any) {
			toolConfiguration(b)["secondary_domains"] = []string{"https://cdn.example.com"}
		}, message: "secondary_domains"},
		{name: "an http initiate_login_uri", change: func(b map[string]any) { b["initiate_login_uri"] = "http://client.example.org/lti" }, message: "initiate_login_uri"},
		{name: "an initiate_login_uri on another domain", change: func(b map[string]any) { b["initiate_login_uri"] = "https://evil.example.net/lti" }, message: "initiate_login_uri"},
		{name: "no redirect_uris", change: func(b map[string]any) { b["redirect_uris"] = []string{} }, message: "redirect_uris"},
		{name: "a redirect_uri on another domain", change: func(b map[string]any) { b["redirect_uris"] = []string{"https://evil.example.net/callback"} }, message: "redirect_uris"},
		{name: "a redirect_uri with a fragment", change: func(b map[string]any) { b["redirect_uris"] = []string{"https://client.example.org/callback#x"} }, message: "redirect_uris"},
		{name: "a target_link_uri on another domain", change: func(b map[string]any) { toolConfiguration(b)["target_link_uri"] = "https://evil.example.net/lti" }, message: "target_link_uri"},
		{
			name: "a message target_link_uri on another domain",
			change: func(b map[string]any) {
				toolConfiguration(b)["messages"] = []any{map[string]any{"type": "LtiDeepLinkingRequest", "target_link_uri": "https://evil.example.net/dl"}}
			},
			message: "message's target_link_uri",
		},
		{name: "a message without a type", change: func(b map[string]any) { toolConfiguration(b)["messages"] = []any{map[string]any{"label": "x"}} }, message: "type"},
		{name: "a wrongly typed field", change: func(b map[string]any) { b["redirect_uris"] = "https://client.example.org/callback" }, message: "not valid client metadata json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := createTestRegistrationJSON()
			tt.change(body)

			// RFC 7591 §3.2.2 has its own code for redirect uris.
			code := lti.ErrorInvalidClientMetadata
			if tt.message == "redirect_uris" {
				code = lti.ErrorInvalidRedirectURI
			}

			_, err := ParseRegistration(encodeRegistration(t, body))
			requireRegistrationRejection(t, err, code, tt.message)
		})
	}
}

func TestParseRegistration_RejectsABodyOver1MiB(t *testing.T) {
	t.Parallel()

	body := createTestRegistrationJSON()
	body["client_name"] = strings.Repeat("a", MaxRegistrationBytes)

	_, err := ParseRegistration(encodeRegistration(t, body))
	requireRegistrationRejection(t, err, lti.ErrorInvalidClientMetadata, "")
}

func TestParseRegistration_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := ParseRegistration([]byte(`{"client_name":`))
	requireRegistrationRejection(t, err, lti.ErrorInvalidClientMetadata, "")
}

func TestPlatform_ReviewRegistration(t *testing.T) {
	t.Parallel()

	platform := createTestConfig()
	platform.Scopes = []lti.Scope{lti.ScopeAGSScore}

	review := parseTestRegistration(t).Review(platform)

	assert.Equal(t, RegistrationReview{
		ClientName:  "Virtual Garden",
		ClientNames: map[string]string{"sv": "Virtuell trädgård", "de-DE": "Virtueller Garten"},
		Description: "Learn botany by tending to your little (virtual) garden.",
		LogoURI:     "https://client.example.org/logo.png",
		Domains:     []string{"client.example.org", "cdn.example.com"},
		Contacts:    []string{"ve7jtb@example.org", "mary@example.org"},
		ClientURI:   "https://client.example.org",
		TOSURI:      "https://client.example.org/tos",
		PolicyURI:   "https://client.example.org/privacy",
		Messages: []ReviewMessage{
			{Type: "LtiDeepLinkingRequest", Label: "Add a virtual garden", TargetLinkURI: "https://client.example.org/lti/dl", Supported: true},
			{Type: "LtiSubmissionReviewRequest", Supported: false},
		},
		RequestedClaims:   []string{"iss", "sub", "name", "given_name", "family_name", "email"},
		RequestsName:      true,
		RequestsEmail:     true,
		RequestedScopes:   []lti.Scope{lti.ScopeAGSScore, lti.ScopeNRPSMembershipRead},
		UnsupportedScopes: []lti.Scope{lti.ScopeNRPSMembershipRead},
	}, review)
}

func TestPlatform_ReviewRegistration_ToolThatAsksForNoPersonalData(t *testing.T) {
	t.Parallel()

	body := createTestRegistrationJSON()
	body["client_name"] = ""
	delete(body, "scope")
	toolConfiguration(body)["claims"] = []string{"iss", "sub"}

	req, err := ParseRegistration(encodeRegistration(t, body))
	require.NoError(t, err)

	review := req.Review(createTestConfig())

	assert.Equal(t, "client.example.org", review.ClientName)
	assert.False(t, review.RequestsName)
	assert.False(t, review.RequestsEmail)
	assert.Empty(t, review.RequestedScopes)
	assert.Empty(t, review.UnsupportedScopes)
}

func TestPlatform_RegistrationResponse(t *testing.T) {
	t.Parallel()

	req := parseTestRegistration(t)

	response := req.Response(RegistrationGrant{
		ClientID:     "client-1",
		DeploymentID: "deployment-1",
		Scopes:       []lti.Scope{lti.ScopeAGSScore, lti.ScopeAGSLineItem},
		Claims:       []string{"iss", "sub", "aud"},
	})

	body, _ := json.Marshal(response)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))

	assert.Equal(t, "client-1", got["client_id"])
	assert.Equal(t, "Virtual Garden", got["client_name"])
	assert.Equal(t, "https://purl.imsglobal.org/spec/lti-ags/scope/score", got["scope"], "only granted scopes the tool asked for")

	config, ok := got["https://purl.imsglobal.org/spec/lti-tool-configuration"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "deployment-1", config["deployment_id"])
	assert.Equal(t, []any{"iss", "sub"}, config["claims"], "only granted claims the tool asked for")

	// The request itself is left as the tool sent it, for the admin review.
	assert.Empty(t, req.ToolConfiguration.DeploymentID)
	assert.Contains(t, req.ToolConfiguration.Claims, "email")
}

func TestPlatform_RegistrationResponse_GrantsNothingByDefault(t *testing.T) {
	t.Parallel()

	response := parseTestRegistration(t).Response(RegistrationGrant{ClientID: "client-1", DeploymentID: "deployment-1"})

	body, _ := json.Marshal(response)

	assert.NotContains(t, string(body), `"scope"`)
	assert.NotContains(t, string(body), `"claims"`)
}

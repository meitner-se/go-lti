package platform

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/ltitest"
)

// ============================================================================
// Test helper functions
// ============================================================================

func createTestAssetProcessorSettingsRequest() *lti.AssetProcessorSettingsRequest {
	common := createTestCommon()
	common.Roles = []lti.Role{lti.RoleInstructor}

	return &lti.AssetProcessorSettingsRequest{Common: common, Activity: lti.Activity{ID: "activity-1"}}
}

func createTestReportReviewRequest() *lti.ReportReviewRequest {
	common := createTestCommon()
	common.Roles = []lti.Role{lti.RoleInstructor}

	return &lti.ReportReviewRequest{
		Common:   common,
		Activity: lti.Activity{ID: "activity-1"},
		ForUser: lti.ForUser{
			UserID: "7b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e", Name: "Grace Hopper", GivenName: "Grace", FamilyName: "Hopper",
			Email: "grace@example.com", Roles: []lti.Role{lti.RoleLearner},
		},
		Submission:      lti.AssetSubmission{ID: "submission-1"},
		Asset:           lti.ReviewedAsset{ID: "asset-1"},
		AssetReportType: "originality",
	}
}

func createTestEulaRequest() *lti.EulaRequest {
	common := createTestCommon()
	common.Context = nil
	common.Roles = []lti.Role{lti.RoleInstitutionStudent}

	return &lti.EulaRequest{
		Common: common,
		EulaService: lti.EulaService{
			URL:    "https://platform.example.com/lti/eula/deployment-1",
			Scopes: []lti.Scope{lti.ScopeEulaUser, lti.ScopeEulaDeployment},
		},
	}
}

func createTestAssetProcessorSubmission() AssetProcessorSubmission {
	return AssetProcessorSubmission{
		DeploymentID: "deployment-1",
		ID:           "notice-1",
		Timestamp:    time.Date(2026, 11, 10, 12, 45, 12, 0, time.UTC),
		Context:      lti.LaunchContext{ID: "course-1"},
		ForUser:      lti.ForUser{UserID: "7b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e", Roles: []lti.Role{lti.RoleLearner}},
		Activity:     lti.Activity{ID: "activity-1"},
		Submission:   lti.AssetSubmission{ID: "submission-1"},
		AssetService: lti.AssetService{Assets: []lti.Asset{{
			ID:             "asset-1",
			URL:            "https://platform.example.com/lti/assets/asset-1",
			SHA256Checksum: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
			Timestamp:      time.Date(2026, 11, 10, 12, 44, 58, 0, time.UTC),
			Size:           0,
			ContentType:    "text/plain",
		}}},
		AssetReport: &lti.AssetReport{ReportURL: "https://platform.example.com/lti/reports/activity-1/proc-7"},
		Custom:      map[string]string{"processor_id": "proc-7"},
	}
}

func createTestAssetProcessorItem() map[string]any {
	return map[string]any{
		"type":   "ltiAssetProcessor",
		"url":    "https://tool.example.com/processor/settings",
		"title":  "Originality check",
		"custom": map[string]any{"processor_id": "proc-7", "notes": ""},
		"report": map[string]any{"url": "https://tool.example.com/processor/report", "custom": map[string]any{"view": "full"}},
	}
}

func createTestAssetProcessorSession() DeepLinkingSession {
	session := createTestDeepLinkingSession()
	session.Settings.AcceptTypes = []lti.ContentItemType{lti.ContentItemTypeLTIAssetProcessor}

	return session
}

// ============================================================================
// Tests
// ============================================================================

func TestLauncher_IDTokenClaims_DeepLinkingRequestOffersAssetProcessors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	msg := createTestDeepLinkingRequest()
	msg.Settings.AcceptTypes = []lti.ContentItemType{lti.ContentItemTypeLTIResourceLink, lti.ContentItemTypeLTIAssetProcessor}
	msg.Activity = &lti.Activity{ID: "activity-1"}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, lti.Activity{ID: "activity-1"}, claims[lti.ClaimActivity])
	assert.Contains(t, claimsJSON(t, claims), `"accept_types":["ltiResourceLink","ltiAssetProcessor"]`)

	msg.Activity = nil
	_, err = launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.ErrorContains(t, err, "offers ltiAssetProcessor needs an activity")

	msg.Activity = &lti.Activity{ID: ""}
	_, err = launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.ErrorContains(t, err, "activity id")
}

func TestLauncher_IDTokenClaims_AssetProcessorSettingsRequest(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	msg := createTestAssetProcessorSettingsRequest()
	msg.Custom = map[string]string{"processor_id": "proc-7", "course": "$Context.id"}
	msg.ContextMembershipsURL = "https://platform.example.com/lti/contexts/course-1/memberships"
	msg.AGSEndpoint = &lti.AGSEndpoint{Scopes: []lti.Scope{lti.ScopeAGSScore}, LineItems: "https://platform.example.com/lti/contexts/course-1/lineitems"}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, lti.MessageTypeAssetProcessorSettingsRequest, claims[lti.ClaimMessageType])
	assert.Equal(t, lti.Activity{ID: "activity-1"}, claims[lti.ClaimActivity])
	assert.Equal(t, map[string]string{"processor_id": "proc-7", "course": "course-1"}, claims[lti.ClaimCustom])
	assert.Contains(t, claims, lti.ClaimContext)
	assert.Contains(t, claims, lti.ClaimNamesRoleService)
	assert.Contains(t, claims, lti.ClaimAGSEndpoint)
	assert.NotContains(t, claims, lti.ClaimResourceLink)
	assert.NotContains(t, claims, lti.ClaimDeepLinkingSettings)
}

func TestLauncher_IDTokenClaims_ReportReviewRequest(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	msg := createTestReportReviewRequest()
	msg.Sharing = lti.Sharing{Name: true}

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
	require.NoError(t, err)

	assert.Equal(t, lti.MessageTypeReportReviewRequest, claims[lti.ClaimMessageType])
	assert.Equal(t, lti.Activity{ID: "activity-1"}, claims[lti.ClaimActivity])
	assert.Equal(t, lti.AssetSubmission{ID: "submission-1"}, claims[lti.ClaimSubmission])
	assert.Equal(t, lti.ReviewedAsset{ID: "asset-1"}, claims[lti.ClaimAsset])
	assert.Equal(t, lti.AssetReportType("originality"), claims[lti.ClaimAssetReportType])
	assert.Equal(t, lti.ForUser{
		UserID: "7b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e", Name: "Grace Hopper", GivenName: "Grace", FamilyName: "Hopper",
		Roles: []lti.Role{lti.RoleLearner},
	}, claims[lti.ClaimForUser], "sharing allows the owner's name, not their email address")
	assert.NotContains(t, claims, lti.ClaimResourceLink)

	assert.Equal(t, "grace@example.com", msg.ForUser.Email, "the message is left as it was")
}

func TestLauncher_IDTokenClaims_EulaRequest(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", createTestEulaRequest(), testNow)
	require.NoError(t, err)

	assert.Equal(t, lti.MessageTypeEulaRequest, claims[lti.ClaimMessageType])
	assert.JSONEq(t, `{
		"url": "https://platform.example.com/lti/eula/deployment-1",
		"scope": ["https://purl.imsglobal.org/spec/lti/scope/eula/user", "https://purl.imsglobal.org/spec/lti/scope/eula/deployment"]
	}`, string(mustJSON(t, claims[lti.ClaimEulaService])))
	assert.Equal(t, []lti.Role{lti.RoleInstitutionStudent}, claims[lti.ClaimRoles])
	assert.NotContains(t, claims, lti.ClaimContext)
	assert.NotContains(t, claims, lti.ClaimResourceLink)
}

func TestLauncher_IDTokenClaims_RejectsIncompleteAssetProcessorMessages(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	lineItem := &lti.AGSEndpoint{Scopes: []lti.Scope{lti.ScopeAGSScore}, LineItem: "https://platform.example.com/lti/contexts/course-1/lineitems/1"}

	tests := []struct {
		name    string
		msg     func() lti.Message
		wantErr string
	}{
		{"settings without a context", func() lti.Message {
			m := createTestAssetProcessorSettingsRequest()
			m.Context = nil

			return m
		}, "settings request needs a context"},
		{"settings with an ags line item", func() lti.Message {
			m := createTestAssetProcessorSettingsRequest()
			m.AGSEndpoint = lineItem

			return m
		}, "can't carry an ags lineitem url"},
		{"settings with a long activity id", func() lti.Message {
			m := createTestAssetProcessorSettingsRequest()
			m.Activity.ID = string(make([]byte, 256))

			return m
		}, "activity id"},
		{"report review without a context", func() lti.Message {
			m := createTestReportReviewRequest()
			m.Context = nil

			return m
		}, "report review request needs a context"},
		{"report review with an ags line item", func() lti.Message {
			m := createTestReportReviewRequest()
			m.AGSEndpoint = lineItem

			return m
		}, "can't carry an ags lineitem url"},
		{"report review without a report type", func() lti.Message {
			m := createTestReportReviewRequest()
			m.AssetReportType = ""

			return m
		}, "assetreport_type"},
		{"report review without the owner", func() lti.Message {
			m := createTestReportReviewRequest()
			m.ForUser.UserID = ""

			return m
		}, "for_user user_id"},
		{"eula with an ags endpoint", func() lti.Message {
			m := createTestEulaRequest()
			m.Context = &lti.LaunchContext{ID: "course-1"}
			m.AGSEndpoint = &lti.AGSEndpoint{Scopes: []lti.Scope{lti.ScopeAGSScore}, LineItems: "https://platform.example.com/lti/contexts/course-1/lineitems"}

			return m
		}, "can't carry the context's"},
		{"eula with context roles and no context", func() lti.Message {
			m := createTestEulaRequest()
			m.Roles = []lti.Role{lti.RoleInstitutionStudent, lti.RoleTeachingAssistant}

			return m
		}, "can't carry context roles"},
		{"eula without a scope", func() lti.Message {
			m := createTestEulaRequest()
			m.EulaService.Scopes = nil

			return m
		}, "eula service needs a scope"},
		{"eula with a relative url", func() lti.Message {
			m := createTestEulaRequest()
			m.EulaService.URL = "/eula"

			return m
		}, "eula service url"},
		{"a nil settings request", func() lti.Message { return (*lti.AssetProcessorSettingsRequest)(nil) }, "needs a message"},
		{"a nil report review", func() lti.Message { return (*lti.ReportReviewRequest)(nil) }, "needs a message"},
		{"a nil eula request", func() lti.Message { return (*lti.EulaRequest)(nil) }, "needs a message"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := launcher.idTokenClaims(createTestTool(), "nonce-1", tt.msg(), testNow)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestLauncher_IDTokenClaims_ExtensionsCantSetAssetProcessorClaims(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for _, name := range []string{
		lti.ClaimActivity, lti.ClaimForUser, lti.ClaimSubmission, lti.ClaimAsset, lti.ClaimAssetReportType, lti.ClaimEulaService,
	} {
		msg := createTestResourceLinkRequest()
		msg.Extensions = []lti.Claim{testNamedClaim{name: name}}

		_, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
		require.Error(t, err, name)
	}
}

func TestLauncher_Respond_LaunchesAssetProcessorMessages(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for _, msg := range []lti.Message{createTestAssetProcessorSettingsRequest(), createTestReportReviewRequest(), createTestEulaRequest()} {
		t.Run(string(msg.MessageType()), func(t *testing.T) {
			t.Parallel()

			launch := createTestLaunch()
			launch.Message = msg

			form, err := launcher.Respond(t.Context(), parseTestAuthenticationRequest(t), launch)
			require.NoError(t, err)
			assert.NotEmpty(t, fieldsOf(form)["id_token"])

			// The message must launch what the login initiation started.
			launch.Initiation.DeploymentID = "deployment-2"
			_, err = launcher.Respond(t.Context(), parseTestAuthenticationRequest(t), launch)
			require.ErrorContains(t, err, "deployment_id")
		})
	}
}

func TestAssetProcessorSubmission_SignsANoticeAToolCanVerify(t *testing.T) {
	t.Parallel()

	launcher, err := NewLauncher(createTestConfig(), ltitest.NewKeys(t, ltitest.NewSigningKey(t)))
	require.NoError(t, err)

	submission := createTestAssetProcessorSubmission()
	submission.Subject = "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b"
	submission.Roles = []lti.Role{lti.RoleInstructor}
	submission.Claims = []lti.Claim{testEndpointClaim{URL: "https://platform.example.com/extension"}}

	notice, err := submission.Notice()
	require.NoError(t, err)
	assert.Equal(t, lti.NoticeTypeAssetProcessorSubmission, notice.Type)

	token, err := launcher.SignNotice(t.Context(), createTestTool(), notice)
	require.NoError(t, err)

	_, claims := verifyNotice(t, launcher, token)

	assert.Equal(t, "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b", claims["sub"])
	assert.Equal(t, []any{string(lti.RoleInstructor)}, claims[lti.ClaimRoles])
	assert.Equal(t, map[string]any{"user_id": "7b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e", "roles": []any{string(lti.RoleLearner)}}, claims[lti.ClaimForUser])
	assert.Equal(t, map[string]any{"id": "activity-1"}, claims[lti.ClaimActivity])
	assert.Equal(t, map[string]any{"id": "submission-1"}, claims[lti.ClaimSubmission])
	assert.Equal(t, map[string]any{"id": "course-1"}, claims[lti.ClaimContext])
	assert.Equal(t, map[string]any{"processor_id": "proc-7"}, claims[lti.ClaimCustom])
	assert.Equal(t, map[string]any{
		"scope":      []any{string(lti.ScopeReport)},
		"report_url": "https://platform.example.com/lti/reports/activity-1/proc-7",
	}, claims[lti.ClaimAssetReport])
	assert.Equal(t, map[string]any{"url": "https://platform.example.com/extension"}, claims["https://platform.example.com/lti/claim/endpoint"])

	service, ok := claims[lti.ClaimAssetService].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []any{string(lti.ScopeAssetReadOnly)}, service["scope"])
	assert.Len(t, service["assets"], 1)
	assert.NotContains(t, claims, lti.ClaimMessageType, "a notice isn't a launch")
}

func TestAssetProcessorSubmission_ExtraClaimsCantOverrideItsOwn(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	submission := createTestAssetProcessorSubmission()
	submission.Claims = []lti.Claim{lti.Activity{ID: "activity-2"}}

	notice, err := submission.Notice()
	require.NoError(t, err)

	_, err = launcher.SignNotice(t.Context(), createTestTool(), notice)
	require.ErrorContains(t, err, "set twice")
}

func TestAssetProcessorSubmission_NoticeDoesNotShareItsSlices(t *testing.T) {
	t.Parallel()

	submission := createTestAssetProcessorSubmission()
	submission.Subject = "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b"
	submission.Roles = []lti.Role{lti.RoleInstructor}

	notice, err := submission.Notice()
	require.NoError(t, err)

	notice.Roles[0] = lti.RoleLearner
	notice.Context.ID = "course-2"

	assert.Equal(t, lti.RoleInstructor, submission.Roles[0])
	assert.Equal(t, "course-1", submission.Context.ID)
}

func TestAssetProcessorSubmission_AllowsAnEmptyFileAndNoAssets(t *testing.T) {
	t.Parallel()

	submission := createTestAssetProcessorSubmission()
	_, err := submission.Notice()
	require.NoError(t, err, "an empty file has a size of 0")

	submission.AssetService.Assets = nil
	notice, err := submission.Notice()
	require.NoError(t, err)

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))
	claims, err := launcher.noticeClaims(createTestTool(), notice, "nonce-1", testNow)
	require.NoError(t, err)
	assert.Contains(t, claimsJSON(t, claims), `"assets":[]`)
}

func TestAssetProcessorSubmission_RejectsANegativeSize(t *testing.T) {
	t.Parallel()

	submission := createTestAssetProcessorSubmission()
	submission.AssetService.Assets[0].Size = -1

	_, err := submission.Notice()
	require.ErrorContains(t, err, "size")
}

func TestDeepLinkingVerifier_Verify_AcceptsAnAssetProcessor(t *testing.T) {
	t.Parallel()

	setup := createTestDeepLinkingSetup(t)
	claims := createTestDeepLinkingResponseClaims(setup.now)
	setContentItems(claims, createTestAssetProcessorItem(), map[string]any{"type": "ltiAssetProcessor", "custom": map[string]any{}})

	session := createTestAssetProcessorSession()
	session.Settings.AcceptMultiple = true

	response, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), session)
	require.NoError(t, err)
	require.Len(t, response.Items, 2)

	item := response.Items[0]
	assert.Equal(t, lti.ContentItemTypeLTIAssetProcessor, item.Type)
	assert.Equal(t, "https://tool.example.com/processor/settings", item.URL)
	assert.Equal(t, map[string]string{"processor_id": "proc-7", "notes": ""}, item.Custom)
	assert.Equal(t, &lti.ContentItemReport{URL: "https://tool.example.com/processor/report", Custom: map[string]string{"view": "full"}}, item.Report)

	bare := response.Items[1]
	assert.Empty(t, bare.URL, "the settings launch goes to the tool's own url")
	assert.Nil(t, bare.Report, "the tool means to post no reports")
	assert.Equal(t, map[string]string{}, bare.Custom)
}

func TestDeepLinkingVerifier_Verify_RejectsBadAssetProcessors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		item    func(map[string]any)
		session func(*DeepLinkingSession)
		wantErr string
	}{
		{"without custom", func(i map[string]any) { delete(i, "custom") }, nil, "without custom parameters"},
		{"with null custom", func(i map[string]any) { i["custom"] = nil }, nil, "without custom parameters"},
		{"with custom that isn't an object", func(i map[string]any) { i["custom"] = "proc-7" }, nil, "malformed"},
		{"with a null custom value", func(i map[string]any) { i["custom"] = map[string]any{"a": nil} }, nil, "null, not a string"},
		{"with a null report custom value", func(i map[string]any) {
			i["report"] = map[string]any{"custom": map[string]any{"a": nil}}
		}, nil, "null, not a string"},
		{"with an http report url", func(i map[string]any) {
			i["report"] = map[string]any{"url": "http://tool.example.com/processor/report"}
		}, nil, "isn't https"},
		{"with a miscased report key", func(i map[string]any) {
			i["Report"] = i["report"]
			delete(i, "report")
		}, nil, "miscased"},
		{"with a miscased report url key", func(i map[string]any) {
			i["report"] = map[string]any{"URL": "http://tool.example.com/processor/report"}
		}, nil, "miscased"},
		{"that the request didn't offer", nil, func(s *DeepLinkingSession) {
			s.Settings.AcceptTypes = []lti.ContentItemType{lti.ContentItemTypeLTIResourceLink}
		}, "type the request didn't accept"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			setup := createTestDeepLinkingSetup(t)
			item := createTestAssetProcessorItem()
			if tt.item != nil {
				tt.item(item)
			}

			claims := createTestDeepLinkingResponseClaims(setup.now)
			setContentItems(claims, item)

			session := createTestAssetProcessorSession()
			if tt.session != nil {
				tt.session(&session)
			}

			_, err := setup.verifier.Verify(t.Context(), setup.sign(t, claims), session)
			requireRejection(t, err, tt.wantErr)
		})
	}
}

func TestConfig_OpenIDConfiguration_AssetProcessor(t *testing.T) {
	t.Parallel()

	cfg := createTestConfig()

	configuration, err := cfg.OpenIDConfiguration()
	require.NoError(t, err)
	assert.Equal(t, []SupportedMessage{
		{Type: lti.MessageTypeResourceLinkRequest},
		{Type: lti.MessageTypeDeepLinkingRequest},
	}, configuration.PlatformConfiguration.MessagesSupported, "nothing changes for a platform without asset processors")

	cfg.AssetProcessor = true
	cfg.Scopes = []lti.Scope{lti.ScopeAssetReadOnly, lti.ScopeReport, lti.ScopeEulaUser, lti.ScopeEulaDeployment}
	cfg.NoticeTypes = []lti.NoticeType{lti.NoticeTypeAssetProcessorSubmission}

	configuration, err = cfg.OpenIDConfiguration()
	require.NoError(t, err)

	body, _ := json.Marshal(configuration)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &got))

	var platform map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(got["https://purl.imsglobal.org/spec/lti-platform-configuration"], &platform))

	assert.JSONEq(t, `[
		{"type": "LtiResourceLinkRequest"},
		{"type": "LtiDeepLinkingRequest", "placements": ["ActivityAssetProcessor"]},
		{"type": "LtiAssetProcessorSettingsRequest"},
		{"type": "LtiReportReviewRequest"},
		{"type": "LtiEulaRequest"}
	]`, string(platform["messages_supported"]))
	assert.JSONEq(t, `[
		"openid",
		"https://purl.imsglobal.org/spec/lti/scope/asset.readonly",
		"https://purl.imsglobal.org/spec/lti/scope/report",
		"https://purl.imsglobal.org/spec/lti/scope/eula/user",
		"https://purl.imsglobal.org/spec/lti/scope/eula/deployment"
	]`, string(got["scopes_supported"]))
	assert.JSONEq(t, `["LtiAssetProcessorSubmissionNotice"]`, string(platform["notice_types_supported"]))
}

func TestParseRegistration_AcceptsAnAssetProcessorTool(t *testing.T) {
	t.Parallel()

	body := createTestRegistrationJSON()
	body["scope"] = "https://purl.imsglobal.org/spec/lti/scope/asset.readonly https://purl.imsglobal.org/spec/lti/scope/report " +
		"https://purl.imsglobal.org/spec/lti/scope/eula/user https://purl.imsglobal.org/spec/lti/scope/eula/deployment"
	toolConfiguration(body)["messages"] = []any{
		map[string]any{"type": "LtiDeepLinkingRequest", "target_link_uri": "https://client.example.org/pick", "placements": []any{"ContentArea"}},
		map[string]any{"type": "LtiDeepLinkingRequest", "target_link_uri": "https://client.example.org/processor", "placements": []any{"ActivityAssetProcessor"}},
		map[string]any{"type": "LtiAssetProcessorSettingsRequest"},
		map[string]any{"type": "LtiReportReviewRequest"},
		map[string]any{"type": "LtiEulaRequest", "target_link_uri": "https://client.example.org/eula"},
	}

	reg, err := ParseRegistration(encodeRegistration(t, body))
	require.NoError(t, err)

	cfg := createTestConfig()
	cfg.Scopes = []lti.Scope{lti.ScopeAssetReadOnly, lti.ScopeReport}

	review := reg.Review(cfg)
	assert.Equal(t, "https://client.example.org/pick", review.DeepLinkingURL)
	assert.Equal(t, "https://client.example.org/processor", review.AssetProcessorDeepLinkingURL)
	assert.Equal(t, "https://client.example.org/eula", review.EulaURL)
	assert.Equal(t, []string{"ActivityAssetProcessor"}, review.Messages[1].Placements)
	assert.Equal(t, []lti.Scope{lti.ScopeEulaUser, lti.ScopeEulaDeployment}, review.UnsupportedScopes)

	for _, message := range review.Messages {
		assert.True(t, message.Supported, message.Type)
	}
}

func TestRegistration_Review_ToolWithoutAssetProcessor(t *testing.T) {
	t.Parallel()

	body := createTestRegistrationJSON()
	toolConfiguration(body)["messages"] = []any{
		map[string]any{"type": "LtiDeepLinkingRequest"},
		map[string]any{"type": "LtiSubmissionReviewRequest"},
	}

	reg, err := ParseRegistration(encodeRegistration(t, body))
	require.NoError(t, err)

	review := reg.Review(createTestConfig())
	assert.Empty(t, review.AssetProcessorDeepLinkingURL, "a Deep Linking message without the placement offers no processors")
	assert.Empty(t, review.EulaURL)
	assert.False(t, review.Messages[1].Supported)
}

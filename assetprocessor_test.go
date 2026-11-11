package lti_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
)

// ============================================================================
// Tests
// ============================================================================

func TestAssetProcessorClaims_NamesAndShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		claim     lti.Claim
		claimName string
		want      string
	}{
		{
			name:      "activity",
			claim:     lti.Activity{ID: "activity-1"},
			claimName: "https://purl.imsglobal.org/spec/lti/claim/activity",
			want:      `{"id":"activity-1"}`,
		},
		{
			name:      "for_user with only its required user_id",
			claim:     lti.ForUser{UserID: "user-1"},
			claimName: "https://purl.imsglobal.org/spec/lti/claim/for_user",
			want:      `{"user_id":"user-1"}`,
		},
		{
			name: "for_user with every member",
			claim: lti.ForUser{
				UserID: "user-1", PersonSourcedID: "sis-1", GivenName: "Grace", FamilyName: "Hopper", Name: "Grace Hopper",
				Email: "grace@example.com", Roles: []lti.Role{lti.RoleLearner},
			},
			claimName: "https://purl.imsglobal.org/spec/lti/claim/for_user",
			want: `{"user_id":"user-1","person_sourcedid":"sis-1","given_name":"Grace","family_name":"Hopper",
				"name":"Grace Hopper","email":"grace@example.com","roles":["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"]}`,
		},
		{
			name:      "submission",
			claim:     lti.AssetSubmission{ID: "submission-1"},
			claimName: "https://purl.imsglobal.org/spec/lti/claim/submission",
			want:      `{"id":"submission-1"}`,
		},
		{
			name:      "asset",
			claim:     lti.ReviewedAsset{ID: "asset-1"},
			claimName: "https://purl.imsglobal.org/spec/lti/claim/asset",
			want:      `{"id":"asset-1"}`,
		},
		{
			name:      "assetreport_type is a string",
			claim:     lti.AssetReportType("originality"),
			claimName: "https://purl.imsglobal.org/spec/lti/claim/assetreport_type",
			want:      `"originality"`,
		},
		{
			name: "assetservice with its only scope",
			claim: lti.AssetService{Assets: []lti.Asset{{
				ID: "asset-1", URL: "https://platform.example.com/lti/assets/asset-1", Title: "Essay", Filename: "essay.pdf",
				SHA256Checksum: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
				Timestamp:      time.Date(2026, 11, 10, 13, 44, 58, 0, time.FixedZone("CET", 3600)),
				Size:           48213, ContentType: "application/pdf",
			}}},
			claimName: "https://purl.imsglobal.org/spec/lti/claim/assetservice",
			want: `{"scope":["https://purl.imsglobal.org/spec/lti/scope/asset.readonly"],"assets":[{
				"asset_id":"asset-1","url":"https://platform.example.com/lti/assets/asset-1","title":"Essay","filename":"essay.pdf",
				"sha256_checksum":"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=","timestamp":"2026-11-10T13:44:58.000+01:00",
				"size":48213,"content_type":"application/pdf"}]}`,
		},
		{
			name:      "assetservice with no assets",
			claim:     lti.AssetService{},
			claimName: "https://purl.imsglobal.org/spec/lti/claim/assetservice",
			want:      `{"scope":["https://purl.imsglobal.org/spec/lti/scope/asset.readonly"],"assets":[]}`,
		},
		{
			name:      "assetreport with its only scope",
			claim:     lti.AssetReport{ReportURL: "https://platform.example.com/lti/reports/1"},
			claimName: "https://purl.imsglobal.org/spec/lti/claim/assetreport",
			want:      `{"scope":["https://purl.imsglobal.org/spec/lti/scope/report"],"report_url":"https://platform.example.com/lti/reports/1"}`,
		},
		{
			name: "eulaservice",
			claim: lti.EulaService{
				URL:    "https://platform.example.com/lti/eula/deployment-1",
				Scopes: []lti.Scope{lti.ScopeEulaUser, lti.ScopeEulaDeployment},
			},
			claimName: "https://purl.imsglobal.org/spec/lti/claim/eulaservice",
			want: `{"url":"https://platform.example.com/lti/eula/deployment-1","scope":[
				"https://purl.imsglobal.org/spec/lti/scope/eula/user","https://purl.imsglobal.org/spec/lti/scope/eula/deployment"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.claimName, tt.claim.ClaimName())

			body, err := json.Marshal(tt.claim)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(body))
		})
	}
}

func TestAssetService_RoundTrips(t *testing.T) {
	t.Parallel()

	claim := lti.AssetService{Assets: []lti.Asset{{
		ID: "asset-1", URL: "https://platform.example.com/lti/assets/asset-1",
		SHA256Checksum: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
		Timestamp:      time.Date(2026, 11, 10, 12, 44, 58, 123456000, time.UTC),
		Size:           0, ContentType: "text/plain",
	}}}

	body, err := json.Marshal(claim)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"timestamp":"2026-11-10T12:44:58.123456Z"`, "sub-millisecond precision is kept")

	var decoded lti.AssetService
	require.NoError(t, json.Unmarshal(body, &decoded))
	require.Len(t, decoded.Assets, 1)
	assert.True(t, claim.Assets[0].Timestamp.Equal(decoded.Assets[0].Timestamp))

	decoded.Assets[0].Timestamp = claim.Assets[0].Timestamp
	assert.Equal(t, claim, decoded)
}

func TestAssetReport_RoundTrips(t *testing.T) {
	t.Parallel()

	claim := lti.AssetReport{ReportURL: "https://platform.example.com/lti/reports/1"}

	body, err := json.Marshal(claim)
	require.NoError(t, err)

	var decoded lti.AssetReport
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, claim, decoded)
}

func TestAsset_UnmarshalJSON_ReadsISO8601Offsets(t *testing.T) {
	t.Parallel()

	var asset lti.Asset
	require.NoError(t, json.Unmarshal([]byte(`{"asset_id":"asset-1","timestamp":"2026-11-10T13:44:58+0100"}`), &asset))

	assert.True(t, time.Date(2026, 11, 10, 12, 44, 58, 0, time.UTC).Equal(asset.Timestamp))
}

func TestAssetProcessorMessages_MessageTypes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, lti.MessageType("LtiAssetProcessorSettingsRequest"), (&lti.AssetProcessorSettingsRequest{}).MessageType())
	assert.Equal(t, lti.MessageType("LtiReportReviewRequest"), (&lti.ReportReviewRequest{}).MessageType())
	assert.Equal(t, lti.MessageType("LtiEulaRequest"), (&lti.EulaRequest{}).MessageType())
}

func TestContentItem_DecodesAnAssetProcessorReport(t *testing.T) {
	t.Parallel()

	var item lti.ContentItem
	require.NoError(t, json.Unmarshal([]byte(`{"type":"ltiAssetProcessor","custom":{},"report":{}}`), &item))

	assert.Equal(t, lti.ContentItemTypeLTIAssetProcessor, item.Type)
	assert.Equal(t, &lti.ContentItemReport{}, item.Report, "an empty report still says the tool posts reports")
	assert.Equal(t, map[string]string{}, item.Custom)
}

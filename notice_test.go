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

func TestPlatformNotificationService_MarshalJSON(t *testing.T) {
	t.Parallel()

	claim := lti.PlatformNotificationService{
		URL:                  "https://platform.example.com/lti/notice-handlers/deployment-1",
		NoticeTypesSupported: []lti.NoticeType{"LtiHelloWorldNotice"},
	}

	body, err := json.Marshal(claim)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"platform_notification_service_url": "https://platform.example.com/lti/notice-handlers/deployment-1",
		"service_versions": ["1.0"],
		"scope": ["https://purl.imsglobal.org/spec/lti/scope/noticehandlers"],
		"notice_types_supported": ["LtiHelloWorldNotice"]
	}`, string(body))

	var decoded lti.PlatformNotificationService
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, claim, decoded)
}

func TestPlatformNotificationService_MarshalJSON_NoNoticeTypesIsAnEmptyArray(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(lti.PlatformNotificationService{URL: "https://platform.example.com/lti/notice-handlers/deployment-1"})
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, []any{}, got["notice_types_supported"])
}

func TestNoticeHandlers_MarshalJSON(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(lti.NoticeHandlers{
		ClientID:     "client-1",
		DeploymentID: "deployment-1",
		NoticeHandlers: []lti.NoticeHandler{
			{NoticeType: "LtiHelloWorldNotice", Handler: "https://tool.example.com/notices"},
			{NoticeType: "LtiAssetProcessorSubmissionNotice", Handler: ""},
		},
	})
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"client_id": "client-1",
		"deployment_id": "deployment-1",
		"notice_handlers": [
			{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/notices"},
			{"notice_type": "LtiAssetProcessorSubmissionNotice", "handler": ""}
		]
	}`, string(body))

	body, err = json.Marshal(lti.NoticeHandlers{ClientID: "client-1", DeploymentID: "deployment-1"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"client_id": "client-1", "deployment_id": "deployment-1", "notice_handlers": []}`, string(body))
}

func TestNoticeHandlerRegistration_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body string
		want lti.NoticeHandlerRegistration
	}{
		"with a batch size": {
			body: `{"notice_type": "LtiHelloWorldNotice", "handler": "https://tool.example.com/notices", "max_batch_size": 20}`,
			want: lti.NoticeHandlerRegistration{NoticeType: "LtiHelloWorldNotice", Handler: "https://tool.example.com/notices", MaxBatchSize: 20},
		},
		"an integral float": {
			body: `{"notice_type": "LtiHelloWorldNotice", "handler": "", "max_batch_size": 5.0}`,
			want: lti.NoticeHandlerRegistration{NoticeType: "LtiHelloWorldNotice", Handler: "", MaxBatchSize: 5},
		},
		"without a batch size": {
			body: `{"notice_type": "LtiHelloWorldNotice", "handler": ""}`,
			want: lti.NoticeHandlerRegistration{NoticeType: "LtiHelloWorldNotice", Handler: "", MaxBatchSize: 0},
		},
		"a null batch size": {
			body: `{"notice_type": "LtiHelloWorldNotice", "handler": "", "max_batch_size": null}`,
			want: lti.NoticeHandlerRegistration{NoticeType: "LtiHelloWorldNotice", Handler: "", MaxBatchSize: 0},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var got lti.NoticeHandlerRegistration
			require.NoError(t, json.Unmarshal([]byte(tt.body), &got))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNoticeHandlerRegistration_UnmarshalJSON_RefusesABadBatchSize(t *testing.T) {
	t.Parallel()

	for _, size := range []string{"0", "-1", "2.5", `"10"`, "true", "1e12"} {
		var got lti.NoticeHandlerRegistration

		err := json.Unmarshal([]byte(`{"notice_type": "LtiHelloWorldNotice", "handler": "", "max_batch_size": `+size+`}`), &got)
		require.ErrorIs(t, err, lti.ErrMaxBatchSize, size)
	}
}

func TestNotice_MarshalJSON_KeepsTheTimeZone(t *testing.T) {
	t.Parallel()

	notice := lti.Notice{
		ID:        "notice-1",
		Timestamp: time.Date(2026, 11, 10, 13, 45, 12, 250_000_000, time.FixedZone("CET", 3600)),
		Type:      "LtiHelloWorldNotice",
	}

	body, err := json.Marshal(notice)
	require.NoError(t, err)
	assert.JSONEq(t, `{"id": "notice-1", "timestamp": "2026-11-10T13:45:12.250+01:00", "type": "LtiHelloWorldNotice"}`, string(body))

	var decoded lti.Notice
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, notice.ID, decoded.ID)
	assert.Equal(t, notice.Type, decoded.Type)
	assert.True(t, notice.Timestamp.Equal(decoded.Timestamp))
}

func TestNewNoticeEnvelope(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(lti.NewNoticeEnvelope("eyJ.a.b", "eyJ.c.d"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"notices": [{"jwt": "eyJ.a.b"}, {"jwt": "eyJ.c.d"}]}`, string(body))

	body, err = json.Marshal(lti.NewNoticeEnvelope())
	require.NoError(t, err)
	assert.JSONEq(t, `{"notices": []}`, string(body))
}

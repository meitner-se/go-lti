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

func TestLineItem_MarshalJSON(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 10, 16, 0, 0, 0, time.FixedZone("CET", 3600))
	released := false

	item := lti.LineItem{
		ID:             "https://platform.example.com/lti/contexts/course-1/lineitems/1",
		ScoreMaximum:   60,
		Label:          "Chapter 5 Test",
		ResourceID:     "quiz-231",
		ResourceLinkID: "link-1",
		Tag:            "grade",
		StartDateTime:  &start,
		EndDateTime:    &end,
		GradesReleased: &released,
	}

	body, err := json.Marshal(item)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"id": "https://platform.example.com/lti/contexts/course-1/lineitems/1",
		"scoreMaximum": 60,
		"label": "Chapter 5 Test",
		"resourceId": "quiz-231",
		"resourceLinkId": "link-1",
		"tag": "grade",
		"startDateTime": "2026-11-03T08:00:00.000Z",
		"endDateTime": "2026-11-10T16:00:00.000+01:00",
		"gradesReleased": false
	}`, string(body))

	var decoded lti.LineItem
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, item.ID, decoded.ID)
	assert.True(t, start.Equal(*decoded.StartDateTime))
	assert.True(t, end.Equal(*decoded.EndDateTime))
	assert.Equal(t, &released, decoded.GradesReleased)
}

func TestLineItem_MarshalJSON_LeavesOutEmptyFields(t *testing.T) {
	t.Parallel()

	// AGS 2.0 §3.2.5: a tool's create request has no id; label and scoreMaximum are required.
	body, err := json.Marshal(lti.LineItem{ScoreMaximum: 100, Label: "Essay"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"scoreMaximum": 100, "label": "Essay"}`, string(body))

	body, err = json.Marshal(lti.LineItemContainer(nil))
	require.NoError(t, err)
	assert.JSONEq(t, `[]`, string(body))
}

func TestLineItem_UnmarshalJSON_BlankTimesAreNoTime(t *testing.T) {
	t.Parallel()

	// AGS 2.0 §3.2.12: a platform without a start time may send it blank or null.
	var item lti.LineItem
	require.NoError(t, json.Unmarshal([]byte(`{"scoreMaximum": 1, "label": "Quiz", "startDateTime": "", "endDateTime": null}`), &item))
	assert.Nil(t, item.StartDateTime)
	assert.Nil(t, item.EndDateTime)
	assert.Nil(t, item.GradesReleased)
}

func TestLineItemContainer_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	var container lti.LineItemContainer
	require.NoError(t, json.Unmarshal([]byte(`[
		{"id": "https://platform.example.com/lti/lineitems/1", "scoreMaximum": 60, "label": "Chapter 5 Test", "resourceId": "quiz-231", "tag": "grade"},
		{"id": "https://platform.example.com/lti/lineitems/2", "scoreMaximum": 100, "label": "Chapter 5 Progress", "resourceLinkId": "link-1"}
	]`), &container))

	assert.Equal(t, lti.LineItemContainer{
		{ID: "https://platform.example.com/lti/lineitems/1", ScoreMaximum: 60, Label: "Chapter 5 Test", ResourceID: "quiz-231", Tag: "grade"},
		{ID: "https://platform.example.com/lti/lineitems/2", ScoreMaximum: 100, Label: "Chapter 5 Progress", ResourceLinkID: "link-1"},
	}, container)
}

func TestScore_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	// AGS 2.0 §3.4.3.1 and §3.4.3.2.
	var final lti.Score
	require.NoError(t, json.Unmarshal([]byte(`{
		"timestamp": "2017-04-16T18:54:36.736+00:00",
		"scoreGiven": 83,
		"scoreMaximum": 100,
		"comment": "This is exceptional work.",
		"activityProgress": "Completed",
		"gradingProgress": "FullyGraded",
		"userId": "5323497",
		"scoringUserId": "4567890"
	}`), &final))

	scoreGiven := 83.0
	assert.Equal(t, lti.Score{
		UserID:           "5323497",
		ScoreGiven:       &scoreGiven,
		ScoreMaximum:     100,
		Comment:          "This is exceptional work.",
		Timestamp:        final.Timestamp,
		ActivityProgress: lti.ActivityProgressCompleted,
		GradingProgress:  lti.GradingProgressFullyGraded,
		ScoringUserID:    "4567890",
	}, final)
	assert.True(t, time.Date(2017, 4, 16, 18, 54, 36, 736_000_000, time.UTC).Equal(final.Timestamp))

	var started lti.Score
	require.NoError(t, json.Unmarshal([]byte(`{
		"timestamp": "2017-03-16T18:54:36.736+00:00",
		"activityProgress": "InProgress",
		"gradingProgress": "NotReady",
		"userId": "5323497",
		"submission": {"startedAt": "2017-03-13T16:12:27.000+00:00", "submittedAt": "2017-03-14T18:42:15.000+00:00"}
	}`), &started))

	assert.Nil(t, started.ScoreGiven, "no scoreGiven is no score")
	assert.Equal(t, lti.ActivityProgressInProgress, started.ActivityProgress)
	assert.Equal(t, lti.GradingProgressNotReady, started.GradingProgress)
	require.NotNil(t, started.Submission)
	assert.True(t, time.Date(2017, 3, 13, 16, 12, 27, 0, time.UTC).Equal(*started.Submission.StartedAt))
	assert.True(t, time.Date(2017, 3, 14, 18, 42, 15, 0, time.UTC).Equal(*started.Submission.SubmittedAt))
}

func TestScore_UnmarshalJSON_Timestamps(t *testing.T) {
	t.Parallel()

	want := time.Date(2017, 4, 16, 18, 54, 36, 736_000_000, time.UTC)

	// AGS 2.0 §3.4.9.1 lists these three forms as valid.
	for _, timestamp := range []string{"2017-04-16T18:54:36.736+00:00", "2017-04-16T18:54:36.736Z", "2017-04-16T18:54:36.736+00", "2017-04-16T20:54:36.736+02"} {
		var score lti.Score
		require.NoError(t, json.Unmarshal([]byte(`{"userId": "1", "timestamp": "`+timestamp+`"}`), &score), timestamp)
		assert.True(t, want.Equal(score.Timestamp), timestamp)
	}

	for _, timestamp := range []string{`"2017-04-16T18:54:36.736"`, `"2017-04-16"`, `"yesterday"`, `1492368876`} {
		var score lti.Score
		require.Error(t, json.Unmarshal([]byte(`{"userId": "1", "timestamp": `+timestamp+`}`), &score), timestamp)
	}
}

func TestScore_MarshalJSON(t *testing.T) {
	t.Parallel()

	scoreGiven := 0.0
	startedAt := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	score := lti.Score{
		UserID:           "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
		ScoreGiven:       &scoreGiven,
		ScoreMaximum:     10,
		Comment:          "Try again.",
		Timestamp:        time.Date(2026, 11, 3, 9, 30, 0, 0, time.UTC),
		ActivityProgress: lti.ActivityProgressSubmitted,
		GradingProgress:  lti.GradingProgressPendingManual,
		ScoringUserID:    "8b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
		Submission:       &lti.Submission{StartedAt: &startedAt},
	}

	body, err := json.Marshal(score)
	require.NoError(t, err)

	// A score of 0 is still a score, and the timestamp keeps sub-second precision (§3.4.4, §3.4.9).
	assert.JSONEq(t, `{
		"userId": "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
		"scoreGiven": 0,
		"scoreMaximum": 10,
		"comment": "Try again.",
		"timestamp": "2026-11-03T09:30:00.000Z",
		"activityProgress": "Submitted",
		"gradingProgress": "PendingManual",
		"scoringUserId": "8b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
		"submission": {"startedAt": "2026-11-03T08:00:00.000Z"}
	}`, string(body))

	var decoded lti.Score
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.True(t, score.Timestamp.Equal(decoded.Timestamp))
	decoded.Timestamp = score.Timestamp
	assert.True(t, startedAt.Equal(*decoded.Submission.StartedAt))
	decoded.Submission = score.Submission
	assert.Equal(t, score, decoded)
}

func TestScore_MarshalJSON_LeavesOutEmptyFields(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(lti.Score{
		UserID:           "user-1",
		Timestamp:        time.Date(2026, 11, 3, 9, 30, 0, 123_456_789, time.UTC),
		ActivityProgress: lti.ActivityProgressStarted,
		GradingProgress:  lti.GradingProgressNotReady,
	})
	require.NoError(t, err)

	// Precision finer than milliseconds is kept, so two updates stay in order.
	assert.JSONEq(t, `{
		"userId": "user-1",
		"timestamp": "2026-11-03T09:30:00.123456789Z",
		"activityProgress": "Started",
		"gradingProgress": "NotReady"
	}`, string(body))
}

func TestResultContainer_MarshalJSON(t *testing.T) {
	t.Parallel()

	resultScore := 0.83
	container := lti.ResultContainer{
		{
			ID:            "https://platform.example.com/lti/contexts/course-1/lineitems/1/results/5323497",
			ScoreOf:       "https://platform.example.com/lti/contexts/course-1/lineitems/1",
			UserID:        "5323497",
			ResultScore:   &resultScore,
			ResultMaximum: 1,
			ScoringUserID: "4567890",
			Comment:       "This is exceptional work.",
		},
		{
			ID:      "https://platform.example.com/lti/contexts/course-1/lineitems/1/results/8b1c2d3e",
			ScoreOf: "https://platform.example.com/lti/contexts/course-1/lineitems/1",
			UserID:  "8b1c2d3e",
		},
	}

	body, err := json.Marshal(container)
	require.NoError(t, err)

	// AGS 2.0 §3.3.4.1; a result without a score leaves resultScore out.
	assert.JSONEq(t, `[
		{
			"id": "https://platform.example.com/lti/contexts/course-1/lineitems/1/results/5323497",
			"scoreOf": "https://platform.example.com/lti/contexts/course-1/lineitems/1",
			"userId": "5323497",
			"resultScore": 0.83,
			"resultMaximum": 1,
			"scoringUserId": "4567890",
			"comment": "This is exceptional work."
		},
		{
			"id": "https://platform.example.com/lti/contexts/course-1/lineitems/1/results/8b1c2d3e",
			"scoreOf": "https://platform.example.com/lti/contexts/course-1/lineitems/1",
			"userId": "8b1c2d3e"
		}
	]`, string(body))

	var decoded lti.ResultContainer
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, container, decoded)

	body, err = json.Marshal(lti.ResultContainer(nil))
	require.NoError(t, err)
	assert.JSONEq(t, `[]`, string(body))
}

func TestAGSEndpoint_MarshalJSON(t *testing.T) {
	t.Parallel()

	body, _ := json.Marshal(lti.AGSEndpoint{Scopes: []lti.Scope{lti.ScopeAGSScore}, LineItem: "https://platform.example.com/lti/lineitems/1"})
	assert.JSONEq(t, `{"scope": ["https://purl.imsglobal.org/spec/lti-ags/scope/score"], "lineitem": "https://platform.example.com/lti/lineitems/1"}`, string(body))
}

func TestAGSMediaTypes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "application/vnd.ims.lis.v2.lineitemcontainer+json", lti.LineItemContainerMediaType)
	assert.Equal(t, "application/vnd.ims.lis.v2.lineitem+json", lti.LineItemMediaType)
	assert.Equal(t, "application/vnd.ims.lis.v1.score+json", lti.ScoreMediaType)
	assert.Equal(t, "application/vnd.ims.lis.v2.resultcontainer+json", lti.ResultContainerMediaType)
}

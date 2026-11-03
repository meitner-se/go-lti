package lti

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Media types of Assignment and Grade Services 2.0 bodies (§3.2.1, §3.3.4, §3.4.3).
const (
	LineItemContainerMediaType = "application/vnd.ims.lis.v2.lineitemcontainer+json"
	LineItemMediaType          = "application/vnd.ims.lis.v2.lineitem+json"
	ScoreMediaType             = "application/vnd.ims.lis.v1.score+json"
	ResultContainerMediaType   = "application/vnd.ims.lis.v2.resultcontainer+json"
)

// AGSEndpoint is the Assignment and Grade Services endpoint claim (AGS 2.0 §3.1).
type AGSEndpoint struct {
	// Scopes are the AGS scopes the tool may ask an access token for; at least one.
	Scopes []Scope `json:"scope"`
	// LineItems is the context's line item container URL, empty when the tool may not use it.
	LineItems string `json:"lineitems,omitempty"`
	// LineItem is the URL of the launched link's only line item, else empty (§3.1).
	LineItem string `json:"lineitem,omitempty"`
}

// LineItemContainer is a context's line items, or a page of them (AGS 2.0 §3.2).
type LineItemContainer []LineItem

// MarshalJSON encodes the container, with no line items as an empty array.
func (c LineItemContainer) MarshalJSON() ([]byte, error) {
	if c == nil {
		return []byte("[]"), nil
	}

	return json.Marshal([]LineItem(c))
}

// LineItem is a gradebook column (AGS 2.0 §3.2); empty optional fields are left out.
type LineItem struct {
	// ID is the line item's URL, empty in a tool's create request since the platform picks it.
	ID string `json:"id,omitempty"`
	// ScoreMaximum is the highest score, strictly greater than 0 (§3.2.8).
	ScoreMaximum float64 `json:"scoreMaximum"`
	// Label is the line item's title; a tool must send one that isn't blank (§3.2.7).
	Label string `json:"label"`
	// ResourceID is the tool's own id for what the line item grades; the platform keeps it as sent.
	ResourceID string `json:"resourceId,omitempty"`
	// ResourceLinkID binds the line item to one of the tool's resource links (§3.2.9).
	ResourceLinkID string `json:"resourceLinkId,omitempty"`
	// Tag is the tool's own label for the line item, such as "final"; the platform keeps it as sent.
	Tag string `json:"tag,omitempty"`
	// StartDateTime and EndDateTime bound when learners may submit; nil is no bound.
	StartDateTime *time.Time `json:"startDateTime,omitempty"`
	EndDateTime   *time.Time `json:"endDateTime,omitempty"`
	// GradesReleased is whether the tool wishes the grades released; nil when it doesn't say.
	GradesReleased *bool `json:"gradesReleased,omitempty"`
}

// MarshalJSON encodes the line item, with times in ISO 8601 to the millisecond or finer.
func (l LineItem) MarshalJSON() ([]byte, error) {
	type lineItem LineItem

	return json.Marshal(struct {
		lineItem

		StartDateTime *dateTime `json:"startDateTime,omitempty"`
		EndDateTime   *dateTime `json:"endDateTime,omitempty"`
	}{lineItem(l), newDateTime(l.StartDateTime), newDateTime(l.EndDateTime)})
}

// UnmarshalJSON decodes a line item. A blank or null time is no time (§3.2.12).
func (l *LineItem) UnmarshalJSON(data []byte) error {
	type lineItem LineItem

	var v struct {
		lineItem

		StartDateTime *dateTime `json:"startDateTime"`
		EndDateTime   *dateTime `json:"endDateTime"`
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*l = LineItem(v.lineItem)
	l.StartDateTime = v.StartDateTime.time()
	l.EndDateTime = v.EndDateTime.time()

	return nil
}

// Score is a user's score and progress as a tool posts it (AGS 2.0 §3.4).
type Score struct {
	// UserID is the user's sub in launches to the same tool.
	UserID string `json:"userId"`
	// ScoreGiven is nil for no score, which clears one sent before, since 0 is a score (§3.4.4).
	ScoreGiven *float64 `json:"scoreGiven,omitempty"`
	// ScoreMaximum is the denominator, which a ScoreGiven needs; ScoreGiven may exceed it.
	ScoreMaximum float64 `json:"scoreMaximum,omitempty"`
	// Comment is plain text (§3.4.11).
	Comment string `json:"comment,omitempty"`
	// Timestamp increases strictly per line item and user, to order score updates (§3.4.9).
	Timestamp        time.Time        `json:"timestamp"`
	ActivityProgress ActivityProgress `json:"activityProgress"`
	GradingProgress  GradingProgress  `json:"gradingProgress"`
	// ScoringUserID is the sub of the user who gave the score, such as an instructor (§3.4.6).
	ScoringUserID string `json:"scoringUserId,omitempty"`
	// Submission is when the user started and submitted the attempt, if the tool says.
	Submission *Submission `json:"submission,omitempty"`
}

// MarshalJSON encodes the score, with its timestamp to the millisecond or finer (§3.4.9).
func (s Score) MarshalJSON() ([]byte, error) {
	type score Score

	return json.Marshal(struct {
		score

		Timestamp dateTime `json:"timestamp"`
	}{score(s), dateTime(s.Timestamp)})
}

// UnmarshalJSON decodes a score. A missing or blank timestamp is the zero time.
func (s *Score) UnmarshalJSON(data []byte) error {
	type score Score

	var v struct {
		score

		Timestamp *dateTime `json:"timestamp"`
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*s = Score(v.score)
	if t := v.Timestamp.time(); t != nil {
		s.Timestamp = *t
	}

	return nil
}

// Submission is a score's submission attempt (AGS 2.0 §3.4.10); nil times are left out.
type Submission struct {
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	SubmittedAt *time.Time `json:"submittedAt,omitempty"`
}

// MarshalJSON encodes the submission, with times in ISO 8601 to the millisecond or finer.
func (s Submission) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		StartedAt   *dateTime `json:"startedAt,omitempty"`
		SubmittedAt *dateTime `json:"submittedAt,omitempty"`
	}{newDateTime(s.StartedAt), newDateTime(s.SubmittedAt)})
}

// UnmarshalJSON decodes a submission. A blank or null time is no time.
func (s *Submission) UnmarshalJSON(data []byte) error {
	var v struct {
		StartedAt   *dateTime `json:"startedAt"`
		SubmittedAt *dateTime `json:"submittedAt"`
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*s = Submission{StartedAt: v.StartedAt.time(), SubmittedAt: v.SubmittedAt.time()}

	return nil
}

// ResultContainer is a line item's results, as the platform answers them (AGS 2.0 §3.3).
type ResultContainer []Result

// MarshalJSON encodes the container, with no results as an empty array.
func (c ResultContainer) MarshalJSON() ([]byte, error) {
	if c == nil {
		return []byte("[]"), nil
	}

	return json.Marshal([]Result(c))
}

// Result is a user's current score for a line item in the platform's gradebook (AGS 2.0 §3.3.4).
type Result struct {
	ID string `json:"id"`
	// ScoreOf is the line item's ID.
	ScoreOf string `json:"scoreOf"`
	// UserID is the user's sub in launches to the same tool.
	UserID string `json:"userId"`
	// ResultScore is the score. Nil when the user has none.
	ResultScore *float64 `json:"resultScore,omitempty"`
	// ResultMaximum is greater than 0; left out, a tool reads it as 1 (§3.3.4.6).
	ResultMaximum float64 `json:"resultMaximum,omitempty"`
	// ScoringUserID is the sub of the user who gave the score (§3.3.4.7).
	ScoringUserID string `json:"scoringUserId,omitempty"`
	Comment       string `json:"comment,omitempty"`
}

// dateTimeLayout always writes milliseconds, since a score's timestamp needs sub-second precision.
const dateTimeLayout = "2006-01-02T15:04:05.000Z07:00"

// dateTime reads every form AGS 2.0 §3.4.9.1 allows, which time.Time's RFC 3339 doesn't.
type dateTime time.Time

func newDateTime(t *time.Time) *dateTime {
	if t == nil {
		return nil
	}

	d := dateTime(*t)

	return &d
}

// time returns the decoded time, or nil when d is nil.
func (d *dateTime) time() *time.Time {
	if d == nil || time.Time(*d).IsZero() {
		return nil
	}

	t := time.Time(*d)

	return &t
}

func (d dateTime) MarshalJSON() ([]byte, error) {
	t := time.Time(d)

	layout := dateTimeLayout
	if t.Nanosecond()%int(time.Millisecond) != 0 {
		layout = time.RFC3339Nano
	}

	return json.Marshal(t.Format(layout))
}

func (d *dateTime) UnmarshalJSON(data []byte) error {
	var s *string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("lti: %s is not a date and time", data)
	}

	if s == nil || strings.TrimSpace(*s) == "" {
		return nil
	}

	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		// AGS 2.0 §3.4.9.1 allows an offset of hours only, such as "+00".
		t, err = time.Parse("2006-01-02T15:04:05.999999999-07", *s)
	}

	if err != nil {
		return fmt.Errorf("lti: %q is not an ISO 8601 date and time with a time zone", *s)
	}

	*d = dateTime(t)

	return nil
}

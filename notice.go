package lti

import (
	"encoding/json"
	"errors"
	"time"
)

// PlatformNotificationServiceVersion is the LTI Platform Notification Service version the platform
// offers, the only one in the service claim's service_versions.
const PlatformNotificationServiceVersion = "1.0"

// NoticeType is the type of a platform notice, such as LtiContextCopyNotice.
type NoticeType string

// PlatformNotificationService is the LTI Platform Notification Service claim: where the tool
// registers its notice handlers and which notice types the platform sends. It is encoded with
// service_versions ["1.0"] and scope [ScopeNoticeHandlers], the only ones the service has.
type PlatformNotificationService struct {
	// URL is the deployment's notice handler registration endpoint, an absolute https URL.
	URL string
	// NoticeTypesSupported are the notice types the platform sends; none is sent as [].
	NoticeTypesSupported []NoticeType
}

// MarshalJSON encodes the claim, with no notice types as an empty array.
func (s PlatformNotificationService) MarshalJSON() ([]byte, error) {
	types := s.NoticeTypesSupported
	if types == nil {
		types = []NoticeType{}
	}

	return json.Marshal(platformNotificationService{
		URL:                  s.URL,
		ServiceVersions:      []string{PlatformNotificationServiceVersion},
		Scopes:               []Scope{ScopeNoticeHandlers},
		NoticeTypesSupported: types,
	})
}

// UnmarshalJSON decodes the claim's URL and notice types.
func (s *PlatformNotificationService) UnmarshalJSON(data []byte) error {
	var v platformNotificationService
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*s = PlatformNotificationService{URL: v.URL, NoticeTypesSupported: v.NoticeTypesSupported}

	return nil
}

//nolint:tagliatelle // the Platform Notification Service defines snake_case keys
type platformNotificationService struct {
	URL                  string       `json:"platform_notification_service_url"`
	ServiceVersions      []string     `json:"service_versions"`
	Scopes               []Scope      `json:"scope"`
	NoticeTypesSupported []NoticeType `json:"notice_types_supported"`
}

// NoticeHandler is a tool's handler for one notice type: the URL the platform posts notices of
// that type to, or "" when the tool has none.
//
//nolint:tagliatelle // the Platform Notification Service defines snake_case keys
type NoticeHandler struct {
	NoticeType NoticeType `json:"notice_type"`
	Handler    string     `json:"handler"`
}

// NoticeHandlers are a deployment's notice handlers, as the platform answers a tool's GET of its
// registration endpoint: every notice type the platform supports, with "" where the tool has no
// handler.
//
//nolint:tagliatelle // the Platform Notification Service defines snake_case keys
type NoticeHandlers struct {
	ClientID       string          `json:"client_id"`
	DeploymentID   string          `json:"deployment_id"`
	NoticeHandlers []NoticeHandler `json:"notice_handlers"`
}

// MarshalJSON encodes the handlers, with none as an empty array.
func (h NoticeHandlers) MarshalJSON() ([]byte, error) {
	type noticeHandlers NoticeHandlers

	if h.NoticeHandlers == nil {
		h.NoticeHandlers = []NoticeHandler{}
	}

	return json.Marshal(noticeHandlers(h))
}

// NoticeHandlerRegistration is what a tool PUTs to its registration endpoint to replace its
// handler for one notice type. An empty Handler removes it.
//
//nolint:tagliatelle // the Platform Notification Service defines snake_case keys
type NoticeHandlerRegistration struct {
	NoticeType NoticeType `json:"notice_type"`
	Handler    string     `json:"handler"`
	// MaxBatchSize is the most notices the tool takes in one request, or 0 when it didn't say.
	MaxBatchSize int `json:"max_batch_size,omitempty"`
}

// ErrMaxBatchSize is what decoding a NoticeHandlerRegistration returns for a max_batch_size that
// isn't a positive integer.
var ErrMaxBatchSize = errors.New("lti: max_batch_size must be a positive integer")

// UnmarshalJSON decodes a registration, requiring a max_batch_size, when present, to be a
// positive integer.
func (r *NoticeHandlerRegistration) UnmarshalJSON(data []byte) error {
	var v noticeHandlerRegistration
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*r = NoticeHandlerRegistration{NoticeType: v.NoticeType, Handler: v.Handler, MaxBatchSize: 0}

	if len(v.MaxBatchSize) == 0 || string(v.MaxBatchSize) == "null" {
		return nil
	}

	var size integer
	if err := json.Unmarshal(v.MaxBatchSize, &size); err != nil || size < 1 {
		return ErrMaxBatchSize
	}

	r.MaxBatchSize = int(size)

	return nil
}

//nolint:tagliatelle // the Platform Notification Service defines snake_case keys
type noticeHandlerRegistration struct {
	NoticeType   NoticeType      `json:"notice_type"`
	Handler      string          `json:"handler"`
	MaxBatchSize json.RawMessage `json:"max_batch_size"`
}

// Notice is the notice claim of a notice JWT: which event it tells the tool about.
type Notice struct {
	// ID is the notice's id, unique for ever within the deployment and the same on every resend.
	ID string `json:"id"`
	// Timestamp is when the event happened, written with its time zone.
	Timestamp time.Time `json:"timestamp"`
	// Type is the notice's type.
	Type NoticeType `json:"type"`
}

// MarshalJSON encodes the notice, with its timestamp in ISO 8601 to the millisecond or finer.
func (n Notice) MarshalJSON() ([]byte, error) {
	type notice Notice

	return json.Marshal(struct {
		notice

		Timestamp dateTime `json:"timestamp"`
	}{notice(n), dateTime(n.Timestamp)})
}

// UnmarshalJSON decodes a notice. A missing or blank timestamp is the zero time.
func (n *Notice) UnmarshalJSON(data []byte) error {
	type notice Notice

	var v struct {
		notice

		Timestamp *dateTime `json:"timestamp"`
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*n = Notice(v.notice)
	if t := v.Timestamp.time(); t != nil {
		n.Timestamp = *t
	}

	return nil
}

// NoticeEnvelope is the body the platform POSTs to a notice handler: one or more signed notices,
// all of one type.
type NoticeEnvelope struct {
	Notices []SignedNotice `json:"notices"`
}

// SignedNotice is one notice in an envelope: its notice JWT, signed by the platform.
type SignedNotice struct {
	JWT string `json:"jwt"`
}

// NewNoticeEnvelope returns the envelope of the notice JWTs jwts.
func NewNoticeEnvelope(jwts ...string) NoticeEnvelope {
	notices := make([]SignedNotice, 0, len(jwts))
	for _, jwt := range jwts {
		notices = append(notices, SignedNotice{JWT: jwt})
	}

	return NoticeEnvelope{Notices: notices}
}

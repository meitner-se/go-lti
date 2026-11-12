package lti

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// Activity is the activity claim: the activity, such as an assignment, that an asset processor is
// attached to. Its ID is fixed from the Deep Linking request on, even while the activity isn't
// saved yet, and is the same in the settings launch, the submission notices and report reviews.
type Activity struct {
	// ID is the activity's id within its context. At most 255 characters.
	ID string `json:"id"`
}

// ClaimName returns ClaimActivity.
func (Activity) ClaimName() string { return ClaimActivity }

// ForUser is the for_user claim, as LTI Submission Review defines it: the user the message is
// about, such as the owner of submitted assets, who may differ from the user it was sent for.
// Only UserID is required. The other fields are personal data; a launch sends a name or an email
// address only when its Sharing allows it.
//
//nolint:tagliatelle // LTI Submission Review defines snake_case keys
type ForUser struct {
	// UserID is the user's sub in launches to the same tool. At most 255 characters.
	UserID          string `json:"user_id"`
	PersonSourcedID string `json:"person_sourcedid,omitempty"`
	GivenName       string `json:"given_name,omitempty"`
	FamilyName      string `json:"family_name,omitempty"`
	Name            string `json:"name,omitempty"`
	Email           string `json:"email,omitempty"`
	Roles           []Role `json:"roles,omitempty"`
}

// ClaimName returns ClaimForUser.
func (ForUser) ClaimName() string { return ClaimForUser }

// AssetSubmission is the submission claim: one submission of assets. A submission and its assets
// never change; a resubmission is a new submission with a new ID, and new IDs for all its assets.
type AssetSubmission struct {
	// ID is the submission's id. At most 255 characters.
	ID string `json:"id"`
}

// ClaimName returns ClaimSubmission.
func (AssetSubmission) ClaimName() string { return ClaimSubmission }

// ReviewedAsset is the asset claim of a report review: the asset whose report the user views. Its
// ID is an Asset.ID the platform sent the tool.
type ReviewedAsset struct {
	ID string `json:"id"`
}

// ClaimName returns ClaimAsset.
func (ReviewedAsset) ClaimName() string { return ClaimAsset }

// AssetReportType is the assetreport_type claim of a report review: the type of the report the
// user views, as the tool posted it.
type AssetReportType string

// ClaimName returns ClaimAssetReportType.
func (AssetReportType) ClaimName() string { return ClaimAssetReportType }

// AssetService is the assetservice claim: every asset the owner currently has submitted to the
// activity, and where the tool downloads each. It is encoded with scope [ScopeAssetReadOnly], the
// service's only scope.
type AssetService struct {
	// Assets are the owner's current assets; none is sent as [].
	Assets []Asset
}

// ClaimName returns ClaimAssetService.
func (AssetService) ClaimName() string { return ClaimAssetService }

// MarshalJSON encodes the claim with its scope, and no assets as an empty array.
func (s AssetService) MarshalJSON() ([]byte, error) {
	assets := s.Assets
	if assets == nil {
		assets = []Asset{}
	}

	return json.Marshal(assetService{Scopes: []Scope{ScopeAssetReadOnly}, Assets: assets})
}

// UnmarshalJSON decodes the claim's assets.
func (s *AssetService) UnmarshalJSON(data []byte) error {
	var v assetService
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*s = AssetService{Assets: v.Assets}

	return nil
}

type assetService struct {
	Scopes []Scope `json:"scope"`
	Assets []Asset `json:"assets"`
}

// Asset is one submitted file in the assetservice claim. An asset never changes: a new version of
// the file is a new asset with a new ID.
//
//nolint:tagliatelle // the Asset Service defines snake_case keys
type Asset struct {
	// ID is the asset's id. At most 255 characters.
	ID string `json:"asset_id"`
	// URL is where the tool downloads the asset with an access token: an absolute https URL that
	// keeps working, since the tool may download it later and more than once. It must not carry a
	// token that expires or works once.
	URL      string `json:"url"`
	Title    string `json:"title,omitempty"`
	Filename string `json:"filename,omitempty"`
	// SHA256Checksum is the SHA-256 digest of the asset's bytes, base64-encoded.
	SHA256Checksum string `json:"sha256_checksum"`
	// Timestamp is when the asset was uploaded.
	Timestamp time.Time `json:"timestamp"`
	// Size is the asset's size in bytes.
	Size int64 `json:"size"`
	// ContentType is the asset's media type, the Content-Type the platform answers a download with.
	ContentType string `json:"content_type"`
}

// MarshalJSON encodes the asset, with its timestamp in ISO 8601 to the millisecond or finer.
func (a Asset) MarshalJSON() ([]byte, error) {
	type asset Asset

	return json.Marshal(struct {
		asset

		Timestamp dateTime `json:"timestamp"`
	}{asset(a), dateTime(a.Timestamp)})
}

// UnmarshalJSON decodes an asset. A missing or blank timestamp is the zero time.
func (a *Asset) UnmarshalJSON(data []byte) error {
	type asset Asset

	var v struct {
		asset

		Timestamp *dateTime `json:"timestamp"`
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*a = Asset(v.asset)
	if t := v.Timestamp.time(); t != nil {
		a.Timestamp = *t
	}

	return nil
}

// AssetReport is the assetreport claim: where the tool posts its reports about the assets. It is
// encoded with scope [ScopeReport], the service's only scope.
type AssetReport struct {
	// ReportURL is where the tool posts reports, an absolute https URL. It belongs to one processor
	// attached to one activity, so the platform knows from the URL which processor a report is from.
	ReportURL string
}

// ClaimName returns ClaimAssetReport.
func (AssetReport) ClaimName() string { return ClaimAssetReport }

// MarshalJSON encodes the claim with its scope.
func (r AssetReport) MarshalJSON() ([]byte, error) {
	return json.Marshal(assetReport{Scopes: []Scope{ScopeReport}, ReportURL: r.ReportURL})
}

// UnmarshalJSON decodes the claim's report URL.
func (r *AssetReport) UnmarshalJSON(data []byte) error {
	var v assetReport
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	*r = AssetReport{ReportURL: v.ReportURL}

	return nil
}

//nolint:tagliatelle // the Asset Report Service defines snake_case keys
type assetReport struct {
	Scopes    []Scope `json:"scope"`
	ReportURL string  `json:"report_url"`
}

// EulaService is the eulaservice claim: where the tool records EULA acceptance for the deployment.
type EulaService struct {
	// URL is the deployment's EULA service, an absolute https URL that stays the same, since a tool
	// may keep it.
	URL string `json:"url"`
	// Scopes are the EULA scopes the tool may ask an access token for: ScopeEulaUser,
	// ScopeEulaDeployment or both.
	Scopes []Scope `json:"scope"`
}

// ClaimName returns ClaimEulaService.
func (EulaService) ClaimName() string { return ClaimEulaService }

// ContentItemReport is the report member of an ltiAssetProcessor content item: the tool means to
// post reports, and where a report review launches.
type ContentItemReport struct {
	// URL is the report review's target link URI; empty means the tool's.
	URL string `json:"url,omitempty"`
	// Custom are the custom parameters of every report review launch for the processor.
	Custom map[string]string `json:"custom,omitempty"`
}

// AssetProcessorSettingsRequest launches an asset processor's settings for the activity it is
// attached to. It needs a context, and the activity.
type AssetProcessorSettingsRequest struct {
	Common

	Activity Activity
}

// MessageType returns LtiAssetProcessorSettingsRequest.
func (*AssetProcessorSettingsRequest) MessageType() MessageType {
	return MessageTypeAssetProcessorSettingsRequest
}

func (*AssetProcessorSettingsRequest) isMessage() {}

// ReportReviewRequest launches the tool's report about one asset. It needs a context, and has no
// resource link: a report is found by its activity, asset and report type.
type ReportReviewRequest struct {
	Common

	Activity Activity
	// ForUser is the owner of the asset.
	ForUser    ForUser
	Submission AssetSubmission
	Asset      ReviewedAsset
	// AssetReportType is the type of the report, as the tool posted it.
	AssetReportType AssetReportType
}

// MessageType returns LtiReportReviewRequest.
func (*ReportReviewRequest) MessageType() MessageType { return MessageTypeReportReviewRequest }

func (*ReportReviewRequest) isMessage() {}

// EulaRequest launches the tool's EULA for the user to accept or decline. It is a deployment's,
// with no resource link and no context services; it may have a context, and without one it has no
// context roles. The tool records the user's answer with the EULA service.
type EulaRequest struct {
	Common

	EulaService EulaService
}

// MessageType returns LtiEulaRequest.
func (*EulaRequest) MessageType() MessageType { return MessageTypeEulaRequest }

func (*EulaRequest) isMessage() {}

// Report is one report a tool posts about one asset with the Asset Report Service. A report is
// found by its processor (the report URL it was posted to), its AssetID and its Type: a report with
// the same or a later Timestamp replaces the one the platform has, and an earlier one may be
// discarded.
//
// Decoding is lenient, so that a tool's report isn't turned away for what the platform can still
// show: an unknown processingProgress is read as ProcessingProgressNotReady, an errorCode may be the
// tool's own, result has no length limit, an indicationColor is kept without an indicationAlt, and
// a timestamp may have any precision, and no time zone, which is read as UTC. Every other member is
// kept in Extensions. Decoding fails, with an *Error with ErrorInvalidRequest, for anything but a
// JSON object, a member of the wrong JSON type, and a report without an assetId, a type, a
// timestamp, a priority from 0 to 5 or a processingProgress.
type Report struct {
	// AssetID is the asset's id, an Asset.ID the platform sent the tool for the processor.
	AssetID string
	// Type is the report's type, opaque to the platform. Reports of different types about one asset
	// are separate reports.
	Type string
	// Timestamp is when the tool made the report, which orders its versions.
	Timestamp time.Time
	Title     string
	// Result is the report's short result, such as a score, for when processing succeeded. The spec
	// asks a tool to keep it to 16 characters, and a platform not to cut a short one.
	Result string
	// Comment is for people to read, such as why processing failed.
	Comment string
	// IndicationColor is a color, such as "#ff0000", for the platform to show without interpreting
	// it. The spec requires IndicationAlt with it, at most 255 characters, to describe it in words.
	IndicationColor string
	IndicationAlt   string
	// Priority is from 0, nothing notable, through 1, notable, and 3, somewhat urgent or a warning,
	// to 5, urgent or an error.
	Priority int
	// VisibleToOwner says the asset's owner may see the report and its indication. Users who may
	// see the owner's submission, such as teachers, always may.
	VisibleToOwner     bool
	ProcessingProgress ProcessingProgress
	// ErrorCode says why processing failed, when it did. It may be a code of the tool's own.
	ErrorCode ReportErrorCode
	// Extensions are the report's other members, such as properties a tool names after its own
	// domain, as raw JSON.
	Extensions map[string]json.RawMessage
}

// reportTimestampLayout writes a report's timestamp to the microsecond, as the spec asks.
const reportTimestampLayout = "2006-01-02T15:04:05.000000Z07:00"

//nolint:tagliatelle // the Asset Report Service defines keys such as assetId
type report struct {
	AssetID            string             `json:"assetId"`
	Type               string             `json:"type"`
	Timestamp          string             `json:"timestamp"`
	Title              string             `json:"title,omitempty"`
	Result             string             `json:"result,omitempty"`
	Comment            string             `json:"comment,omitempty"`
	IndicationColor    string             `json:"indicationColor,omitempty"`
	IndicationAlt      string             `json:"indicationAlt,omitempty"`
	Priority           int                `json:"priority"`
	VisibleToOwner     bool               `json:"visibleToOwner,omitempty"`
	ProcessingProgress ProcessingProgress `json:"processingProgress"`
	ErrorCode          ReportErrorCode    `json:"errorCode,omitempty"`
}

// MarshalJSON encodes the report with its Extensions, with its timestamp to the microsecond or
// finer. A member of the report's own wins over an extension of the same name.
func (rep Report) MarshalJSON() ([]byte, error) {
	layout := reportTimestampLayout
	if rep.Timestamp.Nanosecond()%int(time.Microsecond) != 0 {
		layout = time.RFC3339Nano
	}

	known, err := json.Marshal(report{
		AssetID: rep.AssetID, Type: rep.Type, Timestamp: rep.Timestamp.Format(layout), Title: rep.Title, Result: rep.Result,
		Comment: rep.Comment, IndicationColor: rep.IndicationColor, IndicationAlt: rep.IndicationAlt, Priority: rep.Priority,
		VisibleToOwner: rep.VisibleToOwner, ProcessingProgress: rep.ProcessingProgress, ErrorCode: rep.ErrorCode,
	})
	if err != nil || len(rep.Extensions) == 0 {
		return known, err
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(known, &members); err != nil {
		return nil, err
	}

	for name, value := range rep.Extensions {
		if _, ok := members[name]; !ok {
			members[name] = value
		}
	}

	return json.Marshal(members)
}

// processingProgresses are the processing progress values the spec names.
var processingProgresses = []ProcessingProgress{
	ProcessingProgressNotReady, ProcessingProgressProcessed, ProcessingProgressProcessing, ProcessingProgressPending,
	ProcessingProgressPendingManual, ProcessingProgressFailed, ProcessingProgressNotProcessed,
}

// UnmarshalJSON decodes a report leniently, as Report describes.
func (rep *Report) UnmarshalJSON(data []byte) error {
	o, err := newObjectReader("report", data)
	if err != nil {
		return err
	}

	var (
		v         Report
		timestamp lenientDateTime
		priority  integer
		progress  string
	)

	o.require("assetId", o.decode("assetId", &v.AssetID) && v.AssetID != "")
	o.require("type", o.decode("type", &v.Type) && v.Type != "")
	o.require("timestamp", o.decode("timestamp", &timestamp) && !time.Time(timestamp).IsZero())
	o.decode("title", &v.Title)
	o.decode("result", &v.Result)
	o.decode("comment", &v.Comment)
	o.decode("indicationColor", &v.IndicationColor)
	o.decode("indicationAlt", &v.IndicationAlt)
	o.decode("visibleToOwner", &v.VisibleToOwner)
	o.decode("errorCode", &v.ErrorCode)

	hasPriority := o.decode("priority", &priority)
	if o.err == nil && hasPriority && (priority < 0 || priority > 5) {
		o.err = NewError(ErrorInvalidRequest, "the report's priority must be an integer from 0 to 5", nil)
	}

	o.require("priority", hasPriority)
	o.require("processingProgress", o.decode("processingProgress", &progress))

	if o.err != nil {
		return o.err
	}

	v.Timestamp = time.Time(timestamp)
	v.Priority = int(priority)

	v.ProcessingProgress = ProcessingProgress(progress)
	if !slices.Contains(processingProgresses, v.ProcessingProgress) {
		v.ProcessingProgress = ProcessingProgressNotReady
	}

	if len(o.members) > 0 {
		v.Extensions = o.members
	}

	*rep = v

	return nil
}

// EulaAcceptance is what a tool posts to the EULA service's user endpoint: whether a user accepted
// the tool's EULA, for the whole deployment. The platform keeps it only to know whether to show the
// EULA again; the tool decides. An acceptance older than the one the platform has for the user
// changes nothing.
//
// Decoding fails, with an *Error with ErrorInvalidRequest, for anything but a JSON object, and one
// without a userId, accepted or a timestamp. Other members are ignored. A timestamp may have any
// precision, and no time zone, which is read as UTC.
type EulaAcceptance struct {
	// UserID is the user's sub in launches to the tool.
	UserID string
	// Accepted is false for a user who declined the EULA.
	Accepted bool
	// Timestamp is when the user answered.
	Timestamp time.Time
}

//nolint:tagliatelle // the EULA service defines the key userId
type eulaAcceptance struct {
	UserID    string   `json:"userId"`
	Accepted  bool     `json:"accepted"`
	Timestamp dateTime `json:"timestamp"`
}

// MarshalJSON encodes the acceptance, with its timestamp in ISO 8601 to the millisecond or finer.
func (a EulaAcceptance) MarshalJSON() ([]byte, error) {
	return json.Marshal(eulaAcceptance{UserID: a.UserID, Accepted: a.Accepted, Timestamp: dateTime(a.Timestamp)})
}

// UnmarshalJSON decodes an acceptance, as EulaAcceptance describes.
func (a *EulaAcceptance) UnmarshalJSON(data []byte) error {
	o, err := newObjectReader("acceptance", data)
	if err != nil {
		return err
	}

	var (
		v         EulaAcceptance
		timestamp lenientDateTime
	)

	o.require("userId", o.decode("userId", &v.UserID) && v.UserID != "")
	o.require("accepted", o.decode("accepted", &v.Accepted))
	o.require("timestamp", o.decode("timestamp", &timestamp) && !time.Time(timestamp).IsZero())

	if o.err != nil {
		return o.err
	}

	v.Timestamp = time.Time(timestamp)
	*a = v

	return nil
}

// EulaDeployment is what a tool puts to the EULA service's deployment endpoint: whether users in
// the deployment must accept its EULA. A deployment with the EULA service requires it until the
// tool says otherwise.
//
// Decoding fails, with an *Error with ErrorInvalidRequest, for anything but a JSON object, and one
// without eulaRequired. Other members are ignored.
type EulaDeployment struct {
	EulaRequired bool `json:"eulaRequired"`
}

// UnmarshalJSON decodes the deployment's setting, as EulaDeployment describes.
func (d *EulaDeployment) UnmarshalJSON(data []byte) error {
	o, err := newObjectReader("eula deployment setting", data)
	if err != nil {
		return err
	}

	var v EulaDeployment

	o.require("eulaRequired", o.decode("eulaRequired", &v.EulaRequired))

	if o.err != nil {
		return o.err
	}

	*d = v

	return nil
}

// objectReader decodes a JSON object a tool sent member by member, so that a rejection names the
// member at fault. Members it decodes are taken out of members, which leaves the others.
type objectReader struct {
	what    string
	members map[string]json.RawMessage
	err     error
}

func newObjectReader(what string, data []byte) (*objectReader, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil || members == nil {
		return nil, NewError(ErrorInvalidRequest, "the "+what+" is not a JSON object", err)
	}

	return &objectReader{what: what, members: members, err: nil}, nil
}

// decode decodes the member name into v, and reports whether it was there and not null. It does
// nothing once the reader has failed.
func (o *objectReader) decode(name string, v any) bool {
	raw, ok := o.members[name]
	delete(o.members, name)

	if !ok || o.err != nil || string(raw) == "null" {
		return false
	}

	if err := json.Unmarshal(raw, v); err != nil {
		o.err = NewError(ErrorInvalidRequest, fmt.Sprintf("the %s's %s is not valid", o.what, name), err)

		return false
	}

	return true
}

// require fails the reader for a member that isn't present, unless it has failed already.
func (o *objectReader) require(name string, present bool) {
	if o.err == nil && !present {
		o.err = NewError(ErrorInvalidRequest, fmt.Sprintf("the %s's %s is missing", o.what, name), nil)
	}
}

// lenientDateTime reads what dateTime reads, and a date and time without a time zone as UTC.
type lenientDateTime time.Time

func (d *lenientDateTime) UnmarshalJSON(data []byte) error {
	var zoned dateTime
	if err := json.Unmarshal(data, &zoned); err == nil {
		*d = lenientDateTime(zoned)

		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("lti: %s is not a date and time", data)
	}

	t, err := time.Parse("2006-01-02T15:04:05.999999999", s)
	if err != nil {
		return fmt.Errorf("lti: %q is not an ISO 8601 date and time", s)
	}

	*d = lenientDateTime(t)

	return nil
}

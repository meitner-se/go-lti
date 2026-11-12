package lti

import (
	"encoding/json"
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

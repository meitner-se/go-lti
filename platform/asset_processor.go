package platform

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
)

// contextRolePrefix starts every context role URI (LTI 1.3 Appendix A.2.3).
const contextRolePrefix = "http://purl.imsglobal.org/vocab/lis/v2/membership"

// checkIdentifier checks that id is set and at most 255 characters.
func checkIdentifier(name, id string) error {
	if id == "" || len(id) > maxIdentifierLength {
		return fmt.Errorf("lti: %s must be set and at most 255 characters", name)
	}

	return nil
}

// deepLinkingActivityClaim checks a Deep Linking request's activity and adds its claim. A request
// that offers ltiAssetProcessor names the activity the processors attach to (Asset Processor
// Content Item).
func deepLinkingActivityClaim(m *lti.DeepLinkingRequest, claims map[string]any) error {
	if m.Activity == nil {
		if slices.Contains(m.Settings.AcceptTypes, lti.ContentItemTypeLTIAssetProcessor) {
			return errors.New("lti: deep linking request that offers ltiAssetProcessor needs an activity")
		}

		return nil
	}

	if err := checkIdentifier("activity id", m.Activity.ID); err != nil {
		return err
	}

	claims[lti.ClaimActivity] = *m.Activity

	return nil
}

// assetProcessorSettingsClaims checks an LtiAssetProcessorSettingsRequest and adds its own claims.
// The settings are for an activity in a context, so it needs both. The context's service claims are
// allowed, but there is no resource to carry an AGS line item.
func assetProcessorSettingsClaims(m *lti.AssetProcessorSettingsRequest, claims map[string]any) error {
	switch {
	case m.Context == nil:
		return errors.New("lti: asset processor settings request needs a context")
	case m.AGSEndpoint != nil && m.AGSEndpoint.LineItem != "":
		return errors.New("lti: asset processor settings request can't carry an ags lineitem url")
	}

	if err := checkIdentifier("activity id", m.Activity.ID); err != nil {
		return err
	}

	claims[lti.ClaimActivity] = m.Activity

	return nil
}

// reportReviewClaims checks an LtiReportReviewRequest and adds its own claims: the activity, the
// asset's owner, the submission, the asset and the report type. It has a context, the activity's,
// and no resource link. The owner's name and email address are sent only when Sharing allows them.
func reportReviewClaims(m *lti.ReportReviewRequest, claims map[string]any) error {
	switch {
	case m.Context == nil:
		return errors.New("lti: report review request needs a context")
	case m.AGSEndpoint != nil && m.AGSEndpoint.LineItem != "":
		return errors.New("lti: report review request can't carry an ags lineitem url")
	case m.AssetReportType == "":
		return errors.New("lti: report review request needs an assetreport_type")
	}

	for _, id := range []struct{ name, value string }{
		{"activity id", m.Activity.ID},
		{"for_user user_id", m.ForUser.UserID},
		{"submission id", m.Submission.ID},
		{"asset id", m.Asset.ID},
	} {
		if err := checkIdentifier(id.name, id.value); err != nil {
			return err
		}
	}

	forUser := m.ForUser
	if !m.Sharing.Name {
		forUser.Name, forUser.GivenName, forUser.FamilyName = "", "", ""
	}

	if !m.Sharing.Email {
		forUser.Email = ""
	}

	claims[lti.ClaimActivity] = m.Activity
	claims[lti.ClaimForUser] = forUser
	claims[lti.ClaimSubmission] = m.Submission
	claims[lti.ClaimAsset] = m.Asset
	claims[lti.ClaimAssetReportType] = m.AssetReportType

	return nil
}

// eulaClaims checks an LtiEulaRequest and adds its eulaservice claim. The EULA is the
// deployment's: the message has no context services, and without a context it has no context
// roles.
func eulaClaims(m *lti.EulaRequest, claims map[string]any) error {
	switch {
	case m.ContextMembershipsURL != "" || m.AGSEndpoint != nil:
		return errors.New("lti: eula request can't carry the context's names and role or ags service")
	case m.Context == nil && slices.ContainsFunc(m.Roles, isContextRole):
		return errors.New("lti: eula request without a context can't carry context roles")
	}

	if err := checkEulaService(m.EulaService); err != nil {
		return err
	}

	claims[lti.ClaimEulaService] = m.EulaService

	return nil
}

func checkEulaService(s lti.EulaService) error {
	if !urlcheck.IsHTTPS(s.URL) {
		return errors.New("lti: eula service url must be an absolute https url")
	}

	if len(s.Scopes) == 0 {
		return errors.New("lti: eula service needs a scope")
	}

	for _, scope := range s.Scopes {
		if scope != lti.ScopeEulaUser && scope != lti.ScopeEulaDeployment {
			return fmt.Errorf("lti: eula service scope %q is not a eula scope", scope)
		}
	}

	return nil
}

func isContextRole(role lti.Role) bool {
	return strings.HasPrefix(string(role), contextRolePrefix)
}

// AssetProcessorSubmission is an LtiAssetProcessorSubmissionNotice: a user submitted assets to an
// activity that has an asset processor attached. Its Notice method lays it out as a Notice for
// Launcher.SignNotice. Send one for each processor attached to the activity, and only to a tool
// that registered a handler for the type; for a group, send one notice, for the member who
// submitted.
type AssetProcessorSubmission struct {
	// DeploymentID, ID and Timestamp are the notice's, as in Notice.
	DeploymentID string
	ID           string
	Timestamp    time.Time
	// Subject is the sub of the user who submitted, if any, such as a teacher submitting for a
	// student. It needs Roles, Subject's roles.
	Subject string
	Roles   []lti.Role
	// Context is the activity's context.
	Context lti.LaunchContext
	// ForUser is the owner of the assets. Its personal data is sent as it is: leave out what the
	// tool may not have.
	ForUser lti.ForUser
	// Activity is the activity the processor is attached to.
	Activity lti.Activity
	// Submission is the submission, new for every resubmission.
	Submission lti.AssetSubmission
	// AssetService lists all the owner's current assets in the activity, not only the new ones: a
	// later notice for the same owner and activity replaces this one for the tool.
	AssetService lti.AssetService
	// AssetReport is where the tool posts its reports for this processor and activity. Without it,
	// the tool can't post any; it may be left out for a processor whose content item had no report.
	AssetReport *lti.AssetReport
	// ContextMembershipsURL and AGSEndpoint send the context's service claims, as a launch in the
	// context would; see Notice.
	ContextMembershipsURL string
	AGSEndpoint           *lti.AGSEndpoint
	// Custom are the processor's custom parameters, from its content item, sent as they are.
	Custom map[string]string
	// Claims are extra claims, such as an extension's. They may not override a claim the notice sets.
	Claims []lti.Claim
}

// Notice returns the submission as a Notice of type LtiAssetProcessorSubmissionNotice, with the
// for_user, activity, submission, assetservice and, when set, assetreport claims. It fails when
// something the notice requires is missing: the context, the owner's user_id, the activity and
// submission ids, roles with a sub, or an asset's id, https url, base64 SHA-256 checksum, timestamp,
// size or content type.
func (s AssetProcessorSubmission) Notice() (Notice, error) {
	if s.Subject != "" && len(s.Roles) == 0 {
		return Notice{}, errors.New("lti: asset processor submission notice with a sub needs its roles")
	}

	for _, id := range []struct{ name, value string }{
		{"context id", s.Context.ID},
		{"for_user user_id", s.ForUser.UserID},
		{"activity id", s.Activity.ID},
		{"submission id", s.Submission.ID},
	} {
		if err := checkIdentifier(id.name, id.value); err != nil {
			return Notice{}, err
		}
	}

	if err := checkAssets(s.AssetService.Assets); err != nil {
		return Notice{}, err
	}

	if s.AssetReport != nil && !urlcheck.IsHTTPS(s.AssetReport.ReportURL) {
		return Notice{}, errors.New("lti: asset report url must be an absolute https url")
	}

	claims := []lti.Claim{s.ForUser, s.Activity, s.Submission, s.AssetService}
	if s.AssetReport != nil {
		claims = append(claims, *s.AssetReport)
	}

	activityContext := s.Context

	return Notice{
		DeploymentID:          s.DeploymentID,
		ID:                    s.ID,
		Type:                  lti.NoticeTypeAssetProcessorSubmission,
		Timestamp:             s.Timestamp,
		Subject:               s.Subject,
		Roles:                 slices.Clone(s.Roles),
		Context:               &activityContext,
		ContextMembershipsURL: s.ContextMembershipsURL,
		AGSEndpoint:           s.AGSEndpoint,
		Custom:                s.Custom,
		Claims:                append(claims, s.Claims...),
	}, nil
}

// checkAssets checks each asset of an assetservice claim, and that no two share an id.
func checkAssets(assets []lti.Asset) error {
	seen := make(map[string]bool, len(assets))

	for i := range assets {
		asset := &assets[i]

		if err := checkIdentifier("asset id", asset.ID); err != nil {
			return err
		}

		if seen[asset.ID] {
			return fmt.Errorf("lti: asset id %q appears more than once", asset.ID)
		}

		seen[asset.ID] = true

		digest, err := base64.StdEncoding.DecodeString(asset.SHA256Checksum)

		switch {
		case !urlcheck.IsHTTPS(asset.URL):
			return errors.New("lti: asset url must be an absolute https url")
		case err != nil || len(digest) != sha256.Size:
			return errors.New("lti: asset sha256_checksum must be a base64-encoded sha-256 digest")
		case asset.Timestamp.IsZero():
			return errors.New("lti: asset needs the timestamp of its upload")
		case asset.Size < 0:
			return errors.New("lti: asset size can't be negative")
		case asset.ContentType == "":
			return errors.New("lti: asset needs a content_type")
		}
	}

	return nil
}

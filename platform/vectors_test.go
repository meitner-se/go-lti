package platform

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type registrationVector struct {
	Description      string          `json:"description"`
	Request          json.RawMessage `json:"request"`
	Valid            bool            `json:"valid"`
	ErrorCode        lti.ErrorCode   `json:"error_code"`
	ErrorDescription string          `json:"error_description"`
	Expect           struct {
		Domains             []string          `json:"domains"`
		RequestsName        bool              `json:"requests_name"`
		RequestsEmail       bool              `json:"requests_email"`
		ClientNames         map[string]string `json:"client_names"`
		OffDomainURIs       []string          `json:"off_domain_uris"`
		PublicSuffixDomains []string          `json:"public_suffix_domains"`
	} `json:"expect"`
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type deepLinkingVector struct {
	Description string `json:"description"`
	Session     struct {
		AcceptTypes    []lti.ContentItemType `json:"accept_types"`
		AcceptMultiple bool                  `json:"accept_multiple"`
		Data           string                `json:"data"`
	} `json:"session"`
	PlatformIssuer   string         `json:"platform_issuer"`
	ClientID         string         `json:"client_id"`
	DeploymentID     string         `json:"deployment_id"`
	Claims           map[string]any `json:"claims"`
	IATOffsetSeconds *int64         `json:"iat_offset_seconds"`
	EXPOffsetSeconds *int64         `json:"exp_offset_seconds"`
	Valid            bool           `json:"valid"`
	Items            int            `json:"items"`
	ErrorCode        lti.ErrorCode  `json:"error_code"`
	ErrorDescription string         `json:"error_description"`
}

func loadVectors[T any](tb testing.TB, kind string) map[string]T {
	tb.Helper()

	fsys := os.DirFS(filepath.Join("..", "testdata", "vectors", kind))

	names, err := fs.Glob(fsys, "*.json")
	require.NoError(tb, err)
	require.NotEmpty(tb, names)

	vectors := map[string]T{}
	for _, name := range names {
		body, err := fs.ReadFile(fsys, name)
		require.NoError(tb, err)

		var v T
		require.NoError(tb, json.Unmarshal(body, &v))

		vectors[name] = v
	}

	return vectors
}

// ============================================================================
// Tests
// ============================================================================

func TestParseRegistration_Vectors(t *testing.T) {
	t.Parallel()

	for name, v := range loadVectors[registrationVector](t, "registration") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reg, err := ParseRegistration(v.Request)
			if !v.Valid {
				requireRegistrationRejection(t, err, v.ErrorCode, v.ErrorDescription)

				return
			}

			require.NoError(t, err, v.Description)

			review := reg.Review(createTestConfig())
			assert.Equal(t, v.Expect.Domains, review.Domains)
			assert.Equal(t, v.Expect.RequestsName, review.RequestsName)
			assert.Equal(t, v.Expect.RequestsEmail, review.RequestsEmail)
			assert.Equal(t, v.Expect.ClientNames, review.ClientNames)
			assert.ElementsMatch(t, v.Expect.OffDomainURIs, review.OffDomainURIs)
			assert.ElementsMatch(t, v.Expect.PublicSuffixDomains, review.PublicSuffixDomains)
		})
	}
}

func TestDeepLinkingVerifier_Verify_Vectors(t *testing.T) {
	t.Parallel()

	tool := ltitest.NewSigningKey(t)
	server := ltitest.NewJWKSServer(t, tool)
	now := time.Now()
	fetcher := newTestFetcher(t, server.Client())

	for name, v := range loadVectors[deepLinkingVector](t, "deep_linking") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := createTestConfig()
			session := DeepLinkingSession{
				Tool:         Tool{ClientID: "client-1", JWKSURI: server.URL, Domains: []string{"tool.example.com"}},
				DeploymentID: "deployment-1",
				Settings: lti.DeepLinkingSettings{
					AcceptTypes:    v.Session.AcceptTypes,
					AcceptMultiple: v.Session.AcceptMultiple,
					Data:           v.Session.Data,
				},
			}

			// A vector taken from the spec carries the spec's own identifiers.
			if v.PlatformIssuer != "" {
				cfg.Issuer = v.PlatformIssuer
				session.Tool.ClientID = v.ClientID
				session.DeploymentID = v.DeploymentID
			}

			verifier, err := NewDeepLinkingVerifier(cfg, fetcher, ltitest.NewNonceStore(t), WithClock(func() time.Time { return now }))
			require.NoError(t, err)

			claims := v.Claims
			if v.IATOffsetSeconds != nil {
				claims["iat"] = now.Unix() + *v.IATOffsetSeconds
			}

			if v.EXPOffsetSeconds != nil {
				claims["exp"] = now.Unix() + *v.EXPOffsetSeconds
			}

			response, err := verifier.Verify(t.Context(), ltitest.Sign(t, tool, claims), session)
			if !v.Valid {
				require.Error(t, err, v.Description)

				rejection, ok := lti.AsError(err)
				require.True(t, ok, v.Description)
				assert.Equal(t, v.ErrorCode, rejection.Code)
				assert.Contains(t, rejection.Description, v.ErrorDescription, "the vector must fail for its own reason")

				return
			}

			require.NoError(t, err, v.Description)
			assert.Len(t, response.Items, v.Items)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type authenticationRequestVector struct {
	Description      string        `json:"description"`
	Form             url.Values    `json:"form"`
	Valid            bool          `json:"valid"`
	ErrorCode        lti.ErrorCode `json:"error_code"`
	ErrorDescription string        `json:"error_description"`
}

func TestParseAuthenticationRequest_Vectors(t *testing.T) {
	t.Parallel()

	for name, v := range loadVectors[authenticationRequestVector](t, "authentication_request") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseAuthenticationRequest(v.Form)
			if v.Valid {
				require.NoError(t, err, v.Description)

				return
			}

			rejection, ok := lti.AsError(err)
			require.True(t, ok, v.Description)
			assert.Equal(t, v.ErrorCode, rejection.Code, v.Description)
			assert.Contains(t, rejection.Description, v.ErrorDescription, "the vector must fail for its own reason")
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type substitutionVector struct {
	Description  string             `json:"description"`
	MessageType  lti.MessageType    `json:"message_type"`
	Subject      string             `json:"sub"`
	Context      *lti.LaunchContext `json:"context"`
	ResourceLink lti.ResourceLink   `json:"resource_link"`
	Locale       string             `json:"locale"`
	User         struct {
		Name       string `json:"name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
		Email      string `json:"email"`
	} `json:"user"`
	Sharing struct {
		Name  bool `json:"name"`
		Email bool `json:"email"`
	} `json:"sharing"`
	Variables    map[lti.Variable]string `json:"variables"`
	Custom       map[string]string       `json:"custom"`
	ExpectCustom map[string]string       `json:"expect_custom"`
}

func TestLauncher_SubstitutesCustom_Vectors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for name, v := range loadVectors[substitutionVector](t, "substitution") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			common := lti.Common{
				DeploymentID: "deployment-1",
				Subject:      v.Subject,
				Context:      v.Context,
				Presentation: lti.Presentation{Locale: v.Locale},
				Custom:       v.Custom,
				Variables:    v.Variables,
				User:         lti.User(v.User),
				Sharing:      lti.Sharing(v.Sharing),
			}

			var msg lti.Message

			switch v.MessageType {
			case lti.MessageTypeResourceLinkRequest:
				msg = &lti.ResourceLinkRequest{Common: common, ResourceLink: v.ResourceLink}
			case lti.MessageTypeDeepLinkingRequest:
				msg = &lti.DeepLinkingRequest{Common: common, Settings: createTestDeepLinkingSettings()}
			default:
				t.Fatalf("unknown message_type %q", v.MessageType)
			}

			claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
			require.NoError(t, err, v.Description)
			assert.Equal(t, v.ExpectCustom, claims[lti.ClaimCustom], v.Description)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type namesRoleServiceVector struct {
	Description           string             `json:"description"`
	MessageType           lti.MessageType    `json:"message_type"`
	Context               *lti.LaunchContext `json:"context"`
	ContextMembershipsURL string             `json:"context_memberships_url"`
	Valid                 bool               `json:"valid"`
	ExpectClaim           json.RawMessage    `json:"expect_claim"`
}

func TestLauncher_NamesRoleService_Vectors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for name, v := range loadVectors[namesRoleServiceVector](t, "names_role_service") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			common := lti.Common{
				DeploymentID:          "deployment-1",
				Subject:               "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
				Context:               v.Context,
				ContextMembershipsURL: v.ContextMembershipsURL,
			}

			var msg lti.Message

			switch v.MessageType {
			case lti.MessageTypeResourceLinkRequest:
				msg = &lti.ResourceLinkRequest{Common: common, ResourceLink: lti.ResourceLink{ID: "link-1"}}
			case lti.MessageTypeDeepLinkingRequest:
				msg = &lti.DeepLinkingRequest{Common: common, Settings: createTestDeepLinkingSettings()}
			default:
				t.Fatalf("unknown message_type %q", v.MessageType)
			}

			claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
			if !v.Valid {
				require.Error(t, err, v.Description)

				return
			}

			require.NoError(t, err, v.Description)

			claim, ok := claims[lti.ClaimNamesRoleService]
			if len(v.ExpectClaim) == 0 || string(v.ExpectClaim) == "null" {
				assert.False(t, ok, v.Description)

				return
			}

			require.True(t, ok, v.Description)

			body, err := json.Marshal(claim)
			require.NoError(t, err)
			assert.JSONEq(t, string(v.ExpectClaim), string(body), v.Description)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type agsEndpointVector struct {
	Description string             `json:"description"`
	MessageType lti.MessageType    `json:"message_type"`
	Context     *lti.LaunchContext `json:"context"`
	AGSEndpoint *lti.AGSEndpoint   `json:"ags_endpoint"`
	Valid       bool               `json:"valid"`
	ExpectClaim json.RawMessage    `json:"expect_claim"`
}

func TestLauncher_AGSEndpoint_Vectors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for name, v := range loadVectors[agsEndpointVector](t, "ags_endpoint") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			common := lti.Common{
				DeploymentID: "deployment-1",
				Subject:      "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
				Context:      v.Context,
				AGSEndpoint:  v.AGSEndpoint,
			}

			var msg lti.Message

			switch v.MessageType {
			case lti.MessageTypeResourceLinkRequest:
				msg = &lti.ResourceLinkRequest{Common: common, ResourceLink: lti.ResourceLink{ID: "link-1"}}
			case lti.MessageTypeDeepLinkingRequest:
				msg = &lti.DeepLinkingRequest{Common: common, Settings: createTestDeepLinkingSettings()}
			default:
				t.Fatalf("unknown message_type %q", v.MessageType)
			}

			claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
			if !v.Valid {
				require.Error(t, err, v.Description)

				return
			}

			require.NoError(t, err, v.Description)

			claim, ok := claims[lti.ClaimAGSEndpoint]
			if len(v.ExpectClaim) == 0 || string(v.ExpectClaim) == "null" {
				assert.False(t, ok, v.Description)

				return
			}

			require.True(t, ok, v.Description)

			body, err := json.Marshal(claim)
			require.NoError(t, err)
			assert.JSONEq(t, string(v.ExpectClaim), string(body), v.Description)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type platformNotificationServiceVector struct {
	Description                 string                           `json:"description"`
	MessageType                 lti.MessageType                  `json:"message_type"`
	PlatformNotificationService *lti.PlatformNotificationService `json:"platform_notification_service"`
	Valid                       bool                             `json:"valid"`
	ExpectClaim                 json.RawMessage                  `json:"expect_claim"`
}

func TestLauncher_PlatformNotificationService_Vectors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for name, v := range loadVectors[platformNotificationServiceVector](t, "platform_notification_service") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			common := lti.Common{
				DeploymentID:                "deployment-1",
				Subject:                     "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
				PlatformNotificationService: v.PlatformNotificationService,
			}

			var msg lti.Message

			switch v.MessageType {
			case lti.MessageTypeResourceLinkRequest:
				msg = &lti.ResourceLinkRequest{Common: common, ResourceLink: lti.ResourceLink{ID: "link-1"}}
			case lti.MessageTypeDeepLinkingRequest:
				msg = &lti.DeepLinkingRequest{Common: common, Settings: createTestDeepLinkingSettings()}
			default:
				t.Fatalf("unknown message_type %q", v.MessageType)
			}

			claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", msg, testNow)
			if !v.Valid {
				require.Error(t, err, v.Description)

				return
			}

			require.NoError(t, err, v.Description)

			claim, ok := claims[lti.ClaimPlatformNotificationService]
			if len(v.ExpectClaim) == 0 || string(v.ExpectClaim) == "null" {
				assert.False(t, ok, v.Description)

				return
			}

			require.True(t, ok, v.Description)

			body, err := json.Marshal(claim)
			require.NoError(t, err)
			assert.JSONEq(t, string(v.ExpectClaim), string(body), v.Description)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type noticeHandlersVector struct {
	Description      string              `json:"description"`
	NoticeTypes      []lti.NoticeType    `json:"notice_types"`
	RedirectURIs     []string            `json:"redirect_uris"`
	Domains          []string            `json:"domains"`
	Scopes           []lti.Scope         `json:"scopes"`
	Registered       []lti.NoticeHandler `json:"registered"`
	Method           string              `json:"method"`
	Body             json.RawMessage     `json:"body"`
	ExpectStatus     int                 `json:"expect_status"`
	ExpectBody       json.RawMessage     `json:"expect_body"`
	ErrorCode        lti.ErrorCode       `json:"error_code"`
	ErrorDescription string              `json:"error_description"`
}

func TestNewHandler_NoticeHandlers_Vectors(t *testing.T) {
	t.Parallel()

	for name, v := range loadVectors[noticeHandlersVector](t, "notice_handlers") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tool := createTestTool()
			tool.RedirectURIs = v.RedirectURIs
			tool.Domains = v.Domains

			s := newNoticeHandlersServer()
			s.tokens["token-vector"] = v.Scopes
			s.deployments["deployment-1"] = &DeploymentNoticeHandlers{Tool: tool, Handlers: v.Registered}

			cfg := createNoticeHandlersTestConfig()
			cfg.NoticeTypes = v.NoticeTypes

			handler, err := NewHandler(cfg, s.handlers())
			require.NoError(t, err)

			w := callAGS(t, handler, v.Method, noticeHandlerURL, "token-vector", string(v.Body))
			require.Equal(t, v.ExpectStatus, w.Code, v.Description+": "+w.Body.String())

			if v.ErrorCode != "" {
				requireAGSError(t, w, v.ExpectStatus, v.ErrorCode, v.ErrorDescription)
				assert.Empty(t, s.registrations, v.Description)

				return
			}

			assert.JSONEq(t, string(v.ExpectBody), w.Body.String(), v.Description)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type registrationVectorGrant struct {
	ClientID     string      `json:"client_id"`
	DeploymentID string      `json:"deployment_id"`
	Scopes       []lti.Scope `json:"scopes"`
	Claims       []string    `json:"claims"`
}

func (g registrationVectorGrant) grant(clientID string) RegistrationGrant {
	return RegistrationGrant{ClientID: clientID, DeploymentID: g.DeploymentID, Scopes: g.Scopes, Claims: g.Claims}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type registrationClientVector struct {
	Description      string                  `json:"description"`
	Scopes           []lti.Scope             `json:"scopes"`
	Registered       json.RawMessage         `json:"registered"`
	Grant            registrationVectorGrant `json:"grant"`
	Method           string                  `json:"method"`
	PathClientID     string                  `json:"path_client_id"`
	Body             json.RawMessage         `json:"body"`
	ExpectStatus     int                     `json:"expect_status"`
	ExpectBody       json.RawMessage         `json:"expect_body"`
	ErrorCode        lti.ErrorCode           `json:"error_code"`
	ErrorDescription string                  `json:"error_description"`
}

func TestNewHandler_RegistrationClient_Vectors(t *testing.T) {
	t.Parallel()

	for name, v := range loadVectors[registrationClientVector](t, "registration_client") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			registered, err := ParseRegistration(v.Registered)
			require.NoError(t, err, v.Description)

			s := newRegistrationClientServer(t)
			s.tokens["token-vector"] = ServiceClient{ClientID: "client-1", Scopes: v.Scopes}
			s.registrations["client-1"] = registered
			s.grants["client-1"] = v.Grant.grant("client-1")

			cfg := createRegistrationClientTestConfig()

			handler, err := NewHandler(cfg, s.handlers())
			require.NoError(t, err)

			target, err := cfg.RegistrationClientURL(v.PathClientID)
			require.NoError(t, err)

			w := callAGS(t, handler, v.Method, target, "token-vector", string(v.Body))
			require.Equal(t, v.ExpectStatus, w.Code, v.Description+": "+w.Body.String())

			if v.ErrorCode != "" {
				requireAGSError(t, w, v.ExpectStatus, v.ErrorCode, v.ErrorDescription)
				assert.Empty(t, s.updates, v.Description)

				return
			}

			assert.JSONEq(t, string(v.ExpectBody), w.Body.String(), v.Description)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type registrationResponseVector struct {
	Description            string                  `json:"description"`
	Request                json.RawMessage         `json:"request"`
	Grant                  registrationVectorGrant `json:"grant"`
	RegistrationClientPath string                  `json:"registration_client_path"`
	ExpectResponse         json.RawMessage         `json:"expect_response"`
}

func TestNewHandler_RegistrationResponse_Vectors(t *testing.T) {
	t.Parallel()

	for name, v := range loadVectors[registrationResponseVector](t, "registration_response") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := createTestConfig()
			h := Handlers{
				Register: func(_ context.Context, _ string, _ *Registration) (RegistrationGrant, error) {
					return v.Grant.grant(v.Grant.ClientID), nil
				},
			}

			if v.RegistrationClientPath != "" {
				cfg.Paths.RegistrationClient = v.RegistrationClientPath
				s := newRegistrationClientServer(t)
				h.AuthorizeService, h.ReadRegistration, h.UpdateRegistration = s.authorize, s.read, s.update
			}

			handler, err := NewHandler(cfg, h)
			require.NoError(t, err)

			w := postRegistration(t, handler, "", string(v.Request))
			require.Equal(t, http.StatusOK, w.Code, v.Description+": "+w.Body.String())
			assert.JSONEq(t, string(v.ExpectResponse), w.Body.String(), v.Description)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type noticeVector struct {
	Description string `json:"description"`
	Notice      struct {
		DeploymentID string             `json:"deployment_id"`
		ID           string             `json:"id"`
		Type         lti.NoticeType     `json:"type"`
		Timestamp    *time.Time         `json:"timestamp"`
		Subject      string             `json:"sub"`
		Context      *lti.LaunchContext `json:"context"`
		Custom       map[string]string  `json:"custom"`
	} `json:"notice"`
	Valid        bool           `json:"valid"`
	ExpectClaims map[string]any `json:"expect_claims"`
}

func TestLauncher_SignNotice_Vectors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for name, v := range loadVectors[noticeVector](t, "notice") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			notice := Notice{
				DeploymentID: v.Notice.DeploymentID,
				ID:           v.Notice.ID,
				Type:         v.Notice.Type,
				Subject:      v.Notice.Subject,
				Context:      v.Notice.Context,
				Custom:       v.Notice.Custom,
			}

			if v.Notice.Timestamp != nil {
				notice.Timestamp = *v.Notice.Timestamp
			}

			claims, err := launcher.noticeClaims(createTestTool(), notice, "nonce-1", testNow)
			if !v.Valid {
				require.Error(t, err, v.Description)

				return
			}

			require.NoError(t, err, v.Description)

			// iat, exp and nonce are new on every signature.
			assert.Equal(t, testNow.Unix(), claims["iat"], v.Description)
			assert.Equal(t, testNow.Add(NoticeTTL).Unix(), claims["exp"], v.Description)
			assert.Equal(t, "nonce-1", claims["nonce"], v.Description)

			delete(claims, "iat")
			delete(claims, "exp")
			delete(claims, "nonce")

			assert.JSONEq(t, string(mustJSON(t, v.ExpectClaims)), claimsJSON(t, claims), v.Description)
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type assetProcessorLaunchVector struct {
	Description string          `json:"description"`
	MessageType lti.MessageType `json:"message_type"`
	Message     struct {
		AcceptTypes           []lti.ContentItemType `json:"accept_types"`
		Context               *lti.LaunchContext    `json:"context"`
		Roles                 []lti.Role            `json:"roles"`
		Sharing               lti.Sharing           `json:"sharing"`
		Custom                map[string]string     `json:"custom"`
		ContextMembershipsURL string                `json:"context_memberships_url"`
		Activity              *lti.Activity         `json:"activity"`
		ForUser               lti.ForUser           `json:"for_user"`
		Submission            lti.AssetSubmission   `json:"submission"`
		Asset                 lti.ReviewedAsset     `json:"asset"`
		AssetReportType       lti.AssetReportType   `json:"assetreport_type"`
		EulaService           lti.EulaService       `json:"eulaservice"`
	} `json:"message"`
	Valid        bool                       `json:"valid"`
	ExpectClaims map[string]json.RawMessage `json:"expect_claims"`
	ExpectAbsent []string                   `json:"expect_absent"`
}

func (v assetProcessorLaunchVector) message(t *testing.T) lti.Message {
	t.Helper()

	m := v.Message
	common := lti.Common{
		DeploymentID:          "deployment-1",
		Subject:               "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
		Roles:                 m.Roles,
		Context:               m.Context,
		Sharing:               lti.Sharing{Name: m.Sharing.Name, Email: m.Sharing.Email},
		Custom:                m.Custom,
		ContextMembershipsURL: m.ContextMembershipsURL,
	}

	switch v.MessageType {
	case lti.MessageTypeDeepLinkingRequest:
		settings := createTestDeepLinkingSettings()
		settings.AcceptTypes = m.AcceptTypes

		return &lti.DeepLinkingRequest{Common: common, Settings: settings, Activity: m.Activity}
	case lti.MessageTypeAssetProcessorSettingsRequest:
		return &lti.AssetProcessorSettingsRequest{Common: common, Activity: derefActivity(m.Activity)}
	case lti.MessageTypeReportReviewRequest:
		return &lti.ReportReviewRequest{
			Common:          common,
			Activity:        derefActivity(m.Activity),
			ForUser:         m.ForUser,
			Submission:      m.Submission,
			Asset:           m.Asset,
			AssetReportType: m.AssetReportType,
		}
	case lti.MessageTypeEulaRequest:
		return &lti.EulaRequest{Common: common, EulaService: m.EulaService}
	default:
		t.Fatalf("unknown message_type %q", v.MessageType)

		return nil
	}
}

func derefActivity(a *lti.Activity) lti.Activity {
	if a == nil {
		return lti.Activity{}
	}

	return *a
}

func TestLauncher_AssetProcessorLaunch_Vectors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for name, v := range loadVectors[assetProcessorLaunchVector](t, "asset_processor_launch") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			claims, err := launcher.idTokenClaims(createTestTool(), "nonce-1", v.message(t), testNow)
			if !v.Valid {
				require.Error(t, err, v.Description)

				return
			}

			require.NoError(t, err, v.Description)

			for claim, expect := range v.ExpectClaims {
				require.Contains(t, claims, claim, v.Description)
				assert.JSONEq(t, string(expect), string(mustJSON(t, claims[claim])), "%s: %s", v.Description, claim)
			}

			for _, claim := range v.ExpectAbsent {
				assert.NotContains(t, claims, claim, v.Description)
			}
		})
	}
}

//nolint:tagliatelle // the vector files are shared with other languages and use snake_case
type assetProcessorSubmissionVector struct {
	Description string `json:"description"`
	Submission  struct {
		DeploymentID string              `json:"deployment_id"`
		ID           string              `json:"id"`
		Timestamp    time.Time           `json:"timestamp"`
		Subject      string              `json:"sub"`
		Roles        []lti.Role          `json:"roles"`
		Context      lti.LaunchContext   `json:"context"`
		ForUser      lti.ForUser         `json:"for_user"`
		Activity     lti.Activity        `json:"activity"`
		Submission   lti.AssetSubmission `json:"submission"`
		Assets       []lti.Asset         `json:"assets"`
		ReportURL    string              `json:"report_url"`
		Custom       map[string]string   `json:"custom"`
	} `json:"submission"`
	Valid        bool           `json:"valid"`
	ExpectClaims map[string]any `json:"expect_claims"`
}

func TestAssetProcessorSubmission_Vectors(t *testing.T) {
	t.Parallel()

	launcher := createTestLauncher(t, ltitest.NewSigningKey(t))

	for name, v := range loadVectors[assetProcessorSubmissionVector](t, "asset_processor_submission") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := v.Submission
			submission := AssetProcessorSubmission{
				DeploymentID: s.DeploymentID,
				ID:           s.ID,
				Timestamp:    s.Timestamp,
				Subject:      s.Subject,
				Roles:        s.Roles,
				Context:      s.Context,
				ForUser:      s.ForUser,
				Activity:     s.Activity,
				Submission:   s.Submission,
				AssetService: lti.AssetService{Assets: s.Assets},
				Custom:       s.Custom,
			}

			if s.ReportURL != "" {
				submission.AssetReport = &lti.AssetReport{ReportURL: s.ReportURL}
			}

			notice, err := submission.Notice()
			if err == nil {
				var claims map[string]any

				claims, err = launcher.noticeClaims(createTestTool(), notice, "nonce-1", testNow)
				if err == nil {
					require.True(t, v.Valid, v.Description)

					delete(claims, "iat")
					delete(claims, "exp")
					delete(claims, "nonce")

					assert.JSONEq(t, string(mustJSON(t, v.ExpectClaims)), claimsJSON(t, claims), v.Description)

					return
				}
			}

			require.False(t, v.Valid, "%s: %v", v.Description, err)
		})
	}
}

package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/meitner-se/go-lti"
)

// maxAuthenticationFormBytes caps a POSTed authentication request; ParseAuthenticationRequest caps
// each parameter at 4 KiB.
const maxAuthenticationFormBytes = 64 << 10

var (
	// errRegistrationTokenMissing answers a registration without a Bearer token when the platform
	// requires one.
	errRegistrationTokenMissing = lti.NewError(lti.ErrorInvalidToken, "the registration token is missing", nil)
	// errRegistrationNotSaved answers a registration Register failed to save for a reason of its own.
	errRegistrationNotSaved = lti.NewError(lti.ErrorServerError, "the registration could not be saved; try again", nil)
	// errMessageHintMissing answers an authentication request without an lti_message_hint, which a
	// platform can't tie to a launch.
	errMessageHintMissing = lti.NewError(lti.ErrorInvalidRequest, "lti_message_hint is missing", nil)
)

// Handlers are the platform's own parts of the endpoints NewHandler serves.
type Handlers struct {
	// Register saves a tool that sent a valid Dynamic Registration and returns what the platform
	// granted it. token is the registration token the tool sent as a Bearer token, or "" when it
	// sent none. An *lti.Error, such as lti.ErrorInvalidToken for a refused token, is sent to the
	// tool as it is; any other error is answered as a server_error that says nothing more. Required.
	Register func(ctx context.Context, token string, reg *Registration) (RegistrationGrant, error)
	// RequireToken refuses a registration without a Bearer token as invalid_token, before Register
	// is called. The spec leaves the token to the platform, so it is off by default.
	RequireToken bool
	// Keys sign the id_tokens of launches and are published at Paths.JWKS. Set Keys and Launch
	// together to serve the authorization and JWKS endpoints.
	Keys lti.Keys
	// Launch returns the launch an authentication request is for. The platform redeems
	// req.MessageHint with its own state, and checks that a session in r, when there is one,
	// belongs to the launch's user (1EdTech Security Framework §5.1.1.3). req always has an
	// lti_message_hint, but may have failed ParseAuthenticationRequest's other checks: the launch
	// tells where that error can be sent.
	//
	// Return a nil *Launch with an error for a hint that can't be redeemed, such as an
	// *lti.Error with lti.ErrorLoginRequired for one that expired or was already used; the browser
	// gets an error page. Return the launch together with an error, such as one for a session that
	// belongs to another user, to send the error to the launch's tool.
	Launch func(r *http.Request, req *AuthenticationRequest) (*Launch, error)
	// ToolKeys resolve the keys tools sign Deep Linking responses with, such as a *jwks.Fetcher.
	// Set ToolKeys, Nonces, FindDeepLinkingSession and HandleDeepLinkingResponse together to serve
	// the Deep Linking return.
	ToolKeys lti.KeySource
	// Nonces reject replayed Deep Linking responses, such as an *lti.MemoryNonceStore.
	Nonces lti.NonceStore
	// FindDeepLinkingSession returns the session a posted Deep Linking response answers, from the
	// platform's own state, such as the request it stored under the data value it sent, or the
	// record behind the browser's session cookie in r. Nothing in unverified has been checked yet,
	// so use it only as a lookup key; data is optional in the spec, so don't rely on it alone.
	//
	// Return an error that is or wraps ErrDeepLinkingSessionNotFound for a request that is unknown,
	// has expired or was already answered; the browser gets a 400 error page. Any other *lti.Error
	// gets an error page with its description and its StatusCode, except a server_error. A
	// server_error, or an error that isn't an *lti.Error, such as the platform's storage being down,
	// gets a 500 error page that says nothing more.
	FindDeepLinkingSession func(r *http.Request, unverified UnverifiedDeepLinkingResponse) (DeepLinkingSession, error)
	// HandleDeepLinkingResponse answers the browser once a session was found: with the verified
	// response, or with the session and Verify's error, so that the platform can record the error
	// and still send the user back to where they started. It writes the response itself; a redirect
	// should carry Cache-Control: no-store, as go-lti's own answers do.
	//
	// Verify only checks what the specs require. A platform with policies of its own, such as
	// items only from the tool's domains (see OnToolDomains), applies them here.
	HandleDeepLinkingResponse func(w http.ResponseWriter, r *http.Request, result DeepLinkingResult)
	// AuthorizeService validates the access token of a request to one of the platform's LTI
	// services, such as Names and Role Provisioning Services, and returns the tool it was issued to
	// with the scopes it was granted. token is the request's Bearer token (RFC 6750 §2.1); a request
	// without one is answered 401 before AuthorizeService is called. scope is the scope the service
	// needs, such as lti.ScopeNRPSMembershipRead: a client whose Scopes don't include it is refused
	// with a 403, so AuthorizeService needn't check it. A read of line items, which
	// lti.ScopeAGSLineItem allows too, gets lti.ScopeAGSLineItemReadOnly, and a read of a
	// registration, which lti.ScopeRegistration allows too, gets lti.ScopeRegistrationReadOnly. Set
	// it with the services that use it, and only then.
	//
	// Return an *lti.Error with lti.ErrorInvalidToken for a token that is unknown, expired or
	// revoked; the tool gets a 401 with RFC 6750 §3's challenge. One with
	// lti.ErrorInsufficientScope, such as for a policy of the platform's own, gets a 403 with the
	// challenge. Any other *lti.Error is sent to the tool with its StatusCode, except a
	// server_error. A server_error, or an error that isn't an *lti.Error, gets a 500 that says
	// nothing more.
	AuthorizeService func(r *http.Request, token string, scope lti.Scope) (ServiceClient, error)
	// ListContextMembers returns a page of the members of req.ContextID, for a tool whose access
	// token was granted lti.ScopeNRPSMembershipRead. Set Paths.ContextMemberships and
	// ListContextMembers together, with AuthorizeService, to serve Names and Role Provisioning
	// Services.
	//
	// Check that client may read the context, such as by having a deployment in it, and return an
	// error that is or wraps ErrContextNotFound for a context that doesn't exist or that client may
	// not read; the tool gets a 404. Any other error is answered as for AuthorizeService.
	ListContextMembers func(r *http.Request, client ServiceClient, req MembershipsRequest) (MembershipsPage, error)
	// ListLineItems, GetLineItem, CreateLineItem, UpdateLineItem, DeleteLineItem, PostScore and
	// ListResults serve Assignment and Grade Services 2.0 for the context in their request. Set
	// Paths.ContextLineItems and all of them together, with AuthorizeService, to serve it.
	//
	// A line item a hook returns has its ID the platform's own id for it, unique in its context,
	// and go-lti answers with Config.LineItemURL as the id; a line item a hook gets has no ID.
	// A line item belongs to one client: the one that created it, or whose link the platform made
	// it for, such as from a Deep Linking lineItem. Every hook, reads included, sees only client's
	// own line items and their results, never another tool's. Check that client may use the
	// context, such as by having a deployment in it, and that the line item is client's, and return
	// an error that is or wraps ErrContextNotFound or ErrLineItemNotFound otherwise; the tool gets
	// a 404. Any other error is answered as for AuthorizeService.
	//
	// ListLineItems returns a page of client's line items in the context, filtered by the request,
	// for a client granted lti.ScopeAGSLineItem or lti.ScopeAGSLineItemReadOnly.
	ListLineItems func(r *http.Request, client ServiceClient, req LineItemsRequest) (LineItemsPage, error)
	// GetLineItem returns one line item, for a client granted lti.ScopeAGSLineItem or
	// lti.ScopeAGSLineItemReadOnly.
	GetLineItem func(r *http.Request, client ServiceClient, req LineItemRequest) (lti.LineItem, error)
	// CreateLineItem saves a new line item in the context and returns it with its ID, for a
	// client granted lti.ScopeAGSLineItem. go-lti has checked that item has a label and a
	// ScoreMaximum greater than 0; check that a ResourceLinkID is one of the client's links.
	CreateLineItem func(r *http.Request, client ServiceClient, contextID string, item lti.LineItem) (lti.LineItem, error)
	// UpdateLineItem replaces a line item with item, checked as for CreateLineItem, and returns it
	// as saved, for a client granted lti.ScopeAGSLineItem.
	UpdateLineItem func(r *http.Request, client ServiceClient, req LineItemRequest, item lti.LineItem) (lti.LineItem, error)
	// DeleteLineItem removes a line item and its results, for a client granted lti.ScopeAGSLineItem.
	DeleteLineItem func(r *http.Request, client ServiceClient, req LineItemRequest) error
	// PostScore saves a user's score for a line item, for a client granted lti.ScopeAGSScore.
	// go-lti has checked that score has a UserID, a Timestamp and known progress values, and a
	// ScoreMaximum greater than 0 with a ScoreGiven of 0 or more. Return an error that is or wraps
	// ErrStaleScore for a score whose Timestamp isn't after the one the platform has for the line
	// item and user; the tool gets a 409.
	PostScore func(r *http.Request, client ServiceClient, req LineItemRequest, score lti.Score) error
	// ListResults returns a page of a line item's results, filtered by the request, for a client
	// granted lti.ScopeAGSResultReadOnly.
	ListResults func(r *http.Request, client ServiceClient, req ResultsRequest) (ResultsPage, error)
	// ReadNoticeHandlers and ReplaceNoticeHandler serve the LTI Platform Notification Service's
	// notice handler endpoint of the deployment with deploymentID, for a client granted
	// lti.ScopeNoticeHandlers. Set Paths.NoticeHandlers and both of them together, with
	// AuthorizeService, to serve it. The handlers are the platform's to keep, per tool and
	// deployment; Config.NoticeTypes are the types a tool may register for.
	//
	// ReadNoticeHandlers returns the deployment's tool and its handlers. Check that client may
	// manage the deployment, such as by its being client's own, and return an error that is or
	// wraps ErrDeploymentNotFound for a deployment that doesn't exist (a 404) or
	// ErrNoticeHandlersForbidden for one client may not manage (a 403). Any other error is answered
	// as for AuthorizeService.
	ReadNoticeHandlers func(r *http.Request, client ServiceClient, deploymentID string) (DeploymentNoticeHandlers, error)
	// ReplaceNoticeHandler saves client's handler for one notice type in the deployment, or removes
	// it when registration.Handler is "". go-lti has checked, with ReadNoticeHandlers, that client
	// may manage the deployment, that the notice type is one of Config.NoticeTypes, that the handler
	// is an https URL on the tool's own domain (see OnToolHosts), and that MaxBatchSize is 0
	// (not given) or positive. Return an *lti.Error with lti.ErrorInvalidRequest for a MaxBatchSize
	// the platform can't honour (a 400), or ErrNoticeHandlersForbidden (a 403). Any other error is
	// answered as for AuthorizeService.
	ReplaceNoticeHandler func(r *http.Request, client ServiceClient, deploymentID string, registration lti.NoticeHandlerRegistration) error
	// ReadRegistration and UpdateRegistration serve the client configuration endpoint of LTI
	// Dynamic Registration 1.0 §4, where a tool reads and updates its own registration. Set
	// Paths.RegistrationClient and both of them together, with AuthorizeService, to serve it. The
	// tool gets its access token from the token endpoint with its client credentials (§4.1), for
	// lti.ScopeRegistrationReadOnly or lti.ScopeRegistration, so there is no registration access
	// token. go-lti has checked that the endpoint in the request's path is client's own, and answers
	// another client's with a 404.
	//
	// Both return client's registration in the registration response's shape, such as
	// Registration.Response of the registration the platform keeps and what it granted; go-lti sets
	// its ClientID, which never changes, and its RegistrationClientURI. Return an error that is or
	// wraps ErrRegistrationNotFound for a client without a Dynamic Registration (a 404), or
	// ErrRegistrationForbidden for one the platform doesn't let manage its registration (a 403). Any
	// other error is answered as for AuthorizeService.
	//
	// ReadRegistration returns client's registration with any pending update applied, for a client
	// granted lti.ScopeRegistrationReadOnly or lti.ScopeRegistration.
	ReadRegistration func(r *http.Request, client ServiceClient) (RegistrationResponse, error)
	// UpdateRegistration submits reg as an update of client's registration, for a client granted
	// lti.ScopeRegistration. go-lti has checked reg with ParseRegistration, and refused a client_id
	// other than client's. The spec asks that an update not apply at once (§4): keep it pending, such
	// as for an admin to review, and return the registration reflecting the pending update, as
	// ReadRegistration will return it. An *lti.Error with lti.ErrorInvalidClientMetadata, such as
	// for a domain the platform won't let the tool change, gets a 400.
	UpdateRegistration func(r *http.Request, client ServiceClient, reg *Registration) (RegistrationResponse, error)
	// GetAsset serves the LTI Asset Service: it returns the asset with assetID, unescaped from the
	// URL's path, for a client granted lti.ScopeAssetReadOnly, as its bytes or where they are (see
	// AssetDownload). Set Paths.Assets and GetAsset together, with AuthorizeService, to serve it.
	// Check that client may download the asset, such as by its being in a submission notice sent to
	// client, and return an error that is or wraps ErrAssetNotFound otherwise (a 404). Any other
	// error is answered as for AuthorizeService.
	GetAsset func(r *http.Request, client ServiceClient, assetID string) (AssetDownload, error)
	// PostReport serves the LTI Asset Report Service: it saves report for the processor with
	// processorID, unescaped from the report URL's path (see Config.AssetReportURL), for a client
	// granted lti.ScopeReport. Set Paths.AssetReports and PostReport together, with
	// AuthorizeService, to serve it. go-lti has decoded the report leniently, as lti.Report
	// describes. A report replaces the one the platform has with the same AssetID and Type when its
	// Timestamp is the same or later; return nil for an earlier one, which may be discarded.
	//
	// Check that the processor is client's, and return an error that is or wraps
	// ErrAssetProcessorNotFound otherwise (a 404). Return an *lti.Error with
	// lti.ErrorInvalidRequest for an AssetID the platform never sent for the processor (a 400). Any
	// other error is answered as for AuthorizeService.
	PostReport func(r *http.Request, client ServiceClient, processorID string, report lti.Report) error
	// RecordEulaAcceptance, ClearEulaAcceptances and SetEulaRequired serve the EULA service of the
	// deployment with deploymentID, unescaped from the URL's path (see Config.EulaServiceURL). Set
	// Paths.Eula and all three together, with AuthorizeService, to serve it. The platform keeps
	// acceptances only to know whether to show the EULA again, so there is nothing to read back.
	// Check that client may use the deployment, such as by its being client's own, and return an
	// error that is or wraps ErrDeploymentNotFound otherwise (a 404). Any other error is answered as
	// for AuthorizeService.
	//
	// RecordEulaAcceptance saves whether a user accepted the EULA, for a client granted
	// lti.ScopeEulaUser. go-lti has checked that acceptance has a UserID and a Timestamp. Ignore an
	// acceptance older than the one the platform has for the user.
	RecordEulaAcceptance func(r *http.Request, client ServiceClient, deploymentID string, acceptance lti.EulaAcceptance) error
	// ClearEulaAcceptances forgets every user's acceptance in the deployment, such as after the
	// EULA changed, for a client granted lti.ScopeEulaUser.
	ClearEulaAcceptances func(r *http.Request, client ServiceClient, deploymentID string) error
	// SetEulaRequired saves whether users in the deployment must accept the EULA, for a client
	// granted lti.ScopeEulaDeployment. A deployment requires it until the tool says otherwise.
	SetEulaRequired func(r *http.Request, client ServiceClient, deploymentID string, required bool) error
	// Logger, when set, logs every error a tool or browser is answered with: a rejection at Warn
	// with its code, any other error at Error.
	Logger *slog.Logger
	// OnError, when set, is called with every error a tool or browser is answered with.
	OnError func(r *http.Request, err error)
}

// NewHandler returns an http.Handler that serves the platform's endpoints at the issuer's path
// plus each endpoint's path, as Config.Endpoints lists them:
//
//   - GET PathOpenIDConfiguration: the OpenID configuration, to any origin, cacheable for five
//     minutes.
//   - POST Paths.Registration: Dynamic Registration (LTI Dynamic Registration 1.0 §3.5–§3.6).
//   - GET and POST Paths.Authorization: the OIDC authentication request of a launch (1EdTech
//     Security Framework §5.1.1.2), answered with a signed id_token. Served with Keys and Launch.
//   - GET Paths.JWKS: the platform's public keys, to any origin, cacheable for five minutes.
//     Served with Keys and Launch.
//   - POST Paths.DeepLinkReturn: the Deep Linking response a tool posts back (Deep Linking 2.0
//     §4.2), verified and handed to HandleDeepLinkingResponse. Served with ToolKeys, Nonces,
//     FindDeepLinkingSession and HandleDeepLinkingResponse.
//   - GET Paths.ContextMemberships plus "/{context}/memberships": a page of the context's members
//     (Names and Role Provisioning Services 2.0 §2.4), from ListContextMembers, for a tool whose
//     access token AuthorizeService finds granted lti.ScopeNRPSMembershipRead. Served with
//     Paths.ContextMemberships and ListContextMembers, which need AuthorizeService.
//   - Paths.ContextLineItems plus "/{context}/lineitems": Assignment and Grade Services 2.0, for a
//     tool whose access token AuthorizeService finds granted the route's scope. GET answers a page
//     of line items and POST creates one; GET, PUT and DELETE "/{lineitem}" read, replace and
//     remove one; POST "/{lineitem}/scores" saves a score and GET "/{lineitem}/results" answers a
//     page of results. Served with Paths.ContextLineItems and the seven line item hooks, which need
//     AuthorizeService.
//   - Paths.NoticeHandlers plus "/{deployment}": the LTI Platform Notification Service, for a tool
//     whose access token AuthorizeService finds granted lti.ScopeNoticeHandlers. GET answers the
//     deployment's notice handlers and PUT replaces the handler of one notice type. Served with
//     Paths.NoticeHandlers, ReadNoticeHandlers and ReplaceNoticeHandler, which need AuthorizeService.
//   - Paths.RegistrationClient plus "/{client_id}": the client configuration endpoint (LTI Dynamic
//     Registration 1.0 §4), for the tool with that client_id. GET answers its registration, for a
//     tool whose access token AuthorizeService finds granted lti.ScopeRegistrationReadOnly or
//     lti.ScopeRegistration, and PUT submits an update of it, for one granted
//     lti.ScopeRegistration. Served with Paths.RegistrationClient, ReadRegistration and
//     UpdateRegistration, which need AuthorizeService. A registration's response then has its
//     registration_client_uri.
//   - GET Paths.Assets plus "/{asset}": the LTI Asset Service, for a tool whose access token
//     AuthorizeService finds granted lti.ScopeAssetReadOnly. It answers with the asset's bytes and
//     its Content-Type, or 302 Found to where GetAsset says they are. Served with Paths.Assets and
//     GetAsset, which need AuthorizeService.
//   - POST Paths.AssetReports plus "/{processor}": the LTI Asset Report Service, for a tool whose
//     access token AuthorizeService finds granted lti.ScopeReport. It decodes one report
//     leniently, hands it to PostReport and answers 200 with the report object the tool sent.
//     Served with Paths.AssetReports and PostReport, which need AuthorizeService.
//   - Paths.Eula plus "/{deployment}": the deployment's EULA service. POST "/user" records a user's
//     acceptance (200, with the acceptance the tool sent) and DELETE "/user" clears every user's
//     (204), for a tool granted lti.ScopeEulaUser; PUT "/deployment" says whether the deployment
//     requires the EULA (200, with the setting the tool sent), for one granted
//     lti.ScopeEulaDeployment. Served with Paths.Eula, RecordEulaAcceptance, ClearEulaAcceptances
//     and SetEulaRequired, which need AuthorizeService.
//
// Mount it to receive every request under the issuer's path, with the path unchanged. Any other
// path is a 404 and any other method a 405. An error page sent to a browser is plain text with
// Cache-Control: no-store and a Content-Security-Policy that allows nothing. It fails when cfg
// can't make an OpenID configuration, h has no Register, h has only one of Keys and Launch, h has
// only some of the Deep Linking fields, only one of Paths.ContextMemberships and ListContextMembers
// is set, only some of Paths.ContextLineItems and the line item hooks are set, only some of
// Paths.NoticeHandlers and the notice handler hooks are set, only some of Paths.RegistrationClient
// and the registration hooks are set, only one of Paths.Assets and GetAsset or of
// Paths.AssetReports and PostReport is set, only some of Paths.Eula and the EULA hooks are set, a
// service is served without
// AuthorizeService, or AuthorizeService is set without any service that uses it.
func NewHandler(cfg Config, h Handlers) (http.Handler, error) {
	if h.Register == nil {
		return nil, errors.New("lti: the handler needs a Register function")
	}

	if (h.Keys == nil) != (h.Launch == nil) {
		return nil, errors.New("lti: the handler needs both Keys and Launch to serve launches, or neither")
	}

	deepLinking := []bool{h.ToolKeys != nil, h.Nonces != nil, h.FindDeepLinkingSession != nil, h.HandleDeepLinkingResponse != nil}
	if slices.Contains(deepLinking, true) && slices.Contains(deepLinking, false) {
		return nil, errors.New("lti: the handler needs all of ToolKeys, Nonces, FindDeepLinkingSession and HandleDeepLinkingResponse to serve the deep linking return, or none")
	}

	if (cfg.Paths.ContextMemberships != "") != (h.ListContextMembers != nil) {
		return nil, errors.New("lti: the handler needs both Paths.ContextMemberships and ListContextMembers to serve context memberships, or neither")
	}

	lineItems := []bool{
		cfg.Paths.ContextLineItems != "", h.ListLineItems != nil, h.GetLineItem != nil, h.CreateLineItem != nil,
		h.UpdateLineItem != nil, h.DeleteLineItem != nil, h.PostScore != nil, h.ListResults != nil,
	}
	if slices.Contains(lineItems, true) && slices.Contains(lineItems, false) {
		return nil, errors.New("lti: the handler needs all of Paths.ContextLineItems, ListLineItems, GetLineItem, CreateLineItem, UpdateLineItem, DeleteLineItem, PostScore and ListResults to serve assignment and grade services, or none")
	}

	noticeHandlers := []bool{cfg.Paths.NoticeHandlers != "", h.ReadNoticeHandlers != nil, h.ReplaceNoticeHandler != nil}
	if slices.Contains(noticeHandlers, true) && slices.Contains(noticeHandlers, false) {
		return nil, errors.New("lti: the handler needs all of Paths.NoticeHandlers, ReadNoticeHandlers and ReplaceNoticeHandler to serve the platform notification service, or none")
	}

	registrationClient := []bool{cfg.Paths.RegistrationClient != "", h.ReadRegistration != nil, h.UpdateRegistration != nil}
	if slices.Contains(registrationClient, true) && slices.Contains(registrationClient, false) {
		return nil, errors.New("lti: the handler needs all of Paths.RegistrationClient, ReadRegistration and UpdateRegistration to serve the client configuration endpoint, or none")
	}

	if (cfg.Paths.Assets != "") != (h.GetAsset != nil) {
		return nil, errors.New("lti: the handler needs both Paths.Assets and GetAsset to serve the asset service, or neither")
	}

	if (cfg.Paths.AssetReports != "") != (h.PostReport != nil) {
		return nil, errors.New("lti: the handler needs both Paths.AssetReports and PostReport to serve the asset report service, or neither")
	}

	eula := []bool{cfg.Paths.Eula != "", h.RecordEulaAcceptance != nil, h.ClearEulaAcceptances != nil, h.SetEulaRequired != nil}
	if slices.Contains(eula, true) && slices.Contains(eula, false) {
		return nil, errors.New("lti: the handler needs all of Paths.Eula, RecordEulaAcceptance, ClearEulaAcceptances and SetEulaRequired to serve the eula service, or none")
	}

	// Each LTI service endpoint the handler serves, all of which AuthorizeService authorizes.
	services := []bool{
		h.ListContextMembers != nil, h.ListLineItems != nil, h.ReadNoticeHandlers != nil, h.ReadRegistration != nil,
		h.GetAsset != nil, h.PostReport != nil, h.RecordEulaAcceptance != nil,
	}
	if slices.Contains(services, true) && h.AuthorizeService == nil {
		return nil, errors.New("lti: the handler needs AuthorizeService to serve LTI services")
	}

	if h.AuthorizeService != nil && !slices.Contains(services, true) {
		return nil, errors.New("lti: the handler has AuthorizeService but serves no LTI service that uses it")
	}

	document, err := cfg.OpenIDConfiguration()
	if err != nil {
		return nil, err
	}

	discovery, err := json.Marshal(document) //nolint:errchkjson // errcheck requires the check outside _test.go files
	if err != nil {
		return nil, err
	}

	issuer, err := url.Parse(strings.TrimSuffix(cfg.Issuer, "/"))
	if err != nil {
		return nil, err
	}

	// A ServeMux pattern gives braces a meaning of their own.
	if strings.ContainsAny(issuer.Path, "{}") {
		return nil, errors.New("lti: the issuer's path must not contain braces")
	}

	e := &endpoints{config: cfg, handlers: h, launcher: nil, verifier: nil}

	mux := http.NewServeMux()
	mux.Handle("GET "+issuer.Path+PathOpenIDConfiguration, openIDConfigurationHandler(discovery))
	mux.HandleFunc("POST "+issuer.Path+cfg.Paths.Registration, e.register)

	if h.Keys != nil {
		e.launcher, err = NewLauncher(cfg, h.Keys)
		if err != nil {
			return nil, err
		}

		mux.HandleFunc("GET "+issuer.Path+cfg.Paths.Authorization, e.authorize)
		mux.HandleFunc("POST "+issuer.Path+cfg.Paths.Authorization, e.authorize)
		mux.HandleFunc("GET "+issuer.Path+cfg.Paths.JWKS, e.jwks)
	}

	if h.ToolKeys != nil {
		e.verifier, err = NewDeepLinkingVerifier(cfg, h.ToolKeys, h.Nonces)
		if err != nil {
			return nil, err
		}

		mux.HandleFunc("POST "+issuer.Path+cfg.Paths.DeepLinkReturn, e.deepLinkReturn)
	}

	if h.ListContextMembers != nil {
		mux.HandleFunc("GET "+issuer.Path+cfg.Paths.ContextMemberships+"/{context}/memberships", e.contextMemberships)
	}

	if h.ListLineItems != nil {
		lineItems := issuer.Path + cfg.Paths.ContextLineItems + "/{context}/lineitems"
		mux.HandleFunc("GET "+lineItems, e.listLineItems)
		mux.HandleFunc("POST "+lineItems, e.createLineItem)
		mux.HandleFunc("GET "+lineItems+"/{lineitem}", e.getLineItem)
		mux.HandleFunc("PUT "+lineItems+"/{lineitem}", e.updateLineItem)
		mux.HandleFunc("DELETE "+lineItems+"/{lineitem}", e.deleteLineItem)
		mux.HandleFunc("POST "+lineItems+"/{lineitem}/scores", e.postScore)
		mux.HandleFunc("GET "+lineItems+"/{lineitem}/results", e.listResults)
	}

	if h.ReadNoticeHandlers != nil {
		noticeHandlers := issuer.Path + cfg.Paths.NoticeHandlers + "/{deployment}"
		mux.HandleFunc("GET "+noticeHandlers, e.noticeHandlers)
		mux.HandleFunc("PUT "+noticeHandlers, e.replaceNoticeHandler)
	}

	if h.ReadRegistration != nil {
		registrationClient := issuer.Path + cfg.Paths.RegistrationClient + "/{client}"
		mux.HandleFunc("GET "+registrationClient, e.readRegistration)
		mux.HandleFunc("PUT "+registrationClient, e.updateRegistration)
	}

	if h.GetAsset != nil {
		mux.HandleFunc("GET "+issuer.Path+cfg.Paths.Assets+"/{asset}", e.getAsset)
	}

	if h.PostReport != nil {
		mux.HandleFunc("POST "+issuer.Path+cfg.Paths.AssetReports+"/{processor}", e.postReport)
	}

	if h.RecordEulaAcceptance != nil {
		eulaService := issuer.Path + cfg.Paths.Eula + "/{deployment}"
		mux.HandleFunc("POST "+eulaService+"/user", e.recordEulaAcceptance)
		mux.HandleFunc("DELETE "+eulaService+"/user", e.clearEulaAcceptances)
		mux.HandleFunc("PUT "+eulaService+"/deployment", e.setEulaRequired)
	}

	return mux, nil
}

func openIDConfigurationHandler(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		header := w.Header()
		header.Set("Cache-Control", "public, max-age=300")
		header.Set("Access-Control-Allow-Origin", "*")
		writeJSON(w, http.StatusOK, body)
	})
}

type endpoints struct {
	config   Config
	handlers Handlers
	launcher *Launcher
	verifier *DeepLinkingVerifier
}

// register answers a POSTed registration. It reads the registration token from the
// Authorization header's Bearer scheme, refuses a body over MaxRegistrationBytes, checks the body
// with ParseRegistration and hands it to Register. A saved registration is answered 200 OK
// with Response(grant), with its registration_client_uri when the handler serves the client
// configuration endpoint; a rejection with RFC 7591 §3.2.2's error response, plus a Bearer
// challenge for invalid_token (RFC 6750 §3). Every answer has Cache-Control: no-store.
//
// OpenID Connect Registration §3.2 says a success SHOULD be 201 Created, so 200 is allowed. Moodle
// and Canvas answer 200, and some tools treat any other status as a failed registration.
func (e *endpoints) register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	// One byte over the cap, so ParseRegistration sees an oversized body and refuses it.
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRegistrationBytes+1))
	if err != nil {
		e.failRegistration(w, r, lti.NewError(lti.ErrorInvalidClientMetadata, "the registration request could not be read", err))

		return
	}

	reg, err := ParseRegistration(body)
	if err != nil {
		e.failRegistration(w, r, err)

		return
	}

	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" && e.handlers.RequireToken {
		e.failRegistration(w, r, errRegistrationTokenMissing)

		return
	}

	grant, err := e.handlers.Register(r.Context(), token, reg)
	if err != nil {
		e.failRegistration(w, r, err)

		return
	}

	response := reg.Response(grant)

	if e.handlers.ReadRegistration != nil {
		response.RegistrationClientURI, err = e.config.RegistrationClientURL(grant.ClientID)
		if err != nil {
			e.failRegistration(w, r, err)

			return
		}
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		e.failRegistration(w, r, err)

		return
	}

	writeJSON(w, http.StatusOK, encoded)
}

// errorResponse is OAuth 2.0's error response (RFC 6749 §5.2), which Dynamic Registration
// (RFC 7591 §3.2.2) and the LTI services answer with.
//
//nolint:tagliatelle // RFC 6749 §5.2 defines snake_case keys
type errorResponse struct {
	Error            lti.ErrorCode `json:"error"`
	ErrorDescription string        `json:"error_description"`
}

func (e *endpoints) failRegistration(w http.ResponseWriter, r *http.Request, err error) {
	e.report(r, err)

	rejection, ok := lti.AsError(err)
	if !ok {
		rejection = errRegistrationNotSaved
	}

	if rejection.Code == lti.ErrorInvalidToken {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}

	writeErrorResponse(w, rejection.StatusCode(), rejection)
}

// writeErrorResponse answers with rejection as OAuth 2.0's error response.
func writeErrorResponse(w http.ResponseWriter, status int, rejection *lti.Error) {
	body, _ := json.Marshal(errorResponse{Error: rejection.Code, ErrorDescription: rejection.Description}) //nolint:errcheck // errchkjson: two strings always encode
	writeJSON(w, status, body)
}

// authorize answers a tool's OIDC authentication request with a form that posts the signed
// id_token to the tool's redirect_uri. A GET carries the request in the query, a POST in the form
// body; a POST's query is ignored, so no parameter can come from both.
//
// Launch runs once for every request with an lti_message_hint, even one that is otherwise
// invalid, so that the error can go to a redirect_uri the launch has registered. An error the tool
// can't be told about gets an error page.
func (e *endpoints) authorize(w http.ResponseWriter, r *http.Request) {
	form, err := authenticationForm(w, r)
	if err != nil {
		e.failLaunch(w, r, nil, nil, unreadableForm(err))

		return
	}

	req, parseErr := ParseAuthenticationRequest(form)
	if req.MessageHint == "" {
		e.failLaunch(w, r, req, nil, cmpErr(parseErr, errMessageHintMissing))

		return
	}

	launch, err := e.handlers.Launch(r, req)
	if launch == nil {
		e.failLaunch(w, r, req, nil, cmpErr(err, errors.New("lti: Launch returned no launch and no error")))

		return
	}

	if err = cmpErr(err, parseErr); err != nil {
		e.failLaunch(w, r, req, &launch.Tool, err)

		return
	}

	response, err := e.launcher.Respond(r.Context(), req, *launch)
	if err != nil {
		e.failLaunch(w, r, req, &launch.Tool, err)

		return
	}

	response.ServeHTTP(w, r)
}

// failLaunch answers a launch that failed at the tool's redirect_uri when tool is known and the
// request's client_id and redirect_uri are registered for it, and with an error page otherwise.
func (e *endpoints) failLaunch(w http.ResponseWriter, r *http.Request, req *AuthenticationRequest, tool *Tool, err error) {
	e.report(r, err)

	if tool != nil {
		if response, ok := e.launcher.RespondError(req, *tool, err); ok {
			response.ServeHTTP(w, r)

			return
		}
	}

	writeErrorPage(w, err, "The launch could not be completed", "Start it again.")
}

// writeErrorPage answers a browser with a plain-text page that says what failed: with a
// rejection's description and status, 413 for a body over its limit, or, for any other error,
// with nothing more than retry and a 500. It can't be cached or load anything.
func writeErrorPage(w http.ResponseWriter, err error, what, retry string) {
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")

	if rejection, ok := lti.AsError(err); ok && rejection.Code != lti.ErrorServerError {
		status := rejection.StatusCode()

		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}

		http.Error(w, fmt.Sprintf("%s: %s.", what, rejection.Description), status)

		return
	}

	http.Error(w, what+". "+retry, http.StatusInternalServerError)
}

// jwks serves the platform's public keys: the current signing key and, during a rotation, the next.
func (e *endpoints) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := e.launcher.JWKS(r.Context())
	if err != nil {
		e.report(r, err)
		http.Error(w, "the keys could not be listed", http.StatusInternalServerError)

		return
	}

	body, err := json.Marshal(set) //nolint:errchkjson // errcheck requires the check outside _test.go files
	if err != nil {
		e.report(r, err)
		http.Error(w, "the keys could not be listed", http.StatusInternalServerError)

		return
	}

	header := w.Header()
	header.Set("Cache-Control", "public, max-age=300")
	header.Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, body)
}

// report hands err to the Logger and OnError.
func (e *endpoints) report(r *http.Request, err error) {
	if logger := e.handlers.Logger; logger != nil {
		if rejection, ok := lti.AsError(err); ok && rejection.Code != lti.ErrorServerError {
			logger.WarnContext(
				r.Context(), "lti request rejected",
				slog.String("path", r.URL.Path),
				slog.String("code", string(rejection.Code)),
				slog.Any("error", err),
			)
		} else {
			logger.ErrorContext(
				r.Context(), "lti request failed",
				slog.String("path", r.URL.Path),
				slog.Any("error", err),
			)
		}
	}

	if e.handlers.OnError != nil {
		e.handlers.OnError(r, err)
	}
}

// authenticationForm reads the authentication request from the query of a GET or the body of a
// POST.
func authenticationForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if r.Method == http.MethodGet {
		return r.URL.Query(), nil
	}

	return postedForm(w, r, maxAuthenticationFormBytes)
}

// postedForm reads the form in the body of a POST of at most limit bytes, ignoring the query.
func postedForm(w http.ResponseWriter, r *http.Request, limit int64) (url.Values, error) {
	// ParseForm also parses the query, so a malformed query would reject a valid body; parse a copy without it.
	bodyOnly := r.Clone(r.Context())
	bodyOnly.URL.RawQuery = ""
	bodyOnly.Body = http.MaxBytesReader(w, r.Body, limit)

	if err := bodyOnly.ParseForm(); err != nil {
		return nil, err
	}

	return bodyOnly.PostForm, nil
}

// unreadableForm rejects a form postedForm couldn't read. A body over its limit keeps the
// *http.MaxBytesError as its cause, which writeErrorPage answers with 413.
func unreadableForm(err error) *lti.Error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return lti.NewError(lti.ErrorInvalidRequest, fmt.Sprintf("the request is larger than %d bytes", tooLarge.Limit), err)
	}

	return lti.NewError(lti.ErrorInvalidRequest, "the request could not be read", err)
}

// cmpErr returns the first of errs that isn't nil.
func cmpErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	return nil
}

// bearerToken returns the token of an Authorization header with the Bearer scheme, whose name is
// case-insensitive (RFC 7235 §2.1), or "" without one.
func bearerToken(header string) string {
	scheme, token, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}

	return strings.TrimSpace(token)
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body) //nolint:errcheck // the response has started; there is nothing left to report a write error to
}

package platform

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
)

// maxAuthenticationParameterBytes caps each authentication request parameter. Hints and nonces
// are opaque, but a tool has no reason to send kilobytes of them.
const maxAuthenticationParameterBytes = 4096

// LoginInitiation is what the platform sends to start a launch: step 1 of the OIDC third-party
// initiated login (LTI 1.3 §4.1, 1EdTech Security Framework §5.1.1.1).
type LoginInitiation struct {
	DeploymentID string
	// LoginHint identifies the user to the platform. It is opaque to the tool and must come back
	// unchanged; Launcher.Respond checks that it does.
	LoginHint string
	// MessageHint is lti_message_hint: opaque, and whatever the platform needs to resume the launch.
	MessageHint string
	// TargetLinkURI defaults to Tool.TargetLinkURI.
	TargetLinkURI string
}

// LoginInitiationURL returns the tool's login initiation URL with iss, login_hint,
// lti_message_hint, target_link_uri, client_id and lti_deployment_id. The platform sends the
// browser there with a redirect. It needs no keys.
func (c Config) LoginInitiationURL(tool Tool, li LoginInitiation) (string, error) {
	u, ok := urlcheck.ParseHTTPS(tool.InitiateLoginURI)
	if !ok {
		return "", errors.New("lti: the tool's initiate_login_uri must be an absolute https url")
	}

	targetLinkURI := li.TargetLinkURI
	if targetLinkURI == "" {
		targetLinkURI = tool.TargetLinkURI
	}

	switch {
	case !urlcheck.IsHTTPS(c.Issuer):
		return "", errors.New("lti: platform issuer must be an absolute https url")
	case tool.ClientID == "":
		return "", errors.New("lti: login initiation needs the tool's client_id")
	case li.LoginHint == "":
		return "", errors.New("lti: login initiation needs a login_hint")
	case li.DeploymentID == "" || len(li.DeploymentID) > maxIdentifierLength:
		return "", errors.New("lti: login initiation needs a deployment_id of at most 255 characters")
	case !urlcheck.IsHTTPS(targetLinkURI):
		return "", errors.New("lti: login initiation target_link_uri must be an absolute https url")
	}

	query := u.Query()
	query.Set("iss", c.Issuer)
	query.Set("login_hint", li.LoginHint)
	query.Set("target_link_uri", targetLinkURI)
	query.Set("client_id", tool.ClientID)
	query.Set("lti_deployment_id", li.DeploymentID)

	if li.MessageHint != "" {
		query.Set("lti_message_hint", li.MessageHint)
	}

	u.RawQuery = query.Encode()

	return u.String(), nil
}

// AuthenticationRequest is the tool's OIDC authentication request to Endpoints.Authorization:
// step 2 of the launch (1EdTech Security Framework §5.1.1.2). Get one from
// ParseAuthenticationRequest: Launcher.Respond refuses a request built any other way, since only
// the parser checks its response_type, response_mode, prompt and scope.
type AuthenticationRequest struct {
	ClientID    string
	RedirectURI string
	LoginHint   string
	MessageHint string
	Nonce       string
	State       string

	parsed bool
}

// ParseAuthenticationRequest reads an authentication request from a GET query or a POST form.
// It requires scope to include openid, response_type=id_token, response_mode=form_post,
// prompt=none, and a client_id, redirect_uri, login_hint and nonce. Each parameter may appear once
// and is at most 4 KiB.
//
// A rejection is an *lti.Error. The request is still returned with what could be read, so that
// Launcher.RespondError can answer the tool at its redirect_uri when that is registered.
func ParseAuthenticationRequest(form url.Values) (*AuthenticationRequest, error) {
	// The descriptions leave out the parameter's name: it is the sender's text, and descriptions are sent back.
	for _, values := range form {
		if len(values) > 1 {
			return partialRequest(form), lti.NewError(lti.ErrorInvalidRequest, "a parameter appears more than once", nil)
		}

		if len(values) == 1 && len(values[0]) > maxAuthenticationParameterBytes {
			return partialRequest(form), lti.NewError(lti.ErrorInvalidRequest, "a parameter is longer than 4 KiB", nil)
		}
	}

	req := partialRequest(form)

	switch {
	case req.ClientID == "":
		return req, lti.NewError(lti.ErrorInvalidRequest, "client_id is missing", nil)
	case req.RedirectURI == "":
		return req, lti.NewError(lti.ErrorInvalidRequest, "redirect_uri is missing", nil)
	case form.Get("response_type") != "id_token":
		return req, lti.NewError(lti.ErrorUnsupportedResponseType, "response_type must be id_token", nil)
	case !slices.Contains(strings.Fields(form.Get("scope")), "openid"):
		return req, lti.NewError(lti.ErrorInvalidScope, "scope must include openid", nil)
	case form.Get("response_mode") != "form_post":
		return req, lti.NewError(lti.ErrorInvalidRequest, "response_mode must be form_post", nil)
	case form.Get("prompt") != "none":
		return req, lti.NewError(lti.ErrorInvalidRequest, "prompt must be none", nil)
	case req.LoginHint == "":
		return req, lti.NewError(lti.ErrorInvalidRequest, "login_hint is missing", nil)
	case req.Nonce == "":
		return req, lti.NewError(lti.ErrorInvalidRequest, "nonce is missing", nil)
	}

	req.parsed = true

	return req, nil
}

func partialRequest(form url.Values) *AuthenticationRequest {
	// A repeated or oversized parameter is left out, so that RespondError never answers a
	// redirect_uri the tool didn't send unambiguously (RFC 6749 §4.2.2.1).
	first := func(name string) string {
		if values := form[name]; len(values) == 1 && len(values[0]) <= maxAuthenticationParameterBytes {
			return values[0]
		}

		return ""
	}

	return &AuthenticationRequest{
		ClientID:    first("client_id"),
		RedirectURI: first("redirect_uri"),
		LoginHint:   first("login_hint"),
		MessageHint: first("lti_message_hint"),
		Nonce:       first("nonce"),
		State:       first("state"),
	}
}

// Launch is what the platform launches the tool with, once it has redeemed the request's hints.
type Launch struct {
	Tool Tool
	// Initiation is the login initiation the platform sent for this launch.
	Initiation LoginInitiation
	// Message is a *lti.ResourceLinkRequest or a *lti.DeepLinkingRequest.
	Message lti.Message
}

// Respond answers an authentication request with a signed id_token: step 3 of the launch.
//
// It checks the request against launch: the client_id must be the tool's, the redirect_uri one of
// the tool's registered redirect URIs, and the login_hint and lti_message_hint the ones the
// platform sent. The message's deployment_id and target_link_uri must be the ones the login
// initiation sent (LTI 1.3 §4.1.2, §5.3.4). It signs the id_token with the request's nonce and
// returns the form that posts it and state to redirect_uri.
//
// The 1EdTech Security Framework (§5.1.1.3) also asks the platform to check that the user logged in
// is the one the login_hint stands for. Respond can't see the session, so do that before calling it.
//
// A mismatch with the request is an *lti.Error; answer it with RespondError. Any other error, such
// as a signer failure, a message that disagrees with its login initiation, or a request that didn't
// come from ParseAuthenticationRequest, is the platform's.
func (l *Launcher) Respond(ctx context.Context, req *AuthenticationRequest, launch Launch) (*FormPost, error) {
	if req == nil || !req.parsed {
		return nil, errors.New("lti: respond needs a request from ParseAuthenticationRequest")
	}

	tool := launch.Tool
	if launch.Initiation.LoginHint == "" || tool.ClientID == "" {
		return nil, errors.New("lti: launch needs the login_hint sent and the tool's client_id")
	}

	if err := checkMatchesInitiation(tool, launch.Initiation, launch.Message); err != nil {
		return nil, err
	}

	if req.ClientID != tool.ClientID {
		return nil, lti.NewError(lti.ErrorUnauthorizedClient, "client_id doesn't match the launch", nil)
	}

	if !slices.Contains(tool.RedirectURIs, req.RedirectURI) {
		return nil, lti.NewError(lti.ErrorInvalidRequest, "redirect_uri is not registered for the tool", nil)
	}

	if subtle.ConstantTimeCompare([]byte(req.LoginHint), []byte(launch.Initiation.LoginHint)) != 1 {
		return nil, lti.NewError(lti.ErrorLoginRequired, "login_hint doesn't match the launch", nil)
	}

	if subtle.ConstantTimeCompare([]byte(req.MessageHint), []byte(launch.Initiation.MessageHint)) != 1 {
		return nil, lti.NewError(lti.ErrorInvalidRequest, "lti_message_hint doesn't match the launch", nil)
	}

	idToken, err := l.idToken(ctx, tool, req.Nonce, launch.Message)
	if err != nil {
		return nil, err
	}

	fields := []FormField{{Name: "id_token", Value: idToken}}
	if req.State != "" {
		fields = append(fields, FormField{Name: "state", Value: req.State})
	}

	return &FormPost{Action: req.RedirectURI, Fields: fields}, nil
}

// checkMatchesInitiation checks that msg launches what li started: the same deployment and the same
// target link URI, each defaulting to the tool's as they do in the URL and the claims.
func checkMatchesInitiation(tool Tool, li LoginInitiation, msg lti.Message) error {
	var common lti.Common

	switch m := msg.(type) {
	case *lti.ResourceLinkRequest:
		if m != nil {
			common = m.Common
		}
	case *lti.DeepLinkingRequest:
		if m != nil {
			common = m.Common
		}
	}

	sentTarget, messageTarget := li.TargetLinkURI, common.TargetLinkURI
	if sentTarget == "" {
		sentTarget = tool.TargetLinkURI
	}

	if messageTarget == "" {
		messageTarget = tool.TargetLinkURI
	}

	switch {
	case common.DeploymentID != li.DeploymentID:
		return errors.New("lti: the message's deployment_id is not the one the login initiation sent")
	case messageTarget != sentTarget:
		return errors.New("lti: the message's target_link_uri is not the one the login initiation sent")
	}

	return nil
}

// RespondError returns the OIDC error response for err (OpenID Connect Core §3.1.2.6), posted to
// the request's redirect_uri. It does so only when the request's client_id is the tool's and its
// redirect_uri is registered for the tool; otherwise ok is false and the platform shows its own
// error page instead, since an unregistered redirect_uri must never receive a response.
//
// An *lti.Error is sent with its code and description. Return an *lti.Error with
// lti.ErrorLoginRequired for a hint that expired or was already used: with prompt=none the platform
// fails rather than asking the user to log in. Any other error is sent as server_error without its
// details.
func (l *Launcher) RespondError(req *AuthenticationRequest, tool Tool, err error) (resp *FormPost, ok bool) {
	if req == nil || req.ClientID == "" || req.ClientID != tool.ClientID || !slices.Contains(tool.RedirectURIs, req.RedirectURI) {
		return nil, false
	}

	code := lti.ErrorServerError
	description := "the platform could not complete the launch"

	if rejection, isRejection := lti.AsError(err); isRejection {
		code = rejection.Code
		description = rejection.Description
	}

	fields := []FormField{{Name: "error", Value: string(code)}, {Name: "error_description", Value: description}}
	if req.State != "" {
		fields = append(fields, FormField{Name: "state", Value: req.State})
	}

	return &FormPost{Action: req.RedirectURI, Fields: fields}, true
}

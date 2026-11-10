package platform

import (
	"errors"
	"net/http"
	"slices"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
)

// ErrDeploymentNotFound is what ReadNoticeHandlers returns, or wraps, for a deployment that doesn't
// exist. The tool gets a 404 with OAuth 2.0's error response.
var ErrDeploymentNotFound = lti.NewError(lti.ErrorInvalidRequest, "the deployment is unknown", nil)

// ErrNoticeHandlersForbidden is what ReadNoticeHandlers or ReplaceNoticeHandler returns, or wraps,
// for a tool that may not read or replace the deployment's notice handlers, such as another tool's
// deployment. The tool gets a 403 with OAuth 2.0's error response.
var ErrNoticeHandlersForbidden = lti.NewError(lti.ErrorAccessDenied, "the tool may not manage this deployment's notice handlers", nil)

var (
	// errNoticeTypeUnsupported refuses a registration for a notice type the platform doesn't send.
	errNoticeTypeUnsupported = lti.NewError(lti.ErrorInvalidRequest, "the platform doesn't support the notice type", nil)
	// errNoticeHandlerURL refuses a handler that isn't an https URL on the tool's own domain.
	errNoticeHandlerURL = lti.NewError(lti.ErrorInvalidRequest, "the handler must be an https url on the tool's own domain", nil)
	// errMaxBatchSize refuses a max_batch_size that isn't a positive integer.
	errMaxBatchSize = lti.NewError(lti.ErrorInvalidRequest, "max_batch_size must be a positive integer", nil)
)

// DeploymentNoticeHandlers are a deployment's notice handlers as the platform keeps them, as
// ReadNoticeHandlers returns them.
type DeploymentNoticeHandlers struct {
	// Tool is the deployment's tool, whose ClientID must be the client's. A handler must be on the
	// host of one of its RedirectURIs or one of its Domains (see OnToolHosts).
	Tool Tool
	// Handlers are the tool's handler for each notice type it registered one for. A type the
	// platform no longer supports is left out of the answer; a type without a handler is answered
	// with "".
	Handlers []lti.NoticeHandler
}

// noticeHandlers answers a tool's GET of its notice handlers for a deployment: every notice type
// the platform supports, in Config.NoticeTypes's order, with "" where the tool has no handler.
func (e *endpoints) noticeHandlers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeNoticeHandlers

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	deploymentID, current, ok := e.readNoticeHandlers(w, r, client)
	if !ok {
		return
	}

	answer := lti.NoticeHandlers{ClientID: client.ClientID, DeploymentID: deploymentID, NoticeHandlers: make([]lti.NoticeHandler, 0, len(e.config.NoticeTypes))}

	for _, noticeType := range e.config.NoticeTypes {
		handler := lti.NoticeHandler{NoticeType: noticeType, Handler: ""}

		if i := slices.IndexFunc(current.Handlers, func(h lti.NoticeHandler) bool { return h.NoticeType == noticeType }); i >= 0 {
			handler.Handler = current.Handlers[i].Handler
		}

		answer.NoticeHandlers = append(answer.NoticeHandlers, handler)
	}

	e.writeService(w, r, scope, http.StatusOK, "application/json", answer)
}

// replaceNoticeHandler answers a tool's PUT of its handler for one notice type in a deployment. It
// checks the registration, hands it to ReplaceNoticeHandler, and answers with the notice type and
// its handler, "" for one the tool removed.
func (e *endpoints) replaceNoticeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeNoticeHandlers

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	var registration lti.NoticeHandlerRegistration
	if err := readServiceBody(w, r, "notice handler", &registration); err != nil {
		if errors.Is(err, lti.ErrMaxBatchSize) {
			err = errMaxBatchSize
		}

		e.failService(w, r, scope, err)

		return
	}

	if !slices.Contains(e.config.NoticeTypes, registration.NoticeType) {
		e.failService(w, r, scope, errNoticeTypeUnsupported)

		return
	}

	deploymentID, current, ok := e.readNoticeHandlers(w, r, client)
	if !ok {
		return
	}

	if registration.Handler != "" && !OnToolHosts(current.Tool, registration.Handler) {
		e.failService(w, r, scope, errNoticeHandlerURL)

		return
	}

	if err := e.handlers.ReplaceNoticeHandler(r, client, deploymentID, registration); err != nil {
		e.failNoticeHandlers(w, r, err)

		return
	}

	e.writeService(w, r, scope, http.StatusOK, "application/json", lti.NoticeHandler{NoticeType: registration.NoticeType, Handler: registration.Handler})
}

// readNoticeHandlers reads the deployment id from the request's path and has ReadNoticeHandlers
// return its handlers. It answers a deployment the tool may not use itself and returns false.
func (e *endpoints) readNoticeHandlers(w http.ResponseWriter, r *http.Request, client ServiceClient) (string, DeploymentNoticeHandlers, bool) {
	deploymentID := r.PathValue("deployment")
	if !isPathSegment(deploymentID) {
		e.failNoticeHandlers(w, r, ErrDeploymentNotFound)

		return "", DeploymentNoticeHandlers{}, false
	}

	current, err := e.handlers.ReadNoticeHandlers(r, client, deploymentID)
	if err == nil && current.Tool.ClientID != client.ClientID {
		// The hook should have refused another tool's deployment; never let it through.
		err = ErrNoticeHandlersForbidden
	}

	if err != nil {
		e.failNoticeHandlers(w, r, err)

		return "", DeploymentNoticeHandlers{}, false
	}

	return deploymentID, current, true
}

// failNoticeHandlers answers ErrDeploymentNotFound with a 404 and ErrNoticeHandlersForbidden with a
// 403, and any other error as failService does.
func (e *endpoints) failNoticeHandlers(w http.ResponseWriter, r *http.Request, err error) {
	for _, answer := range []struct {
		target *lti.Error
		status int
	}{
		{ErrDeploymentNotFound, http.StatusNotFound},
		{ErrNoticeHandlersForbidden, http.StatusForbidden},
	} {
		if errors.Is(err, answer.target) {
			e.report(r, err)
			writeErrorResponse(w, answer.status, answer.target)

			return
		}
	}

	e.failService(w, r, lti.ScopeNoticeHandlers, err)
}

// OnToolHosts reports whether rawURL is an https URL whose host is exactly the host of one of the
// tool's redirect URIs or one of its domains, as a notice handler must be. Subdomains don't count.
func OnToolHosts(tool Tool, rawURL string) bool {
	u, ok := urlcheck.ParseHTTPS(rawURL)
	if !ok {
		return false
	}

	host := urlcheck.NormalizeDomain(u.Hostname())

	hosts := make([]string, 0, len(tool.RedirectURIs)+len(tool.Domains))
	for _, redirectURI := range tool.RedirectURIs {
		if redirect, ok := urlcheck.ParseHTTPS(redirectURI); ok {
			hosts = append(hosts, redirect.Hostname())
		}
	}

	hosts = append(hosts, tool.Domains...)

	return slices.ContainsFunc(hosts, func(toolHost string) bool {
		return toolHost != "" && urlcheck.NormalizeDomain(toolHost) == host
	})
}

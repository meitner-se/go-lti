package platform

import (
	"encoding/json"
	"net/http"

	"github.com/meitner-se/go-lti"
)

// maxReportBytes caps a report a tool posts. The spec sets no limit on a report or its extensions,
// so it is well above what a report needs.
const maxReportBytes = 1 << 20

// ErrAssetProcessorNotFound is what PostReport returns, or wraps, for a report URL whose processor
// doesn't exist or isn't the tool's, such as one detached from its activity. The tool gets a 404
// with OAuth 2.0's error response.
var ErrAssetProcessorNotFound = lti.NewError(lti.ErrorInvalidRequest, "the asset processor is unknown", nil)

// postReport answers a tool's POST of one report to a processor's report URL, for a token granted
// lti.ScopeReport. It decodes the report as lti.Report does, leniently, hands it to PostReport and
// answers 200 with the report object the tool sent.
func (e *endpoints) postReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeReport

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	processorID := r.PathValue("processor")
	if !isPathSegment(processorID) {
		e.failAssetProcessor(w, r, scope, ErrAssetProcessorNotFound)

		return
	}

	body, err := readServiceBytes(w, r, "report", maxReportBytes)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	var report lti.Report
	if err := json.Unmarshal(body, &report); err != nil {
		e.failService(w, r, scope, objectRejection("report", err))

		return
	}

	if err := e.handlers.PostReport(r, client, processorID, report); err != nil {
		e.failAssetProcessor(w, r, scope, err)

		return
	}

	writeJSON(w, http.StatusOK, body)
}

// objectRejection is the rejection of a body that failed to decode: the decoder's own, which names
// the member at fault, or one for a body that isn't JSON at all.
func objectRejection(what string, err error) error {
	if _, ok := lti.AsError(err); ok {
		return err
	}

	return lti.NewError(lti.ErrorInvalidRequest, "the "+what+" is not a JSON object", err)
}

package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/meitner-se/go-lti"
)

// maxServiceBodyBytes caps the body of a line item or score a tool sends.
const maxServiceBodyBytes = 64 << 10

// ErrLineItemNotFound is what a line item hook returns, or wraps, for a line item that doesn't
// exist in the request's context or that the tool may not use. The tool gets a 404 with OAuth 2.0's
// error response. ErrContextNotFound is answered the same way.
var ErrLineItemNotFound = lti.NewError(lti.ErrorInvalidRequest, "the line item is unknown", nil)

// ErrStaleScore is what PostScore returns, or wraps, for a score whose timestamp isn't after the
// one of the score the platform has for the same line item and user (Assignment and Grade Services
// 2.0 §3.4.9). The tool gets a 409 with OAuth 2.0's error response.
var ErrStaleScore = lti.NewError(lti.ErrorInvalidRequest, "a score with the same or a later timestamp was already received", nil)

// LineItemsRequest is a tool's request for a page of a context's line items (Assignment and Grade
// Services 2.0 §3.2.4), as ListLineItems gets it.
type LineItemsRequest struct {
	// ContextID is the context's id, unescaped from the URL's path.
	ContextID string
	// ResourceLinkID, when set, keeps only the line items bound to the resource link with the id a
	// launch sent the tool (resource_link_id).
	ResourceLinkID string
	// ResourceID, when set, keeps only the line items with the tool's resource id (resource_id).
	ResourceID string
	// Tag, when set, keeps only the line items with the tool's tag (tag).
	Tag string
	// Limit is how many line items the tool asks for per page, or 0 when it didn't ask, for the
	// platform's own page size. The platform may send fewer.
	Limit int
	// PageToken is the NextPageToken of the page before, or "" for the first page.
	PageToken string
}

// LineItemsPage is a page of a context's line items, as ListLineItems returns it.
type LineItemsPage struct {
	// LineItems are the page's line items, each with its ID the platform's own id for it in the
	// context. go-lti answers with Config.LineItemURL as the id.
	LineItems []lti.LineItem
	// NextPageToken is what ListLineItems gets back as PageToken to answer with the next page, or ""
	// on the last page. It is opaque to go-lti and the tool.
	NextPageToken string
}

// LineItemRequest names one of a context's line items, unescaped from the URL's path.
type LineItemRequest struct {
	ContextID  string
	LineItemID string
}

// ResultsRequest is a tool's request for a page of a line item's results (Assignment and Grade
// Services 2.0 §3.3.3), as ListResults gets it.
type ResultsRequest struct {
	LineItemRequest

	// UserID, when set, keeps only the user's result (user_id).
	UserID string
	// Limit is how many results the tool asks for per page, or 0 when it didn't ask.
	Limit int
	// PageToken is the NextPageToken of the page before, or "" for the first page.
	PageToken string
}

// ResultsPage is a page of a line item's results, as ListResults returns it.
type ResultsPage struct {
	// Results are the page's results, each with a UserID. go-lti fills in their ID and ScoreOf.
	Results []lti.Result
	// NextPageToken is what ListResults gets back as PageToken to answer with the next page, or ""
	// on the last page. It is opaque to go-lti and the tool.
	NextPageToken string
}

// listLineItems answers with a page of a context's line items, as a line item container. While
// there is a next page, it is linked as rel="next": the request's URL with its filters and the
// next page's token.
func (e *endpoints) listLineItems(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeAGSLineItemReadOnly

	client, ok := e.authorizeService(w, r, scope, lti.ScopeAGSLineItem)
	if !ok {
		return
	}

	query := r.URL.Query()
	req := LineItemsRequest{
		ContextID:      r.PathValue("context"),
		ResourceLinkID: query.Get("resource_link_id"),
		ResourceID:     query.Get("resource_id"),
		Tag:            query.Get("tag"),
		Limit:          0,
		PageToken:      query.Get("page"),
	}

	limit, ok := parseLimit(query.Get("limit"))
	if !ok {
		e.failService(w, r, scope, errLimit)

		return
	}

	req.Limit = limit

	if !isPathSegment(req.ContextID) {
		e.failAGS(w, r, scope, ErrContextNotFound)

		return
	}

	page, err := e.handlers.ListLineItems(r, client, req)
	if err != nil {
		e.failAGS(w, r, scope, err)

		return
	}

	items := make(lti.LineItemContainer, 0, len(page.LineItems))

	for _, item := range page.LineItems {
		item, err = e.lineItemWithURL(req.ContextID, "", item)
		if err != nil {
			e.failService(w, r, scope, err)

			return
		}

		items = append(items, item)
	}

	base, err := e.config.LineItemsURL(req.ContextID)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	params := map[string]string{"resource_link_id": req.ResourceLinkID, "resource_id": req.ResourceID, "tag": req.Tag, "limit": formatLimit(req.Limit)}
	e.writePage(w, r, scope, lti.LineItemContainerMediaType, items, base, params, page.NextPageToken)
}

// createLineItem adds a line item to a context and answers 201 with it, its URL as Location.
func (e *endpoints) createLineItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeAGSLineItem

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	contextID := r.PathValue("context")

	item, err := readLineItem(w, r)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	if !isPathSegment(contextID) {
		e.failAGS(w, r, scope, ErrContextNotFound)

		return
	}

	created, err := e.handlers.CreateLineItem(r, client, contextID, item)
	if err != nil {
		e.failAGS(w, r, scope, err)

		return
	}

	created, err = e.lineItemWithURL(contextID, "", created)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	w.Header().Set("Location", created.ID)
	e.writeService(w, r, scope, http.StatusCreated, lti.LineItemMediaType, created)
}

// getLineItem answers with one of a context's line items.
func (e *endpoints) getLineItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeAGSLineItemReadOnly

	client, ok := e.authorizeService(w, r, scope, lti.ScopeAGSLineItem)
	if !ok {
		return
	}

	req, ok := e.lineItemRequest(w, r, scope)
	if !ok {
		return
	}

	item, err := e.handlers.GetLineItem(r, client, req)
	if err != nil {
		e.failAGS(w, r, scope, err)

		return
	}

	e.writeLineItem(w, r, scope, req, item)
}

// updateLineItem replaces one of a context's line items and answers with it as the platform saved it.
func (e *endpoints) updateLineItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeAGSLineItem

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	item, err := readLineItem(w, r)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	req, ok := e.lineItemRequest(w, r, scope)
	if !ok {
		return
	}

	updated, err := e.handlers.UpdateLineItem(r, client, req, item)
	if err != nil {
		e.failAGS(w, r, scope, err)

		return
	}

	e.writeLineItem(w, r, scope, req, updated)
}

// deleteLineItem removes one of a context's line items, with its results, and answers 204.
func (e *endpoints) deleteLineItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeAGSLineItem

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	req, ok := e.lineItemRequest(w, r, scope)
	if !ok {
		return
	}

	if err := e.handlers.DeleteLineItem(r, client, req); err != nil {
		e.failAGS(w, r, scope, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// postScore hands a user's score for a line item to PostScore and answers 204.
func (e *endpoints) postScore(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeAGSScore

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	var score lti.Score
	if err := readServiceBody(w, r, "score", &score); err != nil {
		e.failService(w, r, scope, err)

		return
	}

	if err := validateScore(score); err != nil {
		e.failService(w, r, scope, err)

		return
	}

	req, ok := e.lineItemRequest(w, r, scope)
	if !ok {
		return
	}

	if err := e.handlers.PostScore(r, client, req, score); err != nil {
		e.failAGS(w, r, scope, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// listResults answers with a page of a line item's results, as a result container, linking the
// next page as listLineItems does.
func (e *endpoints) listResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeAGSResultReadOnly

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	query := r.URL.Query()

	limit, ok := parseLimit(query.Get("limit"))
	if !ok {
		e.failService(w, r, scope, errLimit)

		return
	}

	lineItem, ok := e.lineItemRequest(w, r, scope)
	if !ok {
		return
	}

	req := ResultsRequest{LineItemRequest: lineItem, UserID: query.Get("user_id"), Limit: limit, PageToken: query.Get("page")}

	page, err := e.handlers.ListResults(r, client, req)
	if err != nil {
		e.failAGS(w, r, scope, err)

		return
	}

	lineItemURL, err := e.config.LineItemURL(req.ContextID, req.LineItemID)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	results := make(lti.ResultContainer, 0, len(page.Results))

	for _, result := range page.Results {
		if result.UserID == "" {
			e.failService(w, r, scope, errors.New("lti: ListResults returned a result without a user id"))

			return
		}

		// The results URL filtered to the user is served, so it can be the result's id.
		result.ID = withQuery(lineItemURL+"/results", map[string]string{"user_id": result.UserID})
		result.ScoreOf = lineItemURL
		results = append(results, result)
	}

	params := map[string]string{"user_id": req.UserID, "limit": formatLimit(req.Limit)}
	e.writePage(w, r, scope, lti.ResultContainerMediaType, results, lineItemURL+"/results", params, page.NextPageToken)
}

// lineItemRequest reads the context and line item ids from the request's path. It answers an id no
// URL can carry, such as an escaped ".", with a 404 and returns false.
func (e *endpoints) lineItemRequest(w http.ResponseWriter, r *http.Request, scope lti.Scope) (LineItemRequest, bool) {
	req := LineItemRequest{ContextID: r.PathValue("context"), LineItemID: r.PathValue("lineitem")}
	if !isPathSegment(req.ContextID) || !isPathSegment(req.LineItemID) {
		e.failAGS(w, r, scope, ErrLineItemNotFound)

		return LineItemRequest{}, false
	}

	return req, true
}

// lineItemWithURL returns item with its URL as its ID, made from lineItemID, or from its own ID when
// lineItemID is "".
func (e *endpoints) lineItemWithURL(contextID, lineItemID string, item lti.LineItem) (lti.LineItem, error) {
	if lineItemID == "" {
		lineItemID = item.ID
	}

	if lineItemID == "" {
		return lti.LineItem{}, errors.New("lti: a line item hook returned a line item without an id")
	}

	id, err := e.config.LineItemURL(contextID, lineItemID)
	if err != nil {
		return lti.LineItem{}, err
	}

	item.ID = id

	return item, nil
}

// writeLineItem answers 200 with item, the line item req names.
func (e *endpoints) writeLineItem(w http.ResponseWriter, r *http.Request, scope lti.Scope, req LineItemRequest, item lti.LineItem) {
	item, err := e.lineItemWithURL(req.ContextID, req.LineItemID, item)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	e.writeService(w, r, scope, http.StatusOK, lti.LineItemMediaType, item)
}

// writePage answers 200 with a page of a container, linking the next page while there is one: base
// with params and the next page's token.
func (e *endpoints) writePage(w http.ResponseWriter, r *http.Request, scope lti.Scope, mediaType string, container any, base string, params map[string]string, nextPageToken string) {
	if nextPageToken != "" {
		params["page"] = nextPageToken
		if err := addLinks(w.Header(), "page", []headerLink{{withQuery(base, params), "next"}}); err != nil {
			e.failService(w, r, scope, err)

			return
		}
	}

	e.writeService(w, r, scope, http.StatusOK, mediaType, container)
}

// writeService answers with v as JSON of mediaType.
func (e *endpoints) writeService(w http.ResponseWriter, r *http.Request, scope lti.Scope, status int, mediaType string, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.Header().Del("Link")
		w.Header().Del("Location")
		e.failService(w, r, scope, err)

		return
	}

	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(status)
	_, _ = w.Write(body) //nolint:errcheck // the response has started; there is nothing left to report a write error to
}

// failAGS answers ErrLineItemNotFound and ErrContextNotFound with a 404 and ErrStaleScore with a
// 409, and any other error as failService does.
func (e *endpoints) failAGS(w http.ResponseWriter, r *http.Request, scope lti.Scope, err error) {
	for _, answer := range []struct {
		target *lti.Error
		status int
	}{
		{ErrLineItemNotFound, http.StatusNotFound},
		{ErrContextNotFound, http.StatusNotFound},
		{ErrStaleScore, http.StatusConflict},
	} {
		if errors.Is(err, answer.target) {
			e.report(r, err)
			writeErrorResponse(w, answer.status, answer.target)

			return
		}
	}

	e.failService(w, r, scope, err)
}

// readLineItem reads and checks the line item a tool sent, with its ID cleared: the URL names it.
func readLineItem(w http.ResponseWriter, r *http.Request) (lti.LineItem, error) {
	var item lti.LineItem
	if err := readServiceBody(w, r, "line item", &item); err != nil {
		return lti.LineItem{}, err
	}

	switch {
	case strings.TrimSpace(item.Label) == "":
		return lti.LineItem{}, lti.NewError(lti.ErrorInvalidRequest, "the line item's label is missing", nil)
	case item.ScoreMaximum <= 0:
		return lti.LineItem{}, lti.NewError(lti.ErrorInvalidRequest, "the line item's scoreMaximum must be greater than 0", nil)
	case item.StartDateTime != nil && item.EndDateTime != nil && item.EndDateTime.Before(*item.StartDateTime):
		return lti.LineItem{}, lti.NewError(lti.ErrorInvalidRequest, "the line item's endDateTime is before its startDateTime", nil)
	}

	item.ID = ""

	return item, nil
}

// readServiceBody decodes a JSON body of at most maxServiceBodyBytes into v. what names it.
func readServiceBody(w http.ResponseWriter, r *http.Request, what string, v any) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxServiceBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return lti.NewError(lti.ErrorInvalidRequest, fmt.Sprintf("the %s is larger than %d bytes", what, tooLarge.Limit), err)
		}

		return lti.NewError(lti.ErrorInvalidRequest, "the "+what+" could not be read", err)
	}

	if err := json.Unmarshal(body, v); err != nil {
		return lti.NewError(lti.ErrorInvalidRequest, "the "+what+" is not valid JSON of its media type", err)
	}

	return nil
}

var (
	activityProgresses = []lti.ActivityProgress{
		lti.ActivityProgressInitialized, lti.ActivityProgressStarted, lti.ActivityProgressInProgress,
		lti.ActivityProgressSubmitted, lti.ActivityProgressCompleted,
	}
	gradingProgresses = []lti.GradingProgress{
		lti.GradingProgressFullyGraded, lti.GradingProgressPending, lti.GradingProgressPendingManual,
		lti.GradingProgressFailed, lti.GradingProgressNotReady,
	}
)

// validateScore checks what Assignment and Grade Services 2.0 §3.4 requires of a score.
func validateScore(s lti.Score) error {
	var problem string

	switch {
	case strings.TrimSpace(s.UserID) == "":
		problem = "the score's userId is missing"
	case s.Timestamp.IsZero():
		// A missing timestamp decodes to the zero time, but it is required to order updates (§3.4.9).
		problem = "the score's timestamp is missing"
	case !slices.Contains(activityProgresses, s.ActivityProgress):
		problem = "the score's activityProgress is missing or unknown"
	case !slices.Contains(gradingProgresses, s.GradingProgress):
		problem = "the score's gradingProgress is missing or unknown"
	case s.ScoreGiven != nil && *s.ScoreGiven < 0:
		problem = "the score's scoreGiven must be 0 or more"
	case s.ScoreGiven != nil && s.ScoreMaximum <= 0, s.ScoreMaximum < 0:
		// A scoreGiven needs a scoreMaximum as its denominator (§3.4.5).
		problem = "the score's scoreMaximum must be greater than 0"
	default:
		return nil
	}

	return lti.NewError(lti.ErrorInvalidRequest, problem, nil)
}

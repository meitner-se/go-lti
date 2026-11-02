package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
)

// ErrContextNotFound is what ListContextMembers returns, or wraps, for a context that doesn't
// exist or that the tool may not read. The tool gets a 404 with OAuth 2.0's error response.
var ErrContextNotFound = lti.NewError(lti.ErrorInvalidRequest, "the context is unknown", nil)

// errMembershipsLimit answers a memberships request whose limit isn't a positive integer.
var errMembershipsLimit = lti.NewError(lti.ErrorInvalidRequest, "limit must be a positive integer", nil)

// MembershipsRequest is a tool's request for a page of a context's members (Names and Role
// Provisioning Services 2.0 §2.4.1), as ListContextMembers gets it.
type MembershipsRequest struct {
	// ContextID is the context's id, unescaped from the URL's path.
	ContextID string
	// Role, when set, keeps only the members with the role, as the tool sent it: a full role URI
	// or, for a context role, its short name such as "Learner".
	Role lti.Role
	// Limit is how many members the tool asks for per page, or 0 when it didn't ask, for the
	// platform's own page size. The platform may send fewer.
	Limit int
	// PageToken is the NextPageToken of the page before, or "" for the first page.
	PageToken string
	// ResourceLinkID, when set, keeps only the members who can access the resource link with the id
	// a launch sent the tool (NRPS 2.0 §3).
	ResourceLinkID string
}

// MembershipsPage is a page of a context's members, as ListContextMembers returns it.
type MembershipsPage struct {
	// Context is the context the members belong to. An empty ID is the request's ContextID.
	Context lti.MembershipContext
	// Members are the page's members.
	Members []lti.Member
	// NextPageToken is what ListContextMembers gets back as PageToken to answer with the next
	// page, or "" on the last page. It is opaque to go-lti and the tool, and sent to the tool in
	// the next page's URL.
	NextPageToken string
}

// MembershipLinks are the Link headers of a membership container answer (Names and Role
// Provisioning Services 2.0 §2.4.2, §2.4.3). An empty URL is left out. Each URL is opaque to the
// tool and must be an absolute https URL without spaces or angle brackets.
type MembershipLinks struct {
	// Next is the next page of members, linked as rel="next". Empty on the last page, which tells
	// the tool it has every member.
	Next string
	// Differences is the changes since this answer, linked as rel="differences". Empty when the
	// platform offers none.
	Differences string
}

// AddMembershipLinks adds links to h as Link headers. On an error nothing is added.
func AddMembershipLinks(h http.Header, links MembershipLinks) error {
	rels := []struct{ url, rel string }{{links.Next, "next"}, {links.Differences, "differences"}}

	for _, link := range rels {
		if link.url != "" && (!urlcheck.IsHTTPS(link.url) || strings.ContainsAny(link.url, "<> ")) {
			return fmt.Errorf("lti: membership %s link must be an absolute https url without spaces or angle brackets", link.rel)
		}
	}

	for _, link := range rels {
		if link.url != "" {
			h.Add("Link", "<"+link.url+`>; rel="`+link.rel+`"`)
		}
	}

	return nil
}

// contextMemberships answers a tool's request for a context's members with a page of them, as a
// membership container whose id is the request's URL: Config.ContextMembershipsURL plus the
// request's role, limit, rlid and page parameters. While there is a next page, it is linked as
// rel="next" with the same URL and the next page's token. Every answer has Cache-Control: no-store.
func (e *endpoints) contextMemberships(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeNRPSMembershipRead

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	query := r.URL.Query()
	req := MembershipsRequest{
		ContextID:      r.PathValue("context"),
		Role:           lti.Role(query.Get("role")),
		Limit:          0,
		PageToken:      query.Get("page"),
		ResourceLinkID: query.Get("rlid"),
	}

	if limit := query.Get("limit"); limit != "" {
		n, err := strconv.Atoi(limit)
		if err != nil || n < 1 {
			e.failService(w, r, scope, errMembershipsLimit)

			return
		}

		req.Limit = n
	}

	page, err := e.handlers.ListContextMembers(r, client, req)
	if errors.Is(err, ErrContextNotFound) {
		e.report(r, err)
		writeErrorResponse(w, http.StatusNotFound, ErrContextNotFound)

		return
	}

	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	if page.Context.ID == "" {
		page.Context.ID = req.ContextID
	}

	body, err := e.encodeMembershipsPage(w.Header(), req, page)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	w.Header().Set("Content-Type", lti.MembershipContainerMediaType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) //nolint:errcheck // the response has started; there is nothing left to report a write error to
}

// encodeMembershipsPage links page's next page in h and returns its membership container.
func (e *endpoints) encodeMembershipsPage(h http.Header, req MembershipsRequest, page MembershipsPage) ([]byte, error) {
	base, err := e.config.ContextMembershipsURL(req.ContextID)
	if err != nil {
		return nil, err
	}

	// A page's URL keeps the request's filters, so that every page lists the same members.
	pageURL := func(token string) string {
		query := url.Values{}

		for name, value := range map[string]string{"role": string(req.Role), "rlid": req.ResourceLinkID, "page": token} {
			if value != "" {
				query.Set(name, value)
			}
		}

		if req.Limit > 0 {
			query.Set("limit", strconv.Itoa(req.Limit))
		}

		if len(query) == 0 {
			return base
		}

		return base + "?" + query.Encode()
	}

	var links MembershipLinks
	if page.NextPageToken != "" {
		links.Next = pageURL(page.NextPageToken)
	}

	body, err := json.Marshal(lti.MembershipContainer{ID: pageURL(req.PageToken), Context: page.Context, Members: page.Members})
	if err != nil {
		return nil, err
	}

	if err := AddMembershipLinks(h, links); err != nil {
		return nil, err
	}

	return body, nil
}

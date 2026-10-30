package platform

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/meitner-se/go-lti/internal/urlcheck"
)

// AddMembershipLinks adds the Link headers of a membership container answer to h (Names and Role
// Provisioning Services 2.0 §2.4.2, §2.4.3): rel="next" for the next page of members, and
// rel="differences" for the changes since this answer. An empty URL is left out; no next link tells
// the tool it has every member. Each URL must be an absolute https URL, opaque to the tool, without
// spaces or angle brackets. On an error nothing is added.
func AddMembershipLinks(h http.Header, next, differences string) error {
	links := []struct{ url, rel string }{{next, "next"}, {differences, "differences"}}

	for _, link := range links {
		if link.url != "" && (!urlcheck.IsHTTPS(link.url) || strings.ContainsAny(link.url, "<> ")) {
			return fmt.Errorf("lti: membership %s link must be an absolute https url without spaces or angle brackets", link.rel)
		}
	}

	for _, link := range links {
		if link.url != "" {
			h.Add("Link", "<"+link.url+`>; rel="`+link.rel+`"`)
		}
	}

	return nil
}

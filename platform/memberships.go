package platform

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/meitner-se/go-lti/internal/urlcheck"
)

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

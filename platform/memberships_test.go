package platform

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Tests
// ============================================================================

func TestAddMembershipLinks(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	require.NoError(t, AddMembershipLinks(h, MembershipLinks{
		Next:        "https://platform.example.com/lti/memberships?page=2",
		Differences: "https://platform.example.com/lti/memberships?since=abc",
	}))

	assert.Equal(t, []string{
		`<https://platform.example.com/lti/memberships?page=2>; rel="next"`,
		`<https://platform.example.com/lti/memberships?since=abc>; rel="differences"`,
	}, h.Values("Link"))
}

func TestAddMembershipLinks_LeavesOutEmptyURLs(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	require.NoError(t, AddMembershipLinks(h, MembershipLinks{}))
	assert.Empty(t, h.Values("Link"), "the last page has no next link")

	require.NoError(t, AddMembershipLinks(h, MembershipLinks{Next: "https://platform.example.com/lti/memberships?page=2"}))
	assert.Equal(t, []string{`<https://platform.example.com/lti/memberships?page=2>; rel="next"`}, h.Values("Link"))
}

func TestAddMembershipLinks_Rejects(t *testing.T) {
	t.Parallel()

	for _, link := range []string{
		"http://platform.example.com/lti/memberships?page=2",
		"/lti/memberships?page=2",
		"https://platform.example.com/lti/memberships?page=2>; rel=\"differences\"",
		"https://platform.example.com/lti/memberships?page=<2>",
		"https://platform.example.com/lti/memberships?page= 2",
		"https://platform.example.com/lti/memberships?page=2\r\nSet-Cookie: a=b",
	} {
		h := http.Header{}
		require.Error(t, AddMembershipLinks(h, MembershipLinks{Next: link}), link)
		require.Error(t, AddMembershipLinks(h, MembershipLinks{
			Next:        "https://platform.example.com/lti/memberships?page=2",
			Differences: link,
		}), link)
		assert.Empty(t, h.Values("Link"), "nothing is added on an error")
	}
}

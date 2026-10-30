package lti

import "encoding/json"

// MembershipContainerMediaType is the media type of a membership container (Names and Role
// Provisioning Services 2.0 §2.1): the Content-Type the platform answers with, and the Accept header
// a tool asks with.
const MembershipContainerMediaType = "application/vnd.ims.lti-nrps.v2.membershipcontainer+json"

// MembershipContainer is a context's members, as the platform's Names and Role Provisioning
// Services endpoint answers with them (NRPS 2.0 §2). A page of the members is a container too; the
// platform links the next one with a Link header.
type MembershipContainer struct {
	// ID is the URL the container was read from, such as the context_memberships_url with its query.
	ID      string            `json:"id"`
	Context MembershipContext `json:"context"`
	// Members are the context's members. None is sent as an empty array.
	Members []Member `json:"members"`
}

// MarshalJSON encodes the container, with no members as an empty array.
func (c MembershipContainer) MarshalJSON() ([]byte, error) {
	type container MembershipContainer

	if c.Members == nil {
		c.Members = []Member{}
	}

	return json.Marshal(container(c))
}

// MembershipContext is the context a membership container lists the members of (NRPS 2.0 §2.2).
type MembershipContext struct {
	// ID is the context's id, the same as in a launch's context claim.
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	Title string `json:"title,omitempty"`
}

// Member is one user's membership of the context (NRPS 2.0 §2.2). Only UserID and Roles are
// required. The other fields are personal data, which the platform sends only when the tool may
// have it, as with Sharing in a launch; empty ones are left out.
//
//nolint:tagliatelle // NRPS 2.0 §2 defines snake_case keys
type Member struct {
	// Status is Active, Inactive or, only in a differences answer, Deleted (§2.3). Empty is left out,
	// which a tool reads as Active.
	Status MembershipStatus `json:"status,omitempty"`
	// UserID is the user's sub in launches to the same tool.
	UserID string `json:"user_id"`
	// Roles are the user's roles in the context. None is sent as an empty array.
	Roles      []Role `json:"roles"`
	Name       string `json:"name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	MiddleName string `json:"middle_name,omitempty"`
	Email      string `json:"email,omitempty"`
	// Picture is the URL of the user's picture.
	Picture string `json:"picture,omitempty"`
	// LISPersonSourcedID is the user's id in the institution's student information system.
	LISPersonSourcedID string `json:"lis_person_sourcedid,omitempty"`
}

// MarshalJSON encodes the member, with no roles as an empty array.
func (m Member) MarshalJSON() ([]byte, error) {
	type member Member

	if m.Roles == nil {
		m.Roles = []Role{}
	}

	return json.Marshal(member(m))
}

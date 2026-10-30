package lti_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
)

// ============================================================================
// Tests
// ============================================================================

func TestMembershipContainer_MarshalJSON(t *testing.T) {
	t.Parallel()

	container := lti.MembershipContainer{
		ID:      "https://platform.example.com/lti/contexts/course-1/memberships?limit=2",
		Context: lti.MembershipContext{ID: "course-1", Label: "BIO1", Title: "Biology 1"},
		Members: []lti.Member{
			{
				Status:             lti.MembershipStatusActive,
				UserID:             "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
				Roles:              []lti.Role{lti.RoleInstructor},
				Name:               "Ada Lovelace",
				GivenName:          "Ada",
				FamilyName:         "Lovelace",
				MiddleName:         "Augusta",
				Email:              "ada@example.com",
				Picture:            "https://platform.example.com/pictures/ada.png",
				LISPersonSourcedID: "sis-42",
			},
			{UserID: "8b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e", Roles: []lti.Role{lti.RoleLearner}},
		},
	}

	body, err := json.Marshal(container)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"id": "https://platform.example.com/lti/contexts/course-1/memberships?limit=2",
		"context": {"id": "course-1", "label": "BIO1", "title": "Biology 1"},
		"members": [
			{
				"status": "Active",
				"user_id": "3f2a8c1e-7d4b-4e8f-9a6c-1b2d3e4f5a6b",
				"roles": ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
				"name": "Ada Lovelace",
				"given_name": "Ada",
				"family_name": "Lovelace",
				"middle_name": "Augusta",
				"email": "ada@example.com",
				"picture": "https://platform.example.com/pictures/ada.png",
				"lis_person_sourcedid": "sis-42"
			},
			{
				"user_id": "8b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
				"roles": ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"]
			}
		]
	}`, string(body))

	var decoded lti.MembershipContainer
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, container, decoded)
}

func TestMembershipContainer_MarshalJSON_SendsRequiredMembersWhenEmpty(t *testing.T) {
	t.Parallel()

	// NRPS 2.0 §2.2: members, and each member's user_id and roles, are required.
	body, err := json.Marshal(lti.MembershipContainer{ID: "https://platform.example.com/lti/memberships", Context: lti.MembershipContext{ID: "course-1"}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"id": "https://platform.example.com/lti/memberships", "context": {"id": "course-1"}, "members": []}`, string(body))

	body, err = json.Marshal(lti.Member{UserID: "user-1"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"user_id": "user-1", "roles": []}`, string(body))
}

func TestMembershipContainerMediaType(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "application/vnd.ims.lti-nrps.v2.membershipcontainer+json", lti.MembershipContainerMediaType)
}

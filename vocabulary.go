package lti

import (
	"fmt"
	"strings"
)

// MessageType is an LTI message type.
type MessageType string

// Message types. The platform side of this package sends and accepts the first three; the others
// are named so a registration review can recognise them.
const (
	MessageTypeResourceLinkRequest MessageType = "LtiResourceLinkRequest"
	MessageTypeDeepLinkingRequest  MessageType = "LtiDeepLinkingRequest"
	MessageTypeDeepLinkingResponse MessageType = "LtiDeepLinkingResponse"
	MessageTypeSubmissionReview    MessageType = "LtiSubmissionReviewRequest"
	MessageTypeReportReviewRequest MessageType = "LtiReportReviewRequest"
	MessageTypeEulaRequest         MessageType = "LtiEulaRequest"
)

// Role is a role URI from LTI 1.3 Appendix A.2.
type Role string

// Context roles (LTI 1.3 Appendix A.2.3).
const (
	RoleAdministrator     Role = "http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator"
	RoleContentDeveloper  Role = "http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper"
	RoleInstructor        Role = "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"
	RoleLearner           Role = "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"
	RoleMentor            Role = "http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor"
	RoleManager           Role = "http://purl.imsglobal.org/vocab/lis/v2/membership#Manager"
	RoleMember            Role = "http://purl.imsglobal.org/vocab/lis/v2/membership#Member"
	RoleOfficer           Role = "http://purl.imsglobal.org/vocab/lis/v2/membership#Officer"
	RoleTeachingAssistant Role = "http://purl.imsglobal.org/vocab/lis/v2/membership/Instructor#TeachingAssistant"
)

// Institution roles (LTI 1.3 Appendix A.2.2).
const (
	RoleInstitutionAdministrator      Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator"
	RoleInstitutionFaculty            Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Faculty"
	RoleInstitutionGuest              Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Guest"
	RoleInstitutionNone               Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#None"
	RoleInstitutionOther              Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Other"
	RoleInstitutionStaff              Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Staff"
	RoleInstitutionStudent            Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student"
	RoleInstitutionAlumni             Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Alumni"
	RoleInstitutionInstructor         Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor"
	RoleInstitutionLearner            Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Learner"
	RoleInstitutionMember             Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Member"
	RoleInstitutionMentor             Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Mentor"
	RoleInstitutionObserver           Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Observer"
	RoleInstitutionProspectiveStudent Role = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#ProspectiveStudent"
)

// System roles (LTI 1.3 Appendix A.2.1).
const (
	RoleSystemAdministrator Role = "http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator"
	RoleSystemNone          Role = "http://purl.imsglobal.org/vocab/lis/v2/system/person#None"
	RoleSystemAccountAdmin  Role = "http://purl.imsglobal.org/vocab/lis/v2/system/person#AccountAdmin"
	RoleSystemCreator       Role = "http://purl.imsglobal.org/vocab/lis/v2/system/person#Creator"
	RoleSystemSysAdmin      Role = "http://purl.imsglobal.org/vocab/lis/v2/system/person#SysAdmin"
	RoleSystemSysSupport    Role = "http://purl.imsglobal.org/vocab/lis/v2/system/person#SysSupport"
	RoleSystemUser          Role = "http://purl.imsglobal.org/vocab/lis/v2/system/person#User"
)

// ContextType is a context type URI from LTI 1.3 Appendix A.1.
type ContextType string

// Context types.
const (
	ContextTypeCourseTemplate ContextType = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseTemplate"
	ContextTypeCourseOffering ContextType = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseOffering"
	ContextTypeCourseSection  ContextType = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseSection"
	ContextTypeGroup          ContextType = "http://purl.imsglobal.org/vocab/lis/v2/course#Group"
)

// MembershipStatus is a member's status in a membership container (Names and Role Provisioning
// Services 2.0 §2.3).
type MembershipStatus string

// Membership statuses.
const (
	MembershipStatusActive   MembershipStatus = "Active"
	MembershipStatusInactive MembershipStatus = "Inactive"
	// MembershipStatusDeleted is for an answer to a differences link only.
	MembershipStatusDeleted MembershipStatus = "Deleted"
)

// DocumentTarget says how the platform shows the tool or a content item. The two specs that use it
// allow different values: a launch's document_target is frame, iframe or window (LTI 1.3 §5.4.4),
// and Deep Linking's accept_presentation_document_targets are embed, iframe or window (LTI Deep
// Linking 2.0 §4.4.1, §4.6.2).
type DocumentTarget string

// Document targets.
const (
	// DocumentTargetEmbed is for Deep Linking settings only.
	DocumentTargetEmbed DocumentTarget = "embed"
	// DocumentTargetFrame is for a launch's presentation only.
	DocumentTargetFrame  DocumentTarget = "frame"
	DocumentTargetIframe DocumentTarget = "iframe"
	DocumentTargetWindow DocumentTarget = "window"
)

// ContentItemType is a Deep Linking content item type (LTI Deep Linking 2.0 §3).
type ContentItemType string

// Content item types.
const (
	ContentItemTypeLTIResourceLink ContentItemType = "ltiResourceLink"
	ContentItemTypeLink            ContentItemType = "link"
	ContentItemTypeFile            ContentItemType = "file"
	ContentItemTypeHTML            ContentItemType = "html"
	ContentItemTypeImage           ContentItemType = "image"
)

// ParseDocumentTarget returns the DocumentTarget s names, or an error when it is none of them. It
// accepts the values of both specs; a launch refuses embed and Deep Linking settings refuse frame.
func ParseDocumentTarget(s string) (DocumentTarget, error) {
	switch target := DocumentTarget(s); target {
	case DocumentTargetEmbed, DocumentTargetFrame, DocumentTargetIframe, DocumentTargetWindow:
		return target, nil
	default:
		return "", fmt.Errorf("lti: unknown document target %q", s)
	}
}

// ParseContentItemType returns the ContentItemType s names, or an error when it is none of the
// types Deep Linking 2.0 §3 defines.
func ParseContentItemType(s string) (ContentItemType, error) {
	switch itemType := ContentItemType(s); itemType {
	case ContentItemTypeLTIResourceLink, ContentItemTypeLink, ContentItemTypeFile, ContentItemTypeHTML, ContentItemTypeImage:
		return itemType, nil
	default:
		return "", fmt.Errorf("lti: unknown content item type %q", s)
	}
}

// Scope is an LTI service scope.
type Scope string

// Assignment and Grade Services 2.0 and Names and Role Provisioning Services 2.0 scopes.
const (
	ScopeAGSLineItem         Scope = "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"
	ScopeAGSLineItemReadOnly Scope = "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly"
	ScopeAGSResultReadOnly   Scope = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
	ScopeAGSScore            Scope = "https://purl.imsglobal.org/spec/lti-ags/scope/score"
	ScopeNRPSMembershipRead  Scope = "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
)

// Variable is a substitution variable for custom parameter values (LTI 1.3 Appendix B),
// written without its "$".
type Variable string

// Substitution variables.
const (
	VariableUserID                  Variable = "User.id"
	VariableUserUsername            Variable = "User.username"
	VariablePersonNameFull          Variable = "Person.name.full"
	VariablePersonNameGiven         Variable = "Person.name.given"
	VariablePersonNameFamily        Variable = "Person.name.family"
	VariablePersonEmailPrimary      Variable = "Person.email.primary"
	VariableContextID               Variable = "Context.id"
	VariableContextTitle            Variable = "Context.title"
	VariableContextLabel            Variable = "Context.label"
	VariableResourceLinkID          Variable = "ResourceLink.id"
	VariableResourceLinkTitle       Variable = "ResourceLink.title"
	VariableResourceLinkDescription Variable = "ResourceLink.description"
	VariableMessageLocale           Variable = "Message.locale"
)

// Substitute returns custom with each value that is exactly "$<Variable>" replaced by that
// variable's value in values (LTI 1.3 §5.4.6, Appendix B). Values that name a variable missing from
// values, or that only contain one, stay as they are, as the spec requires for variables the
// platform doesn't support; put a supported variable that has no value in values as "".
//
// A launch already substitutes Common.Custom; Substitute is for custom parameters sent elsewhere.
//
// A variable about the user that sharing doesn't allow is replaced by "", so the tool learns nothing
// about the user and still sees a supported variable: Person.name.* and User.username need Name,
// Person.email.* needs Email, and the other Person.* variables are always "", since Sharing has no
// setting for them. Such a variable missing from values still stays as it is.
func Substitute(custom map[string]string, values map[Variable]string, sharing Sharing) map[string]string {
	if custom == nil {
		return nil
	}

	out := make(map[string]string, len(custom))
	for name, value := range custom {
		if variable, ok := strings.CutPrefix(value, "$"); ok {
			if substituted, ok := values[Variable(variable)]; ok {
				value = substituted
				if !sharing.allows(Variable(variable)) {
					value = ""
				}
			}
		}

		out[name] = value
	}

	return out
}

// allows reports whether sharing lets the tool have variable's value.
func (s Sharing) allows(variable Variable) bool {
	switch {
	case strings.HasPrefix(string(variable), "Person.name.") || variable == VariableUserUsername:
		return s.Name
	case strings.HasPrefix(string(variable), "Person.email."):
		return s.Email
	case strings.HasPrefix(string(variable), "Person."):
		return false
	default:
		return true
	}
}

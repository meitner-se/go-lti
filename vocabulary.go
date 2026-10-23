package lti

import "strings"

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

// DocumentTarget says how the platform shows the tool (LTI 1.3 §5.4.4).
type DocumentTarget string

// Document targets.
const (
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
// variable's value in values. Values that name a variable missing from values, or that only
// contain one, stay as they are, as LTI 1.3 requires for variables the platform doesn't support.
func Substitute(custom map[string]string, values map[Variable]string) map[string]string {
	if custom == nil {
		return nil
	}

	out := make(map[string]string, len(custom))
	for name, value := range custom {
		if variable, ok := strings.CutPrefix(value, "$"); ok {
			if substituted, ok := values[Variable(variable)]; ok {
				value = substituted
			}
		}

		out[name] = value
	}

	return out
}

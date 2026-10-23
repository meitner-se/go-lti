package lti

import "encoding/json"

// Claim names from LTI 1.3 §5 and LTI Deep Linking 2.0 §4.
const (
	ClaimMessageType         = "https://purl.imsglobal.org/spec/lti/claim/message_type"
	ClaimVersion             = "https://purl.imsglobal.org/spec/lti/claim/version"
	ClaimDeploymentID        = "https://purl.imsglobal.org/spec/lti/claim/deployment_id"
	ClaimTargetLinkURI       = "https://purl.imsglobal.org/spec/lti/claim/target_link_uri"
	ClaimRoles               = "https://purl.imsglobal.org/spec/lti/claim/roles"
	ClaimContext             = "https://purl.imsglobal.org/spec/lti/claim/context"
	ClaimResourceLink        = "https://purl.imsglobal.org/spec/lti/claim/resource_link"
	ClaimLaunchPresentation  = "https://purl.imsglobal.org/spec/lti/claim/launch_presentation"
	ClaimToolPlatform        = "https://purl.imsglobal.org/spec/lti/claim/tool_platform"
	ClaimCustom              = "https://purl.imsglobal.org/spec/lti/claim/custom"
	ClaimDeepLinkingSettings = "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings"
	ClaimDeepLinkingData     = "https://purl.imsglobal.org/spec/lti-dl/claim/data"
	ClaimContentItems        = "https://purl.imsglobal.org/spec/lti-dl/claim/content_items"
	ClaimDeepLinkingMessage  = "https://purl.imsglobal.org/spec/lti-dl/claim/msg"
	ClaimDeepLinkingLog      = "https://purl.imsglobal.org/spec/lti-dl/claim/log"
	ClaimDeepLinkingErrorMsg = "https://purl.imsglobal.org/spec/lti-dl/claim/errormsg"
	ClaimDeepLinkingErrorLog = "https://purl.imsglobal.org/spec/lti-dl/claim/errorlog"
)

// Message is a message the platform launches a tool with: *ResourceLinkRequest or
// *DeepLinkingRequest. Other packages can't implement it.
type Message interface {
	MessageType() MessageType
	isMessage()
}

// ResourceLinkRequest launches a resource link (LTI 1.3 §5.1).
type ResourceLinkRequest struct {
	Common

	ResourceLink ResourceLink
}

// MessageType returns LtiResourceLinkRequest.
func (*ResourceLinkRequest) MessageType() MessageType { return MessageTypeResourceLinkRequest }

func (*ResourceLinkRequest) isMessage() {}

// DeepLinkingRequest asks the tool for content to place (LTI Deep Linking 2.0 §4.4).
type DeepLinkingRequest struct {
	Common

	Settings DeepLinkingSettings
}

// MessageType returns LtiDeepLinkingRequest.
func (*DeepLinkingRequest) MessageType() MessageType { return MessageTypeDeepLinkingRequest }

func (*DeepLinkingRequest) isMessage() {}

// Common is what every launch message says. The caller decides each value, such as which roles a
// placement maps to; the package only checks it against the spec and lays it out as claims.
type Common struct {
	// DeploymentID is the deployment the launch happens in. At most 255 characters.
	DeploymentID string
	// Subject is the user's sub: opaque and stable for the tool, never a name or an email address.
	// At most 255 characters.
	Subject string
	// TargetLinkURI is where the tool should take the user. It defaults to Tool.TargetLinkURI.
	TargetLinkURI string
	// Roles are the user's roles. An empty list is an anonymous launch.
	Roles []Role
	// Context is the course or group the launch happens in, if any.
	Context *LaunchContext
	// Presentation is how the platform shows the tool.
	Presentation Presentation
	// Custom are the custom parameters of the link or tool, already substituted.
	Custom map[string]string
	// User is the user's name and email address. Only what Sharing allows is sent.
	User User
	// Sharing is what the platform may share with this tool. The zero value shares nothing.
	Sharing Sharing
	// Extensions are extra claims, such as a service's endpoint claim. They may not override a
	// claim the package sets.
	Extensions []Claim
}

// Claim is an extra claim. Its value is the Claim itself, marshalled as JSON under ClaimName.
type Claim interface {
	ClaimName() string
}

// LaunchContext is the context claim (LTI 1.3 §5.4.1).
type LaunchContext struct {
	// ID is the context's id. At most 255 characters.
	ID    string        `json:"id"`
	Label string        `json:"label,omitempty"`
	Title string        `json:"title,omitempty"`
	Types []ContextType `json:"type,omitempty"`
}

// ResourceLink is the resource_link claim (LTI 1.3 §5.3.5).
type ResourceLink struct {
	// ID is the link's id, stable for the placement. At most 255 characters.
	ID          string `json:"id"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

// Presentation is the launch_presentation claim (LTI 1.3 §5.4.4).
//
//nolint:tagliatelle // LTI 1.3 §5.4.4 defines snake_case keys
type Presentation struct {
	DocumentTarget DocumentTarget `json:"document_target,omitempty"`
	Width          int            `json:"width,omitempty"`
	Height         int            `json:"height,omitempty"`
	ReturnURL      string         `json:"return_url,omitempty"`
	Locale         string         `json:"locale,omitempty"`
}

// User is the user's personal data that a tool may be allowed to receive.
type User struct {
	Name       string
	GivenName  string
	FamilyName string
	Email      string
}

// Sharing is which personal claims the platform may send a tool.
type Sharing struct {
	// Name allows name, given_name and family_name.
	Name bool
	// Email allows email.
	Email bool
}

// DeepLinkingSettings is what the platform asks the tool for (LTI Deep Linking 2.0 §4.4.1).
// The same value checks the tool's response.
type DeepLinkingSettings struct {
	// ReturnURL is where the tool posts its response. It defaults to Endpoints.DeepLinkReturn.
	ReturnURL string
	// AcceptTypes are the content item types the platform can place.
	AcceptTypes []ContentItemType
	// AcceptPresentationDocumentTargets are the document targets the platform can show items in.
	AcceptPresentationDocumentTargets []DocumentTarget
	// AcceptMediaTypes are MIME types for file items, such as "image/*".
	AcceptMediaTypes []string
	// AcceptMultiple allows the tool to return more than one item.
	AcceptMultiple bool
	// AcceptLineItem says the platform creates a line item for items that ask for one.
	AcceptLineItem bool
	// AutoCreate says the platform saves the items without asking the user again.
	AutoCreate bool
	// Title and Text are a default title and text the tool may use for the items.
	Title string
	Text  string
	// Data is opaque to the tool and must come back unchanged in the response.
	Data string
}

// DeepLinkingResponseField is the form field a tool posts its Deep Linking response in.
const DeepLinkingResponseField = "JWT"

// DeepLinkingResponse is a verified LtiDeepLinkingResponse (LTI Deep Linking 2.0 §4.5).
type DeepLinkingResponse struct {
	// Items are the content items the user picked. None means the user cancelled.
	Items []ContentItem
	// Message and ErrorMessage are for the user; Log and ErrorLog for logs.
	Message      string
	Log          string
	ErrorMessage string
	ErrorLog     string
}

// ContentItem is one item in a Deep Linking response (LTI Deep Linking 2.0 §3).
// Fields that don't apply to the item's type are empty.
type ContentItem struct {
	Type      ContentItemType   `json:"type"`
	Title     string            `json:"title,omitempty"`
	Text      string            `json:"text,omitempty"`
	URL       string            `json:"url,omitempty"`
	Icon      *Image            `json:"icon,omitempty"`
	Thumbnail *Image            `json:"thumbnail,omitempty"`
	Window    *Window           `json:"window,omitempty"`
	Iframe    *Iframe           `json:"iframe,omitempty"`
	Custom    map[string]string `json:"custom,omitempty"`
	// MediaType is the MIME type of a file item.
	MediaType string `json:"mediaType,omitempty"`
	// HTML is the markup of an html item, exactly as the tool sent it. Sanitize it before showing it.
	HTML string `json:"html,omitempty"`
	// LineItem is the line item an ltiResourceLink asks the platform to create, as the tool sent it.
	LineItem json.RawMessage `json:"lineItem,omitempty"`
	// Raw is the whole item as the tool sent it, for properties this struct doesn't model.
	Raw json.RawMessage `json:"-"`
}

// Image is an icon or thumbnail of a content item.
type Image struct {
	URL    string `json:"url"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
}

// Window is how a content item asks to be opened in a new window.
type Window struct {
	TargetName     string `json:"targetName,omitempty"`
	Width          int    `json:"width,omitempty"`
	Height         int    `json:"height,omitempty"`
	WindowFeatures string `json:"windowFeatures,omitempty"`
}

// Iframe is how a content item asks to be embedded.
type Iframe struct {
	Src    string `json:"src,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
}

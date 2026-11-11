// Package lti holds the types that both sides of LTI 1.3 share: messages and their claims, content
// items, the spec's vocabulary, signing keys and errors.
//
// MembershipContainer and Member are what a platform answers a Names and Role Provisioning
// Services 2.0 request with; Common.ContextMembershipsURL sends a tool the URL to ask at.
//
// LineItem, Score and Result are the bodies of Assignment and Grade Services 2.0;
// Common.AGSEndpoint sends a tool the endpoint claim with its URLs and scopes.
//
// NoticeHandlers and NoticeHandlerRegistration are the bodies of the LTI Platform Notification
// Service's registration endpoint, Notice is the notice claim of a notice JWT and NoticeEnvelope is
// what the platform posts to a handler; Common.PlatformNotificationService sends a tool the claim.
//
// Activity, ForUser, AssetSubmission, ReviewedAsset, AssetReportType, AssetService, AssetReport and
// EulaService are the claims of LTI Asset Processor. AssetProcessorSettingsRequest,
// ReportReviewRequest and EulaRequest are its launches, and ContentItemTypeLTIAssetProcessor its
// Deep Linking item, whose ContentItem.Report says where report reviews go.
//
// The platform side (its configuration, its record of each tool, launches, Deep Linking
// verification, Dynamic Registration and its client configuration endpoint, the OpenID
// configuration, the Names and Role Provisioning
// Services endpoint, the Assignment and Grade Services endpoints, and the Platform Notification
// Service endpoint and notices, and the Asset Processor submission notice) lives in package platform.
// Package jwks publishes and fetches keys, safehttp fetches tool-controlled URLs safely, and
// ltitest has test doubles.
//
// go-lti does no I/O except fetching a tool's keys. It has no storage or cookies; the caller passes
// plain values and implements Keys, KeySource and NonceStore. ParseKeysPEM and NewDevelopmentKeys
// make Keys from a PEM key or a generated one, jwks.Fetcher is a KeySource, and MemoryNonceStore is
// a NonceStore for a platform with a single replica. ParseContentItemType and ParseDocumentTarget
// read the vocabulary back from strings a platform stored. Where the spec leaves a choice to the
// platform, such as what sub is or which roles a user has, go-lti takes the value and never makes
// the choice.
package lti

// Package lti holds the types that both sides of LTI 1.3 share: messages and their claims, content
// items, the spec's vocabulary, signing keys and errors.
//
// MembershipContainer and Member are what a platform answers a Names and Role Provisioning
// Services 2.0 request with; Common.ContextMembershipsURL sends a tool the URL to ask at.
//
// The platform side (its configuration, its record of each tool, launches, Deep Linking
// verification, Dynamic Registration, the OpenID configuration and the membership service's Link
// headers) lives in package platform.
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

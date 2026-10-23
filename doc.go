// Package lti holds the types that both sides of LTI 1.3 share: messages and their claims, content
// items, the spec's vocabulary, signing keys and errors.
//
// The platform side (its configuration, its record of each tool, launches, Deep Linking
// verification, Dynamic Registration and the OpenID configuration) lives in package platform.
// Package jwks publishes and fetches keys, safehttp fetches tool-controlled URLs safely, and
// ltitest has test doubles.
//
// go-lti does no I/O except fetching a tool's keys. It has no routes, storage or cookies; the
// caller passes plain values and implements Keys, KeySource and NonceStore. Where the spec leaves
// a choice to the platform, such as what sub is or which roles a user has, go-lti takes the value
// and never makes the choice.
package lti

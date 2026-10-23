package lti

import (
	"errors"
	"fmt"
	"net/http"
)

// Version is the LTI version of every message this package sends and accepts.
const Version = "1.3.0"

// ErrorCode is an error code from OAuth 2.0 (RFC 6749 §4.2.2.1, §5.2), OpenID Connect Core §3.1.2.6,
// Dynamic Client Registration (RFC 7591 §3.2.2) or Bearer tokens (RFC 6750 §3.1).
type ErrorCode string

// Error codes the platform answers with.
const (
	ErrorInvalidRequest          ErrorCode = "invalid_request"
	ErrorUnauthorizedClient      ErrorCode = "unauthorized_client"
	ErrorUnsupportedResponseType ErrorCode = "unsupported_response_type"
	ErrorLoginRequired           ErrorCode = "login_required"
	ErrorInvalidClient           ErrorCode = "invalid_client"
	ErrorInvalidScope            ErrorCode = "invalid_scope"
	ErrorInvalidGrant            ErrorCode = "invalid_grant"
	ErrorInvalidClientMetadata   ErrorCode = "invalid_client_metadata"
	ErrorInvalidRedirectURI      ErrorCode = "invalid_redirect_uri"
	ErrorInvalidToken            ErrorCode = "invalid_token"
)

// Error is a rejection of something a tool or a browser sent. Description is safe to send back.
// Any other error from this module is the platform's own, such as a signer or fetch failure,
// and is a 500 or 502.
type Error struct {
	Code        ErrorCode
	Description string

	cause error
}

// NewError returns an Error. cause, which may be nil, is kept for logs and errors.Is, and is
// never part of Description.
func NewError(code ErrorCode, description string, cause error) *Error {
	return &Error{Code: code, Description: description, cause: cause}
}

// Error returns the code, the description and the cause.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("lti: %s: %s: %v", e.Code, e.Description, e.cause)
	}

	return fmt.Sprintf("lti: %s: %s", e.Code, e.Description)
}

// StatusCode returns the HTTP status to answer with: 401 for invalid_client and invalid_token,
// 400 otherwise.
func (e *Error) StatusCode() int {
	switch e.Code {
	case ErrorInvalidClient, ErrorInvalidToken:
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

// Unwrap returns the cause.
func (e *Error) Unwrap() error {
	return e.cause
}

// AsError returns err as an *Error when it is or wraps one.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)

	return e, ok
}

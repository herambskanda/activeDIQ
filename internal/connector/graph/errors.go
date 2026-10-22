package graph

import (
	"errors"
	"fmt"
	"time"
)

// Code is a connector error code (connector-contract.md §7). Callers classify on Code only.
type Code string

const (
	CodeUnreachable      Code = "UNREACHABLE_DC"
	CodeTransportSec     Code = "TRANSPORT_SECURITY"
	CodeBindFailed       Code = "BIND_FAILED"
	CodeInsufficient     Code = "INSUFFICIENT_RIGHTS"
	CodeNotFound         Code = "OBJECT_NOT_FOUND"
	CodeThrottled        Code = "THROTTLED"
	CodeIdentityMismatch Code = "DIRECTORY_IDENTITY_MISMATCH"
	CodeInvalidArgument  Code = "INVALID_ARGUMENT"
	CodeLimitExceeded    Code = "LIMIT_EXCEEDED"
	CodeProviderFailure  Code = "PROVIDER_FAILURE"
)

// Error is the only error type a Client read returns (besides context cancellation). Message never
// carries tokens, assertions, response bodies or attribute values.
type Error struct {
	Code       Code
	Message    string
	HTTPStatus int           // provider result code, diagnosis only
	RetryAfter time.Duration // THROTTLED only
	cause      error
}

func (e *Error) Error() string {
	if e.HTTPStatus != 0 {
		return fmt.Sprintf("graph: %s: %s (http %d)", e.Code, e.Message, e.HTTPStatus)
	}
	return fmt.Sprintf("graph: %s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.cause }

func newErr(c Code, status int, msg string, cause error) *Error {
	return &Error{Code: c, Message: msg, HTTPStatus: status, cause: cause}
}

// CodeOf returns the Code of err, or "" when err is not a graph *Error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

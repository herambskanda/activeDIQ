package ad

import "errors"

// Code is a stable, value-free error code. Errors never carry credentials, DNs or filter text.
type Code string

const (
	CodeInvalidArgument     Code = "INVALID_ARGUMENT"
	CodeFilterRejected      Code = "FILTER_REJECTED"
	CodeSecretAttribute     Code = "SECRET_ATTRIBUTE"
	CodeAttributeNotAllowed Code = "ATTRIBUTE_NOT_ALLOWED"
	CodeUnreachable         Code = "DC_UNREACHABLE"
	CodeBindFailed          Code = "BIND_FAILED"
	CodeObjectNotFound      Code = "OBJECT_NOT_FOUND"
	CodeInsufficientRights  Code = "INSUFFICIENT_RIGHTS"
	CodeUnexpectedReferral  Code = "UNEXPECTED_REFERRAL"
	CodeGlobalCatalog       Code = "GLOBAL_CATALOG_NOT_ALLOWED"
	CodeDelegationRootGone  Code = "DELEGATION_ROOT_GONE"
	CodeControlNotAllowed   Code = "CONTROL_NOT_ALLOWED"
	CodeSecretNotSet        Code = "SECRET_NOT_SET"
	CodeProtocol            Code = "PROTOCOL_ERROR"
	CodeCanceled            Code = "CANCELED"
)

// Error is the package's error type.
type Error struct {
	Code   Code
	Detail string // fixed text, e.g. a rule id or an LDAP result code number; never a value
	cause  error
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "ad: " + string(e.Code)
	}
	return "ad: " + string(e.Code) + ": " + e.Detail
}

// Unwrap exposes the cause for errors.Is/As; the cause is never printed by Error.
func (e *Error) Unwrap() error { return e.cause }

func fail(c Code, detail string, cause error) error {
	return &Error{Code: c, Detail: detail, cause: cause}
}

// CodeOf returns the Code of err, or "" when it is not an *Error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// NewError returns the package error for a code, for adapters and test doubles of the directory
// seams that consumers define over Session.
func NewError(c Code) error { return fail(c, "", nil) }

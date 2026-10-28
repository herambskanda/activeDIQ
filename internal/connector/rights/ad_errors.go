package rights

import (
	"github.com/skenzeriq/activediq/internal/connector/ad"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// adConnectorError maps a failed AD read to the contract's error by the session's typed code only
// (never by message text). ok is false when err carries no AD code. The message is fixed: an LDAP
// diagnostic can carry a DN (DM-24.I3), so nothing from err is ever copied.
func adConnectorError(err error) (ce *v1.ConnectorError, ok bool) {
	code, retry, msg := v1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, v1.RetryAdvice_RETRY_ADVICE_NEVER, "a directory read for this check failed"
	switch ad.CodeOf(err) {
	case "":
		return nil, false
	case ad.CodeObjectNotFound:
		code, msg = v1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND, "object not found"
	case ad.CodeInsufficientRights:
		code, retry, msg = v1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS, v1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION, "insufficient rights"
	case ad.CodeUnreachable, ad.CodeCanceled:
		code, retry, msg = v1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, v1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "domain controller unreachable"
	case ad.CodeBindFailed:
		code, retry, msg = v1.ErrorCode_ERROR_CODE_BIND_FAILED, v1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION, "bind failed"
	case ad.CodeSecretAttribute:
		code, msg = v1.ErrorCode_ERROR_CODE_SECRET_ATTRIBUTE, "attribute not readable"
	case ad.CodeAttributeNotAllowed:
		code, msg = v1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED, "attribute not allowed"
	case ad.CodeInvalidArgument, ad.CodeFilterRejected:
		code, msg = v1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invalid request"
	case ad.CodeUnexpectedReferral:
		code, msg = v1.ErrorCode_ERROR_CODE_UNEXPECTED_REFERRAL, "unexpected referral"
	}
	return &v1.ConnectorError{Code: code, Retry: retry, Message: msg}, true
}

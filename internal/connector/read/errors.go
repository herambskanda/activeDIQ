package read

import (
	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Every error text is fixed: no GUID, DN, attribute value or connector message goes into it.

func refuse(code connectorv1.ErrorCode, retry connectorv1.RetryAdvice, msg string) error {
	return write.NewRefusal(code, retry, msg)
}

func invalid(field string) error {
	r := write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "invalid request")
	r.Err.Details = &connectorv1.ConnectorError_RejectedInput{RejectedInput: &connectorv1.RejectedInputDetails{RuleId: "InvalidReadRequest", Field: field}}
	return r
}

// pinRefusal: the DC this connector is bound to is not the DC the caller pinned (ADR-0005 rule 5,
// DM-15.I3). Never a silent switch.
func pinRefusal() error {
	return refuse(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "pinned domain controller is not the bound one")
}

// mapAD maps a session error to the contract code; dc names the DC that produced it.
func mapAD(err error, dc *connectorv1.DcIdentity) error {
	code, retry, msg := connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory read failed"
	switch ad.CodeOf(err) {
	case ad.CodeObjectNotFound:
		code, msg = connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND, "object not found"
	case ad.CodeInsufficientRights:
		code, msg = connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS, "insufficient rights"
	case ad.CodeUnreachable, ad.CodeCanceled:
		code, retry, msg = connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "domain controller unreachable"
	case ad.CodeBindFailed:
		code, msg = connectorv1.ErrorCode_ERROR_CODE_BIND_FAILED, "bind failed"
	case ad.CodeSecretAttribute:
		code, msg = connectorv1.ErrorCode_ERROR_CODE_SECRET_ATTRIBUTE, "attribute not readable"
	case ad.CodeAttributeNotAllowed:
		code, msg = connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED, "attribute not allowed"
	case ad.CodeInvalidArgument, ad.CodeFilterRejected:
		code, msg = connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invalid request"
	case ad.CodeUnexpectedReferral:
		code, msg = connectorv1.ErrorCode_ERROR_CODE_UNEXPECTED_REFERRAL, "unexpected referral"
	}
	r := write.NewRefusal(code, retry, msg)
	r.Err.Dc = proto.Clone(dc).(*connectorv1.DcIdentity)
	return r
}

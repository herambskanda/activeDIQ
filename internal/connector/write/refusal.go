package write

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Refusal is how Plan and Apply end when they do not proceed. It implements GRPCStatus, so the
// gRPC server sends it as a status with the ConnectorError as a detail, and an in-process caller
// that passes it to directory/client.FromStatus gets the same *ConnectorError. The message is a
// fixed text per code: no identifier, DN, value or peer ever goes into it.
type Refusal struct {
	Err *connectorv1.ConnectorError
	// stage is the step of §8.1 that ended the call, for the local record only.
	stage string
}

func (r *Refusal) Error() string { return "write: " + r.Err.GetCode().String() }

// Code is the connector error code.
func (r *Refusal) Code() connectorv1.ErrorCode { return r.Err.GetCode() }

// GRPCStatus implements the interface google.golang.org/grpc/status looks for.
func (r *Refusal) GRPCStatus() *status.Status {
	st := status.New(grpcCode(r.Err.GetCode()), r.Err.GetMessage())
	if d, err := st.WithDetails(r.Err); err == nil {
		return d
	}
	return st
}

func grpcCode(c connectorv1.ErrorCode) codes.Code {
	switch c {
	case connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH:
		return codes.InvalidArgument
	case connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED:
		return codes.Unimplemented
	case connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED:
		return codes.PermissionDenied
	case connectorv1.ErrorCode_ERROR_CODE_ACTIVATION_REFUSED_OVERPRIVILEGED:
		return codes.FailedPrecondition
	case connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC:
		return codes.Unavailable
	case connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED:
		return codes.Aborted
	case connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND:
		return codes.NotFound
	case connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS:
		return codes.PermissionDenied
	case connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED, connectorv1.ErrorCode_ERROR_CODE_SECRET_ATTRIBUTE:
		return codes.InvalidArgument
	}
	return codes.Internal
}

func newRefusal(code connectorv1.ErrorCode, retry connectorv1.RetryAdvice, stage, msg string) *Refusal {
	return &Refusal{stage: stage, Err: &connectorv1.ConnectorError{Code: code, Retry: retry, Message: msg}}
}

func invalid(stage, rule, field string) *Refusal {
	r := newRefusal(connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, stage, "invalid request")
	r.Err.Details = &connectorv1.ConnectorError_RejectedInput{RejectedInput: &connectorv1.RejectedInputDetails{RuleId: rule, Field: field}}
	return r
}

// pinRefusal is ADR-0005 rule 5: the DC this connector is bound to is not the DC the caller pinned.
// The message carries no hostname or GUID.
func pinRefusal(stage string) *Refusal {
	return newRefusal(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, stage, "pinned domain controller is not the bound one")
}

func mismatch() *Refusal {
	return newRefusal(connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "1", "directory identity mismatch")
}

func unsupported() *Refusal {
	return newRefusal(connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "5", "write kind not supported")
}

// tier0Refusal names the object and the stage, never a peer or a context value.
func tier0Refusal(obj *connectorv1.Guid, bases []connectorv1.Tier0Basis, st connectorv1.Tier0RefusalStage, step string) *Refusal {
	retry := connectorv1.RetryAdvice_RETRY_ADVICE_NEVER
	if st == connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_MISSING || st == connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_STALE {
		retry = connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN
	}
	r := newRefusal(connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED, retry, step, "target is protected")
	r.Err.Details = &connectorv1.ConnectorError_Tier0Refused{Tier0Refused: &connectorv1.Tier0RefusedDetails{Object: obj, Basis: bases, Stage: st}}
	return r
}

func gateRefusal(state connectorv1.WriteGateState, vid *connectorv1.Guid, unack uint32) *Refusal {
	retry := connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION
	switch state {
	case connectorv1.WriteGateState_WRITE_GATE_STATE_NOT_VERIFIED, connectorv1.WriteGateState_WRITE_GATE_STATE_STALE,
		connectorv1.WriteGateState_WRITE_GATE_STATE_COULD_NOT_VERIFY:
		retry = connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN
	}
	r := newRefusal(connectorv1.ErrorCode_ERROR_CODE_ACTIVATION_REFUSED_OVERPRIVILEGED, retry, "2", "write gate closed")
	r.Err.Details = &connectorv1.ConnectorError_ActivationRefused{ActivationRefused: &connectorv1.ActivationRefusedDetails{
		State: state, VerificationId: vid, UnacknowledgedFindings: unack}}
	return r
}

// NewRefusal builds a refusal for another handler of the connector service (the read group), so
// both transports and both groups end a call the same way. The message must be a fixed text.
func NewRefusal(code connectorv1.ErrorCode, retry connectorv1.RetryAdvice, msg string) *Refusal {
	return newRefusal(code, retry, "", msg)
}

// coded builds a refusal with a fixed text for a code that carries no details.
func coded(code connectorv1.ErrorCode, retry connectorv1.RetryAdvice, stage, msg string) *Refusal {
	return newRefusal(code, retry, stage, msg)
}

var (
	errReplan   = connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN
	errNever    = connectorv1.RetryAdvice_RETRY_ADVICE_NEVER
	errOperator = connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION
)

func attrNotAllowed(stage string) *Refusal {
	return coded(connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED, errNever, stage, "attribute not allowed")
}
func limitExceeded(stage string) *Refusal {
	return coded(connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, errNever, stage, "limit exceeded")
}
func targetChanged(stage string) *Refusal {
	return coded(connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED, errReplan, stage, "target changed")
}
func transportSecurity(stage string) *Refusal {
	return coded(connectorv1.ErrorCode_ERROR_CODE_TRANSPORT_SECURITY, errOperator, stage, "channel is not secure")
}

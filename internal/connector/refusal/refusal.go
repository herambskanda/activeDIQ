// Package refusal is how a connector handler ends a call it does not serve: a *Refusal is a gRPC
// status carrying the ConnectorError as a detail, for both transports and every group (write, read,
// rights), so they all end a call the same way. It holds no policy.
package refusal

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Refusal is how a call ends when it does not proceed. It implements GRPCStatus, so the
// gRPC server sends it as a status with the ConnectorError as a detail, and an in-process caller
// that passes it to directory/client.FromStatus gets the same *ConnectorError. The message is a
// fixed text per code: no identifier, DN, value or peer ever goes into it.
type Refusal struct {
	Err *connectorv1.ConnectorError
	// Stage is the step of the write guard (§8.1) that ended the call, for the local record only.
	Stage string
}

func (r *Refusal) Error() string { return "connector: " + r.Err.GetCode().String() }

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

// New builds a refusal. The message must be a fixed text.
func New(code connectorv1.ErrorCode, retry connectorv1.RetryAdvice, stage, msg string) *Refusal {
	return &Refusal{Stage: stage, Err: &connectorv1.ConnectorError{Code: code, Retry: retry, Message: msg}}
}

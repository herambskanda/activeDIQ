package client

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// RemoteError carries a connector's ConnectorError through Go error handling. The transport returns
// it (or an error wrapping it); MapError reads it.
type RemoteError struct{ Err *connectorv1.ConnectorError }

// Error never includes the connector's message text or any detail: only the code.
func (e *RemoteError) Error() string { return "client: connector error " + e.Err.GetCode().String() }

// TransportError is a gRPC status error that carried no ConnectorError detail. Its description is
// free text set by the connector or by Go's net errors on the connector host, and can name a DC, an
// IP or a DN, so only the gRPC code is kept: the text never reaches Error, %+v, %#v or a wrapped
// cause. It is not the fixed ErrTransport that write sanitising returns; it is the read-side error.
type TransportError struct{ Code codes.Code }

// Error names the code only.
func (e *TransportError) Error() string {
	return "client: connector transport error " + e.Code.String()
}

// Retryable is true for the codes where repeating the same call can succeed: the connector or its
// DC was unavailable, throttled, or the call was aborted. It is a hint, not the connector's advice
// (a ConnectorError carries that).
func (e *TransportError) Retryable() bool {
	switch e.Code {
	case codes.Unavailable, codes.ResourceExhausted, codes.Aborted:
		return true
	}
	return false
}

// Is lets a Canceled or DeadlineExceeded status match the context errors, as a cancelled call
// would if it had not crossed gRPC.
func (e *TransportError) Is(target error) bool {
	switch target {
	case context.Canceled:
		return e.Code == codes.Canceled
	case context.DeadlineExceeded:
		return e.Code == codes.DeadlineExceeded
	}
	return false
}

// FromStatus extracts the ConnectorError detail of a gRPC status error. A status error without one
// becomes a TransportError carrying only its code; its description is dropped. A context error and
// an error that is already typed (RemoteError, TransportError) pass through as they are; any other
// non-status error is returned unchanged.
func FromStatus(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var re *RemoteError
	var te *TransportError
	if errors.As(err, &re) || errors.As(err, &te) {
		return err
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	for _, d := range st.Details() {
		if ce, ok := d.(*connectorv1.ConnectorError); ok {
			return &RemoteError{Err: ce}
		}
	}
	return &TransportError{Code: st.Code()}
}

// OutcomeStatus is how a step ends when its write was not applied.
type OutcomeStatus string

// Outcome statuses. StatusStaleState is DM-42.I2's stale_state; StatusRefused is a refusal by the
// connector's own guards, which a retry cannot change.
const (
	StatusStaleState OutcomeStatus = "stale_state"
	StatusRefused    OutcomeStatus = "refused"
	StatusFailed     OutcomeStatus = "failed"
)

// StepOutcome is the mapping of a failed write.
type StepOutcome struct {
	Status OutcomeStatus
	Code   connectorv1.ErrorCode
	// Retryable is true only when the connector's advice is a retry of the same step (same DC after
	// backoff or another DC). TIER0_REFUSED, ACTIVATION_REFUSED_OVERPRIVILEGED and TARGET_CHANGED are
	// never retried as is (connector contract §7).
	Retryable bool
	// Audit holds the fields that may go into an audit event. It never holds an object identifier of
	// a refused or changed object (DM-24.I5: it would map the Tier-0 set).
	Audit map[string]string
	// ObjectGUID is the object a Tier0 refusal or TargetChanged named. The step outcome may store
	// it; it is deliberately not in Audit.
	ObjectGUID []byte
}

// MapError maps the error of a write to a step outcome. A nil error maps to nil. An error that is
// not a connector error is a plain failure: not retryable, nothing echoed.
func MapError(err error) *StepOutcome {
	if err == nil {
		return nil
	}
	var tc *Tier0ContextError
	if errors.As(err, &tc) {
		// The write was refused here, before the connector: the reason is a code, never an object.
		return &StepOutcome{Status: StatusFailed, Audit: map[string]string{"error": "tier0_context", "reason": string(tc.Reason)}}
	}
	var re *RemoteError
	if !errors.As(FromStatus(err), &re) || re.Err == nil {
		return &StepOutcome{Status: StatusFailed, Audit: map[string]string{"error": "transport"}}
	}
	ce := re.Err
	o := &StepOutcome{Status: StatusFailed, Code: ce.GetCode(), Audit: map[string]string{"code": ce.GetCode().String()}}
	switch ce.GetCode() {
	case connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED:
		o.Status = StatusStaleState
		o.ObjectGUID = ce.GetTargetChanged().GetObject().GetValue()
	case connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED:
		o.Status = StatusRefused
		d := ce.GetTier0Refused()
		o.ObjectGUID = d.GetObject().GetValue()
		o.Audit["stage"] = d.GetStage().String()
	case connectorv1.ErrorCode_ERROR_CODE_ACTIVATION_REFUSED_OVERPRIVILEGED:
		o.Status = StatusRefused
		o.Audit["gate_state"] = ce.GetActivationRefused().GetState().String()
	default:
		switch ce.GetRetry() {
		case connectorv1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF, connectorv1.RetryAdvice_RETRY_ADVICE_OTHER_DC:
			o.Retryable = true
		}
	}
	return o
}

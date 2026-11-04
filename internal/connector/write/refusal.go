package write

import (
	"github.com/skenzeriq/activediq/internal/connector/refusal"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Refusal is the connector refusal type (package refusal); the write guard builds it with a stage.
type Refusal = refusal.Refusal

func newRefusal(code connectorv1.ErrorCode, retry connectorv1.RetryAdvice, stage, msg string) *Refusal {
	return refusal.New(code, retry, stage, msg)
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

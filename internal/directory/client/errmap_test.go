package client

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func TestMapError(t *testing.T) {
	secret := []byte("SECRET-OBJECT-GUID")
	g := &connectorv1.Guid{Value: secret}
	cases := []struct {
		name      string
		ce        *connectorv1.ConnectorError
		want      OutcomeStatus
		retryable bool
		hasObject bool
	}{
		{"target changed", &connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED,
			Retry:   connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN,
			Details: &connectorv1.ConnectorError_TargetChanged{TargetChanged: &connectorv1.TargetChangedDetails{Object: g}}}, StatusStaleState, false, true},
		{"tier0 refused", &connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED,
			Details: &connectorv1.ConnectorError_Tier0Refused{Tier0Refused: &connectorv1.Tier0RefusedDetails{Object: g,
				Stage: connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD}}}, StatusRefused, false, true},
		{"activation refused", &connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_ACTIVATION_REFUSED_OVERPRIVILEGED,
			Details: &connectorv1.ConnectorError_ActivationRefused{ActivationRefused: &connectorv1.ActivationRefusedDetails{
				State: connectorv1.WriteGateState_WRITE_GATE_STATE_OVERPRIVILEGED}}}, StatusRefused, false, false},
		{"unreachable dc retries", &connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC,
			Retry: connectorv1.RetryAdvice_RETRY_ADVICE_OTHER_DC}, StatusFailed, true, false},
		{"insufficient rights does not", &connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS,
			Retry: connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION}, StatusFailed, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := MapError(fmt.Errorf("wrapped: %w", &RemoteError{Err: c.ce}))
			if o.Status != c.want || o.Retryable != c.retryable || o.Code != c.ce.Code {
				t.Fatalf("got %+v", o)
			}
			if c.hasObject != (len(o.ObjectGUID) > 0) {
				t.Fatalf("ObjectGUID = %q", o.ObjectGUID)
			}
			for k, v := range o.Audit {
				if strings.Contains(k+v, string(secret)) || strings.Contains(fmt.Sprint(o.Audit), "SECRET") {
					t.Fatalf("object identifier in audit field %s", k)
				}
			}
		})
	}
}

func TestMapErrorNonConnectorAndNil(t *testing.T) {
	if MapError(nil) != nil {
		t.Fatal("nil must map to nil")
	}
	o := MapError(errors.New("dial tcp 10.0.0.1: secret-host"))
	if o.Status != StatusFailed || o.Retryable || strings.Contains(fmt.Sprint(o.Audit), "secret-host") {
		t.Fatalf("got %+v", o)
	}
}

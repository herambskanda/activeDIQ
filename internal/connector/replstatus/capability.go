package replstatus

import (
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Capability is the Describe row for OPERATION_READ_REPLICATION_STATUS (rule 7). AD with at least
// one reachable DC is SUPPORTED; no reachable DC is UNSUPPORTED; Samba is UNVERIFIED with a reason,
// because its answers are expected to be partial (spec §7.3.1 [UNVERIFIED]) and only a Windows lab
// run (CC-REPL-04..06) proves the values. Entra has no replication: its provider answers
// CAPABILITY_UNSUPPORTED (UnsupportedCapability).
func Capability(reachableDCs int, samba bool) *connectorv1.OperationSupport {
	row := &connectorv1.OperationSupport{Operation: connectorv1.Operation_OPERATION_READ_REPLICATION_STATUS}
	switch {
	case reachableDCs <= 0:
		row.State, row.Reason = connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED, "no reachable domain controller"
	case samba:
		row.State, row.Reason = connectorv1.SupportState_SUPPORT_STATE_UNVERIFIED, "Samba: replication attributes may be partial or missing; values are proven only on Windows"
	default:
		row.State = connectorv1.SupportState_SUPPORT_STATE_SUPPORTED
	}
	return row
}

// UnsupportedCapability is the Entra provider's row: there is no replication to report.
func UnsupportedCapability() *connectorv1.OperationSupport {
	return &connectorv1.OperationSupport{
		Operation: connectorv1.Operation_OPERATION_READ_REPLICATION_STATUS,
		State:     connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED,
		Reason:    "Entra ID has no replication",
	}
}

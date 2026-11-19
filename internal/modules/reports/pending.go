package reports

import (
	"context"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// pending answers the operations whose rows of modules/reports.md 12 have not landed: schedules (B11), the SYS-03 thresholds (T-1744) and the manager picker (T-1745).
// They are in the contract and mounted, and until their row
// lands they answer 501 not-implemented rather than a made-up body. Each row deletes its methods here.
type pending struct{}

// ListReportRunPolicyTargets (T-1718) is in the contract ahead of the policy dataset (T-1114, inventory.policies).
// Until the dataset lands no run holds a policy row, so every policyId is "not a policy row of the run"; the
// honest answer is 501 rather than a made-up empty page, which a client would read as "no direct targets".
func (pending) ListReportRunPolicyTargets(context.Context, api.ListReportRunPolicyTargetsInput) (api.ListReportRunPolicyTargetsOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (policy dataset, T-1114)")
}

// GetReportRunRowDetail (T-1717) is in the contract ahead of the read behind it (T-2117). Until then the honest
// answer is 501, not an empty or invented detail a client would read as "no attributes changed".
func (pending) GetReportRunRowDetail(context.Context, api.GetReportRunRowDetailInput) (api.GetReportRunRowDetailOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (change-history row detail, T-2117)")
}

var _ api.Handlers = (*Handlers)(nil)

func (pending) GetReportSchedule(context.Context, api.GetReportScheduleInput) (api.GetReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) ListReportSchedules(context.Context, api.ListReportSchedulesInput) (api.ListReportSchedulesOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) CreateReportSchedule(context.Context, api.CreateReportScheduleInput) (api.CreateReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) DeleteReportSchedule(context.Context, api.DeleteReportScheduleInput) (api.DeleteReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) PauseReportSchedule(context.Context, api.PauseReportScheduleInput) (api.PauseReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) ReassignReportSchedule(context.Context, api.ReassignReportScheduleInput) (api.ReassignReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) ResumeReportSchedule(context.Context, api.ResumeReportScheduleInput) (api.ResumeReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) RunReportScheduleNow(context.Context, api.RunReportScheduleNowInput) (api.RunReportScheduleNowOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) UpdateReportSchedule(context.Context, api.UpdateReportScheduleInput) (api.UpdateReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) PreviewCreateReportSchedule(context.Context, api.PreviewCreateReportScheduleInput) (api.PreviewCreateReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) PreviewDeleteReportSchedule(context.Context, api.PreviewDeleteReportScheduleInput) (api.PreviewDeleteReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) PreviewPauseReportSchedule(context.Context, api.PreviewPauseReportScheduleInput) (api.PreviewPauseReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) PreviewReassignReportSchedule(context.Context, api.PreviewReassignReportScheduleInput) (api.PreviewReassignReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) PreviewResumeReportSchedule(context.Context, api.PreviewResumeReportScheduleInput) (api.PreviewResumeReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) PreviewUndoReportScheduleOperation(context.Context, api.PreviewUndoReportScheduleOperationInput) (api.PreviewUndoReportScheduleOperationOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) PreviewUpdateReportSchedule(context.Context, api.PreviewUpdateReportScheduleInput) (api.PreviewUpdateReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) UndoReportScheduleOperation(context.Context, api.UndoReportScheduleOperationInput) (api.UndoReportScheduleOperationOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) GetReportReplicationThresholds(context.Context, api.GetReportReplicationThresholdsInput) (api.GetReportReplicationThresholdsOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (T-1744)")
}

func (pending) UpdateReportReplicationThresholds(context.Context, api.UpdateReportReplicationThresholdsInput) (api.UpdateReportReplicationThresholdsOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (T-1744)")
}

func (pending) PreviewUpdateReportReplicationThresholds(context.Context, api.PreviewUpdateReportReplicationThresholdsInput) (api.PreviewUpdateReportReplicationThresholdsOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (T-1744)")
}

func (pending) UndoReportReplicationThresholdsOperation(context.Context, api.UndoReportReplicationThresholdsOperationInput) (api.UndoReportReplicationThresholdsOperationOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (T-1744)")
}

func (pending) PreviewUndoReportReplicationThresholdsOperation(context.Context, api.PreviewUndoReportReplicationThresholdsOperationInput) (api.PreviewUndoReportReplicationThresholdsOperationOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (T-1744)")
}

func (pending) ListReportManagers(context.Context, api.ListReportManagersInput) (api.ListReportManagersOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (T-1745)")
}

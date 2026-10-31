package reports

import (
	"context"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// pending answers the operations whose rows of modules/reports.md 12 have not landed: schedules (B11).
// They are in the contract and mounted, and until their row
// lands they answer 501 not-implemented rather than a made-up body. Each row deletes its methods here.
type pending struct{}

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

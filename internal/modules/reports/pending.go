package reports

import (
	"context"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// pending answers the operations whose rows of modules/reports.md 12 have not landed: the library
// (B5), exports (B9) and schedules (B11). They are in the contract and mounted, and until their row
// lands they answer 501 not-implemented rather than a made-up body. Each row deletes its methods here.
type pending struct{}

var _ api.Handlers = (*Handlers)(nil)

func (pending) CreateReportExport(context.Context, api.CreateReportExportInput) (api.CreateReportExportOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B9)")
}

func (pending) DeleteReportExport(context.Context, api.DeleteReportExportInput) (api.DeleteReportExportOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B9)")
}

func (pending) DownloadReportExport(context.Context, api.DownloadReportExportInput) (api.DownloadReportExportOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B9)")
}

func (pending) GetReportDefinition(context.Context, api.GetReportDefinitionInput) (api.GetReportDefinitionOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B5)")
}

func (pending) GetReportExport(context.Context, api.GetReportExportInput) (api.GetReportExportOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B9)")
}

func (pending) GetReportSchedule(context.Context, api.GetReportScheduleInput) (api.GetReportScheduleOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B11)")
}

func (pending) ListReportDefinitions(context.Context, api.ListReportDefinitionsInput) (api.ListReportDefinitionsOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (row B5)")
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

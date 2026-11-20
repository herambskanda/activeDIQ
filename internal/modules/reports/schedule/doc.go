// Package schedule is the report schedule (T-0965; modules/reports.md §8, row B11; DM-73): the stored
// schedule, its versions and recipients, the reports.schedule.* Actions, the reports.schedule.tick and reports.schedule.fire jobs (fire.go) and the
// delivery Renderer (render.go).
//
// A schedule is data in four tables. Writes are Actions (ADR-0005 rule 10); a fire is a job, not an Action.
package schedule

import "github.com/skenzeriq/activediq/internal/platform/tablekind"

var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.report_schedules", Entity: "DM-73", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.report_schedule_versions", Entity: "DM-73", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.report_schedule_recipients", Entity: "DM-73", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.report_schedule_fires", Entity: "DM-73", Kind: tablekind.Tenant})
)

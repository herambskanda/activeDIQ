// Package reports is the server module of the 2a report operations (T-0866, contract first). Today it
// holds only the permission names the contract binds; the handlers, the runner and the exports arrive
// with the reporting tickets and must not add a domain rule to the generated api package.
//
// The contract is api/openapi/modules/reports.yaml. Columns are a closed enum and filters a typed
// tree: nothing in a request is a column name, an LDAP filter, a DN or SQL.
package reports

import "github.com/skenzeriq/activediq/internal/platform/authz"

// The five permissions of spec reports-2a 8.5.
const (
	// RunPermission guards the library, runs, the run header and stored-result paging.
	RunPermission authz.Permission = "reports.run"
	// ExportPermission guards exports, the export record, downloads and deleting a file.
	ExportPermission authz.Permission = "reports.export"
	// SchedulePermission guards the caller's own schedules.
	SchedulePermission authz.Permission = "reports.schedule"
	// ScheduleManageAllPermission is bound to reassignReportSchedule only. It is also checked inside
	// the schedule operations when the caller lists owner=any or acts on another owner's schedule.
	ScheduleManageAllPermission authz.Permission = "reports.schedule.manage_all"
	// DeliverExternalPermission is bound to no operation. The schedule Action checks it when a
	// recipient is outside the allowed recipient domains.
	DeliverExternalPermission authz.Permission = "reports.deliver.external"
)

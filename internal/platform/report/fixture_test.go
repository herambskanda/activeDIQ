package report_test

import (
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

func anchorT() report.Anchor {
	return report.Anchor{ID: "t", Table: "directory_objects", Mode: report.RowAnchor, Project: []report.Ident{"object_guid"},
		Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}
}

// usersDataset is a small dataset with an attribute, a JSON attribute, a derived state with its
// dependent column, and a per-DC column.
func usersDataset() report.Dataset {
	return report.Dataset{
		ID:      "inventory.users",
		Base:    report.Relation{Table: "directory_objects", Where: report.SQL("{t}.kind = 'user'")},
		RowKey:  report.SQL("{t}.object_guid"),
		Anchors: []report.Anchor{anchorT()},
		Columns: []report.Column{
			{ID: "name", Label: "Name", Type: report.TypeText, Source: report.JSONAttr{Col: "attributes", Key: "cn", As: report.TypeText},
				Filter: []report.Op{report.OpEq, report.OpContains, report.OpPrefix}, Sortable: true, Default: true},
			{ID: "status", Label: "Status", Type: report.TypeEnum, Source: report.Derived{SQL: report.SQL("CASE WHEN {t}.state = 'live' THEN 'enabled' ELSE 'disabled' END")},
				Enum:   []report.EnumValue{{ID: "enabled", Label: "Enabled"}, {ID: "disabled", Label: "Disabled"}},
				Filter: []report.Op{report.OpEq, report.OpNe, report.OpIn}, Sortable: true},
			{ID: "locked_out", Label: "Locked out", Type: report.TypeEnum, Source: report.Derived{SQL: report.SQL("'not_locked'")},
				Enum:   []report.EnumValue{{ID: "locked", Label: "Locked"}, {ID: "not_locked", Label: "Not locked"}, {ID: report.UnknownInputMissing, Label: "Unknown"}},
				Filter: []report.Op{report.OpEq}},
			{ID: "lockout_ends_at", Label: "Lockout ends", Type: report.TypeTime, Source: report.Derived{SQL: report.SQL("{t}.lockout_time")},
				UnknownWhen: "locked_out", Filter: []report.Op{report.OpPresent, report.OpAbsent}},
			{ID: "pwd_last_set", Label: "Password last set", Type: report.TypeTime, Source: report.Attr{Col: "pwd_last_set"},
				Filter: []report.Op{report.OpLt, report.OpOlderThanDays, report.OpWithinLastDays, report.OpPresent, report.OpAbsent}, Sortable: true},
			{ID: "last_logon", Label: "Last logon (exact)", Type: report.TypeTime, Source: report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax},
				Filter: []report.Op{report.OpOlderThanDays}},
			{ID: "object_guid", Label: "GUID", Type: report.TypeGUID, Source: report.Attr{Col: "object_guid"}, Filter: []report.Op{report.OpEq, report.OpIn}},
		},
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_objects"},
	}
}

func usersDef() report.Definition {
	return report.Definition{
		ID: "usr-03", Version: 2, Category: report.CategoryUsers, Title: "Inactive users", Dataset: "inventory.users",
		Columns: []report.ColumnID{"name", "status", "pwd_last_set"},
		Sort:    []report.SortKey{{Column: "name", Dir: report.Asc}},
		Params:  []report.ParamSpec{{Name: "days", Kind: report.ParamDays, Min: 30, Max: 3650, Default: ptr(report.DaysP(90))}},
		Presets: []report.Preset{
			{ID: "inactive", Where: report.And{Terms: []report.Expr{
				report.Cmp{Column: "status", Op: report.OpEq, Value: report.EnumV("enabled")},
				report.Cmp{Column: "pwd_last_set", Op: report.OpOlderThanDays, Param: "days"},
			}}},
			{ID: "all"},
		},
	}
}

func ptr[T any](v T) *T { return &v }

func oid(b byte) authz.ObjectID { return authz.ObjectID{b} }

func parse(s string) (authz.ObjectID, error) { return authz.ParseObjectID(s) }

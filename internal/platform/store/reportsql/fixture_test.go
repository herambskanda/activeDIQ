package reportsql_test

import (
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
)

var schema = reportsql.MapSchema{
	"directory_objects": {
		"connection_id": reportsql.KindGUID, "nc_guid": reportsql.KindGUID, "object_guid": reportsql.KindGUID,
		"parent_guid": reportsql.KindGUID, "ancestry": reportsql.KindGUIDList, "ancestry_complete": reportsql.KindBool,
		"attributes": reportsql.KindJSON, "kind": reportsql.KindEnum, "state": reportsql.KindEnum,
		"pwd_last_set": reportsql.KindTime, "lockout_time": reportsql.KindTime, "sam_account_name": reportsql.KindText, "display_name": reportsql.KindText,
		"groups": reportsql.KindTextList, "logon_count": reportsql.KindInt, "enabled": reportsql.KindBool,
	},
	"group_links": {
		"group_guid": reportsql.KindGUID, "member_guid": reportsql.KindGUID, "link_kind": reportsql.KindEnum, "note": reportsql.KindText,
		"since": reportsql.KindTime, "meta": reportsql.KindJSON,
	},
}

func secretKey(k string) bool { return k == "unicodePwd" || k == "ntPwdHistory" }

func opts() reportsql.Options { return reportsql.Options{Schema: schema, SecretKey: secretKey} }

func anchorT() report.Anchor {
	return report.Anchor{ID: "t", Table: "directory_objects", Mode: report.RowAnchor, Project: []report.Ident{"object_guid"},
		Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}
}

func usersDataset() report.Dataset {
	return report.Dataset{
		ID:      "inventory.users",
		Base:    report.Relation{Table: "directory_objects", Where: report.SQL("{t}.kind = 'user'")},
		RowKey:  report.SQL("{t}.object_guid"),
		Anchors: []report.Anchor{anchorT()},
		Columns: []report.Column{
			{ID: "name", Label: "Name", Type: report.TypeText, Source: report.JSONAttr{Col: "attributes", Key: "cn", As: report.TypeText},
				Filter: []report.Op{report.OpEq, report.OpContains, report.OpPrefix, report.OpPresent, report.OpAbsent}, Sortable: true, Default: true},
			{ID: "sam", Label: "SAM", Type: report.TypeText, Source: report.Attr{Col: "sam_account_name"},
				Filter: []report.Op{report.OpEq, report.OpIn, report.OpNe}, Sortable: true},
			{ID: "status", Label: "Status", Type: report.TypeEnum, Source: report.Derived{SQL: report.SQL("CASE WHEN {t}.state = 'live' THEN 'enabled' ELSE 'disabled' END")},
				Enum:   []report.EnumValue{{ID: "enabled", Label: "Enabled", SortRank: 2}, {ID: "disabled", Label: "Disabled", SortRank: 1}},
				Filter: []report.Op{report.OpEq, report.OpNe, report.OpIn}, Sortable: true},
			{ID: "locked_out", Label: "Locked out", Type: report.TypeEnum,
				Source: report.Derived{SQL: report.SQL("CASE WHEN {t}.enabled IS NULL THEN 'unknown_input_missing' WHEN {t}.lockout_time IS NULL THEN 'not_locked' ELSE 'locked' END")},
				Enum:   []report.EnumValue{{ID: "locked", Label: "Locked"}, {ID: "not_locked", Label: "Not locked"}, {ID: report.UnknownInputMissing, Label: "Unknown"}},
				Filter: []report.Op{report.OpEq}},
			{ID: "lockout_ends_at", Label: "Lockout ends", Type: report.TypeTime, Source: report.Derived{SQL: report.SQL("{t}.lockout_time")},
				UnknownWhen: "locked_out", Filter: []report.Op{report.OpPresent, report.OpAbsent}},
			{ID: "pwd_last_set", Label: "Password last set", Type: report.TypeTime, Source: report.Attr{Col: "pwd_last_set"},
				Filter: []report.Op{report.OpLt, report.OpOlderThanDays, report.OpWithinLastDays, report.OpPresent, report.OpAbsent}, Sortable: true},
			{ID: "logons", Label: "Logons", Type: report.TypeInt, Source: report.Attr{Col: "logon_count"},
				Filter: []report.Op{report.OpEq, report.OpGt, report.OpGe, report.OpLt, report.OpLe}, Sortable: true},
			{ID: "enabled", Label: "Enabled", Type: report.TypeBool, Source: report.Attr{Col: "enabled"}, Filter: []report.Op{report.OpEq}},
			{ID: "groups", Label: "Groups", Type: report.TypeTextList, Source: report.Attr{Col: "groups"}, Filter: []report.Op{report.OpContains, report.OpPresent}},
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
		ID: "usr-03", Version: 2, Category: report.CategoryUsers, Title: "Users", Dataset: "inventory.users",
		Columns: []report.ColumnID{"name", "status", "pwd_last_set"},
		Sort:    []report.SortKey{{Column: "name", Dir: report.Asc}},
		Presets: []report.Preset{{ID: "all"}, {ID: "hid", Hidden: []report.HiddenGroup{{ID: "off", Label: "Disabled", Where: report.Cmp{Column: "status", Op: report.OpEq, Value: report.EnumV("disabled")}}}},
			{ID: "subject", Requires: &report.Subjects{Min: 1, Max: 5}}},
	}
}

func registry(t testing.TB, ds ...report.Dataset) *reportsql.Registry {
	t.Helper()
	r, err := reportsql.NewRegistry(opts(), ds...)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func resolve(t testing.TB, p report.RunParams) (report.Query, reportsql.Dataset) {
	t.Helper()
	preset := "all"
	if len(p.Subjects) > 0 {
		preset = "subject"
	}
	return resolveP(t, preset, p)
}

func resolveP(t testing.TB, preset string, p report.RunParams) (report.Query, reportsql.Dataset) {
	t.Helper()
	r := registry(t, usersDataset())
	ds, _ := r.Dataset("inventory.users")
	q, err := report.Resolve(usersDef(), preset, p, usersDataset())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return q, ds
}

func oid(b byte) authz.ObjectID { return authz.ObjectID{b} }

var fixedNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func in() reportsql.Inputs { return reportsql.Inputs{Now: fixedNow} }

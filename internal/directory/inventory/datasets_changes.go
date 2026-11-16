package inventory

import (
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// DatasetObjectChanges is the change-history dataset behind the Recently Modified and Recently Deleted
// reports (reports-2-second-slice §4.1, D10; DM-18).
const DatasetObjectChanges report.DatasetID = "inventory.object_changes"

func init() {
	for k, v := range map[string]string{
		"created": "Created", "edited": "Edited", "moved": "Moved", "renamed": "Renamed", "deleted": "Removed (restore status unknown)",
		"observed": "Observed",
	} {
		enumLabels[k] = v
	}
}

// objectChangesDataset lists one row per observed change. The row exists only while the object it is
// about is in the runner's scope (RowAnchor "obj" on the object's current row, which a deleted object
// keeps with its last ancestry), so a name, DN or count never reveals an out-of-scope or deleted-out-of-scope
// object (RP11). The time is the time activeDIQ observed the change, never a DC's whenChanged (spec
// §4.1 rule 1, DM-18.I2): the only basis there is today is "observed", and the column says so.
func objectChangesDataset() report.Dataset {
	changeKinds := []string{"created", "edited", "moved", "renamed", "deleted"}
	cols := []report.Column{
		attr("change_id", "Change ID", report.TypeGUID, "change_id", opsGUID, false),
		attr("object_guid", "Object GUID", report.TypeGUID, "object_guid", opsGUID, false),
		attr("connection_id", "Connection", report.TypeGUID, "connection_id", opsGUID, false),
		derived("domain", "Domain (naming context)", report.TypeGUID, report.SQL("{rel.obj}.nc_guid"), opsGUID),
		state("object_kind", "Object type", report.SQL("{t}.object_kind"), memberKinds...),
		state("change_kind", "Change", report.SQL("{t}.change_kind"), changeKinds...),
		attr("name", "Name", report.TypeText, "name", opsText, true),
		attr("sam_account_name", "Logon name (pre-Windows 2000)", report.TypeText, "sam_account_name", opsText, true),
		attr("dn", "Distinguished name (last known)", report.TypeText, "dn", opsText, false),
		{ID: "attributes_changed", Label: "Attributes changed (names only)", Type: report.TypeTextList,
			Source: report.Attr{Col: "attributes_changed"}, Filter: []report.Op{report.OpContains, report.OpPresent, report.OpAbsent}, Sortable: false, Default: true},
		attr("automatic_only", "Automatic updates only", report.TypeBool, "automatic_only", opsBool, false),
		attr("observed_at", "Observed at", report.TypeTime, "observed_at", opsTime, true),
		state("basis", "Basis", report.SQL("'observed'"), "observed"),
	}
	return report.Dataset{
		ID: DatasetObjectChanges,
		Base: report.Relation{Table: "directory_object_changes",
			Joins: []report.RowJoin{{Anchor: "obj", On: report.SQL("{rel.obj}.connection_id = {t}.connection_id AND {rel.obj}.object_guid = {t}.object_guid")}}},
		RowKey: report.SQL("{t}.change_id"),
		Anchors: []report.Anchor{{ID: "obj", Table: "directory_objects", Mode: report.RowAnchor, Project: idents("connection_id", "object_guid", "nc_guid"),
			Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}},
		Columns:   cols,
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_object_changes", "directory_objects"},
	}
}

package inventory

import (
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// The group, OU and contact datasets (reports contract §3.3, row B6; spec reports-2a §6.6, FR-15).
// Effective membership is read from the stored closure (closure.go), never walked live. Counts join a
// FilterAnchor, so they count in-scope objects only; a name or GUID in a cell comes from a RowAnchor or
// a MaskAnchor identity column (RP11).
const (
	DatasetGroups       report.DatasetID = "inventory.groups"
	DatasetGroupMembers report.DatasetID = "inventory.group_members"
	DatasetOUs          report.DatasetID = "inventory.ous"
	DatasetContacts     report.DatasetID = "inventory.contacts"
)

const (
	outsideGroup  = "'(group outside your scope)'"
	externalLabel = "'External principal (unresolved)'"

	// groupType is the stored AD groupType as an integer; NULL when it was not read. The text test
	// keeps a non-integer JSON number from reaching the cast.
	groupType = "(CASE WHEN jsonb_typeof({t}.attributes -> 'groupType') = 'number' AND length({t}.attributes ->> 'groupType') <= 11" +
		" AND NOT ({t}.attributes ->> 'groupType') ~ '[^0-9-]' THEN ({t}.attributes ->> 'groupType')::bigint END)"
	// 0x80000000 is security-enabled; a signed int32 read sign-extends, so the bit holds either way.
	groupTypeSQL  = "CASE WHEN " + groupType + " IS NULL THEN 'unknown_input_missing' WHEN (" + groupType + " & 2147483648) <> 0 THEN 'security' ELSE 'distribution' END"
	groupScopeSQL = "CASE WHEN " + groupType + " IS NULL THEN 'unknown_input_missing' WHEN (" + groupType + " & 2) <> 0 THEN 'global'" +
		" WHEN (" + groupType + " & 4) <> 0 THEN 'domain_local' WHEN (" + groupType + " & 8) <> 0 THEN 'universal' ELSE 'unknown_input_missing' END"

	// A member reached through a closure row counts when it is a live, in-scope object. A cycle row is
	// a finding, not a member.
	memberCount = "(SELECT count(*) FROM {rel.clo} JOIN {rel.mem} ON mem.connection_id = clo.connection_id AND mem.object_guid = clo.member_guid" +
		" WHERE clo.connection_id = {t}.connection_id AND clo.group_guid = {t}.object_guid AND clo.edge_kind <> 'cycle' AND mem.state = 'live'"
	directMembersSQL    = memberCount + " AND clo.depth = 1)"
	effectiveMembersSQL = memberCount + ")"
	primaryMembersSQL   = memberCount + " AND clo.edge_kind = 'primary_group')"
	hasMembersSQL       = "EXISTS (SELECT 1 FROM {rel.clo} JOIN {rel.mem} ON mem.connection_id = clo.connection_id AND mem.object_guid = clo.member_guid" +
		" WHERE clo.connection_id = {t}.connection_id AND clo.group_guid = {t}.object_guid AND clo.depth = 1 AND clo.edge_kind <> 'cycle' AND mem.state = 'live')"

	// A member edge whose target has no inventory row at all: a domain outside the inventory. Whether a
	// row exists is not scoped (it names no object); what the row is would be.
	outsideInventorySQL = "EXISTS (SELECT 1 FROM {rel.memb} WHERE memb.connection_id = {t}.connection_id AND memb.source_guid = {t}.object_guid" +
		" AND NOT EXISTS (SELECT 1 FROM {rel.known} WHERE known.connection_id = memb.connection_id AND known.object_guid = memb.target_guid))"

	// The manager shows only when it is a live, in-scope object of the same connection: a DN is only
	// unique within a forest, so another connection's object with the same DN says nothing about this one.
	managedBySQL = "CASE WHEN jsonb_typeof({t}.attributes -> 'managedBy') IS DISTINCT FROM 'string' THEN NULL" +
		" WHEN EXISTS (SELECT 1 FROM {rel.mgr} WHERE mgr.connection_id = {t}.connection_id AND mgr.state = 'live'" +
		" AND lower(mgr.dn) = lower({t}.attributes ->> 'managedBy')) THEN {t}.attributes ->> 'managedBy'" +
		" ELSE '(manager outside your scope)' END"
	hasManagerSQL = "jsonb_typeof({t}.attributes -> 'managedBy') = 'string'"

	// A group whose nesting is deeper than the closure follows: some effective members are not listed.
	nestingCutSQL = "EXISTS (SELECT 1 FROM {rel.clo} WHERE clo.connection_id = {t}.connection_id AND clo.group_guid = {t}.object_guid AND clo.cut)"

	memberNameSQL = "CASE WHEN {rel.mbr}.kind = 'fsp' THEN " + externalLabel +
		" ELSE COALESCE(NULLIF({rel.mbr}.sam_account_name, ''), NULLIF({rel.mbr}.display_name, ''), {rel.mbr}.rdn) END"
)

const (
	// The primary group is an edge the sync writes (DM-17.I2); its name shows only when the group is in scope.
	primaryGroupSQL = "(SELECT CASE WHEN {in_scope.pgrp} THEN pgrp.sam_account_name ELSE " + outsideGroup + " END FROM {rel.memb} JOIN {rel.pgrp}" +
		" ON pgrp.connection_id = memb.connection_id AND pgrp.object_guid = memb.source_guid" +
		" WHERE memb.connection_id = {t}.connection_id AND memb.target_guid = {t}.object_guid AND memb.link_attr = 'primary_group' LIMIT 1)"
	inOtherGroupsSQL = "EXISTS (SELECT 1 FROM {rel.memb} WHERE memb.connection_id = {t}.connection_id AND memb.target_guid = {t}.object_guid AND memb.link_attr = 'member')"
)

var memberKinds = []string{"user", "inetorgperson", "group", "computer", "contact", "ou", "container", "gmsa", "fsp", "other"}

func init() {
	for k, v := range map[string]string{
		"security": "Security", "distribution": "Distribution", "global": "Global", "domain_local": "Domain local", "universal": "Universal",
		"direct": "Direct member", "primary_group": "Primary group", "nested": "Nested member", "cycle": "Circular nesting",
		"user": "User", "inetorgperson": "inetOrgPerson", "group": "Group", "computer": "Computer", "contact": "Contact", "ou": "Organizational unit",
		"container": "Container", "gmsa": "Group managed service account", "fsp": "Foreign security principal", "other": "Other",
	} {
		enumLabels[k] = v
	}
}

func objectColumns() []report.Column {
	return []report.Column{
		attr("object_guid", "Object GUID", report.TypeGUID, "object_guid", opsGUID, true),
		attr("connection_id", "Connection", report.TypeGUID, "connection_id", opsGUID, false),
		attr("domain", "Domain (naming context)", report.TypeGUID, "nc_guid", opsGUID, false),
		attr("dn", "Distinguished name", report.TypeText, "dn", opsText, false),
		attr("rdn", "Name", report.TypeText, "rdn", opsText, true),
		attr("display_name", "Display name", report.TypeText, "display_name", opsText, false),
		attr("when_created", "Created", report.TypeTime, "when_created", opsTime, false),
		attr("observed_at", "Observed at", report.TypeTime, "observed_at", opsTime, false),
	}
}

func counted(id report.ColumnID, label string, sql report.Fragment) report.Column {
	c := derived(id, label, report.TypeInt, sql, opsInt)
	c.Count = true
	return c
}

func groupsDataset() report.Dataset {
	cols := objectColumns()
	cols = append(cols,
		attr("sam_account_name", "Logon name (pre-Windows 2000)", report.TypeText, "sam_account_name", opsText, true),
		state("group_type", "Group type", report.SQL(groupTypeSQL), "security", "distribution", report.UnknownInputMissing),
		state("group_scope", "Group scope", report.SQL(groupScopeSQL), "global", "domain_local", "universal", report.UnknownInputMissing),
		counted("direct_members", "Direct members", report.SQL(directMembersSQL)),
		counted("effective_members", "Effective members", report.SQL(effectiveMembersSQL)),
		counted("primary_group_members", "Members by primary group", report.SQL(primaryMembersSQL)),
		derived("has_members", "Has members (member or primary group)", report.TypeBool, report.SQL(hasMembersSQL), opsBool),
		derived("includes_members_outside_inventory", "Includes members outside the covered domains", report.TypeBool, report.SQL(outsideInventorySQL), opsBool),
		derived("nesting_cut", "Nesting deeper than 128 levels (members beyond not listed)", report.TypeBool, report.SQL(nestingCutSQL), opsBool),
		derived("managed_by", "Managed by", report.TypeText, report.SQL(managedBySQL), opsText),
		derived("has_manager", "Managed by is set", report.TypeBool, report.SQL(hasManagerSQL), opsBool),
	)
	return report.Dataset{
		ID:     DatasetGroups,
		Base:   report.Relation{Table: "directory_objects", Where: report.SQL("{t}.kind = 'group' AND {t}.state = 'live'")},
		RowKey: report.SQL("{t}.object_guid"),
		Anchors: []report.Anchor{rowAnchorT(),
			{ID: "mem", Table: "directory_objects", Mode: report.FilterAnchor, Project: idents("connection_id", "object_guid", "state"),
				Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"},
			{ID: "mgr", Table: "directory_objects", Mode: report.FilterAnchor, Project: idents("connection_id", "dn", "state"),
				Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"},
			{ID: "known", Table: "directory_objects", Mode: report.MaskAnchor, Project: idents("connection_id", "object_guid"), Identity: idents("rdn"),
				Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}},
		Rels: []report.Rel{
			{ID: "clo", Kind: report.RelEdge, Table: "inventory_group_members", Project: idents("connection_id", "group_guid", "member_guid", "edge_kind", "depth", "cut")},
			{ID: "memb", Kind: report.RelEdge, Table: "links", Project: idents("connection_id", "source_guid", "target_guid"),
				Where: report.SQL("state = 'active' AND link_attr = 'member'")},
		},
		Columns:   cols,
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_objects", "inventory_group_members", "links"},
	}
}

func groupMembersDataset() report.Dataset {
	kind := state("member_kind", "Member type", report.SQL("{rel.mbr}.kind"), memberKinds...)
	via := derived("via_path", "Via", report.TypeText, report.SQL(viaPathSQL), nil)
	via.Sortable = false
	finding := derived("finding", "Finding", report.TypeText, report.SQL(findingSQL), opsText)
	finding.Sortable = false
	edge := state("edge_kind", "Membership", report.SQL("{t}.edge_kind"), "direct", "primary_group", "nested", "cycle")
	cols := []report.Column{
		attr("group_guid", "Group GUID", report.TypeGUID, "group_guid", opsGUID, false),
		attr("member_guid", "Member GUID", report.TypeGUID, "member_guid", opsGUID, false),
		attr("connection_id", "Connection", report.TypeGUID, "connection_id", opsGUID, false),
		derived("domain", "Group domain (naming context)", report.TypeGUID, report.SQL("{rel.grp}.nc_guid"), opsGUID),
		derived("group_name", "Group", report.TypeText, report.SQL("{rel.grp}.sam_account_name"), opsText),
		derived("group_dn", "Group distinguished name", report.TypeText, report.SQL("{rel.grp}.dn"), opsText),
		derived("member_name", "Member", report.TypeText, report.SQL(memberNameSQL), opsText),
		derived("member_dn", "Member distinguished name", report.TypeText, report.SQL("{rel.mbr}.dn"), opsText),
		derived("member_sid", "Member SID", report.TypeText, report.SQL("{rel.mbr}.sid_text"), opsText),
		derived("member_enabled", "Member enabled", report.TypeBool, report.SQL("{rel.mbr}.enabled"), opsBool),
		derived("member_unresolved", "External principal (unresolved)", report.TypeBool, report.SQL("{rel.mbr}.kind = 'fsp'"), opsBool),
		kind, edge,
		attr("depth", "Depth", report.TypeInt, "depth", opsInt, false),
		via, finding,
	}
	cols[0].Default, cols[1].Default = false, false
	for _, id := range []string{"group_name", "member_name", "member_kind", "edge_kind", "via_path"} {
		for i := range cols {
			if string(cols[i].ID) == id {
				cols[i].Default = true
			}
		}
	}
	rowAnchor := func(id report.AnchorID) report.Anchor {
		return report.Anchor{ID: id, Table: "directory_objects", Mode: report.RowAnchor, Project: idents("object_guid"),
			Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}
	}
	return report.Dataset{
		ID: DatasetGroupMembers,
		Base: report.Relation{Table: "inventory_group_members", Where: report.SQL("{rel.grp}.state = 'live' AND {rel.mbr}.state = 'live'"),
			Joins: []report.RowJoin{
				{Anchor: "grp", On: report.SQL("{rel.grp}.connection_id = {t}.connection_id AND {rel.grp}.object_guid = {t}.group_guid")},
				{Anchor: "mbr", On: report.SQL("{rel.mbr}.connection_id = {t}.connection_id AND {rel.mbr}.object_guid = {t}.member_guid")},
			}},
		RowKey: report.SQL("{t}.group_guid::text || '|' || {t}.member_guid::text"),
		Anchors: []report.Anchor{rowAnchor("grp"), rowAnchor("mbr"),
			{ID: "via", Table: "directory_objects", Mode: report.MaskAnchor, Project: idents("connection_id", "object_guid"), Identity: idents("sam_account_name"),
				Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}},
		Columns:   cols,
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_objects", "inventory_group_members"},
	}
}

const subtreeCount = "(SELECT count(*) FROM {rel.sub} WHERE sub.connection_id = {t}.connection_id AND sub.ancestry @> ARRAY[{t}.object_guid] AND sub.state = 'live'"

func ousDataset() report.Dataset {
	cols := objectColumns()
	cols = append(cols,
		counted("subtree_objects", "Objects in the subtree", report.SQL(subtreeCount+")")),
		counted("subtree_users", "Users in the subtree", report.SQL(subtreeCount+" AND sub.kind IN ('user', 'inetorgperson'))")),
		counted("subtree_computers", "Computers in the subtree", report.SQL(subtreeCount+" AND sub.kind IN ('computer', 'gmsa'))")),
		counted("subtree_groups", "Groups in the subtree", report.SQL(subtreeCount+" AND sub.kind = 'group')")),
		counted("subtree_contacts", "Contacts in the subtree", report.SQL(subtreeCount+" AND sub.kind = 'contact')")),
		counted("subtree_ous", "Organizational units in the subtree", report.SQL(subtreeCount+" AND sub.kind = 'ou')")),
		counted("child_objects", "Objects directly in the unit",
			report.SQL("(SELECT count(*) FROM {rel.sub} WHERE sub.connection_id = {t}.connection_id AND sub.parent_guid = {t}.object_guid AND sub.state = 'live')")),
	)
	return report.Dataset{
		ID:     DatasetOUs,
		Base:   report.Relation{Table: "directory_objects", Where: report.SQL("{t}.kind = 'ou' AND {t}.state = 'live'")},
		RowKey: report.SQL("{t}.object_guid"),
		Anchors: []report.Anchor{rowAnchorT(),
			{ID: "sub", Table: "directory_objects", Mode: report.FilterAnchor, Project: idents("connection_id", "object_guid", "parent_guid", "ancestry", "kind", "state"),
				Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}},
		Columns:   cols,
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_objects"},
	}
}

func contactsDataset() report.Dataset {
	cols := objectColumns()
	cols = append(cols,
		jsonText("mail", "Email", "mail"),
		jsonText("company", "Company", "company"),
		jsonText("description", "Description", "description"),
	)
	return report.Dataset{
		ID:        DatasetContacts,
		Base:      report.Relation{Table: "directory_objects", Where: report.SQL("{t}.kind = 'contact' AND {t}.state = 'live'")},
		RowKey:    report.SQL("{t}.object_guid"),
		Anchors:   []report.Anchor{rowAnchorT()},
		Columns:   cols,
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_objects"},
	}
}

// viaHopSQL names the group at position idx (1-based) of the row's via array.
func viaHopSQL(idx string) string {
	return "COALESCE((SELECT CASE WHEN {in_scope.via} THEN via.sam_account_name ELSE " + outsideGroup + " END FROM {rel.via}" +
		" WHERE via.connection_id = {t}.connection_id AND via.object_guid = {t}.via[" + idx + "]), " + outsideGroup + ")"
}

var (
	// The hops between group and member, by name: a hop outside the scope is named only as such. A fragment
	// may not call unnest or string_agg, so the path is built by a recursive walk down the via array.
	viaPathSQL = "(WITH RECURSIVE hop(i, path) AS (SELECT 1, " + viaHopSQL("1") + " WHERE cardinality({t}.via) > 0" +
		" UNION ALL SELECT hop.i + 1, hop.path || ' → ' || " + viaHopSQL("hop.i + 1") + " FROM hop WHERE hop.i < cardinality({t}.via))" +
		" SELECT hop.path FROM hop WHERE hop.i = cardinality({t}.via))"
	findingSQL = "CASE WHEN {t}.edge_kind = 'cycle' THEN 'Circular nesting: ' || {rel.grp}.sam_account_name || COALESCE(' → ' || (" + viaPathSQL + "), '') || ' → ' || {rel.grp}.sam_account_name" +
		" WHEN {t}.cut THEN 'Nesting deeper than 128 levels: members of ' || {rel.mbr}.sam_account_name || ' and below are not listed' END"
)

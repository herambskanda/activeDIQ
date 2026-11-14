package inventory

import (
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// DatasetUsers and DatasetComputers are the EP-8 dataset IDs this package registers (reports
// contract §2, row B3).
const (
	DatasetUsers     report.DatasetID = "inventory.users"
	DatasetComputers report.DatasetID = "inventory.computers"
	// DatasetPrincipals is users and computers in one dataset, for GRP-04 (T-0962).
	DatasetPrincipals report.DatasetID = "inventory.principals"
)

// SecretKey reports whether a JSON attribute key is a secret (D8, TM-TB15-T3): the one predicate the
// writer refuses on, exported for reportsql.Options.SecretKey so a dataset can never read a secret
// attribute.
func SecretKey(key string) bool { return secretKey(key) }

// Datasets returns the datasets this package registers. compose/server hands them to report.NewHost
// with the owner key "inventory" (boot refuses them until the table-owner map lists their tables).
func Datasets() []report.Dataset {
	return []report.Dataset{usersDataset(), computersDataset(), groupsDataset(), groupMembersDataset(), ousDataset(), contactsDataset(), principalsDataset(), objectChangesDataset()}
}

func idents(s ...string) []report.Ident {
	out := make([]report.Ident, len(s))
	for i, v := range s {
		out[i] = report.Ident(v)
	}
	return out
}

func rowAnchorT() report.Anchor {
	return report.Anchor{ID: "t", Table: "directory_objects", Mode: report.RowAnchor, Project: idents("object_guid"),
		Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}
}

var (
	opsText  = []report.Op{report.OpEq, report.OpNe, report.OpIn, report.OpContains, report.OpPrefix, report.OpPresent, report.OpAbsent}
	opsEnum  = []report.Op{report.OpEq, report.OpNe, report.OpIn, report.OpPresent, report.OpAbsent}
	opsBool  = []report.Op{report.OpEq, report.OpNe, report.OpPresent, report.OpAbsent}
	opsInt   = []report.Op{report.OpEq, report.OpNe, report.OpLt, report.OpLe, report.OpGt, report.OpGe, report.OpPresent, report.OpAbsent}
	opsGUID  = []report.Op{report.OpEq, report.OpNe, report.OpIn, report.OpPresent, report.OpAbsent}
	opsTime  = []report.Op{report.OpLt, report.OpLe, report.OpGt, report.OpGe, report.OpPresent, report.OpAbsent, report.OpWithinLastDays, report.OpOlderThanDays, report.OpWithinNextDays}
	enumRank = func(ids ...string) []report.EnumValue {
		out := make([]report.EnumValue, len(ids))
		for i, id := range ids {
			out[i] = report.EnumValue{ID: id, Label: enumLabels[id], SortRank: i + 1}
		}
		return out
	}
)

var enumLabels = map[string]string{
	"locked": "Locked out", "not_locked": "Not locked out", "not_applicable": "Not applicable",
	"unknown_input_missing": "Unknown (input missing)",
	"never_account_flag":    "Never expires (account flag)", "not_applicable_smartcard": "Not applicable (smartcard required)",
	"must_change": "Must change at next logon", "never_policy": "Never expires (policy)", "expired": "Password expired", "expires": "Expires",
	"not_expired": "Not expired", "never": "Never", "recorded": "Recorded", "none_recorded": "None recorded",
	"blocked": "Blocked", "blocked_one_ace": "Blocked (one deny ACE only)", "no_deny_ace": "No deny ACE", "not_confirmed": "Not confirmed",
	"spn_set": "servicePrincipalName set", "none": "None",
	"uac_not_read": "userAccountControl not read", "lockout_time_not_read": "lockoutTime not read", "pwd_last_set_not_read": "pwdLastSet not read",
	"account_expires_not_read": "accountExpires not read", "last_logon_not_read": "lastLogonTimestamp not read",
	"activity_inputs_not_read": "pwdLastSet and lastLogonTimestamp not read", "domain_policy_not_read": "Domain password policy not read",
	"pso_set_not_read": "Password settings objects not read for this domain", "pso_not_read": "A password settings object that applies was not read",
	"pso_precedence_not_read": "A password settings object has no precedence", "pso_interval_not_read": "The password settings object's interval was not read",
	"account_inputs_not_read":  "Account attributes that select the policy (userAccountControl, SID, logon name) not read",
	"group_closure_incomplete": "Group membership closure not current or over budget, so a group-linked policy could not be ruled out",
	"workstation":              "Workstation", "server": "Server", "domain_controller": "Domain controller", "read_only_dc": "Read-only domain controller",
	"managed_account": "Group managed service account", "unconstrained": "Unconstrained", "constrained": "Constrained",
	"protocol_transition": "Constrained with protocol transition",
	"logon":               "Replicated logon", "password_set": "Password last set", "created": "Created",
}

func attr(id report.ColumnID, label string, t report.ValueType, col string, ops []report.Op, def bool) report.Column {
	return report.Column{ID: id, Label: label, Type: t, Source: report.Attr{Col: report.Ident(col)}, Filter: ops, Sortable: true, Default: def}
}

func jsonText(id report.ColumnID, label, key string) report.Column {
	return report.Column{ID: id, Label: label, Type: report.TypeText, Source: report.JSONAttr{Col: "attributes", Key: key, As: report.TypeText},
		Filter: opsText, Sortable: true}
}

func derived(id report.ColumnID, label string, t report.ValueType, sql report.Fragment, ops []report.Op) report.Column {
	return report.Column{ID: id, Label: label, Type: t, Source: report.Derived{SQL: sql}, Filter: ops, Sortable: true}
}

func state(id report.ColumnID, label string, sql report.Fragment, values ...string) report.Column {
	c := derived(id, label, report.TypeEnum, sql, opsEnum)
	c.Enum = enumRank(values...)
	return c
}

func uacFlag(id report.ColumnID, label string, sql report.Fragment) report.Column {
	return derived(id, label, report.TypeBool, sql, opsBool)
}

// baseColumns are shared by both datasets (D1, D2).
func baseColumns() []report.Column {
	enabled := attr("enabled", "Enabled", report.TypeBool, "enabled", opsBool, false)
	return []report.Column{
		attr("object_guid", "Object GUID", report.TypeGUID, "object_guid", opsGUID, true),
		attr("connection_id", "Connection", report.TypeGUID, "connection_id", opsGUID, false),
		attr("domain", "Domain (naming context)", report.TypeGUID, "nc_guid", opsGUID, false),
		attr("dn", "Distinguished name", report.TypeText, "dn", opsText, false),
		attr("sam_account_name", "Logon name (pre-Windows 2000)", report.TypeText, "sam_account_name", opsText, true),
		enabled,
		attr("when_created", "Created", report.TypeTime, "when_created", opsTime, false),
		attr("pwd_last_set", "Password last set", report.TypeTime, "pwd_last_set", opsTime, false),
		attr("last_logon_timestamp", "Last logon (replicated)", report.TypeTime, "last_logon_timestamp", opsTime, false),
		attr("primary_group_id", "Primary group ID", report.TypeInt, "primary_group_id", opsInt, false),
		attr("user_account_control", "userAccountControl", report.TypeInt, "user_account_control", opsInt, false),
		attr("observed_at", "Observed at", report.TypeTime, "observed_at", opsTime, false),
		derived("primary_group", "Primary group", report.TypeText, report.SQL(primaryGroupSQL), opsText),
		derived("in_other_groups", "Member of a group other than its primary group", report.TypeBool, report.SQL(inOtherGroupsSQL), opsBool),
		uacFlag("password_never_expires", "Password never expires (flag)", report.SQL("("+uac+" & 65536) <> 0")),
		uacFlag("smartcard_required", "Smartcard required", report.SQL("("+uac+" & 262144) <> 0")),
		uacFlag("trusted_for_delegation", "Trusted for unconstrained delegation", report.SQL("("+uac+" & 524288) <> 0")),
	}
}

func usersDataset() report.Dataset {
	cols := baseColumns()
	cols = append(cols,
		attr("user_principal_name", "User principal name", report.TypeText, "upn", opsText, false),
		attr("display_name", "Display name", report.TypeText, "display_name", opsText, true),
		attr("lockout_time", "lockoutTime", report.TypeTime, "lockout_time", opsTime, false),
		attr("account_expires", "Account expires", report.TypeTime, "account_expires", opsTime, false),
		state("locked_out", "Locked out", report.SQL(lockedOutSQL), "locked", "not_locked", "not_applicable", report.UnknownInputMissing),
		state("locked_out_reason", "Locked out: reason", report.SQL(lockReasonSQL), reasonValues("lockout_time_not_read")...),
		withUnknown(derived("lockout_ends_at", "Lockout ends", report.TypeTime, report.SQL(lockoutEndsSQL), opsTime), "locked_out"),
		state("password_state", "Password state", report.SQL(pwdStateSQL), "not_applicable", "never_account_flag", "not_applicable_smartcard",
			"must_change", "never_policy", "expired", "expires", report.UnknownInputMissing),
		state("password_state_reason", "Password state: reason", report.SQL(pwdReasonSQL), reasonValues("pwd_last_set_not_read")...),
		withUnknown(derived("password_expires_at", "Password expires", report.TypeTime, report.SQL(pwdExpiresAtSQL), opsTime), "password_state"),
		withUnknown(derived("days_to_password_expiry", "Days to password expiry", report.TypeInt, report.SQL(pwdDaysSQL), opsInt), "password_state"),
		state("pwd_set_recorded", "Password last set recorded", report.SQL(pwdSetRecordedSQL), "recorded", "none_recorded", report.UnknownInputMissing),
		withUnknown(derived("days_since_password_set", "Days since password last set", report.TypeInt, report.SQL(daysSincePwdSetSQL), opsInt), "pwd_set_recorded"),
		state("account_expired", "Account expired", report.SQL(accountExpiredSQL), "expired", "not_expired", "never", report.UnknownInputMissing),
		state("account_expired_reason", "Account expired: reason", report.SQL(accountReasonSQL), "none", "account_expires_not_read"),
		state("logon_recorded", "Replicated logon recorded", report.SQL(logonRecordedSQL), "recorded", "none_recorded", report.UnknownInputMissing),
		withUnknown(derived("days_since_logon", "Days since last logon (replicated)", report.TypeInt, report.SQL(daysSinceLogonSQL), opsInt), "logon_recorded"),
		withUnknown(derived("days_to_account_expiry", "Days to account expiry (negative: since)", report.TypeInt, report.SQL(daysToExpirySQL), opsInt), "account_expired"),
		derived("logon_sync_interval_days", "Domain logon time sync interval (days)", report.TypeInt, report.SQL(logonSyncSQL), opsInt),
		derived("policy_source", "Policy source", report.TypeText, report.SQL(policySourceSQL), opsText),
		derived("probable_service_account", "Probable service account", report.TypeBool, report.SQL(probableSvcSQL), opsBool),
		state("password_change_right", "Password change right", report.SQL(pwChangeSQL), "blocked", "blocked_one_ace", "no_deny_ace", "not_confirmed"),
		attr("descriptor_as_of", "Descriptor as of", report.TypeTime, "password_change_at", opsTime, false),
		state("probable_service_account_reason", "Service account reason", report.SQL(probableReasonSQL), "spn_set", "none"),
	)
	cols = append(cols, userPerDCColumns()...)
	return report.Dataset{
		ID:     DatasetUsers,
		Base:   report.Relation{Table: "directory_objects", Where: report.SQL("{t}.kind IN ('user', 'inetorgperson') AND {t}.state = 'live'")},
		RowKey: report.SQL("{t}.object_guid"),
		Anchors: []report.Anchor{rowAnchorT(), {ID: "pso", Table: "directory_objects", Mode: report.MaskAnchor,
			Project: idents("object_guid", "connection_id"), Identity: idents("rdn"),
			Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}, pgroupAnchor()},
		Rels: []report.Rel{
			{ID: "memb", Kind: report.RelEdge, Table: "links", Project: idents("connection_id", "source_guid", "target_guid", "link_attr"),
				Where: report.SQL("state = 'active'")},
			{ID: "clo", Kind: report.RelEdge, Table: "inventory_group_members", Project: idents("connection_id", "group_guid", "member_guid", "edge_kind", "cut")},
			{ID: "dirty", Kind: report.RelEdge, Table: "inventory_group_closure_dirty", Project: idents("connection_id")},
			{ID: "applies", Kind: report.RelEdge, Table: "inventory_pso_applies", Project: idents("connection_id", "pso_guid", "target_guid"),
				Where: report.SQL("state = 'active'")},
			{ID: "psoval", Kind: report.RelInput, Table: "inventory_psos",
				Project: idents("connection_id", "nc_guid", "pso_guid", "precedence", "max_pwd_age_secs", "lockout_duration_secs")},
			{ID: "dom", Kind: report.RelInput, Table: "inventory_domain_policies",
				Project: idents("connection_id", "nc_guid", "max_pwd_age_secs", "lockout_duration_secs", "logon_sync_interval_days", "psos_read_at")},
		},
		Columns:   cols,
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_objects", "links", "inventory_group_members", "inventory_group_closure_dirty", "inventory_pso_applies", "inventory_psos", "inventory_domain_policies"},
	}
}

// userPerDCColumns are the columns filled after the query by a live read of every DC (reports.md §6.5). The
// replicated lastLogonTimestamp lags by days; lastLogon, badPasswordTime and badPwdCount are per DC and are
// never summed: a time is the latest over the DCs that answered, a count is the count at the DC of the
// latest failed logon.
func userPerDCColumns() []report.Column {
	perDC := func(id report.ColumnID, label string, t report.ValueType, src report.PerDC, ops []report.Op) report.Column {
		return report.Column{ID: id, Label: label, Type: t, Source: src, Filter: ops, Sortable: true}
	}
	return []report.Column{
		perDC("real_last_logon", "Real last logon", report.TypeTime, report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax}, opsTime),
		perDC("real_logon_dc", "From DC", report.TypeText, report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax, Part: report.PartFromDC}, nil),
		perDC("days_since_real_logon", "Days since real logon", report.TypeInt, report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax, Part: report.PartDaysSince}, opsInt),
		perDC("dc_coverage", "DC coverage", report.TypeText, report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax, Part: report.PartCoverage}, nil),
		perDC("last_failed_logon", "Last failed logon", report.TypeTime, report.PerDC{Attr: report.PerDCBadPasswordTime, Agg: report.AggMax}, opsTime),
		perDC("failed_logon_dc", "From DC", report.TypeText, report.PerDC{Attr: report.PerDCBadPasswordTime, Agg: report.AggMax, Part: report.PartFromDC}, nil),
		perDC("failures_on_dc", "Failures on that DC", report.TypeInt,
			report.PerDC{Attr: report.PerDCBadPwdCount, Agg: report.AggMax, Part: report.PartAtWinner, Of: report.PerDCBadPasswordTime}, opsInt),
	}
}

// reasonValues are the causes of an unknown policy-dependent state, led by the account's own input.
func reasonValues(own string) []string {
	return []string{"none", "uac_not_read", own, "domain_policy_not_read", "pso_set_not_read", "pso_not_read",
		"pso_precedence_not_read", "pso_interval_not_read", "account_inputs_not_read", "group_closure_incomplete"}
}

func withUnknown(c report.Column, state report.ColumnID) report.Column {
	c.UnknownWhen = state
	return c
}

func computersDataset() report.Dataset {
	cols := baseColumns()
	cols = append(cols,
		derived("name", "Name", report.TypeText, report.SQL(nameSQL), opsText),
		state("computer_type", "Type", report.SQL(computerType), "workstation", "server", "domain_controller", "read_only_dc", "managed_account", report.UnknownInputMissing),
		state("delegation", "Delegation", report.SQL(delegationSQL), "none", "unconstrained", "constrained", "protocol_transition", report.UnknownInputMissing),
		withUnknown(derived("days_since_activity", "Days since last activity", report.TypeInt, report.SQL(daysSinceActivitySQL), opsInt), "activity_source"),
		jsonText("dns_host_name", "DNS host name", "dNSHostName"),
		jsonText("operating_system", "Operating system", "operatingSystem"),
		jsonText("operating_system_version", "Operating system version", "operatingSystemVersion"),
		uacFlag("trusted_to_auth_for_delegation", "Trusted to authenticate for delegation (protocol transition)", report.SQL("("+uac+" & 16777216) <> 0")),
		derived("constrained_delegation_present", "Constrained delegation targets set", report.TypeBool,
			report.SQL("CASE WHEN jsonb_typeof({t}.attributes -> 'msDS-AllowedToDelegateTo') = 'array' THEN jsonb_array_length({t}.attributes -> 'msDS-AllowedToDelegateTo') > 0 ELSE false END"), opsBool),
		derived("managed_service_account", "Group managed service account", report.TypeBool, report.SQL("{t}.kind = 'gmsa'"), opsBool),
		withUnknown(derived("last_activity", "Last activity", report.TypeTime, report.SQL(activitySQL), opsTime), "activity_source"),
		state("activity_source", "Activity source", report.SQL(activitySrcSQL), "logon", "password_set", "created", "none", report.UnknownInputMissing),
		state("activity_source_reason", "Activity source: reason", report.SQL(activityReasonSQL),
			"none", "pwd_last_set_not_read", "last_logon_not_read", "activity_inputs_not_read"),
	)
	return report.Dataset{
		ID:      DatasetComputers,
		Base:    report.Relation{Table: "directory_objects", Where: report.SQL("{t}.kind IN ('computer', 'gmsa') AND {t}.state = 'live'")},
		RowKey:  report.SQL("{t}.object_guid"),
		Anchors: []report.Anchor{rowAnchorT(), pgroupAnchor()},
		Rels: []report.Rel{{ID: "memb", Kind: report.RelEdge, Table: "links", Project: idents("connection_id", "source_guid", "target_guid", "link_attr"),
			Where: report.SQL("state = 'active'")}},
		Columns:   cols,
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_objects", "links"},
	}
}

// pgroupAnchor reads the primary group's name, masked when the group is outside the scope.
func pgroupAnchor() report.Anchor {
	return report.Anchor{ID: "pgrp", Table: "directory_objects", Mode: report.MaskAnchor, Project: idents("connection_id", "object_guid"), Identity: idents("sam_account_name"),
		Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}
}

// principalsDataset is the objects GRP-04 asks about, users and computers together, so one report with a
// preset per kind answers "Users Not in Groups" and "Computers Not in Groups" (spec reports-2a 6.2, 6.6). It
// shares the base columns of both datasets; the membership test is the same in_other_groups column.
func principalsDataset() report.Dataset {
	cols := baseColumns()
	cols = append(cols,
		derived("name", "Name", report.TypeText, report.SQL(userOrRdnName), opsText),
		state("object_kind", "Object type", report.SQL("CASE WHEN {t}.kind IN ('user', 'inetorgperson') THEN 'user' ELSE 'computer' END"), "user", "computer"),
	)
	return report.Dataset{
		ID:      DatasetPrincipals,
		Base:    report.Relation{Table: "directory_objects", Where: report.SQL("{t}.kind IN ('user', 'inetorgperson', 'computer', 'gmsa') AND {t}.state = 'live'")},
		RowKey:  report.SQL("{t}.object_guid"),
		Anchors: []report.Anchor{rowAnchorT(), pgroupAnchor()},
		Rels: []report.Rel{{ID: "memb", Kind: report.RelEdge, Table: "links", Project: idents("connection_id", "source_guid", "target_guid", "link_attr"),
			Where: report.SQL("state = 'active'")}},
		Columns:   cols,
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_objects", "links"},
	}
}

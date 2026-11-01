package inventory

// SQL fragments of the derived states (reports contract §3.3, spec reports-2a §6.4). Every constant is
// compile-time constant text (RP1); the compiler fills the slots. The rules, with the ad-expert
// consult of T-0958:
//
//   - A trust account (0x800, 0x1000, 0x2000: mask 14336) is never locked out and its password is
//     never evaluated. DONT_EXPIRE_PASSWORD is 0x10000 (65536), SMARTCARD_REQUIRED 0x40000 (262144),
//     NORMAL_ACCOUNT 0x200 (512).
//   - The effective policy is the single PSO that resolves, else the domain policy, never a mix. A
//     direct msDS-PSOAppliesTo beats every group-linked PSO; among the candidates of the winning tier
//     the lowest precedence wins, then the lowest objectGUID compared as the 16 raw wire bytes.
//     Group-linked PSOs come from the transitive membership and the primary group. Only NORMAL_ACCOUNT
//     users that are not krbtgt resolve a PSO.
//   - A candidate PSO that is not stored, has no precedence, or a domain whose PSO set was never read
//     leaves the policy unresolved: the states that need it are unknown_input_missing, never the
//     domain policy.
//   - Locked: lockoutTime non-zero and (duration indefinite, or now <= lockoutTime + duration).
//     Expired: pwdLastSet + max age < now, strictly. Both ages are whole seconds; 0 is "forever".
const (
	uac            = "{t}.user_account_control"
	trustMask      = "14336"
	unknown        = "'unknown_input_missing'"
	notTrustNormal = "(" + uac + " IS NOT NULL AND (" + uac + " & " + trustMask + ") = 0)"

	// wireKey orders a GUID by its 16 raw wire bytes: the uuid is stored in the canonical text order,
	// the wire form swaps the first three groups.
	wireKey = "(substring(cand.b from 4 for 1) || substring(cand.b from 3 for 1) || substring(cand.b from 2 for 1) || substring(cand.b from 1 for 1)" +
		" || substring(cand.b from 6 for 1) || substring(cand.b from 5 for 1) || substring(cand.b from 8 for 1) || substring(cand.b from 7 for 1)" +
		" || substring(cand.b from 9))"

	// eligible: NORMAL_ACCOUNT and not krbtgt (RID 502, or an RODC krbtgt_<n>).
	// A NULL (the sid or the logon name was not read) stays NULL, so the row fails closed to unresolved
	// rather than quietly taking the domain policy.
	eligible = "((" + uac + " & 512) = 512 AND substring({t}.sid from length({t}.sid) - 3) <> decode('f6010000', 'hex')" +
		" AND left(lower({t}.sam_account_name), 7) <> 'krbtgt_')"

	// resInner is one row: status (0 domain policy, 1 PSO, 2 unresolved), the PSO, the effective max
	// password age and lockout duration in seconds (NULL: not read; 0: forever), and why, the cause
	// when the status is 2 (NULL otherwise).
	resInner = "WITH RECURSIVE g(guid) AS (" +
		"SELECT memb.source_guid FROM {rel.memb} WHERE memb.connection_id = {t}.connection_id AND memb.target_guid = {t}.object_guid" +
		" UNION " +
		"SELECT memb.source_guid FROM g JOIN {rel.memb} ON memb.target_guid = g.guid AND memb.connection_id = {t}.connection_id AND memb.link_attr = 'member'" +
		"), cand AS (" +
		"SELECT applies.pso_guid, uuid_send(applies.pso_guid) AS b, 1 AS tier FROM {rel.applies}" +
		" WHERE applies.connection_id = {t}.connection_id AND applies.target_guid = {t}.object_guid" +
		" UNION ALL " +
		"SELECT applies.pso_guid, uuid_send(applies.pso_guid), 2 FROM {rel.applies}" +
		" WHERE applies.connection_id = {t}.connection_id AND applies.target_guid IN (SELECT guid FROM g)" +
		"), best AS (" +
		"SELECT cand.pso_guid, psoval.precedence, psoval.pso_guid IS NOT NULL AS stored, psoval.max_pwd_age_secs AS maxage, psoval.lockout_duration_secs AS lockdur" +
		" FROM cand LEFT JOIN {rel.psoval} ON psoval.connection_id = {t}.connection_id AND psoval.pso_guid = cand.pso_guid" +
		" WHERE cand.tier = (SELECT min(tier) FROM cand) AND (psoval.pso_guid IS NULL OR psoval.nc_guid = {t}.nc_guid)" +
		" ORDER BY psoval.precedence NULLS FIRST, " + wireKey + " LIMIT 1" +
		") SELECT s.status, s.why, s.pso, CASE s.status WHEN 0 THEN s.dmax WHEN 1 THEN s.pmax END AS maxage," +
		" CASE s.status WHEN 0 THEN s.dlock WHEN 1 THEN s.plock END AS lockdur FROM (" +
		"SELECT CASE WHEN dom.psos_read_at IS NULL THEN 2 WHEN " + eligible + " IS NULL THEN 2 WHEN NOT " + eligible + " THEN 0" +
		" WHEN EXISTS (SELECT 1 FROM best) THEN (CASE WHEN (SELECT precedence FROM best) IS NULL THEN 2 ELSE 1 END) ELSE 0 END AS status," +
		" CASE WHEN dom.nc_guid IS NULL THEN 'domain_policy_not_read' WHEN dom.psos_read_at IS NULL THEN 'pso_set_not_read'" +
		" WHEN " + eligible + " IS NULL THEN 'account_inputs_not_read'" +
		" WHEN " + eligible + " AND EXISTS (SELECT 1 FROM best) AND (SELECT precedence FROM best) IS NULL THEN" +
		" (CASE WHEN (SELECT stored FROM best) THEN 'pso_precedence_not_read' ELSE 'pso_not_read' END) END AS why," +
		" (SELECT pso_guid FROM best) AS pso, dom.max_pwd_age_secs AS dmax, dom.lockout_duration_secs AS dlock," +
		" (SELECT maxage FROM best) AS pmax, (SELECT lockdur FROM best) AS plock" +
		" FROM (SELECT 1 AS one) o LEFT JOIN {rel.dom} ON dom.connection_id = {t}.connection_id AND dom.nc_guid = {t}.nc_guid) s"

	// lockPre: the lockout inputs are read and the account can be locked out at all.
	lockPre = notTrustNormal + " AND ({t}.inputs_read & 1) <> 0 AND {t}.lockout_time IS NOT NULL"
	lockEnd = "{t}.lockout_time + res.lockdur * interval '1 second'"

	lockedOutSQL = "CASE WHEN " + uac + " IS NULL THEN " + unknown +
		" WHEN (" + uac + " & " + trustMask + ") <> 0 THEN 'not_applicable'" +
		" WHEN ({t}.inputs_read & 1) = 0 THEN " + unknown +
		" WHEN {t}.lockout_time IS NULL THEN 'not_locked'" +
		" ELSE (SELECT CASE WHEN res.lockdur IS NULL THEN " + unknown + " WHEN res.lockdur = 0 THEN 'locked'" +
		" WHEN {now} <= " + lockEnd + " THEN 'locked' ELSE 'not_locked' END FROM (" + resInner + ") res) END"

	lockoutEndsSQL = "CASE WHEN " + lockPre + " THEN (SELECT CASE WHEN res.lockdur > 0 AND {now} <= " + lockEnd + " THEN " + lockEnd +
		" END FROM (" + resInner + ") res) END"

	// cause is the reason of an unknown policy-dependent state: the status-2 cause, else the interval
	// that was not read (the domain's or the winning PSO's). res is the resInner row.
	cause = "COALESCE(res.why, CASE res.status WHEN 0 THEN 'domain_policy_not_read' ELSE 'pso_interval_not_read' END)"

	lockReasonSQL = "CASE WHEN " + uac + " IS NULL THEN 'uac_not_read'" +
		" WHEN (" + uac + " & " + trustMask + ") <> 0 THEN 'none'" +
		" WHEN ({t}.inputs_read & 1) = 0 THEN 'lockout_time_not_read'" +
		" WHEN {t}.lockout_time IS NULL THEN 'none'" +
		" ELSE (SELECT CASE WHEN res.lockdur IS NULL THEN " + cause + " ELSE 'none' END FROM (" + resInner + ") res) END"

	pwdStateSQL = "CASE WHEN " + uac + " IS NULL THEN " + unknown +
		" WHEN (" + uac + " & " + trustMask + ") <> 0 THEN 'not_applicable'" +
		" WHEN (" + uac + " & 65536) <> 0 THEN 'never_account_flag'" +
		" WHEN (" + uac + " & 262144) <> 0 THEN 'not_applicable_smartcard'" +
		" WHEN ({t}.inputs_read & 2) = 0 THEN " + unknown +
		" WHEN {t}.pwd_last_set IS NULL THEN 'must_change'" +
		" ELSE (SELECT CASE WHEN res.maxage IS NULL THEN " + unknown + " WHEN res.maxage = 0 THEN 'never_policy'" +
		" WHEN {now} > {t}.pwd_last_set + res.maxage * interval '1 second' THEN 'expired' ELSE 'expires' END FROM (" + resInner + ") res) END"

	pwdReasonSQL = "CASE WHEN " + uac + " IS NULL THEN 'uac_not_read'" +
		" WHEN (" + uac + " & " + trustMask + ") <> 0 OR (" + uac + " & 65536) <> 0 OR (" + uac + " & 262144) <> 0 THEN 'none'" +
		" WHEN ({t}.inputs_read & 2) = 0 THEN 'pwd_last_set_not_read'" +
		" WHEN {t}.pwd_last_set IS NULL THEN 'none'" +
		" ELSE (SELECT CASE WHEN res.maxage IS NULL THEN " + cause + " ELSE 'none' END FROM (" + resInner + ") res) END"

	// pwdPre: the password inputs are read, the row reaches the age rule, and pwdLastSet is set.
	pwdPre = notTrustNormal + " AND (" + uac + " & 65536) = 0 AND (" + uac + " & 262144) = 0 AND ({t}.inputs_read & 2) <> 0 AND {t}.pwd_last_set IS NOT NULL"
	pwdEnd = "{t}.pwd_last_set + res.maxage * interval '1 second'"

	pwdExpiresAtSQL = "CASE WHEN " + pwdPre + " THEN (SELECT CASE WHEN res.maxage > 0 THEN " + pwdEnd + " END FROM (" + resInner + ") res) END"
	pwdDaysSQL      = "CASE WHEN " + pwdPre + " THEN (SELECT CASE WHEN res.maxage > 0 THEN floor(extract(epoch FROM (" + pwdEnd + " - {now})) / 86400) END FROM (" + resInner + ") res) END"

	accountExpiredSQL = "CASE WHEN ({t}.inputs_read & 4) = 0 THEN " + unknown + " WHEN {t}.account_expires IS NULL THEN 'never'" +
		" WHEN {now} > {t}.account_expires THEN 'expired' ELSE 'not_expired' END"

	accountReasonSQL = "CASE WHEN ({t}.inputs_read & 4) = 0 THEN 'account_expires_not_read' ELSE 'none' END"

	// USR-02, USR-03 (T-0960). The replicated logon is "recorded" only when its input was read (bit 8): an
	// unread input is Unknown, never "no logon recorded". Whole days are floored; a negative count of days
	// to expiry is the days since expiry.
	logonRecordedSQL  = "CASE WHEN ({t}.inputs_read & 8) = 0 THEN " + unknown + " WHEN {t}.last_logon_timestamp IS NULL THEN 'none_recorded' ELSE 'recorded' END"
	daysSinceLogonSQL = "CASE WHEN ({t}.inputs_read & 8) = 0 OR {t}.last_logon_timestamp IS NULL THEN NULL" +
		" ELSE floor(extract(epoch FROM ({now} - {t}.last_logon_timestamp)) / 86400) END"
	daysToExpirySQL = "CASE WHEN ({t}.inputs_read & 4) = 0 OR {t}.account_expires IS NULL THEN NULL" +
		" ELSE floor(extract(epoch FROM ({t}.account_expires - {now})) / 86400) END"
	// The domain's msDS-LogonTimeSyncInterval in days: NULL when the domain row or the value was not read.
	logonSyncSQL = "(SELECT dom.logon_sync_interval_days FROM {rel.dom} WHERE dom.connection_id = {t}.connection_id AND dom.nc_guid = {t}.nc_guid)"

	outside = "'(policy outside your scope)'"

	policySourceSQL = "(SELECT CASE res.status WHEN 0 THEN 'Domain policy' WHEN 1 THEN COALESCE((" +
		"SELECT CASE WHEN {in_scope.pso} THEN substring(pso.rdn from position('=' in pso.rdn) + 1) ELSE " + outside + " END" +
		" FROM {rel.pso} WHERE pso.connection_id = {t}.connection_id AND pso.object_guid = res.pso), " + outside + ")" +
		" ELSE 'Unknown (policy not resolved)' END FROM (" + resInner + ") res)"

	notKrbtgt = "substring({t}.sid from length({t}.sid) - 3) IS DISTINCT FROM decode('f6010000', 'hex')"

	probableSvcSQL    = "CASE WHEN {t}.spn_present IS NULL THEN NULL ELSE ({t}.spn_present AND " + notKrbtgt + ") END"
	probableReasonSQL = "CASE WHEN {t}.spn_present IS NULL THEN NULL WHEN {t}.spn_present AND " + notKrbtgt + " THEN 'spn_set' ELSE 'none' END"

	// CMP-02: the later of the replicated logon and pwdLastSet; whenCreated when neither is set.
	activityKnown  = "({t}.inputs_read & 10) = 10"
	activitySQL    = "CASE WHEN NOT " + activityKnown + " THEN NULL WHEN GREATEST({t}.last_logon_timestamp, {t}.pwd_last_set) IS NOT NULL THEN GREATEST({t}.last_logon_timestamp, {t}.pwd_last_set) ELSE {t}.when_created END"
	activitySrcSQL = "CASE WHEN NOT " + activityKnown + " THEN " + unknown +
		" WHEN GREATEST({t}.last_logon_timestamp, {t}.pwd_last_set) IS NULL THEN CASE WHEN {t}.when_created IS NULL THEN 'none' ELSE 'created' END" +
		" WHEN {t}.last_logon_timestamp IS NOT NULL AND ({t}.pwd_last_set IS NULL OR {t}.last_logon_timestamp >= {t}.pwd_last_set) THEN 'logon' ELSE 'password_set' END"

	activityReasonSQL = "CASE WHEN " + activityKnown + " THEN 'none' WHEN ({t}.inputs_read & 10) = 0 THEN 'activity_inputs_not_read'" +
		" WHEN ({t}.inputs_read & 2) = 0 THEN 'pwd_last_set_not_read' ELSE 'last_logon_not_read' END"

	// PWD-02 (T-0962). pwdLastSet 0 is stored as NULL with its input read: the account must change its
	// password at next logon, which is "none recorded", not "unread".
	pwdSetRecordedSQL  = "CASE WHEN ({t}.inputs_read & 2) = 0 THEN " + unknown + " WHEN {t}.pwd_last_set IS NULL THEN 'none_recorded' ELSE 'recorded' END"
	daysSincePwdSetSQL = "CASE WHEN ({t}.inputs_read & 2) = 0 OR {t}.pwd_last_set IS NULL THEN NULL" +
		" ELSE floor(extract(epoch FROM ({now} - {t}.pwd_last_set)) / 86400) END"

	// CMP-01 and CMP-02 (T-0962). The type follows the account, not a guess: a gMSA by class, a read-only DC by
	// PARTIAL_SECRETS_ACCOUNT (0x4000000), a DC by SERVER_TRUST_ACCOUNT (0x2000), then the operating system name
	// (a name with "server" is a server, spec 6.2). No operating system name and no DC flag is Unknown: the
	// report never calls an unlabelled machine a workstation.
	osName       = "jsonb_typeof({t}.attributes -> 'operatingSystem')"
	computerType = "CASE WHEN {t}.kind = 'gmsa' THEN 'managed_account' WHEN " + uac + " IS NULL THEN " + unknown +
		" WHEN (" + uac + " & 67108864) <> 0 THEN 'read_only_dc' WHEN (" + uac + " & 8192) <> 0 THEN 'domain_controller'" +
		" WHEN " + osName + " IS DISTINCT FROM 'string' THEN " + unknown +
		" WHEN position('server' in lower({t}.attributes ->> 'operatingSystem')) > 0 THEN 'server' ELSE 'workstation' END"
	// Delegation: unconstrained (0x80000, DCs carry it too), else constrained when msDS-AllowedToDelegateTo has a
	// target, with protocol transition when TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) is also set.
	delegationTargets = "(CASE WHEN jsonb_typeof({t}.attributes -> 'msDS-AllowedToDelegateTo') = 'array' THEN jsonb_array_length({t}.attributes -> 'msDS-AllowedToDelegateTo') > 0 ELSE false END)"
	delegationSQL     = "CASE WHEN " + uac + " IS NULL THEN " + unknown + " WHEN (" + uac + " & 524288) <> 0 THEN 'unconstrained'" +
		" WHEN " + delegationTargets + " THEN (CASE WHEN (" + uac + " & 16777216) <> 0 THEN 'protocol_transition' ELSE 'constrained' END) ELSE 'none' END"
	daysSinceActivitySQL = "floor(extract(epoch FROM ({now} - (" + activitySQL + "))) / 86400)"

	// The object's own name: the value of the RDN ("CN=PC01" is PC01). A user shows the display name when set.
	rdnName       = "substring({t}.rdn from position('=' in {t}.rdn) + 1)"
	nameSQL       = rdnName
	userOrRdnName = "CASE WHEN {t}.kind IN ('user', 'inetorgperson') THEN COALESCE(NULLIF({t}.display_name, ''), " + rdnName + ") ELSE " + rdnName + " END"
)

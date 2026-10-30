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
	eligible = "COALESCE((" + uac + " & 512) = 512 AND substring({t}.sid from length({t}.sid) - 3) <> decode('f6010000', 'hex')" +
		" AND left(lower({t}.sam_account_name), 7) <> 'krbtgt_', false)"

	// resInner is one row: status (0 domain policy, 1 PSO, 2 unresolved), the PSO, the effective max
	// password age and lockout duration in seconds (NULL: not read; 0: forever).
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
		"SELECT cand.pso_guid, psoval.precedence, psoval.max_pwd_age_secs AS maxage, psoval.lockout_duration_secs AS lockdur" +
		" FROM cand LEFT JOIN {rel.psoval} ON psoval.connection_id = {t}.connection_id AND psoval.pso_guid = cand.pso_guid" +
		" WHERE cand.tier = (SELECT min(tier) FROM cand) AND (psoval.pso_guid IS NULL OR psoval.nc_guid = {t}.nc_guid)" +
		" ORDER BY psoval.precedence NULLS FIRST, " + wireKey + " LIMIT 1" +
		") SELECT s.status, s.pso, CASE s.status WHEN 0 THEN s.dmax WHEN 1 THEN s.pmax END AS maxage," +
		" CASE s.status WHEN 0 THEN s.dlock WHEN 1 THEN s.plock END AS lockdur FROM (" +
		"SELECT CASE WHEN dom.psos_read_at IS NULL THEN 2 WHEN NOT " + eligible + " THEN 0" +
		" WHEN EXISTS (SELECT 1 FROM best) THEN (CASE WHEN (SELECT precedence FROM best) IS NULL THEN 2 ELSE 1 END) ELSE 0 END AS status," +
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

	pwdStateSQL = "CASE WHEN " + uac + " IS NULL THEN " + unknown +
		" WHEN (" + uac + " & " + trustMask + ") <> 0 THEN 'not_applicable'" +
		" WHEN (" + uac + " & 65536) <> 0 THEN 'never_account_flag'" +
		" WHEN (" + uac + " & 262144) <> 0 THEN 'not_applicable_smartcard'" +
		" WHEN ({t}.inputs_read & 2) = 0 THEN " + unknown +
		" WHEN {t}.pwd_last_set IS NULL THEN 'must_change'" +
		" ELSE (SELECT CASE WHEN res.maxage IS NULL THEN " + unknown + " WHEN res.maxage = 0 THEN 'never_policy'" +
		" WHEN {now} > {t}.pwd_last_set + res.maxage * interval '1 second' THEN 'expired' ELSE 'expires' END FROM (" + resInner + ") res) END"

	// pwdPre: the password inputs are read, the row reaches the age rule, and pwdLastSet is set.
	pwdPre = notTrustNormal + " AND (" + uac + " & 65536) = 0 AND (" + uac + " & 262144) = 0 AND ({t}.inputs_read & 2) <> 0 AND {t}.pwd_last_set IS NOT NULL"
	pwdEnd = "{t}.pwd_last_set + res.maxage * interval '1 second'"

	pwdExpiresAtSQL = "CASE WHEN " + pwdPre + " THEN (SELECT CASE WHEN res.maxage > 0 THEN " + pwdEnd + " END FROM (" + resInner + ") res) END"
	pwdDaysSQL      = "CASE WHEN " + pwdPre + " THEN (SELECT CASE WHEN res.maxage > 0 THEN floor(extract(epoch FROM (" + pwdEnd + " - {now})) / 86400) END FROM (" + resInner + ") res) END"

	accountExpiredSQL = "CASE WHEN ({t}.inputs_read & 4) = 0 THEN " + unknown + " WHEN {t}.account_expires IS NULL THEN 'never'" +
		" WHEN {now} > {t}.account_expires THEN 'expired' ELSE 'not_expired' END"

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
)

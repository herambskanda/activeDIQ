# T-1267 win lab bootstrap on GSSAPI + channel binding (2026-11-05)

dc1 at LDAPServerIntegrity=2 / LdapEnforceChannelBindingTokens=2 (checked before and after). Keytab for svc-activediq made with `gssapi-lab keytab` (ktpass AES256, existing password kept); server booted with WIN_LAB_SVC_KEYTAB, no password. Run: `with-dc1-lock lab/e2e/live-user-search.sh`.

```
LDAPServerIntegrity = 2
LdapEnforceChannelBindingTokens = 2
Default Domain Controllers Policy GptTmpl.inf LDAPServerIntegrity = 2
cleartext simple bind to 192.168.1.250:389 as svc-activediq@win.activediq.test -> resultCode 8 (strongerAuthRequired)
dc1-policy: enforced (LDAPServerIntegrity=2, LdapEnforceChannelBindingTokens=2, cleartext bind of a valid account refused with 8)
window: 2026-11-05T19:43:23.763Z .. 2026-11-05T19:44:52.524Z
event 2887: 0
event 3039: 0
event 3074: 0
event 2889: 0  (recorded, not judged)
event 3040: 0  (recorded, not judged)
event 3041: 0  (recorded, not judged)
event 3075: 0  (recorded, not judged)
dc1-evidence: ok
svc-activediq direct member of: (only the primary group)
  Domain Admins (S-1-5-21-3048684280-3061665338-2348266937-512): not a member (recursive)
  Schema Admins (S-1-5-21-3048684280-3061665338-2348266937-518): not a member (recursive)
  Enterprise Admins (S-1-5-21-3048684280-3061665338-2348266937-519): not a member (recursive)
  Administrators (S-1-5-32-544): not a member (recursive)
dc1-evidence: ok
2026/11/05 19:44:43 INFO server: lab connection active (in-process connector) lab=win connection_id=e7e7cdab-1b92-4f2e-8095-8566fb0c123e tenant_id=68bb090d-8854-4032-95be-962fe58cac67
```

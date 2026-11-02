# T-0148: channel-binding acceptance on dc1 (2026-11-02)

Acceptance (T-0148, TM-TB3-T3): with LDAP signing required and channel binding Always, the connector's SASL binds over TLS succeed and
the DC logs none of 2887, 3039, 3074, 3075. Driver: `lab/windows/bin/gssapi-lab accept` (runbook windows-lab.md section 19), under
`lab/windows/bin/with-dc1-lock`, dc1 = Proxmox VM 119 at 192.168.1.250 (A-0032), WinRM 5985 NTLM (A-0025). No secret appears here.

## dc1 state

| | before | after |
| --- | --- | --- |
| `NTDS\Parameters\LDAPServerIntegrity` | 2 | 2 |
| `NTDS\Parameters\LdapEnforceChannelBindingTokens` | 2 | 2 |
| Default Domain Controllers Policy template `LDAPServerIntegrity` | 4,2 | 4,2 |
| cleartext simple bind of `svc-activediq` to 389 (`dc1-policy check`) | resultCode 8 strongerAuthRequired | resultCode 8 |
| `16 LDAP Interface Events` | 0 | 0 (2 only during the run) |
| clock, dc minus host | -0.22 s | not changed (NTP since T-0850; the driver refuses a skew over 60 s and never steps the clock) |

## Code under test

`factory/T-0148` = main + the done-but-unmerged lab branches T-0846 (go-krb5 PA-FX-FAST fix, makes `ad.Open` bind to WS2025), T-0850 (dc1 NTP),
T-1265 (policy guard) and T-1279 (no default DC address). They were merged into this branch because the merge queue had not landed them (T-1296).

## Result: PASSED

Real run, 2026-11-02 09:57:19Z .. 09:57:38Z (full output of `dc1-policy check; gssapi-lab accept; dc1-policy check`):

```
started 2026-11-02T09:57:19Z
c5e5b9633
LDAPServerIntegrity = 2
LdapEnforceChannelBindingTokens = 2
Default Domain Controllers Policy GptTmpl.inf LDAPServerIntegrity = 2
cleartext simple bind to 192.168.1.250:389 as svc-activediq@win.activediq.test -> resultCode 8 (strongerAuthRequired)
dc1-policy: enforced (LDAPServerIntegrity=2, LdapEnforceChannelBindingTokens=2, cleartext bind of a valid account refused with 8)
CLOCK: dc minus host = -1 day, 23:59:59.778847
DIAG prior 16 LDAP Interface Events = 0
== A. correct bindings: signing required + CBT Always
=== RUN   TestWindowsLabKerberosKeytabBindWithChannelBinding
--- PASS: TestWindowsLabKerberosKeytabBindWithChannelBinding (0.02s)
=== RUN   TestWindowsLabKerberosGMSAKeytabBind
--- PASS: TestWindowsLabKerberosGMSAKeytabBind (0.04s)
=== RUN   TestWindowsLabKerberosOpenKeytabBind
--- PASS: TestWindowsLabKerberosOpenKeytabBind (0.04s)
=== RUN   TestWindowsLabKerberosOpenGMSABind
--- PASS: TestWindowsLabKerberosOpenGMSABind (0.04s)
PASS
ok  	github.com/skenzeriq/activediq/internal/connector/ad	0.152s

== B. control: a wrong binding must be refused and logged
=== RUN   TestWindowsLabKerberosWrongChannelBindingRejected
--- PASS: TestWindowsLabKerberosWrongChannelBindingRejected (0.04s)
PASS
ok  	github.com/skenzeriq/activediq/internal/connector/ad	0.057s

control window (wrong binding): 1 event(s)
  id=3039 2026-11-02T09:57:28.6562414Z The following client performed an LDAP bind over SSL/TLS and failed the channel binding token validation. Either the cli
window of the correct binds: dc1 2026-11-02T09:57:24.622Z .. 2026-11-02T09:57:26.459Z (+-1 s), ids queried [2886, 2887, 2888, 2889, 3039, 3040, 3041, 3074, 3075]
correct-binding window: 0 event(s)
DIAG restored
POLICY after:
LDAPServerIntegrity = 2
LdapEnforceChannelBindingTokens = 2
ACCEPTANCE PASSED: correct SASL-over-TLS binds succeeded with signing required + CBT Always and dc1 logged none of [2887, 3039, 3074, 3075]
gssapi-lab exit=0
LDAPServerIntegrity = 2
LdapEnforceChannelBindingTokens = 2
Default Domain Controllers Policy GptTmpl.inf LDAPServerIntegrity = 2
cleartext simple bind to 192.168.1.250:389 as svc-activediq@win.activediq.test -> resultCode 8 (strongerAuthRequired)
dc1-policy: enforced (LDAPServerIntegrity=2, LdapEnforceChannelBindingTokens=2, cleartext bind of a valid account refused with 8)
dc1-policy exit=0
finished 2026-11-02T09:57:38Z
```

Reading it: the four correct-binding tests (keytab and gMSA identities, through the test handshake and through `ad.Open`) passed; the DC's
Directory Service log has **no event of 2886, 2887, 2888, 2889, 3039, 3040, 3041, 3074, 3075** between 09:57:24.6Z and 09:57:26.5Z
(+-1 s) on dc1's own clock; the control (wrong channel binding, refused with ldap 49) produced one 3039 at 09:57:28.7Z, so the query sees
events. An earlier run at 09:55 passed the same way (control 3039 at 09:55:04Z, window empty).

Limits worth knowing: 2887 is a DC summary logged at most once per 24 h, so its absence in a 2-second window is weak evidence by itself;
in the 26 h before the run dc1's log holds six events of the queried ids: five `3039` (four are this ticket's controls and its broken run; one is at
2026-11-01 15:35Z from an earlier session) and one `2889` at 2026-11-01 15:35Z (a SASL bind without signing, logged while dc1 was at
LDAPServerIntegrity=1, before T-1265); no 2887, 3074 or 3075 at all. 3074/3075 are the audit-mode events of the "when supported" settings
[UNVERIFIED: ids taken from the ticket], which cannot fire at 2/2.

## Broken run: the acceptance bites

The wrong-binding test moved into the "correct binds" list (temporary edit, reverted), same dc1, 09:56:59Z:

```
ACCEPTANCE FAILED: event 3039 at 2026-11-02T09:57:01.2314394Z logged during correct binds: The following client performed an LDAP bind over SSL/TLS and failed the channel binding token validation. ...
correct-binding window: 1 event(s)
  id=3039 2026-11-02T09:57:01.2314394Z ...
exit=1
```

Offline mutations of `lab/windows/lib/cbtevents.py` (`python3 -m unittest lab/windows/tests/test_cbt_acceptance.py`, 14 tests):
dropping 3075 from the judged ids -> 3 tests red; `passed_tests` accepting every name -> 2 red; `violations()` returning nothing -> 4 red
(one per event); `control_seen` always true -> 1 red.

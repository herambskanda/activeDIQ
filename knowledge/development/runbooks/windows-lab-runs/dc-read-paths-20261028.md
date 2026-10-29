---
title: Windows DC proof — tokenGroups, effective rights, SD read (no SACL), LDAPS policy
status: draft
owner: test-engineer
ticket: T-0210
---
# Windows DC read-path proof (T-0210, 2026-10-28)

Tests: `internal/connector/ad/windows_lab_dcrights_test.go` (tags `lab,windowslab`), run by
`make lab-test-connector-windows` (filter `^TestWindowsLab`). Run against dc1 (Windows Server 2025,
`192.168.1.9`) with the main checkout's lab env/CA via `WIN_LAB_ENV`, `WIN_LAB_CA`, `WIN_LAB_DC_ADDR`.

| Behaviour | Windows result |
| --- | --- |
| tokenGroups on a base Read (by GUID and by DN) | transitive, includes Domain Users (RID 513); a search asking for it is refused by the connector (`AttributeNotAllowed`) |
| allowedChildClassesEffective | none at the domain root; `organizationalUnit group user computer` on `OU=Managed` |
| allowedAttributesEffective on OU=Managed | **0 values** — the delegation is create-child only (Samba lab not compared); logged, not asserted |
| sDRightsEffective | present, SACL bit (8) not granted |
| Critical SD-flags control (7) | domain root, OU=Managed, svc-activediq, Domain Admins: header has no SE_SACL_PRESENT, offsetSacl 0, DACL present |
| LDAPS simple bind with signing policy | success |
| Plaintext simple bind on 389 | **result 8 strongerAuthRequired**, `DSID-0C090343` "server requires binds to turn on integrity checking" → LDAP signing is required on dc1 |

## Gap (AC2, honest)
`LdapEnforceChannelBinding=2` cannot be read or set from Go, and no registry/GPO access to dc1 was
available to this ticket, so the value itself is **not verified**. What is proven: signing is
enforced (code 8 above) and the LDAPS simple bind succeeds. Channel binding gates SASL
(Kerberos/NTLM) binds, which the connector does not do over LDAPS here; the GSSAPI+CBT path is T-0023.
Follow-up: verify `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding` on dc1.

## Proof the tests bite
Inverting the offsetSacl assertion fails `TestWindowsLabReadSecurityDescriptorNoSACL` for every target
(header `01 00 04 8c 34 08 00 00 40 08 …`, offsetSacl 0); restoring passes.

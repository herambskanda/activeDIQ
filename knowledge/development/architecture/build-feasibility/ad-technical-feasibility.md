---
title: "activeDIQ Technical Feasibility & Build Blueprint"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
sources_last_checked: 2026-10-02
---

# activeDIQ Technical Feasibility & Build Blueprint

> **Scope.** This document answers four questions:
> - Can skenzeriq build a replacement for the ManageEngine AD suite (ADManager Plus, ADAudit Plus, ADSelfService Plus, RecoveryManager Plus, M365 Manager Plus) on the house Go / React / PostgreSQL platform?
> - Which parts must be Windows-native?
> - How do we keep a Tier-0 product from becoming the attack path?
> - In what order should we build it?
>
> **Conventions.**
> - `[UNVERIFIED]`: not confirmed from a primary source on 2026-10-02.
> - `[LAB]`: must be proven in the Phase-0 lab.
> - `[EST]`: an engineering estimate.
> - Complexity (Cx): **S** = 2 engineer-weeks or less · **M** = 2–6 · **L** = 6–16 · **XL** = more than 16, or research risk.
> - "WS2025" means Windows Server 2025.
>
> All versions and dates are as of 2026-10-02.

---

## 0. Executive summary

**Verdict: feasible.** Every capability family can be built.
- About two-thirds of the product `[EST]` can run cross-platform in Go over standard protocols: LDAP v3, Kerberos, SMB2/3, MS-RPC and Microsoft Graph.
- The rest **must** run Windows-native code:
  1. a password-filter DLL inside LSASS on every writable DC;
  2. a credential-provider DLL inside LogonUI, for password reset at logon;
  3. event collection on DCs and file servers (an agent or WEF);
  4. NTFS effective-access calculation and bulk ACL changes on file servers;
  5. optional tasks that need GPMC or PowerShell for parity, such as GPMC-format reports and Exchange Online cmdlets.

**Stack recommendation.**
- **Go** for the server and the Windows/DC agent.
- **Rust by default (C++ fallback)** for the two in-process Windows DLLs.
- **Swift** for macOS and **C** for Linux PAM.
- A small **.NET 10 / PowerShell 7.6 sidecar** only for Exchange Online and GPMC parity.
- Go cannot be used for DLLs that LSASS or LogonUI load: a Go c-shared DLL cannot be unloaded ([golang/go#11100](https://github.com/golang/go/issues/11100)).

**2026 facts that shape the design.**
- On new WS2025 deployments, DCs require LDAP signing (sealing) after a SASL bind. Confidential attributes can only be read or written over encrypted connections. KDCs no longer issue RC4 TGTs ([WS2025 what's new](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025)).
- NTLM is deprecated, and NTLMv1 has been removed ([deprecated features](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features)).
- go-ldap's Kerberos bind does **not** negotiate SASL signing or sealing, and supports channel binding **only** through Windows SSPI ([go-ldap PR #565](https://github.com/go-ldap/ldap/pull/565)).
- gokrb5 v8 has been dormant since 2023. Its maintained successor, [go-krb5/krb5](https://github.com/go-krb5/krb5), has RFC 3244 set-password and S4U. Its channel bindings exist **only on `main`**, not in the v0.1.0 tag ([#117](https://github.com/go-krb5/krb5/pull/117); T-0023 findings, `t-0023-ldap-gssapi-cbt-spike.md`). We therefore own a small GSSAPI adapter, pin go-krb5/krb5 to a `main` commit, and run LDAP over TLS (LDAPS or StartTLS).

**Long poles.**
1. The password filter, plus **Microsoft's file-signing service for LSA plug-ins** (mandatory under LSA protection).
2. The credential provider. This is exactly where ManageEngine shipped SYSTEM-level bugs.
3. Editing GPO settings, and GPO reports that match GPMC.
4. The audit pipeline at DC scale. Microsoft plans for about 3,000 events/s per Windows event collector (WEC).
5. An effective-permissions engine for AD and NTFS.

**Tier-0 posture.** The *main server is not Tier 0 by default*:
- No Domain Admin account.
- Change tracking uses DirSync with `OBJECT_SECURITY`, not replication rights.
- AdminSDHolder-protected accounts are out of scope.
- Tier-0 actions run only through an optional, separately deployed Tier-0 connector with approvals.
- DC agents connect outbound only and accept a closed set of typed commands.

**Injection bug classes are removed by construction.** We use typed primitives: an LDAP filter syntax tree; a DN type plus `<GUID=…>` binding; a binary security-descriptor model; PowerShell called only with typed parameters; and `sqlc` + `set_config($1)` + `FORCE ROW LEVEL SECURITY` for SQL. Lint rules and fuzzing enforce them.

**ManageEngine's CVE record is our requirements list.**
- NVD lists **153 CVEs** for its AD-family products since 2019.
- Top classes: SQL injection (34), XSS (26), unrestricted upload (18), OS/command injection (10).
- **21 of 24** ADAudit Plus CVEs published in 2024 were SQL injection.
- **3** are on CISA KEV; 2 of those have known ransomware use.

**Lab.**
- Samba 4.25 AD DC in Docker covers most LDAP, Kerberos and password tests on macOS and in Linux CI.
- It does *not* cover Windows event logs, AD Web Services / the AD PowerShell module, client-side GPO processing, or WS2025 hardening behaviour.
- Windows Server is **x64-only**, so Apple-silicon Macs cannot host DCs. Use Azure or an x86 lab box. In Azure, 2 DCs + 1 member server cost **≈ $71–$89/month at 220 h** with auto-shutdown, or **≈ $168–$229/month running 24×7** (East US, pay-as-you-go).

**Build order.**
- First: tenancy/RBAC core, the safe-primitive library, the directory connector, and the job + audit-log engine.
- Then Phase 0 (≈ 8 weeks, `[EST]`): spikes that de-risk LDAP hardening interop, the password filter, the credential provider, event ingestion at scale and GPO parsing.

---

## 1. Capability → implementation table

How to read the table:
- "Windows-native?" means a component must run on Windows: an agent, a DLL, or a Windows-only API or tool. "No" means it can be done from Linux, Docker or macOS over the network.
- OIDs are written in full the first time. After that, `…NNN` is short for `1.2.840.113556.1.4.NNN`.

### 1.1 Directory management (ADManager Plus parity)

| Capability | Approach | Cx | Windows-native? | Key risks | Authoritative source |
|---|---|---|---|---|---|
| Directory read & discovery | LDAPS (636) or StartTLS. Kerberos SASL bind through **our own GSSAPI adapter on go-krb5/krb5 with channel binding (CBT)**. Find DCs via DNS SRV. Cache rootDSE and schema. Paged search with control `1.2.840.113556.1.4.319`. Typed decoding of GUID, SID, FILETIME and large integers. | M | No | DCs that enforce signing or channel binding reject naive binds. GC vs DC read semantics. Referrals in multi-domain forests. | [LDAP signing & CBT](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing); [RFC 2696](https://www.rfc-editor.org/rfc/rfc2696); [MS-ADTS LDAP controls](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea) |
| Directory write (create, modify, move, rename, delete) | LDAP add / modify / modDN. Address objects by **`<GUID=…>`**, never by a user-supplied DN. Use `PERMISSIVE_MODIFY` (…1413) for idempotent value changes. `TREE_DELETE` (…805) only after approval. | M | No | RDN escaping. Replication latency, so pin one DC per job for read-your-writes. | [Alternative DN forms](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/92a54869-38d7-4e71-a3be-5f67a0dcdd7e); [LDAP controls](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea) |
| Bulk operations (CSV import, templated mass create/modify) | Job engine: dry-run diff, then approval, then per-object operations with idempotency keys, rate limits, DC affinity and resumable checkpoints. Optionally, small all-or-nothing batches via **`LDAP_SERVER_BATCH_REQUEST_OID` (…2212, WS2012+)**: earlier operations roll back on the first failure; limits are MaxBatchReturnMessages 1,100 and MaxQueryDuration 120 s. Sent with go-ldap's generic `Conn.Extended` `[LAB]`. | M | No | AD has no RFC 5805 transactions. Defining partial-failure UX. Load on DCs. | [Batch request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ee97400e-e551-4b4a-9a60-998e89493b3c); [LDAP extended ops](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/962a5f25-f541-48a6-b73c-da01f1b7fc69); [LDAP policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99); [go-ldap extended.go](https://github.com/go-ldap/ldap/blob/master/v3/extended.go) |
| Password **reset** (helpdesk, self-service) | LDAPS modify-replace of `unicodePwd`, value = UTF-16LE `"<pwd>"` with the quotes. Needs an encrypted connection and the User-Force-Change-Password right `00299570-246d-11d0-a768-00aa006e0529`. Add **`LDAP_SERVER_POLICY_HINTS_OID` (…2239, flags = 1, WS2012+)** so resets enforce password history and minimum age. | S | No | Without the hint, admin resets silently skip history. Never log the payload. Turn `constraintViolation` into a useful message. | [unicodePwd](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2); [policy hints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4add7bce-e502-4e0f-9d69-1a3f153713e2); [control access rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb) |
| Password **change** (user knows the old password) | (a) One LDAPS modify that deletes the old `unicodePwd` value and adds the new one; or (b) Kerberos kpasswd (RFC 3244, TCP/UDP 464). AD also accepts the *set* form, with `targname`. | S | No | gokrb5 v8 `ChangePasswd` can only change the caller's own password. The set form needs go-krb5/krb5 `SetPasswd`. | [RFC 3244](https://www.rfc-editor.org/rfc/rfc3244); [MS-KILE change/set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/00380d42-3b3f-456c-945f-8685bd189bed); [go-krb5/krb5](https://github.com/go-krb5/krb5) |
| SAMR fallback (only if LDAPS is impossible) | MS-SAMR `SamrUnicodeChangePasswordUser4` (opnum 73, AES), or `SamrSetInformationUser2` with the AES information classes 31/32, via [go-msrpc](https://github.com/oiweiwei/go-msrpc) `samr`. | M | No | WS2025 DCs block the legacy SAMR change methods remotely by default. For Protected Users, every remote SAMR change is blocked, including User4. | [User4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/bbc1c5e5-9b81-4038-b2b9-c87d3569ed38); [info classes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6); [WS2025](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025) |
| Unlock / enable / disable / expire / must-change-at-logon | `lockoutTime = 0` (also resets `badPwdCount` and triggers urgent replication). `userAccountControl` bits. `accountExpires`. `pwdLastSet = 0` forces a change at next logon (other accepted values are `[UNVERIFIED]`). | S | No | Finding the lockout source needs per-DC data plus events 4740/4771. | [lockoutTime](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/85edb873-7549-401f-9108-01c128b875cb); [pwdLastSet](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/c3e2da33-f158-4a44-9a59-ec2729825c2e) |
| Groups (very large, nested) | Add/delete individual `member` values. Ranged reads `member;range=0-1499` (MaxValRange 1,500). `memberOf` is a read-only backlink. The primary group is in `primaryGroupID`, not `member`. Nested lookups via `…1941` (`IN_CHAIN` / `TRANSITIVE_EVAL`, link attributes only). | M | No | `…1941` is CPU-heavy on high fan-out; precompute the closure from snapshots instead. | [Range retrieval](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e27b48db-6f82-44cd-9038-2e54f790cc1f); [TRANSITIVE_EVAL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1e889adc-b503-4423-8985-c28d5c7d4887) |
| OU / computer / contact / gMSA / dMSA; LAPS read | Standard CRUD and computer pre-staging. Read Windows LAPS only with explicit rights over an encrypted connection. | M | Decrypting *encrypted* Windows LAPS passwords (DPAPI-NG) from Linux is `[UNVERIFIED]` | WS2025 requires encryption for confidential attributes. dMSA creation rights are abused by BadSuccessor. | [WS2025](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025); [Akamai BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) |
| Fine-grained password policies (FGPP) | CRUD on `msDS-PasswordSettings` objects in `CN=Password Settings Container,CN=System`. The effective policy is the constructed `msDS-ResultantPSO` (domain functional level 2008+; lowest precedence wins). | S | No | Precedence and tie-break rules. | [PSO container](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/99f7fd20-c7ab-44ce-a891-bfe49325ce3e); [msDS-ResultantPSO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ad735d45-ba6a-42fc-a41c-e91ced8e72d9) |
| AD delegation / ACL management and "who can do what" reports | Read `nTSecurityDescriptor` with `SD_FLAGS` (…801; DACL = 0x4) into a typed binary security-descriptor model; write the DACL only. Implement AD access checks: object and inherited-object-type ACEs, property sets, extended rights, validated writes. Expand principals with `tokenGroups`. | L | No | Must match Windows "Effective Access" exactly. Scale at 1M+ objects. Writing a SACL needs SeSecurityPrivilege (a Tier-0 operation). | [SD_FLAGS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0); [control access rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb); [ACE order](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl) |

### 1.2 Reporting & change tracking

| Capability | Approach | Cx | Windows-native? | Key risks | Authoritative source |
|---|---|---|---|---|---|
| Paged and ranged retrieval at scale | Paged search (MaxPageSize 1,000). Ranged reads for multi-valued attributes (1,500). VLV `2.16.840.1.113730.3.4.9` for UI windows. Filter only on indexed attributes. Full sync per naming context (NC), then incremental. | M | No | Limits: MaxQueryDuration 120 s, MaxResultSetSize 262,144 bytes, MaxConnIdleTime 900 s. DCs flag expensive or inefficient searches as event 1644 (default thresholds 10,000 / 1,000 entries / 30 s). | [LDAP policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99); [Event 1644](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/event1644reader-analyze-ldap-query-performance) |
| Last logon / stale accounts | Coarse: `lastLogonTimestamp`. It replicates, but only updates when older than `msDS-LogonTimeSyncInterval` (default 14 days) minus a random 0–5 days, so it lags 9–14 days. Exact: the maximum `lastLogon` across **every** DC (not replicated). Optionally events 4624/4768. | S–M | No | Unreachable DCs and RODCs. Clock skew. | [Ask DS: lastLogonTimestamp](https://techcommunity.microsoft.com/blog/askds/8220the-lastlogontimestamp-attribute8221-8211-8220what-it-was-designed-for-and-how-it-works8221/396204); [lastLogon](https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogon) |
| Effective / nested membership | `tokenGroups`: constructed, base-scope only, absent if no GC is available. `tokenGroupsGlobalAndUniversal` needs membership of the *Windows Authorization Access Group*. For bulk reports, compute the closure from the snapshot graph in Postgres. | M | No | Cross-forest foreign security principals. GC availability. | [tokenGroups](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/01002598-92db-4c59-822e-b22f53168c90); [TGGAU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a366b6b6-f36f-46e8-ba2d-af79bf8966bf); [security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) |
| Large domains (500k+ objects) | Parallel paged reads per NC or OU, bounded by the DC's MaxPoolThreads (4 per CPU). Ingest into Postgres with `COPY`. Diff snapshots, then switch to DirSync for increments. | L | No | CPU impact on DCs; customer change windows. | [LDAP policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99) |
| Change tracking: **DirSync** (default) | `LDAP_SERVER_DIRSYNC_OID` (…841). Base must be the NC root. Flags: **`OBJECT_SECURITY` 0x1**, so no replication right is needed and only data the account can read is returned; plus `INCREMENTAL_VALUES` 0x80000000. One cookie per NC. Add SHOW_DELETED + EXTENDED_DN to see tombstones. | M | No | A DC on a different OS version may reject the cookie, forcing a full resync. Only the final state is returned, with no intermediate values. Children of moved objects are not reported. | [DirSync](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/2213a7f2-0a36-483c-b2a4-8574d53aa1e3); [Polling with DirSync](https://learn.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-the-dirsync-control) |
| Change tracking: USN / notifications | Keep a `uSNChanged` high-water mark per DC and check `invocationId` to detect restores. `LDAP_SERVER_NOTIFICATION_OID` (…528) gives near-real-time updates on small scopes: **5 per connection by default** (`MaxNotificationPerConn`, then `adminLimitExceeded`), only the filter `(objectclass=*)`, and they must be re-registered after a reconnect, then the state re-read. Per the Win32 notifications page (MS-ADTS is silent on deletes), notifications also fire on deletes (`isDeleted=TRUE`, new DN under Deleted Objects, **no Show Deleted control needed**) and moves, but not when a parent is moved or renamed. Reading the deleted object afterwards still needs Show Deleted. | M | No | MS-ADTS allows subtree scope, but Win32 guidance says NC-root only and warns about performance. **Samba polls `uSNChanged` and hides deleted objects, so it likely does not notify deletes** `[LAB]`; delete detection must not depend on notifications. Prefer DirSync. Full semantics and lab tests: `knowledge/development/domain/ad-change-notifications.md`. | [USNChanged](https://learn.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-usnchanged); [notification OID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f14f3610-ee22-4d07-8a24-1bf1466cba5f); [Win32 notifications](https://learn.microsoft.com/en-us/windows/win32/ad/change-notifications-in-active-directory-domain-services); [LDAP policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99) |
| "Who changed what, and when" | `msDS-ReplAttributeMetaData` / `msDS-ReplValueMetaData` give **when, the originating DC and the version — never who**. "Who" needs events from the originating DC (5136/5137/5139/5141, 4738, 4728…). Correlate on objectGUID, originating DSA, time and the 5136 Correlation ID. | M | Needs event collection (§1.5) | Without audit policy and SACLs, attribution is impossible. | [Replication metadata](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/21ea8133-4947-4409-bca8-4239723d3e6a); [Event 5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136) |

### 1.3 Group Policy

| Capability | Approach | Cx | Windows-native? | Key risks | Authoritative source |
|---|---|---|---|---|---|
| GPO inventory and settings report | **LDAP:** the `groupPolicyContainer` object (`gPCFileSysPath`, `versionNumber`, `flags`, `gPCMachineExtensionNames` / `gPCUserExtensionNames`, `gPCWQLFilter`). **SMB to SYSVOL** (Kerberos, signing/encryption): `GPT.ini`, `Registry.pol` (MS-GPREG `PReg` v1), `GptTmpl.inf` (MS-GPSB, UTF-16LE), Group Policy Preferences XML (MS-GPPREF), scripts. ADMX/ADML central store for display names. | L | Optional: a Windows helper runs `Get-GPOReport` for GPMC-identical output | Dozens of client-side-extension (CSE) formats. ADMX coverage. SYSVOL (DFS-R) and AD versions can drift apart. | [GPO search](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/b0e5c9e8-e858-4a7a-a94a-4a3d0a9d87a2); [Registry.pol syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/5c092c22-bf6b-4e7f-b180-b20743d368f5); [MS-GPSB syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/fa15485d-ae9f-456e-a08f-81f2e5725a7e); [GroupPolicy module](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/) |
| Link / enforce / block inheritance; create / delete GPO | Write `gPLink` = `[LDAP://cn={GUID},cn=policies,cn=system,DC=…;N]…`, where N: 1 = link disabled, 2 = enforced, and string order = precedence. Write `gPOptions` (1 = block inheritance). Creating a GPO means creating the AD container **and** the SYSVOL folder, with matching ACLs. | M | No (LDAP + SMB) | Edit gPLink through the DN type, never by string surgery. ACL drift between the AD and SYSVOL halves. | [Domain SOM search (gPLink/gPOptions)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/08090b22-bc16-49f4-8e10-f27a8fb16d18) |
| GPO backup & restore | **Our own format:** AD attributes + security descriptor + the full SYSVOL tree, content-addressed and signed. Restore writes both halves and bumps `versionNumber` (user = upper 16 bits, computer = lower 16) in AD and in `GPT.ini`. **GPMC-compatible** backups (`Backup-GPO` / `Import-GPO`) via the Windows helper. | M (own) / L (GPMC-compat) | Optional | If the version is unchanged, clients may skip processing. Cross-domain restore needs SID/UNC mapping. | [Version update](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/70fd86b1-926a-4dcf-9ce7-6f9d2149c20d); [version cache](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/bc953fef-0ca0-495f-8097-20772b3f6a6e); [glossary](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/2f362c13-9a2d-469b-8c4b-7b4045258995) |
| GPO **setting editing** | v1: Administrative Templates (`Registry.pol`) and the security template (`GptTmpl.inf`) only, validated against ADMX. Update the CSE GUID lists and versions atomically. Later: Preferences XML, but never write `cpassword` (removed by MS14-025; old files are not cleaned up). Use Microsoft's `Set-GPRegistryValue` (registry-based settings only, Windows-only) as a **test oracle**, and as a fallback write path through the Windows helper. | XL | Optional (Windows helper); verification needs Windows clients (`gpresult` / RSoP) | One bad write breaks policy on thousands of machines. Microsoft's programmatic editing covers registry-based settings only (GroupPolicy module). GPMC COM (`IGPM`) handles backup, links and reports, not individual settings. | [MS-GPREG](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/5c092c22-bf6b-4e7f-b180-b20743d368f5); [Set-GPRegistryValue](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpregistryvalue); [GPP password encryption](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be); [MS14-025](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025); [IGPM](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/api/gpmgmt/nn-gpmgmt-igpm) |

### 1.4 File-system and share permissions

| Capability | Approach | Cx | Windows-native? | Key risks | Authoritative source |
|---|---|---|---|---|---|
| NTFS permissions (view, change, report) | Agentless read/write of security descriptors over SMB2/3: the revived [go-smb2](https://github.com/hirochachacha/go-smb2) v2 and the [cloudsoda fork](https://github.com/cloudsoda/go-smb2) expose get/set. Bulk changes and effective access run in the **file-server agent** (`GetNamedSecurityInfo` / `SetNamedSecurityInfo`, `AuthzAccessCheck`). | L | **Yes** for effective access and large-tree changes | Inheritance propagation on huge trees. Long paths. Canonical ACE order. DFS namespaces. go-smb2 v2 is untagged, so pin a commit. | [x/sys/windows security](https://github.com/golang/sys/blob/master/windows/security_windows.go); [AuthzAccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzaccesscheck); [ACE order](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl) |
| Share permissions | MS-SRVS `NetrShareGetInfo` / `NetrShareSetInfo` at level 502 (includes the security descriptor), via go-msrpc `srvs`. | M | No | We must compute combined share + NTFS effective access ourselves. | [SHARE_INFO_502](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_502); [go-msrpc](https://github.com/oiweiwei/go-msrpc) |

### 1.5 Auditing & threat detection (ADAudit Plus parity)

| Capability | Approach | Cx | Windows-native? | Key risks | Authoritative source |
|---|---|---|---|---|---|
| Collecting DC Security-log events | **Default:** an agent module on each DC subscribes to the `Security` channel with `EvtSubscribe`, reusing the Apache-2.0 winlogbeat wrappers. It keeps a local disk buffer and connects out over mTLS gRPC. **Agentless:** WEF source-initiated subscriptions to a Windows WEC, or to our own MS-WSMV receiver (OpenWEC proves this works on Linux; it is GPLv3, so reference only). **Small estates:** remote pull over MS-EVEN6 (needs Event Log Readers). | L | **Yes** (agent, or a Windows/OpenWEC-style collector) | Microsoft plans for ≈3,000 events/s per WEC on commodity hardware. "Rendered text" is 2–3× larger than binary events. **No gap signal when a log wraps.** An agent on a DC is Tier 0. | [WEF guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection); [OpenWEC](https://github.com/cea-sec/openwec); [winlogbeat wineventlog](https://github.com/elastic/beats/tree/main/winlogbeat/sys/wineventlog) |
| Audit-policy and SACL management | Read and write Advanced Audit Policy via GPO (MS-GPAC; the `audit.csv` path is `[UNVERIFIED]`). SACLs on the domain NC (needed for 5136/4662) via `SD_FLAGS` with the SACL bit. That needs SeSecurityPrivilege, so it is a **Tier-0 operation**. | M | No (Tier-0 connector) | Event-volume explosion. Mis-scoped SACLs. | [MS-GPAC subcategory syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d); [Event 4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662) |
| Windows file-server auditing | SACLs plus the File System / File Share / Detailed File Share subcategories. The agent collects 4656/4663/4660/4670/5140/5145, filters at the source and de-duplicates by handle. | L | **Yes** (agent) | The highest-volume source in the product. | [Appendix L](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) |
| NAS auditing | **NetApp ONTAP:** implement an external FPolicy server in asynchronous mode (used for auditing). ONTAP buffers notifications for up to 10 minutes during an outage, and has a persistent store from 9.14.1. **Dell PowerScale:** Common Event Enabler `[UNVERIFIED]`. Other vendors: syslog or API. | L per vendor | No (Linux service) | Proprietary protocols; vendor partner validation. | [NetApp sync vs async](https://docs.netapp.com/us-en/ontap/nas-audit/synchronous-asynchronous-notifications-concept.html); [FPolicy solution parts](https://docs.netapp.com/us-en/ontap/nas-audit/two-parts-fpolicy-solution-concept.html) |
| Threat-detection signals | A rule engine over normalized events, plus posture checks over LDAP (§1.5.2). Network detections such as DRSUAPI/DCShadow traffic need packet capture on DCs, as Microsoft Defender for Identity (MDI) does: defer. | L (XL with network sensor) | Needs event collection | False positives; evasion; requires an attack-replay lab. | [MDI architecture](https://learn.microsoft.com/en-us/defender-for-identity/architecture); [MITRE T1558.003](https://attack.mitre.org/techniques/T1558/003/) |

#### 1.5.1 DC audit baseline

| Area | Event IDs | Advanced Audit subcategory / prerequisite |
|---|---|---|
| User accounts | 4720 created · 4722 enabled · 4723 change attempt · 4724 reset attempt · 4725 disabled · 4726 deleted · 4738 changed · 4740 locked out · 4767 unlocked · 4781 renamed | User Account Management |
| Groups | 4728/4729 (global) · 4732/4733 (local) · 4756/4757 (universal) | Security Group Management |
| Computers | 4741/4742/4743 | Computer Account Management |
| Directory changes, with old and new values | **5136**: one modify produces "Value Deleted" (old value) then "Value Added" (new value), sharing a Correlation ID · 5137 create · 5138 undelete · 5139 move · 5141 delete | Directory Service Changes **plus a SACL on the objects** ([5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)) |
| Control-access operations | **4662**: Properties lists the GUIDs of the rights or property sets used | Directory Service Access **plus a SACL** ([4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662)) |
| Kerberos | 4768 TGT (has Pre-Authentication Type) · 4769 service ticket (has Ticket Encryption Type) · 4771 pre-auth failed | Kerberos Authentication Service ([4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)); Kerberos Service Ticket Operations ([4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)) |
| NTLM / logon | 4776 · 4624 · 4625 · 4648 | Credential Validation; Logon ([WEF minimum audit policy](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)) |
| High criticality | 4719 audit policy changed · 4765/4766 SID History · 4794 DSRM password set · 1102 log cleared | Rated High / Medium-to-High in [Appendix L](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) |

#### 1.5.2 Detection catalogue, v1

| Signal | Logic | Notes |
|---|---|---|
| Kerberoasting (T1558.003) | 4769 with Ticket Encryption Type **0x17 (RC4)** for a user-account SPN; per-principal spikes in ticket requests; honey-SPN accounts | AES roasting also exists, so do not rely on RC4 alone ([MITRE](https://attack.mitre.org/techniques/T1558/003/)). Once RC4 is off by default, any RC4 ticket is a stronger signal: WS2025 KDCs issue no RC4 TGTs, and Microsoft planned to stop assuming RC4 by end of Q2 2026 ([RC4 guidance](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)) |
| AS-REP roasting | 4768 with **Pre-Authentication Type 0**, plus a posture check for accounts that do not require pre-auth | [4768 table 5](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768) |
| DCSync (T1003.006) | 4662 whose Properties contain `1131f6aa-…` / `1131f6ad-…` / `89e95b76-…` (replication rights) from an account that is not a DC | Needs a SACL on the domain NC. Rights GUIDs: [control access rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb); [MITRE](https://attack.mitre.org/techniques/T1003/006/) |
| Password spray / brute force | One source hitting many accounts in 4625/4771/4776; lockout storms in 4740 | Baseline per source |
| ACL / attribute privilege escalation | 5136 on `CN=AdminSDHolder` (Microsoft recommends monitoring it), `domainDNS`, GPOs linked to DCs; changes to `msDS-KeyCredentialLink` (Shadow Credentials), `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD), SPNs on privileged users, delegation bits in UAC | [5136 guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136) |
| dMSA "BadSuccessor" | 5137 (dMSA created), 5136 on `msDS-ManagedAccountPrecededByLink`, event 2946. Posture check: who can create dMSAs in *any* OU — 91% of environments Akamai examined had non-admins with this right | [Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory). Microsoft's later fix is often linked to CVE-2025-53779 `[UNVERIFIED link]` |
| Persistence / tampering | 4765/4766 (SID History), 4794 (DSRM), 4719 (audit policy), 1102 (log cleared) | All rated High in [Appendix L](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) |
| Posture checks (LDAP only) | Unconstrained delegation; Kerberoastable privileged accounts; AdminSDHolder ACL drift; stale privileged accounts; leftover GPP `cpassword` files; AD CS template misconfigurations (later) | Can run without events, so they are available on day 1 |

### 1.6 Self-service, MFA, SSO (ADSelfService Plus parity)

| Capability | Approach | Cx | Windows-native? | Key risks | Authoritative source |
|---|---|---|---|---|---|
| Self-service password reset (SSPR) web portal | Enrollment, identity verification, reset (§1.1, with history enforcement), unlock and notifications. Reachable from the internet only through the edge component (§4). | M | No | Account takeover through weak enrollment, user enumeration, CAPTCHA bypass. ADSSP shipped each of these: [CVE-2021-37424](https://nvd.nist.gov/vuln/detail/CVE-2021-37424), [CVE-2021-37417](https://nvd.nist.gov/vuln/detail/CVE-2021-37417). | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-37424) |
| SSPR at the Windows logon screen | A **V2 credential provider** (`ICredentialProvider` + `ICredentialProviderCredential2`) DLL hosted by LogonUI. **Native fields only — no embedded browser.** It calls a narrow SSPR API over mutually authenticated, pinned TLS. Scenarios: `CPUS_LOGON`, `CPUS_UNLOCK_WORKSTATION`, `CPUS_CHANGE_PASSWORD`. Build for x64 and ARM64. | XL | **Yes** (native COM DLL) | ManageEngine shipped SYSTEM-level bugs exactly here: [CVE-2018-5353](https://nvd.nist.gov/vuln/detail/CVE-2018-5353) (no server authentication before opening a browser as Winlogon), [CVE-2019-12476](https://nvd.nist.gov/vuln/detail/CVE-2019-12476) (escape from the kiosk browser to a SYSTEM shell), [CVE-2026-74849](https://nvd.nist.gov/vuln/detail/CVE-2026-74849) (RCE in the GINA client). Microsoft recommends always keeping a system provider available. | [Credential providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows); [usage scenarios](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/ne-credentialprovider-credential_provider_usage_scenario); [SDK sample (C++)](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider) |
| Remote / VPN users after a reset | A pre-logon VPN through `CPUS_PLAP` providers, or the agent refreshes the cached credential once the device is connected `[LAB]` | L | Yes | VPN client matrix. A stale cached verifier locks the user out. | [usage scenarios](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/ne-credentialprovider-credential_provider_usage_scenario) |
| macOS login | **Preferred:** a Platform SSO extension. It offers password sync, Secure-Enclave keys and smart cards from macOS 14; Tap to Login from macOS 26; web-based authentication from macOS 27. This means activeDIQ must act as the identity provider. **Fallback:** an authorization plug-in in the `system.login.console` right (XCreds, BSD-3, is a reference). | XL | macOS-native (Swift) | Apple API churn; notarization; work on the IdP protocol. | [Apple Platform SSO](https://support.apple.com/guide/deployment/platform-sso-for-macos-dep7bbb05313/web); [authorization plug-ins](https://developer.apple.com/documentation/security/authorization-plug-ins); [XCreds](https://github.com/twocanoes/xcreds) |
| Linux login | A PAM module (`pam_sm_authenticate`, `pam_sm_chauthtok`) alongside SSSD for AD authentication | L | Linux-native (C) | Variety of display managers and distros. | [pam_sm_chauthtok(3)](https://man7.org/linux/man-pages/man3/pam_sm_chauthtok.3.html) |
| MFA: TOTP / HOTP | RFC 6238 / 4226. Seeds encrypted per tenant. Replay protection. | S | No | — | [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) |
| MFA: WebAuthn / passkeys | [go-webauthn](https://github.com/go-webauthn/webauthn) v0.18.2 supports passkeys, the common attestation formats and FIDO MDS 3. WebAuthn Level 3 became a **W3C Recommendation on 25 Aug 2026**. | M | No | Relying-party ID and origin must work across the edge and internal hostnames. | [WebAuthn L3](https://www.w3.org/TR/webauthn-3/) |
| MFA: push | Our own iOS/Android app with APNs/FCM and mandatory number matching | L | No | App-store operations; MFA-fatigue attacks. | `[UNVERIFIED]` (CISA number-matching guidance not fetched) |
| RADIUS server (VPN / Wi-Fi MFA) | **Our own Go RADIUS server.** layeh/radius has had no commits since 2023, does not compute or check Message-Authenticator, and has no TLS. **Require Message-Authenticator on every packet** (BlastRADIUS, [CVE-2024-3596](https://nvd.nist.gov/vuln/detail/CVE-2024-3596)). Offer RADIUS over TLS / RADIUS/1.1. Use PAP inside TLS, or proxy to NPS. | M | MSCHAPv2/PEAP needs NT-hash validation via Netlogon pass-through (go-msrpc `nrpc`) or NPS `[UNVERIFIED]` | VPN vendor quirks; dependency on MSCHAPv2. | [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865); [BlastRADIUS](https://www.blastradius.fail/); [RFC 9765 (Experimental)](https://www.rfc-editor.org/rfc/rfc9765.html); [layeh/radius](https://github.com/layeh/radius) |
| SSO: OIDC provider | [zitadel/oidc](https://github.com/zitadel/oidc), an OpenID-certified provider library (Apache-2.0, v3.51.11), following the OAuth 2.0 Security BCP | M | No | Key rotation; session hardening. | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) |
| SSO: SAML IdP | Either a minimal IdP built on [goxmldsig](https://github.com/russellhaering/goxmldsig) + xml-roundtrip-validator, or a hardened [crewjam/saml](https://github.com/crewjam/saml) (can act as IdP; slow release cadence; CVE-2020-27846, CVE-2022-41912, CVE-2023-45683). Integrated Windows authentication via SPNEGO with a keytab. | L | No | XML signature wrapping. Dependency rot: compare ManageEngine's CVE-2022-47966, caused by an outdated xmlsec. | [RFC 4559](https://www.rfc-editor.org/rfc/rfc4559); [NVD CVE-2022-47966](https://nvd.nist.gov/vuln/detail/CVE-2022-47966) |
| Entra ID external MFA | Act as an Entra "external MFA" provider (OIDC-based), so activeDIQ MFA satisfies Conditional Access | M | No | Constraints of Microsoft's program. | [Entra external MFA](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-external-method-manage) |

### 1.7 Password policy enforcement & sync

| Capability | Approach | Cx | Windows-native? | Key risks | Authoritative source |
|---|---|---|---|---|---|
| Custom policy; banned and breached passwords | A password-filter DLL on **every writable DC** exporting `InitializeChangeNotify`, `PasswordFilter` and `PasswordChangeNotify`. Registered in the `Notification Packages` REG_MULTI_SZ value under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`. It checks a signed, locally cached policy and breach list; **there is no network I/O in the call path.** | XL | **Yes** (native DLL in LSASS) | Under LSA protection (RunAsPPL), every LSA plug-in **must be Microsoft-signed** through the *file signing service for LSA* and follow SDL guidance. An LSASS crash reboots the DC. No debugger can attach under PPL. | [Password filters](https://learn.microsoft.com/en-us/windows/win32/secmgmt/password-filters); [functions](https://learn.microsoft.com/en-us/windows/win32/secmgmt/management-functions); [registration](https://learn.microsoft.com/en-us/windows/win32/secmgmt/installing-and-registering-a-password-filter-dll); [LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) |
| Password sync (Entra, Google, LDAP directories, apps) | `PasswordChangeNotify` writes to a DPAPI-encrypted local queue. The DC agent forwards to the server, which updates targets (Graph `passwordProfile`, Google Directory API). | L | **Yes** (same DLL) | Plaintext handling; ordering and retries. Competes with Entra password hash sync, which needs Replicate Directory Changes **All**. | [Google Password Sync (installed on all DCs)](https://support.google.com/a/answer/2611859); [Entra Connect permissions](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) |

### 1.8 Backup & recovery (RecoveryManager Plus parity)

| Capability | Approach | Cx | Windows-native? | Key risks | Authoritative source |
|---|---|---|---|---|---|
| Object and attribute snapshots; attribute-level restore | A full snapshot, then DirSync increments, into a versioned, encrypted store. Diff any two points in time. Restore with LDAP modify of only the changed attributes; linked values (e.g. `member`) restore value by value. | L | No | **Secrets cannot be restored.** `unicodePwd` and `supplementalCredentials` are never returned over LDAP; reading them needs replication rights equivalent to DCSync, which we refuse to hold. | [unicodePwd](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2); [control access rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb) |
| Recycle Bin restore / tombstone reanimation | One modify with Show Deleted (…417) that removes `isDeleted` and replaces `distinguishedName` (a string DN in the same NC). Needs Reanimate-Tombstones `45ec5156-db7e-47bb-b53f-dbeb2d03c40f` on the NC root. Recycle Bin needs forest functional level 2008 R2 and **cannot be disabled once enabled**. Without it, a tombstone keeps only preserved attributes (`searchFlags` 0x8 plus a fixed list) and **no links**, so we re-populate from our snapshots. | M | No | Tombstone lifetime is **60 days if unset** (spec). Many forests set 180 `[UNVERIFIED]`, so read the real values. Recycled objects cannot be restored. | [Undelete](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4302a2eb-55c8-426c-b310-6791c6ae8307); [Recycle Bin](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9482178-ee53-4b6c-841d-5259d6261985); [lifetimes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1887de08-2a9e-4694-95e2-898cde411180); [tombstone requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/89e942fa-e1f4-4c2e-ac3a-fd1b770a9799) |
| GPO backup / restore | See §1.3 | M–L | Optional | — | — |
| AD-integrated DNS backup / restore | Read zone and node objects over LDAP. Parse `dnsRecord` (MS-DNSP 2.3.2.2; note **TTL is big-endian**). Restore via MS-DNSP `R_DnssrvUpdateRecord2` (opnum 9) with go-msrpc `dnsp`. Handle `dNSTombstoned` nodes. Partition names (DomainDnsZones / ForestDnsZones) are `[UNVERIFIED]`. | M | No | Tombstoned nodes; scavenging; zones in several partitions. | [dnsRecord](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8); [dnsRecord in the DS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6ad92105-7d2b-4350-ae8f-80e99c09013e); [UpdateRecord2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/8f50ae96-d87f-4fdb-8526-5a86cea25837) |
| Forest recovery (DC system state) | Out of scope for v1. Integrate with Windows Server Backup or the customer's backup vendor; ship a runbook. | — | Yes | — | — |

### 1.9 Cloud directories (M365 Manager Plus parity + Google)

| Capability | Approach | Cx | Windows-native? | Key risks | Authoritative source |
|---|---|---|---|---|---|
| Entra ID / M365 (users, groups, licences, roles) | Microsoft Graph with app-only certificate auth. Use [msgraph-sdk-go](https://github.com/microsoftgraph/msgraph-sdk-go) (GA, v1.103.0), or a **thin generated client** for only the endpoints we use, because the full SDK's models package is huge. | M–L | No | Graph throttling; reliance on beta endpoints. | [SDK size issue #129](https://github.com/microsoftgraph/msgraph-sdk-go/issues/129) |
| Exchange Online mailboxes | A `pwsh` 7.6 sidecar running **ExchangeOnlineManagement v3** (REST-backed cmdlets, supported on Linux and macOS, certificate app-only auth). It is called with **typed parameters only** (§2.7). Use Graph wherever it covers the operation. | L | No | PowerShell dependency; EXO 3.10.0+ requires PS 7.6. EWS in Exchange Online was announced to retire on 2026-10-01 `[UNVERIFIED live status]`, so avoid EWS. | [EXO V3](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2); [EWS→Graph](https://learn.microsoft.com/en-us/graph/migrate-exchange-web-services-overview) |
| Google Workspace | Admin SDK Directory API via `google.golang.org/api/admin/directory/v1`, using a service account with domain-wide delegation (impersonated subject) | M | No | Security of the delegation key; quotas. | [Go client](https://github.com/googleapis/google-api-go-client/tree/main/admin/directory/v1) |

---

## 2. Security architecture for a Tier-0 product

### 2.1 What is Tier 0 in activeDIQ

Any system that can write to Tier-0 objects or run code on DCs **is** Tier 0. Microsoft says this directly about an analogous product: *"The Microsoft Entra Connect server must be treated as a Tier 0 component"* ([Entra Connect prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)).

In the Enterprise Access Model, Tier 0 grows into the **control plane**. It also requires that a higher plane can never be controlled from a lower one ([Enterprise Access Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)).

| Plane | activeDIQ components | Rule |
|---|---|---|
| **Control plane (Tier 0)** | DC agent module; password-filter DLL; optional **Tier-0 connector** (manages protected groups and SACLs, under approvals); signing keys for DC-bound policy; snapshot store **if** it holds LAPS/BitLocker material (excluded by default) | Separately deployable. Never reachable from lower planes except by signed, typed, allowlisted messages. |
| **Management plane** | activeDIQ server; directory connector holding delegated, non-Tier-0 rights; file-server agents; Windows management helper | Default install. Must not hold any right over AdminSDHolder-protected objects or DCs. |
| **User / app access** | SSPR edge; endpoint credential provider and PSSO extension; RADIUS; OIDC/SAML endpoints; public API | Holds no AD credentials. Assume it is compromised. |

### 2.2 ManageEngine's AD-family CVE record → our controls

NVD keyword data (ADSelfService, ADManager, ADAudit, RecoveryManager, M365 Manager, AD360, Exchange Reporter):
- **153 CVEs** since 2019.
- CWE counts: SQLi 34 · XSS 26 · unrestricted upload 18 · OS/command injection 6 + 4 · XXE 5 · path traversal 4.
- ADAudit Plus: 24 CVEs published in 2024, **21 of them SQLi**.
- Sources: [NVD API query](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ADSelfService); CISA KEV catalog version 2026.10.01 ([KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)).

| CVE | Product · class | What went wrong | activeDIQ control |
|---|---|---|---|
| [CVE-2021-40539](https://nvd.nist.gov/vuln/detail/CVE-2021-40539) | ADSSP · REST auth bypass → RCE · **KEV, ransomware** | Unauthenticated path to a privileged API | One deny-by-default authN/authZ middleware. Router tests generated from OpenAPI so every route asserts its policy. No "internal" unauthenticated endpoints. |
| [CVE-2020-24786](https://nvd.nist.gov/vuln/detail/CVE-2020-24786) | 11 products · auth bypass in a shared servlet | Shared framework endpoint without auth | The same middleware for every module. Architecture test: no handler registered outside the router. |
| [CVE-2022-28810](https://nvd.nist.gov/vuln/detail/CVE-2022-28810) | ADSSP · OS command injection · **KEV** | The `%password%` macro was passed unsanitized into an admin-configured "custom script"; a crafted password ran commands as SYSTEM ([Rapid7](https://www.rapid7.com/blog/post/2022/04/14/cve-2022-28810-manageengine-adselfservice-plus-authenticated-command-execution-fixed/)) | **No custom-script feature.** Extensions are typed webhooks or actions. If customers must run scripts, they get JSON on stdin, in a separate low-privilege runner, never on a DC (§2.7). |
| [CVE-2021-28958](https://nvd.nist.gov/vuln/detail/CVE-2021-28958), [CVE-2021-33055](https://nvd.nist.gov/vuln/detail/CVE-2021-33055) | ADSSP · unauthenticated RCE during password change | Command construction in the reset path | Password flows never touch a shell. |
| [CVE-2022-47966](https://nvd.nist.gov/vuln/detail/CVE-2022-47966) | 24+ products · SAML via outdated xmlsec 1.4.1 · **KEV, ransomware** | Dependency rot in signature validation | SBOM, patch SLAs, maintained XML-DSig libraries, signature-wrapping fuzz tests; prefer OIDC. |
| [CVE-2022-28219](https://nvd.nist.gov/vuln/detail/CVE-2022-28219) | ADAudit Plus · unauthenticated XXE → RCE | XML parser with entity expansion | Go `encoding/xml` (no external entities); no untrusted XML outside SAML. |
| [CVE-2023-48792](https://nvd.nist.gov/vuln/detail/CVE-2023-48792) and ≈20 more | ADAudit Plus · SQLi in reports and exports | Hand-built SQL in report builders | Typed report query builder that compiles to parameterized SQL; sqlc; RLS (§2.7). |
| [CVE-2018-5353](https://nvd.nist.gov/vuln/detail/CVE-2018-5353), [CVE-2019-12476](https://nvd.nist.gov/vuln/detail/CVE-2019-12476), [CVE-2026-74849](https://nvd.nist.gov/vuln/detail/CVE-2026-74849) | ADSSP logon agent · spoofing, kiosk breakout to SYSTEM, RCE | A browser inside the logon UI; server not authenticated | No browser in LogonUI. Native fields, pinned mutual TLS, a minimal API, a fuzzed parser. |
| [CVE-2026-6516](https://nvd.nist.gov/vuln/detail/CVE-2026-6516) | ADAudit Plus · **unauthenticated RCE via the agent API** (CVSS 10) | Agent-facing API reachable without auth | Agents dial out over mTLS. The server exposes no agent API without a valid device certificate. Messages are typed protobuf. |
| [CVE-2026-11374](https://nvd.nist.gov/vuln/detail/CVE-2026-11374) | ADSSP/ADAP/RMP/M365MP · predictable SSO tickets | Weak randomness | Only `crypto/rand`, with 128-bit+ tokens; standard session library. |
| [CVE-2019-7161](https://nvd.nist.gov/vuln/detail/CVE-2019-7161) | ADSSP · fixed encryption keys | Hard-coded keys | Keys generated per install and per tenant; KEK in TPM/KMS/DPAPI-NG. |
| [CVE-2022-24978](https://nvd.nist.gov/vuln/detail/CVE-2022-24978) | ADAudit Plus · password returned in JSON | Secrets in API responses | Secret fields are write-only in the API schema; response linter. |
| [CVE-2022-29457](https://nvd.nist.gov/vuln/detail/CVE-2022-29457) | 4 products · NTLM hash disclosure via a storage-path setting | Service account authenticates to an attacker-supplied UNC path | No admin-supplied UNC/SMB paths in the service context; NTLM disabled; object storage only. |

### 2.3 Least-privilege delegation (no Domain Admin, ever)

| Function | Principal | Exact rights | Scope | Notes |
|---|---|---|---|---|
| Inventory and reporting | `adq-read` | Default authenticated read. Add explicit CONTROL_ACCESS only for confidential attributes a feature needs (LAPS, BitLocker), off by default. | Domain(s) | Over LDAPS. WS2025 requires encryption for confidential attributes. |
| Change tracking | `adq-read` | **None extra** when DirSync uses `LDAP_DIRSYNC_OBJECT_SECURITY` (0x1). Otherwise DS-Replication-Get-Changes `1131f6aa-…` on the NC root. **Never** Get-Changes-All `1131f6ad-…`. | NC roots | Get-Changes-**All** is what DCSync and Entra password hash sync use ([Entra Connect perms](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)). |
| Nested-membership reports | `adq-read` | Membership of the Windows Authorization Access Group (for `tokenGroupsGlobalAndUniversal`) | Domain | [Security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) |
| Helpdesk / SSPR reset and unlock | `adq-ops` | Reset Password `00299570-…` + WriteProperty on `lockoutTime` and `pwdLastSet`, inherited to user objects | Delegated OUs only | Send `…2239` so resets keep history. Protected accounts are excluded automatically (below). |
| Provisioning | `adq-prov` | Create/Delete Child for user/group/computer/contact on the target OUs + WriteProperty on templated attributes. **No GenericAll.** | Target OUs | — |
| Group management | `adq-ops` | WriteProperty on `member` | Delegated groups/OUs | — |
| GPO management | `adq-gpo` | Group Policy Creator Owners (to create); per-GPO edit (AD container + SYSVOL ACL); write `gPLink`/`gPOptions` on target OUs | Selected GPOs/OUs | GPOs linked to the DC OU are Tier 0 → Tier-0 connector only. |
| Recycle Bin restore | `adq-restore` (JIT) | Reanimate-Tombstones `45ec5156-…` on the NC root + write on the target container | Domain | Enable only during a restore window (just-in-time group membership). |
| Audit collection | DC agent (LocalSystem) or a WEF collector | Local Event Log Readers is enough for reading the Security channel ([WEF Appendix D](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)) | DCs | — |
| Tier-0 actions (protected groups, SACLs, DC-OU GPOs) | Separate Tier-0 connector | Exactly the needed rights, granted JIT, with two-person approval | Tier-0 objects | Deployed on Tier-0 infrastructure, or not at all. |

**AdminSDHolder is a feature, not a bug.** Every 60 minutes, SDProp on the PDC emulator resets the ACLs of protected accounts and groups to the AdminSDHolder template, and inheritance is disabled on them ([Appendix C](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)). Delegated helpdesk rights therefore never reach Domain Admins and similar accounts.

The UI must say "protected object (adminCount=1) — managed only by the Tier-0 connector" rather than fail with an obscure error.

### 2.4 Service identity: Kerberos vs NTLM, LDAP signing and channel binding

**Windows hosts.** Run services as a **gMSA**. Windows manages the password: the DC computes it from KDS keys and authorised hosts retrieve it ([gMSA overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview)). The default rotation interval is believed to be 30 days `[UNVERIFIED]`; it is fixed at creation ([New-ADServiceAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount)).

**Linux / Docker hosts.** Use a dedicated account with an **AES-only keytab** (`msDS-SupportedEncryptionTypes` 0x18). Why AES-only:
- WS2025 KDCs do not issue RC4 TGTs.
- Microsoft planned to stop assuming RC4 as a default on DCs by the end of Q2 2026 (CVE-2026-20833, [KB5073381](https://support.microsoft.com/help/5073381); [RC4 guidance](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).

Optionally, a Linux host can read a gMSA password through `msDS-ManagedPassword` over an encrypted connection. Samba 4.20's `samba-tool` already reads gMSA passwords as a client ([Samba 4.20 notes](https://www.samba.org/samba/history/samba-4.20.0.html)) `[LAB]`.

**NTLM: off by default.** All NTLM versions are deprecated; NTLMv1 is removed in Windows 11 24H2 / WS2025 ([deprecated features](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features)). Microsoft's own hardening guidance for Entra Connect is to deny NTLM on that server ([prereqs](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)).

activeDIQ must work end to end with NTLM blocked: Kerberos for LDAP, SMB, RPC and WinRM, plus correct SPNs. Note that go-ntlmssp has **no channel-binding support** ([issue #51](https://github.com/Azure/go-ntlmssp/issues/51)), which is another reason NTLM is unacceptable.

**LDAP transport.**
- Always TLS: LDAPS 636 or StartTLS, with certificate validation; TLS 1.3 is available on WS2025.
- **Never** a simple bind on 389.
- A DC that enforces signing rejects SASL binds that don't request signing, and rejects simple binds over clear text.
- On new WS2025 deployments signing is **required by default** and channel binding defaults to "When supported" ([LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)).
- Channel binding can be set to "Always" (`LdapEnforceChannelBinding = 2`; [KB4520412](https://support.microsoft.com/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)). Therefore **every SASL bind over TLS must carry a `tls-server-end-point` CBT**.
- go-ldap's own GSSAPI client cannot send one (only its Windows SSPI client can), so we provide a `GSSAPIClient` implementation backed by go-krb5/krb5's channel-binding support. That support is on `main` only, not in v0.1.0. On Samba 4.22 with strong auth the adapter binds over LDAPS and StartTLS, and unbound binds are rejected (T-0023, `t-0023-ldap-gssapi-cbt-spike.md`). Windows is still unproven (T-0133).
- The Phase-0 acceptance test: binds succeed against a DC with signing enforced and channel binding "Always", and produce no events 2887, 3039 or 3074/3075.

### 2.5 Secrets and credential handling

- **Envelope encryption.** Each tenant has a data key, wrapped by a key-encryption key (KEK) that comes from DPAPI-NG/TPM on Windows, TPM2 or a KMS/HSM/Vault on Linux, or a passphrase-unsealed keystore in air-gapped installs. Deleting a tenant shreds its key.
- **No standing admin passwords.** Prefer gMSA or a keytab. If a customer insists on a password credential, store it sealed and encrypted, never return it from the API (CVE-2022-24978 lesson), and alert on rotation age.
- **Plaintext lifetime.** In Go, keep passwords as `[]byte`, never `string`, and zero them after use. The GC may still copy them, so keep SSPR handlers stateless and fast. On DCs, plaintext exists only inside the filter DLL (Rust/C++, `SecureZeroMemory`) and in a DPAPI-encrypted queue.
- **Redaction by type.** `Secret` types render as `[REDACTED]` in logs. The LDAP layer refuses to debug-log modify operations on `unicodePwd`.
- **Our own audit trail.** Every privileged action records actor, approval, target GUID and before/after values. Records are hash-chained, append-only, exportable to a SIEM, and retained independently of AD.

### 2.6 Keeping the product from becoming the attack path

1. **Small internet surface.** Only the SSPR edge faces the internet. It is stateless and **holds no AD credentials or tenant keys**. The internal server dials out to it (a reverse tunnel), so no inbound firewall hole into the AD network is needed. Rate limits, protection against user enumeration, and CAPTCHA fallback are server-side.
2. **Agents.** Outbound-only mTLS (device certificate bound to the tenant). No listening ports. A **closed, typed command set** with no "run script" verb. Signed configuration and policy (a Tier-0 key signs anything a DC module accepts). Signed updates following TUF-style rules: offline root key, threshold signatures, protection against rollback.
3. **Logon components.** No browser. A minimal attack surface: no file dialogs, help links or printing. Pinned server key. Fuzzed message parser. Credential-provider and filter binaries pass static analysis (MSVC `/analyze` or Clippy), hardened builds (CFG/CET) and Authenticode signing.
4. **Supply chain.** Reproducible builds; SBOM per release; signed artifacts (Sigstore + Authenticode); dependency policy with patch SLAs. ManageEngine's KEV entries are 2 auth bypasses and 1 outdated XML library.
5. **Admin misuse.** RBAC scoped by OU and object type; approval (four-eyes) for Tier-0-adjacent and bulk-destructive actions; just-in-time elevation; immutable audit (§2.5).
6. **Secure defaults.** TLS-only, NTLM off, DirSync with `OBJECT_SECURITY`, protected objects excluded, no custom scripts, MFA required for admin console sign-in.

### 2.7 Safe primitives: remove bug classes by construction

The previous product failed because security-relevant strings were built with `fmt.Sprintf`. The rule for activeDIQ: **security-relevant strings are never formatted by hand. Each one has a single typed constructor, enforced by lint.**

| Bug class | AD-specific form | Safe primitive (the only allowed API) | Enforcement |
|---|---|---|---|
| **LDAP filter injection** (RFC 4515) | `(sAMAccountName=` + user input + `)`. Input such as `*)(objectClass=*` widens the search; a crafted filter can enumerate attributes. | `ldapx/filter`: a typed syntax tree (`And`, `Or`, `Eq(attr, Value)`, `Present`, `BitAnd`, `InChain`). Values are always escaped (go-ldap's `EscapeFilter` covers `()\*`, NUL and **all bytes > 0x7F**). Attribute names come from a **schema allowlist**. Output is a filter string or a BER packet. | `forbidigo` bans `ldap.CompileFilter`, `fmt.Sprintf`/`+` in packages that import go-ldap, and raw `SearchRequest{Filter: …}` outside `ldapx`. Fuzz tests compare round-trips against go-ldap's parser. |
| **DN injection and DN confusion** (RFC 4514) | Building `CN=`+name+`,OU=…` with unescaped `,` `+` `"` `\` `<` `>` `;`; scope checks that use `strings.HasSuffix(dn, "OU=HR,…")` (bypassed by escaping, case or spaces) | `ldapx/dn`: parse with `ParseDN`, build RDNs with `EscapeDN` (go-ldap v3.4.5+), compare with `EqualFold`. **Act on objects by `<GUID=…>`.** Authorize scope by walking objectGUID ancestry, never by string suffix. | Ban `strings.*` on DN-typed values; `DN` is an opaque struct. Property tests: parse(format(x)) == x. |
| **SDDL / ACL corruption** | Concatenating SDDL strings; writing a whole security descriptor and dropping the owner or SACL; non-canonical ACE order | `secdesc`: a binary MS-DTYP security-descriptor model (consider [winacl](https://github.com/TheManticoreProject/winacl), MIT). Diff-based ACE edits, canonical ordering, **DACL-only writes via `SD_FLAGS` 0x4**. SDDL is for display only. | No SDDL parser on write paths. Golden tests against Windows (`x/sys/windows` `SecurityDescriptorFromString`) on the Windows CI runner. |
| **PowerShell / command injection** | Script text with interpolated user data (the CVE-2022-28810 pattern). PowerShell also treats **U+2018–U+201B as single quotes**, **U+201C–U+201E as double quotes** and **U+2013–U+2015 as dashes** ([language spec](https://learn.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-02)), so ASCII-only escaping is broken. | (a) .NET sidecar: `PowerShell.Create().AddCommand(…).AddParameter(…)` ([SMA](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.powershell.addcommand)), with no `AddScript` on user data. (b) From Go: run a **static, signed** `.ps1` via `pwsh -NoProfile -NonInteractive -File` and pass **parameters as JSON on stdin**; the script splats them. Never `-Command` with data, never `cmd.exe`, never `.bat`/`.cmd` (BatBadBut: Go's response was a documentation update only — [Flatt](https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/)). If quoting is unavoidable, use `CodeGeneration.EscapeSingleQuotedStringContent` ([API](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.codegeneration.escapesinglequotedstringcontent)). | Ban `exec.Command("powershell"/"pwsh"/"cmd", …)` outside `psx`; `psx` accepts only script IDs from an embedded, signed manifest. |
| **SQL / tenant-context injection** | `SET app.tenant_id = '` + id + `'`; report builders concatenating `WHERE` clauses (ADAudit Plus 2024: 21 SQLi CVEs) | sqlc-generated queries only. Tenant context is set with `SELECT set_config('app.tenant_id', $1, true)` **inside the transaction** (`is_local = true`, so it is scoped to that transaction — [PostgreSQL docs](https://www.postgresql.org/docs/current/functions-admin.html)). RLS with `FORCE ROW LEVEL SECURITY`, because table owners otherwise bypass RLS. The app role is not the owner and has no `BYPASSRLS` ([RLS](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)). The report DSL compiles to parameterized SQL; dynamic identifiers go through `pgx.Identifier.Sanitize`. | Ban `fmt.Sprintf`/`+` in `store` packages; CI check that every tenant table has RLS + FORCE; tests that assert cross-tenant reads return zero rows. |
| **Output / templating injection** | AD attributes are attacker-controlled (users can often edit their own profile fields) and flow into admin reports: stored XSS, and CSV/XLSX formula injection (`= + - @`, tab, CR, LF and full-width variants — [OWASP](https://owasp.org/www-community/attacks/CSV_Injection)) | React (no `dangerouslySetInnerHTML`); Go `html/template` only (never `text/template` for HTML); a `csvx`/`xlsx` writer that neutralizes formula-leading cells; email/PDF through the same encoders. | ESLint `react/no-danger`; ban `text/template` imports in web packages; property tests on export writers. |
| **XML / SAML** | XXE (CVE-2022-28219); signature wrapping; Go XML round-trip bugs | Go `encoding/xml` (no external entities); [goxmldsig](https://github.com/russellhaering/goxmldsig) + xml-roundtrip-validator; strict schema; no XSLT. | SAML confined to one package; fuzz corpus of known wrapping attacks. |
| **Tokens / JWT / randomness** | Predictable SSO tickets (CVE-2026-11374); hand-built JWT JSON | A maintained JOSE library (go-jose) with typed claims and a pinned algorithm; only `crypto/rand`. | Ban `math/rand` in non-test code; ban manual JWT assembly. |
| **Path / UNC coercion** | An admin-supplied `\\attacker\share` path makes the service account authenticate with NTLM (CVE-2022-29457) | No UNC paths in configuration; storage only through an object-store API; NTLM outbound blocked. | Config schema rejects UNC; integration test with NTLM disabled. |

**House-code check (2026-10-02, outside activeDIQ):** PatchIQ shows both the risk and the fix.
- `internal/agent/patcher/signature_authenticode_windows.go` builds PowerShell with `fmt.Sprintf("(Get-AuthenticodeSignature -FilePath '%s').Status", escapePSPath(filePath))`.
- `escapePSPath` only doubles the ASCII `'`.
- A file name containing `’` (U+2019) ends the string literal, because PowerShell treats it as a quote.
- This is the same bug class as the failed product. The fix is the JSON-on-stdin pattern above.
- PatchIQ's LDAP code escapes filter values correctly with `EscapeFilter`, but still builds filters with `Sprintf`. A typed builder makes forgetting the escape impossible.

---

## 3. Stack evaluation

### 3.1 Library check (as of 2026-10)

| Need | Go | .NET 10 | Notes |
|---|---|---|---|
| LDAP + AD controls | [go-ldap/ldap v3.4.14](https://github.com/go-ldap/ldap) (MIT, 2026-07). Has Paging, DirSync, SD flags, Show Deleted, Notification, server-side sort, tree delete, RFC 4533, `EscapeFilter` / `EscapeDN`, and a generic `Extended`. VLV and Extended DN are OID constants only. **No SASL sign/seal**; **CBT only through Windows SSPI** ([PR #565](https://github.com/go-ldap/ldap/pull/565)). | `System.DirectoryServices.Protocols`, cross-platform since .NET 5. On Linux/macOS it calls OpenLDAP `libldap`, and CBT, sign/seal and some controls behave differently there. `System.DirectoryServices` and `AccountManagement` are **Windows-only** ([API docs](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols)). | Go needs our own GSSAPI adapter; .NET on Linux inherits libldap's quirks. |
| Kerberos | gokrb5 v8 is **dormant since 2023** (change-password only, no CBT, no S4U). Its successor [go-krb5/krb5](https://github.com/go-krb5/krb5) has `SetPasswd` and S4U2Self/Proxy. Its only tag, **v0.1.0 (Feb 2026), has no channel binding and no SASL layers**. Those landed on `main` in Aug 2026: [#117](https://github.com/go-krb5/krb5/pull/117) channel binding (`8b6f497`), [#120](https://github.com/go-krb5/krb5/pull/120) KILE CBT advertisement and [#114](https://github.com/go-krb5/krb5/pull/114) GSSAPI SASL. T-0023 bound with `tls-server-end-point` at `main` `f89757a` with no patches (`t-0023-ldap-gssapi-cbt-spike.md`). | Platform GSSAPI on Linux; SSPI on Windows; [Kerberos.NET](https://www.nuget.org/packages/Kerberos.NET) (managed, active) | Pin a `main` commit until a tag carries #117/#120/#114, never v0.1.0. Fork only on trigger (ADR-0001 erratum E1): upstream stops merging, T-0133 finds a WS2025 wire defect, or no tag exists at GA. |
| MS-RPC (SAMR, LSAD, DRSR, EVEN6, SRVS, DNSP, NRPC, WMI) | [oiweiwei/go-msrpc v1.6.4](https://github.com/oiweiwei/go-msrpc) (MIT, 2026-09). Generated stubs for 100+ protocols; NTLM, Kerberos and Netlogon auth; named pipes and TCP. | P/Invoke Win32 on Windows; little managed MS-RPC on Linux | Go is *ahead* for cross-platform RPC. |
| SMB2/3 (SYSVOL, ACLs) | go-smb2 **revived in Sep 2026** (`/v2`, untagged: Kerberos, SMB3 encryption, security-descriptor get/set); [cloudsoda fork](https://github.com/cloudsoda/go-smb2); [jfjallid/go-smb](https://github.com/jfjallid/go-smb) | Windows: native UNC. Linux: limited | Pin commits; contribute upstream. |
| WinRM / PSRP | [masterzen/winrm](https://github.com/masterzen/winrm): message encryption is **NTLM-only**, so Kerberos needs HTTPS. **No mature Go PSRP with a structured AddCommand.** [go-psrp](https://github.com/smnsjas/go-psrp) is new and script-text only. | Full PowerShell SDK; PS 7.6 LTS (.NET 10, supported to 2028-11-14) ([lifecycle](https://learn.microsoft.com/en-us/powershell/scripting/install/powershell-support-lifecycle)) | Use .NET for PowerShell-heavy work, Python [pypsrp](https://github.com/jborean93/pypsrp) for lab tooling. |
| Graph / Google / IdP | msgraph-sdk-go v1.103.0 GA (size [#129](https://github.com/microsoftgraph/msgraph-sdk-go/issues/129)); Google admin directory v1; zitadel/oidc (certified); go-webauthn v0.18.2; SAML is weaker (crewjam/saml is slow and has CVEs) | First-class Microsoft SDKs; strong SAML options `[UNVERIFIED specifics]` | Both are viable. |
| Windows service, registry, SDs | `x/sys/windows`: `svc`, `registry`, `SecurityDescriptorFromString`, `Get/SetNamedSecurityInfo`, `LookupAccountSid` ([source](https://github.com/golang/sys/blob/master/windows/security_windows.go)) | Native | Equivalent. |
| Event log / ETW consumers | `svc/eventlog` is write-only. Use the Apache-2.0 winlogbeat `EvtSubscribe` wrappers. Go ETW consumers ([bi-zone/etw](https://github.com/bi-zone/etw)) are dormant; go-winio ETW is provider-only. | `System.Diagnostics.Eventing.Reader` and the TraceEvent library `[UNVERIFIED versions]` | .NET is stronger for ETW; ETW is not needed in v1. |
| COM (GPMC `IGPM`) | [go-ole](https://github.com/go-ole/go-ole) supports `IDispatch` late binding (low activity) | Native COM interop | Prefer the .NET helper for GPMC. |
| Support horizon | Go: two most recent releases supported | **.NET 8 and .NET 9 both end 2026-11-10; .NET 10 LTS runs to 2028-11-14** ([lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core)) | The brief's ".NET 8/9" is obsolete; any .NET target is .NET 10. |

### 3.2 (a) Server

| Option | For | Against | Verdict |
|---|---|---|---|
| **Go** | Matches the house stack. PatchIQ already uses go-ldap, chi, pgx/sqlc, River, gRPC agents and testcontainers. One static binary for Linux, Windows, Docker and air-gapped installs. Best cross-platform MS-RPC (go-msrpc). Revived SMB library. Good Graph, Google and IdP libraries. AI agents are productive in Go. | GSSAPI CBT/sign-seal gap (we own an adapter); dormant gokrb5; no structured PSRP; weak SAML and RADIUS libraries (we own these too) | **Choose.** |
| .NET 10 | Best PowerShell/COM/GPMC interop; Kerberos.NET; mature SAML | Second runtime and toolchain against house principles; S.DS.P on Linux depends on libldap; Windows-only S.DS/AccountManagement tempt Windows lock-in | Sidecar only: EXO and GPMC parity. |
| Java | Mature JNDI/JGSS (this is ManageEngine's stack) | Heavy footprint; not the house stack | No. |
| Python | impacket, ldap3, pypsrp: unbeatable for protocol coverage | Packaging, performance and type safety for a product | **Lab and test tooling only.** |
| Rust | Memory safety; [ldap3](https://github.com/inejge/ldap3); [sspi-rs](https://github.com/Devolutions/sspi-rs) | Thinner AD ecosystem, single-maintainer crates; not the house stack | Use only at native boundaries (§3.4). |

### 3.3 (b) Windows / DC agent

- **Go**, matching PatchIQ's agent: `x/sys/windows/svc`, signed MSI, outbound gRPC with mTLS, offline outbox.
- **Platform principle "one agent process per endpoint".** activeDIQ's DC, file-server and endpoint functions should be **modules in the skenzeriq platform agent**, not a new service. On a DC that has both PatchIQ and activeDIQ, there is still one agent process.
- The password-filter and credential-provider DLLs are **in-process plug-ins of LSASS and LogonUI**, not separate processes. They talk to the agent over a local named pipe with a strict ACL.
- Event reading: `EvtSubscribe` through syscall wrappers (adopt the Apache-2.0 winlogbeat code). ETW is optional later.
- GPMC/RSoP/PowerShell tasks go to an optional **"Windows management helper"** role, which is the same agent plus a .NET 10 helper executable invoked with typed requests.

### 3.4 (c) Logon-screen components and DC-resident DLLs

| Component | Go | .NET | C++ | Rust | Choice |
|---|---|---|---|---|---|
| Password filter / notification package (LSASS) | **Blocked.** A c-shared DLL embeds its own runtime and threads, cannot be unloaded ([#11100](https://github.com/golang/go/issues/11100)), and has loader-lock risks inside LSASS. | **Not viable.** Hosting managed code in LSASS is unsupported `[UNVERIFIED]`, and under PPL every module must meet Microsoft's signing rules. | The conventional route; Microsoft docs and samples | `windows-rs`, plain DLL exports, `catch_unwind` at the FFI boundary, memory safety. **No public Rust password filter exists**, so we would be first. | **Rust**, with a C++ fallback decided in Phase 0. Either way: Microsoft LSA signing + SDL. |
| Credential provider (LogonUI, SYSTEM) | Blocked (same DLL reasons) | Not viable for a supported product `[UNVERIFIED]` | Microsoft's V2 sample is C++ ([sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider)) | `windows-rs` `#[implement]` supports COM; sample-quality Rust providers exist ([example](https://github.com/SubconsciousCompute/windows-credential-provider-rs)) | **Rust**, fall back to C++ if the Phase-0 spike hits COM/LogonUI blockers within 2 weeks. Build x64 + ARM64. |
| macOS | — | — | — | — | **Swift**: Platform SSO extension, plus an authorization-plugin fallback |
| Linux PAM | — | — | **C** (or Rust with PAM bindings) | — | C, small and fuzzed |

Why Rust over C++ by default: these DLLs run as SYSTEM or inside LSASS, where a memory bug means DC reboots or privilege escalation. AI coding agents make exactly the mistakes (lifetimes, buffer handling) that Rust's compiler rejects. The fallback exists because Rust here has no precedent.

### 3.5 Recommendation

**Go** for the server, the connector and the Windows agent (as platform-agent modules).
- We own four thin adapters: a GSSAPI client with CBT on go-krb5/krb5 at a pinned `main` commit (no fork unless a trigger in §3.1 fires; ADR-0001 erratum E1); a RADIUS server; a SAML IdP on goxmldsig; a typed PowerShell bridge.

**Rust (C++ fallback)** for the password-filter and credential-provider DLLs. **Swift** for macOS. **C** for PAM.

**.NET 10 + PowerShell 7.6** only as an isolated sidecar for Exchange Online and GPMC-parity reports, always driven through `AddCommand`/`AddParameter`.

House consistency wins wherever it isn't blocked: Go is blocked only inside LSASS/LogonUI and for structured PowerShell, and the recommendation routes around both.

---

## 4. Reference architecture sketch

### 4.1 Components

| Component | Runs where | Language | Purpose |
|---|---|---|---|
| **activeDIQ server** | Windows/Linux VM, Docker, Kubernetes, SaaS | Go | Public API (REST + gRPC, OpenAPI), React UI as one client, policy/RBAC/approvals, jobs (River on Postgres), event pipeline, detections, reports, snapshot/backup service, IdP (OIDC/SAML), MFA, Graph/EXO/Google connectors |
| **Directory connector** | Embedded in the server (on-prem) or a standalone process near the DCs (SaaS/MSP) | Go | LDAP/Kerberos/SMB/MS-RPC to DCs; DC locator; snapshots and DirSync; executes typed write operations; dials out to the control plane |
| **RADIUS service** | On-prem, near the VPN | Go | RADIUS with mandatory Message-Authenticator; RADIUS/TLS |
| **SSPR edge** (optional) | DMZ | Go (+ static React) | Stateless proxy for the public SSPR flows; no secrets; the server tunnels out to it |
| **Platform agent: `addc` module** | Every DC (optional but required for full auditing and password policy) | Go | Security-log subscription, password-filter IPC, local policy cache, health |
| **Password filter DLL** | LSASS on every writable DC | Rust/C++ | Policy checks; change notifications → agent |
| **Platform agent: `fileserver` module** | Windows file servers | Go | File auditing, ACL operations, effective access |
| **Windows management helper** (optional) | One member server | Go agent + .NET 10 helper | `Get-GPOReport`, `Backup-GPO`, RSoP; WS-only PowerShell |
| **Endpoint logon components** | Windows / macOS / Linux endpoints | Rust/C++ · Swift · C | SSPR at logon; cached-credential refresh (through the platform agent where present) |
| **FPolicy receiver** | Linux, near the NAS | Go | NetApp external FPolicy server |
| **Tier-0 connector** (optional) | Tier-0 admin forest or PAW-adjacent host | Go | Protected-group management, SACLs, DC-OU GPOs; JIT + approvals |

### 4.2 Diagram

```
                      +---------------- Optional SaaS control plane (multi-tenant) ----------------+
                      |  API gateway -> activeDIQ services (Go) -> Postgres (RLS by tenant_id)     |
                      |  object store (snapshots, GPO backups) · KMS · detections · IdP/MFA        |
                      +-----------^---------------------------------------^------------------------+
                                  | outbound mTLS gRPC (connector-dialed)  | HTTPS: browsers, OIDC/SAML,
                                  |                                        | WebAuthn, Graph/Google APIs
+-------------------- Customer site (on-prem / private cloud) -----------------------------------------------+
|                                                                                                            |
|  +----------------- activeDIQ server (single binary | k8s) ----------------+      +---- DMZ ----+          |
|  | API + UI · RBAC/approvals · jobs · reports · event pipeline · IdP/MFA   |----->| SSPR edge   |<-- users |
|  | directory connector · backup store · RADIUS · EXO sidecar (.NET/pwsh)   | tunnel| (stateless) |          |
|  +------+------------------------+----------------------------+------------+      +-------------+          |
|         | LDAPS+Kerberos(CBT)    | SMB3 (SYSVOL) / MS-RPC     ^ gRPC mTLS (agents dial in, typed msgs)    |
|         v                        v                            |                                            |
|  +------------------------------------------+     +-----------+-----------+   +------------------------+   |
|  | Domain controllers (AD DS, DNS, SYSVOL)  |     | platform agent        |   | platform agent         |   |
|  |   LSASS + pwd-filter DLL --named pipe--> | --> | 'addc' module (DC)    |   | 'fileserver' /         |   |
|  |   Security log --EvtSubscribe----------> |     | buffer · policy cache |   | 'mgmthelper' modules  |   |
|  +------------------------------------------+     +-----------------------+   +------------------------+   |
|                                                                                                            |
|  Endpoints: Windows credential provider (Rust/C++) · macOS PSSO ext / auth plug-in · Linux PAM             |
|             --- pinned mutual TLS ---> server SSPR API     NetApp ONTAP --FPolicy--> FPolicy receiver      |
|  Optional Tier-0 connector (separate host, JIT rights, 2-person approval) --LDAPS--> DCs                    |
+------------------------------------------------------------------------------------------------------------+
```

### 4.3 Deployment shapes (one codebase, one set of profiles)

| Profile | Shape | Identity to AD | Notes |
|---|---|---|---|
| **On-prem, Windows** | MSI: server service + bundled Postgres, or the customer's Postgres | gMSA | Default for mid-market; WEF option uses the built-in WEC |
| **On-prem, Linux / Docker** | Compose or systemd: server + Postgres + object store (MinIO/filesystem) | AES keytab (or gMSA retrieval `[LAB]`) | Mirrors PatchIQ's compose dev stack |
| **Air-gapped** | Same as above, plus offline update bundles signed with an offline root key; no SaaS; local breach-password corpus | Keytab / gMSA | No telemetry; KEK from a passphrase or HSM |
| **Private cloud** | Helm on Kubernetes; external Postgres; KMS | Keytab via secret store | HA for server workers; connector near the DCs |
| **Multi-tenant SaaS** | Control plane in our cloud; per-customer **directory connector** + agents on-prem, dialing out | Connector-local keytab/gMSA; credentials never leave the site | MSP hierarchy; data residency per region |

### 4.4 Data flows

1. **Inventory and reporting.** Connector paged-reads each NC, then streams DirSync deltas → normalized object store (Postgres; partitioned by tenant and NC) → report engine (typed query DSL) → UI/API/exports.
2. **Write action.** UI/API → policy check (RBAC scope by OU/GUID) → optional approval → job → connector executes typed LDAP operations against a pinned DC → read-back verification → hash-chained audit record → webhook/event.
3. **Change and audit.** DirSync deltas (what/when) + agent events (who: 5136/4738/…) → correlator (GUID + originating DC + time) → change timeline, alerts, SIEM export.
4. **SSPR (web).** User → edge → server (enrollment check, MFA) → connector password reset with `…2239` → result. If the password filter is installed, the DC's filter enforces our policy first.
5. **SSPR at logon.** Credential-provider tile → pinned-TLS SSPR API (direct or through the edge) → same as flow 4 → the provider submits the new credential to LogonUI → the platform agent refreshes cached credentials after reconnect.
6. **Password sync.** Filter `PasswordChangeNotify` → DPAPI-encrypted queue → `addc` module → server → Graph/Google targets (retries, idempotent).
7. **MFA/SSO/RADIUS.** Browser ↔ server IdP (OIDC/SAML/WebAuthn); VPN → RADIUS service → server MFA (push/TOTP) → Access-Accept/Reject with Message-Authenticator.

### 4.5 Where multi-tenancy lives

- **Data.** `tenant_id` is a NOT NULL column on every table from migration 1, and is the leading column of every primary key and index. RLS policies use `current_setting('app.tenant_id')::uuid`, set per transaction with `set_config($1, true)`. `FORCE ROW LEVEL SECURITY` is on. The app role is neither the owner nor `BYPASSRLS`, and migrations run under a separate owner role.
- **Hierarchy.** Platform → tenant (customer or MSP) → child tenants (MSP customers) → forest connections → domains → scopes (OU/GUID sets) used by RBAC.
- **Identity of machines.** Each connector and agent holds an mTLS certificate whose SAN encodes the tenant and the component (SPIFFE-style). The server derives the tenant from the certificate, **never from the message body**.
- **Keys.** Per-tenant data keys under the KEK; per-tenant signing keys for agent policy.
- **Single-tenant on-prem** installs still run with exactly one tenant row, so it is the same codebase and the same migrations.

### 4.6 Extension points (defined before features)

| Extension point | Contract | First implementations |
|---|---|---|
| Directory provider | `Search`/`Apply(op)`/`Watch` with typed operations | AD (LDAP), Entra (Graph), Google; generic LDAP later |
| Action / workflow step | Typed input/output schema, idempotency key, compensation | create user, reset password, add to group, create mailbox |
| Event source | Normalized event schema (OCSF-like) `[EST]` | DC agent, WEF receiver, FPolicy, Samba JSON audit (lab) |
| Detection rule | Declarative rule (Sigma-like) over normalized events + posture queries | §1.5.2 catalogue |
| Authentication method | Enroll / verify interface | TOTP, WebAuthn, push, RADIUS proxy, Entra external MFA |
| Notifier / sink | Typed payload, signed webhooks | email, Teams/Slack, SIEM (syslog/CEF/HTTP) |

---

## 5. Lab & test strategy (macOS team, AI agents)

### 5.1 Test pyramid

| Layer | Runs on | What |
|---|---|---|
| Unit + property/fuzz | macOS / Linux CI | `ldapx` filter/DN/SD primitives, Registry.pol/GptTmpl/dnsRecord parsers, report DSL → SQL, RLS policy tests |
| Protocol contract | macOS / Linux CI | Recorded BER exchanges from real DCs (golden fixtures) replayed against the client; Windows-only behaviour pinned by fixtures |
| Integration (Samba) | Docker on macOS / Linux CI (testcontainers-go) | Connector reads/writes, paging/range, DirSync, password set/change, FGPP, kpasswd, SAMR, SMB SYSVOL |
| System (Windows) | Nightly, self-hosted ephemeral runners in an Azure lab | WS2025 + WS2022 DCs with LDAP signing/CBT enforced; agent, password filter, credential provider, WEF, GPO round-trips, detections |
| Attack replay | Weekly, GOAD-style vulnerable lab | Kerberoast, AS-REP roast, DCSync, spray, Shadow Credentials, BadSuccessor → detections fire |
| E2E UI | Linux CI (Playwright) against a Samba-backed stack | Admin and SSPR journeys |

### 5.2 What Samba 4 AD DC emulates faithfully vs not

Latest stable: **4.25.0 (2026-09-24)** ([news](https://www.samba.org/samba/latest_news.html)).

| Area | Samba fidelity | Source |
|---|---|---|
| Schema / functional level | Default functional level is 2008 R2. Since 4.19, new domains get a database prepared for **FL 2016 with schema 2019**. Raising to 2016 is opt-in (`ad dc functional level = 2016`), with claims, silos and auth policies partially implemented. No WS2025 functional level. | [4.19 notes](https://www.samba.org/samba/history/samba-4.19.0.html) |
| LDAP controls | Paged results, VLV, **DirSync** present (`dirsync.c`, `vlv_pagination.c` in the DSDB module tree); ranged retrieval, IN_CHAIN, tokenGroups `[LAB]` | [dirsync.c](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/dirsync.c); [vlv_pagination.c](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/vlv_pagination.c) |
| LDAP signing / channel binding | Server supports SASL over TLS **with channel bindings since 4.21** (`ldap server require strong auth = yes`) — good for testing our CBT adapter | [4.21 notes](https://www.samba.org/samba/history/samba-4.21.0.html) |
| Kerberos | Heimdal-based KDC; kpasswd on 464; since 4.24 the default domain enctypes are AES-only at domain functional level 2008+ (addresses CVE-2026-20833) | [4.24 notes](https://www.samba.org/samba/history/samba-4.24.0.html); [ports](https://wiki.samba.org/index.php/Samba_AD_DC_Port_Usage) |
| Password policy / FGPP | FGPP (PSOs) supported since 4.9 | [4.9 notes](https://www.samba.org/samba/history/samba-4.9.0.html) |
| gMSA | `samba-tool` client support for reading gMSA passwords and getting TGTs (4.20) | [4.20 notes](https://www.samba.org/samba/history/samba-4.20.0.html) |
| Recycle Bin / tombstones | DSDB code tracks deleted/recycled states (`replmd_recyclebin_enabled`); full undelete parity `[LAB]` | [repl_meta_data.c](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/repl_meta_data.c) |
| GPO | GPC/GPT objects exist and `samba-tool gpo` manages them, but **no Windows client processing**; SYSVOL is not replicated between Samba DCs `[UNVERIFIED]` | — |
| ADWS / AD PowerShell | **Not present.** Port 9389 is absent from Samba's port list, so the `ActiveDirectory` PowerShell module cannot target Samba. | [ports](https://wiki.samba.org/index.php/Samba_AD_DC_Port_Usage) |
| Windows Security event log | **None.** Samba writes JSON audit logs instead, so event-pipeline tests need Windows DCs or recorded EVTX fixtures | — |
| Hardening behaviour | No WS2025-specific defaults (confidential-attribute encryption, SAMR blocking, RC4 TGT refusal) → test on Windows | [WS2025](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025) |

**Running it on macOS:** Samba's SYSVOL needs xattr/ACL support, so start with Docker named volumes rather than macOS bind mounts `[UNVERIFIED]`. Pin an arm64-capable image or build our own from the distro package `[LAB]`.

### 5.3 Windows Server labs and Apple silicon

- **Evaluation media.** WS2025 evaluation comes as ISO, VHD or an Azure image, **expires in 180 days**, must be activated online, and can be converted to retail ([Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025); [conversion](https://learn.microsoft.com/en-us/windows-server/get-started/upgrade-conversion-options)). Rearm counts are `[UNVERIFIED]`. Rebuild labs from code rather than rearming.
- **x64 only.** Windows Server requires an "x64 instruction set" processor ([hardware requirements](https://learn.microsoft.com/en-us/windows-server/get-started/hardware-requirements)).
  - Azure's Arm (Cobalt 100) VMs list *Windows Client*, not Windows Server ([Dpsv6](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dpsv6-series)).
  - On Macs, Parallels Desktop 18–20 is authorized for **Arm Windows 11 Pro/Enterprise** only ([Microsoft support](https://support.microsoft.com/en-us/windows/options-for-using-windows-11-with-mac-computers-with-apple-m1-m2-and-m3-chips-cd15fd62-9b34-4b78-b0bc-121baa3c568c)).
  - Docker Desktop on Mac cannot run Windows containers.
  - UTM x86 emulation is impractically slow for DCs `[EST]`.
- **Local use for Macs.** A Windows 11 ARM64 VM (Parallels) for developing the credential provider (ARM64 build) and as a domain-joined client of a cloud DC over VPN/Tailscale.
- **Domain controllers.** Azure (§5.4), or a shared **x86 lab box** (64–96 GB mini-PC with Proxmox, ≈ $1.0–1.5k one-time `[EST]`) running GOAD or Ludus.

### 5.4 Cloud lab cost: 2 DCs + 1 member server

Azure Retail Prices API, East US, pay-as-you-go, Windows, retrieved 2026-10-02 ([API](https://prices.azure.com/api/retail/prices)):

| Item | Price |
|---|---|
| B2s Windows (2 vCPU / 4 GB) | $0.0496/h |
| B2ms Windows (2 vCPU / 8 GB) | $0.0912/h |
| D2s_v5 Windows | $0.188/h |
| Standard SSD E10 (128 GiB) | $9.60/month |
| Premium SSD P10 | $19.71/month |

Deallocated VMs incur no compute charges, but disks and networking still bill ([billing states](https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing)). Azure VM [auto-shutdown](https://learn.microsoft.com/en-us/azure/virtual-machines/auto-shutdown-vm) handles the off-hours schedule.

| Lab sizing | 24×7 (730 h) | Workdays only (220 h, auto-shutdown) |
|---|---|---|
| A: 3 × B2ms + 3 × E10 | 3 × 0.0912 × 730 = **$199.73** + $28.80 = **≈ $229/mo** | $60.19 + $28.80 = **≈ $89/mo** |
| B: 2 × B2s (DCs) + 1 × B2ms + 3 × E10 | $138.99 + $28.80 = **≈ $168/mo** | $41.89 + $28.80 = **≈ $71/mo** |
| C (performance): 3 × D2s_v5 + 3 × P10 | $411.72 + $59.13 = **≈ $471/mo** | $124.08 + $59.13 = **≈ $183/mo** |

- These figures exclude public IPs, Bastion, egress and snapshots. Use a Tailscale/WireGuard subnet router instead of Bastion.
- Five developers on per-person ephemeral labs (B, 220 h) cost ≈ $354/month `[EST]`.
- **AWS** for comparison: t3.large Linux is $0.0832/h ([Vantage](https://instances.vantage.sh/aws/ec2/t3.large)). The Windows rate is ≈ $0.11/h `[UNVERIFIED]`, so costs are similar.

### 5.5 Automated lab building

| Tool | Use | Constraints |
|---|---|---|
| **Terraform (azurerm) + Packer** | Golden WS2025/WS2022 images (patched, sysprepped) → 2-DC forest + member + Win11 client per test run | Promoting a DC needs reboots, so drive it with PowerShell DSC ([ActiveDirectoryDsc](https://github.com/dsccommunity/ActiveDirectoryDsc), MIT, active 2026-09) or a custom script extension |
| [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (GPL-3.0) | Deliberately vulnerable multi-forest labs (GOAD 5 VMs, GOAD-Light 3, MINILAB 2, SCCM 4) for **detection testing** | Providers: VirtualBox, VMware, Azure, AWS, Proxmox, Ludus ([providers](https://orange-cyberdefense.github.io/GOAD/providers/)); internal use only (GPL) |
| [AutomatedLab](https://github.com/AutomatedLab/AutomatedLab) (MIT) | PowerShell lab framework | Needs a Windows Hyper-V host or Azure; not usable from macOS directly |
| Ludus | Proxmox-based range builder (hosts GOAD) | Requires an x86 Proxmox host `[UNVERIFIED specifics]` |
| [rgl/windows-vagrant](https://github.com/rgl/windows-vagrant) (MIT, active), [StefanScherer/packer-windows](https://github.com/StefanScherer/packer-windows) (last push 2025-06) | Packer templates for Windows boxes | x86 hypervisors only, so not on Apple silicon |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (MIT) | Scripted ATT&CK techniques to generate detection test events | Run only in isolated labs |

**Snapshot hygiene.** Never revert a single DC in a multi-DC lab: it risks USN rollback. Revert the whole lab, or rebuild from images.

### 5.6 Entra / M365 / Google test tenants

- **Microsoft 365 Developer Program (2026).** E5 sandboxes (25 licences, instant sandbox) only for **Visual Studio Professional/Enterprise subscribers** or **ISV Success / eligible Microsoft AI Cloud Partner Program** members ([FAQ](https://learn.microsoft.com/en-us/office/developer-program/microsoft-365-developer-program-faq)).
  - Action: join ISV Success / MAICPP as skenzeriq, or buy one VS Professional subscription.
  - Fallback: an Entra ID Free tenant (comes with an Azure account) for Graph user/group work, plus time-boxed trials for E5 features `[UNVERIFIED trial terms]`.
- **Google:** a Workspace trial or a Cloud Identity Free tenant for the Admin SDK Directory API `[UNVERIFIED limits]`.
- **Graph tests:** app-only certificate auth; record and replay HTTP fixtures for CI; live-tenant tests nightly only.

### 5.7 CI: what runs where

| Job | Runner | Cost / notes |
|---|---|---|
| Go unit/fuzz, Samba integration (testcontainers), web unit + Playwright, codegen-drift, lint (forbidigo/semgrep rules from §2.7) | GitHub Linux x64/arm64 | $0.006/min (2-core) ([pricing](https://docs.github.com/en/billing/reference/actions-runner-pricing)) |
| Windows agent build + unit tests, SD golden tests vs `x/sys/windows`, DLL builds (x64 + **ARM64** on `windows-11-arm`), Authenticode signing | GitHub `windows-2025` / `windows-2022` / `windows-11-arm` ([runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)) | $0.010/min. **Cannot promote a DC on hosted runners**: promotion reboots the runner `[EST]` |
| DC system tests, password filter in LSASS (audit mode → events 3065/3066), credential provider UI automation, WEF/agent throughput (target ≥ 3k eps per collector), detections | Self-hosted **ephemeral** runners inside the Azure lab, nightly | Lab cost §5.4 |
| macOS PSSO extension / auth plug-in | GitHub macOS runners | Notarization in CI with a stored API key |
| LSA-plugin signing submission, EV/Authenticode key use | Human-gated release pipeline | Not delegated to agents |

### 5.8 Making it AI-agent friendly

- Use PatchIQ-style `make` targets: `make lab-up`/`lab-down`, `make test-samba`, `make test-windows` (dispatches to the lab), `make fixtures-record`.
- Lab state comes only from code: Terraform state lives in the backend, nothing is configured by hand. Seeds are deterministic: generated users, OUs and groups from a fixture spec.
- Golden-fixture recorder: capture LDAP/RPC exchanges against real WS2025 once, so agents can iterate offline on macOS.
- Guardrails in CI: forbidden-API lint, RLS coverage check, "no secret fields in responses" schema check, and dependency licence check (block GPL into product binaries).

---

## 6. Build-order implications

### 6.1 Must exist first (foundation, before any feature)

1. **Tenant + RBAC core.** `tenant_id` + RLS from migration 1; scopes as OU/GUID sets; approvals; hash-chained audit log of our own actions.
2. **Safe-primitive library and its lint rules.** `ldapx/filter`, `ldapx/dn`, `secdesc`, `psx`, `sqlx` helpers, `csvx`, `Secret` type. Lint rules land before the first feature PR.
3. **Directory connector.**
   - DC locator, LDAPS, the Kerberos GSSAPI adapter **with CBT**, and connection pooling with DC affinity.
   - Paging, range and DirSync; schema cache; `<GUID=…>` addressing.
   - Typed operations with idempotency.
   - Operating modes: embedded and out-of-process (SaaS).
4. **Job engine** (River) with dry-run/diff/approve/execute/verify phases.
5. **Event pipeline skeleton.** Normalized schema, partitioned storage, agent ingestion over gRPC, back-pressure.
6. **Platform-agent module contract.** Agreed with the PatchIQ/UEM owners, to honour "one agent process per endpoint".
7. **Public API + OpenAPI codegen.** The UI is just one client.

### 6.2 Long poles

| Long pole | Why it is long | De-risking spike (Phase 0) |
|---|---|---|
| **Password filter + LSA signing** | Code in LSASS on every writable DC. Microsoft-signature requirement under LSA protection plus SDL conformance, with an unknown review lead time. Crash = DC reboot. No debugger under PPL. | Minimal Rust and C++ filters on a WS2025 DC in **audit mode** (`AuditLevel=8` → events 3065/3066). Start the Partner Center / LSA file-signing enrolment **in week 1**. |
| **Credential provider** | COM in LogonUI as SYSTEM; x64 + ARM64; logon, unlock, change and PLAP scenarios; RDP/NLA; offline/VPN; security review. ManageEngine's repeated CVEs show the risk. | A V2 provider with native fields calling a mock SSPR API over pinned mTLS; fuzz the message parser; red-team kiosk-escape attempts. |
| **GPO settings (report parity, then editing)** | Many CSE formats, ADMX resolution, version and ACL invariants across AD and SYSVOL | Parse Registry.pol, GptTmpl.inf and GPP for 50 real-world GPOs; diff against `Get-GPOReport` XML; round-trip one Admin Template edit verified by `gpresult`. |
| **Auditing at scale** | DC event volume; ≈ 3k eps per collector; no gap signal on log wrap; storage and retention costs | Agent `EvtSubscribe` throughput test at 5k eps synthetic; WEF → own MS-WSMV receiver prototype (HTTPS with client certs first, Kerberos-encrypted second); measure Postgres partitioned ingest. |
| **Effective permissions (AD + NTFS)** | Must match Windows access-check semantics exactly | Implement the AD access check over the typed SD model; compare with Windows "Effective Access" on 1,000 generated cases (golden tests on the Windows runner). |
| **macOS Platform SSO** | Requires activeDIQ to be an IdP plus a Swift extension, with Apple entitlements and notarization | Defer to Phase 3; spike only the authorization-plug-in fallback earlier if sales need it. |
| **LDAP hardening interop** | go-ldap has no CBT/sign-seal on Linux; go-krb5/krb5 is young and its CBT is untagged (`main` only) | The Phase-0 gate in §2.4: bind under signing + CBT "Always" on WS2025 and Samba 4.21+, with no 2887/3039/3074 events. |

### 6.3 Phased technical roadmap `[EST]`

| Phase | Duration | Scope | Exit criteria |
|---|---|---|---|
| **0 — Prototypes and foundations** | ~8 weeks | Spikes from §6.2. Foundations 1–7 at skeleton level. Terraform/Packer Azure lab + Samba compose. Golden-fixture recorder. LSA-signing enrolment. Graph + EXO V3 cert-auth smoke test from a Linux container. | Every gate green, or an explicit fallback decision (Rust vs C++; own WEC vs Windows WEC; .NET helper scope) |
| **1 — "ADManager core" MVP** | ~4–6 months | Directory management, bulk ops, delegation/RBAC/approvals, reports (stale, membership, ACL), DirSync change history, snapshots + attribute-level restore, Recycle Bin restore, GPO inventory/link/backup/restore, **SSPR web portal** with TOTP + WebAuthn, admin MFA | Runs against WS2016–WS2025 with signing/CBT enforced; no Domain Admin; passes external pentest |
| **2 — Audit + password security** | ~4–6 months | DC agent module, event pipeline, change attribution ("who"), §1.5.2 detections, file-server auditing, **password filter GA** (custom/banned/breached rules) + password sync, **credential provider GA** (Windows logon/unlock), RADIUS | 3k eps sustained per collector; filter signed and loading under RunAsPPL; provider passes red-team |
| **3 — Breadth and cloud** | ~6+ months | OIDC/SAML IdP, push MFA app, Entra external MFA, M365/Exchange Online + Google, NetApp FPolicy, GPO Admin-Template editing, macOS (PSSO/auth plug-in) + Linux PAM, multi-tenant SaaS + MSP | Parity checklist vs the ManageEngine suite ≥ 90% of the features customers actually use (per the market-research docs) |

---

## Appendix A. Open questions

1. **Minimum supported DC OS.** WS2016+ fits the FL-2016 floor for new WS2025 forests ([WS2025](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025)). Do we need WS2012 R2?
2. **Agents on DCs.** Will target customers accept an agent and a password-filter DLL on DCs, or must auditing work agentless (WEF) from day 1?
3. **LSA plug-in signing.** Programme requirements, cost and lead time for skenzeriq (Partner Center account, EV certificate, SDL evidence)? This gates Phase 2.
4. **Platform agent ownership.** Who owns the unified skenzeriq agent (PatchIQ/UEM) and its module API, for "one agent process per endpoint"?
5. **SaaS acceptance.** Will customers allow outbound-only connectors near DCs? Which data-residency regions?
6. **Scope of on-prem Exchange.** Exchange Server management needs Windows/PowerShell remoting; EWS on-prem is unaffected by the Exchange Online retirement.
7. **RADIUS protocols.** Do target VPNs need MSCHAPv2/PEAP? That requires Netlogon pass-through or NPS.
8. **macOS strategy.** Build a full IdP + Platform SSO extension, or ship the authorization-plug-in fallback first?
9. **Sensitive snapshot content.** Exclude LAPS/BitLocker/confidential attributes from snapshots by default? (Proposed: yes.)
10. **Password sync vs Entra Connect.** Is password sync to Entra a differentiator, or do we defer to Entra PHS and writeback?
11. **Licence policy.** Confirm GPL tools (GOAD, OpenWEC) are lab/reference-only, and that the MPL-2.0 (layeh/radius) policy is moot since we write our own.
12. **Rust vs C++ for the DLLs.** Who on the team can review Rust/C++ COM and LSASS code? AI-written code here needs expert human review.

## Appendix B. Key references

**Microsoft Open Specifications**
- MS-ADTS: [unicodePwd](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2), [LDAP controls](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea), [LDAP policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99), [DirSync](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/2213a7f2-0a36-483c-b2a4-8574d53aa1e3), [replication metadata](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/21ea8133-4947-4409-bca8-4239723d3e6a), [undelete](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4302a2eb-55c8-426c-b310-6791c6ae8307), [control access rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb)
- MS-GPOL [GPO search](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/b0e5c9e8-e858-4a7a-a94a-4a3d0a9d87a2) · MS-GPREG [syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/5c092c22-bf6b-4e7f-b180-b20743d368f5) · MS-SAMR [User4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/bbc1c5e5-9b81-4038-b2b9-c87d3569ed38) · MS-KILE [change/set](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/00380d42-3b3f-456c-945f-8685bd189bed) · MS-DNSP [dnsRecord](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8)

**Microsoft Learn (platform and security)**
- [What's new in WS2025](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025)
- [LDAP signing & CBT](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)
- [LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Password filters](https://learn.microsoft.com/en-us/windows/win32/secmgmt/password-filters)
- [Credential providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [WEF](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- [Appendix L](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [RC4 remediation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Enterprise access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)

**Libraries**
- [go-ldap](https://github.com/go-ldap/ldap) · [go-krb5/krb5](https://github.com/go-krb5/krb5) · [go-msrpc](https://github.com/oiweiwei/go-msrpc) · [go-smb2](https://github.com/hirochachacha/go-smb2) · [winacl](https://github.com/TheManticoreProject/winacl) · [go-webauthn](https://github.com/go-webauthn/webauthn) · [zitadel/oidc](https://github.com/zitadel/oidc) · [msgraph-sdk-go](https://github.com/microsoftgraph/msgraph-sdk-go) · [OpenWEC](https://github.com/cea-sec/openwec) · [windows-rs](https://github.com/microsoft/windows-rs)

**Threat data**
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [NVD](https://nvd.nist.gov/) · [Akamai BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) · [BlastRADIUS](https://www.blastradius.fail/) · [MITRE T1558.003](https://attack.mitre.org/techniques/T1558/003/) · [T1003.006](https://attack.mitre.org/techniques/T1003/006/)

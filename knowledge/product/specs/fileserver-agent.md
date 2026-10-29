---
title: "Spec: fileserver agent module — root allow-list, closed command set, ACL via the typed SD primitive"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: heramb
author: product-manager
ticket: T-0143
epic: E-001
milestone: M3
parity: [ADM-023, ADM-045, ADA-055, ADA-057, ADA-063]
scope: locked
sources_last_checked: 2026-10-28
---

# Spec: `fileserver` agent module

> An admin installs one small agent on a file server, names the folders it may touch, and from then
> on home folders, NTFS permission changes and file-access auditing work from the console. The agent
> can do four things, only inside those folders, and nothing a compromised activeDIQ server says
> can make it do a fifth.

Closes the hand-off in [threat model §12 (TM-D13)](../../development/architecture/threat-model.md)
and TM-TB12-T10…T15, and the "final identity" open item in TM-TB12-T13. Names the subject of
**TM-F-AGENTCMD** (`fileserver` half). The host (process model, outbox, update staging, tunnel) is
[agent-host-addc-contract](../../development/architecture/agent-host-addc-contract.md); this spec
adds only the `fileserver` module. Input to `solution-architect` (reviewer: contract
`activediq.fileserver.v1`, golden RPC list), `windows-engineer` (owner of the module) and
`directory-engineer` (SD write half). `security-architect` reviews §3–§6. **Tag every build ticket
from this spec `security-sensitive`.**

## 1. Problem and user

| Who | Job | Today in ManageEngine |
| --- | --- | --- |
| AD admin / help desk | Create a user's home folder with a correct ACL as part of account creation (ADM-023) and as the NTFS step of offboarding (ADM-045) | Parity row P1/P2 in the [matrix](../../business/competitive-analysis/feature-parity-matrix.md) (ADM-023 `par`, M; ADM-045 `par`, L, Windows-native) |
| File-server admin / auditor | See who changed NTFS and share permissions and who touched which file (ADA-055, ADA-057, ADA-063) | Parity rows P2 in the matrix; matrix §"File-server agent" notes the module "must match Windows access-check semantics exactly; file auditing is the highest-volume source" |
| Security owner | Be sure the agent cannot be turned into a remote shell on a file server | Not a ManageEngine-sourced item; this is the buying objection for any host agent. Source: TM-TB12-T10 (a compromised server is assumed) |

The agent exists because the server cannot write NTFS ACLs or read the local Security log over the
product's Kerberos-only SMB path at the scale required (blueprint §5.5, §13). The whole point of the
spec is that the agent is **small enough to review in an afternoon**.

## 2. Parity baseline

| ID | Capability | What the `fileserver` module supplies | Phase |
| --- | --- | --- | --- |
| ADM-023 | Home and profile folders | `CreateFolder` + `ApplyAcl` under a root, owner is the user, no standing Full Control over all home folders (TM R12) | M3 |
| ADM-045 (NTFS block only) | Offboarding NTFS step | `ReadAcl` / `ApplyAcl` to remove a departed user's ACEs from named folders | M3 |
| ADA-055 | Windows file-server auditing | `CollectFileEvents` (stream of access events) | M3 (collection); screens per ADA specs |
| ADA-057 | NTFS and share permission changes | permission-change events (Security events 4670 class, `[UNVERIFIED — lab]` IDs) in the same stream | M3 |
| ADA-063 | File reports by server/user/share/profile | consumes the stored events and ACL reads as inventory; report definitions belong to `reporting-engineer` | M3 data, report later |

Bulk NTFS permission management (matrix lists ADM-078/079/081/082/091 under the same agent) is **out
of scope** here and gets its own spec; this module's commands are the ones it will reuse.

## 3. The closed command set

These are the only RPCs the server may invoke on a `fileserver` agent, in addition to the host
service. The list is pinned in a golden file; any addition, rename or removal fails CI and needs
`security-architect` approval (CODEOWNERS). No field of any request is a free-form string that is a
command, argument, script, SDDL text or regular expression.

| RPC | Request (typed) | Effect |
| --- | --- | --- |
| `ReadAcl` | `root_id`, relative path components (list), `operation_id` | Returns owner, DACL as typed ACE rows, control flags, and a digest of the exact bytes read. Never reads the SACL |
| `ApplyAcl` | `root_id`, relative path components, base digest, a `DACLWrite` plan from the SD primitive (T-0149 write half), `operation_id`, acting principal | Writes the DACL only, only if the current digest equals the base digest; returns before and after descriptors |
| `CreateFolder` | `root_id`, relative path components, optional initial `DACLWrite` plan, `operation_id`, acting principal | Creates one directory (not a file). Fails if it exists |
| `CollectFileEvents` | none (agent-initiated stream); the policy selects event classes from a compiled-in catalogue, narrowed to local roots | Agent calls the server's `EventIngest.Append` |
| host `GetStatus`, `ApplyPolicy`, `ApplyKeyset`, `StageUpdate`, `AckEvents` | as the host contract | unchanged |

**Denied categories (TM-D13), absent from the contract and refused if sent:** execute or spawn a
process; write file *content*; delete or rename a file or folder; change owner; read or write a
SACL; change a service or registry value; update outside the release-signed channel. The agent has
no `Delete` because ADM-045 removes access, not data.

## 4. Root allow-list (TM-TB12-T11)

- Roots are set **locally, at install, by the file server's administrator**, in a config file whose
  ACL allows administrators only. Each root gets a stable `root_id` chosen at install.
- The server addresses a root **only by `root_id` plus relative path components**. A request never
  carries an absolute path, and policy cannot name a root.
- The server can **narrow** (for example "only `\Homes\Staff`") by policy and never widen. A policy
  entry that does not resolve to a subtree of a local root rejects the whole policy.
- `SYSVOL`, `NETLOGON` and any share on a DC cannot be a root; the installer refuses them.
  Volume roots (`C:\`), the Windows directory, `Program Files`, `ProgramData` and the agent's own
  data/binary directories are refused as roots by the installer and again at every service start.
- The console shows each agent's effective roots read from `GetStatus`, so an admin sees what the
  agent can touch without logging on to the server.

## 5. Path safety (TM-TB12-T12)

Every path is canonicalised before the root check, and the check is repeated on the canonical result.
Reparse points (junctions, symbolic links, mount points) are **not followed**: a component that is a
reparse point is opened as the link itself and the command is refused. Refused syntax: `..`, 8.3
short names that resolve differently from the long name, `\\?\` and `\\.\` device paths, UNC paths,
alternate data stream syntax (`:`), trailing dots/spaces, reserved device names. Refusals return one
stable error code and are audited; the error text never echoes a resolved target path.

## 6. Identity and privileges (TM-TB12-T13)

**Decision (product-manager, subject to `security-architect` review):** the agent runs as a
**virtual service account** `NT SERVICE\activeDIQFileAgent`, the same family as
[ADR-0006](../../development/decisions/0006-dc-agent-runs-as-a-virtual-service-account.md); not a
gMSA (a gMSA is a second directory identity, ADR-0002 rule 3), not LocalSystem.

- The installer grants the service SID **Modify + WRITE_DAC on each root only**, as an inheritable
  ACE, and removes it at uninstall. It makes no other ACL change on the host.
- The token holds no SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege or
  SeSecurityPrivilege (the last is why the SACL is out). At every start the agent reads its own
  token and refuses to run holding any of them.
- The module **refuses to start on a domain controller**.
- Network use is the `fleet` mTLS dial-out only. No SMB, LDAP or RPC from the agent.
- Writable locations: the agent data directory and, within roots, only what `CreateFolder` and
  `ApplyAcl` do.
- Tier: the file server's tier (Tier 1). Install documentation states that host administrators are
  at the tier of the service (TM-R4).
- Reading file-access events needs the Security channel; it uses the same channel-ACE approach as
  ADR-0006 §2 and fails closed with a clear error if the ACE does not work.

**Known limit, stated to the user:** a folder whose DACL is protected from inheritance and that does
not grant the service SID WRITE_DAC cannot be changed, because the agent may not take ownership. The
command returns `permission_denied` for that path; it is never worked around.

## 7. Enhancements

| # | Enhancement | Pain it answers | v1 (M3)? |
| --- | --- | --- | --- |
| E1 | Every `ApplyAcl` and `CreateFolder` returns before/after descriptors, so the change is previewable and one-click undoable (ENH-04, [decisions D-0004](../../memory/decisions-log.md)) | ACL corruption by tools is the failure class the SD primitive was built to remove ([SD primitive spec](../../development/architecture/safe-primitives-security-descriptor.md) intro, feasibility §2.7) | Yes |
| E2 | The console shows "this agent can touch exactly these folders" per file server | A host agent with unknowable reach is the standard objection (TM-TB12-T11) | Yes |
| E3 | Stale-base protection: an ACL change made while someone else changed the folder fails instead of overwriting | SD-E10b `sd.stale_base` | Yes |

## 8. Experience target

Set with `product-designer` before the design ticket; proposed targets, to be confirmed against the
[task benchmark](top-admin-tasks-benchmark.md) method:

- Install and first root: **≤ 5 minutes** from MSI to "agent healthy" in the console, with the root
  entered once, as a folder picker, not typed paths.
- Create a user with a home folder: **no extra screen** over creating the user (the folder is a
  field of the creation flow).
- The admin never writes SDDL, never types an ACE mask number, never types a UNC path to an
  administrative share.

## 9. Platform matrix

| Cell | Decision |
| --- | --- |
| Agent OS | **Windows Server 2019, 2022, 2025, member servers only.** Server 2016 and earlier: not supported (decision; matches the `addc` WS2019+ floor) |
| Linux/Samba/NAS file servers | **Not supported in M3.** No Linux agent exists (blueprint §13). NetApp/Dell FPolicy is a later research item, not this spec |
| Domain controllers | Refused (§6) |
| Failover clusters / DFS-N namespaces | Roots must be local volumes or clustered volumes with the agent installed on every node; DFS namespace paths are not roots. Clustered behaviour is `[UNVERIFIED — lab]` and a lab ticket precedes build |
| Filesystem | NTFS only. ReFS and FAT/exFAT: refused as roots until tested |
| Directory | On-prem AD and hybrid: trustees are SIDs resolved by the server. Entra-only tenants have no file server in scope; the module is not offered. Cloud-only users get no folder |
| Server side | Both deployment profiles run `fleet`, `EventIngest` and the SD write half |

## 10. Security and audit

- Directory privileges: **none**. The agent holds no AD identity; trustees arrive as SIDs.
- Our audit trail records, per command: operation ID, acting principal, tenant, agent identity, root
  id, relative path, the before and after descriptors (ACE rows and digests), outcome, and refusals
  with their code (TM-TB12-T14). ACL reads and file events are inventory under RBAC trimming and
  carry the per-agent identity (TM-TB12-T15).
- A hostile or compromised server can still apply any DACL the primitive can express inside the
  roots (residual, TM-TB12-T10). The agent therefore also refuses plans the primitive rejects
  (`sd.self_lockout`, `sd.inherited_ace_immutable`, `sd.not_editable` and the SD-E codes) and
  applies a per-minute ceiling on `ApplyAcl` set locally (can be narrowed, not widened).
- `security-architect` must look at: root canonicalisation, token check at start, the golden RPC
  list, the installer ACE on roots, and the Security-channel ACE.

## 11. Acceptance criteria

All verifiable by `qa-verifier` against a Windows lab file server and a test server that can send
hostile requests. Evidence is the agent's response code plus an audit record.

**Threat-model rows (each required by the ticket)**

- **TM-TB12-T10 (hostile commands).**
  Given a test server that is fully compromised, When it sends `Exec`, `WriteFile`, `Delete`,
  `SetOwner`, `SetSacl`, `SetService`, `SetRegistry` or any method not in §3, or an `ApplyAcl` whose
  descriptor is raw bytes or SDDL text, Then every call is refused with the same code, no file,
  service, registry or ACL changes (verified by before/after listing), and an audit event names the
  agent. And the generated `activediq.fileserver.v1` descriptors equal the golden list; adding any
  RPC in a branch fails the lint.
- **TM-TB12-T11 (root allow-list).**
  Given roots `D:\Homes` and `D:\Shares\Finance` set locally, When the server sends a request for
  `C:\`, another share, `D:\Other`, an absolute path, or a policy that names a root, Then each is
  refused and nothing is created. Given a policy that narrows to `Homes\Staff`, Then requests under
  `Homes\Contractors` are refused. Given a policy that tries to widen, Then the policy is rejected
  whole and the previous policy stays active. Given the config file is edited by a non-administrator
  account, Then the edit is impossible (ACL) and a tampered file makes the agent refuse to start.
- **TM-TB12-T12 (path escape).**
  Given a corpus that includes `..\`, a junction inside a root pointing to `C:\Windows`, a symbolic
  link to another share, a mount point, an 8.3 name, `\\?\C:\`, `\\.\PhysicalDrive0`, a UNC path,
  `file.txt:stream`, trailing dot/space and `CON`, When each is sent to `ReadAcl`, `ApplyAcl` and
  `CreateFolder`, Then every one is refused, the target of the link is unchanged (checked by hash
  of its descriptor before and after), and the error text contains no resolved target path. A
  junction created *after* a successful earlier command is also refused on the next one.
- **TM-TB12-T13 (agent privilege).**
  Given a domain controller, When the MSI or service starts, Then it refuses with a clear message.
  Given `SYSVOL`, `NETLOGON` or `C:\` entered as a root, Then the installer refuses it, and a
  hand-edited config with it makes the service refuse to start. Given the service token is modified
  to hold SeBackupPrivilege (or Restore, TakeOwnership, Security), Then the service refuses to run.
  Given a running agent, Then `whoami /priv` of its process shows none of them, the account is
  `NT SERVICE\activeDIQFileAgent`, and its only added ACE on the host is Modify + WRITE_DAC on each
  root. Uninstall removes that ACE.
- **TM-TB12-T14 (attribution and undo).**
  Given an `ApplyAcl` from operation OP-1 by principal P, When it succeeds, Then the audit trail has
  OP-1, P, the before and after descriptors, and the console offers undo that, when run, restores the
  original ACE rows (byte-equal DACL). Given a command without an operation ID or acting principal,
  Then the agent refuses it. Given the DACL changed on the server between read and write, Then
  `ApplyAcl` fails `stale_base` and writes nothing.
- **TM-TB12-T15 (exposure).**
  Given a help-desk technician whose RBAC scope excludes the Finance share, When they open file
  events or ACL reads for it, Then they see none (API and UI). Given a stored event, Then it carries
  the server-stamped per-agent identity and any identity field inside the payload is ignored.

**Product behaviour**

- Given a user created with a home folder under `D:\Homes`, When creation completes, Then the folder
  exists, the user owns it with Modify, no other standing Full Control ACE was added, and the audit
  record exists (ADM-023).
- Given an offboarding that removes user U from three folders, When one folder is protected and
  not writable by the service, Then two succeed, one returns `permission_denied`, the console shows
  a partial result naming the folder, and retry after the admin grants access succeeds.
- Given the agent is offline, When a command is issued, Then the console shows the agent as
  unreachable and the operation as not applied (never "success"); on reconnect nothing replays
  without a new operation ID.
- Given a root with 1 000 000 files and a folder whose ACL has 1 500 ACEs, When `ReadAcl` runs on
  the folder, Then it returns inside 2 s, and a root-wide enumeration is **not** a command
  (nothing walks the tree on the server's request).
- Given an ACL result that would exceed 4 095 ACEs or 65 535 bytes, Then `ApplyAcl` fails with
  `sd.acl_too_large` and writes nothing.
- Given file-access events at 3 000 events/s for 10 minutes, Then agent CPU and memory stay within
  the local ceilings, the outbox drops oldest-first only after raising a visible gap event, and the
  file server's user-visible latency does not change `[UNVERIFIED — lab threshold, set in the lab
  ticket]`.
- Given an empty install (no roots configured), Then the agent starts, reports "no roots", and
  every path command is refused.

## 12. Out of scope

Bulk NTFS permission management and effective-access reports (separate spec); share-permission
(SMB share ACL) writes; file content operations, delete, move, quota; Linux, NAS, Azure Files and
SharePoint; SACL management; tree walks initiated by the server; DFS namespace management; agent
self-update beyond the host's signed channel.

## 13. Open questions

Answered here (decided, logged in the ticket): identity (§6), OS floor (§9), no SACL (§3), no delete (§3).

For others, not CEO-directional:

1. `ad-expert` / lab: event IDs for permission-change and file-access events at scale, and whether
   auditing SACLs must be set by the customer's GPO (the agent does not set them). Needed before the
   ADA-055/057 screens.
2. `windows-engineer` / lab: cluster-node behaviour and the Security-channel ACE on member servers.
3. `solution-architect`: whether `ApplyAcl` accepts the plan encoded as typed rows (preferred) or the
   binary `DACLWrite` value; either must keep "no SDDL, no raw bytes" true on the wire.
4. `market-analyst`: how ADManager Plus and ADAudit Plus deploy their file-server components and
   what privileges they require — not researched here, so no competitor claim is made `[UNVERIFIED]`.

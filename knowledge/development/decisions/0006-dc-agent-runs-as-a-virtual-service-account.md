---
title: "ADR-0006: The DC agent runs as a virtual service account with a restricted token and a channel ACE, never LocalSystem"
date: 2026-10-28
updated: 2026-11-07
status: proposed
owner: solution-architect
kind: technical
ticket: T-0142
fitness: fitness-agent-host (built, T-0554: `make fitness-agent-host`, tools/fitness/agenthost; checks needing the agent proto or MSI print inactive until they land)
---

# ADR-0006: The DC agent runs as a virtual service account with a restricted token and a channel ACE, never LocalSystem

**Status:** proposed. Ratified by factory-director after security-architect review; `accepted` when `fitness-agent-host` runs green in CI and the lab items in "Verification" are confirmed.
**Kind:** technical. **Deciders:** solution-architect; security-architect reviews (Tier 0). **Ticket:** T-0142. Answers TM §6.1 "DC agent" and TM §12 "DC agent identity".

## Context

`cmd/agent` runs on every domain controller (M3). A DC is Tier 0, so whatever the agent runs as is a
foothold on the forest if the agent or the server that commands it is compromised. The agent needs
to read the `Security` event channel and, in M4, serve a named pipe to the password filter in LSASS.
It needs nothing else: no directory identity (ADR-0002 rule 3), no file write outside its data
directory, no service or registry changes (TM-D13).

Microsoft's WEF guidance says the collecting identity needs Event Log Readers membership to read the
Security log ([WEF Appendix D](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)). The non-obvious part: on a DC there is no local SAM. `Event Log Readers` is a domain-local builtin group stored in AD, and a virtual account's SID (`S-1-5-80-…`) is not a directory principal, so "add the virtual account to Event Log Readers" may not be possible on a DC `[UNVERIFIED — lab]`. The event log service also lets an administrator set a per-channel access SDDL ([wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil), `sl /ca`), which accepts any SID.

## Decision

1. The agent service runs as the **virtual service account** `NT SERVICE\activeDIQAgent`. It is never LocalSystem, never a domain account, never a gMSA (a gMSA is a second directory identity, ADR-0002 rule 3).
2. **Read access to the Security channel is a channel ACE** for the service SID (read-only: `0x1` `ChannelReadAccess`), written by the MSI at install and removed at uninstall. It is not an AD group membership, and no AD object is created or modified by the install. If the lab shows the ACE does not work, the install **fails closed with a clear error**; LocalSystem is not the fallback. The fallback is a new ADR decided with security-architect.
3. The service has a **restricted token**: service SID type `RESTRICTED`; `RequiredPrivileges` = `SeChangeNotifyPrivilege` only; every other privilege (notably SeBackup, SeRestore, SeTakeOwnership, SeDebug, SeImpersonate, SeLoadDriver, SeTcb) is absent. At start the agent reads its own token and **refuses to run** holding any privilege outside that list.
4. **No Windows-authenticated network use.** A virtual account authenticates on the network as the computer account (on a DC, a Tier-0 identity). The agent therefore makes exactly one kind of outbound connection, the `fleet` mTLS dial. No SMB, LDAP, RPC or Kerberos from the agent. *Amended 2026-11-05 (T-1148): this rule was enforced by an MSI firewall rule that the ADR said existed and does not. The MSI installs no firewall rule at all (`Agent.wxs`; lab X1-no-listener), and an outbound "allow" rule restricts nothing on Windows anyway. The control is in the binary: A4 (no LDAP, SMB, RPC or SSPI client package) plus the single dial site. A per-service outbound block rule is optional customer hardening, listed in the operations runbook, not a product guarantee.*
5. Writable locations: the agent data directory (`%ProgramData%\skenzeriq\agent`, DACL: service SID, SYSTEM, Administrators, nothing else) and nothing else. The binary directory is not writable by the service SID.
6. The password-filter pipe (M4, T-0145) is created by the agent with a DACL granting the filter's client (SYSTEM, since LSASS runs as SYSTEM) and the service SID only. *Added 2026-11-05 (T-1148), binding on T-0145:* the agent creates the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE` (a squatting pipe makes the agent fail to start, visibly), sets `PIPE_REJECT_REMOTE_CLIENTS`, and checks the client with `GetNamedPipeClientProcessId`, then token user = SYSTEM and image path = `lsass.exe` in `System32` (an image-path check alone is spoofable by any SYSTEM process; it is a defence in depth beside the DACL, not the boundary). Candidate passwords cross the pipe only under TM-TB12-T7. LSASS being SYSTEM is the filter's property, not the agent's.

## Alternatives considered

| Alternative | What it would buy us | Why not |
| --- | --- | --- |
| LocalSystem | Reads every log, simplest install, what ManageEngine-style agents commonly use | A compromised agent is SYSTEM on a DC: it can dump `ntds.dit` and LSASS. Tier 0 forbids holding more than the job needs |
| Virtual account in Event Log Readers (the TM preferred option) | Matches Microsoft's wording | May not be possible on a DC because the group is in AD and a service SID is not a directory principal `[UNVERIFIED — lab]`. Even if it is, it touches AD. Kept as the verification target, not the mechanism |
| gMSA in Event Log Readers | A real directory principal, works with the group | A second directory identity on every DC, a password retrievable by the DC computer accounts, and an AD change at install. Violates ADR-0002 rule 3 |
| NETWORK SERVICE in the group (Microsoft's own DC example) | Documented | Shares an identity with every other NETWORK SERVICE process on the DC |

## Consequences

Positive: the agent's blast radius on a DC is "read the Security log and write its own directory". Install touches no AD object. The refuse-on-privilege check turns a mis-installed agent into a visible failure.
Negative: the MSI must write an event-log channel ACE, which is host configuration the customer's GPO could overwrite; the agent reports `channel_unreadable` in health and the server alerts. The install is more work than LocalSystem.

## Fitness function

`fitness-agent-host` (CI, plus Windows lab for the items marked L):
- A1 the MSI manifest names `NT SERVICE\activeDIQAgent`, service SID type `restricted`, and a `RequiredPrivileges` list equal to the pinned list; any other account or `LocalSystem` string in the MSI source fails.
- A2 (L) agent started with an extra privilege in its token exits non-zero before opening any subscription.
- A3 (L) the service SID can read `Security` via the channel ACE on a DC, and cannot write the binary directory or any path outside the data directory.
- A4 the agent binary's import scan shows no LDAP, SMB, RPC or SSPI client package.

## Security review (T-1148, 2026-11-05)

**Verdict: approve**, with the two amendments above (decision 4 firewall claim; decision 6 pipe hardening). Reviewed against TM §6.1/§12 "DC agent identity", TM-D13, TM-TB12-T3, T8, T9 and the code on main (`internal/platform/agent/token.go`, `token_windows.go`, `internal/compose/agent/agent.go:59`, `cmd/agentsetup`, `packaging/windows/agent/Agent.wxs`) and the Windows lab run [T-0648](../runbooks/windows-lab-runs/T-0648-agent-20261029-rerun.log).

| Decision | Evidence | Result |
| --- | --- | --- |
| 1 virtual account, never LocalSystem | lab A2-startname; A1 fitness | holds |
| 2 channel ACE, no AD change | lab A3-ace, A3-others-kept, A3-readable (82 events on a DC), X1-ace-gone; `editSDDL` edits through typed ACL APIs, no SDDL concatenation | holds |
| 3 restricted token, pinned privileges, refuse to run | lab A1-sidtype RESTRICTED, A2-token (`SeChangeNotifyPrivilege` only); `HeldPrivileges` lists disabled privileges too; `CheckPrivileges` is called before any subscription | holds |
| 4 no Windows-authenticated network use | A4 import scan; firewall claim wrong | amended |
| 5 data directory | lab A5-datadir, D1 junction refused, D2 foreign owner refused, callback-ACE refused | holds |
| 6 pipe | M4, not built | constraints added |

Findings: (1) decision 4 firewall claim was false: amended. (2) Pipe hardening: added for T-0145. (3) Residual, accepted: a customer GPO that resets the Security channel ACL silences the agent, which reports `channel_unreadable` (lab G1; **corrected by T-0557**: a real GPO takes effect only at the next Event Log service restart (reboot), and neither the MSI ACE nor `agentsetup grant-channel` beats it; the fix is the service SID in the GPO's SDDL); a failed upgrade removes the ACE (lab U2, T-0732 owns the fix). Both fail visibly, not open. (4) Residual, accepted: the agent can write its own anchor and installed policy in the data directory; an attacker who is the agent already owns that agent (TM-TB12-T8).

## Verification owed

All three items were run on the Windows DC lab and passed (T-0648: A3, G1, A2-token). The `[UNVERIFIED — lab]` question whether a virtual account can join Event Log Readers on a DC is moot: the mechanism is the channel ACE, and nothing depends on the group route.

**T-0557 (2026-11-07, Windows Server 2025 build 26100, `dc1`)** re-ran these on a real GPO and added what T-0648 left: the channel ACE is readable as `NT SERVICE\activeDIQAgent` (329 654 events); an elevated administrator token is refused with exit 1 naming 25 privileges; a real "Configure log access" GPO applies only after an Event Log service restart, then shadows the ACE and beats `grant-channel`; deleting the GPO also needs a restart; the service SID is name-derived and identical on every host. Spec §5 figures: CPU cap is 5 % of all logical CPUs, the 256 MiB limit is per-process committed memory (not a working set), the sustained rate under the cap is 578 events/s on 4 vCPUs. Not proven: low I/O priority, live collection under load (bug T-1752: the live path collected 321 of 58 822 events), logon latency while collecting. Evidence and caveats: [domain note](../domain/dc-agent-channel-acl-gpo-and-bounds.md).

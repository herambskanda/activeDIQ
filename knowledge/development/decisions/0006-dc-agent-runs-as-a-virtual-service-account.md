---
title: "ADR-0006: The DC agent runs as a virtual service account with a restricted token and a channel ACE, never LocalSystem"
date: 2026-10-28
updated: 2026-10-28
status: proposed
owner: solution-architect
kind: technical
ticket: T-0142
fitness: fitness-agent-host (to be built, follow-up ticket)
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
4. **No Windows-authenticated network use.** A virtual account authenticates on the network as the computer account. The agent therefore makes exactly one kind of outbound connection, the `fleet` mTLS dial, and the host firewall rule the MSI installs allows that endpoint only. No SMB, LDAP, RPC or Kerberos from the agent.
5. Writable locations: the agent data directory (`%ProgramData%\skenzeriq\agent`, DACL: service SID, SYSTEM, Administrators, nothing else) and nothing else. The binary directory is not writable by the service SID.
6. The password-filter pipe (M4, T-0145) is created by the agent with a DACL granting the filter's client (SYSTEM, since LSASS runs as SYSTEM) and the service SID only, and the agent verifies the peer process image. LSASS being SYSTEM is the filter's property, not the agent's.

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

## Verification owed

Lab items to hand to T-0076's lab (new ticket): channel ACE read on a DC with the virtual account; behaviour after a GPO resets channel access; token privileges as installed.

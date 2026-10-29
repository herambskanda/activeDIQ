---
title: "Runbook: operating the DC agent (activediq-agent)"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: windows-engineer
ticket: T-0555
---

# Runbook: operating the DC agent

Design: [ADR-0006](../decisions/0006-dc-agent-runs-as-a-virtual-service-account.md), [contract](../architecture/agent-host-addc-contract.md). Rehearsed on a Windows Server DC lab under T-0648 (evidence: [windows-lab-runs/T-0648-agent-20261029.log](windows-lab-runs/T-0648-agent-20261029.log), method in [windows-lab.md](windows-lab.md) §11). Enrolled-agent fault tests remain open (see "Still owed").

## Identity and footprint

- Service `activeDIQAgent` runs as `NT SERVICE\activeDIQAgent`, restricted service SID, `SeChangeNotifyPrivilege` only. It listens on nothing; there is **no inbound firewall rule**, by design. Outbound: the one mTLS endpoint given at enrolment.
- **The MSI does not start the service** (`Start=install` was removed: an unenrolled agent exits at once and raced the installer). Run `agentsetup`/`agent enroll`, then start `activeDIQAgent`.
- Data directory (`%ProgramData%\skenzeriq\agent`): DACL service SID, SYSTEM, Administrators. **Kept on uninstall** (outbox, policy anchor); remove by hand only when decommissioning the DC.
- The `Security` channel ACE (read, `0x1`) is written by the MSI via `agentsetup grant-channel` and removed by `revoke-channel`. A failure aborts the install; it never falls back to LocalSystem.
- **Known residual (T-0732):** `RollbackGrantChannel` runs `revoke-channel`, which removes the service-SID ACE without knowing whether it existed before this install. On a repair, or a major upgrade that fails and rolls back over an installed agent, the previously granted Security read ACE is therefore removed and the still-installed agent reports `CHANNEL_UNREADABLE` until `agentsetup grant-channel` is re-run (or the MSI repair is repeated). Fail-safe direction: reads stop, nothing is over-granted. **Reproduced in the lab (T-0648):** a forced failed major upgrade removed the ACE and `agentsetup grant-channel` recovered it.
- Local ceilings (outbox bytes, batch bytes, events/s) live in `agent.json` beside the executable, writable by Administrators only. A signed policy can narrow them, never widen.

## Application-log events (source "activeDIQ Agent")

| ID | Level | Meaning | Action |
| --- | --- | --- | --- |
| 100 | Info | A signed policy was applied (sequence in the text) | none |
| 101 | Error | Start refused: token holds a privilege outside the pinned list, or the data directory DACL is unsafe | reinstall with the MSI; do not edit the token |
| 102 | Warning | The Security channel cannot be read | a GPO may have reset channel access: re-run `agentsetup grant-channel`; the server shows `channel_unreadable` |

## Verified in the lab (T-0648) and still owed

Verified on a Windows Server DC (log above): Security channel ACE `0x1` for the service SID and the agent reading Security as that identity; GPO reset, regrant and idempotence; installed token and `sc qprivs` hold `SeChangeNotifyPrivilege` only (A2); corrupt `agent.json`; repair; failed major upgrade (T-0732 residual); data-directory junction/parent refusals; revoke-failure event 4101; uninstall leaves nothing registered and no files; DC stays healthy.

Still owed: fault tests with an enrolled agent (kill the server connection, fill the disk) — T-0814; unenrolled-start behaviour — T-0813; other supported Server versions; Directory Service event placement.

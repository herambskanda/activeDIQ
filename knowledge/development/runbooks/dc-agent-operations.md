---
title: "Runbook: operating the DC agent (activediq-agent)"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: windows-engineer
ticket: T-0555
---

# Runbook: operating the DC agent

Design: [ADR-0006](../decisions/0006-dc-agent-runs-as-a-virtual-service-account.md), [contract](../architecture/agent-host-addc-contract.md). **Not yet rehearsed on a Windows host** (see "Lab owed"); do not publish to customers until it is.

## Identity and footprint

- Service `activeDIQAgent` runs as `NT SERVICE\activeDIQAgent`, restricted service SID, `SeChangeNotifyPrivilege` only. It listens on nothing; there is **no inbound firewall rule**, by design. Outbound: the one mTLS endpoint given at enrolment.
- Data directory (`%ProgramData%\skenzeriq\agent`): DACL service SID, SYSTEM, Administrators. **Kept on uninstall** (outbox, policy anchor); remove by hand only when decommissioning the DC.
- The `Security` channel ACE (read, `0x1`) is written by the MSI via `agentsetup grant-channel` and removed by `revoke-channel`. A failure aborts the install; it never falls back to LocalSystem.
- **Known residual (T-0732):** `RollbackGrantChannel` runs `revoke-channel`, which removes the service-SID ACE without knowing whether it existed before this install. On a repair, or a major upgrade that fails and rolls back over an installed agent, the previously granted Security read ACE is therefore removed and the still-installed agent reports `CHANNEL_UNREADABLE` until `agentsetup grant-channel` is re-run (or the MSI repair is repeated). Fail-safe direction: reads stop, nothing is over-granted. To be reproduced in the lab under T-0648.
- Local ceilings (outbox bytes, batch bytes, events/s) live in `agent.json` beside the executable, writable by Administrators only. A signed policy can narrow them, never widen.

## Application-log events (source "activeDIQ Agent")

| ID | Level | Meaning | Action |
| --- | --- | --- | --- |
| 100 | Info | A signed policy was applied (sequence in the text) | none |
| 101 | Error | Start refused: token holds a privilege outside the pinned list, or the data directory DACL is unsafe | reinstall with the MSI; do not edit the token |
| 103 | Warning | Installed but not enrolled: the service is running and idling, re-checking every 15 s | run `activediq-agent.exe enroll <server:port> <pin>`; the agent picks the enrolment up within 15 s, no restart needed |
| 102 | Warning | The Security channel cannot be read | a GPO may have reset channel access: re-run `agentsetup grant-channel`; the server shows `channel_unreadable` |

## Install order

The MSI starts the service on install. Install, start (it idles with event 103), then enrol; the agent notices the enrolment within 15 s. Starting before enrolling is expected, not a failure; the SCM recovery action never fires for it.

## Lab owed (needs a Windows Server DC and a client; a CEO action if it costs money)

Channel ACE read on a DC; behaviour after a GPO resets channel access; installed token privileges (A2); SCM default privileges beyond the pinned list; Directory Service event placement; `wevtapi` on every supported Server version; MSI install/upgrade/rollback/uninstall leaves nothing registered; fault tests (kill the server connection, fill the disk, corrupt `agent.json`) with the DC continuing to authenticate.

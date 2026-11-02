---
title: "Runbook: operating the DC agent (activediq-agent)"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: windows-engineer
ticket: T-0555
---

# Runbook: operating the DC agent

Design: [ADR-0006](../decisions/0006-dc-agent-runs-as-a-virtual-service-account.md), [contract](../architecture/agent-host-addc-contract.md). Rehearsed on a Windows Server DC lab under T-0648 (evidence: [windows-lab-runs/T-0648-agent-20261029.log](windows-lab-runs/T-0648-agent-20261029.log), method in [windows-lab.md](windows-lab.md) §13). Enrolled-agent fault tests remain open (see "Still owed").

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
| 110 | Warning | The tunnel to the server ended: **server unreachable** (refused, timed out, network or firewall) | check the route and firewall to the enrolment endpoint; the agent keeps retrying with backoff |
| 111 | Warning | The server's host name **does not resolve** | check DNS on the DC for the enrolment endpoint's name |
| 112 | Warning | The server's certificate **was not accepted** (not the pinned CA, wrong name, expired) | a changed server certificate or a name mismatch: re-run `agent enroll` with the current pin |
| 113 | Warning | **TLS failed** for another reason, including the server refusing the agent's certificate | check the agent's certificate has not been revoked/expired on the server; re-enrol if so |
| 114 | Warning | The server **rejected the agent's identity** | the agent was removed or revoked in the console; re-enrol |
| 115 | Warning | The server broke the tunnel protocol | version skew or a proxy in the path that rewrites TLS; collect support data |
| 116 | Warning | The tunnel ended for another transport reason | persistent: collect support data |
| 118 / 119 | Warning / Error | Any other warning / error the agent logged (a fixed message, no data) | the message names the condition (for example `installed policy could not be activated`) |

Events 110–119 carry a fixed text (the class and, for 118/119, a code-literal message) and never an address, error string, token or key. Each class writes **at most one event per 15 minutes**; the next one says "(N more since the last report)". A tunnel that comes back and later fails again therefore stays quiet until the interval has passed. Detail (addresses, error text) is on stderr only, which the SCM discards; run `agent.exe` in the foreground to see it.

## Verified in the lab (T-0648) and still owed

Verified on a Windows Server DC (log above): Security channel ACE `0x1` for the service SID and the agent reading Security as that identity; GPO reset, regrant and idempotence; installed token and `sc qprivs` hold `SeChangeNotifyPrivilege` only (A2); corrupt `agent.json`; repair; failed major upgrade (T-0732 residual); data-directory junction/parent refusals; revoke-failure event 4101; uninstall leaves nothing registered and no files; DC stays healthy.

Still owed: fault tests with an enrolled agent (kill the server connection, fill the disk) — T-0814; unenrolled-start behaviour — T-0813; other supported Server versions; Directory Service event placement.

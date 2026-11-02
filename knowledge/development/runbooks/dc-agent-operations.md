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
| 103 | Warning | Installed but not enrolled: the service is running and idling, re-checking every 5 s | run `activediq-agent.exe enroll <server:port> <pin>`; the agent picks the enrolment up within seconds (re-check every 5 s, every 1 s while the files are being written), no restart needed |
| 104 | Error | Enrolment state exists but the service refuses it. The text starts `enrolment state cannot be used (<class>)`: `unsafe-permissions` (owner or DACL names someone other than SYSTEM, Administrators and the service; a reparse point), `expired` (the component certificate is past its validity), `corrupt` (incomplete or does not verify). The service keeps running, does not connect, writes this once per class and re-checks every 5 s | `unsafe-permissions`: stop the service, delete `C:\ProgramData\skenzeriq\agent\enrol` and run `activediq-agent.exe enroll` again (state written by a build before T-1249 names the administrator who enrolled and is refused); `expired`/`corrupt`: enrol again with a new token |
| 102 | Warning | The Security channel cannot be read | a GPO may have reset channel access: re-run `agentsetup grant-channel`; the server shows `channel_unreadable` |
| 105 | Error | The CPU limit (5 % hard cap) is lifted for the few seconds of a connection set-up and could not be put back. The service retries at once (3 times) and then every 2 s until it succeeds; until then the agent is uncapped. Written once per episode | none needed if 106 follows; if it does not, restart the service (a restart re-applies the cap) and send the support bundle |
| 106 | Info | The CPU limit was restored by a retry after a 105 | none |

## Enrolment state and who may read it

`activediq-agent.exe enroll` is run by an administrator, but the service runs as `NT SERVICE\activeDIQAgent`. The enrolment directory and its files are therefore written for the service: owner `BUILTIN\Administrators`, protected DACL granting SYSTEM, Administrators and the service SID, never the administrator's own user SID (the service refuses state that names anyone else). `agentsetup repin` does the same. The service tells "no enrolment yet" (event 103) from "state exists but refused" (event 104).

## Building the MSI

```
wix build Agent.wxs -ext WixToolset.Util.wixext -arch x64 -wx -sw1149 -d Version=<x.y.z> -d AgentExe=<path>\activediq-agent.exe -d SetupExe=<path>\agentsetup.exe -o activediq-agent-<x.y.z>.msi
```

WiX 5.0.2. `-wx` turns every warning into an error, so the build fails on any warning not suppressed on purpose. The one suppression is `-sw1149`: WIX1149 is raised by the **core** `ServiceConfig` itself, the only element that can set `ServiceSid="restricted"` and `RequiredPrivilege` (`util:ServiceConfig` has neither; ADR-0006 A2 needs both; T-0648 read back on a DC that it applies them). The recovery actions (restart x3, 30 s, reset 1 day) are on `util:ServiceConfig`, the only element that has them (the core one has no failure-action attributes: WIX0004); `sc qfailure activeDIQAgent` reads them back (T-0833). The release pipeline (devops-engineer) must use the same flags; `agent-unenrolled-verify` checks both fixtures.

## Install order

The MSI starts the service on install. Install, start (it idles with event 103), then enrol; the agent notices the enrolment within a few seconds (it polls every 5 s, 1 s while an enrolment is being written). Starting before enrolling is expected, not a failure; the SCM recovery action never fires for it.

## Verified in the lab (T-0648) and still owed

Verified on a Windows Server DC (log above): Security channel ACE `0x1` for the service SID and the agent reading Security as that identity; GPO reset, regrant and idempotence; installed token and `sc qprivs` hold `SeChangeNotifyPrivilege` only (A2); corrupt `agent.json`; repair; failed major upgrade (T-0732 residual); data-directory junction/parent refusals; revoke-failure event 4101; uninstall leaves nothing registered and no files; DC stays healthy.

Still owed: fault tests with an enrolled agent (kill the server connection, fill the disk) — T-0814; unenrolled-start behaviour — T-0813; other supported Server versions; Directory Service event placement.

---
title: "DC agent on a real DC: Security-channel ACE, GPO reset, token privileges and resource bounds (lab confirmation)"
date: 2026-11-07
updated: 2026-11-07
status: review
owner: heramb
author: ad-expert
ticket: T-0557
---

# DC agent on a real DC: channel ACE, GPO reset, token, resource bounds

**What this is.** The Windows-DC confirmation of the items ADR-0006 left open and of the `[EST]` figures in
[agent-host-addc-contract.md](../architecture/agent-host-addc-contract.md) §5. It follows T-0648, which
already proved the channel ACE, the restricted token and a *simulated* GPO reset.

**Verification status: run on Windows Server, not on Samba.** One lab DC, `dc1`: Windows Server 2025 Standard
Evaluation, build 26100, 4 logical processors, 8 GiB RAM (a VM; the numbers are for that VM). Samba AD has no
Windows Security event log, no event-log service and no job objects: a Samba test of any row below would
give a false pass or no result. Run 2026-11-07 by `agent-verify --guest agent-t0557.ps1` under the dc1 lock,
`SUMMARY failures=0` in each of the two final logs (26 cases in total; the earlier "38" in the ticket note was a miscount). Evidence:

- Final run (16 `CASE` lines, all PASS, `SUMMARY failures=0`): [T-0557-agent-20261107.log](../runbooks/windows-lab-runs/T-0557-agent-20261107.log)
- Restart mode (real GPO + Event Log service restart; 10 `CASE` lines, all PASS, `SUMMARY failures=0`): [T-0557-agent-gpo-restart-20261107.log](../runbooks/windows-lab-runs/T-0557-agent-gpo-restart-20261107.log)
- First full run (15 `CASE` lines; superseded), kept because it records a wrong expectation that the run corrected (G4 expected the GPO to
  take effect on `gpupdate`; it does not): [T-0557-agent-20261107-run1-superseded.log](../runbooks/windows-lab-runs/T-0557-agent-20261107-run1-superseded.log)
- Guest script `lab/windows/guest/agent-t0557.ps1`; Go tests `internal/compose/agent/resource_windowslab_test.go`.
- After the run: `dc1-policy check` = `LDAPServerIntegrity=2`, `LdapEnforceChannelBindingTokens=2`, GPO template 2, cleartext bind refused with 8 (T-1265 tooling). dc1 left as found (no GPO, no agent, `channelAccess` back to baseline, Security `maxSize` 536870912).

## 1. Security-channel ACE for the virtual service account (ADR-0006 decision 2)

| Item | Result | Evidence |
| --- | --- | --- |
| MSI adds `(A;;CC;;;S-1-5-80-…)` to the Security channel's configured `channelAccess` | **Confirmed** | CASE I1; baseline `O:BAG:SYD:(A;;CCLCSDRCWDWO;;;SY)(A;;CCLC;;;BA)(A;;CC;;;ER)` |
| `NT SERVICE\activeDIQAgent` can read Security through the agent's event source (no AD change) | **Confirmed**: 329 654 events readable | CASE I2 |
| The ACE grants read only (`CC`, no `LC`/`WD`/`WO`) | **Confirmed** from the SDDL | log line `after-gpo-removed wevtutil.channelAccess` |
| The service SID is the same on every host | **Confirmed by derivation**: SHA-1 of the upper-cased UTF-16LE service name, five little-endian DWORDs after `S-1-5-80`, recomputed offline for `ACTIVEDIQAGENT` = `S-1-5-80-3803417868-3083394944-3978303958-4174658546-1200079750`, identical to the DC's. The tag is dropped on that basis: the SID is a pure function of the name, so it needs no second host; only one DC was actually read | CASE I1 log |
| "Virtual account in `Event Log Readers`" on a DC | **Moot, not tested.** `ER` (`Event Log Readers`) already appears in the Security channel default (`CC`), but it is a domain-local builtin group stored in AD; a service SID is not a directory principal. The ACE route needs neither | ADR-0006 |

## 2. What a customer GPO does to it (ADR-0006 residual 3)

The setting is *Computer Configuration → Administrative Templates → Windows Components → Event Log Service →
Security → Configure log access*; it writes `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\ChannelAccess`
(an SDDL string). Microsoft's page only says the setting "takes the same SDDL string"
([Set event log security locally or via Group Policy](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/set-event-log-security-locally-or-via-group-policy));
it does not say when it takes effect. Everything below is lab-observed on Server 2025 only. The lab GPO was created with `New-GPO`, `Set-GPRegistryValue` on that Policies key (the registry value the ADMX setting writes; not clicked through the Group Policy editor) and `New-GPLink` to the Domain Controllers OU.

| Step | Observed | CASE |
| --- | --- | --- |
| Real GPO (created in AD, linked to the DC OU, `ChannelAccess` without the service SID); `gpupdate` | Policies value is written; **the effective ACL does not change**: `wevtutil gl security` still reports the MSI ACE, and the service identity stayed readable for 60 s | G4 (both policy-value and no-immediate-effect cases) |
| Event Log service restarted with that GPO in force | `wevtutil gl` now reports the **policy** SDDL; the MSI ACE is shadowed; the service identity is **unreadable** | G7 (restart log) |
| `agentsetup grant-channel` while the policy is in force | exits 0, writes the *configuration*, **policy still wins**: still unreadable | G8 (restart log) |
| GPO edited to include the service SID | Policies value follows the edit; effective only on the next service restart (same mechanism) | G5 |
| GPO deleted, `gpupdate` | value cleared; effective ACL unchanged until the next restart; after the restart the MSI ACE is back (it was kept in the configuration) | G6, G9 (restart log) |

**Meaning for the agent and for reports.**
1. A GPO that resets the Security log ACL does not silence the agent at once. It silences it at the next Event Log
   service restart, which on a DC means the next reboot (a reboot restarts the service; not run separately
   `[UNVERIFIED]`). Expect "the agent went quiet after patch Tuesday", not "after the GPO changed". The agent's
   `channel_unreadable` status is the signal; correlate it with the DC's last boot, not with the GPO's `whenChanged`.
2. Re-running the installer or `grant-channel` cannot fix it. The only remedy that survives is the customer adding
   the service SID to the GPO's SDDL. Because the SID is name-derived (§1), one ACE works on every DC.
3. The reverse also holds: a GPO the customer adds *later* only bites after a restart, so a "green" agent right
   after a GPO change proves nothing.
4. Whether the agent's own `Security` log must also be re-readable after a *running* subscription is cut by the
   restart was not exercised; G7 reads with a fresh subscription.

## 3. Token privileges (ADR-0006 decision 3, A2)

An elevated Administrator launching `activediq-agent.exe` is **refused, exit 1**, with
`process token holds privileges outside the pinned list:` followed by 25 names (`SeBackupPrivilege`,
`SeDebugPrivilege`, `SeRestorePrivilege`, `SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`,
`SeImpersonatePrivilege`, `SeEnableDelegationPrivilege`, … ). CASE P1 and P2. The admin token holds 26 privileges
on this build (log line 12); the refusal names 25, all but `SeChangeNotifyPrivilege`, which is the pinned one. That the refusal
comes *before* any subscription is true by code order (`CheckPrivileges`, T-1148); the run observed only the exit
and the message, not the absence of a subscription. Service-token side (only `SeChangeNotifyPrivilege`) is T-0648 A2-token.

## 4. Resource bounds (spec §5 `[EST]` figures)

| Figure in the spec | Measured | Verdict |
| --- | --- | --- |
| CPU hard cap "5 % of the DC" | Job `CpuRate`=500 with hard cap (documented as a percentage ×100 **of the whole system** when there is no parent rate-controlled job: [JOBOBJECT_CPU_RATE_CONTROL_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information)). A spinning process measured **5.48 %** and **5.30 %** of all logical CPUs over 12 s (= 21–22 % of one core on 4 vCPUs). Over a 596 s backlog read: 4.51 % | **Confirmed as "5 % of all logical CPUs"**. The `Confine` doc comment "≤ 5 % of one core" is **wrong** (the constant's own comment, "of all cores", is right). The cap scales with the machine: ≈0.1 core on a 2-vCPU DC, ≈3 cores on a 64-vCPU DC |
| "working set cap 256 MiB" | Job flags `0x120` = `JOB_OBJECT_LIMIT_PROCESS_MEMORY` + priority class; `workingset_limit=false`. A 300 MiB commit failed ("The paging file is too small…"), 128 MiB succeeded | **Corrected**: it is a **per-process committed-memory** ceiling (256 MiB), not a working-set cap. Observed peaks: working set 18–22 MiB, private 52–55 MiB, under load and under a 344 k-event backlog read |
| below-normal priority | `priority class=0x4000` | **Confirmed** |
| low I/O priority | Not measured, because **not implemented**: `Confine()` sets only the process-memory limit, the below-normal priority class and the CPU rate; no I/O priority or `PROCESS_MODE_BACKGROUND_BEGIN` exists in any `*.go` (below-normal CPU priority does not lower I/O priority) | **Specified, not implemented (T-1756)** |
| Collection rate the cap sustains | Backlog read: 344 084 events in 595.8 s = **578 events/s**, 312 µs CPU per event, 0 throttled, 0 gaps, 0 outbox drops | **New figure.** About 160 events/s per logical CPU at the 5 % cap (extrapolated from one 4-vCPU VM `[UNVERIFIED on other hardware]`) |
| "bounds hold at 3 000 events/s" (spec C13/L1) | Not demonstrated. The logon generator on a 4-vCPU DC wrote 58 800–67 700 catalogue-id events in 60 s (≈ 1 000/s), and at 3 000/s the agent would need ≈ 0.94 CPU-s per second = 23 % of this VM, so the cap would bind | **Corrected**: 3 000/s is the policy rate cap (a ceiling), not a sustained capacity. Above ≈ 160 events/s per logical CPU the agent falls behind by design and relies on the Security log retaining the backlog |
| "DC logon latency unchanged" | 8 threads: mean 32.5 → 34.4 ms, p95 36.6 → 43.8 ms, 234 → 222 logons/s. 24 threads: mean 64 → 89 ms, p95 121 → 109 ms, 236 → 245/s (two baselines differed by 12 ms in the mean, so noise is of that order) | **Not proven either way**: during these runs the agent used 0.1 % CPU because it collected almost nothing (§5). Latency while the agent is genuinely collecting at the cap was not measured `[UNVERIFIED]` |

## 5. Open finding: the live subscription collected almost nothing under load

In the two live-load cases the agent's module reported `collected=321` (8 threads) and `collected=148` (24
threads) while the Security log held **58 822 / 58 645** catalogue-id events for the same window (4624/4634/4648/4768/4769…),
with `gaps=0`, `throttled=0` and `outbox_dropped=0`. The backlog read of the same log (same catalogue, same
module) collected 344 084 events with no gaps. So the live path is either losing events silently or delivering them
long after the window; either violates the "never silent" rule (TM-R7). The test passed because it asserts no
completeness. Not diagnosed here (implementation); bug T-1752 (also: wording chore T-1753). Consequence for this
note: the live latency/CPU numbers above prove only that an idle agent costs ≈ 0.1 % CPU and 18–20 MiB.

## 6. What to change in the documents

- Spec §5: say "5 % of all logical CPUs", "256 MiB committed-memory ceiling", drop the `[EST]` tags that are now
  measured, replace "WEF planning figure" confirmation with the 578 events/s measurement, mark low-I/O priority
  "specified, not implemented (T-1756)" and keep the latency claim `[UNVERIFIED]` (done in this ticket).
- ADR-0006 "Verification owed": record this run and the corrected residual 3 (done in this ticket).
- Customer-facing: a GPO runbook (name the service SID in *Configure log access*; the effect appears at the next
  Event Log restart). Ticket T-1754.

## Sources

- Microsoft Learn, [Set event log security locally or via Group Policy](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/set-event-log-security-locally-or-via-group-policy): setting name and SDDL; silent on timing (the restart finding is lab-only).
- Microsoft Learn, [JOBOBJECT_CPU_RATE_CONTROL_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information): `CpuRate` is a percentage ×100; with no rate-controlled parent job it is the share of the whole system.
- Lab logs linked at the top.

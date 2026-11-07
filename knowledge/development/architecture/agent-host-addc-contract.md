---
title: Agent host and addc contract (skenzeriq.agent.v1, activediq.addc.v1)
status: draft
date: 2026-10-28
updated: 2026-11-07
owner: solution-architect
author: solution-architect
ticket: T-0142
---

# Agent host and `addc` contract

Binds: [threat model](./threat-model.md) §12, TB12 rows T1–T9 and T16, TM-D13, TM-D14, TM-Q19 (policy-key half). Decisions: [ADR-0006](../decisions/0006-dc-agent-runs-as-a-virtual-service-account.md) (identity) and [ADR-0007](../decisions/0007-agent-policy-trust-and-key-rotation.md) (policy trust and rotation). Map: [blueprint](./blueprint.md) §13, EP-13, EP-14, ADR-0003 (generated module list). Tunnel: [fleet-contract](./fleet-contract.md). The `fileserver` contract is T-0143's; this file defines the **host** both modules share, and `addc`.
Source files once built: `proto/skenzeriq/agent/v1/agent.proto`, `proto/activediq/addc/v1/addc.proto`. If a proto and this file disagree, the proto wins and this file is fixed.

**Platform matrix.** `addc` and the host are **Windows only**, on domain controllers (writable and RODC), WS2019+. There is no Linux agent and no `linux-oci` variant: a DC is always Windows (blueprint §13). The server side (`fleet`, policy signer, event ingest) runs in both profiles. This asymmetry is deliberate, not an omission.

## 1. Process model

- One service, `activediq-agent.exe` (`cmd/agent`), identity per ADR-0006. The `addc` module runs **in-process**; the composition root links only the generated list of agent modules (ADR-0003). No listener: the only network activity is the `fleet` mTLS dial-out and serving the reverse tunnel on that same connection (TM-D13; fleet-contract).
- The binding contract comes from the certificate SAN component kind (`addc`), never from the method string (TM-TB12-T16). The agent serves the `addc` service and the host service, and nothing else.
- Host responsibilities (`skenzeriq.agent.v1`): module lifecycle (`Start`/`Stop` with a fixed dependency struct, `internal/agenthost/hostapi.ModuleDeps`; the Windows event log is reached only through its read-only `EventSource`, implemented by the host), the **outbox** (durable, bounded, at-least-once), policy store, health, update staging, local logging. A module cannot open its own listener, spawn a process, or write outside the data directory; the dependency struct offers no such capability.
- Update: the host stages only artefacts verified by the one TUF verifier (TM-D12); there is no "run this" and no server-signed code. DC agents never auto-update without customer approval (TM-D12 rule 6).

## 2. Server-callable surface (closed)

These are the **only** RPCs the server can invoke on an `addc` agent. The list is pinned in a golden file; changing it needs security-architect approval (CODEOWNERS).

| Service | RPC | Request (all fields typed; no free-form string that is a path, URL, command, script or argument) | Effect |
| --- | --- | --- | --- |
| `agent.v1.Host` | `GetStatus` | none | health, versions, policy seq, keyset seq, outbox depth, collection state, token check result |
| `agent.v1.Host` | `ApplyPolicy` | `SignedPolicy` | verify (ADR-0007 §2) then persist and activate |
| `agent.v1.Host` | `ApplyKeyset` | `SignedKeyset` | verify then persist |
| `agent.v1.Host` | `StageUpdate` | TUF metadata + artefact digest reference | verify under TM-D12 before anything is unpacked; activation waits for local approval state |
| `agent.v1.Host` | `AckEvents` | `through_agent_seq` | outbox may drop records through that sequence |
| `addc.v1.Addc` | `GetCollectionState` | none | per-channel bookmark, last `EventRecordID`, gaps seen |

Events and acknowledgements flow the other way: the agent calls the server's `EventIngest.Append(batch)` over the tunnel (the server registers that service; TB6 rules apply). So **no verb in either direction can execute code, write a file, delete, change a service or registry value, or update outside the signed channel**; the denied categories (TM-D13) are exec, arbitrary file write, delete, service/registry change, and update.

## 3. Policy schema (data within bounds)

`AddcPolicy` has exactly these fields. The bounds are constants compiled into the agent; a policy cannot change them, and values outside them reject the whole document.

| Field | Type | Bound |
| --- | --- | --- |
| `password.min_length` | uint | 1 to 256 (the agent's floor is 1 so a legitimate customer rule is expressible; a server cannot raise it above 256) |
| `password.max_length` | uint | ≥ `min_length`, ≤ 256 |
| `password.classes_required` | enum set | subset of `{LOWER, UPPER, DIGIT, SYMBOL}`, `min_classes` 0 to 4 |
| `password.banned_terms` | repeated string | ≤ 20 000 entries, each ≤ 64 UTF-16 units, total ≤ 1 MiB, Unicode-normalised on load; matched as literal substrings; **no regular expressions** (ReDoS next to LSASS) |
| `password.reject_sam_in_password`, `reject_display_name_parts` | bool | — |
| `events.collection_enabled` | bool | stopping collection is allowed by design (TM-R7) and always reported |
| `events.channels` | enum set | `{SECURITY, DIRECTORY_SERVICE}` only |
| `events.event_ids` | repeated uint | ≤ 256 entries; each must be in the agent's **compiled-in catalogue** of supported IDs; unknown IDs reject |
| `events.max_events_per_second` | uint | 1 to the **local ceiling** |
| `events.batch_max_bytes`, `outbox_max_bytes` | uint | clamped to the local ceiling |

**Local ceilings** (outbox disk, CPU, memory, events/s) are set at install in a config file ACL'd to administrators. The policy can narrow them and never widen them, the same rule as the `fileserver` root list (TM-TB12-T11). The only strings in a policy are `banned_terms`, which are matched, never interpreted. No path, URL, command, script, regex, or `Any` appears anywhere, and the lint (R2) enforces that.

## 4. Event records (TB12-T8)

Each record the agent appends carries: `agent_seq` (agent-assigned, gapless), `channel`, `event_record_id` (the log's own), the rendered fields, and `observed_at`. The agent's identity (tenant, component, agent ID) is **stamped by the server from the client certificate**, never taken from the payload. The `dc_guid` the agent reports is cross-checked server-side against replication metadata (BP §9); a mismatch raises an alert. The agent detects discontinuities in `event_record_id` (log wrap, FEAS notes there is no native gap signal) and emits an explicit `gap` record.

## 5. Resource bounds (TB12-T9)

The service runs in a Windows job object: CPU hard-cap of 5 % of **all logical CPUs** of the DC (configurable down; confirmed on a lab DC at 5.3-5.5 % over 12 s and 4.5 % over a 10-minute backlog read, [T-0557](../domain/dc-agent-channel-acl-gpo-and-bounds.md)), a **committed-memory** ceiling of 256 MiB per process (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`; it is not a working-set cap, and measured peaks were 18-22 MiB working set and 52-55 MiB private), below-normal CPU priority (confirmed) and low I/O priority `[UNVERIFIED]`. The CPU cap is lifted only for connection set-up (dial, TLS handshake, stream open), and the lift is hard-limited to 5 s per window: a timer puts the cap back even if the connection attempt is still stalled, the rest of that attempt runs capped, and a stalled or tarpitted peer cannot hold the cap off. Each set-up also has its own 15 s deadline (`tunnelclient.Config.SetupTimeout`), not gRPC's default. Windows are reference-counted; a restore that fails is retried at once and then every 2 s, reported as event 105, and **fails closed**: if the cap is not back within 30 s the process exits non-zero (event 105 with `exiting`), the SCM recovery action restarts it and `Confine` applies the cap again (`internal/platform/agent/cpucap.go`, read back from a real job in `confine_windows_test.go`): under the 5% hard cap that burst measured 25-34 s on a lab DC against 1.3 s uncapped (T-1249). Memory ceiling and priority stay in force during the burst. The outbox is a bounded disk queue; when full it drops **oldest bulk records first and writes a `dropped` gap record**, never blocks the subscription. The subscription uses a persisted bookmark and the policy throttle. `MaxEventsPerSecond` (policy default and local ceiling, about 3 000 events/s following the [WEF guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)) is a throttle ceiling, **not a sustained capacity**. Measured on a 4-vCPU Windows Server 2025 lab DC (T-0557): under the 5 % cap the agent sustains **578 events/s** (312 µs CPU per event, 0 gaps, 0 outbox drops), about 160 events/s per logical CPU `[UNVERIFIED on other hardware]`. A DC that logs more than that falls behind by design; the backlog stays in the Security log, so log retention must cover the lag, and a wrap is reported as a `gap`. Live collection under logon load and DC logon latency while collecting at the cap are **not yet proven** `[UNVERIFIED]`: the live-load run collected far fewer events than the log held (bug T-1752).

## 6. TM §12 constraint → contract rule → test

| # | Binding constraint (source) | Contract rule | Test (all feed TM-F-AGENTCMD, T-0144, unless noted) |
| --- | --- | --- | --- |
| C1 | No code execution (TM-D13, TB12-T3) | §2 closed list; R1 golden-file allowlist | R1: generated service descriptors equal the golden list; any added/renamed RPC fails |
| C2 | No file write outside the data directory (TM-D13) | Host dependency struct offers no path capability; ADR-0006 §5 DACLs | R3 import/capability scan of `internal/agentmodules/addc`; lab A3 write-denied outside data dir |
| C3 | No service or registry configuration change | No such RPC; token has no right | R1; R3 scan for `golang.org/x/sys/windows/registry` and `svc/mgr`; lab A3 |
| C4 | No update outside the release-signed channel (TM-D12) | `StageUpdate` verifies TUF first | T-0139 TM-F-UPDATE cases against the agent; artefact signed only by the server key refused |
| C5 | Outbound-only mTLS, no listener (TM-D13, TB12-T1/T2) | §1; agent pins the installation CA | R4 the agent binary opens no listening socket (lab netstat + import scan); TM-F-FLEET cross-kind method cases (T16) |
| C6 | Tenant from the SAN, commands only from its server (TM-D13) | Policy header tenant checked against SAN (ADR-0007 P1) | P1 |
| C7 | `addc` is event collection and password-policy enforcement only | §3 schema is the whole policy; §2 is the whole surface | R1, R2 |
| C8 | Policy is typed data in bounds, never code, paths, commands (TM-D14) | §3; R2 lint forbids `Any`, `map<string,string>`, `bytes` and unconstrained strings in policy messages | R2; fuzz: out-of-bounds policies rejected (F1); in-bounds hostile policy changes only password-rule outcomes (F2, corpus of malicious in-bounds policies run through the rule engine, asserting no side effect beyond verdicts) |
| C9 | Worst case of a malicious policy is TM-R7 | `collection_enabled=false` allowed, reported in `GetStatus` and as a server alert; local log entry on every policy (ADR-0007 §8) | F3: applying a policy writes the local entry and an audit event |
| C10 | Policy key sealed in the management plane, rotation (TM-A10, §9.1) | ADR-0007 | P1–P8 |
| C11 | DC agent identity: virtual account preferred (§12) | ADR-0006 | A1–A4 |
| C12 | Per-DC agent identity in every record (TB12-T8) | §4 server-stamped identity | S1: ingest ignores any identity field in the payload; mismatching `dc_guid` raises an alert |
| C13 | CPU, memory, queue bounds (TB12-T9) | §5 | L1 lab load test: bounds hold at 3 000 events/s, DC logon latency unchanged |
| C14 | Pipe ACL'd to the service SID, peer checked (TB12-T5, M4) | ADR-0006 §6 | T-0145 spike test (not this ticket) |
| C15 | Candidate-password IPC content (TB12-T7, TM-Q19 first half) | **Not decided here.** Constraint for T-0145: the pipe carries no more than the candidate and verdict; never logged; zeroed at both ends; no field of the `addc` surface or event record may carry a password or hash | R5 lint: no field named or typed as password/credential in `addc.v1`; remainder T-0145 |
| C16 | Fail-open/closed of the filter (TB12-T6) | **Out of scope**: CEO decision TM-Q20 before M4. The host contract has no setting for it, so a policy cannot choose it | R2 (no such field) |

R-tests run in `fitness-agent-host` (CI, `tools/fitness/agenthost`, T-0554: R1/R2/R5 call the AG rules of `fitness-proto`, R3/R4 scan agent-owned Go source, F1 is `internal/platform/agentpolicy/f1_test.go` and its fuzz target) and the proto lint; L/lab tests run in the Windows lab. `fitness-agent-host` is the ADR-0006/0007 fitness function and is the CI half of TM-F-AGENTCMD for `addc`.

## 7. Open items

- The server side is named: module `agentfleet` ([page](modules/agentfleet.md), T-0556). The signer, keyset rotation job and event ingest are built; the `activediq.addc.v1` RPC handlers wait for the proto (T-0600), the composition for the tenant DEK source (T-0598), the operator Actions for T-0599 and the dc_guid cross-check data for T-0601.
- The lab confirmations in ADR-0006 "Verification owed" gate `accepted`, not `ratified`; all items are now recorded ([T-0557 note](../domain/dc-agent-channel-acl-gpo-and-bounds.md)).
- Password-filter IPC content (C15) belongs to T-0145; this file fixes only what the agent surface must never carry.
- Resource figures in §5: CPU, memory and priority confirmed (T-0557); low I/O priority, live-load collection and logon latency under collection remain `[UNVERIFIED]` (bug T-1752).

## 8. Implementation status (T-0555)

Built on Linux, compile-checked for Windows (`GOOS=windows go vet`), **not run on Windows**.

| Piece | Where | State |
| --- | --- | --- |
| Protos (`SubmitEvents` replaces `Append`; `EventIngest` in the AG1 golden list) | `proto/skenzeriq/agent/v1`, `proto/activediq/addc/v1` | built; `fitness-proto` green |
| Host: verifier-before-parse, transactional apply, durable bounded outbox, sender | `internal/platform/agent` | built; unit and fault tests pass (-race) |
| addc module: rule engine, catalogue, collector with GAP/throttle/bookmark, wevtapi source | `internal/agentmodules/addc` | built; Windows source compile-checked only |
| Role package, local ceilings file, enrol, tunnel dial | `internal/compose/agent`, `cmd/agent` | built; Windows enrol/load fails closed until T-0291's ACL support is on main |
| Token privilege refusal, job-object caps, Application event log (IDs 100 applied, 101 start refused, 102 channel unreadable) | `internal/platform/agent/*_windows.go` | compile-checked only (A2 NOT RUN) |
| MSI source and `agentsetup` custom actions | `packaging/windows/agent/Agent.wxs`, `cmd/agentsetup` | not built (no WiX in the lab) |
| `StageUpdate` | host | **fails closed** (`FailedPrecondition`): no TUF verifier exists yet |
| Fitness | `tools/fitness/agenthost` (`fitness-agent-host`) | A1, A4, R3 in CI; A2, A3 print NOT RUN |

The agent sends no "policy applied" audit record: the server's ingest rejects unknown record kinds. The local log and Windows event 100 carry the trace until a kind is added (follow-up).

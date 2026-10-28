---
title: Agent host and addc contract (skenzeriq.agent.v1, activediq.addc.v1)
status: draft
date: 2026-10-28
updated: 2026-10-28
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
- Host responsibilities (`skenzeriq.agent.v1`): module lifecycle (`Start`/`Stop` with a fixed dependency struct), the **outbox** (durable, bounded, at-least-once), policy store, health, update staging, local logging. A module cannot open its own listener, spawn a process, or write outside the data directory; the dependency struct offers no such capability.
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

The service runs in a Windows job object: CPU hard-cap `[EST]` 5% of the DC (configurable down), working set cap `[EST]` 256 MiB, below-normal CPU and low I/O priority. The outbox is a bounded disk queue; when full it drops **oldest bulk records first and writes a `dropped` gap record**, never blocks the subscription. The subscription uses a persisted bookmark and the policy throttle. The `[EST]` numbers are confirmed in the lab (follow-up) at the WEF planning figure of about 3 000 events/s ([WEF guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)).

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

R-tests run in `fitness-agent-host` (CI) and the proto lint; L/lab tests run in the Windows lab. `fitness-agent-host` is the ADR-0006/0007 fitness function and is the CI half of TM-F-AGENTCMD for `addc`.

## 7. Open items

- The server side is named: module `agentfleet` ([page](modules/agentfleet.md), T-0556). The signer, keyset rotation job and event ingest are built; the `activediq.addc.v1` RPC handlers wait for the proto (T-0600), the composition for the tenant DEK source (T-0598), the operator Actions for T-0599 and the dc_guid cross-check data for T-0601.
- The lab confirmations in ADR-0006 "Verification owed" gate `accepted`, not `ratified`.
- Password-filter IPC content (C15) belongs to T-0145; this file fixes only what the agent surface must never carry.
- `[UNVERIFIED]` the `[EST]` resource figures in §5.

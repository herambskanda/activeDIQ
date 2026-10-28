---
title: "Module: agentfleet"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: heramb
author: backend-engineer
ticket: T-0556
tier: server
---

# Module `agentfleet`

**Purpose.** The server's side of the host agents, starting with `addc`: it signs the policy an agent
enforces, publishes the keyset chain that lets the signing key rotate without touching the fleet, and
stores the events an agent appends, stamping who sent them from the client certificate.
**Owner:** backend-engineer. **Epic:** agent host (ADR-0006, ADR-0007).
**Spec:** [agent-host-addc-contract](../agent-host-addc-contract.md); decisions
[ADR-0006](../../decisions/0006-agent-host-and-process-model.md) and
[ADR-0007](../../decisions/0007-agent-policy-trust-and-key-rotation.md).
**Parity:** none (ADManager Plus has no host agent; the audit feed is ADAudit Plus's, ENH signature enhancement).
**Capabilities required (`Requires()`):** none.
**Platform matrix:** same on windows, linux-oci and saas. The agent it serves runs on Windows only.

## Owned tables

The module package owns no table (ADR-0003 F1): its consumers run on the worker and on the fleet
listener, outside an Operation, so the tables belong to the platform packages the module names.

| Table | Entity (DM-nn) | Migration | Partitioned | Retention |
| --- | --- | --- | --- | --- |
| `agent_policy_key` | DM-86, owner `platform/agentpolicy/signer` | `0048_agentfleet_policy_and_events.sql` | no | rows kept; a dropped key's sealed material is erased |
| `agent_policy_keyset` | DM-87, same owner, append-only | same | no | whole chain kept (an agent offline for months replays it) |
| `agent_policy_head` | DM-88, same owner | same | no | one row per tenant and agent kind |
| `agent_event` | DM-89, owner `platform/agentingest`, append-only | same | not yet | not decided; `[OPEN]` with the audit retention work |

## Contributions (what `Register` registers)

| Kind (Registrar method) | ID | Notes |
| --- | --- | --- |
| — | — | Nothing yet. Policy edit and emergency key rotation are Operations that need new permissions in the role catalogue and its database guard: T-0599. |

## Platform packages it is made of

| Package | Does | Rule it keeps |
| --- | --- | --- |
| `internal/platform/agentpolicy` | Canonical wire format (`activediq.agentpolicy.v1\0` and `activediq.agentkeyset.v1\0` domains), the typed `AddcPolicy` and its bounds (contract §3), and the `Verifier` an agent runs (the reference for P1-P7) | Typed data inside bounds, never code; strict decoder (no trailing bytes) |
| `internal/platform/agentpolicy/signer` | Generates the per-tenant Ed25519 key, seals it with `keys.Seal`, signs policy and keysets, rotates, drops expired keys, reads the chain back | **P8**: the only code that opens the key; the accessor is unexported and `TestP8…` scans the tree for any other SQL naming the key table. One advisory lock per tenant serialises signers |
| `internal/platform/agentpolicy/rotation` | Job `agentfleet.keyset_maintenance`, daily per tenant: drop keys whose 30-day overlap ended, rotate a key older than 180 days; `EnsureAndSchedule` creates the first key and starts the cadence | Idempotent, successor queued first, no retry of an integrity failure |
| `internal/platform/agentingest` | Stores `AppendEvents` batches | **S1**: tenant, component and kind come from `fleet.IdentityFrom`; `Batch` has no field for them. Redelivery is idempotent on `agent_seq` **only for identical content** (per-row `content_sha256`); a different record under a stored seq is `ErrSeqDivergence` + alert `agentfleet.event.seq_divergence`, never a duplicate. NUL / invalid UTF-8 in fields are repaired to U+FFFD and listed under `_sanitized` so one hostile string cannot stall collection; the batch audit ID is the accepted seq range |

## Writes to other owners

| Owner | API called | Why |
| --- | --- | --- |
| `platform/keys` | `Seal`, `Open`, a `KeySource` for the tenant DEK | The policy key is sealed under the tenant DEK (TM-D7) |
| `platform/audit` | `Sink.Append` in the same transaction | `agentfleet.keyset.published`, `agentfleet.policy.signed`, `agentfleet.events.accepted`; details carry sequences and key IDs, never key material |
| `platform/jobs` | `Registry.Register` / `Enqueue` | The maintenance job |
| `platform/fleet`, `fleetsql` | `IdentityFrom`, `Alert` | Identity and the `agentfleet.event.dc_guid_mismatch` alert |

## Depends on

`platform` packages only; no other module. Nothing imports the module except the generated
`modules.gen.go`.

## Fitness and tests

P1-P7 as unit tests on the `Verifier` (`agentpolicy/verifier_test.go`) and end to end through the
signer (`signer/signer_test.go`, Postgres 16 and 18); P8 `signer/p8_test.go`; S1
`agentingest/ingest_test.go`; rotation and chain-following `rotation/rotation_test.go`.

## Not built (tickets)

Composition in `compose/server` waits for the production tenant DEK source (T-0598; the fleet CA has
the same gap). The `activediq.addc.v1` handlers wait for the proto (T-0600). Operator Actions: T-0599.
The dc_guid cross-check has an optional port, `agentingest.DCClaims`, and no implementation (T-0601).

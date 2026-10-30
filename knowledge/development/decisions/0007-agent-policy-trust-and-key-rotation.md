---
title: "ADR-0007: Agent policy is a signed, sequenced, bounded document; the policy key rotates through a keyset chain anchored at first contact"
date: 2026-10-28
updated: 2026-10-28
status: proposed
owner: solution-architect
kind: technical
ticket: T-0142
fitness: fitness-agent-host (built, T-0554: `make fitness-agent-host`, tools/fitness/agenthost; checks needing the agent proto or MSI print inactive until they land)
---

# ADR-0007: Agent policy is a signed, sequenced, bounded document; the policy key rotates through a keyset chain anchored at first contact

**Status:** proposed. Ratified by factory-director after security-architect review; `accepted` when `fitness-agent-host` P1–P8 run green in CI. **Kind:** technical. **Ticket:** T-0142. Answers TM-Q19 (policy-key rotation half) and fills the "`[OPEN → T-0142]`" rotation cell in TM §9.1.

## Context

TM-D14 says the policy signing key lives in the management plane, so a compromised server can sign any policy, and the control is that policy is *data within bounds the agent enforces* (residual TM-R7). That fixes what the signature is for. It does **not** protect against a compromised server. It gives: tenant binding (a policy for tenant A is refused by tenant B's agent), replay and rollback protection, integrity across the outbox, caches and server nodes, and a single identifiable key that is sealed under the tenant DEK ([keys-custody-design](../architecture/keys-custody-design.md)). Rotation therefore protects against *leakage* of the key (a backup, a DB dump, a stolen DEK), not against server compromise, and the design must not pretend otherwise. It must also work for an agent that was offline for weeks.

## Decision

1. **Key.** One Ed25519 policy key per tenant, generated and sealed by `platform/keys` under the tenant DEK. The private key is used only by the policy signer in the `agentfleet` server module; no other code path can read it. Policy documents are signed over canonical bytes with the domain-separation prefix `activediq.agentpolicy.v1\0`.
2. **Document header** (signed): `tenant_id`, `agent_kind` (`addc`/`fileserver`), `policy_seq` (strictly increasing per tenant+kind), `issued_at`, `not_after` (≤ 30 days after issue), `key_id`, and the policy body hash. The agent refuses: wrong tenant (compared with its certificate SAN), wrong kind, `policy_seq` ≤ the highest seen (persisted), a document past `not_after`, a `key_id` not in its keyset, and any body outside schema bounds (the bounds are in the agent, not the document).
3. **Expiry gates acceptance, not enforcement.** An installed policy stays in force until replaced, however long the agent is offline. This deliberately avoids creating a second fail-open/fail-closed decision (TM-Q20 stays the CEO's, for the filter only).
4. **Keyset chain.** The agent holds a keyset `{key_id, public_key, state}`. A new key is introduced by a **keyset document signed by a key already in the keyset**, carrying `keyset_seq` (increasing). Roll-over: add the new key (`active`), mark the old `retiring` for an overlap equal to the longest `not_after` already issued (30 days), then drop it. Policies signed by a `retiring` key are accepted until the keyset drops it.
5. **Anchor.** The first keyset the agent accepts is the one delivered on its first authenticated call after enrolment (trust on first use inside the channel that enrolment already authenticated, TM-D24). It is persisted in the data directory. Re-enrolment (new certificate) resets the anchor. There is no other way to replace the anchor.
6. **Schedule and triggers.** Scheduled rotation every 180 days. Immediate rotation on: suspected key exposure, restore of a database backup to a new host, DEK rotation (TM-D15) that re-seals the key (re-seal alone does not change the key, so this is a no-op for agents; only a *new* key is a rotation).
7. **Emergency (key believed stolen).** A stolen key can sign a keyset, so the chain cannot recover on its own. Recovery is the anchor reset: revoke the agents' enrolment, re-enrol each DC (an admin step with step-up, TM-D16), which re-anchors on the new key. The runbook and a bulk re-enrolment flow are follow-ups. This cost is accepted: the exposure bounded by TM-D14 is password-rule changes and event collection stopping.
8. **Evidence outside the server.** On every applied policy or keyset the agent writes a local Windows Application-log entry (policy seq, key id, body hash) and reports the same to the server as an audit event, so a hostile policy is visible on the DC itself.

## Alternatives considered

| Alternative | What it buys | Why not |
| --- | --- | --- |
| Unsigned policy over mTLS only | Simplest | No tenant binding across hops, no replay protection, no durable object for the local audit entry |
| Policy signed by an offline customer-held key | Defeats a compromised server | Operationally heavy (a human signs every rule change), breaks scheduled changes; a CEO-level product decision, not taken. Revisit if TM-R7 is re-rated |
| Release-signing root signs policy | Strong root | Policy is tenant data; skenzeriq must not sign customer data and the root is offline (TM-D12 rule 7: the server never signs code, but this is not code) |
| Fixed pinned key, no rotation | No keyset code | A leaked key stays valid forever, and DEK loss would force re-enrolment of every agent |
| Rotate by replacing the key through the server with no chain | Easy | Any server node could swap the key silently; the chain makes each step verifiable by the previous key |

## Consequences

Positive: rollback, replay and cross-tenant policy are impossible; key leakage is recoverable; a hostile policy leaves a local trace. Negative: a stolen key needs a re-enrolment sweep; the signer and keyset code is a new server module and an agent verifier to build and fuzz.

## Fitness function

`fitness-agent-host` P1–P8 (CI): P1 wrong tenant refused; P2 `policy_seq` replay and rollback refused across agent restart; P3 expired document refused but installed policy still enforced; P4 unknown `key_id` refused; P5 keyset signed by an unknown key refused; P6 old key accepted during overlap and refused after drop; P7 anchor not replaceable except by re-enrolment; P8 the signer package is the only importer of the policy private key accessor (import-graph rule).

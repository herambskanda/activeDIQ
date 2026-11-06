---
title: "ADR-0007: Agent policy is a signed, sequenced, bounded document; the policy key rotates through a keyset chain anchored at first contact"
date: 2026-10-28
updated: 2026-11-05
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
4. **Keyset chain.** The agent holds a keyset `{key_id, public_key, state}`. A new key is introduced by a **keyset document signed by a key already in the keyset**, carrying `keyset_seq` (increasing). Roll-over: add the new key (`active`), mark the old `retiring` for an overlap equal to the longest `not_after` already issued (30 days), then drop it. Policies signed by a `retiring` key are accepted until the keyset drops it. *Amended 2026-11-05 (T-1148): a `retiring` key is a full member of the keyset, so it can also sign a **keyset** (`ApplyKeyset` checks only membership), not just policies. During an overlap a stolen retiring key can therefore plant a key of the attacker's choice. The overlap bounds nothing about a stolen key; this is why decision 6 splits rotation into two classes.*
5. **Anchor.** The first keyset the agent accepts is the one delivered on its first authenticated call after enrolment (trust on first use inside the channel that enrolment already authenticated, TM-D24). It is persisted in the data directory. Re-enrolment (new certificate) resets the anchor. There is no other way to replace the anchor.
6. **Schedule and triggers, two classes.**
   - **Routine** (every 180 days; `early_scheduled`): the old key goes `retiring` for the 30-day overlap (decision 4).
   - **Compromise class** (`suspected_exposure`; `backup_restored_to_new_host`, because the old host's copy of the key is outside our control): **no overlap**. The new keyset (`keyset_seq` N+1) is signed once by the current active key, since agents hold no other, and lists **only the fresh key**. Every suspect key is dropped in the same publication and its sealed material erased. In the same transaction the server re-signs the current policy with the fresh key at the next `policy_seq`, so no agent depends on a policy signed by a dropped key. The cost to an agent that is offline is nil beyond what it already does: it keeps enforcing its installed policy (decision 3), and on return it replays the chain (`signer.Chain(since)`), applies N+1 (signed by a key it holds) and then the re-signed policy. A policy signed by a dropped key still in transit is refused, which is intended. The compromise class is allowed while a routine overlap is open (the Action's "wait for the overlap" refusal applies to routine rotation only) and drops that overlap's retiring key too.
   - DEK re-seal alone changes no key and is a no-op for agents (TM-D15); only a *new* key is a rotation.
   - **What this does not do.** An attacker who already used the key to publish a keyset or policy keeps what agents applied; compromise-class rotation closes the window, it does not undo the past. Detection is decision 8 (the Application-log entry on each DC) plus the server comparing each agent's reported `KeysetSeq` and key set (GetStatus) with its own chain; a mismatch is alerted and recovered by decision 7.
7. **Emergency (key believed stolen).** A stolen key can sign a keyset, so the chain cannot recover on its own. Recovery is the anchor reset: revoke the agents' enrolment, re-enrol each DC (an admin step with step-up, TM-D16), which re-anchors on the new key. The runbook and a bulk re-enrolment flow are follow-ups. This cost is accepted: the exposure bounded by TM-D14 is password-rule changes and event collection stopping.
8. **Evidence outside the server.** On every applied policy or keyset the agent writes a local Windows Application-log entry (policy seq, key id, body hash) and reports the same to the server as an audit event, so a hostile policy is visible on the DC itself.

9. **Sequence step bound** *(added 2026-11-05, T-1148)*. A key holder can sign `policy_seq` or `keyset_seq` = 2^64−1, after which the agent refuses every legitimate document as a replay for ever; the only cure is re-enrolment, a denial of policy updates for the fleet. The agent therefore refuses a document whose sequence exceeds the highest seen by more than `MaxSeqStep` (value set in the build ticket; a legitimate server advances by 1). A backup restore that rewinds the server's counters is handled by the server resuming above the agents' reported sequences, never by loosening the bound.
10. **Approver sees the trust horizon** *(added 2026-11-05, T-1148)*. The plan diff of `agentfleet.keyset.rotate` states when each existing key stops being trusted ("retiring, trusted until <time>" for routine; "removed immediately" for compromise class), how many enrolled agents report an older keyset than the current one (they converge on reconnect), and, for the compromise class, that misuse before the rotation is not undone.

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
**Owed (T-1148 findings; tickets below):** P9 a compromise-class rotation publishes a keyset with exactly one key and the current policy re-signed at seq+1, and an agent holding the previous keyset applies both; P10 after a compromise-class rotation the dropped key is refused for policies and keysets alike, including when a routine overlap was open; P11 a `policy_seq` or `keyset_seq` more than `MaxSeqStep` above the highest seen is refused and later legitimate documents still apply; P12 the rotate Action's plan diff carries the trust-horizon lines of decision 10 (golden test).

## Security review (T-1148, 2026-11-05)

**Verdict: approve with the amendments above.** It stays `proposed` until the director ratifies; it becomes `accepted` when P1–P12 run in CI (P9–P12 are not built). Reviewed against TM §9.1 and §9.2 (policy key rows), TM-A10, TM-D14, TM-TB12-T4, TM-R7, TM-Q19 and the code on main (`internal/platform/agentpolicy/{verifier,document}.go`, `signer/signer.go` Rotate and DropExpired, `rotation/rotation.go`) and the T-0599 Action (`factory/T-0599`, `actions.go` KeyRotate).

1. **High — exposure rotation was routine rotation.** `signer.Rotate` keeps the old key `retiring` for `OverlapWindow` (30 days) whatever the reason, and `Verifier.ApplyKeyset` accepts a keyset signed by any held key, retiring included. A suspect key could keep signing policies and could plant a key of its own for the whole overlap. Fixed in decisions 4 and 6; ticket filed.
2. **Medium — sequence denial of service.** Neither verifier path bounds sequence jumps (`ErrReplay` and `ErrKeysetReplay` compare only with the highest seen). Decision 9; ticket filed.
3. **Medium — the approver was not told the trust horizon.** The Action's plan diff shows only `active → retiring`. Decision 10; ticket filed with finding 1.
4. **Low, accepted — `Reenroll()` resets `HighestPolicySeq` to 0.** After a plain re-enrolment a captured policy still inside its 30-day `not_after` and signed by a still-trusted key could be replayed, but only by whoever can deliver it over the pinned mTLS channel: the compromised-server case already accepted as TM-R7. After a compromise-class rotation old policies fail the key check.
5. **Confirmed.** The anchor is trust on first use inside the enrolled channel (TM-D24 rule D pins the CA before the token is sent) and is replaceable only through `Reenroll`; `ApplyPolicy` checks tenant, kind, key, signature, sequence, lifetime and expiry, and refuses a foreign tenant before parsing the body; the private key is opened only in `signer` and cleared after use; expiry gates acceptance only, so an offline agent keeps enforcing.
6. **Honesty.** Rotation protects against leakage, not server compromise. A key thief who can also deliver documents is a server compromise; decision 7 stays the recovery.

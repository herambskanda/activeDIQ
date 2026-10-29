---
title: "platform/operation: persisted pipeline, fenced claims, holds, approvals"
date: 2026-10-24
updated: 2026-10-24
status: draft
owner: backend-engineer
ticket: T-0174
---

# platform/operation persistence (ADR-0005 rules 3, 6, 8, 9)

Code: `internal/platform/operation/`; migration `migrations/0013_operation_operations.sql`.

- **Tables** (all tenant-keyed, FORCE RLS): `operations`, `operation_items`, `operation_steps`,
  `operation_secrets` (runtime role has no UPDATE). The item is the system of record; the job is a driver.
- **State writes** only in `persist.go`, each an edge checked by `Transition` and a compare-and-set.
- **Step life** (`apply.go`): claim (tx1, SKIP LOCKED, attempt+1, DB-clock lease, per-DC slots under an
  advisory lock) -> write through the Action with no tx open -> record (tx2, fenced on
  `state='applying' AND attempt=n`; audit event, secret deletion and settle in the same tx).
- **Reconcile / verify / sweep** (`reconcile.go`): lapsed claims resolve by observing the target
  (after -> applied+recovered, before -> re-apply or not_run, other -> `stale_state`; credential steps are
  never re-applied). Sweeper redrives lost jobs, settles finished operations, drops expired secrets.
- **Job kinds** (`jobs.go`, ManagedTx): `operation.apply|verify|reconcile|sweep`; chunks of 100, unique
  key `(operation, revision, phase, chunk)`. Next phase is enqueued by `settle`.
- **Holds and approvals** (`holds.go`, `approve.go`): kernel holds first (undo-needed-approval, step-up,
  blast radius, irreversible); approval binds `plan_hash`; separation of duties incl. sock-puppet check
  (fail closed). A gate error leaves the operation `planned` and alerts.
- **Secrets** (`secrets.go`): sealed with `keys.Seal`, AAD includes the step key, TTL <= 72h, deleted in
  the recording tx and at every terminal state; expired -> `secret_expired`.
- `audit.Detail` is an alias of `chain.Detail` so `operation` need not import `audit/chain` (O9).

Pinner (T-0320): `compose/server.dcPinner` implements `operation.Pinner` over `client.DCDirectory`
(connector `Describe` with refresh): host and DSA GUID come from one DC entry, GUID validated by the
`attr/guid` codec; a kept `previous` host is re-read (rebuilt DC => new GUID); failures never yield a
partial pin. Built in `server.go` and passed to `buildOperation`.

Deferred: undo, bulk chunked planning, `tier0_after_write` handling, a real Observer (per-Action; the
first Directory Action supplies it, see backlog ticket).

## Approval scope (security review fixes)

- `Approve` and `Reject` require `operation.approve` over every item target, blocked and skipped items included; Reject needs no step-up.
- A re-plan keeps an approval only if the plan hash and the set of items blocked at plan are both unchanged.
- An operation held by a workflow Request (`request_ref`) is decided only through `ApproveRequest` / `RejectRequest` with that reference; direct `Approve`/`Reject` return `ErrApprovalByRequest`.
- Transient secrets: unsealed plaintext is cleared after copy and the step's secret is destroyed when the step ends.

## Audit event kinds (for SIEM rules)

Constants in `persist.go`. Every event carries the requester chain (real human behind a delegated account),
`plan_hash` where one exists, and the key `(operation, item)`. Outcomes are `success`, `failure` or `denied`.
Per-step events (a step applied, failed, recovered) are separate and recorded by `apply.go`/`reconcile.go`
with the step key; they are not `operation.*` kinds.

| Kind | Outcome / reason | Emitted when |
| --- | --- | --- |
| `operation.started` | `success` / none | The first step of a queued operation is claimed (queued -> running). Once per operation. |
| `operation.held` | `success` / the hold reason: `blast_radius`, `irreversible`, `step_up`, `undo_needed_approval`, `gate` | Submit finds a kernel hold or the gate routes to a request; the operation waits in `awaiting_approval`. Detail `hold_reason`. Not a refusal: nobody was denied. |
| `operation.approved` | `success` / none | `Approve` (or an approving workflow Request) moves `awaiting_approval` -> `approved`. Actor is the approver. Detail `hold_reason`, `initiator`. A re-plan that keeps a prior approval emits nothing. |
| `operation.rejected` | `denied` / `gate_denied` or `rejected_by_approver` | `gate_denied`: the gate returned deny at submit, operation `rejected`. `rejected_by_approver`: an approver rejected an `awaiting_approval` operation. |
| `operation.refused` | `denied` / `tier0` or `denied` | One event **per item** refused by authorisation at plan time: `tier0` = target is Tier-0 protected, `denied` = the initiator lacks the permission over it. Key carries the item index, `target` the object GUID and DN, detail `phase=plan`. Emitted whatever else the plan holds, so a partly refused plan still leaves one denied event per refused item. The block reason on `operation_items` is mutable and outside the hash chain; this event is the durable record. |
| `operation.completed` | see below | The operation reaches a terminal state other than cancelled, or planning ends with no work. |
| `operation.cancelled` | `success` / `cancel_requested`, `cancelled` or `abandoned` | `cancel_requested`: the requester asked to cancel a running operation (running -> cancelling). `cancelled`: a pre-run operation was cancelled at once, or a cancelling operation drained and settled. `abandoned`: reconcile cancelled an operation nobody progressed. |

### `operation.completed` outcomes

| Outcome | Reason | Meaning |
| --- | --- | --- |
| `success` | `succeeded` | Every item succeeded (or was skipped). |
| `failure` | `partially_succeeded` | Some items succeeded, some failed or were blocked. Details carry counts (`succeeded`, `failed`, `blocked`, `skipped`). |
| `failure` | `failed` | No item succeeded and at least one failed or was blocked. |
| `success` | `no_change` | Plan found nothing to do; nothing was written. |
| `failure` | `plan_failed` | Planning produced no runnable item and at least one item was blocked for a technical (non-authorisation) reason, or the plan errored. |
| `denied` | `tier0` or `denied` | Planning produced no runnable item and **every** blocked item was refused by authorisation. The reason is `tier0` if all refusals were Tier-0, `denied` if all were permission denials. |

**All-refused plans with mixed reasons:** when the refusals mix `tier0` and `denied`, `operation.completed` is
`denied` with reason `denied` and **names no target** (no `target` on the event). The specific items and
reasons are in the per-item `operation.refused` events. When all refusals share one reason, the completed
event names the first refused target, and that item is not repeated as an `operation.refused` event; every other refused item still is.
If any blocked item has a technical reason, the outcome is `failure`/`plan_failed` and no target is named.

SIEM guidance: alert on `outcome=denied` for `operation.refused` and `operation.rejected` (attempted
out-of-scope or Tier-0 changes); a `denied` `operation.completed` with no target is the same signal at
operation level, so correlate by operation id and use `operation.refused` for the per-object detail.

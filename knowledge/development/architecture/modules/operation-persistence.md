---
title: "platform/operation: persisted pipeline, fenced claims, holds, approvals"
date: 2026-10-24
updated: 2026-10-24
status: draft
owner: backend-engineer
ticket: T-0174
---

# platform/operation persistence (ADR-0005 rules 3, 6, 8, 9)

Code: `internal/platform/operation/`; migration `migrations/0010_operation_operations.sql`.

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

Deferred: undo, bulk chunked planning, `tier0_after_write` handling, real `directory/client`
Pinner/Observer wiring (see backlog tickets).

## Approval scope (security review fixes)

- `Approve` and `Reject` require `operation.approve` over every item target, blocked and skipped items included; Reject needs no step-up.
- A re-plan keeps an approval only if the plan hash and the set of items blocked at plan are both unchanged.
- An operation held by a workflow Request (`request_ref`) is decided only through `ApproveRequest` / `RejectRequest` with that reference; direct `Approve`/`Reject` return `ErrApprovalByRequest`.
- Transient secrets: unsealed plaintext is cleared after copy and the step's secret is destroyed when the step ends.

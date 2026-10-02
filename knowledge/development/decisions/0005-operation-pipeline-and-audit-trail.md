---
title: "ADR-0005: Every write is an Action run by one operation pipeline (plan, gate, apply, verify, undo); a step token is the only key to a write; our audit trail is a per-tenant hash chain, chained at commit, with signed and externally anchored checkpoints and erasable personal values"
date: 2026-10-02
updated: 2026-10-02
status: proposed
owner: heramb
kind: technical
ticket: T-0047
fitness: fitness-operation, fitness-audit
---

# ADR-0005: Every write is an Action run by one operation pipeline; a step token is the only key to a write; our audit trail is a per-tenant hash chain with signed, anchored checkpoints and erasable personal values

**Status:** proposed. factory-director ratifies it at review of T-0047 and files a `notice`. It becomes `accepted` when `fitness-operation` (O1–O8) and `fitness-audit` (A1–A8) run green in `make ci` on `main`.
**Kind:** technical. The customer-visible results (preview before every change, undo from the audit record, a tamper-evident audit trail, "anonymize on deletion") were decided by the CEO in D-0004 (ENH-04) and by the scope lock. This ADR decides how they are built.
**Deciders:** solution-architect (author). Consulted on 2026-10-02, both concurring with conditions that this text applies (§ Consultation): security-architect on the audit guarantees, erasure, transient secrets and separation of duties; backend-engineer on the job wrapper, chunking, recovery and the commit-time chain. factory-director ratifies. **Ticket:** T-0047. **Parity / scope refs:** ADM-005, ADM-033, ADM-034, ADM-098, ADM-137, ADM-138, ADM-207; ENH-04.

> Amendments (ratified ADRs only): none.

## Context

**What this ADR makes binding.** The [blueprint](../architecture/blueprint.md) sketches one write path (§4.2, §8, §14 flow 2) and an audit pipeline (§9). It leaves the hard parts here (§16):
- the Action contract and its reversibility classes;
- the operation and item state machines (domain model DM-41/42 carry provisional names and say "this file follows T-0047", §11 Q6);
- idempotency, DC affinity, chunking, checkpoint and resume;
- re-checking authorisation against live ancestry;
- the approval-gate extension point (EP-4);
- the mechanics behind the threat model's audit guarantees AG-1…AG-9 ([threat model §11](../architecture/threat-model.md));
- how personal values in append-only records become erasable (domain model X11, §11 Q9);
- whether configuration writes are Actions (m2-plan §2 decision 7).

**Why now.** No write may ship before this is fixed. The first audit event, written by T-0088 for sign-in, already needs the chain format and the erasure mechanism: a chain hashed over clear names cannot be made erasable later (X11). Four checkpoint 2a tickets (T-0093, T-0095, T-0096, T-0104) wait on the configuration-write ruling.

**Constraints already decided.**
- ADR-0001: Go, cgo-free; PostgreSQL is the only stateful service; River for jobs, imported only by `platform/jobs`. Everything below uses the Go standard library for crypto (`crypto/sha256`, `crypto/ed25519`, `crypto/hmac`). No dependency is added, so the licence register is unchanged.
- ADR-0002: `tenant_id` and forced RLS on every tenant table; the job wrapper opens `WithTenantTx` (rule 6 adds a managed-transaction mode); one hash chain per tenant; the embedded connector runs inside the caller's `WithTenantTx` to unseal that tenant's credentials.
- ADR-0003: Actions enter through `Registrar.Action` (EP-3), and the one non-default approval gate through `Registrar.ApprovalGate` (EP-4). Modules have no goroutines (M4). Kernel host functions that take extension-point types are callable only from `platform/**` and `compose/**` (rule 5). Kernel and directory packages hand their own contributions to hosts through `compose/server`, as `inventory.Datasets()` does.
- ADR-0004 (proposed): the API declares `Idempotency-Key` and `If-Match` headers; one `x-permission` per operation; object-level scope is checked again inside the Action.
- Threat model: authorisation is re-checked per item against live ancestry (§7.7, TM-F-AUTHZ); step-up for the §7.4 list (TM-D16); secrets never persist in clear except sealed credentials and seeds (X4, §9).

**What PatchIQ teaches.** A correct interface that a feature can bypass becomes decoration (postmortem §5–§6, §11). The write path is where a bypass hurts most here: a single direct LDAP modify outside the pipeline has no preview, no approval, no audit event and no undo, and nobody would notice in review. So "only Actions write" must be a property of the types, not of good behaviour.

**What the directory gives us and what it does not.**
- An LDAP modify is atomic: "The entire list of modifications MUST be performed in the order they are listed as a single atomic operation" ([RFC 4511 §4.6](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6)). A `delete` of a specific value that is absent fails with `noSuchAttribute`, and an `add` of a present value fails with `attributeOrValueExists` (RFC 4511 Appendix A). A modify that deletes the planned old value and adds the new one is therefore a compare-and-set on that attribute. AD's exact result codes for single-valued attributes are `[LAB: Windows]` (T-0051).
- LDAP has no idempotency key and no transaction across objects. Microsoft Graph throttles with `429` and a `Retry-After` header, and Microsoft says to wait that long before retrying ([Graph throttling](https://learn.microsoft.com/en-us/graph/throttling)). How long a Graph write takes to become readable is `[UNVERIFIED]` and is measured in the Entra lab (T-0051).
- Neither directory takes part in a PostgreSQL transaction. "The audit event commits with the action" (AG-1) can be literally true only for writes to our own database. For directory writes it needs a write-ahead claim and reconciliation (rule 6).

## Decision

We will route **every write a principal makes** (to a directory or to activeDIQ's own configuration) through **one operation pipeline: Plan → gate → Apply → Verify → audit, with Undo as a new operation**. A **step token**, minted only by the pipeline, is the only key that opens a write. Our audit trail is **one hash chain per tenant, chained at commit**, with **signed checkpoints anchored outside the host**, and **personal values held outside the hashed form** so they can be erased. Twelve rules follow. On ratification it amends ADR-0002's Jobs row (rule 6), and it has amended threat-model AG-1, AG-8 and TM-D8 (§ Consultation).

### Rule 1: The Action contract (EP-3)

```go
// internal/platform/operation (replaces the scaffold's Action in operation.go)
type Action interface {
    Describe() Descriptor
    // Plan is the dry run: live reads through PlanContext, the diff, preconditions, reversibility.
    // It cannot write: PlanContext has no write method and its database transaction is READ ONLY.
    Plan(ctx context.Context, pc PlanContext, in Input) ([]StepPlan, error)
    // Apply performs one planned step. The Step is the only key to a write (rule 2).
    Apply(ctx context.Context, s Step, p StepPlan) (Outcome, error)
    // Verify compares the read-back with the plan's after-state.
    Verify(ctx context.Context, s Step, p StepPlan, o Outcome) (Verdict, error)
    // Inverse returns the input that undoes this step, or ErrIrreversible with a reason.
    Inverse(p StepPlan, o Outcome) (Input, error)
}

type Descriptor struct {
    ID            ActionID          // "<owner>.<noun>.<verb>", stable and never reused (X6)
    Version       int               // bumped when Plan/Apply semantics change; recorded on every step
    Permission    authz.Permission  // checked at Plan and again at Apply
    Input         SchemaRef         // the OpenAPI component (ADR-0004): API, workflow, automation, palette
    Target        TargetKind        // Directory(ad | entra) or Store
    Reversibility Reversibility     // worst case: Reversible | Lossy | Irreversible
    AuditKind     audit.Kind        // the step event kind (EP-7), declared by the same owner
    StepUp        bool              // TM-D16 §7.4: submit needs a fresh MFA
    SecretInput   bool              // the input carries a secret.Secret (rule 9)
}
```

- **Modules write typed Actions.** A generic adaptor `operation.Define[In, P, Out](...)` turns typed functions into an `Action`, so a module never handles untyped input. `Input`, `StepPlan.Payload` and `Outcome` are encodable in the canonical form (rule 11), because the plan hash and the audit record cover them.
- **`StepPlan`** holds the target (`connection_id` + `objectGUID`, or "to be created" with a planned parent GUID and RDN), the diff (attribute: before → after), the **preconditions** Apply will enforce, the DC pin (rule 5), the step's actual reversibility class with a reason, and the item's **phase** (items in phase n+1 start only after phase n is terminal, for example "create OU" before "create users in it").
- **Reversibility classes.**
  - `Reversible`: the inverse restores the before-state exactly.
  - `Lossy`: the inverse restores declared fields only. The plan names what is lost, for example a tombstone reanimation that loses link values (DM-16, F3).
  - `Irreversible`: no inverse. Examples: setting a password, an Entra hard delete, sending a message.
  The Descriptor states the worst case; Plan states the class per step. **The preview, the gate and the API response show `Lossy` and `Irreversible` steps before anything runs** (ENH-04 risk). An Action whose Descriptor says `Reversible` and whose Plan returns `Irreversible` fails its contract test.
- **Target kinds.** `Directory` Actions call `directory/client` with the Step. `Store` Actions call the owning package's write API with the Step, and Apply, Verify, the state change and the audit event run in **one database transaction** (rule 6).
- **How Actions are registered.** Modules call `Registrar.Action(a)`. Kernel and directory packages export theirs (`notify.Actions()`, `authn.Actions()`, `authz.Actions()`), and `compose/server` hands them to the operation host, as ADR-0003 rule 5 already allows for datasets. `Boot` refuses an Action whose ID is not namespaced by its owner, whose `AuditKind` is not registered by the same owner, or whose `Permission` is not in the EP-6 catalogue.
- **The read-only catalogue.** `operation.Catalogue()` lists registered Descriptors for `search` and the command palette (ADR-0003 F4).

### Rule 2: A step token is the only key to a write, and it opens only the planned write

```go
// Step is minted only by the operation runner, for one claimed step, and dies when Apply or Verify returns.
type Step struct{ s *stepState }    // unexported field; the zero value is refused everywhere

func (s Step) Key() IdempotencyKey  // (operation, item, step)
func (s Step) Attempt() int         // the fencing number (rule 6)
func (s Step) Operation() OperationID
func (s Step) Actor() authz.Principal   // the initiator chain, never the approver's authority (rule 7)
func (s Step) DC(nc NamingContextID) DCRef  // the pin (rule 5)
func (s Step) Tx() store.Tx              // Store Actions only: the recording transaction
```

- **Directory writes.** Every write method of `directory/client` takes a `Step`: `client.Write(ctx, step, op)`. The connector contract's `Apply` RPC carries the step's idempotency key, attempt, operation ID, acting principal, DC pin and **plan digest**. The connector logs all of them (TM-TB6-T5). Named secret reads (LAPS, BitLocker) are reads with their own audit kind (safe-primitives §3.7) and take no Step. A LAPS *reset* is a write, so it is an Action.
- **A Step authorises this write, not just any write.** `stepState` carries a digest of the step's planned target and operation (target GUID, operation kind, attributes and values; secret values are excluded, but the presence of a secret is included).
  - `client.Write` recomputes the digest of the operation it is handed and refuses a mismatch. The connector checks it again.
  - An Action cannot use its Step to write to a different object or attribute than the one that was previewed, approved and hashed.
- **The checks live in the pipeline, not in Action code.** `client.Write` (Directory) and the runner (Store) perform the Apply-time authorisation re-check (rule 7) before the write. An Action's Apply cannot skip it.
- **Configuration writes.** The exported write functions of a table classed `config` (rule 10) take a `Step` and use `Step.Tx()`.
- **A Step cannot escape.**
  - It is never stored in a struct field, global, map, slice or channel.
  - It is never captured by a closure.
  - It is never passed to a function that is not itself a write API or a helper with a `Step` parameter (O1).
  - Modules start no goroutines (ADR-0003 M4).
  - After Apply or Verify returns, the runner revokes the Step, and the client refuses a revoked, expired or zero Step. A smuggled copy is therefore dead.

### Rule 3: The operation and item state machines

These tables are the source. Code declares the same transitions in `internal/platform/operation/transitions.go`, and O4 fails if the two differ. DM-41 and DM-42 follow this rule.

```transitions
# Operation (DM-41)
draft             -> planning           input complete; Plan starts (inline for one item, chunked job for bulk)
draft             -> cancelled          abandoned or withdrawn
planning          -> planned            plan recorded with plan_hash; at least one applicable item
planning          -> plan_failed        input invalid, capability missing, Action permission refused, or no applicable item
planning          -> cancelled          cancelled while planning
planned           -> approved           gate: allow
planned           -> awaiting_approval  gate: hold (workflow Request or kernel single approval)
planned           -> rejected           gate: deny
planned           -> planning           re-plan: input edited or plan_valid_until passed
planned           -> cancelled          withdrawn, or not submitted before the abandon window
awaiting_approval -> approved           approvals complete for the current plan_hash
awaiting_approval -> rejected           an approver rejects, or the Request expires
awaiting_approval -> planning           re-plan; approvals bound to the old plan_hash lapse
awaiting_approval -> cancelled          withdrawn by the requester or a tenant-owner
approved          -> queued             plan still valid; chunk jobs enqueued
approved          -> planning           plan expired; re-plan, then the gate runs again for the new hash
approved          -> cancelled          withdrawn before it was queued
queued            -> running            first step claimed
queued            -> cancelled          cancelled before any step was claimed
running           -> succeeded          every item succeeded or skipped
running           -> partially_succeeded at least one item succeeded and at least one failed or was blocked
running           -> failed             no item succeeded
running           -> cancelling         cancel requested
cancelling        -> cancelled          in-flight steps finished; remaining steps not_run
# OperationItem (DM-42)
pending           -> planned            Plan produced at least one step
pending           -> skipped            nothing to change (empty diff)
pending           -> blocked            refused at Plan: authorisation, tier0, validation, a stale input row
planned           -> running            first step claimed
planned           -> cancelled          operation cancelled before the item started
running           -> succeeded          every step verified
running           -> failed             a step failed or verify_failed; later steps not_run
running           -> cancelled          operation cancelling; the current step finished, later steps not_run
succeeded         -> undone             an undo operation verified the inverse of every step
failed            -> undone             an undo operation verified the inverse of every applied step
# Step (DM-42 steps[])
planned           -> applying           claimed: key bound, attempt recorded, DC pinned; committed before the write
planned           -> not_run            an earlier step did not succeed, or the operation was cancelled
applying          -> applied            Apply returned, or reconciliation found the planned after-state
applying          -> failed             denied at the re-check, stale_state, outcome_unknown, permanent error, or retries exhausted
applying          -> not_run            reconciler only: the operation is cancelling and the before-state shows no write happened
applied           -> verified           read-back matches the plan's after-state
applied           -> verify_failed      read-back differs, scope changed, or the verify window elapsed
verified          -> undone             the undo operation's inverse step verified
```

- **Terminal states.** Operation: `plan_failed`, `rejected`, `succeeded`, `partially_succeeded`, `failed`, `cancelled`. Item: `skipped`, `blocked`, `succeeded`, `failed`, `cancelled`, `undone`. Step: `not_run`, `failed`, `verify_failed`, `verified`, `undone`. Nothing leaves a terminal state except the explicit `→ undone` rows, which an Undo operation drives.
- **Partial success is never success** (DM-41.I2). A blocked item makes the result at best `partially_succeeded`. `cancelled` reports counts of applied, verified and not-run steps.
- **The DM-41 and DM-42 review points are answered.** (a) `planning → plan_failed` exists. (b) The stale check moves *into* `applying`: the authorisation re-check and the precondition are the first things the claimed step does, and a refusal is `applying → failed` with reason `denied` or `stale_state`. There is no `planned → failed`. `expired` is no longer a state: an expired plan is re-planned (`→ planning`), and an abandoned one is `cancelled` by the sweeper with reason `abandoned`.
- **Only the transition function writes a state.** Every state change goes through one function in `operation` that checks the table and writes the audit event in the same transaction (rule 6). No other SQL updates a state column (O4).

### Rule 4: Idempotency at three levels

| Level | Key | Effect |
| --- | --- | --- |
| Submission | `(tenant, principal, Idempotency-Key)` from the API header (ADR-0004), kept 24 hours | A retried submit returns the existing operation |
| Automation firing | `(policy, version, firing)` (DM-62.I1) | A retried firing creates no second operation |
| Step | `(operation, item, step)` (DM-42.I1) | A retried step never double-applies |

**How a step is idempotent when the directory has no idempotency key.** Apply is a **conditional write** whose precondition is the plan's before-state.
- For AD, a modify deletes the planned old value and adds the new one in one atomic request (RFC 4511 §4.6), so a concurrent change fails it. A create fails with `entryAlreadyExists` if the planned name is taken.
- For Entra, and for AD operations with no value to compare, the connector reads and compares on the pinned DC immediately before writing. The window between read and write is a declared residual of the provider capability. The connector spec decides whether Graph ETags narrow it `[UNVERIFIED]`.
- **Repeat after success.** When a retried step finds the after-state already in place, Apply returns `already_applied` with the read-back, and the step moves to `applied`. A create is recognised as already applied when an object exists at the planned parent and RDN, was created after the step's claim, and matches the planned attributes.

### Rule 5: DC affinity per operation

- **Plan pins one writable DC per naming context** for the whole operation. It prefers the connector's site and a healthy DC, and records the pin in the plan, so the pin is covered by `plan_hash`. Plan reads, the Apply re-check, the write and Verify all go to the pinned DC, which gives read-your-writes (FEAS §1.1).
- **If the pinned DC is lost mid-operation:**
  - Steps not yet claimed are re-pinned to another DC only after their preconditions are re-read there. Items whose before-state differs on the new DC fail `stale_state`.
  - Steps that are `applied` but not verified keep retrying Verify on the pinned DC within the verify window. After that, they read back from another DC and are recorded `verified` with that DC named, or `verify_failed` with reason `dc_unavailable`.
- **Entra has no DC.** Verify retries with backoff inside a per-provider verify window, because Graph reads after writes may lag `[UNVERIFIED]`. Throttling honours `Retry-After` (Graph throttling guidance).
- **Concurrency limits** are kernel defaults, adjustable per connection: four concurrent writes per (connection, DC), four per Entra tenant, and two concurrent chunk jobs per operation.

### Rule 6: Execution on the job wrapper: chunks, fenced claims, recovery, and when the audit event commits

- **The OperationItem is the system of record; the job is only a driver** (DM-43.I1). `operation` registers these job kinds on `platform/jobs` (EP-5). All are tenant-carrying (ADR-0002 Jobs row):

  | Kind | What it does |
  | --- | --- |
  | `operation.plan` | plans one chunk of a bulk operation |
  | `operation.apply` | runs one chunk. This includes a held `Store` step once it is approved |
  | `operation.verify` | drives deferred verification of `applied` steps (Entra, or a lost DC) |
  | `operation.reconcile` | per tenant, under a lease: recovers steps whose claim lapsed |
  | `operation.sweep` | per tenant, under a lease: re-drives stalled operations, detects terminal operations as a backstop, abandons stale plans, deletes expired transient secrets (rule 9) |

- **These kinds run with a tenant-bound context and a `TenantTx` runner, not inside one wrapper transaction.**
  - Their body opens short `WithTenantTx` transactions itself, through the wrapper-provided runner.
  - It never holds a transaction across a directory call.
  - **On ratification this amends ADR-0002's Jobs row.** That row says "one job wrapper opens `WithTenantTx` before the job body runs". It becomes: "the wrapper establishes the tenant before the body runs; a kind either runs inside one wrapper transaction (the default) or declares `ManagedTx` and receives the tenant-bound transaction runner". T-0084 implements both modes (note filed).
- **Enqueueing.** Chunk jobs are inserted with the job API's transactional insert, in the same transaction as `approved → queued`, so a queued operation cannot lack its jobs.
- **Chunks** default to 100 items, adjustable per provider. A chunk job's unique key, `(operation, plan_revision, phase, chunk_no)`, is a **de-duplication optimisation only**. Correctness never depends on it, because job records are cleaned up after completion. It comes from the fenced claims below. Each job kind's timeout is set above its chunk's worst case. A timeout mid-call is recovered by reconciliation.
- **Fenced claims.** A step is claimed **only when it is about to run**, meaning a concurrency slot (rule 5) is free:
  - The claim is `planned → applying` with `FOR UPDATE SKIP LOCKED`, a new `attempt` number and `claimed_until = now() + lease`. `now()` is the database clock.
  - The runner renews `claimed_until` while the call is in flight.
  - Every recording `UPDATE` is predicated on `state = 'applying' AND attempt = $n`. A late result from a superseded attempt changes nothing.
  - The reconciler takes over a lapsed claim by compare-and-set, which bumps `attempt`.
  - Plan-chunk results are predicated on `plan_revision`, so they cannot land after a re-plan or cancel.
- **The life of a directory step:**
  1. **Claim** (transaction 1). The `operation.started` event was written at `queued → running`. The claim commits before the write. **These commits are the write-ahead record.**
  2. **Re-check, then write** (no recording transaction is open). `client.Write` re-checks authorisation against live ancestry on the pinned DC (rule 7), verifies the plan digest (rule 2), and sends the conditional write. The embedded connector unseals its credential inside its own short `WithTenantTx`, as ADR-0002 requires. A remote connector uses its local credential (TM-D8).
  3. **Record** (transaction 2). The step moves `applying → applied → verified | verify_failed`, or `applying → failed`. Its audit events are written **in the same transaction**. Several steps of one chunk may be recorded together, which amortises the chain lock (rule 11). When Verify needs more time, `applied` commits with its event, and `operation.verify` commits `verified` later with its own event.
- **Transient errors** (connector unreachable, DC busy, `429`) keep the step in `applying` and retry with the **same key** and a new attempt number. Retries back off and honour `Retry-After`. After the attempt limit, the step fails with reason `retries_exhausted`.
- **Crash recovery.** A step still `applying` after `claimed_until` is reconciled. The reconciler reads the live state on the pinned DC:
  - the after-state is in place → `applied`, with `recovered: true` on the event;
  - the before-state is still in place → re-apply with the same key, or `not_run` if the operation is `cancelling`;
  - anything else → `failed` with reason `stale_state`.
  - **A password step is never re-applied** by reconciliation: a repeat would be refused by password history and would record a false failure. It is `applied` if `pwdLastSet` is later than the claim, and otherwise `failed` with reason `outcome_unknown`. The technician then retries as a new operation. That `pwdLastSet` is set by every successful reset is `[LAB: Windows]` (ad-expert, T-0051).
  No step is ever left `applying` silently.
- **Stalled operations.** River may discard a job after its last attempt, and the cleaner may remove one. So `operation.sweep` re-enqueues the work for any operation that is `planning`, `queued`, `running` or `approved` and still has unclaimed work but no progress within the stall window. The unique key makes a duplicate harmless.
- **Terminal detection.** The recording transaction that moves an operation's last non-terminal item locks the operation row and runs the operation's terminal transition. `operation.sweep` is the backstop.
- **`Store` Actions: one transaction, after any I/O.**
  - **Plan first.** Plan runs before the transaction. This includes any I/O, such as a connection test, an SMTP test send or an LDAP bind for verification.
  - **Then one transaction holds everything.** Inside the single transaction the runner:
    1. checks that the definition version (X7) or the row's version still matches the plan, and that `plan_hash` is unchanged;
    2. runs the gate;
    3. re-checks authorisation;
    4. runs Apply and Verify, with the state changes and the audit event.
  - **If anything fails, the outcome is still recorded.** When that transaction rolls back (Apply or Verify error, or a refusal at the re-check), the runner records the outcome and its event in **a fresh transaction**: `failed`, or `denied` for a refusal. A failure or denial is never lost with the rollback (AG-2).
  - **A held `Store` operation** keeps its persisted plan. After approval, it runs as one `operation.apply` job, in one transaction.
- **What AG-1 means here.**
  - For `Store` Actions, AG-1 holds literally.
  - For `Directory` Actions it holds as **write-ahead plus same-transaction outcome**. The started event and the claim commit before the write. The outcome event commits with the outcome state, and a crash between the two is closed by reconciliation.
  - **The honest residual.** Between the directory write and the recording commit, the change exists in the directory without its outcome event. That lasts until the commit or until reconciliation, and inventory history (DM-18) shows the change meanwhile. The threat model's AG-1 wording is amended to say this (§ Consultation).

### Rule 7: Authorisation at Plan and again at Apply, against live ancestry (TOCTOU)

- **The pipeline performs both checks, never Action code.**
  - **At Plan.** After the Action's Plan returns its steps, the runner authorises every target through a kernel port, `operation.LiveAncestry`. `directory/client` implements the port and `compose/server` wires it (the ADR-0003 F6 kernel→directory port pattern). The check is role ∩ delegation scope ∩ token scope (threat model §7.7), for the initiator, against the target's **GUID ancestry read live from the pinned DC**, never from inventory. Time-dependent state is read live too (DM-16.I5a).
  - A refused item is `blocked`, with a denial event per item (AG-2). A missing Action permission fails the whole plan (`plan_failed`), with a denial event.
- **At Apply.** `client.Write` re-reads the ancestry on the pinned DC and authorises again, **immediately before the conditional write**. A move or rename checks both the source and the destination parent. Role assignments are read as they are now, so a technician who lost a role between Plan and Apply is refused (`failed`, reason `denied`, with a denial event).
- **Whose authority.** Authorisation always evaluates the **initiator chain**: the requester, the automation policy as its own subject (DM-60.I2), and the API token's scope. An approval **never widens** it. A request whose requester lost the right while it waited fails `denied` at Apply.
- **Residual.** LDAP cannot make a write conditional on the object's parent. If someone else moves an object out of scope in the milliseconds between the re-check and the write, the write still happens. Verify then reads the ancestry again, records `verify_failed` with reason `scope_changed`, and alerts. TM-F-AUTHZ's "moved between Plan and Apply" test covers the window that matters, which lasts from minutes to days.
- **No role touches `tier0`** (TM-D2, DM-35.I5). It is checked at both points, and no gate can lift it.

### Rule 8: The approval gate (EP-4), kernel holds and separation of duties

```go
// internal/platform/operation
type Gate interface {
    ID() GateID
    // Route runs once per plan revision, after Plan and authorisation, inside the transaction that records the plan.
    Route(ctx context.Context, g GateContext, p PlanSummary) (Route, error) // Allow | Hold{ref} | Deny{reason}
}
// What a gate calls back, through platform.Deps (never a module import):
type Approvals interface {
    Approve(ctx context.Context, op OperationID, planHash PlanHash, by Approval) error
    Reject(ctx context.Context, op OperationID, planHash PlanHash, by Approval, reason string) error
}
```

- **One kernel default and at most one registered gate** (ADR-0003). The kernel default, `permission-only`, allows the operation, because Plan has already checked the permission. `workflow` registers the one non-default gate. It matches the operation against WorkflowDefinitions (DM-64 `applies_to`: Action IDs, origin, hold reason, scopes, requester roles) and returns either `Hold` with a Request reference (DM-65) or `Allow`.
- **The gate fails closed.** A gate that returns an error, or does not answer, leaves the operation in `planned` and raises an alert. It never allows.
- **Kernel holds come first and cannot be skipped.** Before any gate runs, `operation` applies its own hold rules:
  - **Blast radius:** an automation run that plans more than the policy's `max_objects` (DM-60.I3).
  - **Irreversible steps,** when the tenant setting "approval for irreversible changes" is on.
  - **A `StepUp` Action started by a principal that cannot step up** (an API token, an automation policy). It is held for an approval that carries step-up. If no approval path exists, it is refused.
  - **Undo of an operation that itself needed approval** (DM-41.I3).

  A held operation goes to the registered gate with `hold_reason` set. **This answers T-0006 review point (c).** If a WorkflowDefinition matches the hold, approval is a Request on that workflow. Otherwise the kernel's **single approval** applies: one approval by an account holding `operation.approve` over the scope of **every** item. A `tenant-owner` always qualifies.
- **Approvals bind to `plan_hash`** (DM-65.I1). `Approve` with a stale hash is refused. A re-plan that changes the hash sends the operation back through the gate. A re-plan that yields the **same** hash keeps its approvals.
- **The kernel enforces who may approve. It does not trust the gate to.** `Approve` refuses:
  - any principal in the initiator chain (DM-64.I1);
  - anything but an **interactive human session** (API tokens and automation policies never approve);
  - an approval of an `Irreversible` or `StepUp` operation without a fresh step-up (TM-D16);
  - **a sock-puppet approver:** an account that was created, or granted `operation.approve`, by a principal in the initiator chain within the last 30 days. Such an attempt also alerts `tenant-owner` accounts. This closes the second-account bypass by a compromised tenant-owner (X5).

  A buggy or hostile gate therefore cannot get an operation self-approved.
- Every gate outcome writes an audit event: held, approved (with the approver), rejected, or request expired.

### Rule 9: Inputs, secrets and plan validity

- **The plan hash** is SHA-256 over the canonical encoding (rule 11) of: the Action IDs and versions, every item's target, diff, preconditions, phase and reversibility, the DC pins, and a flag for each secret input. It never covers a secret value.
- **Transient secrets** (security-architect concurs, with the conditions below, § Consultation). Some Action inputs carry a `secret.Secret`, such as a password typed in the console or a CSV password column. Such a secret is stored only in `operation_secret`. The rules for it:
  - **Sealing.** It is sealed with the TM-D7 seal primitive. Its associated data is `(tenant, table, row, column, key version)` plus the step key. There is no separate binding scheme.
  - **Its own TTL.** The TTL is the request's expiry, capped at **72 hours**. It is independent of `plan_valid_until`. An expired secret fails its step closed, with reason `secret_expired`. A secret is never regenerated, and never replaced after submission: a new secret means a new operation.
  - **Deletion.** It is deleted in the step's recording transaction, and on every terminal operation state. The sweeper deletes any that are left over. The runtime role holds no `UPDATE` on `operation_secret`.
  - **Transit to a remote connector.** The server unseals the secret and sends it inside the Apply RPC over the mTLS tunnel. The connector never persists it. TM-D8 is amended from "nothing secret is pushed over fleet" to "no **standing** credential is pushed over fleet".
  - **Where it never appears.** Never in a plan, diff, event, export, inverse input or log (X4, AG-9, DM-42.I4).
  - **What changes in X4.** X4's "secrets are never stored" becomes "never stored in clear, and stored sealed only while a step that needs it is in flight". The domain model's X4 follows.
- **Plan validity.** `plan_valid_until` defaults to 1 hour for directory Actions and 24 hours for `Store` Actions. At `approved → queued` the kernel re-plans an expired plan, and a plan whose hash is unchanged keeps its approvals. Every step's precondition is checked again at Apply in any case.

### Rule 10: Configuration writes are Actions; system bookkeeping is not

**Ruling on m2-plan decision 7.** Every write **a principal makes to activeDIQ's own configuration** is an EP-3 Action with `Target: Store`. It gets the same preview (a diff against the current version), gate, step-up, audit and undo as a directory write. Each runs inline in the request when the gate allows, so the user waits for one transaction, not a queue. Examples:
- connections and credentials (T-0093): `connections.*`;
- notification channels and SMTP settings (T-0095): `notify.channel.*`, exported by `platform/notify`;
- accounts created, disabled or reset by an administrator (T-0096): `authn.account.*`;
- roles, assignments and delegation scopes: `authz.*`, `delegation.*`;
- templates, naming formats, attribute lists, workflow definitions, automation policies, report definitions and schedules (T-0104: `reports.schedule.*`), data sources;
- audit retention, SIEM sinks, tenant settings, erasure requests (rule 12).

**System bookkeeping is not an Action.** It is written by its owning package and audited where the threat model says so (DM-80.I3). The complete list, kept in the fitness configuration, follows. Adding to it is an amendment to this ADR.
- sign-in, sessions and the signing-in user's **own** factor enrolment at first sign-in (DM-31, DM-37 self-service);
- the first-run bootstrap, a registered platform path (ADR-0002);
- connector and agent enrollment handshakes (`fleet`);
- sync and inventory (D-kind, DM-14…DM-23);
- the bookkeeping of jobs, leases, schedules, operations, requests and approval decisions (DM-06, DM-41–44, DM-65, DM-66);
- report runs, automation runs and policy progress, deliveries (DM-61, DM-62, DM-72, DM-84);
- audit events, checkpoints and the personal-value store (DM-80, DM-81, rule 12);
- data-key rotation (TM-D15).

**Tables carry a write class.** The ownership map (ADR-0003 rule 6) gains a column, `config` or `system`, declared beside the migration. O3 checks that every write to a `config` table is made by a function that takes an `operation.Step`.

**Undo for configuration** restores the previous version. Definitions are versioned (X7), and other configuration rows keep their before-image in the step outcome.

### Rule 11: The audit chain: format, per-tenant serialisation, checkpoints, export, verifier, retention, SIEM

**Event envelope** (AG-3, DM-80). Each event carries:
- `tenant_id`, `seq` and `at`;
- `kind` and `kind_version`;
- the actor (a principal reference) and the on-behalf-of chain: API token, automation policy and version, request and its approvals;
- the verification factor;
- the source: the component, plus the client address as a personal value;
- the targets: connection, GUID and class, with display snapshots as personal values;
- the operation, item, step, request and correlation IDs;
- the outcome (`success`, `failure` or `denied`) with a reason code;
- typed details;
- `prev_hash` and `hash`.

**Which transitions emit events.**
- An inline `Store` Action that the gate allows writes **one** event: the step outcome, which carries the operation ID, `plan_hash` and the final state.
- Other operations write:
  - `operation.planned`, only when the plan is persisted for later (bulk preview, or held);
  - `operation.plan_failed`;
  - `operation.item.blocked`, one per item;
  - the gate events;
  - `operation.started`;
  - the step outcome events (`applied`, `verified`, `verify_failed`, `failed`, `denied`);
  - `operation.completed` or `operation.cancelled`, with counts.
- `not_run` and `skipped` are counted, not evented.

**Canonical form `adq-canon/1`.** This is a deterministic, length-prefixed, tagged binary encoding:
- fields appear in strictly increasing tag order;
- unsigned varints are minimal;
- UTF-8 strings are stored as exact bytes, and invalid UTF-8 is refused;
- UUIDs take 16 bytes;
- timestamps are int64 microseconds, UTC;
- lists keep their order;
- there are no maps; sorted key/value lists replace them;
- absent fields are omitted.

A decoder rejects any non-canonical input. The format needs only the standard library. T-0088 specifies it byte by byte in a public format document, so an auditor can write an independent verifier.

**Chain construction.**
- `body_hash = SHA-256(adq-canon/1(envelope without prev_hash and hash))`
- `hash_n = SHA-256("adq-audit-chain/1" ‖ 0x00 ‖ tenant_id ‖ uint64be(seq_n) ‖ hash_{n-1} ‖ body_hash_n)`
- `hash_0 = SHA-256("adq-audit-genesis/1" ‖ 0x00 ‖ tenant_id)`

The tenant ID and `seq` are inside every link. An event therefore cannot be spliced into another tenant's chain, or moved within its own chain. The genesis value is public, so **the chain alone proves nothing to someone who holds the whole export**. Trust comes from checkpoints anchored outside the host. That is why the verifier needs a trust root (below).

**Per-tenant serialisation: chained at commit.**
- **Append buffers; the store chains.** `audit.Append(tx, kind, event)` buffers the event on the transaction. `store.WithTenantTx` runs the body, then the chain statements, then `COMMIT`. The chain statements are:
  1. a check that the transaction is `READ COMMITTED`, refusing it otherwise;
  2. `SELECT seq, hash, at FROM audit_head WHERE tenant_id = $1 FOR UPDATE`;
  3. for each buffered event: `at = greatest(clock_timestamp(), head.at)`, then hash, then `INSERT` into `audit_event`;
  4. an `UPDATE` of `audit_head`.
- **Why a head row.** The row lock serialises the tenant's appenders. Under `READ COMMITTED`, a `SELECT … FOR UPDATE` that waited re-reads the row's committed version, so it sees the predecessor's head ([row-level locks](https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS), [EvalPlanQual behaviour](https://www.postgresql.org/docs/current/transaction-iso.html#XACT-READ-COMMITTED)).
- **What the head row costs.** It is the only audit table on which the runtime role holds `UPDATE`. A tampered head breaks the next link, so the verifier catches it.
- **Backstop and lock order.** The unique index `(tenant_id, seq)` is the backstop: a stale head fails the transaction rather than forking the chain. The head lock is the last lock a transaction takes, under a `lock_timeout`. Nested `WithTenantTx` calls are refused.
- **Gapless by construction.** `seq` order is commit order, so `seq` has no gaps: a rolled-back transaction consumed nothing. `at` is monotonic per tenant, so time partitions are `seq` ranges.
- **An ambiguous `COMMIT`** (the connection drops during commit) is resolved by the caller's idempotent retry (rule 4).
- **Throughput budget.** The lock is held for the inserts plus the commit flush. That gives roughly 200–1,000 audited commits per second per tenant on local storage, and roughly 100 per second with a synchronous standby `[UNVERIFIED: measure in the T-0088 load test]`. Bulk operations amortise the lock by recording several steps per transaction (rule 6). A transaction that appends nothing never takes the lock.

**Signed checkpoints (DM-81, AG-6).**
- **The key.**
  - Each tenant has an Ed25519 checkpoint key ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), Go `crypto/ed25519`).
  - Its private key is sealed under the tenant data key (TM-D7).
  - Keys have **validity windows in the chain**. An `audit.checkpoint_key.created` event introduces a key, and an `audit.checkpoint_key.retired` event ends it. The verifier rejects a signature by a key outside its window.
  - **Routine rotation** is yearly or on demand. The first checkpoint under the new key is also signed by the old key.
  - **Rotation on suspected compromise** skips that cross-signature, because it would prove nothing. It sends the new fingerprint to every sink at once.
- **Cadence.** The `audit.checkpoint` job runs per tenant, under a lease. It signs the head every 1,000 events or 5 minutes, whichever comes first, if anything new was appended. It also signs:
  - the **last event of every time partition**;
  - the head before every export;
  - the head on clean shutdown.
- **The signed statement** is `adq-canon/1` of `{tenant_id, seq, hash, signed_at, key_id, prev_checkpoint_seq, prev_checkpoint_hash}`, prefixed with the domain string `adq-audit-checkpoint/1`.
- **What signing buys.** A database administrator who rewrites rows (TM-TB4-T4) cannot sign without the KEK. Root on the host (X6) can sign, so checkpoints are also **anchored outside the host**.

**External anchoring.**
- Every checkpoint and every key event is sent to every configured SIEM sink as its own message.
- Every export ends at a fresh checkpoint and carries all checkpoints in its range.
- The console shows the latest checkpoint hash and the current key fingerprint for out-of-band recording.
- **No anchor, an alert.** If no checkpoint has left the host for 7 days (no sink and no export), `tenant-owner` accounts are alerted. This is the residual for an install with no SIEM.
- The threat model's honest limit stands: root on the host can rewrite only the tail after the last checkpoint that left the host.

**Export and the offline verifier (AG-7, AG-8).**
- **The export bundle, `adq-audit-export/1`,** contains:
  - a manifest: tenant, `seq` range, format versions, key fingerprints and their chained introduction and retirement events;
  - the canonical events;
  - the checkpoints;
  - a personal side file with values and salts. A pseudonymous export omits values **and** salts.
- **Exporting needs step-up** (TM-D16), and the export is audited with its range and row count.
- **Reading the audit trail is audited but needs no step-up.** The threat model's AG-8 wording is aligned to this (§ Consultation).
- **The verifier, `adq-audit-verify`** (`cmd/auditverify`), is a standard-library-only Go binary for Windows, Linux and macOS, published with each release. It needs no installation. It checks:
  - the canonical encoding;
  - `seq` continuity;
  - every hash link from genesis, or from a retained checkpoint;
  - every checkpoint signature against the chained key windows;
  - the anchors;
  - every personal side value against its commitment (rule 12);
  - that every missing personal value is explained by an erasure event that itself references a verified `personal.subject.erase` step or a recorded trigger event;
  - that every retention gap is explained by a purge event.
- **It needs a trust root.** That is a key fingerprint pinned out of band (from the console, the SIEM or an earlier export), or at least one anchor. With neither, it reports **`UNANCHORED`**, never `OK`, because anyone holding an export could re-sign a rebuilt chain. Otherwise it reports `OK`, or the first failing `seq` with a reason code.

**Retention without breaking verification (AG-4, DM-80.I2, X10).**
- **Settings and roles.** Retention is a tenant setting per record class (ADM-206). Purges run on the **maintenance path under the owner role**. The runtime role holds only `INSERT` and `SELECT` on `audit_event` and `audit_checkpoint`.
- **The purge unit** is a time partition whose last `seq` is a checkpoint's `seq`; the partition-boundary checkpoint guarantees that.
- **A purge needs an archive.** It requires a recorded archive export covering the range, unless the tenant's `purge_without_archive` setting is on. Changing that setting needs step-up and is audited.
- **Every purge is evidence.** It appends `audit.retention.purged`, carrying the range, the boundary checkpoint and the archive digest.
- **Checkpoints are never purged** (DM-81.I1), and verification of the retained chain starts at the boundary checkpoint.

**SIEM forwarding (ADM-198, AG-6).**
- **The job.** `audit.forward`, one per tenant and sink, reads by `seq` watermark. It sends events, checkpoints and key events through EP-9 sinks, rendered by the T-0139 encoders.
- **Delivery semantics.** Delivery is at least once; `seq` de-duplicates.
- **Never on the write path.** Forwarding happens outside the recording transaction, so a SIEM outage never blocks a write.
- **Lag is watched.** Lag is a metric. A sink more than 15 minutes behind, or failing repeatedly, alerts `tenant-owner` accounts.
- **Sink changes** need step-up and are audited (AG-8).
- **Personal values.** Forwarded events carry personal values in clear unless the sink is set to `pseudonymous`. **Erasure cannot recall what a SIEM already holds**, and the sink settings page says so.

### Rule 12: Personal values are erasable: salted commitments in the chain, clear values in a side store (answers DM §11 Q9)

**The chained form never holds a clear personal value.** It holds a `PersonalRef`: `subject_ref` (a typed reference to the person the value is about, for example `dir:<connection>:<objectGUID>` or `acct:<account_id>`), `value_id`, `field` and
`commitment = HMAC-SHA-256(key = subject_salt, msg = adq-canon/1({"adq-personal/1", value_id, field, value}))`.
The length-prefixed canonical form removes any ambiguity at field boundaries. The clear value lives in a side store owned by a new kernel package, **`platform/personal`**:
- `personal_subject(tenant_id, subject_ref, salt[32], hold)`;
- `personal_value(tenant_id, value_id, subject_ref, record_kind, field, value)`.

The runtime role cannot `UPDATE` either table. Only erasure deletes from them.

| Property | How it holds |
| --- | --- |
| **Readable and searchable** while the subject exists | Reads join the side store, which is ordinary indexed data |
| **Tamper-evident** | The offline verifier recomputes each commitment from the exported salt and value, with no key. An edited value fails |
| **Erasable without touching evidence** | Erasure deletes the subject's salt and values. The event, its GUIDs and its hash remain, the chain still verifies, and the UI shows `[erased]` (X11). Without the 256-bit secret salt, a guessed low-entropy value cannot be confirmed. Including `value_id` stops values being linked even within one subject |
| **Erasure is itself evidence** | A `personal.subject.erased` event records the subject reference, the value count and the trigger, with no values. It must reference a verified `personal.subject.erase` step or a recorded trigger event. The verifier flags a missing value that no such event explains, so someone with runtime-role database access cannot quietly delete values and forge an erasure |

- **What counts as personal:**
  - display snapshots of targets and actors (DN, name, UPN, mail, sAMAccountName);
  - client addresses;
  - free text (comments, reasons);
  - before/after values of attributes that the attribute catalogue (safe-primitives P3) classes `personal`. **An attribute the catalogue does not know is personal by default.**

  GUIDs and SIDs stay in clear in the chained form, because they carry the evidence. The result is therefore **pseudonymised, not anonymised**: a GUID is still personal data under the GDPR's pseudonymisation definition ([GDPR Art. 4(5)](https://eur-lex.europa.eu/eli/reg/2016/679/oj), Recital 26). Customer-facing wording for ADM-207 goes to the CEO through the PRD, not this ADR.
- **What triggers an erasure:**
  1. the ADM-207 tenant setting "erase personal data when a directory object is purged": inventory observes the purge, and erasure runs after the configured delay;
  2. an explicit request by a `tenant-owner`, through the Action `personal.subject.erase` (step-up, `Irreversible`);
  3. deletion of an activeDIQ account, under the same setting as trigger 1.

  A `hold` on the subject (legal hold) blocks all three. The default for trigger 1 and the hold UX belong to the audit and compliance PRD.
- **What erasure cannot reach.**
  - SIEM copies, earlier non-pseudonymous exports and **database backups** keep the values until they expire.
  - So that a restore cannot resurrect erased subjects, every erasure is also written to an **erasure register outside the database**, in the blob store (ADR-0001 rule 3). The restore runbook replays the register after a restore.
  - Application logs never carry personal values (telemetry redaction, threat model §9.7).
- **One shape for every append-only record.** DM-18 ChangeRecord old and new values (owner `directory/inventory`, applied by T-0065), DM-66 comments (`workflow`) and DM-80 events all store `PersonalRef`s. They write values through `personal`'s Go API, so one erasure path covers them all.
- **Mutable records** (Operation input, Request, Account) are erased in place, as X11 already says.

## Alternatives considered

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **Static analysis alone** for "only Actions write" (a call-graph rule, no token) | No new type in the client API; less ceremony for directory-engineer | A call graph over interfaces and function values is approximate. It is PatchIQ's "the interface exists, review will catch it". The token makes a bypass a compile error, and the analyzer only has to stop the token escaping, which is a local, syntactic check |
| **Event sourcing** for operations (state derived from an event log) | One store for state and evidence; replay | Two sources of truth to reconcile (River, OperationItem, events) and a harder query model for every operations screen. Persisted state plus same-transaction audit gives the same evidence |
| **Configuration writes as plain audited CRUD**, Actions only for directories | Less code in four 2a tickets; no Plan for an SMTP form | Two write paths, so two places to forget step-up, approval or audit. RBAC changes are the escalation path (TM-TB1-T11), and customers ask for four-eyes on them. Undo for configuration comes free from the Action shape. The inline fast path keeps the UX cost to one transaction |
| **Asynchronous chainer** (events inserted unchained; a per-tenant job assigns `seq` and hashes later) | No per-tenant lock in the business transaction; higher burst throughput | Events exist unchained for a while; `seq` no longer equals commit order; the chainer's own crash and fork handling becomes another protocol to verify. Chain-at-commit holds the lock only for the insert and commit. Revisit if append p99 exceeds the budget |
| **Advisory lock plus `ORDER BY seq DESC LIMIT 1`** to find the head (keeps the runtime role INSERT-only on every audit table) | No mutable audit row at all | A lock-and-read in one statement reads a stale snapshot, and reading the head across time partitions is a slow merge-append at partition edges (backend-engineer, B4). A head row with `FOR UPDATE` locks and reads in one step. A tampered head only breaks the next link, which the verifier catches |
| **Merkle tree / transparency log** (RFC 6962 style, e.g. Trillian) | Logarithmic inclusion and consistency proofs; efficient third-party audit | A second service or a large dependency for a self-hosted product (ADR-0001 rule 3). Linear verification of one tenant's chain is cheap at our volumes (T-0026). Revisit for SaaS-scale third-party auditing |
| **One chain per installation** | Simpler in single-tenant installs | ADR-0002 requires per-tenant export and verification. A shared chain leaks tenant activity counts and cannot be handed to one tenant's auditor |
| **Per-subject crypto-shredding** for erasure (values sealed under a per-subject key; the hash covers the ciphertext) | Values never stored in clear; one record instead of two | Millions of directory subjects means millions of keys to manage and back up. Every audit read decrypts, and search by name is impossible. An offline verifier cannot check a clear value without the key, so an export either leaks keys or ships unverifiable clear text. The salted commitment gives verifiable clear values and the same erasure strength |
| **Pseudonymous form with a keyed MAC** (HMAC under a tenant key) | Exact-match search over pseudonyms | The offline verifier would need the tenant's MAC key to check a value. A per-subject random salt needs no key, and its deletion is the erasure |
| **Transient secrets in memory only** | X4 stays absolute | A password typed into a request waiting for approval, or a CSV with a password column, would be lost on restart and is unusable across SaaS nodes. A sealed row with associated data and deletion at the terminal state is the smaller risk. security-architect concurs |
| **RFC 3161 timestamping** of checkpoints | A third-party time anchor | It is outbound traffic every self-hosted install would need to allow, and the SIEM stream plus exports already anchor outside the host. Offered later as an optional sink |

## Consequences

**Positive.**
- One shape carries a single edit, a 50,000-row CSV, a workflow step, an automation policy, act-on-results, the palette, undo and every configuration change. Preview, approval, step-up, audit and undo are written once.
- A directory write outside an Action does not compile. An escaped Step is caught by O1 and dead at runtime.
- The chain format, checkpoint mechanism and erasure exist before the first audit event, so nothing needs migrating later.
- An auditor verifies an export on their own laptop with a published tool and a published format.
- The T-0006 review points (a), (b) and (c) and DM §11 Q6 and Q9 are closed.

**Negative.**
- Every write module carries the Plan/Verify/Inverse discipline. A simple settings form is an Action with a contract test.
- `directory/client`'s write API depends on a kernel type (`operation.Step`). That is a directory → kernel import, which ADR-0003 allows.
- Per-tenant serialisation caps one tenant's audited commits at the rule 11 budget: roughly 200–1,000 per second, or about 100 with a synchronous standby. That is ample for a self-hosted tenant. It is the first thing to measure for a large SaaS tenant (revisit below).
- The runtime role holds `UPDATE` on one audit table, `audit_head`. That is a deliberate exception to "INSERT only": tampering with it breaks the next link and is detected.
- The verifier says `UNANCHORED` for an install with no SIEM sink whose exports nobody pinned. That is honest, but auditors will ask, so the docs explain how to pin the fingerprint.
- The personal store doubles writes for personal attribute changes in inventory history. T-0065 sizes it.
- The transient secret table narrows X4. It is a new sealed-at-rest secret class that backups contain while a step is in flight.
- Erasure cannot recall SIEM copies or earlier exports. That is stated in the product, not hidden.
- Approvals bind to the requester's authority, so a long-pending request can fail `denied` at Apply if the requester's role changed. That is correct, but it will surprise people. The UI explains it.

**Follow-on work** (filed with this ADR; IDs on the T-0047 ticket note):
- **operation kernel** (build, backend-engineer): `platform/operation`, meaning EP-3, the Step token, the state machine, the job kinds, reconciliation, the inline Store path, the kernel holds, the default EP-4 gate with single approval, Undo, `operationtest`, and the `Registrar.Action`/`ApprovalGate` methods. It replaces the scaffold's `Action` in `internal/platform/operation/operation.go` in the same change. It goes into checkpoint 2a ahead of T-0093, T-0095, T-0096 and T-0104.
- **fitness-operation and fitness-audit** (chore, devops-engineer): O1–O8 and A1–A8 in `make ci`, each with a failing case in `tools/ci/proof.sh`.
- **architecture map** (spec, solution-architect): blueprint §4.2, §8, §9, §16 and §17; a §5.1 row for `platform/personal`; the ADR-0002 Jobs-row amendment line; the ADR-0003 amendment adding `cmd/auditverify` as a class row and a rule 7 binary row (it links only `platform/audit/chain` and the standard library); and the `config | system` column of the ownership map.
- **T-0088** (existing) builds the chain, the head row, checkpoints and key windows, export, the verifier, `platform/personal` with its erasure register, and the byte-level format document under this ADR (note filed). The SIEM stream stays with E2.10.
- **T-0084** (existing) adds the `ManagedTx` job mode and the transactional insert (note filed).
- **The restore runbook** replays the erasure register (rule 12). It is part of the E2.12 backup work (note on the architecture-map ticket).
- **T-0065** (existing) applies rule 12 to DM-18 (note filed).
- **Domain model**: DM-41 and DM-42 follow rule 3; X4, X11, DM-60.I3, DM-80, DM-81 and §11 Q6 and Q9 are updated in this change.
- **Open for the audit and compliance PRD:** the default for ADM-207 erasure, the legal-hold UX, and minimum retention.

**Revisit when:**
- per-tenant audit append p99 exceeds 50 ms under the T-0026-style load test, or a SaaS tenant exceeds about 200 audited commits per second sustained (then consider the asynchronous chainer, with a superseding ADR);
- third-party auditors ask for inclusion proofs (then consider a Merkle log);
- a provider gains native conditional writes or idempotency keys (narrow the residuals in rule 4).

## Platform matrix

| Capability | `windows` | `linux-oci` | `saas` (CI only) | Notes |
| --- | --- | --- | --- | --- |
| Operation pipeline, gate, undo | ✓ | ✓ | ✓ | One code path; the provider decides the details |
| Directory Actions: AD | ✓ embedded or remote connector | ✓ embedded or remote | ✓ on-site remote connector only | DC pin and conditional modify per rules 4–5 |
| Directory Actions: Entra | ✓ | ✓ | ✓ (cell's embedded connector) | No DC; verify window; `Retry-After` |
| Store Actions | ✓ | ✓ | ✓ | One transaction |
| Audit chain, checkpoints, retention | ✓ | ✓ | ✓ | Checkpoint key sealed under the tenant DEK; KMS-wrapped in `saas` |
| Offline verifier | Windows, Linux and macOS binaries | same | same | Runs on an auditor's machine; no product install |
| SIEM anchoring | ✓ | ✓ | ✓ | Sinks are EP-9 |

There is no asymmetry between the profiles. The only differences are which connector carries which provider, as ADR-0002 already decides.

## Fitness function

Two jobs run in `make ci`, owned by devops-engineer (follow-on ticket). Each check has a failing fixture in `tools/ci/proof.sh`, as the ci-gates standard requires.

**`fitness-operation`** (`tools/fitness/operation/`)

| # | Fails when |
| --- | --- |
| O1 | **Step escape** (`go/analysis`): a value of type `operation.Step` is stored in a field, global, map, slice or channel; is captured by a closure; or is passed to a function with no `operation.Step` parameter. Or an `operation.Step` is constructed outside `platform/operation`'s runner |
| O2 | **Write surface**: a `directory/client` exported method that issues a connector-contract write RPC lacks an `operation.Step` parameter; the generated connector-contract write client is referenced outside `directory/client`; a directory protocol or Graph client is imported outside the connector root (shared with `fitness-profiles` P3) |
| O3 | **Configuration writes**: SQL that writes a `config`-class table runs in a function with no `operation.Step` parameter, outside the rule 10 system-writer list; a table has no write class |
| O4 | **State machine**: the transition table in `transitions.go` differs from this ADR's `transitions` block; SQL that updates a state column of `operation`'s tables appears outside the transition function; a property test driving random event sequences reaches an undeclared transition |
| O5 | **Registry completeness** (the `compose/server` boot test over every module and every kernel-exported Action) fails when an Action: lacks a Descriptor field; has an `AuditKind` that is unregistered or owned by someone else; declares `Reversible` or `Lossy` while `Inverse` returns `ErrIrreversible` for a contract fixture |
| O6 | **Contract coverage**: a registered `ActionID` has no `operationtest.Contract` run in `go test ./...`. The harness writes coverage, and the check compares it with the registry |
| O7 | **Contract behaviour** (inside `operationtest.Contract`, against the fake provider and a rolled-back store) fails when: Plan writes anything (its store transaction is `READ ONLY`, and the fake directory counts writes); Apply run twice with one key changes state twice; Verify passes after the fake directory drops the write; apply → inverse → apply does not restore the before-state of a `Reversible` step; a `Lossy` step loses an undeclared field; the success, failure **and** denial events are not all emitted with their AG-3 fields (TM-F-AUDIT coverage) |
| O8 | **Pipeline behaviour** (integration, Postgres + Samba lab) fails when any of these is not as stated: a step killed after its claim is reconciled to `applied`, re-applied, `not_run` (operation cancelling) or `stale_state`, never left `applying`; a password step is never re-applied by reconciliation; a superseded attempt's late result changes nothing; a lost chunk job is re-driven by the sweeper; a target changed between Plan and Apply fails `stale_state` and is not overwritten; an object moved out of scope between Plan and Apply is refused (TM-F-AUTHZ); `client.Write` refuses an operation whose digest differs from the step's plan; an approval with a stale `plan_hash`, by the initiator, by an API token, without step-up for an `Irreversible` operation, or by a sock-puppet account, is refused; a `StepUp` Action initiated by a token is held or refused; an automation run over `max_objects` is held; a gate error leaves the operation unapproved; an expired transient secret fails its step `secret_expired`; a `Store` Action whose Apply fails or is denied still has its outcome event |

**`fitness-audit`** (`tools/fitness/audit/`; it implements TM-F-AUDIT)

| # | Fails when |
| --- | --- |
| A1 | **Catalog**: the runtime role holds `UPDATE`, `DELETE` or `TRUNCATE` on `audit_event` or `audit_checkpoint`; `UPDATE` on `personal_subject`, `personal_value` or `operation_secret`; or any privilege on `audit_head` beyond `SELECT` and `UPDATE` (this extends `fitness-tenancy` T3) |
| A2 | **AG-1 and AG-2**: an event appended in a rolled-back transaction exists; a `Store` Action's state change commits without its event; a `Store` Action that fails or is denied leaves no outcome event; the chain hook accepts a non-`READ COMMITTED` transaction |
| A3 | **Concurrency**: 32 concurrent appenders in one tenant leave a `seq` gap or a broken link; two tenants appending concurrently interleave in one chain |
| A4 | **Seeded-tenant verification**: after the lab seed (operations, sign-ins, setting changes, a key rotation, an erasure and a purge) is exported, `adq-audit-verify` with the pinned fingerprint does not return `OK` |
| A5 | **Tamper corpus**: the verifier does not fail at the right `seq` with the right reason after any of these: an event edited, deleted, reordered or inserted; an event spliced from another tenant; a personal side value altered; side values deleted with no erasure event, or with a forged erasure event that references no erase step or trigger; a checkpoint signed by a retired key; **the whole chain rebuilt and re-signed under a fresh key**. That last case, run with no trust root, must return `UNANCHORED`, and with the pinned fingerprint it must fail |
| A6 | **Anchoring**: a checkpoint or key event is missing from the fake SIEM sink's stream or from the export; a history rewritten before an anchored checkpoint verifies against the anchors; seven days with no anchor raises no alert |
| A7 | **Classification**: an audit detail type has a string field tagged neither `personal` nor `public`; a detail type contains a `secret.Secret` (AG-9); a `personal`-tagged field reaches the canonical form as anything but a `PersonalRef` |
| A8 | **AG-8 coverage**: an audit read, export, retention change or SIEM-sink change emits no event; an export, retention change or sink change succeeds without step-up |

**What CI cannot check, and who checks it.**
- Whether an Action's Plan reads *enough* to make its diff honest. code-reviewer checks this against the Action's spec, and the lab conformance suite exercises it.
- Whether the residual windows in rules 4 and 7, and the `pwdLastSet` reconciliation, behave as stated on Windows DCs. T-0051 measures them, and security-architect reviews.

## Consultation

**security-architect** reviewed the audit guarantees, erasure, the transient secrets, the Step token and separation of duties on 2026-10-02. Verdict: **concur with conditions**. All conditions are applied in this text:

| # | Finding | Disposition |
| --- | --- | --- |
| S1 | A `Store` Action's failure or denial rolled back with its event | Rule 6: the outcome is recorded in a fresh transaction after the rollback, as `denied` for a refusal; A2, O8 |
| S2 | The genesis is public, so an export re-signed end to end verified | Rule 11: the verifier needs a pinned fingerprint or an anchor, and otherwise reports `UNANCHORED`; A5 |
| S3 | AG-6 depends on a sink existing | Rule 11: an alert after 7 days with no anchor; A6 |
| S4 | AG-1 wording; A8 vs §7.4 on reads; A1 must cover the new tables; hook must enforce the isolation level; gate must fail closed | AG-1 and AG-8 amended in threat-model §11 in this change; A1, A2 extended; rule 11 hook check; rule 8 fail-closed |
| S5 | Transient secrets: TM-D7 seal; own TTL; remote connector transit; deletion points; password reconciliation | Rule 9 (a–d) and rule 6 (e); TM-D8 amended in this change; `pwdLastSet` is `[LAB: Windows]` for ad-expert in T-0051 |
| S7 | Ambiguous `field ‖ value` boundaries in the commitment | Rule 12: HMAC-SHA-256 keyed by the salt, over `adq-canon/1` |
| S8 | Pseudonymous exports must omit salts; backups; wording; logs; forged erasure | Rule 12: all applied, including the erasure register outside the database |
| S9 | Key validity windows; rotation after compromise | Rule 11: chained created and retired events; no cross-signature after a compromise |
| S10 | The Step authorised *a* write, not *this* write; the re-check sat in Action code; StepUp for tokens; who may approve | Rule 2 plan digest; rules 2 and 7 move the checks into the pipeline; rule 8 approvers and StepUp hold |
| S11 | Sock-puppet approver created by the initiator | Rule 8: a 30-day refusal plus an alert |

**backend-engineer** reviewed the job wrapper, chunking, recovery and chain-at-commit on 2026-10-02. Verdict: **concur with conditions**. All conditions are applied:

| # | Finding | Disposition |
| --- | --- | --- |
| B1 | ADR-0002's Jobs row puts the whole body in one transaction | Rule 6: a `ManagedTx` mode; ADR-0002 Jobs row amended on ratification; note on T-0084 |
| B2 | Chunk-wide claims lapse, so the reconciler races live workers | Rule 6: claim only what runs now, with a DB-clock lease, an attempt fence on every record, and takeover by compare-and-set; `plan_revision` predicate |
| B3 | River job timeouts; the unique key is not a correctness tool | Rule 6: per-kind timeouts; the key is de-duplication only; transactional enqueue |
| B4 | Lock-then-read must be separate statements; head row preferred; throughput budget | Rule 11: `audit_head … FOR UPDATE` as its own statement, `lock_timeout`, no nesting, budget stated |
| B5 | Lost or discarded jobs stall operations; cancel during reconciliation; deferred verify has no driver; terminal detection | Rule 6: the sweeper re-drives; `applying → not_run`; `operation.verify`; last-item terminal transition |
| B6 | `Store` Plan I/O inside the transaction; event volume on the inline path; held `Store` steps | Rule 6: I/O before the transaction, with a version and hash re-check inside it; rule 11 emits one event inline; held steps run as one `operation.apply` |


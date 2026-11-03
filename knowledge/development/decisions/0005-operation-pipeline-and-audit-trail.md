---
title: "ADR-0005: Every write is an Action run by one operation pipeline (plan, gate, apply, verify, undo); a step token is the only key to a write; our audit trail is a per-tenant hash chain, chained at commit, with signed and externally anchored checkpoints and erasable personal values"
date: 2026-10-02
updated: 2026-11-01
status: ratified
owner: heramb
kind: technical
ticket: T-0047
fitness: fitness-operation, fitness-audit
decision: D-0015, D-0019
ratified_on: 2026-10-02
ratified_by: factory-director
---

# ADR-0005: Every write is an Action run by one operation pipeline; a step token is the only key to a write; our audit trail is a per-tenant hash chain with signed, anchored checkpoints and erasable personal values

**Status:** ratified 2026-10-02 by factory-director at the T-0047 review (rework 1; dispositions in § Review rework), notice D-0015. It becomes `accepted` when `fitness-operation` (O1–O9) and `fitness-audit` (A1–A9) run green in `make ci` on `main`.
**Kind:** technical. The customer-visible results (preview before every change, undo from the audit record, a tamper-evident audit trail, "anonymize on deletion") were decided by the CEO in D-0004 (ENH-04) and by the scope lock. This ADR decides how they are built.
**Deciders:** solution-architect (author). Consulted on 2026-10-02, both concurring with conditions that this text applies (§ Consultation): security-architect on the audit guarantees, erasure, transient secrets and separation of duties; backend-engineer on the job wrapper, chunking, recovery and the commit-time chain. factory-director ratifies. **Ticket:** T-0047. **Parity / scope refs:** ADM-005, ADM-033, ADM-034, ADM-098, ADM-137, ADM-138, ADM-207; ENH-04.

> Amendments (ratified ADRs only):
> - 2026-11-01 · solution-architect · T-1221 · **Rule 10 and O3: a checkable rule for configuration writers, the system-writer allow-list as data, and the class test.** (1) The Step sits at the package boundary. A SQL write to a `config` table needs a guarded root, which is one of three things. It can be an exported function that takes a `step.Step` and writes only in its `Tx()`. It can be an unexported helper called only from guarded functions of its package. Or it can be a `system` row of `tools/fitness/operation/o3-writers.json`, with named `callers` and a closure over the owning package's exported wrappers. Two alternatives were rejected: threading the Step into every SQL function, and whole-program reachability (rule 10, "The O3 rule", gives the reasons). (2) The allow-list is JSON data. It has 25 `system` rows, and adding one is an amendment. It also has 31 `convert` rows, which are pending baseline entries naming T-1228 to T-1232 and T-1246. A `convert` row may stand in a `system` row's `callers` until its ticket deletes it. Every one of the 61 current write sites is classified in rule 10. (3) The system list gains the host-local `init-local` CLI (item 2), connection verification bookkeeping (item 4), the takeover attestation callback (item 9) and the v1 end-user enrolment page (item 10). Items 9 and 10 are stated to widen, with the bounds that make them acceptable, and item 1 is narrowed to the first factor. Item 3 excludes token issue. (4) **The class test** is stated: a table is `config` when the product makes a widening decision to it, from any surface. The no-Step widening writes are a closed set (items 2, 9 and 10). The numbered items are instances of the test, not exceptions to it. Re-running the borderline tables corrects `personal_hold`, `authn_authority_approvals` (migrations 0049, 0048), `correlations` (0006), `enrollment_tokens` (0007), `authn_authenticator_enrollments` (0016) and `authn_webauthn_credentials` (0047) to `config`, and confirms `inventory_servers`, `tier0_designations` and the item 5 approval decisions. `make gen-modules` was run after each correction. Rule 2's configuration-writes bullet and the O3 row are updated to match. There are no state, edge or package changes, so O4 and O9 are unaffected. The check lands in T-0391. Director review rework, same day: the class criterion was restated as a test, item 9 and its row were corrected (the callback also clears `demoted_at`), the dead wrappers were listed as callers, and `SetState`'s callers were aligned. Second review, same day: the own-credential exemption was narrowed to item 1's first factor, so any later own factor add or replace, or own password change, is widening. The test was made surface-independent, with a closed set of no-Step widening writes. Item 10 was added for the end-user enrolment page. Item 9 now states its binding (one unexpired attempt consumed by `state`, and `tid` equal to `directory_identity`). The two factor-credential tables moved to `config`. Third review, same day: a widening decision is defined by a value nobody read or derived, chosen by a principal, an anonymous caller, a host operator or a component, so a write from a surface with no principal is covered, and items 1 to 10 are re-read against it. Adding a caller or a row to a widening category (`bootstrap`, `attestation`, `enduser-enrolment`) is an amendment reviewed by security-architect, checked by O3 against the new `o3-widening` block. Item 1 covers a console account's first factor only and is never item 10; its rationale is restated as trust on first use, with TM-TB1-T13's residual and an audit event and notice. No table changes class. **Ratified 2026-11-01 by factory-director at the fourth T-1221 review, notice D-0019.**
> - 2026-10-30 · solution-architect · T-0892 · **Rule 10, how a configuration undo is planned.** A Store Action's inverse is its family's `<owner>.<noun>.restore` Action. It is planned for the principal undoing, with the checks of each transition it makes, so undo never lifts a check that the forward change passed. It is refused as `superseded` when the row moved past the version the operation wrote. The HTTP surface (preview twins, `ActiveDIQ-Operation-Id`, family undo pair) is ADR-0004 rule 14. No state, edge or package changes; O8 gains the superseded and transition-check cases through T-0977.
> - 2026-10-02 · solution-architect · T-0209 · **The job queue is `platform/jobs`' own table, not River** (ADR-0001 E3, ADR-0002 amendment of the same date). Rule 6's contract with the job wrapper is unchanged: tenant-carrying kinds, `ManagedTx`, transactional insert, per-kind timeouts, unique keys for de-duplication only. It is now met natively: enqueue is an `INSERT` in the caller's `store.Tx`, so `approved → queued` and the chunk jobs commit together. Two clarifications follow from owning the queue. (1) A `ManagedTx` job renews its job claim while its body runs, so the rescuer does not re-queue a live job. A duplicate driver would still be harmless, because each step's fenced claim (this rule) is what guards a directory write. (2) A discarded job is one that used all its attempts. The cleaner deletes finished jobs after a retention period. Changes: Context's ADR-0001 bullet; rule 6 "Stalled operations" and "Chunks"; the event-sourcing row in Alternatives; consultation row B3. No rule or fitness check changes.
> - 2026-10-22 · solution-architect · T-0129 · **Verify re-runs the `tier0` guard after every write; reason `tier0_after_write` and a `critical` security alert** (threat model §6.2 TM-D23 rule 11 and TM-R17; [connector contract](../architecture/connector-contract.md) v1.2 §8.1 step 9, R-T0RACE-1, D28, D30). Rule 7 gains the bullet "Tier-0 after the write" and fixes the severity of the two Verify alerts (`scope_changed` `high`, `tier0_after_write` `critical`). Rule 3's `applied -> verify_failed` comment names the new cause, and "What undo inverts" states that an undo of such a step is refused by the `tier0` guard (the item stays `failed`). The server's Tier-0 re-read follows rule 5's verify window and DC fallback: only a fact still `unknown` after both counts as `tier0`, while the connector's step-9 report (empty basis included) counts at once, so `dc_unavailable` stays reachable for a lost pin whose Tier-0 facts were read clean on a fallback DC. An Entra step whose verify window elapses is `read_back_mismatch`. O8 gains the TM-F-T0GUARD rule 11 cases and both sides of the `dc_unavailable` split. DM-42 gains I5 (the closed list of `verify_failed` reasons). No state, edge or package changes, so O4 and O9 are unaffected.
> - 2026-10-24 · solution-architect · T-0310 · **Rule 11 now describes routine rotation as built, and states the limit of the nested-`WithTenantTx` refusal** (T-0229 security review). (1) The old key cross-signs the chained `audit.checkpoint_key.created` event of its successor. It does not co-sign the first checkpoint under the new key. The text gives the signed statement and the verifier's conditions, because auditors and third-party verifiers read this rule as the format spec. The trust is the same. A5 already covers forged, late and second vouches (`internal/platform/audit/chain/verify_test.go`). (2) The nested refusal recognises a context marker, so a body that calls `WithTenant` with a context not derived from the one it was given is not caught. This is recorded as an accepted residual: atomicity between the two transactions is lost, the chain is not broken. An analyzer is filed (T-0334). No fitness check changes.
> - 2026-10-26 · backend-engineer (code-review finding, T-0361) · **`store.DB.WithTenantSeparate`: one sanctioned second transaction, for `platform/authn`'s TOTP failure budget** (ENH-09 §5, DM-37). Rule 11's nested refusal stands for `WithTenant`. A refused code must count even when its caller rolls back, so a refusal is charged in its own short, separately committed transaction. `WithTenantSeparate(ctx, tenant, lockWait, fn)` is allowed on the context of a running transaction, sets `lock_timeout = lockWait` itself (1 ms to 10 s, a bound parameter), and fails closed on error. **Misuse is caught** by `nestedtx` (FF-SP2), which reports any call or interface method named `WithTenantSeparate` outside `internal/platform/authn` and `internal/platform/store`. Residuals: (a) the caller must not hold the enrolment row, or the refusal waits `lockWait` and the check fails closed (a refusal, not a hang); (b) the app role can still `INSERT`/`UPDATE` its own tenant's rows, so migration 0015's triggers (refund binding: 0017) carry the guarantee: `paused_until` can only be set or extended, `confirm_attempts` and `last_used_step` only increase, and `authn_totp_failures` rows younger than 90 minutes cannot be deleted (older rows are pruned by the app at two hours). A role that is not the runtime role is outside this threat model (ADR-0002).
> - 2026-10-26 · backend-engineer (security review, T-0361) · **Amendment to the above.** (1) **Charge before evaluate.** `authn.check` books the attempt through `WithTenantSeparate` under the enrolment row lock *before* looking at the code (a refusal for paused, expired or over budget is returned unevaluated); in-flight attempts count, so evaluations per enrolment never exceed 10 an hour (5 per pending enrolment) however many requests race. A success sets its row `succeeded` in the caller's transaction (migration 0015 trigger: only false→true; migration 0017 (T-0389) binds it to a real spend: the spend UPDATE records the refunded attempt in `refund_attempt`, the enrolment guard lets that column change only when `last_used_step` strictly increases, and the failures guard requires `refund_attempt` = the row refunded, in the transaction that wrote the enrolment row. Merely touching the enrolment row no longer unlocks a refund; the app role can mint at most one refund per strictly increasing step, and steps run ahead of real time); a rolled-back success stays charged. (2) **The separate transaction uses its own pool** (`Config.SeparateMaxConns`, default 4; `SeparateAcquireTimeout`, default 5 s), never the main pool, so refusals that each hold a main connection cannot form a circular wait; a full dedicated pool fails the attempt closed after the timeout. (3) **Clocks.** Failure windows, pauses and expiry checks use the app node's clock (the window has no upper bound, so a fast node cannot hide another node's rows); the database clamps `expires_at` to its own `now() + 10 minutes` on insert. Residual: skew between nodes of more than a few seconds shifts a window edge by that much; node clocks are expected to be NTP-synced. (4) Residual: a paused correct code racing an in-flight tenth attempt is refused (the pause is never cleared).
> - 2026-10-28 · solution-architect · T-0515 · **Amendment to rule 11: a legal hold suspends the purge (decision, option a).** A retention purge never deletes an event that references a held subject, nor that subject's values or salt. The purge range is a prefix of the chain (ends at a partition-boundary checkpoint), so the purge **stops before the oldest partition containing an event that references a held subject**, and keeps every later partition too. The run deletes nothing from the blocked partition on (no events, no values), appends `audit.retention.held` (blocking partition, count of held subjects, no names) and alerts `tenant-owner` accounts; `PurgeResult` reports `blocked_by_hold`. Releasing the hold lets the next run proceed. The check runs in the purge's own maintenance transaction, after taking the tenant's hold lock exclusively (T-0587: holds live in `personal_hold`, not on the salt row; `SetHold` takes the same lock shared), so a hold set during a purge either is seen or commits after it, whether or not the subject has a salt row. An event references a held subject also through its actor chain: a human `Requester`/`Via` account (`acct:<id>`) counts. Residual: a hold set after a partition was purged cannot recover it; the hold UX shows the oldest retained `seq` and says so. Rejected: (b) values kept but events deleted (the evidence is the event), (c) export-before-purge (the archive is not a preservation copy that legal can rely on, and `purge_without_archive` removes even that). Notice logged. Follow-up: T-0576.
> - 2026-10-28 · backend-engineer · T-0576 · **Legal hold suspends the purge, as built.** `Purger.Purge` takes all the tenant's subject rows `FOR SHARE` (not only held ones: a pending `UPDATE … SET hold` blocks it, and the flag is read after the lock; test with a second open transaction), finds the oldest partition (up to the boundary) with an event referencing a held subject (value-ref subjects, or the targeted directory object), re-selects the boundary before it, and appends `audit.retention.held` (`held_subjects`, `oldest_retained_seq`, `partition_start`). `PurgeResult.BlockedByHold` is set; with nothing earlier to purge the run returns it with no error. `Purger.WithHoldAlerter` takes the tenant-owner alert port (not yet wired: the purge has no product caller). `Event.Validate` refuses an event targeting a directory object whose non-secret change values carry no `Subject`. Inventory-history skipping (T-0065) has no code yet.
> - 2026-10-28 · backend-engineer · T-0372 · **Rule 11 purge deletes personal values (A9).** `Purger.Purge` reads the `value_id`s from the envelopes it is about to delete (changes' before/after and snapshots) and calls `personal.Store.PurgeValues` in the same maintenance transaction: it deletes those `personal_value` rows, then the `personal_subject` salt of each affected subject left with no value and no `hold`. `PurgeResult` reports both counts. The `purge_without_archive` setting with step-up, archive-export recording and the scheduled retention job remain open (follow-up tickets).
> - 2026-10-26 · backend-engineer · T-0305 · **Rule 11 retention and key retirement as built.** (1) A *time partition* is a UTC calendar month, a `seq` range of the one `audit_event` table, not a native PostgreSQL partition; `Checkpointer.Sign` first signs the last event of every ended partition (`SignBoundaries`), then the head. A partition that ended across a rotation, with its last event before the current key's introduction, is not signed and is not purgeable. (2) `audit.Purger` runs on a `store.OpenMaintenance` store (owner role; it refuses a superuser or BYPASSRLS role) and deletes only up to the newest checkpoint that sits on the last event of a partition ended by the cutoff, then chains `audit.retention.purged` in the same transaction. It needs an archive digest or the caller's `purge_without_archive`; the setting and the personal-value deletion (rule 11, A9) are not built here. (3) The export manifest lists keys whose introduction was purged from windows (`k.<key_id>.created|retired|pub`) that the purge event carries forward. (4) A retired checkpoint key's `sealed_private_key` is emptied by `public.audit_wipe_retired_key(text)`, the one SECURITY DEFINER function of the audit tables (migration 0015, registered in the tenancy exemption registry); the runtime role still has no `UPDATE`. `Rotate` calls it after the rotation commits, `WipeRetiredKeys` repeats it. (5) A2's non-`READ COMMITTED` clause is tested at `REPEATABLE READ` and `SERIALIZABLE`: the hook refuses with `ErrIsolation`, the transaction rolls back and the chain stays gapless.
> - 2026-10-27 · backend-engineer · T-0357 · **Rule 12 `platform/personal` core as built (migration 0040).** `Put(tx, tenant, subject, record_kind, field, value)` runs in the caller's own transaction (the audit commit hook), creates the subject salt on first use and returns a `Ref`; `Ref.Canonical()` is the adq-canon/1 form a record hashes and holds the commitment, never the value or salt, so erasure leaves every hash unchanged. `Resolve` returns `"[erased]"` for a value whose rows are gone and `ErrTampered` if the stored value fails its commitment. `Erase` takes a `step.Step`, refuses a held subject (`ErrHeld`) and deletes values then salt. Both tables are RLS tenant tables the runtime role cannot UPDATE (`SELECT ... FOR UPDATE` is therefore not used; the hold is only ever set by the owner role until the compliance PRD defines the hold UX). Not yet built: `PurgeValues`, the erasure register in `blob`, `personal/actions`, `personal/erasure`.
> - 2026-11-01 · backend-engineer · T-1160 · **Rule 13 dag: `authn/throttlejob` added (no edge change for `authn`).** The `authn.throttle.purge` job registered on `platform/jobs` from inside `authn` (T-0868), an edge `authn -> jobs` the dag does not allow. The job moved to a subpackage above both `authn` and `jobs`, the same placement as `<pkg>/actions` and `personal/erasure`; `authn` keeps only the SQL (`LocalCredentials.PurgeThrottle`). `compose/server` registers it. The row is `authn/throttlejob -> authn, jobs, store, tenant`.

## Context

**What this ADR makes binding.** The [blueprint](../architecture/blueprint.md) sketches one write path (§4.2, §8, §14 flow 2) and an audit pipeline (§9). It leaves the hard parts here (§16):
- the Action contract and its reversibility classes;
- the operation and item state machines (domain model DM-41/42 carry provisional names and say "this file follows T-0047", §11 Q6);
- idempotency, DC affinity, chunking, checkpoint and resume;
- re-checking authorisation against the live directory (ancestry, membership and correlation, per scope root kind);
- the approval-gate extension point (EP-4);
- the mechanics behind the threat model's audit guarantees AG-1…AG-9 ([threat model §11](../architecture/threat-model.md));
- how personal values in append-only records become erasable (domain model X11, §11 Q9);
- whether configuration writes are Actions (m2-plan §2 decision 7).

**Why now.** No write may ship before this is fixed. The first audit event, written by T-0088 for sign-in, already needs the chain format and the erasure mechanism: a chain hashed over clear names cannot be made erasable later (X11). Four checkpoint 2a tickets (T-0093, T-0095, T-0096, T-0104) wait on the configuration-write ruling.

**Constraints already decided.**
- ADR-0001: Go, cgo-free; PostgreSQL is the only stateful service; jobs run on `platform/jobs`' own `SKIP LOCKED` table (ADR-0001 E3, ADR-0002 Jobs row). Everything below uses the Go standard library for crypto (`crypto/sha256`, `crypto/ed25519`, `crypto/hmac`). No dependency is added, so the licence register is unchanged.
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

We will route **every write a principal makes** (to a directory or to activeDIQ's own configuration) through **one operation pipeline: Plan → gate → Apply → Verify → audit, with Undo as a new operation**. A **step token**, minted only by the pipeline, is the only key that opens a write. Our audit trail is **one hash chain per tenant, chained at commit**, with **signed checkpoints anchored outside the host**, and **personal values held outside the hashed form** so they can be erased. Thirteen rules follow; rule 13 places every type in a package so the write APIs compile without import cycles. On ratification it amends ADR-0002's Jobs row (rule 6), and it has amended threat-model AG-1, AG-8 and TM-D8 (§ Consultation).

### Rule 1: The Action contract (EP-3)

```go
// internal/platform/operation (replaces the scaffold's Action in operation.go). Package placement: rule 13.
type Action interface {
    Describe() Descriptor
    // Plan is the dry run: live reads through PlanContext, the diff, preconditions, reversibility.
    // It cannot write: PlanContext has no write method and its database transaction is READ ONLY.
    Plan(ctx context.Context, pc PlanContext, in Input) ([]StepPlan, error)
    // Apply performs one planned step. The step.Step is the only key to a write (rule 2).
    Apply(ctx context.Context, s step.Step, p StepPlan) (Outcome, error)
    // Verify compares the read-back with the plan's after-state.
    Verify(ctx context.Context, s step.Step, p StepPlan, o Outcome) (Verdict, error)
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
- **How Actions are registered.** Modules call `Registrar.Action(a)`. A kernel package never exports its own Actions, because `operation` imports it (rule 13). Its Actions live in a subpackage above both, `internal/platform/<pkg>/actions` (`authz/actions.All()`, `authn/actions.All()`, `notify/actions.All()`, `audit/actions.All()`, `personal/actions.All()`), and `compose/server` hands them to the operation host, as ADR-0003 rule 5 already allows for datasets. Directory packages export theirs the same way. `Boot` refuses an Action whose ID is not namespaced by its owner, whose `AuditKind` is not registered by the same owner, or whose `Permission` is not in the EP-6 catalogue.
- **The read-only catalogue.** `operation.Catalogue()` lists registered Descriptors for `search` and the command palette (ADR-0003 F4).

### Rule 2: A step token is the only key to a write, and it opens only the planned write

```go
// internal/platform/operation/step: a leaf below every write API (rule 13).
// Step is minted only by the operation runner, for one claimed step, and dies when Apply or Verify returns.
type Step struct{ s *state }        // unexported field; the zero value is refused everywhere

func (s Step) Key() Key                          // (operation, item, step)
func (s Step) Attempt() int                      // the fencing number (rule 6)
func (s Step) Operation() OperationID
func (s Step) Actor() authority.Chain            // the initiator chain, never the approver's authority (rule 7)
func (s Step) DC(nc authority.NamingContextID) DCRef // the pin (rule 5); none for Entra
func (s Step) Tx() store.Tx                      // Store Actions only: the recording transaction
func (s Step) FactsQuery() authority.FactsQuery  // what the Apply-time re-check must read live (rule 7)
// Recheck runs the runner's authorisation check, installed at mint, on facts read live
// immediately before the write. It returns the only value that lets a write be sent.
func (s Step) Recheck(ctx context.Context, f authority.Facts) (Clearance, error)
```

- **A Clearance is as narrow as its Step.** It is bound to the step's key and plan digest. The send path checks both again when the RPC goes out, and a Clearance dies when its Step is revoked. A Clearance replayed for another step or operation is refused.
- **Minting.** `step` has one minter. `step.TakeMinter()` returns it to the first caller only, and `operation`'s runner takes it during package initialisation. `compose/server`'s boot asserts that `operation` holds it, so a second taker fails start-up, and O1 refuses any reference to `TakeMinter` outside `platform/operation`.
- **Directory writes.** Every write method of `directory/client` takes a `step.Step`: `client.Write(ctx, s, op)`. It reads the facts `s.FactsQuery()` names on the pinned DC, calls `s.Recheck`, and sends only with the returned `Clearance`. The connector contract's `Apply` RPC carries the step's idempotency key, attempt, operation ID, acting principal, DC pin and **plan digest**. The connector logs all of them (TM-TB6-T5). Named secret reads (LAPS, BitLocker) are reads with their own audit kind (safe-primitives §3.7) and take no Step. A LAPS *reset* is a write, so it is an Action.
- **A Step authorises this write, not just any write.** `stepState` carries a digest of the step's planned target and operation (target GUID, operation kind, attributes and values; secret values are excluded, but the presence of a secret is included).
  - `client.Write` recomputes the digest of the operation it is handed and refuses a mismatch. The connector checks it again.
  - An Action cannot use its Step to write to a different object or attribute than the one that was previewed, approved and hashed.
- **The checks live in the pipeline, not in Action code.** `client.Write` (Directory) and the runner (Store) perform the Apply-time authorisation re-check (rule 7) before the write. An Action's Apply cannot skip it, and `client.Write` cannot either: the connector-contract write RPC is reachable only through a function that takes a `step.Clearance` (O2).
- **Configuration writes.** The exported write functions of a table classed `config` (rule 10) take a `step.Step` and use `Step.Tx()`. Unexported helpers below them may take the `store.Tx`, as long as only those functions call them. The exceptions are the rule 10 system writers, named in the fitness configuration (rule 10, "The O3 rule"). Because `step` is a leaf, `authz`, `authn`, `notify`, `audit` and `personal` can take it without importing `operation` (rule 13).
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
planning          -> planned            plan recorded with plan_hash; at least one item planned
planning          -> no_change          every item skipped (empty diff); nothing blocked, nothing to apply
planning          -> plan_failed        input invalid, capability missing, Action permission refused, or no item planned and at least one blocked
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
failed            -> undone             an undo operation verified the inverse of every verified or verify_failed step, except a tier0_after_write step, whose inverse is blocked: that item stays failed (the undo is partially_succeeded or plan_failed)
# Step (DM-42 steps[])
planned           -> applying           claimed: key bound, attempt recorded, DC pinned; committed before the write
planned           -> not_run            an earlier step did not succeed, or the operation was cancelled
applying          -> applied            Apply returned, or reconciliation found the planned after-state
applying          -> failed             denied at the re-check, stale_state, outcome_unknown, permanent error, or retries exhausted
applying          -> not_run            reconciler only: the operation is cancelling and the before-state shows no write happened
applied           -> verified           read-back matches the plan's after-state
applied           -> verify_failed      read-back differs, scope changed, a touched object is tier0 after the write, or the verify window elapsed
verified          -> undone             the undo operation's inverse step verified
verify_failed     -> undone             the undo operation's inverse step verified, planned against the live state
```

- **Terminal states.** Operation: `no_change`, `plan_failed`, `rejected`, `succeeded`, `partially_succeeded`, `failed`, `cancelled`. Item: `skipped`, `blocked`, `succeeded`, `failed`, `cancelled`, `undone`. Step: `not_run`, `failed`, `verify_failed`, `verified`, `undone`. Nothing leaves a terminal state except the explicit `→ undone` rows, which an Undo operation drives.
- **Partial success is never success** (DM-41.I2). A blocked item makes the result at best `partially_succeeded`. `cancelled` reports counts of applied, verified and not-run steps.
- **Nothing to change is a success, not a failure.** Re-running a CSV, or a daily automation that finds every target already in its desired state, plans only `skipped` items. The operation goes `planning → no_change`: it passes no gate, claims nothing, raises no failure event and no alert, and writes one `operation.completed` event with result `no_change` and its counts (rule 11). If any item is `blocked` and none is `planned`, the outcome is `plan_failed`, because a refusal must be seen. The completed event's audit outcome is `denied` (reason `tier0` or `denied`, first refused target) when every blocked item was refused by authorisation, and `failure` (reason `plan_failed`) when any block is technical (`facts_unavailable`, `no_pin`) (T-0477).
- **What undo inverts.** A `failed` step never changed its target, with one exception. `denied` and `stale_state` are decided before the write. A permanent LDAP error means the atomic modify did not happen (RFC 4511 §4.6). `retries_exhausted` is recorded only after a read on the pin shows the before-state (rule 6); a step whose state cannot be read stays `applying` for the reconciler. The exception is `outcome_unknown`, which only a password step can reach, and a password step is `Irreversible`. An undo therefore inverts the `verified` and `verify_failed` steps. Because Undo is a new operation planned against the live state, an inverse whose before-state is already back in place plans as `skipped`. **Exception: a `verify_failed` step with reason `tier0_after_write` cannot be undone by activeDIQ.** Its target, or another object it touched, is now `tier0`, so the undo's inverse step is `blocked` at Plan by the `tier0` guard like any other write to a `tier0` object (rule 7, TM-D2), and no gate or override lifts that. Recovery is an administrator's task outside activeDIQ, which the rule 7 alert hands over.
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

- **Plan pins one writable DC per AD naming context the operation reads or writes** for the whole operation. That includes a naming context read only for authorisation, such as the correlated AD object's domain for an Entra Action authorised through `include_correlated`, or an AD `group_members` root in another domain (rule 7). It prefers the connector's site and a healthy DC, and records the pins in the plan. Plan reads, the Apply re-check, the write and Verify all go to the pinned DC, which gives read-your-writes (FEAS §1.1).
- **Pins are not part of `plan_hash`** (rule 9). An approver approves what changes, not which DC carries it. A re-plan keeps each previous pin while that DC is healthy, and only otherwise picks a new one. Either way the before-state is re-read on the pin, so a re-plan on a different DC that reads the same before-state yields the same hash and keeps its approvals. A different before-state changes the diff, and so the hash, and goes back to the approver as it should.
- **If the pinned DC is lost mid-operation:**
  - Steps not yet claimed are re-pinned to another DC only after their preconditions are re-read there. Items whose before-state differs on the new DC fail `stale_state`.
  - Steps that are `applied` but not verified keep retrying Verify on the pinned DC within the verify window. After that, they read back, and re-read the Tier-0 facts (rule 7), from another DC and are recorded `verified` with that DC named, or `verify_failed` with reason `dc_unavailable` when the Tier-0 facts were read clean but the read-back could not be completed. Tier-0 facts unreadable on every DC make the step `tier0_after_write` instead (rule 7, fail closed).
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
- **Chunks** default to 100 items, adjustable per provider. A chunk job's unique key, `(operation, plan_revision, phase, chunk_no)`, is a **de-duplication optimisation only**. Correctness never depends on it, because job records are cleaned up after completion. It comes from the fenced claims below. Each job kind's timeout is set above its chunk's worst case and is required when the kind is registered. A `ManagedTx` body's job claim is renewed while it runs. A timeout mid-call is recovered by reconciliation.
- **Fenced claims.** A step is claimed **only when it is about to run**, meaning a concurrency slot (rule 5) is free:
  - The claim is `planned → applying` with `FOR UPDATE SKIP LOCKED`, a new `attempt` number and `claimed_until = now() + lease`. `now()` is the database clock.
  - The runner renews `claimed_until` while the call is in flight.
  - Every recording `UPDATE` is predicated on `state = 'applying' AND attempt = $n`. A late result from a superseded attempt changes nothing.
  - The reconciler takes over a lapsed claim by compare-and-set, which bumps `attempt`.
  - Plan-chunk results are predicated on `plan_revision`, so they cannot land after a re-plan or cancel.
- **The life of a directory step:**
  1. **Claim** (transaction 1). The `operation.started` event was written at `queued → running`. The claim commits before the write. **These commits are the write-ahead record.**
  2. **Re-check, then write** (no recording transaction is open). `client.Write` verifies the plan digest (rule 2), reads the scope facts the step names live on the pins (rule 7), calls `Step.Recheck`, and sends the conditional write with the returned clearance. The embedded connector unseals its credential inside its own short `WithTenantTx`, as ADR-0002 requires. A remote connector uses its local credential (TM-D8).
  3. **Record** (transaction 2). The step moves `applying → applied → verified | verify_failed`, or `applying → failed`. Its audit events are written **in the same transaction**. Several steps of one chunk may be recorded together, which amortises the chain lock (rule 11). When Verify needs more time, `applied` commits with its event, and `operation.verify` commits `verified` later with its own event.
- **Transient errors** (connector unreachable, DC busy, `429`) keep the step in `applying` and retry with the **same key** and a new attempt number. Retries back off and honour `Retry-After`. After the attempt limit, the runner reads the target on the pin, as the reconciler would: the after-state in place is `applied`, the before-state in place is `failed` with reason `retries_exhausted`, and a target it cannot read leaves the step `applying` for the reconciler. So a `failed` step never hides a write (rule 3).
- **Crash recovery.** A step still `applying` after `claimed_until` is reconciled. The reconciler reads the live state on the pinned DC:
  - the after-state is in place → `applied`, with `recovered: true` on the event;
  - the before-state is still in place → re-apply with the same key, or `not_run` if the operation is `cancelling`;
  - anything else → `failed` with reason `stale_state`.
  - **A password step is never re-applied** by reconciliation: a repeat would be refused by password history and would record a false failure. It is `applied` if `pwdLastSet` is later than the claim, and otherwise `failed` with reason `outcome_unknown`. The technician then retries as a new operation. That `pwdLastSet` is set by every successful reset is `[LAB: Windows]` (ad-expert, T-0051).
  No step is ever left `applying` silently.
- **Stalled operations.** `platform/jobs` discards a job after its last attempt, and its cleaner deletes finished jobs after their retention period. So `operation.sweep` re-enqueues the work for any operation that is `planning`, `queued`, `running` or `approved` and still has unclaimed work but no progress within the stall window. The unique key makes a duplicate harmless.
- **Terminal detection.** The recording transaction that moves an operation's last non-terminal item locks the operation row and runs the operation's terminal transition. `operation.sweep` is the backstop.
- **`Store` Actions: one transaction, after any I/O.**
  - **Plan first.** Plan runs before the transaction. This includes any I/O, such as a connection test, an SMTP test send or an LDAP bind for verification.
  - **Then one transaction holds everything.** Inside the single transaction the runner:
    1. checks that the definition version (X7) or the row's version still matches the plan, and that `plan_hash` is unchanged;
    2. runs the gate;
    3. re-checks authorisation;
    4. runs Apply and Verify, with the state changes and the audit event.
  - **If anything fails, the outcome is still recorded.** When that transaction rolls back (Apply or Verify error, or a refusal at the re-check), the runner records the outcome and its event in **a fresh transaction**: `failed`, or `denied` for a refusal. A failure or denial is never lost with the rollback (AG-2).
  - **If the fresh transaction cannot take the chain lock either.** It runs with a longer `lock_timeout` than the business path (the head lock is held only for inserts and commit, so contention clears in milliseconds). On `lock_timeout`, serialisation or connection failure it retries with jittered backoff, up to 5 attempts within 30 seconds, under the same event ID, so an ambiguous commit is not recorded twice. If every attempt fails, the database is in effect unavailable: nothing was written, because the business transaction rolled back. The API answers `503` with the correlation ID, the runner writes a structured `audit.record_failed` log line (event kind, operation ID, body hash, the pseudonymous principal ID and the target reference, so the attempt stays attributable; no personal values, threat model §9.7) and raises the `audit_record_failed` metric, which alerts. The residual is stated in § Consequences: during a database outage, the record of an attempt that changed nothing can be lost. The record of a change cannot, because the change and its event share one transaction.
  - **Nothing applies later what the caller was told failed.** On the inline path the plan was never persisted, so after a `503` no operation row exists and nothing can run it; a retry is a new submission that plans again. On the job path (a held `Store` operation) there is no caller to answer: the claim rolled back with the transaction, the step is still `planned`, and the job's retry runs the whole check again until its outcome is recorded.
  - **A held `Store` operation** keeps its persisted plan. After approval, it runs as one `operation.apply` job, in one transaction.
- **What AG-1 means here.**
  - For `Store` Actions, AG-1 holds literally.
  - For `Directory` Actions it holds as **write-ahead plus same-transaction outcome**. The started event and the claim commit before the write. The outcome event commits with the outcome state, and a crash between the two is closed by reconciliation.
  - **The honest residual.** Between the directory write and the recording commit, the change exists in the directory without its outcome event. That lasts until the commit or until reconciliation, and inventory history (DM-18) shows the change meanwhile. The threat model's AG-1 wording is amended to say this (§ Consultation).

### Rule 7: Authorisation at Plan and again at Apply, against live facts for every scope root kind (TOCTOU)

- **The pipeline performs both checks, never Action code.** Each check is role ∩ delegation scope ∩ token scope (threat model §7.7) for the **initiator chain**, evaluated by `authz` and the delegation module's EP-6 scope evaluator over **live facts** about the target, never over inventory. Time-dependent state is read live too (DM-16.I5a).
- **One port for every root kind.** The kernel declares the port; `directory/client` implements it and `compose/server` wires it (the ADR-0003 F6 kernel→directory port pattern). It is not ancestry-only:

  ```go
  // internal/platform/operation: the port. The types live in the leaf internal/platform/authority (rule 13).
  type LiveFacts interface {
      // Facts reads, live and on the pins, exactly what q asks about one target.
      Facts(ctx context.Context, pins authority.Pins, t authority.TargetRef, q authority.FactsQuery) (authority.Facts, error)
  }
  ```

  `authz.FactsQuery(chain, permission, connection)` builds the query from the initiator's assignments. It names every root of every include **and** exclude entry that could decide the target, plus the Tier-0 facts (T-0007 Q1), so the read is bounded by the initiator's scopes, not by the target's whole membership. `authority.Facts` carries, for what was asked: the target's existence and kind, its GUID ancestry, its membership in each asked group, its membership in each asked AU, `isManagementRestricted` (DM-35.I7), the correlation state and the correlated AD object's ancestry, and the Tier-0 flag.
- **What is read live, per DM-35 root kind.** The Plan check and the Apply check read the same facts; Apply reads them **immediately before the write**.

  | `root_kind` | Live fact | Where it is read | Apply residual (no write is conditional on it) |
  | --- | --- | --- | --- |
  | `naming_context`, `ou_subtree`, `ou_one_level` (AD) | The target's parent chain by `objectGUID`. A move or rename checks the source **and** the destination parent | The pinned DC of the target's naming context | LDAP cannot make a write conditional on the parent |
  | `group_members` (AD) | Transitive membership of the target in each asked root group, with an in-chain filter built by `ldapfilter` (`LDAP_MATCHING_RULE_IN_CHAIN`, [search filter syntax](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)). Deactivated links never count (DM-36.I2) | The pinned DC of the **group's** naming context. Whether a root group in another domain needs a global catalog or that domain's DC is `[LAB: Windows]` (connector spec, T-0051) | A membership removed between the read and the write |
  | `group_members` (Entra) | Transitive membership through Graph `checkMemberGroups`, at most 20 group IDs per request ([checkMemberGroups](https://learn.microsoft.com/en-us/graph/api/directoryobject-checkmembergroups?view=graph-rest-1.0)) | The Entra connection | Read, then write; Graph read-after-change consistency is `[UNVERIFIED]` (T-0051) |
  | `administrative_unit` (Entra) | **Direct** membership of the target in each asked AU (`GET /directory/administrativeUnits/{id}/members/{id}`, [get a member](https://learn.microsoft.com/en-us/graph/api/administrativeunit-get-members?view=graph-rest-1.0)), because AU membership is not transitive (DM-35.I2), plus `isManagementRestricted` (DM-35.I7) | The Entra connection | As above |
  | `entra_tenant` | The target exists, is not deleted, and belongs to that connection's tenant | The Entra connection | As above |
  | AD entry with `include_correlated`, Entra target (DM-35.I6) | Three facts, all live: the Entra target; the correlation gate re-checked (DM-20.I5), so only `matched` authorises; and the parent chain (or group membership) of the **correlated AD object** | The Entra connection **and** the pinned DC of the correlated AD object's naming context (rule 5 pins it although nothing is written there) | Spans two directories. Neither write is conditional on the other directory |

  **Facts fail closed.** Each asked root comes back `member`, `not_member` or `unknown`, and `unknown` refuses the target whether the root is an include or an exclude. `unknown` covers a read error, a timeout, a partial batch (Graph checks at most 20 groups per request, so every batch must answer), and a root whose hidden-membership status cannot be determined. This matters for exclusions. `checkMemberGroups` returns only the groups the target belongs to, and it silently omits hidden-membership groups the caller may not evaluate ([checkMemberGroups](https://learn.microsoft.com/en-us/graph/api/directoryobject-checkmembergroups?view=graph-rest-1.0)), so an omitted ID cannot tell "not a member" from "not evaluable". The connector therefore reports a hidden-membership root as `unknown` unless the connection holds `Member.Read.Hidden`, and an exclusion can never fail open. How the connector knows which roots are hidden-membership is the connector spec's. `Member.Read.Hidden` is an optional right of the Entra app registration, and the connection health check reports whether it is held.

  The connector reads authorisation facts with default Graph queries. It never uses advanced queries (`ConsistencyLevel: eventual`), which Graph serves from a separate index store ([advanced queries](https://learn.microsoft.com/en-us/graph/aad-advanced-queries)).
- **At Plan.** After the Action's Plan returns its steps, the runner reads the facts and authorises every target. A refused item is `blocked`, with a denial event per item (AG-2). A missing Action permission fails the whole plan (`plan_failed`), with a denial event.
- **At Apply.** `client.Write` reads the facts `Step.FactsQuery()` names and calls `Step.Recheck` immediately before the conditional write (rule 2). Role assignments are read as they are now, so a technician who lost a role between Plan and Apply is refused (`failed`, reason `denied`, with a denial event). For `Store` Actions the runner re-checks inside the transaction (rule 6).
- **Whose authority.** Authorisation always evaluates the **initiator chain**: the requester, the automation policy as its own subject (DM-60.I2), and the API token's scope. An approval **never widens** it. A request whose requester lost the right while it waited fails `denied` at Apply.
- **Residual, every root kind.** No directory makes a write conditional on ancestry, membership or correlation. If someone else takes the target out of scope in the moments between the re-check and the write, the write still happens. For Entra the window also includes Graph's read consistency `[UNVERIFIED]`. In every case Verify reads the same facts again, records `verify_failed` with reason `scope_changed`, and alerts. TM-F-AUTHZ's "moved or removed from scope between Plan and Apply" tests cover the window that matters, which lasts from minutes to days, for an AD move, an Entra AU or group removal, and a broken correlation (O8).
- **No role touches `tier0`** (TM-D2, DM-35.I5), in any root kind. It is checked at both points, and no gate can lift it.
- **Tier-0 after the write (TM-D23 rule 11, TM-R17).** The same residual applies to `tier0`: LDAP cannot make a modify conditional on membership, ancestry or a DACL on another object ([RFC 4511 §4.6](https://www.rfc-editor.org/rfc/rfc4511#section-4.6)), so an object added to Domain Admins, granted DCSync or given a DC between the Apply-time check and the write can be written (contract R-T0RACE-1). Verify therefore checks every directory step that reached `applied` for `tier0` after the write, with two independent sources:
  1. **The server's own guard.** Verify reads, live and on the pins, the Tier-0 facts of `authority.FactsQuery` for **every touched object** (the target and each object the step's typed change touches, which is the set the server sent a `CorrelationStatement` for, contract §8.3), and runs the server's `tier0` guard (threat model §6.4) on that re-read. This re-read follows rule 5 exactly like the read-back: it retries on the pin within the verify window and, if the pin stays unreachable, falls back to another DC of the same naming context (for Entra, it retries within the per-provider verify window). A fact counts as `tier0` when any read shows it `tier0`, or when it is **still `unknown` (read error, timeout, partial batch) after the verify window has elapsed and the fallback read is done**: unknown counts as `tier0`, as at Plan and Apply, but a pin outage alone is not a Tier-0 finding. This check does not depend on the connector: it runs when the connector reports nothing.
  2. **The connector's report.** Every object in `ApplyResponse.tier0_after_write` (contract §8.1 step 9, D28) counts as `tier0` after the write, **with or without a `basis`**. An empty `basis` means the connector could not re-read or classify the object after the write (D30); it is treated exactly like a basis, never as "nothing found", so blocking the reads after a write raises the alert instead of suppressing it. The report counts **at once**, without waiting for the verify window: the connector observed the failure on the DC that took the write, which is the only place the race is certain to be visible.

  **How this splits from `dc_unavailable` and the window's other outcomes** (every reason reachable, fail closed kept):

  | Connector step-9 report | Server's Tier-0 re-read (after rule 5's window and fallback) | Read-back | Outcome |
  | --- | --- | --- | --- |
  | lists a touched object (with or without a basis) | any | any | `verify_failed` `tier0_after_write`, immediately |
  | none | any touched object `tier0`, or a fact still `unknown` on every DC tried | any | `verify_failed` `tier0_after_write` |
  | none | every fact read on some DC (pin or fallback), none `tier0` | after-state seen | `verified` (the DC named) |
  | none | as above | differs | `verify_failed` `read_back_mismatch` (or `scope_changed`, from the scope facts) |
  | none | as above | not completed on the pin or the fallback DC by the end of the window | `verify_failed` `dc_unavailable` (AD only) |

  So a pinned DC lost after the write, with a clean step-9 report and a readable fallback DC whose facts show nothing `tier0`, is `verified` or `dc_unavailable` with no `critical` alert; the same loss with no DC readable is `tier0_after_write`. The fallback DC may lag replication of a Tier-0 change made on the pin; the step-9 report is the source that covers the pin. For Entra (no DC), a step whose verify window elapses without the after-state being observed is `verify_failed` `read_back_mismatch`, and Tier-0 facts still `unknown` at the end of that window are `tier0_after_write`.

  If either source finds any touched object `tier0`, the step goes `applied → verify_failed` with reason **`tier0_after_write`**, whatever the read-back says. The step's `verify_failed` audit event lists each such object by `objectGUID` with its bases, or `unclassified` for an empty basis, and which source reported it. `tier0_after_write` takes precedence over every other Verify reason; a `scope_changed` finding on the same step is recorded in the same event's detail, not as a second outcome. The item goes `running → failed` and its later steps `not_run` (rule 3); the pipeline also requests cancel of the operation (`running → cancelling`, reason `tier0_after_write`), so no further item is started while someone is changing the Tier-0 set under it. Steps already in flight finish under their own Apply-time checks.
- **Verify alerts and their severity.** Both are security alerts from `audit` through `notify` (rule 13), raised in the transaction that records the `verify_failed` outcome, sent to `tenant-owner` accounts and to every EP-9 sink. Severities are ordered `info < warning < high < critical`.

  | Verify reason | Alert severity | What the alert says and asks |
  | --- | --- | --- |
  | `scope_changed` | `high` | The target left the initiator's scope between the re-check and the write. Review the change; undo is available (rule 3) |
  | `tier0_after_write` | `critical`, the highest a Verify outcome raises | A `tier0` object was written: the object, its bases or `unclassified`, the operation, step, initiator chain, DC and which source found it. Undo is refused by the `tier0` guard; an administrator must review the change, and the change that made the object `tier0`, outside activeDIQ |

  A `critical` Verify alert cannot be muted, rate-limited or downgraded by tenant notification settings; only its delivery channels are configurable. Its absence would hide an attack in progress, and it fires only when a write and a Tier-0 change race, which is rare.

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
  - **a sock-puppet approver.** Within the last 30 days, a principal in the initiator chain, through activeDIQ: (a) created the approving account (`created_by`, DM-30); (b) granted `operation.approve` to that account directly; (c) bound or rebound its `directory_ref` (DM-30.I5); (d) added its directory object to the group through which it holds `operation.approve`; or (e) set or reset its directory password, or changed its sign-in binding attributes (UPN, mail, `altSecurityIdentities`), which would let the initiator take over an existing approver. **The rule runs both ways:** it also refuses an approver who did (a)–(e) to any principal in the initiator chain, so a compromised tenant-owner cannot start an operation from a fresh second account and approve it as themselves. Such an attempt also alerts `tenant-owner` accounts. This closes the second-account bypass by a compromised tenant-owner (X5).

  A buggy or hostile gate therefore cannot get an operation self-approved.
- **What does not make a sock-puppet.** A `directory` or `sso` account created by sign-in through an admission rule or a group-subject grant (DM-30, DM-36.I2) is created by the system, not by a principal. Creating the admission rule, or granting the group a role, does not by itself taint the group's members: their identities exist in the directory independently of the initiator. An approval by an account whose granting-group membership is younger than 30 days in inventory history (DM-18), and was not made through activeDIQ, is allowed but alerts `tenant-owner` accounts, because the initiator may also hold rights in AD outside activeDIQ.
- **How a pilot gets a legitimate approver.** On a new install the tenant-owner creates every local account, so for 30 days no local account can approve a held operation the tenant-owner starts. A pilot gets an approver on day one by admitting its administrators from the directory: an `sso` or `directory` account admitted through a group the administrators already belong to. Accounts admitted that way can approve each other's and the tenant-owner's held operations. A local-only pilot waits out the window, because every local account is tied to the tenant-owner in one direction or the other. This is customer-visible and goes in the ratification notice (§ Consequences).
- Every gate outcome writes an audit event: held, approved (with the approver), rejected, or request expired.

### Rule 9: Inputs, secrets and plan validity

- **The plan hash** is SHA-256 over the canonical encoding (rule 11) of: the Action IDs and versions, every item's target, diff, preconditions, phase and reversibility, and a flag for each secret input. It never covers a secret value. It does not cover the DC pins or `plan_valid_until`, which say how and when the change runs, not what it is (rule 5).
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
- notification channels and SMTP settings (T-0095): `notify.channel.*`, exported by `platform/notify/actions`;
- accounts created, disabled or reset by an administrator (T-0096): `authn.account.*`, exported by `platform/authn/actions`;
- roles and assignments: `authz.*`, exported by `platform/authz/actions`; delegation scopes: `delegation.*`;
- templates, naming formats, attribute lists, workflow definitions, automation policies, report definitions and schedules (T-0104: `reports.schedule.*`), data sources;
- audit retention and SIEM sinks (`audit/actions`), tenant settings, erasure requests (`personal/actions`, rule 12).

**System bookkeeping is not an Action.** It is written by its owning package and audited where the threat model says so (DM-80.I3). The complete list, kept in the fitness configuration, follows. Adding to it is an amendment to this ADR.
1. sign-in, sessions and step-up, with what they record after verifying a proof (the session, a spent TOTP step, an authenticator's sign count, attempt counters and pauses), and a **console account's** enrolment of its **first** factor inside a sign-in that has no factor yet (DM-31, DM-37 console MFA, ADM-142). It covers console accounts only: an end user enrolling on the FD-05 page is item 10, never item 1. A later add or replacement of one's own factor, and a change of one's own password, are not on this list. No code on main enrols a factor at sign-in; the change that builds it audits the enrolment and notifies the account's contact data already held (T-1221);
2. the first-run bootstrap, a registered platform path (ADR-0002), and the host-local `activediq-server account init-local` command, whose authority is access to the host (principal `cli-account-init-local`, T-0808), including the enrolment and confirmation of the first TOTP factor of the account it creates (T-1221);
3. connector and agent enrollment handshakes (`fleet`): redeeming a single-use token and recording the enrolled component. Issuing a token is a principal's decision and is not on this list (T-1221);
4. sync and inventory (D-kind, DM-14…DM-23), and connection verification runs with what they record from the directory: run results, findings, the directory identity, a run's own draft/verifying moves, and takeover-attestation demotion signals (T-1221);
5. the bookkeeping of jobs, leases, schedules, operations, requests and approval decisions (DM-06, DM-41–44, DM-65, DM-66);
6. report runs, automation runs and policy progress, deliveries (DM-61, DM-62, DM-72, DM-84);
7. audit events, checkpoints and the personal-value store (DM-80, DM-81, rule 12);
8. data-key rotation (TM-D15);
9. the Entra takeover attestation callback, the IdP redirect of a Global Administrator sign-in. It writes the `attested_*` values the server read from Graph, sets `first_attested_at` on the first move to `attested` (DM-10.I7(f)) and clears `demoted_at`. The last two can move a `stale` takeover back to `attested`, so this write **widens**: it can let correlations in the tenant become `matched` again. That is accepted for three reasons. I7(d) says a demotion lasts until a new attestation, and this is that attestation. The values come from Graph through the Global Administrator's own sign-in and are never typed in (I7(a)). A principal holding `connections.takeover.attest` started the attempt after step-up, and the callback appends the audit event that names both people (I7(b)). The callback writes only when its `state` matches one unexpired attempt row, which it consumes single-use (`connection.Store.ConsumeAttempt` deletes the row by `state_hash` and refuses an expired one, `internal/directory/connection/takeover.go:245`, called first by `Attester.Callback` at `internal/modules/connections/attest.go:329`), and the token's `tid` is the connection's `directory_identity` (DM-10.I7(a), `internal/modules/connections/attest.go:361`); otherwise it fails and writes nothing. No Step can exist, because the callback is an unauthenticated redirect (an ADR-0002 platform path, threat model AN-11) (T-1221);
10. the v1 end-user TOTP enrolment page (threat model AN-5; FD-05, DM-04): an end user enrolling their own factor in `authn_authenticator_enrollments`. It is an anonymous route, so no principal and no Step exist. This write **widens**: the factor later passes caller verification (ENH-09) and can lead to a password reset. Its bounds are TM-TB1-T13's: the end user's own AD authentication inside the flow (connector `VerifyUser` or SPNEGO); a re-enrolment needs the existing factor or a technician-verified reset, which is an Action; every enrolment notifies contact data already held and is audited. Its writer must enforce all four. No code writes it yet. The change that builds the page adds its `system` row (category `enduser-enrolment`); that is an amendment, reviewed by security-architect against these bounds (T-1221).

**Tables carry a write class.** The ownership map (ADR-0003 rule 6) gains a column, `config` or `system`, declared beside the migration. **Which class (T-1221, restated at review).** The class follows from one test, applied to each write the product makes to the table.
- **A widening decision** is a write whose value the system did not read or derive, because someone chose it (a principal, an anonymous caller, a host operator or a component), and which can, by itself, widen what anyone may do, see or keep. Who chose it does not matter, and neither does whether a principal exists: a value typed on an anonymous route or at the host CLI is chosen just as a console administrator's is. That covers authority (roles, assignments, owners, scopes); credentials, or the means to obtain one (accounts, passwords, factors and their approvals, enrollment tokens); data sources and destinations (connections, bindings, inventory hosts, SIEM sinks, channels); what activeDIQ treats as one identity or as Tier-0 (correlations, hybrid links, Tier-0 designations); and the guards and limits that hold the rest in place (retention, holds, attestation age, overrides, settings).
- **Not a decision:** a value the system read or derived, from the directory, an IdP, a handshake or a clock, with nobody choosing it. This holds even when a principal's request started the run that read it, as a live read at Plan does. What a sign-in or step-up records after verifying a proof (the session, a spent TOTP step, an authenticator's sign count) is of this kind.
- **Narrowing only:** a write that can only revoke, end, refuse, consume or demote.
- **Own first factor:** a **console account** enrolling its own first factor inside a sign-in that has no factor yet (item 1) is not a widening decision. No session exists yet, so a hijacked session cannot make it. The factor does outlive the sign-in, but it grants nothing beyond what the account's own proof already entitles it to: this is trust on first use. Its residual is TM-TB1-T13's: someone who already holds the account's first proof can enrol before its owner does. Item 1's audit event and notice shorten that window. That is the whole exemption, and it never covers an end user on the FD-05 page (item 10). Every later add or replacement of one's own factor, and every change of one's own password, **is** a widening decision: it creates a credential that outlives the session that made it, which is the means to obtain one. So is setting another account's credential, or approving another account's factor.
- **Releasing only:** a write that adds no authority of its own and lets a write proceed that is itself an Action, authorised for its requester and re-checked at Apply (rule 7). An approval decision is the case (rule 8).

A table is **`config`** when the product makes at least one widening decision to it, from any surface: an authenticated request, an Action, an unauthenticated route, a job, the fleet listener or a CLI. Every other table is **`system`**. The numbered list above is the list of system bookkeeping, and each item is an instance of the test, not an exception to it. On a `config` table, a function may be a **`system` row** only in two cases:
- each of its writes is not a decision, narrowing only, releasing only or an own first factor; or
- it is a widening decision in the **closed set of no-Step widening writes**: item 2 (the first-run bootstrap and the host CLI, before any principal exists or on the host's own authority), item 9 (the takeover attestation callback) and item 10 (the end-user enrolment page). Such a row must say in its reason what it widens and what bounds it.

Every other widening decision is an Action, so O3 requires the Step. A widening write with no Step outside the closed set is a defect, and admitting one is an amendment that adds a numbered item. Anonymous surfaces planned later, such as SSPR (AN-7, M4), are not admitted: their specs bring either an Action design or that amendment.

**The numbered items, re-read against the definition (third review).**
- *Item 1:* the session, a spent step, a sign count, attempt counters and pauses are derived from a verified proof, so they are not a decision, whatever the anonymous caller typed. A console account's first factor is chosen by the account and is the *own first factor* case.
- *Item 2:* the host operator chooses the account, its password, its first factor and its grants. These are widening decisions, so item 2 is in the closed set.
- *Item 3:* the component chooses its key and redeems the token. That spends a token once (narrowing only) and admits only what the token's issue, an Action (T-1246), already decided.
- *Item 9:* the `attested_*` values are read from Graph. Clearing `demoted_at` and setting `first_attested_at` happen because the attesting principal and the Global Administrator chose to attest. The write is therefore counted as a widening decision, and item 9 stays in the closed set; it is not argued out of the test as a read.
- *Item 10:* the end user, an anonymous caller until their AD authentication succeeds, chooses the factor. It is a widening decision, so item 10 is in the closed set.
- *Items 4 to 8* record what was read, derived or released, and none of them takes a chosen value that widens.

**The O3 rule (T-1221): the Step sits at the package boundary, not at the SQL.**
- **Write site.** A write site is a call in non-test Go under `internal/` and `cmd/` (default build constraints) to a method named `Exec`, `Query`, `QueryRow`, `CopyFrom` or `Batch.Queue` (the set safe-primitives' `sqlconst` pass checks) whose SQL parameter is a `string`, where the SQL writes a `config` table (`owners.ClassOf`). Writing means `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `COPY … FROM` or `TRUNCATE`, also inside a CTE or an `ON CONFLICT … DO UPDATE`, with or without the `public.` qualifier. The SQL is the argument folded as a Go constant by `go/types`, so concatenated constants count.
- **Guarded.** A function F guards a write to table T when one of these holds:
  - (a) F has a `step.Step` parameter, has no `store.Tx` or `*store.DB` parameter, calls no `store.DB` method, and every transaction it writes in or hands to a helper is `s.Tx()` of that parameter (the call itself, or a local assigned only from it);
  - (b) F is a `system` row for T in the allow-list;
  - (c) F is unexported, every non-test reference to F is a direct call from its own package, and every function making such a call guards T. A cycle with no (a) or (b) member is unguarded, and so is a helper with no static caller (dead, or reached through an interface or a function value).
  A reference inside a closure belongs to the declaration that encloses it.
- **Root.** The root of a write site is the function that contains it, or, when that function is an unexported helper, each nearest function above it that is exported, referenced as a value, or uncalled. O3 reports an unguarded root with the table.
- **The allow-list** is data: `tools/fitness/operation/o3-writers.json`, read by O3 (T-0391), parsed with `encoding/json`. Each `writers[]` row has:
  - `package` (import path below the module);
  - `function` (`Func` or `Type.Method`, pointer receivers written without `*`);
  - `tables`;
  - `disposition`: `system` or `convert`;
  - `ticket`;
  - `reason`;
  - for `system` rows, a `category` from the file's `categories` (each maps to an item of the list above) and `callers`.
- **What the rows mean.** A `system` row is permanent. Adding one, or adding a table to one, is an amendment to this ADR. Its `callers` are the only functions (`<package>.<Func|Type.Method>`) that may reference it in non-test code. `["*"]` lifts the restriction and is allowed only when the reason shows that the write can only reduce access, as a session-epoch bump does. An exported caller in the row's own package must have its own row for the table, so the owning package cannot re-export a system writer. Adding a caller to an existing row in a non-widening category is reviewed by solution-architect in the change that adds it, and is not an amendment. **Widening rows are different.** The categories `bootstrap`, `attestation` and `enduser-enrolment` (items 2, 9 and 10) hold the no-Step widening writes. Their writers are generic: `Service.Enroll` takes any subject, including a directory user by connection and GUID, and `Service.Activate` and `Accounts.SetState` are just as general. Adding a caller to a row in one of those categories, adding a row to one, or moving a row into or out of one is an amendment to this ADR, reviewed by security-architect. O3 makes this checkable from the ADR, as O9 does with the `dag` block: the `o3-widening` block below is the source. O3 fails when the file's `widening_categories` is not the block's category set, when a `system` row in a widening category is missing from the block, when the block lists a row the file does not have, or when a row's `callers` differ from the block's. So a new caller of a widening row cannot pass O3 without an edit to this ADR. A `convert` row is a pending baseline entry, as O8's gaps are: O3 prints it as pending with its ticket (not a pass), and the ticket deletes the row when the root is guarded. A `convert` row's function may appear in a `system` row's `callers` while it waits. The ticket that deletes or converts it also removes it from those `callers` in the same change, and O3's stale-caller check enforces that. O3 fails a stale row: a root that no longer writes the table, an exported caller that is no longer a caller, or a `convert` row whose violation has gone. It also fails a malformed row: unknown category, missing reason, callers or ticket, or a duplicate.
- **The widening rows** (`o3-widening`). Each line is `<category> <package>.<Func|Type.Method> <- <caller>, …`. A category line without a row (`<category> -`) names a widening category that has no writer yet. O3 parses the one block in this file and compares it with `o3-writers.json`.

```o3-widening
bootstrap internal/platform/authn.CreateIn <- internal/compose/server.firstOwners.CreateFirstOwner, internal/compose/server.createLocalAccount
bootstrap internal/platform/authn.Accounts.SetState <- internal/compose/server.confirmTOTP
bootstrap internal/platform/authn.LocalCredentials.SetPassword <- internal/compose/server.createLocalAccount
bootstrap internal/platform/authn.Service.Enroll <- internal/compose/server.createLocalAccount
bootstrap internal/platform/authn.Service.Activate <- internal/compose/server.confirmTOTP
bootstrap internal/platform/rbac.SeedBuiltIns <- internal/compose/server.firstOwners.CreateFirstOwner, internal/compose/server.createLocalAccount
bootstrap internal/platform/rbac.Grants.GrantBootstrap <- internal/compose/server.grantDirectoryReader
bootstrap internal/platform/rbac.OwnerAssignments.GrantIn <- internal/compose/server.firstOwners.CreateFirstOwner, internal/compose/server.createLocalAccount
attestation internal/directory/connection.Store.RecordAttestation <- internal/modules/connections.Attester.Callback
enduser-enrolment -
```
- **Fails closed.** `sqlconst` (safe-primitives FF-SP2) already requires the SQL argument to be a constant, a sqlc-generated constant or the report compiler's `CompiledSQL`. O3 skips `CompiledSQL`, whose SQL only reads (ADR-0010). Any other argument that O3 cannot fold fails. A migration function, `DO` block or trigger body that writes a `config` table also fails. Top-level backfill DML in a migration is allowed, because it runs once as the migration role.
- **Why this rule.** Two alternatives were rejected:
  - *Thread the Step into every SQL-bearing function.* Every helper would need a Step, and tests could no longer drive a body without a runner-minted Step (`settings.set` and `personal.setHold` are split out for that reason). It adds no safety, because an unexported helper is unreachable from outside its package.
  - *Whole-program reachability from Step-taking functions only.* This needs an interprocedural call graph across interfaces and function values, which either over-approximates (false failures through interfaces) or under-approximates (a function value hides a caller). It also moves the guard to the callers, so an exported `store.Tx` writer would be safe only until someone added a new caller, and its signature would no longer show that it is guarded.
  The package-boundary rule is decidable with `go/types` alone (static calls only; values fail closed). It is rule 2's sentence ("the exported write functions … take a `step.Step`") made checkable.
- **Residuals.** O3 does not trace the owning package's unexported code above a listed caller, and it trusts a listed caller outside the owning package at that function. A system writer reached only through an interface has no static reference, so its `callers` stay empty. Its reason names the interface, and whoever wires the concrete value is bound by fitness-modules' import rules. fitness-modules' import rules bound who can reach those callers, and code review covers the rest. `lab`-tagged files are not analysed: a converted signature fails their compilation, so they cannot keep a bypass.

**Classified at T-1221 (main, 2026-11-01).** There are 61 SQL write sites to the 20 `config` tables: 38 to the 14 tables classed `config` before this amendment, 2 to `personal_hold`, 3 to `authn_authority_approvals`, 6 to `correlations`, 3 to `enrollment_tokens`, 6 to `authn_authenticator_enrollments` and 3 to `authn_webauthn_credentials`. Four are guarded today: `notify/settings` `set` (2 sites), reached only from `Store.Set(step)`, and `personal` `setHold` and `releaseHold`, reached only from `SetHold(step)` and `ReleaseHold(step)`. Every other site's root is a row in the allow-list:

| Package | Sites (file:line) | Root → disposition, ticket |
| --- | --- | --- |
| `directory/connection` | `binding.go:42`; `override.go:93,100`; `store.go:58,196,233`; `takeover.go:175,189,206`; `verification_store.go:112,120`; `hybrid_store.go:34,94` | `Store.Activate`, `Create`, `Transition`, `RecordVerification`, `SetAttestationMaxAge`, `AcknowledgeTier0Override`, `DeclareHybridLink`, `TransitionHybridLink` → convert, T-1229. `Transition` and `RecordVerification` are split: the verification run's own moves and bookkeeping become narrow item-4 system writers, which T-1229 may add with named callers (pre-authorised here); the activation and the credential swap move under a Step. `Store.SetDirectoryIdentity` with `Registry.SetDirectoryIdentity`, and `Store.RecordDemotion` → system (item 4). `Store.RecordAttestation` → system (item 9). `Store.DiscoverHybridLink` → system (item 4). The dead wrappers `Registry.RecordDemotion` and `Registry.DiscoverHybridLink` → convert, T-1229 (delete). Until then each is the only listed caller of its system row, and T-1229 removes it from those `callers` in the same change |
| `directory/inventory` | `writer.go:145,159,246,270,290,426,433`; `reconfirm.go:68` | `Writer.Designate`, `Writer.Undesignate`, `Writer.Reconfirm` → convert, T-1232. `Writer.Form` (caller `Ingester.judge`), `Writer.Remove`, `Writer.RecordLiveFacts` with `Facts.RecordLiveFacts` → system (item 4) |
| `directory/invhost` | `pgstore.go:38` | `PGStore.Insert` → convert, T-1232 |
| `platform/authn` | `accounts.go:281,355,437`; `localcred.go:278,287`; `store.go:74` (run at `store.go:604`); `authority_factor.go:359,470,677,691`; `enrollment.go:191,310,366,369,402,420`; `webauthn.go:150,406` | `CreateIn` → system (item 2; callers: the first-owner claim and the `init-local` CLI). `Accounts.SetState` → system (item 2; caller: `confirmTOTP` of the `init-local` CLI). `LocalCredentials.SetPassword` → system (item 2; caller: `createLocalAccount` of the `init-local` CLI). `Service.Enroll` and `Service.Activate` → system (item 2; callers: `createLocalAccount` and `confirmTOTP`). `Accounts.Bind` → system (item 1; caller: SSO sign-in). `Store.RevokeAccountTx` → system (item 1, callers `*`: it only bumps `session_epoch`). `Service.Verify` (through `check`, `charge`, `pause`, `settleFailure`; callers `SecondFactor.VerifyTOTP` and `StepUp.matchTOTP`), `SecondFactor.VerifyTOTP`, `WebAuthnFactor.Verify` and `AuthorityFactors.Verify` (through `useCredential`) → system (item 1). `Accounts.Create`, `AuthorityFactors.Approve`, `BeginEnrol`, `FinishEnrol`, `Reset`, `Remove` and `WebAuthnFactor.AddCredential` → convert, T-1230 |
| `platform/fleet/fleetsql` | `enrollment.go:152,214`; `reenrol.go:237` | `Enrollment.Issue`, `Reenroller.ReenrolAddc` (through the unexported `one`) → convert, T-1246. `Enrollment.Redeem` and `Enroller.Enroll` (through the unexported `redeemWith`) → system (item 3) |
| `platform/notify/syslog` | `store.go:147,152` | `Store.Create`, `Store.Update` → convert, T-1231 |
| `platform/rbac` | `catalog.go:79,85`; `grants.go:224,229,355,361,476,482,525`; `owner_assign.go:140,146,217` | `SeedBuiltIns`, `OwnerAssignments.GrantIn` → system (item 2). `Grants.GrantBootstrap` → system (item 2; T-0808). `Grants.CreateRole` → convert, T-1228, with a bootstrap twin for `grantDirectoryReader` that T-1228 may add (pre-authorised here). `Grants.SetRolePermissions`, `Grant`, `Revoke`, `OwnerAssignments.Grant`, `OwnerAssignments.Revoke` → convert, T-1228 |

**Borderline classes, reviewed at T-1221 and re-run against the restated test.** Each table was checked against "which class" above. Corrections are in the migration's `-- write-class` line, followed by `make gen-modules`.
- **`correlations`: corrected to `config`** (migration 0006). A tenant owner's re-confirmation (`connections.correlation.reconfirm`) is a widening decision: it makes a correlation `matched`, and only a `matched` correlation carries authority and write routing across the two directories (DM-20, I4(g)). Sync's writers (`Form`, `Remove`, `RecordLiveFacts`) are *not a decision*: they record the I4 gate's verdict on what was read. They are system rows (item 4).
- **`enrollment_tokens`: corrected to `config`** (migration 0007). Issuing a token is a widening decision. The token is the means to obtain a component certificate, which admits an agent or connector to the tenant: a credential and a data source. Authorisation, step-up and an audit event checked inline do not make it bookkeeping. Issue and the ADDC re-enrolment sweep become Actions (T-1246). Redeeming is *narrowing only*: it spends a token once (DM-12.I2, enforced by `enrollment_tokens_guard`). So the handshake (`Redeem`, `Enroller.Enroll`) is a system row (item 3). `components` stays `system`. A pending component grants nothing until a token issued for it is redeemed, and a revocation narrows.
- **`personal_hold`: `config`, as corrected.** Setting a hold is a widening decision with legal effect: it keeps personal values past retention (rule 11). It belongs with audit retention and erasure requests, not with the personal-value store. Its only writers already take the Step of `compliance.hold.set` and `compliance.hold.release`.
- **`authn_authority_approvals`: `config`, as corrected.** An owner's approval of another account's Tier-0-relevant factor (TM-D19 rule 2) is a widening decision about a credential. It is not the bookkeeping of an operation's approvals (item 5). The enrolling account's spend of the approval in `BeginEnrol` narrows the table, but it is one step of an enrolment that adds the account's own authority factor after sign-in, a widening decision. So the enrolment becomes one Action and `BeginEnrol` is a convert row (T-1230). At the first review it was a system row under item 1, which the second review narrowed.
- **`inventory_servers`: `config`, confirmed.** Registering an inventory host is a widening decision: the administrator chooses a data source.
- **`tier0_designations`: `config`, confirmed.** Designating Tier-0 adds protection, but undesignating removes it, and both are an administrator's choice (`inventory.tier0_designation.set`). The undesignation is a widening decision.
- **The other `system` tables, scanned at the rework.** Writes whose value a principal chooses were traced to their entry points on main, and none fails the test:
  - report runs and exports (item 6) record a read within the runner's own authority, and cancel or delete narrows;
  - `connection_attestation_attempts` records which connection an attempt is for, and the attestation itself lands in `connections` (item 9);
  - `authn_authority_challenges` and `authn_webauthn_challenges` hold single-use ceremony challenges, which grant nothing (*not a decision*); the credentials land in the two tables below;
  - `operations`, `operation_items`, `operation_steps` and `operation_secrets` are item 5. The requester's input is planned and gated as the Action itself.
- **`authn_authenticator_enrollments`: corrected to `config`** (migration 0016), at the second review, once *own first factor* was narrowed and the test made surface-independent. Enrolling a TOTP factor is a widening decision (a credential). On main its only enrolment is item 2's host CLI: `Service.Enroll` and `Service.Activate` are system rows (item 2), whose callers are `createLocalAccount` and `confirmTOTP`. `Service.Verify` and its re-exporter `SecondFactor.VerifyTOTP` are system rows (item 1), because a sign-in or step-up only spends a step, counts attempts and pauses. The end-user page writes this table later under item 10.
- **`authn_webauthn_credentials`: corrected to `config`** (migration 0047), at the same review. Registering a credential after sign-in is a widening decision. That covers a second-factor passkey (`WebAuthnFactor.AddCredential`, `webauthn.go:129`, called today only from the lab seeding) and the account's own authority factor (`AuthorityFactors.FinishEnrol`, through `insertCredential` at `authority_factor.go:622`, after an AD proof or an owner approval spent in `BeginEnrol`). `authn_authority_approvals` gates only the authority purpose (TM-D19), not ordinary second factors. Both become Actions, with `BeginEnrol` (convert, T-1230). Sign-in's sign-count update (`useCredential`, under `WebAuthnFactor.Verify` and `AuthorityFactors.Verify`) is item 1. The owner's revoke (`Reset`, `Remove`) narrows, but it stays with its approvals write as an `authn.account.*` reset (convert, T-1230).
- **Every surface re-scanned at the second review.** A widening write from any surface now makes a table `config`, so the writes reachable without a console session or API token were traced again. These were the threat model's anonymous routes AN-1 to AN-11, jobs and the fleet listener. AN-1 and AN-2 write nothing. AN-3 and AN-8 to AN-10 (sign-in) record values derived from a verified proof (item 1). AN-4 is item 2. AN-6 redeems a token (item 3). AN-11 is item 9. AN-5 is item 10. AN-7 (M4) is not built. Jobs are items 4 to 6. No other `system` table receives a widening decision.
- **Approval decisions (item 5): `system`, confirmed.** An approver's decision is *releasing only*. It adds no authority of its own. The operation it releases is an Action, authorised for its requester and re-checked at Apply (rule 7), under rule 8's separation of duties.

**Undo for configuration** restores the previous version. Definitions are versioned (X7), and other configuration rows keep their before-image in the step outcome.

**How a configuration undo is planned (T-0892).**
- A Store Action's `Inverse` returns the input of its family's **restore Action**, `<owner>.<noun>.restore`, with the row and the version to restore. The restore Action is registered like any other Action and is reachable only as an inverse; no route submits it directly. The inverse of a create restores "no row": the row is archived or removed, as the family's delete would do.
- The restore is planned **for the principal undoing**, with the checks of the transitions it makes. A restored owner needs what a reassignment needs. A restored state needs what the matching pause or resume needs, so if only the owner may resume, only the owner may undo a pause. Restored content needs what an update to that content needs: permissions, scope and confirmations, such as external recipients. A check that fails blocks the inverse at Plan. Undo never lifts a check that the forward change had to pass.
- The undo is refused as `superseded` when the row's current version is not the one this operation wrote. A later change is undone first, so an undo never silently overwrites a newer change.
- An undo is itself an operation, so it can be undone. Its HTTP surface is ADR-0004 rule 14.

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
  - `operation.completed` (result `succeeded`, `partially_succeeded`, `failed` or `no_change`) or `operation.cancelled`, with counts. A `no_change` operation writes only this event, with outcome `success` (rule 3).
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
- **Append buffers; audit's commit hook chains; `store` knows nothing about audit.** `store` offers two neutral mechanisms and imports no audit code:
  - a **per-transaction slot**, keyed by a value only its creator holds (`store.NewSlot[T]()`), so a package can attach data to a transaction without `store` knowing its type;
  - **one `BeforeCommit` hook**, set once when `compose/server` opens the store. `WithTenantTx` runs the body, then the hook, then `COMMIT`. Satellite binaries open no store (ADR-0003 rule 7), so the hook exists only in `cmd/server`.

  `audit.Append(tx, kind, event)` puts the event in audit's slot. It refuses a transaction whose store was opened without audit's hook, so a mis-wired process fails closed, never silently unchained. The hook is set once and is immutable: a second set panics. The slot is sealed when the hook starts, so an `Append` after that is refused. Transaction-control SQL (`COMMIT`, `ROLLBACK`, `SAVEPOINT`) is refused inside a `WithTenantTx` body, so no body can commit around the hook. `compose/server` installs `audit.Chainer.BeforeCommit` as the hook. When the slot holds events, the hook runs the chain statements:
  1. a check that the transaction is `READ COMMITTED`, refusing it otherwise;
  2. `SELECT seq, hash, at FROM audit_head WHERE tenant_id = $1 FOR UPDATE`. No row means the tenant was never initialised, and the transaction fails closed;
  3. for each buffered event: `at = greatest(clock_timestamp(), head.at)`, then hash, then `INSERT` into `audit_event`;
  4. an `UPDATE` of `audit_head`.
- **Who owns the chain tables.** `audit_head`, `audit_event` and `audit_checkpoint` are owned by `platform/audit` (migrations `NNNN_audit_*.sql`, ADR-0003 rule 6). The chain SQL lives in `platform/audit`, and `store` executes only the hook function it was handed. No SQL in `store` names an audit table.
- **The genesis row.** The tenant-provisioning platform path (the first-run bootstrap in self-hosted profiles; tenant provisioning in `saas`; T-0037) commits the `tenants` row under `WithPlatform`. It then runs, in the new tenant's first `WithTenantTx`, the kernel tenant initialisers that `compose/server` hands it. `audit.InitTenant` is one of them. It inserts the head row `(seq 0, hash_0)`, creates the first checkpoint key, and appends `audit.checkpoint_key.created` and `audit.tenant.initialised`. This runs as the runtime role, the only role on that path (ADR-0002). So the runtime role holds `INSERT` on `audit_head`, fenced three ways: the primary key `(tenant_id)` allows one head per tenant; there is no `DELETE`, so a head cannot be recreated; and an audit-owned `BEFORE INSERT` trigger, which is not `SECURITY DEFINER`, refuses any row except `seq = 0` with the recomputed `hash_0` (PostgreSQL's built-in `sha256()`, [binary string functions](https://www.postgresql.org/docs/current/functions-binarystring.html)) and sets `at` itself to the transaction time, so a forged future `at` cannot skew every later timestamp through `greatest(...)`. `tenant_id` references `tenants` and passes the RLS `WITH CHECK` like every tenant table (ADR-0002). A trigger protects only against a role that cannot bypass it, so A1 also asserts that the runtime role does not own `audit_head`, is not a superuser and cannot set `session_replication_role`. Provisioning is idempotent: a crash between the two transactions leaves a tenant with no head, which cannot append (step 2), and re-running the path completes it.
- **Why a head row.** The row lock serialises the tenant's appenders. Under `READ COMMITTED`, a `SELECT … FOR UPDATE` that waited re-reads the row's committed version, so it sees the predecessor's head ([row-level locks](https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS), [EvalPlanQual behaviour](https://www.postgresql.org/docs/current/transaction-iso.html#XACT-READ-COMMITTED)).
- **What the head row costs.** It is the only audit table on which the runtime role holds `UPDATE` (and the fenced genesis `INSERT` above). A tampered head breaks the next link, so the verifier catches it.
- **Backstop and lock order.** The unique index `(tenant_id, seq)` is the backstop: a stale head fails the transaction rather than forking the chain. The head lock is the last lock a transaction takes, under a `lock_timeout`. Nested `WithTenantTx` calls are refused.
  - **How the refusal works, and what it does not catch.** `WithTenant` marks the context it hands to the body, and returns `ErrNestedTenant` when it is called with a marked context (`internal/platform/store/store.go`). A derived context (`context.WithoutCancel`, `WithTimeout`, `WithValue`) keeps the mark, so it is refused too. A body that calls `WithTenant` with a context that does not descend from the one it received is **not** caught: a fresh root (`context.Background()`, `context.TODO()`), the enclosing function's `ctx` captured by the closure in place of the body's own parameter, or a context kept from elsewhere. That call opens a second, independent transaction on another pool connection.
  - **Why this is an accepted residual, not a chain break.** The second transaction chains its own events under the head lock and commits on its own, so the chain stays gapless and each transaction still commits its events with its state (AG-1). What is lost is atomicity *between* the two transactions: the inner one can commit while the outer rolls back. And if the inner one waits on a row lock the outer holds, the two block each other until the `statement_timeout`, because PostgreSQL cannot see a wait that passes through the application. Both are correctness defects in the module that wrote the body, not a way to forge or drop an audit event. The `nestedtx` analyzer (FF-SP2, `tools/analyzers/nestedtx`, T-0334) fails the build on them: inside a function literal passed as the body of `WithTenant` or `WithPlatform`, it reports a direct call to `WithTenant`/`WithPlatform` and any call to `context.Background()`/`context.TODO()`. **The residual left is indirect calls**: a body that calls a helper, method or closure variable which itself opens a transaction, or one that uses a context kept from elsewhere, is still caught only in code review.
- **Gapless by construction.** `seq` order is commit order, so `seq` has no gaps: a rolled-back transaction consumed nothing. `at` is monotonic per tenant, so time partitions are `seq` ranges.
- **An ambiguous `COMMIT`** (the connection drops during commit) is resolved by the caller's idempotent retry (rule 4).
- **Throughput budget.** The lock is held for the inserts plus the commit flush. That gives roughly 200–1,000 audited commits per second per tenant on local storage, and roughly 100 per second with a synchronous standby `[UNVERIFIED: measure in the T-0088 load test]`. Bulk operations amortise the lock by recording several steps per transaction (rule 6). A transaction that appends nothing never takes the lock.

**Signed checkpoints (DM-81, AG-6).**
- **The key.**
  - Each tenant has an Ed25519 checkpoint key ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), Go `crypto/ed25519`).
  - Its private key is sealed under the tenant data key (TM-D7).
  - Keys have **validity windows in the chain**. An `audit.checkpoint_key.created` event introduces a key, and an `audit.checkpoint_key.retired` event ends it. The verifier rejects a signature by a key outside its window.
  - **Routine rotation** is yearly or on demand. The old key vouches for the new one by **cross-signing the chained `audit.checkpoint_key.created` event** that introduces it. It does not co-sign the first checkpoint under the new key. `audit.Checkpointer.Rotate` works in two steps. First it signs a final checkpoint under the old key in its own transaction; an anchor-sink failure on that checkpoint does not stop the rotation. Then one transaction appends `audit.checkpoint_key.retired` for the old key and `audit.checkpoint_key.created` for the new key at consecutive `seq`s. If that second transaction fails, the old key has signed one extra checkpoint and stays current. That is harmless, because the chain and every checkpoint in it still verify. That event carries `key_id`, `public_key`, `signed_by` (the old key's id) and `cross_signature`. The next scheduled checkpoint is the first one signed by the new key.
    - **The cross-signed statement** is the domain string `adq-audit-key-crosssign/1`, a NUL byte, then `adq-canon/1` of {1: tenant id, 2: signer key id, 3: new key id, 4: new public key} (`chain.CrossSignStatement`). Binding the tenant stops a signature being reused in another tenant's chain. Binding the signer stops it being credited to another key. The `seq` is not covered, because the chainer assigns it at commit, after the signature exists. A replay could only reintroduce the same successor, which the old key already vouched for, and the verifier conditions below refuse a second vouch.
    - **The verifier accepts the cross-signature only if** all of these hold: the event's `public_key` matches its `key_id` (the fingerprint); the signer key is known and was created at an earlier `seq`; the signer was **retired by a chained event at exactly the previous `seq`**, and the manifest agrees with that retirement; the signer has **not already vouched for another key**; and the Ed25519 signature verifies over the statement under the signer's public key. Any failure is reported as a forgery (`key_event`), never as a missing signature. The result is that a retired key that leaks later, or a current key, cannot introduce more keys.
    - **What it buys.** Trust spreads along cross-signatures only: a key is trusted if it is pinned or anchored, or if a trusted key cross-signed it. A bare `key.created`, or a checkpoint that covers it, vouches for nothing. So a third-party verifier that pinned the old key's fingerprint trusts the new key's checkpoints without a new pin. A key introduced without a cross-signature needs its own pin or an anchor. The trust is the same as that of a co-signed first checkpoint, and the vouch is in the chain, at the point where the key's validity window opens.
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
- **A hold suspends the purge (T-0515).** Before deleting, the purge finds the oldest partition in its range with an event whose envelope references a `subject_ref` that is `hold`ed in `personal_subject`. It purges only the partitions before that one (or nothing), because the chain can be cut only as a prefix. In the blocked partition and after it, no event, value or salt is deleted. It appends `audit.retention.held` and alerts `tenant-owner` accounts, so the over-retention of other subjects' data in those partitions is visible, not silent. Inventory history (DM-18) skips held subjects' rows row by row (T-0065). Every event about a person must carry that person's `subject_ref`; an event that does not is not protected, and A9 checks the producers.
- **A purge needs an archive.** It requires a recorded archive export covering the range, unless the tenant's `purge_without_archive` setting is on. Changing that setting needs step-up and is audited.
- **Every purge is evidence.** It appends `audit.retention.purged`, carrying the range, the boundary checkpoint and the archive digest.
- **A purge takes the purged events' personal values with it.** Each `value_id` belongs to exactly one record (rule 12), so the purge deletes, in the same maintenance transaction and through `personal`'s Go API, the `personal_value` rows that only the purged events reference. It then deletes the `personal_subject` row (the salt) of any subject left with no values and no `hold`. Keeping them would retain personal data for records the customer chose to discard, against the retention setting. The archive export carries the values unless the tenant archives pseudonymously, so nothing the customer chose to keep is lost. Inventory history (DM-18) purges its values the same way (T-0065).
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

The runtime role cannot `UPDATE` either table. Only erasure and the retention purge (rule 11) delete from them.

**Where the code sits** (rule 13). `personal` is below `audit`: `audit` imports it to carry `PersonalRef`s, to export side files and to purge, and `personal` imports no audit code. The pieces that need both live above them. The Action `personal.subject.erase` is in `personal/actions`. The job that runs triggers 1 and 3 below is in `personal/erasure`. Each deletes the values and appends `personal.subject.erased` in one transaction.

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

  A `hold` on the subject (legal hold) blocks all three, and also the retention purge (rule 11). The default for trigger 1 and the hold UX belong to the audit and compliance PRD.
- **What erasure cannot reach.**
  - SIEM copies, earlier non-pseudonymous exports and **database backups** keep the values until they expire.
  - So that a restore cannot resurrect erased subjects, every erasure is also written to an **erasure register outside the database**, in the blob store (ADR-0001 rule 3). The restore runbook replays the register after a restore.
  - Application logs never carry personal values (telemetry redaction, threat model §9.7).
- **One shape for every append-only record.** DM-18 ChangeRecord old and new values (owner `directory/inventory`, applied by T-0065), DM-66 comments (`workflow`) and DM-80 events all store `PersonalRef`s. They write values through `personal`'s Go API, so one erasure path covers them all.
- **Mutable records** (Operation input, Request, Account) are erased in place, as X11 already says.

### Rule 13: Package placement: the kernel import DAG

The write APIs of `authz`, `authn`, `notify`, `audit` and `personal` take a step token, and `operation` calls all of them. That is a Go import cycle unless the types are placed with care. This rule places them. The `dag` block below is the source. O9 compares the imports among the packages it lists with it, and fails on any edge it does not allow. Imports of the standard library, and of kernel infrastructure the block does not list (`keys`, `blob`, `telemetry`, `secret`, `capability`), stay governed by ADR-0003.

```dag
# package          -> kernel packages it may import (among those listed in this block)
audit/canon        -> (none)
audit/chain        -> audit/canon
tenant             -> (none)
authority          -> tenant
store              -> tenant
operation/step     -> authority, store, tenant
jobs               -> store, tenant
personal           -> audit/canon, authority, operation/step, store, tenant
notify             -> authority, jobs, operation/step, store, tenant
audit              -> audit/canon, audit/chain, authority, jobs, notify, operation/step, personal, store, tenant
authz              -> audit, authority, operation/step, store, tenant
authn              -> audit, authority, notify, operation/step, store, tenant
operation          -> audit, audit/canon, authn, authority, authz, jobs, notify, operation/step, personal, store, tenant
module             -> authz, operation
authz/actions      -> authz, operation, (anything operation may import)
authn/actions      -> authn, operation, (anything operation may import)
authn/throttlejob  -> authn, jobs, store, tenant
notify/actions     -> notify, operation, (anything operation may import)
audit/actions      -> audit, operation, (anything operation may import)
personal/actions   -> personal, operation, (anything operation may import)
personal/erasure   -> personal, operation, (anything operation may import)
```

**What each package holds, and why it sits where it does.**

| Package | Holds (for this ADR) | Why here |
| --- | --- | --- |
| `audit/canon`, `audit/chain` | `adq-canon/1`; chain and checkpoint verification | Standard library only. `operation` (plan hash), `personal` (commitments), `audit` and `cmd/auditverify` all need them, and the verifier links nothing else |
| `authority` (**new**, leaf) | `Principal`, `Chain`, `TargetRef`, `NamingContextID`, `Pins`, `FactsQuery`, `Facts` | The step token and the `LiveFacts` port expose them, and both sit below `authz`, which evaluates them. `authz.Permission` stays in `authz`: no package below `authz` needs it (`operation.Descriptor` and `module.Registrar` are above it) |
| `operation/step` (leaf for every write API) | `Step`, `Key`, `OperationID`, `Clearance`, `DCRef`, the plan-digest function, the single minter (rule 2) | Every write API takes a `Step`, so it must sit below all of them. It is a subpackage of `operation` (owner key `operation`, ADR-0003 rule 6), and importing it does not import `operation` |
| `store` | `WithTenantTx`, the per-transaction slot, the one `BeforeCommit` hook | Imports no audit code. The chain runs as audit's hook (rule 11) |
| `personal` | `PersonalRef`, the side store, `Put`, `Resolve`, `Erase`, `PurgeValues`, the erasure register | Below `audit`, which carries its refs, exports its values and purges them (rules 11, 12) |
| `notify` | delivery, EP-9 sinks, alerts | Below `audit`, which forwards to sinks and raises alerts. `notify` appends no audit events itself: changes to its configuration are Actions, which the runner audits |
| `audit` | `Kind`, the envelope, `Append`, `Chainer`, `InitTenant`, checkpoints, export, forwarding, retention | Below everything that appends an event: `authz`, `authn` and `operation` |
| `authz`, `authn` | evaluation (`Authorize`, `FactsQuery`); accounts and sessions; their `config` write functions, which take a `step.Step` | Neither imports the other. The identity facts both need are in `authority` |
| `operation` | `Action`, `Descriptor`, `StepPlan`, `PlanContext`, `Outcome`, `Verdict`, `Define`, `Catalogue`, `Gate`, `Approvals`, the `LiveFacts` port, the runner, the transitions | On top: it orchestrates all of the above. Inside the kernel only `module` and the `actions` subpackages import it |
| `<pkg>/actions`, `personal/erasure` | the kernel's own Actions (rule 10), and jobs that must call both their package and `audit` or `operation` | Above both their package and `operation`. `compose/server` hands their `All()` to the operation host (rule 1) |

**Outside the kernel.** `directory/client` imports `operation/step` and `authority`. It implements `operation.LiveFacts` structurally and does not need to import `operation`. Modules import `operation` and whatever they write through. The import of a kernel type by `directory/client` is a directory → kernel import, which ADR-0003 rule 1 allows.

**Catalogue rows.** `authority` and `personal` are new top-level kernel packages, so ADR-0003 rule 5 needs a blueprint §5.1 row for each. The subpackages are listed in their parents' rows. T-0155 adds them.

## Alternatives considered

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **Static analysis alone** for "only Actions write" (a call-graph rule, no token) | No new type in the client API; less ceremony for directory-engineer | A call graph over interfaces and function values is approximate. It is PatchIQ's "the interface exists, review will catch it". The token makes a bypass a compile error, and the analyzer only has to stop the token escaping, which is a local, syntactic check |
| **Event sourcing** for operations (state derived from an event log) | One store for state and evidence; replay | Two sources of truth to reconcile (job queue, OperationItem, events) and a harder query model for every operations screen. Persisted state plus same-transaction audit gives the same evidence |
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
- `directory/client`'s write API depends on a kernel type (`step.Step`). That is a directory → kernel import, which ADR-0003 allows.
- The kernel grows two top-level packages (`authority`, `personal`) and six thin subpackages (`operation/step`, the five `<pkg>/actions`, `personal/erasure`) so that the write APIs compile without cycles (rule 13). The `dag` block fixes their directions, and O9 holds them there.
- Per-tenant serialisation caps one tenant's audited commits at the rule 11 budget: roughly 200–1,000 per second, or about 100 with a synchronous standby. That is ample for a self-hosted tenant. It is the first thing to measure for a large SaaS tenant (revisit below).
- The runtime role holds `UPDATE` on one audit table, `audit_head`. That is a deliberate exception to "INSERT only": tampering with it breaks the next link and is detected.
- The verifier says `UNANCHORED` for an install with no SIEM sink whose exports nobody pinned. That is honest, but auditors will ask, so the docs explain how to pin the fingerprint.
- The personal store doubles writes for personal attribute changes in inventory history. T-0065 sizes it.
- The transient secret table narrows X4. It is a new sealed-at-rest secret class that backups contain while a step is in flight.
- Erasure cannot recall SIEM copies or earlier exports. That is stated in the product, not hidden.
- Approvals bind to the requester's authority, so a long-pending request can fail `denied` at Apply if the requester's role changed. That is correct, but it will surprise people. The UI explains it.
- **Customer-visible, for the ratification notice: the 30-day separation-of-duties window (rule 8).** For 30 days, an account cannot approve an operation started by an account it created, granted or bound, or by the account that created, granted or bound it. On a new install with only local accounts, the tenant-owner is tied to every account, so nobody can approve a held operation for the first 30 days. A held operation is one that needs approval: an undo of an approved operation, an irreversible change when the tenant turns on "approval for irreversible changes", a step-up Action started by a token, or an automation over its blast radius. A pilot avoids the wait by admitting its administrators from the directory (an `sso` or `directory` account through a group), because the system, not the tenant-owner, creates those accounts.
- **Entra re-checks are read, then write** (rule 7). Graph makes no write conditional on group or AU membership, and its read-after-change consistency is `[UNVERIFIED]`. A target removed from scope seconds before the write can still be written; Verify catches it as `scope_changed` and alerts.
- **During a database outage, the record of an attempt that changed nothing can be lost** (rule 6). It is logged and alerted. The record of a change cannot be lost, because the change and its event share one transaction.

**Follow-on work** (filed with this ADR; IDs on the T-0047 ticket note):
- **operation kernel** (T-0153, build, backend-engineer): `platform/operation`, meaning EP-3, the state machine, the job kinds, reconciliation, the inline Store path, the kernel holds, the default EP-4 gate with single approval, Undo, `operationtest`, and the `Registrar.Action`/`ApprovalGate` methods; plus the rule 13 leaves it needs first: `platform/authority` and `platform/operation/step` (the token, the minter, the clearance), and the `LiveFacts` port. It replaces the scaffold's `Action` in `internal/platform/operation/operation.go` in the same change. It goes into checkpoint 2a ahead of T-0093, T-0095, T-0096 and T-0104.
- **fitness-operation and fitness-audit** (T-0154, chore, devops-engineer): O1–O9 and A1–A9 in `make ci`, each with a failing case in `tools/ci/proof.sh`.
- **architecture map** (T-0155, chore, solution-architect): blueprint §4.2, §8, §9, §16 and §17; §5.1 rows for `platform/authority` and `platform/personal`, with the subpackages of rule 13 in their parents' rows (`operation/step`, `audit/canon`, `audit/chain`, the `<pkg>/actions`, `personal/erasure`); the `store` row gains the slot and the `BeforeCommit` hook; the `audit` row owns `audit_head`, `audit_event` and `audit_checkpoint`; the ADR-0002 Jobs-row amendment line; the ADR-0003 amendment adding `cmd/auditverify` as a class row and a rule 7 binary row (it links only `platform/audit/chain`, `platform/audit/canon` and the standard library); and the `config | system` column of the ownership map.
- **T-0037** (existing) runs the kernel tenant initialisers on the provisioning path, including `audit.InitTenant` (rule 11; note filed).
- **T-0088** (existing) builds the chain, the head row, checkpoints and key windows, export, the verifier, `platform/personal` with its erasure register, and the byte-level format document under this ADR (note filed). The SIEM stream stays with E2.10.
- **T-0084** (existing) adds the `ManagedTx` job mode and the transactional insert (note filed).
- **The restore runbook** replays the erasure register (rule 12). It is part of the E2.12 backup work (note on the architecture-map ticket).
- **T-0065** (existing) applies rule 12 to DM-18 (note filed).
- **Domain model**: DM-41 and DM-42 follow rule 3; X4, X11, DM-60.I3, DM-80, DM-81 and §11 Q6 and Q9 are updated in this change.
- **Open for the audit and compliance PRD:** the default for ADM-207 erasure, the legal-hold UX (case reference, reason, review reminder, warning that a hold cannot recover purged data, oldest retained `seq`), and minimum retention.

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
| O1 | **Step escape** (`go/analysis`): a value of type `step.Step` is stored in a field, global, map, slice or channel; is captured by a closure; or is passed to a function with no `step.Step` parameter. Or a `step.Step` or `step.Clearance` is constructed outside `operation/step`, or `step.TakeMinter` is referenced outside `platform/operation`, or a `//go:linkname` directive targets `operation/step`. The `compose/server` boot test fails if `operation` does not hold the minter |
| O2 | **Write surface**: a `directory/client` exported method that issues a connector-contract write RPC lacks a `step.Step` parameter; the connector-contract write RPC is called from a function with no `step.Clearance` parameter; the generated connector-contract write client is referenced outside `directory/client`; **type-aware (`go/types`, T-1408)**: a type, variable, field, parameter or result outside `directory/client` whose method set carries the generated client's `Plan` or `Apply` (so an alias, a named interface or struct embedding the client, or an inferred variable cannot launder it), an exported type, field or variable of `directory/client` that does, or any use (call, method value, method expression) of the generated `Plan`/`Apply` outside a `directory/client` function with a `step.Clearance` parameter; a directory protocol or Graph client is imported outside the connector root (shared with `fitness-profiles` P3); a package is placed by its path below the module root, so a nested `cmd/*/internal/…` directory gets none of the top-level exemptions |
| O3 | **Configuration writes** (rule 10, "The O3 rule"; allow-list `tools/fitness/operation/o3-writers.json`). Fails when: a write site to a `config`-class table has a root that is unguarded, meaning it neither (a) takes a `step.Step` and writes only in that Step's `Tx()` (no `store.Tx` or `*store.DB` parameter, no transaction of its own), nor (c) is an unexported helper called directly and only from guarded functions of its package, nor (b) is a `system` row for that table; a `system` row is referenced by a function not in its `callers`, or has an exported caller in its own package without its own row; the rows of the widening categories (`bootstrap`, `attestation`, `enduser-enrolment`) or their `callers` differ from the ADR's `o3-widening` block, or the file's `widening_categories` differs from the block's categories; a row is stale (its root no longer writes the table, or a `convert` row's violation has gone) or malformed; an SQL argument O3 cannot fold (other than `CompiledSQL`); a migration function, `DO` or trigger body writes a `config` table; a table has no write class. `convert` rows print as pending with their ticket, not as passes |
| O4 | **State machine**: the transition table in `transitions.go` differs from this ADR's `transitions` block; SQL that updates a state column of `operation`'s tables appears outside the transition function; a property test driving random event sequences reaches an undeclared transition, or an all-skipped plan ends anywhere but `no_change` |
| O5 | **Registry completeness** (the `compose/server` boot test over every module and every kernel-exported Action) fails when an Action: lacks a Descriptor field; has an `AuditKind` that is unregistered or owned by someone else; declares `Reversible` or `Lossy` while `Inverse` returns `ErrIrreversible` for a contract fixture |
| O6 | **Contract coverage**: a registered `ActionID` has no `operationtest.Contract` run in `go test ./...`. The harness writes coverage, and the check compares it with the registry |
| O7 | **Contract behaviour** (inside `operationtest.Contract`, against the fake provider and a rolled-back store) fails when: Plan writes anything (its store transaction is `READ ONLY`, and the fake directory counts writes); Apply run twice with one key changes state twice; Verify passes after the fake directory drops the write; apply → inverse → apply does not restore the before-state of a `Reversible` step; a `Lossy` step loses an undeclared field; the success, failure **and** denial events are not all emitted with their AG-3 fields (TM-F-AUDIT coverage) |
| O8 | **Pipeline behaviour** (integration, Postgres + Samba lab for AD; the connector's Graph fake for Entra) fails when any of these is not as stated: a step killed after its claim is reconciled to `applied`, re-applied, `not_run` (operation cancelling) or `stale_state`, never left `applying`; a password step is never re-applied by reconciliation; a superseded attempt's late result changes nothing; a step whose retries are exhausted while the after-state is in place is not recorded `failed`; a lost chunk job is re-driven by the sweeper; a target changed between Plan and Apply fails `stale_state` and is not overwritten; **removed from scope between Plan and Apply is refused** (TM-F-AUTHZ) in each of: an AD object moved out of an OU root, an AD object removed from a `group_members` root, an Entra object removed from an `administrative_unit` root, an Entra object removed from an Entra `group_members` root, and an Entra target of an `include_correlated` entry whose correlated AD object moved out of scope or whose correlation dropped to `candidate`; a target whose include or exclude root comes back `unknown` (a hidden-membership Entra group, a read error or timeout, a partial batch) is refused; `client.Write` refuses an operation whose digest differs from the step's plan; an approval with a stale `plan_hash`, by the initiator, by an API token, without step-up for an `Irreversible` operation, or by a sock-puppet account in either direction (including an approver whose password or sign-in binding the initiator changed), is refused; a `Clearance` replayed for a different step or operation is refused; an approval by a directory-admitted account not tied to the initiator is accepted; a held operation re-planned on a different DC with the same before-state keeps its approvals; a `StepUp` Action initiated by a token is held or refused; an automation run over `max_objects` is held; a gate error leaves the operation unapproved; an expired transient secret fails its step `secret_expired`; a `Store` Action whose Apply fails or is denied still has its outcome event, including when its first recording attempt hits `lock_timeout`; an undo of a `failed` item restores the before-state of its `verify_failed` steps, except a `tier0_after_write` step, whose inverse is `blocked` so the item stays `failed` and the undo operation is `partially_succeeded` or `plan_failed`; **`tier0` after the write (TM-F-T0GUARD rule 11, contract CC-WRITE-21)**: with the fault-injection proxy holding the modify on user X after the connector's step 7 while X is added to Domain Admins, the step is not recorded `verify_failed` with reason `tier0_after_write` (X, basis C2), the `critical` alert is not raised to `tenant-owner` and the fake EP-9 sink, its severity is not above the `scope_changed` alert's, or the operation is not `cancelling`; the same holds with connector step 9 disabled in a test build (the server's own guard alone must find it), with the server's live Tier-0 read returning `unknown` instead, and when the proxy drops, then separately errors, every read after the released modify so that `tier0_after_write` lists X with an empty basis (recorded `unclassified`); an undo of that step is not `blocked` by the `tier0` guard; a tenant setting mutes or downgrades the `critical` alert; **the split from `dc_unavailable`**: with the pinned DC stopped after the write, a clean step-9 report and a fallback DC that is readable and shows no touched object `tier0`, the step is not `verified` or `verify_failed` `dc_unavailable`, or a `critical` alert is raised, or the step is recorded before the verify window elapses; with the pinned DC stopped and no other DC of the naming context readable, the step is not `verify_failed` `tier0_after_write` with the `critical` alert; an Entra step whose verify window elapses without the after-state is not `read_back_mismatch` |
| O9 | **Kernel DAG**: an import among the packages listed in rule 13's `dag` block is not allowed by that block. The checker parses the block from this file, as O4 does for `transitions` |

**`fitness-audit`** (`tools/fitness/audit/`; it implements TM-F-AUDIT)

| # | Fails when |
| --- | --- |
| A1 | **Catalog**: the runtime role holds `UPDATE`, `DELETE` or `TRUNCATE` on `audit_event` or `audit_checkpoint`; `UPDATE` on `personal_subject`, `personal_value` or `operation_secret`; or any privilege on `audit_head` beyond `SELECT`, `INSERT` and `UPDATE`; or `audit_head` lacks its genesis-only `BEFORE INSERT` trigger, or that trigger accepts a row other than `seq = 0` with the tenant's `hash_0`, or leaves a caller-supplied `at`; or the runtime role owns `audit_head`, is a superuser, or can set `session_replication_role` (this extends `fitness-tenancy` T3) |
| A2 | **AG-1 and AG-2**: an event appended in a rolled-back transaction exists; a `Store` Action's state change commits without its event; a `Store` Action that fails or is denied leaves no outcome event; the chain hook accepts a non-`READ COMMITTED` transaction; `audit.Append` accepts a transaction whose store has no audit hook; an append for a tenant with no head row commits; a transaction commits with a non-empty audit slot that was not chained; an `Append` after the hook started, a second hook set, or a `COMMIT`/`ROLLBACK`/`SAVEPOINT` inside a `WithTenantTx` body is accepted |
| A3 | **Concurrency**: 32 concurrent appenders in one tenant leave a `seq` gap or a broken link; two tenants appending concurrently interleave in one chain |
| A4 | **Seeded-tenant verification**: after the lab seed (operations, sign-ins, setting changes, a key rotation, an erasure and a purge) is exported, `adq-audit-verify` with the pinned fingerprint does not return `OK` |
| A5 | **Tamper corpus**: the verifier does not fail at the right `seq` with the right reason after any of these: an event edited, deleted, reordered or inserted; an event spliced from another tenant; a personal side value altered; side values deleted with no erasure event, or with a forged erasure event that references no erase step or trigger; a checkpoint signed by a retired key; **the whole chain rebuilt and re-signed under a fresh key**. That last case, run with no trust root, must return `UNANCHORED`, and with the pinned fingerprint it must fail |
| A6 | **Anchoring**: a checkpoint or key event is missing from the fake SIEM sink's stream or from the export; a history rewritten before an anchored checkpoint verifies against the anchors; seven days with no anchor raises no alert |
| A7 | **Classification**: an audit detail type has a string field tagged neither `personal` nor `public`; a detail type contains a `secret.Secret` (AG-9); a `personal`-tagged field reaches the canonical form as anything but a `PersonalRef` |
| A8 | **AG-8 coverage**: an audit read, export, retention change or SIEM-sink change emits no event; an export, retention change or sink change succeeds without step-up |
| A9 | **Retention**: after a purge, a `personal_value` row referenced only by purged events remains, or a `personal_subject` row with no values and no `hold` remains; a purge runs without a covering archive while `purge_without_archive` is off; **a purge deletes an event, value or salt at or after the oldest partition holding an event that references a held subject, does not append `audit.retention.held`, or resumes while the hold stands (seeded test: held subject in the middle partition of three)** |

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

**security-architect** re-reviewed the rework 1 deltas on 2026-10-02 (genesis `INSERT`, commit hook, the failure-record residual, facts per root kind, the two-way window, the minter and the clearance). Verdict: **concur with conditions**, all applied:

| # | Finding | Disposition |
| --- | --- | --- |
| R1 | A trigger is bypassable by its owner, a superuser or `session_replication_role`; a forged genesis `at` skews later timestamps; AG-4 said "INSERT only" | Rule 11: the trigger sets `at`; FK and RLS on `tenant_id`; A1 asserts the role can bypass nothing. Threat-model AG-4 carve-out for `audit_head` in this change |
| R2 | Hook and slot hardening | Rule 11: set-once hook, slot sealed at hook start, no transaction-control SQL in a body; A2 |
| R3 | AG-2 must state the outage residual; attribution; no later apply after a `503` | Rule 6: principal and target in the log line; no operation row survives an inline `503`. Threat-model AG-2 amended in this change |
| R4 | `unknown` must cover errors, timeouts, partial batches; `Member.Read.Hidden` visibility | Rule 7; health check reports the right; O8 |
| R5 | Account takeover of an existing approver | Rule 8 (e): password and sign-in binding changes; O8 |
| R6 | Clearance replay; `//go:linkname` | Rule 2: bound to key and digest, re-checked at send, dies with the step; O1, O8 |

**backend-engineer** reviewed the job wrapper, chunking, recovery and chain-at-commit on 2026-10-02. Verdict: **concur with conditions**. All conditions are applied:

| # | Finding | Disposition |
| --- | --- | --- |
| B1 | ADR-0002's Jobs row puts the whole body in one transaction | Rule 6: a `ManagedTx` mode; ADR-0002 Jobs row amended on ratification; note on T-0084 |
| B2 | Chunk-wide claims lapse, so the reconciler races live workers | Rule 6: claim only what runs now, with a DB-clock lease, an attempt fence on every record, and takeover by compare-and-set; `plan_revision` predicate |
| B3 | Job timeouts (raised against River, since replaced by `platform/jobs`' own queue, T-0209); the unique key is not a correctness tool | Rule 6: per-kind timeouts; the key is de-duplication only; transactional enqueue |
| B4 | Lock-then-read must be separate statements; head row preferred; throughput budget | Rule 11: `audit_head … FOR UPDATE` as its own statement, `lock_timeout`, no nesting, budget stated |
| B5 | Lost or discarded jobs stall operations; cancel during reconciliation; deferred verify has no driver; terminal detection | Rule 6: the sweeper re-drives; `applying → not_run`; `operation.verify`; last-item terminal transition |
| B6 | `Store` Plan I/O inside the transaction; event volume on the inline path; held `Store` steps | Rule 6: I/O before the transaction, with a version and hash re-check inside it; rule 11 emits one event inline; held steps run as one `operation.apply` |


## Review rework

factory-director reviewed the draft at commit `5df89a8` on 2026-10-02 and rejected it with nine items. Rework 1 disposes of each one:

| # | Finding | Disposition |
| --- | --- | --- |
| 1 | Import cycles: `operation` ↔ `authz`, `audit`, `personal` (Actions exported by kernel packages, write APIs taking a Step); `store` running SQL on audit-owned tables | **New rule 13**: the kernel `dag` block (O9), with leaves `authority` (Principal, Chain, facts types) and `operation/step` (Step, Clearance, minter); `authz.Permission` stays in `authz`; `Descriptor` stays in `operation`, which no write API needs. Kernel Actions move to `<pkg>/actions` subpackages (rules 1, 10). Rule 11: `store` offers a per-transaction slot and one `BeforeCommit` hook that `compose/server` installs; `audit` owns `audit_head`, `audit_event` and `audit_checkpoint` and their SQL; `personal` sits below `audit`, and erasure code that needs both lives in `personal/actions` and `personal/erasure` (rule 12). Notes on T-0153 and T-0155 restate their scope |
| 2 | Rule 7 covered only AD ancestry | Rule 7 rewritten: the `LiveFacts` port and `authority.FactsQuery`, with a table of the live Plan and Apply facts for every DM-35 root kind (OU and NC, AD and Entra `group_members`, `administrative_unit`, `entra_tenant`, `include_correlated` across two connections) and the Apply residual of each. Rule 5 pins the correlated AD object's naming context. O8 gains the AU, Entra group and `include_correlated` cases |
| 3a | An all-skipped plan landed in `plan_failed` | `planning → no_change`, terminal, no gate, no failure event, no alert; one `operation.completed` event with result `no_change` (rules 3, 11; O4) |
| 3b | Item `failed → undone` needed a `verify_failed` step to be undoable | `verify_failed → undone` added. Rule 3 states what an undo inverts and why a `failed` step never hides a write; rule 6 records `retries_exhausted` only after reading the before-state (O8) |
| 4 | DC pin inside `plan_hash` made a re-plan on another DC lapse approvals | Pins are excluded from `plan_hash`, and a re-plan keeps a healthy previous pin (rules 5, 9; O8) |
| 5 | 30-day sock-puppet window in a pilot | Rule 8 defines (a)–(e), applies them in both directions, says directory-admitted accounts are created by the system, and says how a pilot gets an approver. § Consequences carries the customer-visible text for the ratification notice |
| 6 | DM-42.I3 contradicted rule 5's read-back from another DC | DM-42.I3 now follows rule 5 |
| 7 | Who creates the `audit_head` genesis row | Rule 11: `audit.InitTenant`, run by the provisioning platform path (T-0037) as the runtime role, fenced by the primary key, no `DELETE` and a genesis-only trigger (A1, A2) |
| 8 | A purge left personal values and salts behind | Rule 11: the purge deletes the values only purged events reference, and salts of subjects left with no values and no hold (A9) |
| 9 | The fresh failure transaction could also time out on the chain lock | Rule 6: a longer `lock_timeout`, five jittered retries within 30 s under one event ID, then `503`, a structured log line and an alerting metric; the residual is in § Consequences (O8) |

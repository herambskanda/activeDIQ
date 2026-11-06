---
title: "ADR-0012: A dependent ticket may start on a done-but-unmerged dependency as a stacked branch; it merges only after its dependency, and a failed dependency gate invalidates the stack"
date: 2026-11-06
updated: 2026-11-06
status: proposed
owner: heramb
kind: technical
ticket: T-1705
fitness: fitness-merge-order
---

# ADR-0012: Dependents start on a done-but-unmerged dependency as a stacked branch; merge order is enforced, and a failed gate invalidates the stack

**Status:** proposed. Becomes `ratified` at factory-director review of T-1705, and `accepted` only when `fitness-merge-order` (M1–M5 below) runs green in `make ci`.
**Kind:** technical. It changes factory workflow, nothing a customer or the brand sees. Notice to the CEO, who asked for it.
**Deciders:** solution-architect (author); factory-director (ratifier). **Ticket:** T-1705.

## Context

The pre-merge gate (`factory/lib/premerge.mjs`, run from `Dispatcher.mergePass`) runs `make -k ci` on the merge result and takes ~55–60 min per round. `claimBlockers` (`factory/lib/tickets.mjs:75`) refuses to claim any ticket whose `depends_on` entry is `done` but still on the `unmerged` set (`unmergedBranches`, `factory/lib/worktree.mjs:105`: `main..factory/<id>` has commits). On 2026-11-06 one bisecting train held the queue for hours and every ticket with an unmerged dependency sat unclaimed at 0 active runs, with free worker slots. `train_size` was already cut from 4 to 1 (config.json); that fixes the bisection multiplier and is not revisited here.

What the current rule actually guarantees: **a worker never builds on code that has not passed the gate.** What it protects against is wasted work, not a bad main. Main's guarantee ("main gains only code that passed the gate") is enforced separately, by `mergePass`/`gateGroup`/`mergeTicket`, and does not depend on claim-time blocking. That separation is what makes this decision possible: we can relax the claim-time guarantee without touching the merge-time one.

`ensureWorktree` today always branches `factory/<id>` from `main` (`worktree.mjs:69`), so the dependency's code is simply absent from a dependent started early — it cannot be started early without a different base.

## Decision

We will let a dependent start on a **stacked branch**, and keep every merge-time rule exactly as it is.

1. **Eligibility.** A `ready` code-type ticket (`dispatcher.code_types`, which has a worktree) may be claimed while a `depends_on` entry is `done` and unmerged, provided that dependency (a) has status `done` (not reopened/blocked), (b) is not embargoed (`EMBARGO_TAG`) or held, (c) has a worktree/branch `factory/<dep>` with commits, and (d) the stack depth is ≤ `dispatcher.stacking.max_depth` (default 2: the dependent and one level beneath; deeper chains wait). `dispatcher.stacking.enabled` defaults to `true`; `false` restores today's behaviour exactly. A dependency that is not `done` still blocks as now. Spec/docs tickets (no gate, main checkout) keep today's rule: they are not stacked.
2. **Base.** `ensureWorktree` creates `factory/<id>` from the tip of the dependency's branch (for several unmerged dependencies, from an octopus-free linear base: the dependencies are merged into a throwaway base in order; if that conflicts, the ticket waits). The dispatcher records `links.stack = [{dep, dep_tip}]` on the dependent. The ticket otherwise runs the normal flow; its `ci`/test runs inside the worker are against the stacked tree.
3. **Merge order is a hard rule.** `mergePass` never puts a ticket in a gate train, and `mergeOne` never merges it, while any `depends_on` entry is not merged to main. A stacked ticket that reaches `done` first simply waits in the done queue. The gate always judges the **actual merge result** (main + the ticket), so by the time the dependent is gated its dependency is already on main and the gate sees `main + dependent` — identical in meaning to today.
4. **Dependency gate fails or the dependency is reopened.** The dependency's `factory/<dep>` tip moves (or the dependency leaves `done`). The dispatcher compares each dependent's recorded `dep_tip` with the dependency's current tip and marks the dependent **stale**, a visible flag with an event on the dependent. Stale dependents: (a) are not launched or gated; (b) a running one is allowed to finish its run but cannot advance past its current stage while stale; (c) are **rebased** `git rebase --onto <new dep tip> <old dep_tip>` once the dependency is `done` again (a clean rebase clears the flag and updates `dep_tip`; a conflict reopens the dependent with the conflict as its note, as `mergeOne` does today). Work is therefore never discarded wholesale: a failed dependency costs a rebase, and at worst a rework of the dependent. The dependent's commits are never merged onto main on a stale base.
5. **After the dependency merges**, `dep_tip` is an ancestor of main; the dependent is no longer stale-able, `links.stack` is cleared, and its merge into main (`--no-ff`) brings in only its own commits.
6. **Dependency rejected for good** (cancelled/superseded): dependents are marked stale with reason `dependency-cancelled` and handed to factory-director triage; nothing is auto-merged.

**Traded away, stated plainly.** We give up *"every worker builds only on gated code"*. A stacked worker's tests, and anything its author learns about the dependency, run against code that may still be refused by the gate. We keep *"main only gains code that passed the gate, on the exact tree it will become"* and add *"a ticket reaches main only after all its dependencies"*. The cost of the trade is bounded wasted work (one rebase, or one rework, per failed dependency, capped by depth 2), measured by the metric in Consequences.

## Alternatives considered

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| Keep blocking (status quo) + `train_size` 1 | Zero new mechanism; no wasted work ever. | The gate is ~1 h per ticket and serial; a chain of N dependents idles the factory N hours. Free slots are the cost the CEO is paying for. |
| Merge to main first, gate afterward, revert on failure | Dependents see the code instantly; no stacking. | Breaks the guarantee we are keeping: main would hold ungated code, other workers and all new branches would be built on it, and a revert races them. Rejected outright. |
| Integration branch (`integration/next`) that dependents branch from, gated as a whole and fast-forwarded to main | One gate per batch; dependents see each other. | A failure in any one ticket invalidates the whole branch for everyone, i.e. the bisection problem we just removed at `train_size` 4 → 1, moved elsewhere. Needs a second long-lived branch with its own conflict surface. |
| Speculative gate: start the dependent's gate on `main + dep + dependent` in parallel with the dep's gate | Overlaps gate time as well as work time. | Doubles gate load on one machine (`make -k ci` is already ~1 h), results are wasted on any dep failure, and it needs a gate runner that is not serial. Valid later, if wasted gate time is cheap; it composes with this ADR (the dependent is already stacked). |
| Stack unlimited depth | Maximum parallelism. | A single gate failure cascades through the whole chain; depth 2 caps the blast radius. Tunable via `max_depth`. |

## Consequences

**Positive** — Free worker slots are used while a dependency waits for the gate; the gate's runtime is no longer on the critical path of the dependency chain; main's invariant is unchanged and now additionally checked on history.

**Negative** — Wasted work when a dependency's gate refuses it (rebase/rework). More states to reason about (`links.stack`, `stale`). Octopus/multi-dependency bases can conflict and then simply wait. Reviewers/QA of a stacked ticket see the dependency's diff in the branch until it merges (the review diff must be taken against the dependency tip, not main: `ticket show` and the review prompt need the base). Disk: one extra worktree per stacked ticket, same as any ticket.

**Follow-on work** — filed as tickets (IDs in the T-1705 note): (1) implement stacking in `claimBlockers`/`claimTicket`/`ensureWorktree`/`mergePass` and stale/rebase handling; (2) the `fitness-merge-order` CI job; (3) review/QA prompts and board diff-base; (4) architecture-map entry for the factory merge workflow.

**Revisit when** — more than 25% of stacked tickets go stale in a week (metric: stale events / stacked claims, from the event log), or the gate becomes parallel (then re-evaluate the speculative gate row).

## Fitness function

CI job `fitness-merge-order` in `make ci` (node tests under `factory/test/` plus a history scan), failing the build on any of:

- **M1 — merge-order, behavioural.** A dispatcher test with a fake gate: a stacked dependent that is `done` while its dependency is unmerged is never in a train and never merged (`mergePass`, `mergeOne`); it merges only after the dependency's merge commit exists.
- **M2 — claim relaxation is exactly this.** A test matrix over `claimBlockers`/`claimTicket`: stacking allowed only for code-type + `done` + not-embargoed + depth ≤ `max_depth` + `enabled`; every other combination still blocks, and `enabled:false` is byte-for-byte today's behaviour.
- **M3 — stale on tip move.** Moving or deleting `factory/<dep>` (simulated gate refusal) marks each stacked dependent stale, blocks its launch and gate, and a rebase onto the new tip clears it; a conflict reopens it.
- **M4 — gate sees the merge result.** The gate always runs on a tree equal to `main` + that ticket's merge (no stacked base in the gate worktree): asserted in `premerge.test.mjs` by comparing the gate worktree's tree to `git merge-tree main factory/<id>`.
- **M5 — history invariant on real main.** A script (`factory/bin/fitness-merge-order`) walks `git log --first-parent --merges main`: for every `Merge T-x:` commit it checks each `depends_on` of `T-x` has its own `Merge` commit as an earlier ancestor. Fails on any violation (grandfathered: commits before this ADR's acceptance date, listed in the script).

The ADR is `accepted` only when M1–M5 are green in `make ci` on `main`.

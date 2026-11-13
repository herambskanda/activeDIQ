---
title: "Factory merge workflow: stacked branches, merge order, stale handling"
date: 2026-11-12
updated: 2026-11-12
status: draft
owner: heramb
ticket: T-1709
binding_sources: ADR-0012 (ratified)
---

# Factory merge workflow

Architecture-map entry for [ADR-0012](../decisions/0012-stacked-branches-dependents-start-on-done-unmerged-dependencies.md). This is factory tooling (`factory/`), not product code. It changes when a worker may start, never what may reach `main`.

## Two guarantees, kept separate

| Guarantee | Enforced at | Changed by ADR-0012? |
| --- | --- | --- |
| `main` gains only code that passed the gate, on the exact tree it becomes | merge time: `mergePass` / `gateGroup` / `mergeTicket` (`factory/lib/premerge.mjs`, `make -k ci` on the merge result) | No |
| A worker builds only on gated code | claim time: `claimBlockers` (`factory/lib/tickets.mjs`) | **Relaxed** for stacked tickets |
| A ticket reaches `main` only after all its dependencies | merge time (new) | Added |

## Flow

1. **Claim.** A `ready` code-type ticket may be claimed while a `depends_on` entry is `done` but unmerged, if that dependency is not embargoed or held, has commits on `factory/<dep>`, and stack depth is ≤ `dispatcher.stacking.max_depth` (default 2). `dispatcher.stacking.enabled: false` restores the old behaviour exactly. Spec/docs tickets are never stacked.
2. **Base.** `ensureWorktree` branches `factory/<id>` from the dependency's tip (several dependencies: merged in order into a throwaway base; on conflict the ticket waits). The dispatcher records `links.stack = [{dep, dep_tip}]`.
3. **Merge order.** `mergePass` never trains and `mergeOne` never merges a ticket while any dependency is not on `main`. A dependency in the same train does not count. The gate sees `main + ticket`, never the stacked base.
4. **Stale.** If `factory/<dep>` moves or the dependency leaves `done`, each dependent is flagged **stale** (event on the dependent): not launched or gated; a running one may finish its run but cannot advance a stage. When the dependency is `done` again the dependent is rebased `--onto <new tip> <old dep_tip>`; a clean rebase clears the flag, a conflict reopens the ticket.
5. **Dependency merges.** `links.stack` is cleared; the dependent merges `--no-ff` with only its own commits.
6. **Dependency cancelled.** Dependents go stale with reason `dependency-cancelled` and to factory-director triage; nothing auto-merges.

Reviewers and QA of a stacked ticket must diff against the dependency tip, not `main`.

## Components

| Component | Role |
| --- | --- |
| `factory/lib/tickets.mjs` `claimBlockers` | claim-time eligibility (rule 1) |
| `factory/lib/worktree.mjs` `ensureWorktree`, `unmergedBranches` | stacked base, unmerged set |
| `factory/lib/premerge.mjs`, `Dispatcher.mergePass` | gate on merge result; merge-order rule |
| `factory/bin/fitness-merge-order` | M5 history scan of `main` first-parent merges |

## Fitness function

`fitness-merge-order` in `make ci`, checks M1–M5 (merge-order behaviour, claim matrix, stale on tip move, gate tree equals `main` + ticket, history invariant). ADR-0012 becomes `accepted` only when all five are green on `main`. Revisit if more than 25% of stacked tickets go stale in a week.

---
name: ticket-craft
description: Write tickets that meet the Definition of Ready — sizing, Given/When/Then acceptance with evidence, parity IDs, dependencies, types, priority — and break epics down. Use when creating any ticket, decomposing an epic, or running a grooming ticket.
---

# Ticket craft

A ticket should be one outcome that one agent can finish in one session, with criteria a
reviewer can check without asking the author anything.

## Definition of Ready — all of these, or it stays `backlog`

1. **Title**: the outcome, imperative, ≤ 70 chars. "Validate CSV rows before bulk create",
   not "CSV stuff".
2. **Summary**: one paragraph in plain words. What exists afterwards that did not exist before,
   and why it matters.
3. **Acceptance criteria**, each with the evidence expected (§2).
4. **Owner**: the single agent whose craft it is (`factory/OPERATING-MODEL.md` §2).
5. **Links**: the spec, ADR, research or design it builds on, as paths in the body. A build
   ticket without a spec link is not ready.
6. **Dependencies** recorded in `--depends`, and **decisions** in `--decisions`.
7. **No unanswered directional decision** behind it.
8. **Epic, milestone and parity refs** where they apply.

`ticket ready` checks title, owner, acceptance and summary. Items 5–8 are on you.

## 1. Sizing

- Fits one session **comfortably**: plan for half the budget (~150k tokens), because reading,
  testing and fixing take the other half.
- Signals to split: more than 6 ACs; two owners' crafts (backend + UI); a contract and its
  implementation together; touching more than one module; "and" in the title; you cannot name
  the test that proves it.
- Split along seams that each leave `main` working: contract → implementation → UI → docs.
  Never split "write code" from "write its tests". Tests ship with the code.
- Too small is also wrong. A one-line rename belongs inside the ticket that needs it.

## 2. Acceptance criteria — Given/When/Then plus evidence

```
Given a CSV with 3 valid rows and 1 row whose sAMAccountName exceeds 20 characters
When the admin runs a dry run
Then the preview lists 3 creatable users and 1 error naming row 4 and the field
Evidence: integration test `bulk_dry_run_rejects_long_sam` passing; screenshot of the preview
```

- Behaviour, not implementation. Observable from outside.
- Cover the unhappy path: invalid input, no permission, the DC unreachable, an empty state.
- Name the evidence: a test name, a command and its output, a screenshot of a named screen
  state, a doc path. QA verifies exactly this.
- For non-behaviour work (spec, research, docs), use checkable statements: "Every capability
  row has a platform matrix", "every external claim has an inline URL".

## 3. Parity IDs and epics

- Parity refs come from the parity matrix kept by `market-analyst` under
  `knowledge/business/competitive-analysis/`. Prefixes: `ADM-` ADManager Plus · `ADA-` ADAudit
  Plus · `ADSS-` ADSelfService Plus · `RMP-` RecoveryManager Plus · `M365-` M365 Manager Plus.
- **Never invent a parity ID.** If the matrix lacks the feature, or does not exist yet, leave
  `--parity` empty. Say so in the body, and file a `research` ticket for `market-analyst` if
  parity matters.
- Enhancements beyond parity: tag `enhancement` and cite the parity ID they improve on, if any.
- Every build ticket belongs to an epic. Epics map to a parity group and a milestone
  (`factory/bin/factory epic list`).

## 4. Dependencies

- Depend only on what you truly consume (a contract, a primitive, a schema), not on related work.
- No cycles. No chains longer than ~4 inside one milestone. Restructure instead.
- Contract-first: when two owners meet at an interface, a `spec` ticket defines it, and both
  build tickets depend on that ticket, not on each other.
- A dependency that is `cancelled` must be resolved during grooming, never left dangling.

## 5. Types → flow → owner

| Type | Use for | Flow |
| --- | --- | --- |
| `build` | New behaviour | owner → review (`code-reviewer`, + `security-architect` if tagged `security-sensitive`) → qa → done |
| `bug` | Behaviour that differs from spec | same as `build`; the first AC reproduces it |
| `test` · `chore` · `ops` | Tests, refactors, CI, lab, packaging | owner → review → done |
| `spec` | PRD slice, functional/API/data contract | owner → `solution-architect` → done |
| `design` · `docs` · `video` | Design, guides, videos | owner → `product-manager` → done |
| `research` · `proposal` · `decision-prep` · `spike` | Investigation, external docs, CEO requests, prototypes | owner → `factory-director` → done |
| `meta` | Grooming, triage, digest, gardening | owner → done |

Tag `security-sensitive` on anything touching credentials, privileges, ACLs, auth, the DC agent,
the password filter, or the safe-primitive builders.

## 6. Priority

| P | Meaning | Examples |
| --- | --- | --- |
| P0 | Stop-the-line: `main` broken, a security exposure, the CEO or a demo blocked | Secret committed; build red; demo env down the day before review |
| P1 | On the critical path of the active milestone | The primitive every M1 build ticket depends on |
| P2 | In the active milestone, not on the critical path (default) | A second report on an existing engine |
| P3 | Later milestone or nice-to-have | Polish, speculative enhancements |

## 7. Command

```bash
factory/bin/factory ticket new --title "…" --type build --owner backend-engineer --priority P1 \
  --epic E-003 --milestone M1 --depends T-0040 --decisions D-0009 --tags security-sensitive \
  --parity ADM-xxx --summary "…" --body-file /tmp/T-body.md \
  --ac "Given … When … Then … Evidence: …" --ac "…" --status backlog
```

Body: context (two or three lines), scope **and out of scope**, links, approach notes only if a
decision was already made (cite it).

## 8. Worked example — epic → tickets

Epic `E-003` "Bulk user creation from CSV" (M1; parity `ADM-xxx` is illustrative, so take the
real ID from the matrix). The spec says: upload CSV → validate → dry-run preview → create →
per-row results.

| # | Ticket | Type · owner | Depends | Key AC |
| --- | --- | --- | --- | --- |
| 1 | Spec: bulk user creation from CSV | spec · product-manager | — | Columns, validation rules, limits, platform matrix, errors defined |
| 2 | Contract: bulk-job API (submit, status, results) | spec · api-engineer | 1 | OpenAPI checked in; idempotency and paging defined |
| 3 | DN and attribute builders for user create | build · directory-engineer · `security-sensitive` | 1 | Hostile RDN values escaped per RFC 4514; fuzz test passing |
| 4 | Bulk job engine: validate, dry-run, execute, per-row results | build · backend-engineer | 2, 3 | Dry run writes nothing to AD (lab assertion) |
| 5 | Bulk create endpoints | build · api-engineer | 2, 4 | Contract tests green against the OpenAPI |
| 6 | Bulk create screens: upload, preview, results | build · frontend-engineer | 5 | Every control works; empty, error and 10k-row states screenshotted |
| 7 | Lab E2E: 500 users from CSV against the test DC | test · test-engineer | 5 | Run recorded; all 500 present with the right attributes |
| 8 | Admin guide: bulk user creation | docs · docs-writer | 6 | Screenshots from the running product |

Tickets 3 and 2 run in parallel after 1. The critical path is 1 → 2 → 4 → 5 → 6, so those are
P1 and 7–8 are P2.

## 9. Grooming (`meta` ticket, `project-manager`)

Triggered when fewer than 3 tickets are `ready`.

1. **Look.** `factory/bin/factory status`; `milestone list`; `ticket list --status ready`,
   `--status backlog`, `--status blocked`; `decision list --status pending`; recent reject and
   triage notes. Read the active milestone's goal.
2. **Repair the backlog.** For each backlog ticket in the active milestone, bring it to the
   Definition of Ready: fill the ACs and evidence, links, owner and dependencies; split it if it
   is oversized (§1). Retitle anything vague. Do not move a ticket behind a pending directional
   decision.
3. **Decompose** the next epic if fewer than ~6 groomable tickets remain (§8).
4. **Make ready** 3–6 tickets with `factory/bin/factory ticket ready <id>`, in this order:
   P0, then the milestone's critical path, then tickets whose dependencies are already done,
   then a spread of owners so both parallel slots have work. Never make ready a ticket whose
   dependencies are not at least in progress.
5. **Flag, do not fix**, what only the director can do: stale `blocked` tickets, a cancelled
   dependency, a milestone at risk. Note these on the grooming ticket.
6. Advance the grooming ticket with a note: which tickets were made ready and why in that
   order, which were split, and the risks.

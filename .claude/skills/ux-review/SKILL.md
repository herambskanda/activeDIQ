---
name: ux-review
description: Heuristic UX review of activeDIQ screens and flows — Nielsen plus task time and clicks vs ManageEngine, 10k-object bulk ops, keyboard, permission-aware UI, design-system fit; severity and report. Use for design review or UI QA.
argument-hint: "[screen, flow, or ticket]"
---

# UX review

The promise to a ManageEngine customer is "a far better experience". This review is where that
claim is measured, not asserted. Who runs it: `product-designer` (design tickets and flows),
`product-manager` (reviewing design tickets), `qa-verifier` (UX section of a build ticket's QA).
Output: a report from `report-template.md`, saved to `factory/demos/evidence/<ticket>/ux-review.md`
with its screenshots beside it.

## 1. Set up

1. Read the spec (`knowledge/product/specs/<feature>.md`): personas, flows, the "what we do
   better" claims and their targets. Those targets are what you measure.
2. Review the **running product** with the demo seed loaded (realistic OUs, users, groups;
   ≥ 10k users for bulk checks). Mockup-only review is allowed for `design` tickets; say so in
   the report.
3. Review as each persona in the spec, with that persona's role — at minimum the full admin
   and one scoped help-desk role.
4. Screenshots and timings with Playwright (1440×900 viewport, both themes for visual checks).

## 2. What to check

**A. Nielsen's ten heuristics**, read for an AD console:

| Heuristic | What it means here |
| --- | --- |
| Visibility of system status | Bulk-job progress; replication/sync lag shown; which DC a write went to |
| Match with the real world | AD terms used correctly; friendly label + LDAP name; DNs shown exactly |
| User control and freedom | Undo, cancel a running job, back in wizards without data loss |
| Consistency and standards | Same pattern for the same need (`design-system` §4); same verbs everywhere |
| Error prevention | Impact preview, dry run, typed confirmation for Tier-0 and > 100 objects |
| Recognition over recall | Saved views, recent objects, command palette, no memorised paths |
| Flexibility and efficiency | Keyboard shortcuts, bulk ops, templates, URL-shareable views |
| Aesthetic and minimalist design | One accent job per view; no decoration; dense but scannable |
| Help users recover from errors | Error says what, why, what next; LDAP result code under Details |
| Help and documentation | Contextual help in a consistent place; links to the admin guide |

**B. Enterprise-admin specifics:**

1. **Task time and clicks vs the ManageEngine baseline** — for every top-20 task the screen
   touches (`top-tasks.md`), count interactions and time the expert path (§3). Floor: never
   worse than the baseline. Target: what the spec claims.
2. **Bulk at 10k objects** — select all matching, impact preview summarises without freezing
   (UI responsive; preview ready in a time the spec states), progress, cancel, per-object
   results, retry failed, export.
3. **Keyboard-first** — complete the top tasks with no mouse; focus always visible and in a
   logical order; `⌘K` reaches the object and the action.
4. **Discoverability** — a new admin finds the action from the object, from the palette, and
   from search, without docs. Count dead ends.
5. **Error recovery** — force: DC unreachable, validation failure, partial bulk failure,
   session expiry mid-wizard. Is the work preserved? Is the next step obvious?
6. **Permission-aware UI** — as the scoped role: nothing visible that fails with 403; disabled
   controls say why; scope is shown.
7. **Design-system consistency** — the `design-system` §9 checklist; WCAG 2.2 AA spot checks
   (contrast in both themes, focus, target size, screen-reader names on icon buttons).
8. **No fake data, no dead buttons** — click every control on the screen.

## 3. Measuring against ManageEngine

- **Baseline source, in order of preference**: (a) a measured run of ManageEngine in a lab — only
  if the CEO has approved using a ManageEngine trial for benchmarking (a legal/accounts
  question → `ceo-decisions`; check `decisions-log.md` first); (b) the documented flow in
  ManageEngine's admin guide, counted step by step, cited by URL and dated; (c) `[TODO]`. Never
  estimate a baseline from memory.
- Baselines and our measurements live in `knowledge/product/design-system/task-benchmarks.md`
  (owner `product-designer`; one row per top-20 task: ME interactions, ME time, source type
  a/b/c with URL and date, ours, build/date). Create it from `top-tasks.md` if missing; update
  the rows you measured.
- The research files (`knowledge/business/market-research/manageengine-*.md`, "UX notes")
  hold documented paths, e.g. ADSelfService Plus's split Configuration/Admin trees; use them.
- **Counting rule** — one *interaction* = a click, a tap, a keyboard command (`Enter`, a
  shortcut), or one field filled (typing a value counts once). Page loads are not
  interactions but are timed. Count the shortest expert path, from the product's landing page,
  object not yet open.
- **Timing** — script the expert path in Playwright and report the median of 5 runs against the
  lab (system time), plus a KLM estimate for human time (K 0.28 s, P 1.1 s, H 0.4 s, M 1.35 s;
  state the operators). Same method for both products, or the comparison is void.

## 4. Severity

| Sev | Meaning | Examples | Effect |
| --- | --- | --- | --- |
| **S1 Blocker** | Wrong object changed, data loss, or task impossible; a11y blocker; misleading preview | Bulk disable runs without preview; preview count ≠ executed count; keyboard trap | Reject the ticket |
| **S2 Major** | Task completes but is error-prone or slower than the ManageEngine baseline; missing state | No undo for a reversible change; 403 button visible to help desk; no empty state | Reject the ticket |
| **S3 Minor** | Friction with a workaround; inconsistency with the design system | Wrong verb on a button; filter not kept in URL | Follow-up ticket (P2/P3); advance |
| **S4 Polish** | Taste and finish | Spacing off-grid by 4 px; truncation could be smarter | Note only |

Each finding names the heuristic or check, the persona, the steps to reproduce, the evidence
(screenshot path), and a concrete fix. Rejects quote S1/S2 findings as numbered must-fix items:
`factory/bin/factory ticket reject <id> --by <role> --note "1. S1 … 2. S2 …"`.

## 5. Close

- File S3 tickets (`ticket-craft`), linking the report.
- Update the rows you measured in `task-benchmarks.md`. A task that beats the baseline by a
  claimable margin is noted for `market-analyst` (battlecard proof) — the claim still follows
  `competitive-intel` §4.
- A lesson that would save another reviewer 15 minutes → `memory` skill (`lessons.md`).

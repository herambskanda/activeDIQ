---
title: "Second report slice: change-history row detail, account-policy table with deltas, per-DC replication grid"
date: 2026-11-04
updated: 2026-11-04
status: draft
owner: product-designer
ticket: T-1123
spec: ../specs/reports-2-second-slice.md
decisions: [D-0005, D-0012]
---

# Second report slice: the three screens that are not the 2a grid

Design for [reports-2-second-slice.md](../specs/reports-2-second-slice.md) §4.1 (USR-06 and its four siblings), §7.1 (SYS-01), §7.3 (SYS-03), and the picker budget of §11. Everything on the 2a grid, run flow, scope and export is **unchanged** ([reports-2a-flows.md](reports-2a-flows.md)); this note adds one detail pattern, one cell pattern and three screens.

**Preview (clickable, every name, count and DC is generated sample data, labelled on screen):** `reports-2-second-slice-screens/preview.html`, open it in a browser. Every state is a deep link (`#/changes?state=partial`, `#/repl?state=cap&row=3`, `&theme=dark`). Screenshots of 33 states (light, plus dark for two) are in `reports-2-second-slice-screens/shots/`. Rebuild with `node build.mjs` then `node shots.mjs` from that folder (needs `npm ci --prefix tools/playwright`). The preview uses only `web/src/ds/tokens.css` values (`git diff web/src/ds/tokens.css` is empty), not a Storybook story: it is a design preview, the frontend tickets build the real screens on the design-system DataGrid.

## 1. Decisions (usability is ours; none of these is a taste question)

| # | Decision | Why |
| --- | --- | --- |
| 1 | **One docked detail pane for all three screens**, not an inline row expansion and not a modal. 520 px (`--diq-sheet-w`), non-modal, the grid stays live beside it. ↑/↓ move the selected row and the pane follows; Esc closes; the URL carries `?row=` so every detail is a deep link. | An admin hunting through changes compares neighbouring rows. A modal or a row-expansion costs a close or a scroll per row; the pane costs 0 interactions per further row. No modal stack (brief). |
| 2 | **No Restore, no Trigger replication, no Fix button** on any of these. The pane says what the action is and where it arrives (2b). | Spec §4.1.9, §7.3.8. A disabled button is a dead button (CLAUDE.md rule 6). |
| 3 | **Unknown is a word, never a blank or a green.** "Not recorded by AD", "Restore status unknown", "Not reported", "Not yet synced". Every state that is partial says "N of M" and names the missing part. | Spec rules 5, 7, §7.1.3, §7.3.2. An empty list read as "none" is the worst failure a report can have. |
| 4 | **Deltas are glyph + number + word**: `▲ +12` stricter, `▼ −2` weaker, `=` same; the pane says the word. Weaker is the only one coloured (warn). Stricter is plain text, not green. | "Stricter" is not "better": a 0-day lock-out is stricter and may lock out a service account. Colour must never carry the meaning alone (WCAG 2.2). Warn text is 7.2:1 on the surface. |
| 5 | **Replication: worst first, and the blind spots are pinned above the grid** ("Did not answer (n)"), not sorted among the rows. | A DC we could not read is a bigger risk than any row we could. The partner rows of an unreachable DC look healthy from their side only; the note says so. |
| 6 | **The picker is a field on the report page that takes focus on arrival**, typeahead over name, sAMAccountName, UPN and e-mail, Enter picks the highlighted row and runs. No Generate button, no dialog. | Brings a pick report to 5 / 2 / 2 (section 5). |

## 2. Screen A: change history (USR-06, GRP-05, CMP-03, CTC-02, OU-02)

Grid: Name · Change (chip with glyph + word) · Attributes changed (first two, "+n") · Domain · Changed at (Deleted preset: "Deleted at", shown "on or before …") · Basis · Observed at (Deleted: State). Header, in order: history start per covered domain; the three hidden counts, each with its own **Show** ("3,412 automatic updates hidden", "2 credential events not shown", "41 permission changes not shown"); the "No Changed by" note with the reason (rule 6). Chips switch the two opt-in kinds on (rule 2).

Row detail pane, by kind (all shown in the preview, `shots/changes-*-detail.png`):

| Kind | Pane content |
| --- | --- |
| Edited | When (changed at + Basis, observed at, gap in minutes, "several changes between two observations show as one"); a table of attribute name, originating time, version; "Names only, old and new values are not recorded". Who: "not recorded by AD". Object: logon name, domain, OU path, full DN (mono, wraps), Open object, Copy link. |
| Membership changed | "+1,204 added / −8 removed", the first 60 names with "Show 60 more", "37 members are outside your scope: counted, not named" (rule 4, 8). Handles a 3,000-member group because the list is paged inside the pane. |
| Credential event | "A password was changed or reset", never a value (rule 2). |
| Permissions changed | "Metadata cannot say admin edit vs inheritance/SDProp; no descriptor was read" (rule 2). |
| Removed (Deleted preset) | Deleted at "on or before", Basis "observed"; name and OU "last seen by activeDIQ"; State "Removed (restore status unknown)"; Restorable until "Unknown" with the reason (`noSuchObject` is not proof, rule 7). No Restore button. |
| Through activeDIQ | The one case with an actor: "Changed by ana.kowalska through activeDIQ" linking the operation (rule 6). |

**States.** Default (214 rows) · **empty** ("No user changes in the last 7 days. History for corp.example covers 2026-09-14 to now, so this is a real none, not a gap", with Widen to 30 days and Show automatic updates) · **error** ("could not be read", ref, retry, nothing partial shown) · **partial coverage** (2 of 3 domains: a warn banner, rows whose Basis is "whenChanged · DC-EMEA2" carry a chip, and a coverage table says apac "Not yet synced … is not reported as no changes", rule 5) · **12,408 rows** (virtualised; 17 DOM rows at any time; the pane works at row 12,000) · loading (skeleton, `role=status`) · Deleted preset.

## 3. Screen B: account policies with deltas (SYS-01, E-S2)

One table: the **domain policy pinned first as "Baseline"**, then every PSO by precedence. The two ME presets are a three-way switch, default **Both** (Password Policy / Account Lockout Policy narrow the columns; the URL carries `&preset=`). Each PSO cell reads `value ▲ +12`; the last column totals "5 stricter · 1 weaker". Direction rules are in the preview script and shown to the admin in the legend: longer length, longer history, longer min age, complexity on, shorter max age, lock-out threshold lower and duration longer are stricter; reversible encryption on is weaker; **max age 0 ("Never") and threshold 0 ("Never locks") count as weaker** (the zero is the loosest value, not the smallest). Whether those readings match `ad-expert`'s are listed under open items.

Applies-to column: "41: svc-sql01, svc-backup …" (count, then the first two). The pane: setting / domain / this policy / difference table; **precedence ties flagged** ("Same precedence as PSO-Finance. Which one wins for a user is shown per user, not here", spec rule 2); the direct targets list (first 40, paged), with the line "direct targets, not the resultant set"; a link to USR-05 with the "Policy source" filter. The table never claims a per-user result.

**States.** Default · **None exist** (blue info note: "No fine-grained policies exist. Read succeeded at 14:02", a real zero, with the domain row only) · **Unreadable** (red banner naming the container, the reason and "Users may be governed by policies not shown here", plus the right to grant; the domain row stays; **never** "no fine-grained policies", rule 3) · **Partial coverage** (1 of 2 domains readable: the unreadable domain gets its own baseline row labelled "fine-grained policies not readable") · **10,240 rows** (stress only: a real forest has dozens; the table is the same virtualised grid so it does not break) · loading. A 3,000-member target group is one row in the pane, the group, never its members.

## 4. Screen C: per-DC replication grid (SYS-03)

Header: "Read from 5 of 6 DCs" (green check when complete, warn when partial, red when none), then the thresholds line with **edit**, and "At risk is an indicator, not a detection". Status chips double as filters with counts (All, Failing, Warning, Healthy, Not reported). Grid, one row per destination DC x partition x partner, **sorted worst first**: Status (glyph + word) · Domain controller · Partition · Partner (source) · Last attempt · Last success · Failures · Last error (code + text, mono code) · Lingering-object risk ("At risk" / "No indication" / "Not reported"; the word "detected" appears nowhere) · Read at. Above the grid, the pinned band **"Did not answer (n)"** with a row per unreachable DC and the connect error.

Pane: link facts, last success with a human "190 d ago", the error code and Microsoft's meaning, a "What it means" slot, the lingering-object sentence. **E-S3 wording** (what the error means and what to do) is `ad-expert`'s and needs a source per line (spec §7.3.7), so the preview shows the meaning only and says so; no remedy text is invented here.

**States.** Default (6 of 6) · **5 of 6** (DC-EMEA2 pinned, the note says its partners may look healthy from their side only) · **0 of 6** (red, "This is not no problems") · **No DCs in scope** ("not healthy", a real empty) · **100-DC cap** (138 in scope, 100 read, 38 "not read", "Narrow the scope") · **10,240 rows** · loading. Freshness is on screen: "read 14:02, next read allowed after 15:02 (1 h floor, §8.4)".

## 5. Picker budget (spec §11)

Target ≤ 5 / 2 / 2 (interactions / typed fields / screens) for a report that requires a pick. Measured on the preview, **Picker budget › Live**, by driving it with Playwright (`shots.mjs`): `/`, type "manager", Enter (lands on the report with the picker focused, no Generate), type "ana", Enter (picks the highlighted manager and runs) = **5 / 2 / 2, counter output `{"i":5,"f":2,"s":2}`**. The plain run is 3 / 1 / 2 (2a Flow A). States in the preview: empty prompt with recent managers, typing, two people with the same display name (told apart by account and OU, never by order), no match ("Managers are users with at least one direct report"), result (picker collapses to a chip; **M** reopens it). Applies to Manager Based Users (USR-12), Logon Hour parameters, Empty/Duplicate attribute (USR-11, CMP-04).

## 6. Task-time comparison

Counting follows benchmark §1.2 ([top-admin-tasks-benchmark.md](../specs/top-admin-tasks-benchmark.md)): click, key or typed field = 1; drop-down = 2. ME's run is the benchmark's pattern for a report ([T19](../specs/top-admin-tasks-benchmark.md): Reports tab, category menu, report name, Generate = 4 [doc]; a domain is preselected = 0 [demo pattern]; an object picker is 5 [inferred]). ME's content of these particular reports is `[UNVERIFIED]` where marked: T-1120 (F1) re-measures them, and **no new time is claimed here** (the stopwatch re-measure is the ux-review job).

| Job | ME steps (I) | activeDIQ steps (I) | Note |
| --- | --- | --- | --- |
| Who was deleted last week, and what was their OU | Reports, User Reports, Recently Deleted Users, Generate = 4 [doc]; the date range default is `[UNVERIFIED]` | `/`, type, Enter = **3**; list shows OU, Deleted at, State | 7-day default, no Generate |
| What exactly changed on one user (attribute names, time, basis) | Run Recently Modified Users (4) then no per-row detail documented `[UNVERIFIED]` | **3 + 1** (Enter on the row opens the pane) | Added step is the pane; its content (attributes, version, basis) has no ME counterpart on its page `[ME-HELP]` |
| Why is a group's membership different (who was added) | Group report run (4) + member report run per group `[inferred]` | **3 + 1**, names in the pane | Counts per period; observation-based, stated |
| How do my PSOs compare with the domain policy | Two reports "Password Policy", "Account Lockout Policy": 2 x 4 = 8 [doc: two names]; whether PSOs appear `[UNVERIFIED]`; deltas by eye | **3** for both presets, deltas on screen; +1 for a PSO's targets | E-S2 |
| Which DCs are not replicating, and the error | Reports, Other Reports, DC Replication Status, pick DC(s) `[UNVERIFIED]`, Generate; error detail link +1 | **3** (worst first, unreachable DCs pinned); +1 for the pane | "Not read" is on screen |
| Run a pick report (Manager Based Users) | 4 + 5 (object picker) = **9** | **5** | -4 (-44%) |

## 7. Accessibility

Contrast is computed from the token values in both themes (all pairs used): warn on surface 7.2 (light) and 9.5 (dark), warn on warn tint 6.1 / 7.9, crit on crit tint 5.6 / 7.0, ok on ok tint 6.0 / 7.7, muted on muted tint 6.1 / 6.9, signal on signal tint 5.5 / 6.6, secondary text on tints at least 7.0. Every status is glyph + word, every delta is glyph + number with an `aria-label` ("stricter than domain"). The grid is one tab stop with arrow-key movement; the pane is a labelled `aside`, not a dialog, so it does not trap focus; Esc closes it. Loading uses `role=status`. The combobox uses `role=combobox` + `listbox`. **Not yet run: axe on the preview** (the production stories get it in the build tickets).

## 8. Component gaps (to `component-designer`, nothing invented in tokens)

1. **DetailDock** (docked, non-modal, prev/next, deep-linked row, Esc): the 2a prototype uses a modal Sheet for details; this is its non-modal sibling.
2. **DeltaCell** (value + glyph + number + accessible word, direction supplied by the screen).
3. **PinnedBand** (a labelled rowgroup above a DataGrid body that is not part of the sort) for "Did not answer".
4. Horizontal scroll with a **sticky name column** on wide grids (the preview scrolls the whole grid; with the pane open SYS-01 needs it). Not built in the preview.

## 9. Open items

- **ad-expert**: confirm the direction table for PSO deltas (lock-out duration "until admin unlocks" as strictest; observation window longer = stricter), and supply the E-S3 wording with sources. Until then ship the deltas; if a direction is unconfirmed, show "differs" (no glyph colour).
- **Sample status thresholds** (1 h / 24 h) and the 180 d tombstone lifetime in the preview are the spec's `[PROPOSED]` values.
- **Unverified in the preview**: nothing on screen is a real ME or AD result. Error texts 1722, 8524 and 8453 are the standard Windows messages used only as sample.
- The PSO "Applies to" column shows direct targets only; a resultant-policy column is out of scope (spec §7.1.2).

## 10. Follow-up tickets

Created in backlog: one `frontend-engineer` ticket per screen (A, B, C including the picker) and one `component-designer` ticket for gaps 1 to 4. Tickets: T-1513 (screen A), T-1514 (screen B), T-1515 (screen C and picker), T-1516 (components).

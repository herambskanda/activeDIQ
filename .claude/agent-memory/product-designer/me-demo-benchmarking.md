---
name: me-demo-benchmarking
description: How to benchmark ManageEngine flows (read-only Playwright on the public demo, counting rules, honest ties) — craft lessons from T-0008
metadata:
  type: feedback
---

Read-only Playwright walks of demo.admanagerplus.com work well for ME step counts and indicative waits; never submit anything on the shared demo.

**Why:** T-0008 needed sourced step counts; docs alone left gaps, and the demo gave screenshots plus real page-load times (dashboard 23.8 s, help-desk console 14.5 s).

**How to apply:**
- ME pages duplicate links in hidden menus — use `getByText(...).filter({ visible: true })` or the last visible match; help-console rows are not `<tr>`, locate buttons by bounding box.
- Demo waits are network-distance numbers: show them separately from the KLM model and block external use until re-measured on a local install (see [[task-time-counting]]).
- Use conservative, unified counting rules (dropdown = 2, defaults = 0, file picker = 1 screen + 2, shortcuts priced as clicks) so the comparison never flatters us.
- State ties honestly (T05 LAPS, T07 templated joiner, T12 were parity on clicks) and say where the win is instead (waits, previews, undo). Justify every added step (caller verification, reveal reason).
- Review round 1 rejected v1 for: a time formula the per-task figures didn't follow, untagged ME steps that didn't add up to their totals, and a competitor claim taken from the in-product hint rather than ME's format doc. To prevent this: give every step an I/F/S count and a [demo]/[doc]/[inferred] tag; ship a re-total script (klm.py) next to the doc; quote competitor text in full; send AD-semantics statements to ad-expert first.
- After rewriting a doc from notes, check for lost sources: diff the old version's URLs against the new one (`comm -23`).
- Review round 2 rejected v2 for three things. First, a ME path longer than the one our own screenshot shows: me-12's hint allowed comma-separated names, so no CSV was needed. Re-read every captured hint against the counted flow. Second, design states that broke the threat model: an escrowed BitLocker copy and a batch key export. Check TM-A7 / TM §7.4 / SP §3.7 before writing any state that touches a secret. Third, an example row with fields the source cannot supply: event 4729 has no workstation and no tool. Check the event or attribute field list before writing sample rows.

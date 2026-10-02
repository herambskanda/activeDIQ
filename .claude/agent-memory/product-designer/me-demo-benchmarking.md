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

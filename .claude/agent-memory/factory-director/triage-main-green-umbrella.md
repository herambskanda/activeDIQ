---
name: triage-main-green-umbrella
description: A "main passes make ci" umbrella ticket that keeps re-blocking on new causes is a bad cut — re-scope ACs to the pre-merge ratchet gate
metadata:
  type: feedback
---

When a ticket blocks again and again on "make ci passes on main" because new red causes land
faster than it can merge, stop unblocking it to chase them. Re-scope it (and every ticket blocked
on it) to: merge main, own targeted checks pass, `factory premerge T-…` shows no new finding.
Cancel per-cause tickets that duplicate a fix already sitting on its branch.

**Why:** T-0696 blocked five times between 2026-10-29 and 11-01. Each cycle cost a 2-hour
`make -k ci` and found 4–9 new P0 causes, while its own fixes (e.g. 7ed450770) never merged, so
workers re-filed them as duplicates (T-1171). T-0531/T-0541 sat a week on a tests-only or empty
diff. (T-1186)

**How to apply:** In triage, compare a main-red ticket's block history: a second "new causes
outside scope" block is the signal. Fix the leak at the gate (T-1001), not by umbrella tickets.
Related: [[triage-blocked-on-another-ticket]], [[triage-merge-conflict-blocks]].

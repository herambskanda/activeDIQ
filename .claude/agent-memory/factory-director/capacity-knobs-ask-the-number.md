---
name: capacity-knobs-ask-the-number
description: CEO sets capacity numbers (slots, run cap) — ask for the number, never pick a cautious one; numbers in an answer note override the option label
metadata:
  type: feedback
---

When the CEO says "we need to change X" about a throughput or spend setting (parallel slots, daily run
cap) and gives no target, ask for the target in one line, with a recommended value. Don't choose a
conservative number yourself.

**Why:** on 2026-10-02 the CEO asked to lift the 2-slot limit. I set 4 "safely" and they corrected it to
"i wanted 6 slots". Earlier, asked about the 60/day cap, they answered 300. They lean towards more capacity,
and they treat the number as theirs to set.

**How to apply:** the AskUserQuestion uses the real headroom data (cores, RAM, MB per worker, $ per run)
and puts the higher value first when the data supports it. Apply the answer at once; config reloads
live, no restart needed.

**Answer notes override option labels.** On D-0016 (2026-11-01) the CEO picked a ("held work in 1 slot")
but wrote "Resume M1/lab in 5 slot; keep 1 slots for M2a". Apply the note's numbers as written, file a
notice that names the inversion, and give way when the split would leave slots idle (veto offered). The
dispatcher has no milestone split (`candidates.mjs`), so ticket it (T-1207) and bridge with priority.

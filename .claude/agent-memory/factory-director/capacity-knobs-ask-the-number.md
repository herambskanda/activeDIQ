---
name: capacity-knobs-ask-the-number
description: When the CEO asks to change a capacity/spend knob (slots, run cap) without a number, ask for the number in one line — don't pick a cautious value
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

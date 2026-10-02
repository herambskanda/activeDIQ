---
name: plan-sprint
description: CEO command — have the project manager groom the backlog now — make the next tickets ready in priority order — and report the plan in eight lines or fewer.
disable-model-invocation: true
context: fork
agent: project-manager
---

# /plan-sprint

Factory state now:

!`factory/bin/factory status 2>&1`

!`factory/bin/factory ticket list --status ready 2>&1`

1. Load the `ticket-craft` skill and run its **Grooming** procedure (§9) in full. This is an
   on-demand run, so there is no meta ticket to advance.
2. Log the run with
   `factory/bin/factory event --actor project-manager --kind ticket "plan-sprint: <n> made ready, <n> split, <n> new"`.
3. Return the plan in **eight lines or fewer**:
   - the active milestone and its done/total;
   - the tickets now ready, in order, as ID · title · owner · priority, on up to 4 lines;
   - the critical path in one line;
   - risks or anything that needs the director or the CEO.

---
name: factory
description: CEO command — show the factory's status in six lines or fewer — running or not, what needs the CEO, what is running, milestone progress, risks.
disable-model-invocation: true
allowed-tools: Bash(factory/bin/factory:*)
---

# /factory

Live status:

!`factory/bin/factory status 2>&1`

Report in **six lines at most**, in this order. Use only the facts above, and leave out any line
with nothing to say.

1. **Factory**: running, paused (with the reason) or stopped; runs today against the cap; any
   rate-limit backoff.
2. **Needs you**: the count of pending decisions and open action items, then the single most
   urgent one by ID and title. Say "nothing" when there is none.
3. **Running**: each active worker, as ticket · role · stage.
4. **Milestone**: the active milestone, done/total, and its status.
5. **Risk**: blocked tickets or anything stuck, if any.
6. The board: http://127.0.0.1:4747. Add "`/decide` to answer" if decisions are pending.

If the output above is an error or says stopped, say so in one line and offer `/factory-up`.
If the error comes from the CLI itself, suggest `factory/bin/factory doctor`.

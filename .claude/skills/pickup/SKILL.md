---
name: pickup
description: CEO command — resume work from the latest handoff (for a ticket, a session, or the newest overall), verify the state, and continue.
argument-hint: "[ticket-id | session-id]"
disable-model-invocation: true
allowed-tools: Bash(factory/bin/factory:*), Bash(git status:*), Bash(git log:*), Bash(ls:*)
---

# /pickup

Newest handoffs:

!`ls -t factory/handoffs/*/*.md 2>/dev/null | head -5`

1. Choose the handoff. With `$0`, run `factory/bin/factory handoff latest $0`. Without it, take
   the newest file above. If there are none, say "No handoff found" and stop.
2. Read it whole, then follow the `handoff` skill's **Resume** steps: verify with
   `git status`, `git log --oneline -5` and its "How to verify" commands. Where reality
   differs from the handoff, reality wins.
3. Tell the CEO in two lines: what is being resumed, and the first next step. Any divergence
   found goes on the ticket as a note.
4. Continue at "Next steps" #1.

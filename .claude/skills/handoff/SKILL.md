---
name: handoff
description: Write a handoff so a fresh session can continue without re-deriving anything — on a 60/72/80 % context warning, before /clear, or when stopping mid-work. Also covers resuming from one. /handoff writes one for the current work now.
argument-hint: "[ticket-id]"
---

# Handoff — the 300k rule

Every session stays under a **300k-token working context** and never stops abruptly. The
`PostToolUse` hook injects a warning once per threshold. Act on it immediately.

| Context used | Do |
| --- | --- |
| < 60 % (180k) | Normal work. |
| ≥ 60 % (180k) | Plan the wrap-up. Pick the next natural stopping point, stop opening new files, and delegate searches to `Explore`. |
| ≥ 72 % (216k) | **Checkpoint now.** Finish the current atomic step only: a test passing, a file complete, a commit made. Then write the handoff (below), add a ticket note, and end with `RESULT: handoff`. |
| ≥ 80 % (240k) | **Critical.** Start nothing new. Write the handoff immediately, even mid-step, and record exactly where the half-done step stands. |

At ≈250k (the 300k window minus Claude Code's reserve), native auto-compaction runs as the last resort. The hooks snapshot state and re-inject
the latest handoff, but that snapshot is mechanical. A written handoff is always better.

## Write one

1. Commit finished work on the ticket branch (code types). Leave nothing half-done uncommitted
   unless the handoff names the exact file and state.
2. Create the file from `factory/templates/handoff.md`:
   - Ticket work: `factory/bin/factory handoff new <ticket> --by <role>`. It prints the path and
     sets `handoff.pending`.
   - No ticket (an interactive session): `factory/bin/factory handoff new session-${CLAUDE_SESSION_ID} --by factory-director`.
     If the CLI refuses a non-ticket ID, copy the template to
     `factory/handoffs/session-${CLAUDE_SESSION_ID}/<YYYYMMDD-HHMMSS>.md` yourself.
3. Fill every section. Write `none` where a section is empty. Delete the template comments.
4. `factory/bin/factory ticket note <ticket> --by <role> "Handoff at <n>k: <path> · next: <step 1>"`
5. End: workers print `RESULT: handoff — <where it stands>`. Interactive sessions, see below.

## The bar

A fresh session continues from the handoff **alone**, without re-reading what you read or
re-deciding what you decided.

- **Goal**: the outcome of this stage, not the history.
- **State right now**: what works, and what is half-done, by exact file and function. Whether
  the build and tests are green.
- **Next steps**: ordered and concrete. "Add the `escapeRdnValue` call in `dn.ts:88`, then
  run `make test-dn`" is a next step. "Continue the DN work" is not.
- **Decisions made and why**: every choice a successor might otherwise reopen, one line each.
- **How to verify**: exact commands with the expected result, e.g. `npm test -- dn` → 14 passing.
- **Traps**: misleading errors, dead ends, things that look right but are not. This section is
  the most valuable one. Never leave it as a token `none` if anything cost you time.
- Paths over prose. No pasted file contents. Aim for 40–80 lines.

## Sessions

- **Headless worker**: the dispatcher starts a fresh session from your handoff. Just end.
- **Interactive (`/handoff`)**: write the handoff for `$0` if a ticket was given. Otherwise use
  the ticket you are on, or the session key. Then tell the CEO in one line: the path, and
  "run `/clear`, then `/pickup`".
- **Subagent**: do not write a handoff file. Wrap up and return your results, with what is
  unfinished, to the parent, which owns the handoff.

## Resume (`/pickup`, or a continuation worker)

1. Read the handoff: `factory/bin/factory handoff latest <ticket|session-id>`.
2. **Verify state before trusting it**: run `git status`, `git log --oneline -5`, then the
   "How to verify" commands. If reality differs from the handoff, reality wins. Note the
   difference on the ticket.
3. Continue at "Next steps" #1. Do not re-explore what the handoff already settled.

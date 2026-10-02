---
name: garden
description: CEO command — have the factory director garden memory now (merge, prune, archive, budget check) and report the changes in three lines or fewer.
disable-model-invocation: true
context: fork
agent: factory-director
---

# /garden

Budgets now:

!`wc -l knowledge/memory/*.md CLAUDE.md .claude/agent-memory/*/MEMORY.md 2>/dev/null`

1. Load the `memory` skill and run its **Weekly gardening** procedure in full. This is an
   on-demand run, so log the event and skip advancing a ticket.
2. Return **three lines or fewer**: the files changed with their line counts before and after;
   the entries merged, archived and added; and any missed CEO preference recorded or
   rule-ticket filed.

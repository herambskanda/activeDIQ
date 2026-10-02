---
name: digest
description: CEO command — have the project manager write today's digest from factory state and print its five lines.
disable-model-invocation: true
context: fork
agent: project-manager
---

# /digest

Today's facts:

!`factory/bin/factory digest --json 2>&1`

1. Load the `status-digest` skill and write today's
   `factory/reports/digest-YYYY-MM-DD.md` from the facts above, plus the commands that skill
   lists. If today's file already exists, update it.
2. Commit the file by path.
3. Return **only the five lines**: Shipped, In progress, At risk, Needs you, Next.

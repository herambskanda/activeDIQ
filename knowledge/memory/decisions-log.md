---
title: Decisions log
updated: 2026-10-02
budget: 120 lines
---

# Decisions log

Newest first. `date · who · decision · why/source`. CEO decisions also live on the board as D-ids;
architecture decisions as ADRs in knowledge/development/decisions/. Roll entries older than the
current milestone into archive/ when this file nears its budget.

- 2026-10-02 · factory · Built-in `Explore` overridden by a project agent on Sonnet/high, because the built-in defaults to Haiku (policy forbids). (.claude/agents/Explore.md)
- 2026-10-02 · factory · Workers are headless `claude -p --agent <role>` sessions launched by a deterministic dispatcher; code tickets get their own git worktree; the dispatcher merges after QA. (factory/README.md)
- 2026-10-02 · factory · Factory Board is a local web app (127.0.0.1:4747) over file-based state; macOS notifications when the CEO is needed. (factory/OPERATING-MODEL.md §1)
- 2026-10-02 · factory · Knowledge base follows the UEM conventions (frontmatter, status ladder, sourcing, three-rung ADR ladder). (knowledge/README.md)
- 2026-10-02 · CEO · 300k-token context budget per working stretch with graceful handoffs. (kickoff brief)
- 2026-10-02 · CEO · Model policy: Opus medium/high (xhigh/max only for hard escalations); Sonnet high/xhigh; no Haiku. (kickoff brief)
- 2026-10-02 · CEO · Operating model: the CEO answers only directional questions; the factory decides the rest and demos each milestone. (kickoff brief)

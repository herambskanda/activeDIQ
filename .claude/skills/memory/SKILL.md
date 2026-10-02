---
name: memory
description: Write, prune and garden the factory's hot memory (knowledge/memory/) and agent-scoped memory. Use when the CEO decides or prefers something, a lesson or convention emerges, product state changes, a file exceeds its budget, or for weekly gardening.
---

# Memory

Memory is small and curated, and agents read it on demand. Each line has to earn its place:
it should save a future session time or stop it from asking the CEO again.

## Tiers

| Tier | Where | Loaded | Budget |
| --- | --- | --- | --- |
| Constitution | `CLAUDE.md` | Always | ≤ 150 lines |
| Hot memory | `knowledge/memory/*.md` | Index always; files by relevance | ≤ 120 lines per file |
| Knowledge base | `knowledge/**` | Never preloaded; targeted reads or `Explore` | Unbounded |
| Agent craft | `.claude/agent-memory/<agent>/MEMORY.md` (roles with `memory` enabled) | By that agent | ≤ 60 lines |

Working state (tickets, runs, handoffs) is not memory. It lives behind the `factory` CLI.

## Write triggers → file

| Trigger | File | Writer |
| --- | --- | --- |
| The CEO answers a decision, gives feedback, states a preference or rejects something | `ceo-preferences.md` (the generalisable taste or priority) and `decisions-log.md` (the decision) | `factory-director` in triage |
| A major factory decision: an accepted ADR, a stack choice, a process change | `decisions-log.md` | Its owner |
| A trap that would cost a future session 15+ minutes | `lessons.md` | Whoever hit it |
| A convention adopted (naming, layout, a commit rule) | `conventions.md` | Whoever adopted it |
| The product's state changes materially: a milestone, a module live, a pivot | `state-of-the-product.md` (rewrite the snapshot, do not append) | `factory-director` |
| A term an agent had to look up | `glossary.md` | Anyone |

## Entry format

One line per entry: dated, atomic, and linked to its source. Use a newest-first order in
`decisions-log.md` and a topic order elsewhere.

```markdown
- 2026-10-02 · D-0003 · Self-hosted first for v1; SaaS later on the same core — matches how ME customers buy. Source: D-0003 · [ADR-0002](../development/decisions/0002-deployment.md)
- Prefers dense, power-user layouts over spacious ones. (2026-10-05, D-0009 note "we're building for people who live in these tables")
- `ldapsearch` against the lab DC needs `-o ldif-wrap=no` or long DNs split mid-value and parse wrong. → always pass it. (2026-10-08, T-0014)
```

- Quote the CEO's own words when recording a preference. Never paraphrase it into something
  they did not say.
- Lessons follow the pattern "trap → what to do". A lesson with no action is trivia.
- Before adding, search the file. If an entry already says it, sharpen that entry instead of
  adding a near-duplicate.
- A missing file gets created with knowledge-base frontmatter (`title date updated status owner`)
  and a one-line purpose. The frontmatter counts toward the budget.

## Never in memory

- Secrets, credentials, lab passwords, tokens, hostnames of customer systems.
- Partner or customer names. Those belong only in `knowledge/business/partnerships/`, so link
  there instead.
- Transient task state ("working on T-0012", "next I will…"). That belongs in ticket notes and
  handoffs.
- Anything derivable from the code, the git history, an ADR or a spec. Link to the source; do
  not copy it.
- Unsourced claims about competitors.

## Over budget

The `PostToolUse` hook warns when a file passes 120 lines. Compress the file before you add the
new entry:

1. **Merge** entries that say the same thing in different words.
2. **Generalise** three specific entries into one rule, keeping the newest source link.
3. **Drop** entries that are now enforced mechanically (a lint rule, a hook, a CI check) or that
   are now in the code or an ADR. The rule's existence is the memory.
4. **Archive** superseded or old-but-true entries to `knowledge/memory/archive/<file>-<YYYY>.md`.
   Append there and never delete. For `decisions-log.md`, keep the latest ~60 lines hot.

## Weekly gardening (`meta` ticket, `factory-director`)

1. `wc -l knowledge/memory/*.md CLAUDE.md .claude/agent-memory/*/MEMORY.md`, then list
   every file over or near budget.
2. In each hot file, check every entry: still true, still sourced, not a duplicate, not
   derivable. Fix it, merge it, or archive it (rules above).
3. `ceo-preferences.md`: check this week's answered decisions and triaged feedback
   (`factory/bin/factory decision list --json`, `feedback list`). Record any preference that
   was missed.
4. `state-of-the-product.md`: make the snapshot match reality (milestones and tickets done).
5. `lessons.md`: a lesson recorded three times is a missing rule. File a ticket to enforce it
   (lint, hook, checklist item), then shrink the lesson to one line pointing at the rule.
6. Agent memory: every line must be role craft (how this role does its job better), within
   60 lines. Move project facts into hot memory and delete stale lines.
7. Commit the memory files by path: `docs(memory): weekly gardening (T-…)`.
8. `factory/bin/factory event --actor factory-director --kind memory "gardened: <n> merged, <n> archived, <n> added"`,
   then advance the ticket.

## Agent-scoped memory

`.claude/agent-memory/<agent>/MEMORY.md` holds **role craft lessons only**: how a
`code-reviewer` spots clone-and-adapt, or which Playwright waits are flaky for `qa-verifier`.
Facts about the product, the CEO or decisions go to hot memory, where every agent can see them.

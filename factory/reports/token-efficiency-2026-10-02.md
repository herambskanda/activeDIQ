---
title: Token efficiency — project start to 2026-10-02 12:40 IST
owner: factory-director
status: draft
updated: 2026-10-02
---

# Token efficiency: spent vs landed

Scope: every Claude Code session for this repo on this machine. That covers factory worker runs and their worktrees, plus interactive and bootstrap sessions. Sister repos and claude.ai chats are not included.
Sources: `factory/state/runs/*.log` (each run's `result` event: exact per-model usage and list cost) and
`~/.claude/projects/*activeDIQ*/**/*.jsonl` (transcripts; assistant usage de-duplicated by message id).
Worker transcripts match run logs to within 1% on cache-read and write tokens. Run logs report about 13% more Opus output than the transcripts do. That is probably thinking tokens, which the transcripts under-count.

## Spent

| Bucket | Output tokens (incl. thinking) | Input-side tokens (fresh + cache write + cache read) | Cost, list-price equivalent |
| --- | ---: | ---: | ---: |
| Factory workers (257 runs, 75 tickets) | 6.96 M | 523 M | $343 (exact) |
| Interactive + bootstrap sessions | 4.13 M | 547 M | ≈ $300 (estimated, ±35 %) |
| **Total** | **≈ 11.1 M** | **≈ 1.07 B** | **≈ $640** |

- Cache reads are 98% of all tokens processed and about 37% of worker cost. Cache writes are about 35% and output about 26%.
- One long interactive session (`38b8b49e`, the original bootstrap orchestrator) accounts for about $244. That is roughly 38% of all spend, and it is almost entirely re-read context (467 M input-side tokens).
- Thinking tokens are 2.8 M, or 40% of worker output.
- About 0.16 M Haiku output tokens show up in worker `modelUsage`. These are Claude Code's own background calls, not agents running on Haiku.

## Landed (on `main`, measured at roughly 3.6 chars per token)

| What | Lines | ≈ Tokens |
| --- | ---: | ---: |
| Product runtime code (internal, cmd, api, proto, migrations, web) incl. tests | ≈ 24 k | ≈ 0.22 M |
| CI guardrails and tooling (tools/fitness, tools/gen, analyzers, lab) | ≈ 28 k | ≈ 0.28 M |
| Generated code + test corpora | ≈ 12.5 k | ≈ 0.11 M |
| Knowledge (specs, ADRs, research, domain model) | ≈ 27 k | ≈ 0.81 M |
| Factory machinery (runtime, board, agents, skills) | ≈ 31 k | ≈ 0.86 M |

- Git churn is low: 115 k lines added and 2.9 k deleted across 194 commits. Rework happens inside sessions before anything is committed, not in git.

## Ratios

- Everything landed (≈ 2.2 M tokens) divided by everything generated (11.1 M) ≈ **20%**.
- Hand-written code (≈ 0.5 M) divided by everything generated ≈ **4.5%**. Divided by all tokens processed, it is ≈ **0.05%**.
- Code tickets (build, bug, chore, ops) took 30% of worker spend ($103) and 2.39 M output tokens. About 20% of that output survives as code.
- Spend per landed line of code is about $5 per 1 k lines when only code-ticket runs are counted, and about $12 per 1 k lines with all spend counted.

## Where the worker money went

- **By type:** spec 52% · chore 12% · research 10% · build 9% · ops 4.5% · bug 4% · other 8%.
- **By stage:** in_progress 76% · review 23% · qa 1%.
- **By role:** solution-architect 27% · factory-director 14% · security-architect 12% · product-designer 9% · devops 9% · backend 7%.
- **By model:** Opus (high) 64% · Sonnet (high) 33%.
- **Rework:**
  - Median of 4 runs per ticket.
  - Seven foundational specs and research tickets (T-0003 to T-0008) took 4 to 9 runs each, at $10 to $31 apiece.
  - 14 runs ended in a context handoff and consumed 24% of worker spend ($83).
- **Policy:**
  - 5 code-reviewer runs ran at `xhigh` and 3 project-manager runs ran on Opus `medium`. All of them were before the 06:08 effort-policy fix, and none came after it.

## Levers for the next iteration

1. **Short interactive sessions.** Clear or hand off at each milestone. A long-lived orchestrator pays for its whole context again on every turn.
2. **Get specs right the first time.** Load the review checklists (director memory: domain-model, ADR and blueprint checks) into the spec author's prompt, and cap review rounds at 2 before re-cutting. Spec rounds are the biggest single cost.
3. **Smaller tickets so they finish without a handoff.** A quarter of worker spend went to runs that ran out of context. Aim for tickets under about 150 k peak context.
4. **Leaner always-loaded context.** Smaller system and skill payloads per worker reduce both cache writes and cache reads, which together are about 70% of cost.
5. **Measure it every week.** Track $ per landed kLOC, runs per ticket and handoff share in the weekly review.

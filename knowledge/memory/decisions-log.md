---
title: Decisions log
updated: 2026-10-02
budget: 120 lines
---

# Decisions log

Newest first. `date · who · decision · why/source`. CEO decisions also live on the board as D-ids;
architecture decisions as ADRs in knowledge/development/decisions/. Roll entries older than the
current milestone into archive/ when this file nears its budget.

- 2026-10-02 · CEO · D-0004 Signature set of 5 beyond parity: ENH-01 task-first console, ENH-04 preview + undo, ENH-07 automatic updates, ENH-05 report builder, ENH-09 help-desk caller verification; plus switch enablers and Tier-0 proof. ENH-11 → ENH-22 → ENH-20 come next. (knowledge/business/strategy/enhancement-catalog.md §3)
- 2026-10-02 · CEO · D-0003 Platform: standalone now on UEM principles, house stack and skenzeriq design system; shared endpoint agent via module contracts; converge on a common core later. (product-strategy.md §11)
- 2026-10-02 · CEO · D-0002 Deployment: self-hosted first (Windows installer + Linux/Docker), SaaS-ready multi-tenant core from the first migration. (product-strategy.md §13 Q2)
- 2026-10-02 · CEO · D-0001 v1 replaces ADManager Plus first, with Graph-based Entra ID / M365 provisioning pulled into v1. ADSelfService/ADAudit parity follow in later milestones. (product-strategy.md §13 Q1)
- 2026-10-02 · factory · Parity matrix uses the research IDs (ADM/ADA/ADSS/RMP/M365/ERP/I360); there are no AD360-### IDs. Switch enablers without ME IDs are listed separately as must items. (knowledge/business/competitive-analysis/feature-parity-matrix.md)
- 2026-10-02 · factory · Repo-local git identity "activeDIQ Factory <factory@activediq.invalid>" for factory commits (no global identity was set). CEO may change it.
- 2026-10-02 · factory · Built-in `Explore` overridden by a project agent on Sonnet/high, because the built-in defaults to Haiku (policy forbids). (.claude/agents/Explore.md)
- 2026-10-02 · factory · Workers are headless `claude -p --agent <role>` sessions launched by a deterministic dispatcher; code tickets get their own git worktree; the dispatcher merges after QA. (factory/README.md)
- 2026-10-02 · factory · Factory Board is a local web app (127.0.0.1:4747) over file-based state; macOS notifications when the CEO is needed. (factory/OPERATING-MODEL.md §1)
- 2026-10-02 · factory · Knowledge base follows the UEM conventions (frontmatter, status ladder, sourcing, three-rung ADR ladder). (knowledge/README.md)
- 2026-10-02 · CEO · 300k-token context budget per working stretch with graceful handoffs. (kickoff brief)
- 2026-10-02 · CEO · Model policy: Opus medium/high (xhigh/max only for hard escalations); Sonnet high/xhigh; no Haiku. (kickoff brief)
- 2026-10-02 · CEO · Operating model: the CEO answers only directional questions; the factory decides the rest and demos each milestone. (kickoff brief)

---
title: Knowledge Base Index
date: 2026-10-02
updated: 2026-10-02
status: accepted
owner: heramb
---

# Knowledge Base

This is not documentation. It is the **knowledge base** for activeDIQ — the durable context that
the CEO and the factory's agents read before doing anything. Conventions are shared with the UEM
project (`../UEM/knowledge/README.md`) so knowledge can move between skenzeriq products.

Rule of thumb: if a fact only lives in a chat log or in someone's head, it is not knowledge yet.

## Layout

```
knowledge/
├── memory/            HOT memory: small, curated, budgeted (≤120 lines/file) — see CLAUDE.md
│   └── archive/             rolled-off memory entries
├── business/          WHY we build, WHO we sell to, WHAT the market does
│   ├── strategy/            north star, positioning, USPs, pricing & packaging
│   ├── market-research/     per-competitor deep dives (ManageEngine products, feature inventories)
│   ├── competitive-analysis/ landscape, feature-parity matrix, battlecards
│   ├── partnerships/        partner/customer profiles — the ONLY place partner names may appear
│   ├── licensing/           open-source licence register
│   ├── scoping/             scope proposals, MoSCoW, milestone scope locks
│   └── service/             proposals, SOWs, SLAs, migration playbooks, service SOPs
├── product/           WHAT we build, precisely
│   ├── prd/                 one PRD per module/epic
│   ├── specs/               functional + API + data-model specs, UX flows
│   ├── design-system/       activeDIQ's own design system and brand (D-0005)
│   └── datasheets/          customer-facing one-pagers, battlecards, RFP answers
└── development/       HOW we build it — the agent working set
    ├── architecture/        system architecture, module contracts, deployment profiles, feasibility
    ├── decisions/           ADRs — numbered, one decision each
    ├── domain/              the domain model
    ├── standards/           coding standards, testing strategy, security baseline
    └── runbooks/            build, lab, release, demo-environment procedures
```

`development/` is the **agent working set**: an implementation agent should be able to read only
`development/` plus the referenced spec and have everything it needs. When business or product
context is needed to implement correctly, copy the relevant slice into `development/` and link
back. Duplication is cheaper than an agent that guesses.

## Conventions

**Frontmatter** on every file:

```yaml
---
title: Human readable title
date: 2026-10-02          # created
updated: 2026-10-02
status: draft | review | accepted | superseded
owner: heramb
---
```

**Status ladder.** `draft` → `review` → `accepted`. Nothing is `accepted` until a human has read it
end to end. `superseded` files stay in place with a link to their replacement.

**Sourcing.** Any non-obvious external claim carries an inline source URL. Anything unverified is
tagged `[UNVERIFIED]`; anything not yet researched is `[TODO]` — never a confirmed absence.
Comparative claims about competitors must be factual, sourced and dated: they end up in RFPs.

**ADRs** live in `development/decisions/NNNN-short-title.md` (Context / Decision / Alternatives /
Consequences / Fitness function) on a three-rung ladder:

| Rung | Meaning |
| --- | --- |
| `proposed` | Drafted. Not binding. |
| `ratified` | Signed off (CEO for strategic forks; factory-director for technical decisions, with a notice to the CEO). **Binding on design.** Amendments allowed; reversal needs a superseding ADR. |
| `accepted` | Ratified **and** its fitness function runs in CI. Immutable — supersede, never edit. |
| `withdrawn` | A proposal that was never adopted. Kept for the trail; never binding. |

**Feature IDs.** ManageEngine features carry stable IDs from the research documents:
`ADM-###` (ADManager Plus), `ADA-###` (ADAudit Plus), `ADSS-###` (ADSelfService Plus),
`RMP-###` (RecoveryManager Plus), `M365-###`, `ERP-###`, `AD360-###`. Specs and tickets reference
them so parity is traceable end to end.

**Naming.** `kebab-case.md`. No dates in filenames — that is what frontmatter is for.

## Reading order for a new contributor (human or agent)

1. `business/strategy/product-strategy.md` — the thesis in one file
2. `business/competitive-analysis/feature-parity-matrix.md` — what we must match and where we lead
3. `business/scoping/` — what we are building now
4. `../UEM/knowledge/development/legacy/patchiq-postmortem.md` — what we learned the hard way
5. `development/architecture/` and `development/decisions/` — how the system is shaped and why
6. The PRD or spec you are implementing against

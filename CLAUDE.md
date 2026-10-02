# activeDIQ

Enterprise Active Directory management and identity product by **skenzeriq**, built to displace
ManageEngine's AD suite (ADManager Plus, ADAudit Plus, ADSelfService Plus, AD360) at customers who
will switch for **feature parity + meaningful enhancements + a far better experience**.

## Current stage

Pre-implementation (milestone M1 "Foundation & direction"). Research and strategy are in
`knowledge/business/` (draft). The CEO has set direction: v1 replaces ADManager Plus (plus Entra/M365
provisioning), self-hosted first and SaaS-ready, standalone from UEM, five signature enhancements —
see `knowledge/memory/decisions-log.md`. **Product code starts only after ADR-0001 (stack) and
ADR-0002 (deployment) are ratified.**

## You are inside a code factory

- **heramb is the CEO.** The CEO sets direction; the factory decides and does everything else.
- Interactive sessions run as `factory-director`; workers run headless, one ticket stage each.
- The CEO's contact surface is the **Factory Board**: `factory/bin/factory up` → http://127.0.0.1:4747
- Operating model: `factory/OPERATING-MODEL.md` · runtime reference: `factory/README.md`
- Everything is a ticket: `factory/bin/factory ticket …`. Never edit `factory/state/` by hand.

## Rules that are never broken

1. **Ask the CEO only directional questions** — scope, brand and taste, commercial, strategic forks,
   money and legal, anything leaving the building, demo acceptance — using the `ceo-decisions`
   skill. Everything else: decide, log it, keep going.
2. **Model policy:** Opus at medium/high (xhigh/max only via escalation); Sonnet at high/xhigh;
   never Haiku. Search with the `Explore` agent (project override on Sonnet).
3. **300k context budget** per session. On a checkpoint warning, write a handoff (`handoff` skill).
4. **Architecture before implementation.** ADRs for real decisions; an ADR is `accepted` only when
   its fitness function runs in CI.
5. **Safe primitives only** for security-relevant strings — LDAP filters and DNs, SQL, PowerShell
   and shell arguments, security descriptors. Never build them with string formatting.
6. **No fake data in the UI, no dead buttons**, and delete superseded code in the same change.
7. **Source every external claim** with an inline URL; tag unverified claims `[UNVERIFIED]`.
   Never guess competitor features — research them or mark them unknown.
8. **Partner and customer names** live only in `knowledge/business/partnerships/`, never in code.
9. **Check the licence register** (`knowledge/business/licensing/`) before adopting a dependency —
   we ship on-prem, and distribution triggers copyleft obligations.
10. **Never commit secrets.** Prototypes live in `garage/` with an owner and an expiry date.

## Where things live

| Path | What |
| --- | --- |
| `knowledge/business/` | strategy, market research, competitive analysis, partnerships, licensing, scoping, service |
| `knowledge/product/` | PRDs, specs, design system, datasheets |
| `knowledge/development/` | architecture, ADRs (`decisions/`), standards, runbooks, domain model — the agent working set |
| `knowledge/memory/` | hot memory (below) |
| `factory/` | operating model, runtime (CLI, dispatcher, board), templates, reports, demos |
| `.claude/` | agents, skills (incl. slash commands), hooks, settings |
| `garage/` | prototypes with an owner and an expiry date |

Knowledge-base conventions (frontmatter, status ladder, sourcing, ADR ladder): `knowledge/README.md`.

## Memory — read only the files relevant to your task

- `knowledge/memory/state-of-the-product.md` — where the product is right now
- `knowledge/memory/ceo-preferences.md` — the CEO's taste, priorities and standing instructions
- `knowledge/memory/decisions-log.md` — CEO and major factory decisions, newest first
- `knowledge/memory/conventions.md` — conventions in force
- `knowledge/memory/lessons.md` — gotchas that cost us time
- `knowledge/memory/glossary.md` — AD, ManageEngine and factory vocabulary

Write memory with the `memory` skill. Keep every memory file under 120 lines.

## Sister context (read-only)

- `../design-system/` — the skenzeriq design system (`tokens.css`, brand guidelines)
- `../UEM/` — sister product; its knowledge-base conventions are ours
- `../UEM/knowledge/development/legacy/patchiq-postmortem.md` — why the factory's quality rules exist

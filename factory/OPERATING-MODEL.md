---
title: activeDIQ Code Factory — Operating Model
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
---

# activeDIQ Code Factory — Operating Model

The factory is a company made of Claude Code agents. **heramb is the CEO.** The CEO sets
direction, makes the directional calls, and accepts or rejects demos. Everything else — planning,
building, testing, reviewing, documenting, packaging — is run by the factory, visibly, on the
**Factory Board**.

This document is the constitution of the factory. `CLAUDE.md` is its one-page summary; skills in
`.claude/skills/` are the detailed procedures; agents in `.claude/agents/` are the people.

---

## 1. The CEO contract

### 1.1 One contact surface

| Surface | What it is for |
| --- | --- |
| **Factory Board** — `factory/bin/factory up` → http://127.0.0.1:4747 | Everything: what needs you, what is happening now, progress, decisions, demos, the research library. Near-real-time (polls every few seconds). |
| **Terminal** — run `claude` in this repo | You are talking to the **Factory Director**. `/factory` shows status, `/decide` walks you through pending decisions, `/ceo-feedback` records feedback, `/demo` runs the latest demo. |
| **Notifications** | macOS notification when the factory needs you (a new decision, a demo ready, a blocker only you can clear). |

### 1.2 What the factory asks you — and what it never asks

The factory asks only **directional (Type 1) questions** — choices that are expensive to reverse
or that are matters of business judgement or taste:

1. **Scope and ambition** — which modules, how many enhancements beyond parity, what to cut.
2. **Brand and taste** — brand guidelines, UI style, video style, documentation style, tone.
3. **Commercial** — pricing and packaging, partner commitments, external timelines.
4. **Strategic architecture forks with business impact** — deployment model, platform strategy —
   always framed in business terms, never as a library choice.
5. **Money, accounts, legal** — paid services, cloud spend, external accounts, licences, contracts.
6. **Anything leaving the building** — proposals sent to partners, published docs or videos,
   partner demos.
7. **Milestone acceptance** — you accept or reject each demo.

Everything else is **Type 2** and the factory decides it: implementation and library choices
(subject to the licence register), refactors, test strategy, ticket breakdown, internal naming,
bug fixes, internal docs. Notable Type-2 decisions appear on the board as **"Factory decided"**
notices with a veto window — you can overrule, but you never have to act.

### 1.3 The decision-request quality bar

A decision request that reaches you must have: **one question**; **2–4 options**; a **concrete
preview** whenever taste is involved (a clickable mockup, a sample doc page, a storyboard or
15-second clip); a **recommendation** with the reason; **what is blocked** while it is open;
**reversibility**; and, for advisory requests, **the default and when it applies**.

- **Decision budget:** at most **3 open CEO decisions** at a time. Batch the rest.
- **Never ask** what the knowledge base, memory, or research already answers.
- **Learn the CEO:** every answer and every piece of feedback updates
  `knowledge/memory/ceo-preferences.md`, so the same kind of question gets asked less over time.

### 1.4 The factory does not stop for you

A pending decision blocks only the tickets that explicitly depend on it. Everything else keeps
moving. Decision kinds:

| Kind | Meaning | If you do not answer |
| --- | --- | --- |
| `directional` | Only you can make this call. | Dependent tickets wait; all other work continues. |
| `advisory` | The factory has a good default but your taste matters. | The recommended option applies after the default window (72 h). The board says so. |
| `notice` | The factory decided; you are being informed. | Stands unless you veto. |

### 1.5 Cadence

| When | What you get |
| --- | --- |
| Continuous | Board status: what is running, what moved, what needs you. |
| Daily | A five-line digest on the board: shipped, in progress, at risk, needs you. |
| Weekly | Milestone progress, risks, next week's plan, decisions made on your behalf. |
| Each milestone | A **demo**: a narrated video walkthrough, a live environment you can click through, a script mapped to the milestone goals, known limitations, and a feedback form. You accept, or say what to change. |

---

## 2. Organisation

The factory is organised like a company. Leads think; specialists build; quality gates verify.

| Agent | Dept | Owns | Model · effort |
| --- | --- | --- | --- |
| `factory-director` | Leadership | Runs the floor. The CEO's counterpart. Triage, priorities, decision requests, demos, unblocking. | Opus · high |
| `product-manager` | Product | PRDs and specs, parity mapping, acceptance criteria, backlog priority. | Opus · high |
| `project-manager` | Delivery | Breaks epics into tickets, plans sprints, tracks dependencies, writes digests, keeps the risk register. | Opus · medium |
| `solution-architect` | Engineering | Architecture, ADRs, module contracts, API and data-model design, fitness functions. | Opus · high |
| `product-designer` | Design | UX strategy, information architecture, flows, design direction, style options for the CEO. | Opus · high |
| `security-architect` | Security | Threat models, security reviews of sensitive changes, Tier-0 posture, compliance mapping. | Opus · high |
| `ad-expert` | Domain | Active Directory, Entra ID, Kerberos, GPO, Windows security semantics: advises and reviews. | Opus · high |
| `market-analyst` | Strategy | Competitive intelligence, positioning, pricing research, battlecards, parity matrix upkeep. | Opus · high |
| `service-manager` | Service | Partner proposals, SOWs, SLAs, onboarding and ManageEngine-migration plans, support SOPs. | Opus · medium |
| `principal-engineer` | Escalation | The hard problems nobody else could solve. Used only via the escalation ladder. | Opus · xhigh (max by director approval) |
| `backend-engineer` | Engineering | Services, domain logic, persistence, jobs. | Sonnet · high |
| `directory-engineer` | Engineering | LDAP/AD/Entra/Graph connectors, sync, change tracking, audit collectors. | Sonnet · xhigh |
| `windows-engineer` | Engineering | Windows-native components: DC agent, credential provider, password filter, services, installers. | Sonnet · xhigh |
| `api-engineer` | Engineering | OpenAPI contracts, endpoints, SDKs, the PowerShell module, webhooks. | Sonnet · high |
| `frontend-engineer` | Engineering | Application screens, state, data fetching, routing. | Sonnet · high |
| `component-designer` | Design-eng | Design-system components, visual polish, motion, accessibility. | Sonnet · high |
| `reporting-engineer` | Engineering | The report engine, queries, scheduling, exports, dashboards. | Sonnet · high |
| `devops-engineer` | Platform | Build, CI, packaging and installers, lab environments, release. | Sonnet · high |
| `test-engineer` | Quality | Unit, integration and end-to-end tests; fixtures; the AD test lab. | Sonnet · high |
| `code-reviewer` | Quality | Reviews every code change before QA. | Sonnet · xhigh |
| `qa-verifier` | Quality | Verifies acceptance criteria; UI/UX checks with screenshots; files bugs. | Sonnet · high |
| `docs-writer` | Product-ization | User and admin guides, API docs, SOPs, release notes. | Sonnet · high |
| `video-producer` | Product-ization | Demo and tutorial videos: script → recording → narration → edit. | Sonnet · high |
| `Explore` | Utility | Read-only context retrieval for any agent (project override of the built-in, which runs on Haiku). Returns conclusions with file paths, not dumps. | Sonnet · high |

---

## 3. Model and effort policy

| Model | Allowed effort | Use it for |
| --- | --- | --- |
| **Opus** | `medium`, `high` | Thinking work: research, strategy, product, architecture, design direction, security review, CEO decision preparation, planning. |
| **Opus** | `xhigh`, `max` | **Escalation only** — a genuinely hard, stuck problem. Requires an escalation ticket with justification; shown on the board with a 🔥 badge. |
| **Sonnet** | `high`, `xhigh` | Doing work: implementation, tests, reviews, docs, video, scouting. Never below `high`. |
| Haiku | — | Not used. The built-in `Explore` (Haiku) is overridden by a project agent of the same name on Sonnet. |

**Escalation ladder** (applied by the dispatcher and the director):

1. Owner at its default effort.
2. Same owner, effort raised one step (Sonnet `high` → `xhigh`; Opus `medium` → `high`).
3. `principal-engineer` (Opus `xhigh`) takes the problem with the full history.
4. Still stuck → the ticket is `blocked`; the director triages. Opus `max` only with director approval.
5. If the blocker is directional, money, access or taste → a CEO decision or action item.

`factory/bin/factory doctor` fails if any agent definition violates this policy.

---

## 4. The work system

### 4.1 Units of work

- **Milestone** (`M1`, `M2`, …) — a demo-able increment with a goal the CEO can judge.
- **Epic** (`E-001`, …) — a feature area or parity group, mapped to ManageEngine feature IDs.
- **Ticket** (`T-0001`, …) — a unit of work one agent can finish in one session (ideally well
  under the context budget). Everything is a ticket, including planning, triage, digests and
  memory gardening.

### 4.2 Flows

Workers never pick the next status themselves: they run `factory ticket advance` (stage done) or
`factory ticket reject` (send back with notes). The flow per ticket type decides the rest.

| Type | Flow |
| --- | --- |
| `build`, `bug` | ready → in_progress (owner) → review (`code-reviewer`; `security-architect` too if tagged `security-sensitive`) → qa (`qa-verifier`) → done (merged) |
| `test`, `chore`, `ops` | ready → in_progress (owner) → review (`code-reviewer`) → done (merged) |
| `spec` | ready → in_progress (owner) → review (`solution-architect`) → done |
| `design` | ready → in_progress (owner) → review (`product-manager`) → done |
| `docs`, `video` | ready → in_progress (owner) → review (`product-manager`) → done |
| `research`, `proposal`, `decision-prep`, `spike` | ready → in_progress (owner) → review (`factory-director`) → done |
| `meta` (grooming, triage, digest, gardening) | ready → in_progress (owner) → done |

`blocked` and `cancelled` are reachable from any state; only the director un-blocks or cancels.

### 4.3 Definition of Ready (all types)

A ticket is `ready` only if it has: a single clear outcome; acceptance criteria (Given/When/Then
for behaviour); an owner agent; links to the spec, ADR or research it depends on; dependencies
recorded; and no unanswered directional decision behind it.

### 4.4 Definition of Done (build types)

Acceptance criteria demonstrably met · tests written and passing · code review passed · QA passed
with evidence (test output, screenshots) · docs and the architecture map updated if anything
user-visible or structural changed · superseded code **deleted** · merged to `main` · the ticket
carries a two-line summary of what changed and why.

### 4.5 Limits

- WIP: `dispatcher.max_parallel` worker sessions (default 2).
- Daily cap on worker sessions (`dispatcher.daily_run_cap`) as a runaway guard.
- Rate-limit aware: on usage-limit errors the dispatcher backs off instead of retrying.

---

## 5. The quality system — built from the PatchIQ postmortem

The previous product (`patchiq`) was abandoned because blind AI iteration destroyed
comprehension. Every rule below exists because of a specific failure recorded in
`../UEM/knowledge/development/legacy/patchiq-postmortem.md`.

| PatchIQ failure | Factory rule | Enforced by |
| --- | --- | --- |
| Mental model lost; 12-agent audits needed to know what state the code was in | Architecture is written before it is implemented. A living architecture map (`knowledge/development/architecture/`) is updated by every ticket that changes structure. ADRs for every real decision. | DoD; `code-reviewer`; weekly comprehension check |
| A correct extension interface was designed, then bypassed | Extension points precede the first feature on their tier. An ADR is `accepted` only once its fitness function runs in CI. | `solution-architect`; CI fitness functions |
| Copy-and-adapt per variant instead of parameterise | "Parameterise, don't clone" is a review blocker. | `code-reviewer`; duplication check in CI |
| Security-relevant strings built by hand (SQL, shell, JWT), recurring | **Safe primitives only**: LDAP filter and DN builders, parameterised SQL, encoded PowerShell arguments, typed security descriptors. Raw construction is banned by lint. | Lint rules; `security-architect` review |
| Fabricated data hardcoded in the UI; dead buttons | **No fake data.** The UI renders only API data; fixtures live only in tests, Storybook and the demo seed. QA clicks every control on a changed screen. | `qa-verifier`; review checklist |
| One customer's names and topology leaked into shared code | Partner and customer specifics live only in `knowledge/business/partnerships/`. Never in code. | CI grep for partner names |
| Secrets committed | `.env*` ignored; secret scanning pre-commit and in CI; guard hook blocks secret-shaped writes. | gitleaks; `guard` hook |
| Exploration trees and AI-tooling dirs left in the main tree | Prototypes live in `garage/` with an owner and an expiry date. Factory runtime state is gitignored. Superseded code is deleted in the same ticket. | DoD; weekly tech-debt sweep |
| Multi-tenancy retrofitted | If the deployment model includes SaaS or MSP use, the tenant key is in the first migration. | ADR + fitness function |
| Capability asymmetry across platforms | Every capability spec states its platform matrix explicitly. | `product-manager`; spec template |

---

## 6. Context budget and handoffs — the 300k rule

Every working session — interactive, headless worker, or long-running agent — stays under a
**300k-token working context** and never stops abruptly.

| Context used | What happens |
| --- | --- |
| < 70 % (210k) | Normal work. |
| ≥ 70 % | Advisory: plan to wrap up at the next milestone in the task. |
| ≥ 85 % (255k) | **Checkpoint now**: finish the current atomic step, write a handoff, update the ticket, end the turn with `RESULT: handoff`. |
| ≥ 95 % (285k) | Critical: stop starting anything; write the handoff immediately. |
| 300k | Native auto-compaction (window pinned to 300k) is the last-resort safety net; the compaction hooks snapshot state and re-inject the latest handoff afterwards. |

A **handoff** is the minimum a fresh session needs to continue without re-deriving anything:
goal, current state, what is done, what is next (ordered), decisions made and why, files touched,
commands to verify, open questions, traps. Template: `factory/templates/handoff.md`.
For headless workers the dispatcher starts a **fresh session** from the handoff — a clean,
graceful compaction. Interactive sessions use `/handoff`, then `/clear` and `/pickup`.

Mechanics: a `PostToolUse` hook reads the session's token usage and injects the warnings;
`PreCompact` snapshots state; `SessionStart` (on `compact` and in workers) re-injects the handoff;
a `Stop` hook refuses to let a worker end without updating its ticket.

---

## 7. Memory — small, curated, and searched on demand

| Tier | What | Loaded | Budget |
| --- | --- | --- | --- |
| **Constitution** | `CLAUDE.md` — mission, rules, map, memory index | Always | ≤ 150 lines |
| **Hot memory** | `knowledge/memory/*.md` — CEO preferences, decisions log, lessons, conventions, glossary, current state of the product | Index always; files on demand, by relevance | ≤ 120 lines per file |
| **Knowledge base** | `knowledge/` — research, strategy, PRDs, specs, ADRs, runbooks | Never by default — retrieved by `Explore` or targeted reads | Unbounded, structured, indexed |
| **Working state** | `factory/state/` — tickets, decisions, runs, events; `factory/handoffs/` | Via the `factory` CLI only | Runtime |

**When to write memory** (the `memory` skill has the details):
- the CEO decides, prefers, or rejects something → `ceo-preferences.md` and `decisions-log.md`;
- a lesson that would save a future session 15 minutes or more → `lessons.md`;
- a convention is adopted → `conventions.md`;
- the product's state changes materially → `state-of-the-product.md`.

**Hygiene:** entries are atomic, dated, and link to their source. When a file exceeds its budget,
the writer compresses it before adding more (a hook warns). A weekly `meta` ticket gardens memory:
merge, prune, archive to `knowledge/memory/archive/`.

**Retrieval:** agents do not preload the knowledge base. They ask `Explore` a precise question and get
back a conclusion with file references.

---

## 8. Runtime — how work starts and stops

```
            ┌───────────────┐     answers, feedback,      ┌─────────────────────┐
  CEO ────► │ Factory Board │ ◄─── pause / resume ───────│  factory/state/      │
            │  :4747        │ ───► reads ────────────────►│  tickets, decisions, │
            └───────────────┘                             │  runs, events        │
                                                          └─────────▲───────────┘
            ┌──────────────────────────┐   launches / reaps          │ writes (via CLI + hooks)
            │ Dispatcher (factory run) │ ──────────────────────────► │
            │ deterministic, no LLM    │ ─► claude -p --agent <role> --effort <e> (worker)
            └──────────────────────────┘        └─► subagents (Explore, reviewers) as needed
```

- **Dispatcher** (`factory/bin/factory run`, started by `factory up`) — a small deterministic
  loop. Each tick: reap finished workers; apply defaults to expired advisory decisions; then
  fill free slots in this order: tickets in `review` → tickets in `qa` → continuations from
  handoffs → `ready` tickets (priority, then age) whose dependencies are done and whose
  decisions are answered → director triage (new CEO answers, feedback, blocked tickets) →
  backlog grooming by `project-manager` when fewer than three tickets are ready.
- **Workers** — headless `claude -p --agent <role>` sessions, one per ticket stage, in their own
  git worktree for code tickets. They receive the ticket, the latest handoff if any, and the
  factory protocol. They end with a `RESULT:` line; the ticket state is the source of truth.
- **Signals** — `pause` and `resume` from the board or CLI; `factory down` stops everything
  gracefully (running workers are asked to hand off).
- **Merging** — after QA passes, the dispatcher merges the ticket branch into `main`. Conflicts
  become a `chore` ticket for the original owner.
- **Interactive sessions** — the CEO's `claude` session runs as `factory-director`. It can do
  anything a worker can, and everything it does is logged to the board.

---

## 9. Productization and service

| Output | Owner | Pipeline |
| --- | --- | --- |
| User and admin guides, API reference | `docs-writer` | Diátaxis structure in `docs/`; screenshots from the running product; reviewed by `product-manager`. |
| Demo and tutorial videos | `video-producer` | Script → Playwright-driven recording → narration → ffmpeg edit → captions. Style chosen by the CEO once, then reused. |
| SOPs and runbooks | `docs-writer` (product), `service-manager` (service) | SOP template; every SOP rehearsed once against the lab before publishing. |
| Partner proposals, SOWs, SLAs | `service-manager` | Templates; every proposal goes to the CEO before it leaves the building. |
| ManageEngine migration playbook | `service-manager` + `product-manager` | Discovery questionnaire → inventory export → mapping → parallel run → cutover → hypercare. |

---

## 10. Rituals

| Ritual | Trigger | Owner |
| --- | --- | --- |
| Triage of CEO answers and feedback | Whenever new ones arrive | `factory-director` |
| Backlog grooming | Fewer than three tickets ready | `project-manager` |
| Daily digest | Once a day | `project-manager` |
| Weekly review, memory gardening, tech-debt sweep, comprehension check | Weekly | `project-manager`, `factory-director`, `solution-architect`, `Explore` |
| Competitive refresh | Monthly, or on a competitor release | `market-analyst` |
| Milestone demo | Milestone `demo-ready` | `factory-director` + `qa-verifier` + `video-producer` |

---

## 11. Where things live

```
CLAUDE.md                     constitution (always loaded)
knowledge/                    the knowledge base (UEM conventions)
  memory/                     hot memory (small, curated)
  business/                   strategy, market research, competitive analysis, partnerships, scoping, service
  product/                    PRDs, specs, design system, datasheets
  development/                architecture, ADRs, standards, runbooks, domain model
factory/                      the factory: operating model, runtime, board, templates
  state/  handoffs/           runtime (gitignored)
.claude/                      agents, skills, commands, hooks, settings
garage/                       prototypes with an owner and an expiry date
docs/                         customer-facing product documentation (later)
```

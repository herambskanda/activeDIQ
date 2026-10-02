# Factory skills

The factory's operating procedures. Each skill lives in `<name>/SKILL.md`, with its supporting
files beside it. **Process** skills load when the model needs them. **CEO commands** run only
when typed, in the CEO's `factory-director` session. The constitution is
`factory/OPERATING-MODEL.md`. The skills say how to carry it out.

## How the factory runs

| Skill | Purpose | CEO command |
| --- | --- | --- |
| `factory-protocol` | The worker protocol: ticket → context → plan → small steps → advance/reject/block + `RESULT` line | — |
| `ceo-decisions` | What goes to the CEO and what the factory decides; decision requests to the quality bar, with previews (`examples.md`) | — |
| `handoff` | The 300k rule: thresholds, writing a handoff, resuming from one | `/handoff [ticket]` |
| `memory` | Hot and agent memory: write triggers, entry format, budgets, weekly gardening | — |
| `ticket-craft` | Definition of Ready, sizing, Given/When/Then, parity IDs, priority, epic breakdown, grooming | — |
| `status-digest` | The daily five-line digest and report file; the weekly review | — |
| `demo` | Milestone demo: script, seed, record, package, present, feedback, acceptance (`script-template.md`) | `/demo [milestone]` |

## CEO commands

| Skill | Purpose | CEO command |
| --- | --- | --- |
| `factory` | Status in six lines or fewer, plus the board URL | `/factory` |
| `factory-up` | Start the board and dispatcher; warn if the repo has no commits | `/factory-up` |
| `factory-down` | Stop gracefully; workers hand off | `/factory-down` |
| `decide` | Walk through pending decisions as multiple choice and record the answers | `/decide [D-id]` |
| `ceo-feedback` | Record feedback against the inferred demo, ticket, doc or decision | `/ceo-feedback <text>` |
| `pickup` | Resume from the latest handoff after verifying state | `/pickup [ticket\|session]` |
| `plan-sprint` | Project manager grooms the backlog now (forked) | `/plan-sprint` |
| `digest` | Project manager writes today's digest (forked) | `/digest` |
| `garden` | Factory director gardens memory now (forked) | `/garden` |

## Craft

| Skill | Purpose | CEO command |
| --- | --- | --- |
| `feature-spec` | Writing PRDs and specs: platform matrix, parity mapping, acceptance | — |
| `competitive-intel` | Sourced research on ManageEngine and the market; keeping the parity matrix | — |
| `design-system` | Building UI on the skenzeriq tokens and components | — |
| `ux-review` | Reviewing screens and flows for usability, consistency and accessibility | — |
| `ad-engineering` | Active Directory, Entra ID, LDAP, Kerberos and GPO engineering practice | — |
| `api-design` | API contracts: OpenAPI, errors, paging, the PowerShell module, webhooks | — |
| `engineering-standards` | Coding standards, structure, the parameterise-don't-clone rule | — |
| `testing-playbook` | Test strategy, fixtures and the AD test lab | — |
| `security-baseline` | Safe primitives, Tier-0 posture, secrets, threat modelling | — |
| `adr` | Writing ADRs and their fitness functions | — |
| `review-checklist` | What `code-reviewer` checks before advancing or rejecting | — |
| `qa-verification` | Verifying acceptance criteria with evidence; clicking every control | — |
| `docs-style` | Voice and structure of user, admin and API docs | — |
| `video-production` | Demo and tutorial videos: script, recording, narration, edit | — |
| `sop-writing` | SOPs and runbooks, rehearsed against the lab | — |
| `service-proposal` | Partner proposals, SOWs, SLAs and migration plans | — |

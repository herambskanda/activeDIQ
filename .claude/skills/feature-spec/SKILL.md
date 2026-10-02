---
name: feature-spec
description: Write or review an activeDIQ PRD (knowledge/product/prd/) or feature spec (knowledge/product/specs/) — personas, JTBD, ManageEngine parity IDs, what we do better, flows, requirements, platform matrix, security, acceptance. Use for any spec ticket.
argument-hint: "[module or feature]"
---

# Feature spec

A PRD says **why and what** for a module. A spec says **exactly what** one feature does, so that
`solution-architect` can shape it and an engineer can build it without asking anyone. Owner:
`product-manager`. Spec tickets are reviewed by `solution-architect` (flow `spec`).

| Doc | Path | Template | One per |
| --- | --- | --- | --- |
| PRD | `knowledge/product/prd/<module>.md` | `templates/prd.md` | module or epic (e.g. `user-lifecycle`, `self-service-password`) |
| Spec | `knowledge/product/specs/<feature>.md` | `templates/spec.md` | feature one epic can deliver (e.g. `bulk-user-create-csv`) |

## 1. Before you write

1. **Scope.** Read `knowledge/business/scoping/` and `knowledge/memory/decisions-log.md`. If the
   module is not in a scope lock, stop: what goes in v1 is a CEO call (`ceo-decisions`, category
   1). Write the PRD as `draft` with `scope: proposed` and file or join the scope decision.
2. **Parity.** Find every ManageEngine feature this covers:
   - the matrix `knowledge/business/competitive-analysis/feature-parity-matrix.md` when it exists;
   - otherwise the inventories in `knowledge/business/market-research/manageengine-<product>.md`
     (§3 "Complete feature inventory"; IDs like `ADSS-001`).
   **Never invent an ID.** A feature with no ID yet → write `parity: [TODO] — <feature>` and
   file a `research` ticket for `market-analyst`. Never write "ManageEngine lacks X" unless the
   research says so with a source (`competitive-intel` §3).
3. **Pain and leapfrog.** Read the same file's "UX notes", "Weaknesses & gaps" and "Parity vs
   leapfrog" sections, `manageengine-ad-customer-voice-and-security.md`, and the personas in
   `knowledge/business/competitive-analysis/ad-management-market-landscape.md` §6.
4. **Feasibility.** Read the matching rows of
   `knowledge/development/architecture/build-feasibility/ad-technical-feasibility.md` §1. If a
   requirement depends on something marked infeasible or `[TODO]`, say so in Open questions.
5. **Domain.** Ask `ad-expert` (consult subagent) one precise question per uncertain AD
   behaviour — replication, linked attributes, `userAccountControl` flags, FGPP precedence,
   the Protected Users group, AdminSDHolder. Cite the answer's source in the spec.

## 2. Writing rules

- **Personas** — use these six names exactly; pick only those who really touch the feature:
  AD admin · help-desk technician · security/SOC analyst · compliance auditor · IT manager ·
  end user. Each gets one line on what they need here.
- **Jobs-to-be-done** — "When <situation>, I want to <motivation>, so I can <outcome>." Situations
  come from the research, not imagination: cite the review, forum thread or doc.
- **What we do better** — every claim is **measurable** and traces to a sourced ManageEngine
  weakness, in the shape "<task> in ≤ N interactions / ≤ T s (ME baseline: <measured or
  documented>, `<ID>`, source)". Enhancements beyond the scope lock are tagged `enhancement` and listed as
  proposed — they are a CEO scope call, not yours.
- **Functional requirements** — numbered `FR-01…`, one testable behaviour each, using MUST /
  SHOULD / MAY. Each FR names its parity ID(s) or `enhancement`. Others cite them as
  `<spec>#FR-03`. Never renumber; retire with ~~strikethrough~~ and a reason.
- **Platform matrix** — mandatory; the PatchIQ capability-asymmetry rule (OPERATING-MODEL §5).
  Every FR × every platform gets `✓`, `◐ <what is partial>`, `✗ <why> → T-…`, or `n/a`. Blank
  cells fail review. Platforms are listed in `templates/spec.md`. For deployment profiles, write
  "provisional until ADR-0001".
- **Data/API impact** — objects, attributes (LDAP display names, e.g. `pwdLastSet`,
  `lockoutTime`), Graph resources, new persisted entities, events emitted, API operations.
  Name them; `api-engineer` designs the contract later in its own `spec` ticket.
- **Security considerations** — the privileges needed (least privilege; say which AD rights on
  which objects), Tier-0 objects touched, safe primitives used (LDAP filter/DN builders,
  parameterised SQL, encoded PowerShell args), what activeDIQ's own audit trail records, and
  abuse cases (enumeration, help-desk social engineering, delegation escape). Anything touching
  credentials, ACLs, the DC agent or the password filter → tag the ticket `security-sensitive`
  and consult `security-architect` before review.
- **UX flows** — numbered steps per primary flow, with the design-system pattern each uses
  (`design-system` skill: data table, drawer, wizard, impact preview…). Include unhappy paths:
  no permission, DC unreachable, partial failure in bulk, 10k objects, empty state.
- **Acceptance criteria** — Given/When/Then plus Evidence (`ticket-craft` §2). Cover every
  MUST, every platform marked `✓`, and the unhappy paths. These are copied into build tickets.
- **Out of scope** — explicit list; each item says where it goes (later milestone, never, other
  spec).
- **Open questions** — each with an owner agent and what it blocks. Directional ones name the
  `D-` decision.
- **Sources** — every external claim has an inline URL (CLAUDE.md rule 7). No customer or
  partner names anywhere (rule 8). No sample data presented as real.

## 3. Frontmatter and status

```yaml
---
title: "Spec: Bulk user creation from CSV"
date: 2026-10-02
updated: 2026-10-02
status: draft            # draft → review → accepted | superseded
owner: heramb
author: product-manager
prd: knowledge/product/prd/user-lifecycle.md
epic: E-003
milestone: M1
parity: [ADM-xxx]        # illustrative — real IDs from the research/matrix, never invented
scope: locked            # locked (in a scope lock) | proposed (awaiting CEO)
---
```

- `draft` while you write. Set `review` when you advance the spec ticket.
- `accepted` only after a human has read it end to end (`knowledge/README.md`) — usually the CEO,
  through a scope lock or a demo. Agents never set `accepted`. Build tickets may be made ready
  against a `review` spec whose spec ticket is `done`.
- A change to an `accepted` spec: edit, bump `updated`, add a line to the Changelog section, and
  re-run review if an FR or AC changed. Replaced entirely → `superseded` with a link.

## 4. Self-check before advancing

- [ ] Every FR has a parity ID, `[TODO]` parity with a research ticket, or `enhancement`.
- [ ] Platform matrix complete; no blank cells; every `✗` has a ticket or a reason.
- [ ] Every "we do better" claim is measurable and sourced.
- [ ] ACs cover every MUST, unhappy paths, permission-denied, and the 10k-object case if bulk.
- [ ] Security section names privileges, Tier-0 impact and the safe primitives.
- [ ] No implementation choices that belong to an ADR (stack is provisional until ADR-0001).
- [ ] No partner/customer names; every external claim has a URL or `[UNVERIFIED]`.
- [ ] Open questions have owners; directional ones are filed decisions, not prose.

Then `factory/bin/factory ticket advance <id> --by product-manager --note "<spec path> · <n> FRs ·
parity <IDs> · open questions <n>"`.

## 5. Reviewing a spec (`solution-architect`; `product-manager` for PRDs)

Reject with numbered must-fix items if: any self-check box fails; an FR is not testable; an AC
cannot be verified from outside; a requirement silently assumes an unratified architecture
choice; or parity IDs do not resolve in the research. Wording and taste are notes, not rejects.

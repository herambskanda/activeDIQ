---
title: "Proposal: activeDIQ for <partner-slug>"
date: YYYY-MM-DD
updated: YYYY-MM-DD
status: draft            # draft → review (director) → approved (CEO decision D-…) → sent
owner: heramb
author: service-manager
partner: <partner-slug>
discovery: knowledge/business/partnerships/<partner-slug>/discovery.md
decision: D-…
---

<!-- Lives at knowledge/business/partnerships/<partner-slug>/proposal.md. Customer-facing text:
no [UNVERIFIED], no internal links, no ticket IDs. Placeholders the CEO fills: [PRICING — CEO],
[DATE — CEO], [LEGAL — CEO], [CEO]. -->

# activeDIQ for <Customer name>

## 1. Executive summary

Half a page. Their goal in their words (from discovery G28), what we propose, the outcome in
numbers they gave us (e.g. help-desk password tickets per month), the timeline in phases, and
the one reason this is low-risk (parallel run, rollback).

## 2. Current state

- ManageEngine footprint: products, editions, licence units, renewal dates (discovery A).
- Environment: forests/domains, object counts, DCs, Entra/Exchange (B).
- How the team works: top tasks and volumes, delegation, workflows (C).
- Audit and compliance obligations (D18–19).
- What works and must be preserved; what hurts (G26–27).

## 3. Proposed solution

| Need (from discovery) | ManageEngine today (feature ID in comment) | activeDIQ | Status |
| --- | --- | --- | --- |
| | | | available / planned for <milestone>, not committed / not available — workaround |

Deployment: <profile — provisional until ADR-0001; state what the customer hosts and what we
do>. Required accounts and rights (least privilege). What is installed on domain controllers,
if anything, and why.

## 4. What changes for each team

Admins, help desk, security, auditors, end users: one short paragraph each — what they do
differently, and the training they get.

## 5. Migration plan from ManageEngine

| Phase | Entry criteria | Activities | Exit criteria | Owner (us / you) | Duration |
| --- | --- | --- | --- | --- | --- |
| 1. Discovery | Questionnaire returned | Workshops; confirm scope | Scope and success measures signed off | | |
| 2. Inventory export | Access to ManageEngine admin | Export templates, roles, workflows, reports, alert profiles, self-service policies | Inventory complete and reviewed | | |
| 3. Mapping | Inventory complete | Map each item; agree gaps and workarounds | Mapping report signed off | | |
| 4. Parallel run | activeDIQ installed, connected read-only first | Run both; compare reports and audit output | Agreed comparison results met for <n> days | | |
| 5. Cutover | Parallel-run exit met; rollback plan approved | Pilot group, then waves; switch end users; disable ManageEngine jobs | All waves live; rollback window closed | | |
| 6. Hypercare | Cutover complete | Daily check-ins; fix list | No open S1/S2; ticket volume at baseline for <n> days | | |

**During the parallel run, one owner each for:** password-policy enforcement — <product>;
self-service portal per user population — <product>; audit-policy GPO settings — <product>.

**Audit history:** ManageEngine audit data remains available until <retention end> via
<archive / read-only instance>.

**Timeline vs renewal:** hypercare ends <date> — before the ManageEngine renewal on <renewal
date>, with <n> weeks' buffer. [DATE — CEO]

## 6. Timeline

Milestones by week from kick-off; dependencies on the customer (access, change windows).

## 7. Commercials

[PRICING — CEO]

## 8. Service levels and support

Support tiers and service levels per the attached SLA. [CEO]

## 9. Assumptions

Specific to this customer: access granted by <date>, a named contact with authority, change
windows, a test OU, network paths to DCs, etc.

## 10. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation | Owner |
| --- | --- | --- | --- | --- |
| Two enforcers active at once during parallel run | | | One-owner table in §5 | |
| ManageEngine export does not cover <item> | | | Recreate by hand; budget time | |
| End users confused by a new portal | | | Communications plan; same URL redirect | |

## 11. Next steps

Three bullets with dates: decision, kick-off, discovery workshop.

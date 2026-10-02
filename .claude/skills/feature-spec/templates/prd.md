---
title: "PRD: <Module name>"
date: YYYY-MM-DD
updated: YYYY-MM-DD
status: draft
owner: heramb
author: product-manager
epics: [E-…]
milestones: [M…]
parity: [<IDs from research — never invented>]
scope: proposed          # locked once a scope lock in knowledge/business/scoping/ covers it
---

# PRD: <Module name>

> One sentence: what this module lets which persona do, and why a ManageEngine customer would
> switch for it.

## 1. Problem

What hurts today, for whom, and how we know. Two to five bullets, each with a source URL from
`knowledge/business/market-research/` or the customer-voice file. No unsourced pain.

## 2. Personas

| Persona | What they need from this module | Frequency |
| --- | --- | --- |
| AD admin | | daily / weekly / rare |
| Help-desk technician | | |
| Security/SOC analyst | | |
| Compliance auditor | | |
| IT manager | | |
| End user | | |

Delete rows for personas who do not touch the module.

## 3. Jobs to be done

1. When <situation>, I want to <motivation>, so I can <outcome>. (source)

## 4. ManageEngine parity

| Parity ID | ME feature (product · edition) | activeDIQ answer | Spec |
| --- | --- | --- | --- |
| ADM-… | | parity / enhanced / deferred / out of scope | `knowledge/product/specs/<feature>.md` |

Source of truth for IDs: `knowledge/business/competitive-analysis/feature-parity-matrix.md`
(or the per-product inventory until it exists). Unknown → `[TODO]` + research ticket.

## 5. What we do better

| Claim (measurable) | Baseline (ManageEngine, sourced) | Our target | How we prove it |
| --- | --- | --- | --- |
| | | | ux-review task timing / test / demo scene |

Enhancements beyond the scope lock are listed here as **proposed** and go to the CEO.

## 6. Feature map

| Spec | Summary | Personas | Milestone | Status |
| --- | --- | --- | --- | --- |

## 7. Module-level platform matrix

Rows: specs. Columns as in `templates/spec.md` §7. Detail lives in each spec; this table is the
roll-up so asymmetry is visible at a glance.

## 8. Non-functional requirements

Scale (objects, domains, forests), latency targets for the top tasks, audit retention, a11y
(WCAG 2.2 AA), localisation, deployment profiles (provisional until ADR-0001).

## 9. Security posture

Privileges the module needs, Tier-0 touchpoints, threat-model link (`security-architect`).

## 10. Success metrics

What we measure after release (task time, ticket deflection, enrollment rate…) and where the
number comes from. No vanity metrics.

## 11. Out of scope

## 12. Open questions

| # | Question | Owner | Blocks | Decision |
| --- | --- | --- | --- | --- |

## Changelog

- YYYY-MM-DD · created (T-…)

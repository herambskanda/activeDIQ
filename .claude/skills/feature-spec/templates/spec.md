---
title: "Spec: <Feature name>"
date: YYYY-MM-DD
updated: YYYY-MM-DD
status: draft
owner: heramb
author: product-manager
prd: knowledge/product/prd/<module>.md
epic: E-…
milestone: M…
parity: [<IDs>]
scope: locked | proposed
---

# Spec: <Feature name>

> One sentence: the outcome for the user.

## 1. Problem

Two to four sentences, sourced.

## 2. Personas and jobs to be done

| Persona | Job (When… I want… so I can…) | Source |
| --- | --- | --- |

## 3. ManageEngine parity

| Parity ID | What ME does (edition) | Source | Our answer |
| --- | --- | --- | --- |

## 4. What we do better

| Claim (measurable) | ME baseline (sourced, dated) | Target | Proof (test, ux-review task, demo scene) |
| --- | --- | --- | --- |

## 5. UX flows

### Flow A — <name> (primary)

| # | Actor does | System shows | Pattern (`design-system`) |
| --- | --- | --- | --- |
| 1 | | | data table / drawer / wizard / impact preview / … |

### Unhappy paths

- No permission for the scope → …
- DC unreachable or slow (> 5 s) → …
- Partial failure in bulk (n of N fail) → per-object results, retry failed only
- 10 000 objects selected → …
- Empty state (no objects match) → …

## 6. Functional requirements

| ID | Requirement (MUST / SHOULD / MAY) | Parity / enhancement |
| --- | --- | --- |
| FR-01 | The system MUST … | ADM-… |

## 7. Platform matrix

Every FR × every column: `✓` · `◐ <what is partial>` · `✗ <why> → T-…` · `n/a`. No blanks.

| FR | AD on-prem (WS 2016–2025 DCs) | Entra ID cloud-only | Hybrid (synced) objects | Exchange on-prem | Exchange Online / M365 | Web console | REST API | PowerShell module | End-user portal (desktop + mobile web) | Windows logon agent | macOS logon agent | Linux logon agent |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FR-01 | | | | | | | | | | | | |

Hybrid note: state the source of authority — an Entra write to a synced object fails or is
overwritten; say which system the feature writes to. Deployment profiles (self-hosted / SaaS /
MSP): provisional until ADR-0001 — write "assumed: <profile>".

## 8. Data and API impact

- **Directory objects and attributes** read / written (LDAP display names; Graph resources):
- **New persisted entities** (name, purpose, retention):
- **Events emitted** to activeDIQ's audit trail (who, what, before → after, why, approval ref):
- **API operations** needed (verb + resource, sync vs job):
- **Scale**: expected object counts; paging; job vs request.

## 9. Security considerations

- Privileges required, per platform, least-privilege (which rights on which containers):
- Tier-0 objects affected (Domain Admins, AdminSDHolder-protected accounts, DCs, GPOs linked
  at domain/DC OU):
- Safe primitives used (LDAP filter/DN builders, parameterised SQL, encoded PowerShell args,
  typed security descriptors):
- Delegation: what a scoped help-desk role can and cannot do; how escape is prevented:
- Abuse cases and mitigations (enumeration, social engineering, mass change, replay):
- `security-sensitive` tag needed? yes / no — why:

## 10. Acceptance criteria

```
AC-01
Given …
When …
Then …
Evidence: <test name | command + output | screenshot of named state | doc path>
```

## 11. Out of scope

- <item> — goes to <milestone / spec / never>, because …

## 12. Open questions

| # | Question | Owner | Blocks | Decision |
| --- | --- | --- | --- | --- |

## Sources

Inline in the text; list any extra here.

## Changelog

- YYYY-MM-DD · created (T-…)

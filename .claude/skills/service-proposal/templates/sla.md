---
title: "Service Level Agreement: activeDIQ support for <partner-slug>"
date: YYYY-MM-DD
status: draft
author: service-manager
partner: <partner-slug>
decision: D-…
---

<!-- Every number below is a proposed default for the CEO to approve or change. Remove [CEO]
markers only after the decision is answered; cite the D-id in frontmatter. activeDIQ is
self-hosted by default (provisional until ADR-0001): uptime commitments apply only to services
WE host, if any. -->

# Service Level Agreement — activeDIQ support

## 1. Scope

Covers support for activeDIQ <version range> deployed at <Customer name>, for the subscription
term. Excludes: customer infrastructure (DCs, network, OS), third-party products (including
ManageEngine), and changes made outside activeDIQ.

## 2. Support tiers [CEO]

| Tier | Hours | Channels | Named contacts | Included |
| --- | --- | --- | --- | --- |
| Standard | Business hours, <time zone> | Portal, email | 2 | Upgrades, security fixes |
| Premium | 24×7 for Severity 1 | Portal, email, phone | 5 | + named engineer, quarterly review |

## 3. Severity definitions

| Severity | Definition (activeDIQ-specific) | Examples |
| --- | --- | --- |
| **1 — Critical** | Production use stopped or a security exposure, no workaround | Console and API down; self-service portal down for all users; activeDIQ making unintended directory changes; a vulnerability under active exploitation |
| **2 — High** | Major function impaired, workaround is impractical | Bulk operations failing; audit collection stopped on a DC; a logon-screen agent failing for a group of machines |
| **3 — Medium** | Function impaired, workaround exists | A report wrong for one filter; a scheduled report not delivered |
| **4 — Low** | Question, cosmetic issue, feature request | How-to questions; UI text |

## 4. Response and resolution targets [CEO]

| Severity | First response (Standard / Premium) | Update frequency | Target to workaround or fix |
| --- | --- | --- | --- |
| 1 | 4 business h / 1 h | Every 4 h / 2 h | Continuous effort until workaround |
| 2 | 8 business h / 4 h | Daily | <n> business days |
| 3 | 2 business days / 1 business day | On change | Next maintenance release |
| 4 | 5 business days / 3 business days | — | Considered for the roadmap |

"Response" means a support engineer has acknowledged and begun work, not an automated reply.

## 5. Security fixes

Security advisories published at <URL — to be set up>. Critical vulnerabilities in activeDIQ:
fix or mitigation target <n> days from validated report [CEO]. Customers are notified through
<channel>.

## 6. Customer responsibilities

Keep within supported versions (current and previous minor); provide logs and diagnostics
bundles; give remote-session access when needed for Severity 1; maintain backups of their own
infrastructure.

## 7. Escalation path

Support engineer → support lead → delivery lead → <executive> [CEO]; with contact details in
the onboarding pack, not here.

## 8. Service credits

[LEGAL — CEO] — if any; only for services skenzeriq hosts.

## 9. Reporting and review

Monthly ticket report (volume by severity, response attainment); quarterly service review for
Premium.

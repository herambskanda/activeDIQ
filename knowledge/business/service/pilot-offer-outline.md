---
title: Pilot Offer Outline (ManageEngine AD estates)
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# Pilot Offer Outline

**Internal draft. Not for sending yet.** The partner-facing version needs CEO approval
(`ceo-decisions`, category 6). Items marked **[CEO]** are CEO-owned. Durations are estimates
`[EST]`. Partner names go in `knowledge/business/partnerships/` only. Method:
[migration playbook](manageengine-migration-playbook.md) Phases 0–3. Sources:
[AD360C](../market-research/manageengine-ad360-suite-and-commercials.md),
[CV](../market-research/manageengine-ad-customer-voice-and-security.md),
[LAND](../competitive-analysis/ad-management-market-landscape.md),
[FEAS](../../development/architecture/build-feasibility/ad-technical-feasibility.md).

## Proposition, in one line

Run activeDIQ next to your current tools on a scoped part of your directory. We do the setup and
configuration import. You measure the difference on your own tasks. Your existing tools stay
untouched throughout.

## Scope

The scope follows what activeDIQ has shipped at pilot start; the feasibility roadmap puts these
in Phase 1 [FEAS §6.3].

| In scope | Out of scope for the first pilot |
|---|---|
| Read-only reporting across the whole domain, including the partner's top reports via the crosswalk (MIG-05) | Replacing ADAudit Plus (needs the Phase 2 event pipeline) |
| Day-to-day management in **one pilot OU** by **2–5 pilot technicians**: create/modify, bulk CSV (ADMP format accepted, MIG-04), reset/unlock, groups, delegation, approvals | Windows/macOS/Linux logon-screen reset and endpoint, VPN or OWA MFA (Phase 2–3) |
| Import of the partner's templates, naming formats, roles and selected automations, with a fidelity report (MIG-02/03). Automations run in **dry-run only** | Writing to Tier-0 / AdminSDHolder-protected accounts [FEAS §0] |
| *Optional:* web self-service password reset for a pilot user group, using factors bootstrapped from existing data, so no user has to enroll (MIG-09) | Decommissioning any ManageEngine component |

## Duration `[EST]`: 8 weeks

| Weeks | Activity |
|---|---|
| 1–2 | Discovery workshop and questionnaire; least-privilege install with no Domain Admin (MIG-12); inventory export; import and fidelity report |
| 3–6 | Parallel run: pilot technicians work in activeDIQ; reports and dry-run automations are compared with current results (MIG-10); weekly 30-minute review |
| 7–8 | Measurement, written readout, and a go/no-go decision on a full migration |

## Success criteria (agreed in week 1; the partner sets the thresholds)

| # | Criterion | Measure | Threshold |
|---|---|---|---|
| 1 | Faster everyday work | Timed run of the partner's 10 most common tasks, current tool vs activeDIQ [CV §6.2; LAND §6] | `[partner sets]` |
| 2 | Configuration carried over | Share of in-scope items imported exactly or with an accepted change (fidelity report) | `[partner sets]` |
| 3 | Report parity | Partner's top reports match within the agreed tolerance | `[partner sets]` |
| 4 | Safe by construction | Zero unintended AD changes; no Domain Admin rights used | Must be met |
| 5 | Security review | The partner's own review of activeDIQ completed | Passed |
| 6 | Technician verdict | Pilot technicians' rating and comments | `[partner sets]` |
| 7 | *(if SSPR in scope)* No stranded users | Pilot users with a working reset factor on day one, without enrolling | 100% |

## What we need from the partner

- An executive sponsor, plus an AD/identity lead available about 2–4 hours a week `[EST]`.
- 2–5 pilot technicians, and a pilot OU (or a test domain).
- A host or VM for activeDIQ (or a connector host, if SaaS is chosen), and a service account
  set up with our least-privilege wizard.
- Read-only access to the ManageEngine consoles, and exports of the top reports. If agreed,
  read-only database access for the configuration import.
- The completed [discovery questionnaire](../partnerships/partner-discovery-questionnaire.md).
- A security-review contact, and permission to time tasks and quote anonymized results
  internally.

## What the partner gets

- Setup and configuration import for the pilot scope done by us. The research recommends
  "migration included", since ManageEngine charges $3,495–$14,995 for onboarding
  [AD360C §6.7, §8.1 item 4]. Whether this is free is **[CEO]**.
- No disruption: current tools keep running unchanged, and rollback means stopping the pilot.
- A written readout: fidelity report, task-time benchmark, report-parity results and a
  migration plan with risks and dates (aligned to their renewal dates).
- Direct access to the product team, and influence on the roadmap for features they rely on.
- Exit at any time by either party. On exit we uninstall and confirm data deletion in writing.

## Commercials: [CEO]

| Item | Placeholder | Options from the research (not commitments) [AD360C §8.1 item 4] |
|---|---|---|
| Pilot fee | **[CEO: free / fixed fee / credited against first-year subscription]** | — |
| Conversion terms | **[CEO]** | Co-term credit for remaining ManageEngine subscription; 90-day parallel run at no cost; 3-year price lock |
| Pricing basis | **[CEO]** | Per enabled human identity, no infrastructure or technician meters [AD360C §8.1 item 1] |

## Preconditions on our side before offering

- The product has shipped the in-scope features to pilot quality (Phase 1 exit: runs against
  WS2016–WS2025 with signing/CBT enforced, no Domain Admin, external pentest passed
  [FEAS §6.3]).
- A ManageEngine lab install has proven the configuration import, or the offer says "guided
  rebuild" instead of "import" ([playbook §9](manageengine-migration-playbook.md)).
- Security documentation for the partner's review exists. Claims are limited to what we can
  evidence [CV §6.2].

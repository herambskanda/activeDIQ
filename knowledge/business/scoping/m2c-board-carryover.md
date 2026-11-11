---
title: M2c off-board carry-over — items to file on the server board at merge
date: 2026-11-11
updated: 2026-11-11
status: draft
owner: factory-director
---

# M2c off-board carry-over

Branch `m2c-plan` was worked on a second machine with no factory board (CEO, 2026-11-10; see
`knowledge/memory/decisions-log.md`). Nothing here has a T-, D- or A- id yet. When the branch
merges on the server, the director files each row below on the board, then deletes this file in the
same change.

| # | File as | Title | Owner | Priority | Source |
|---|---|---|---|---|---|
| 1 | decision (CEO, record only — already answered) | M2c is planned off-board and built on the server; M1-focus hold stands | factory-director | — | decisions-log 2026-11-10 |
| 2 | bug, security-sensitive | Add `ms-DS-ConsistencyGuid` to `guarded-v1` under `map_credential` (AD side of the sync anchor; Entra `onPremisesImmutableId` is already there). Check the code's guarded set on main and the merged branches, not only TM §6.9a line 1911 | directory-engineer | P1 | reviews/2026-11-11-m2c-security-review.md (A-B2) |
| 3 | decision-prep (hold; blocks nothing in 2c) | OQ-C1: ever ship a customer-run helper on the Entra Connect server to start a sync? Recommendation: no — a new component on a Tier-0 host | product-manager | P3 | specs/e2-7-hybrid-provisioning.md |
| 4 | research | Time ADMP's M365-at-creation flow and its behaviour during the sync gap (needs the ADMP trial, A-0036) | market-analyst | P2 | specs/e2-7-hybrid-provisioning.md |
| 5 | chore, security-sensitive | Threat model §6.6: add a residual-risk row for `GroupMember.ReadWrite.All` (reaches Azure-RBAC groups, CA exclusion groups, M365 groups, PIM-eligible nested groups); §6.4: a designation for Azure-privileged groups | security-architect | P1 | reviews/2026-11-11-m2c-security-review.md (round 2, A2-M2) |
| 6 | test (lab, needs Entra tenant A-0026) | Lab G11: does Graph refuse a `GroupMember.ReadWrite.All` add to a PIM-eligible nested group? | test-engineer | P2 | same, A2-M2 |
| 7 | spec tickets | E2.7 and E2.6 specs: file each as a `spec` ticket carrying its review history (two rounds of reviews in `knowledge/product/specs/reviews/`) | product-manager | P1 | this branch |
| 8 | build follow-up, security-sensitive | Outside a hybrid request: adding a user to an AD-synced group whose Entra twin carries a licence must check `m365.licence.assign` over that user (licence state read live at Plan and Apply; unreadable counts as licensed) | backend-engineer (`objects`) | P2 | reviews/2026-11-11-m2c-security-review.md (round 3, A3-m3) |
| 9 | chore, security-sensitive | Threat model §5.18 (TB18): add the E2.11 importer threats from the C-02 review (TM-TB18-T1…T12 coverage table) | security-architect | P1 | reviews/2026-11-11-e2-11-security-review.md (F1) |
| 10 | decision-prep (factory, technical) | What a `request`-mode privilege does when no workflow matches: hold for approval, never allow | solution-architect | P2 | same (F2) |

Rows for the ADR, domain-model and build tickets come from the M2c ticket plan, not from here.

## At merge, also
- File the C-keys of `m2c-plan.md` as tickets. Shrink C-33, C-34 and C-38 against server main first,
  because `internal/modules/connections` already holds attestation, HybridLink and reconfirm code.
- File the two off-board CEO decisions (decisions-log 2026-11-10 and 2026-11-11) as answered D-ids,
  plus a notice for the E2.11 2c scope: file and DB-dump routes; discovery, comparator, ownership
  switch and §8 limits are 2d.
- C-01 and C-02 (the E2.11 reviews) were run off-board; their reviews are in
  `knowledge/product/specs/reviews/2026-11-11-e2-11-*.md`. Start from C-03.
- **E2.11 reviews rejected the draft** (C-01: 2 blockers, 9 majors; C-02: 3 blockers, 7 majors). C-03 grows
  S → M and applies both. Plan corrections at filing:
  - C-27 depends on C-07; C-95 on FB-6b; C-94 waits for the dump-format ruling (PostgreSQL plain-format
    data, parsed and never restored, column allow-list for ADMP 8043).
  - Reword C-97: apply is one Operation of the owning modules' Actions, with no second pipeline.
  - Reword C-99: register a fidelity dataset and export it through `platform/export`.
  - Ownership: the field and its refuse-to-run guard are 2c; only the switch Action is 2d. §8
    leaves E2.11 for E2.9 plus an ADR-0005 amendment.
  - E2.6 erratum: use the `execution_owner` value `activediq | external`.
  - Reconcile the ADMP-trial action ids: A-0024 in the decisions log, A-0036 in the digest and plan.

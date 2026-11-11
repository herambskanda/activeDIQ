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
| 5 | spec tickets | E2.7 and E2.6 specs: file each as a `spec` ticket carrying its review history (two rounds of reviews in `knowledge/product/specs/reviews/`) | product-manager | P1 | this branch |

Rows for the ADR, domain-model and build tickets come from the M2c ticket plan, not from here.

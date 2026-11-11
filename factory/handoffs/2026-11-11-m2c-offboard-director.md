---
title: Handoff — off-board M2c planning (factory-director, CEO session)
date: 2026-11-11
owner: factory-director
branch: m2c-plan (pushed to origin)
---

# Handoff — off-board M2c planning

## Where things stand
- This laptop (K:\activeDIQ) is a fresh clone; `factory/state` is empty — **no board here**. The
  server has newer main, 54 unmerged `factory/T-*` branches and the ticket DB; none is on GitHub.
- CEO decisions (decisions-log 2026-11-10 and 2026-11-11, no D-ids yet): plan M2c here, build on the
  server; M1-focus hold stands; off-board work stops at the plan **plus the E2.11 reviews C-01/C-02**;
  `m2c-plan` is pushed to the public repo.
- Done and committed on `m2c-plan`:
  - specs (advanced by solution-architect + security-architect after 3 rounds + erratum):
    `knowledge/product/specs/e2-7-hybrid-provisioning.md`, `e2-7a-entra-inventory-sync.md`,
    `e2-6-report-builder.md`; reviews in `knowledge/product/specs/reviews/2026-11-11-m2c-*.md`.
  - ticket plan `knowledge/business/scoping/m2c-plan.md` (C-01…C-110, critical path C-04→…→C-109).
  - board carry-over `knowledge/business/scoping/m2c-board-carryover.md` (8 rows, incl. P1 bug:
    `ms-DS-ConsistencyGuid` missing from `guarded-v1`).

## In flight (background agents at handoff time)
- **C-01** solution-architect review of `e2-11-migration-importer.md` →
  `knowledge/product/specs/reviews/2026-11-11-e2-11-architecture-review.md`.
- **C-02** security-architect review of the same →
  `knowledge/product/specs/reviews/2026-11-11-e2-11-security-review.md`.
  If either file is missing or lacks a verdict, re-run that review (prompts: same scope as plan rows
  C-01/C-02; director's 2c scope = file + DB-dump routes; discovery, comparator, ownership switch,
  §8 limits = 2d).

## Next steps
1. When both reviews land: commit them, add any new server follow-ups to the carry-over file, push.
2. **Stop there** — C-03 (E2.11 revision) and everything else waits for the server (CEO 2026-11-11).
3. At the server, at merge: file every carry-over row and the C-keys as tickets (shrink C-33/C-34/C-38
   against server main — connections module already has attestation/HybridLink code), file the
   two off-board CEO decisions as answered D-ids plus the E2.11 2c-scope notice, delete the
   carry-over file in the same change.

## Gotchas
- Don't run `factory/bin/factory ticket|decision` here — it would start a second, unmergeable DB.
- The CEO's VS Code commits too (9a8033a7, generic message). Check `git log` before committing.
- Fresh agents per review round: each used ~200k tokens on 600–900-line specs.

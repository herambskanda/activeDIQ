---
title: E2.1 Console and search — screens, data sources and ticket plan
date: 2026-11-12
updated: 2026-11-12
status: draft
owner: solution-architect
ticket: T-1801
---

# E2.1 Console and search: plan

Roadmap epic E2.1 ([roadmap-skeleton.md](roadmap-skeleton.md)): ADM-001–004, ADM-007, ENH-01.
Board epic: **E-007**, milestone **M2b**. (m2-plan.md §1 numbered E2.1 as E-007 before the board was
recreated; the board now has E-001–E-006 only, so E-007 is new and this plan supersedes that row.)
M2a is `active` with its reports and search work already ticketed, so the remaining console work goes
to M2b, which already holds the directory, bulk, history and delegation epics.

## 1. Starting point (verified 2026-11-12)

- `web/src/app/modules.gen.ts` registers `directory` (`/directory/users`) and `reports` (`/reports`,
  `/reports/*`) only. Nothing owns `/`, no palette overlay exists, nothing is localized.
- API operations that exist: `searchDirectory`, `searchDirectoryUsers` (`api/openapi/modules/directory.yaml`),
  the report family (`reports.yaml`). `connections.yaml` has takeover attestation only, so **there is no
  connection-health read yet**.
- Search is ADR-0011 (`ratified`): inventory + pg_trgm, scope-trimmed in one statement.
- Design: [information-architecture.md](../../product/design-system/information-architecture.md) §4.2
  (Home), §5 (search and palette), §7.2 (Explorer); [brand-guidelines.md](../../product/design-system/brand-guidelines.md).

## 2. Screens, data sources, sequencing

| Screen / block | Route | Data source today | Gap | Ticket(s) |
|---|---|---|---|---|
| Home shell: search, Quick actions, Recent, first-run checklist | `/` | `searchDirectory`; client-side Recent; connection list for first-run | none for shell | T-1832 |
| Home: Directory health, Needs you (connection problems) | `/` | none | `listConnectionHealth` contract and handler | T-1834 → T-1835 → T-1836 |
| Home: Needs you from approvals and failed jobs | `/` | none (workflow is 2d, jobs UI later) | APIs do not exist | not ticketed; **absent, never placeholder** until its epic ships |
| Home: pinned report widgets (ADM-002) | `/` | `listReportRuns`, `listReportRunRows` | preference store, widget contract | T-1840 (spec first) |
| Command palette overlay | any page | `searchDirectory`, Registrar palette entries | none | T-1837 |
| Palette actions (`>`, inline actions) | any page | `operation.Catalogue()` (EP-3) | needs 2b Action tickets | deferred; follows E-003 Actions |
| AD Explorer | `/directory/explorer[/{ouGuid}]` | inventory | tree/contents contract | T-1838 (spec) then api/backend/frontend |
| Localization framework | all | none | framework | T-1839 |

Object page (`/directory/{kind}/{guid}`) is E-003/E-005 (ADM-005); `/go/{identifier}` rides with it.

**Sequencing.** T-1832 and T-1834 start now (no dependencies). T-1837 follows T-1832 (shares the
search plumbing and focus rules). T-1835 follows T-1834, T-1836 follows both T-1832 and T-1835.
T-1838 and T-1840 are specs that cut their own build tickets. T-1839 is independent and may run any
time; it lands before more screens multiply literal strings.

## 3. Decisions made in this plan

1. **Home is "my work", not a dashboard** (IA §4.2). Blocks render only from real APIs; blocks whose
   source does not exist yet are absent. This is why Home is split by data source rather than built whole.
2. **Recent is client-side per account** in v1. It is a convenience list of opened objects, not
   audit data. Server-side recents can follow with the preference store in T-1840.
3. **Connection health is a contract-first read** (ADR-0004), derived from stored sync state, never a
   live LDAP call per request.
4. **Palette actions wait for the Action catalogue.** The overlay ships with search, pages and
   reports; the IA already schedules actions at 2b.
5. **One search path.** The palette calls `searchDirectory` (ADR-0011); no new search endpoint, no
   second scope renderer. `searchDirectoryUsers` (live LDAP) is retired by T-1127.
6. **Languages are not chosen.** Only the framework and `en` ship; the language list is `[TODO]` in the parity matrix.

## 4. Risks

| Risk | Mitigation |
|---|---|
| Home built before its sources exist leads to fake tiles | AC on T-1832 and T-1836: no counts or placeholders without an API |
| Explorer tree bypasses the scope renderer | T-1838 requires the single-producer rule and a fitness expectation |
| Literal strings multiply before i18n lands | T-1839 migrates existing modules and adds a lint rule |

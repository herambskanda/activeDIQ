---
title: "Module: migration (intake)"
date: 2026-11-14
updated: 2026-11-16
status: review
owner: heramb
author: backend-engineer
ticket: T-2060, T-2062
tier: server
---

# Module `migration` — intake

**Purpose.** The base every ManageEngine importer sits on (spec [e2-11](../../../product/specs/e2-11-migration-importer.md) §6.1, §7, §9): the migration project, the import job that starts `quarantined`, the size gate that decides before any byte is read, and the quotas. No format parser or UI yet.
**Capabilities required:** none (importers need no directory access, spec §9). **Permission:** `migration.import` (not control-plane; the tenant may delegate it).

## Owned tables (migration 0082, both tenant tables with forced RLS, `config` write class)

- `migration_projects` (DM-90): name, creator (the real human requester), `closed_at`. No DELETE for the runtime role.
- `migration_jobs` (DM-91): actor, source kind (`csv`, `xlsx`, `html`, `db_dump`), SHA-256, ADMP build, declared size, state, limit hit. A guard trigger fixes identity at insert and makes a finished state final. A `rejected` job has a `limit_hit` and no SHA-256 (CHECKs), because it was never read.

## Actions (the only writers; permission, tenant context and audit come from the operation kernel)

| Action | Audit kind | Refusals |
| --- | --- | --- |
| `migration.project.create` | `migration.project.created` | no `migration.import` → denied attempt, audited, nothing written |
| `migration.job.submit` | `migration.job.submitted` | unknown or closed project (`no_such_project`); tenant quota (`quota_tenant`, Plan and Apply); user quota (Apply) |

`Service` (service.go) runs them and maps outcomes to `ErrSizeLimit`, `ErrQuotaUser`, `ErrQuotaTenant`, `ErrNoSuchProject`.

## Rules

- **Size gate** (`SizeGate`): decided from the declared size (Content-Length or stat) at Plan, before any read, hash or parse. 256 MiB for csv/xlsx/html, 4 GiB for `db_dump`. Over the limit, the job is stored `rejected` with `limit_hit` (`upload_size_256mib`, `upload_size_4gib`) and the caller gets `ErrSizeLimit`. A rejected job holds no quota.
- **Quotas:** at most 3 active (`quarantined`, `running`) jobs per tenant and 1 per actor. Plan refuses early; Apply re-counts under a per-tenant `pg_advisory_xact_lock`, so concurrent submissions cannot exceed them (`migration_quota_concurrent`). Plan does not know the actor, so the user quota is an Apply refusal (audited as a failed step).
- **Quarantine:** every accepted job is `quarantined`. Nothing releases it yet: scan, release and the parsers are later tickets.

## Fidelity report and proposal store (T-2062, migration 0084)

- `migration_fidelity` (DM-92): one row per parsed item (`exact`, `changed` + diff, `manual`, `not_supported` + reason code). `migration_proposals` (DM-93): one inert proposal per `exact`/`changed` item. Both tenant tables, forced RLS, insert-only for the runtime role. The proposal's class is part of its foreign key to the fidelity row, so the database itself refuses a proposal for a `manual` or `not_supported` item.
- **Action `migration.fidelity.record`** (audit `migration.fidelity.recorded`, permission `migration.import`): takes every item of a *running* job once (`ErrJobNotRunning`, `ErrAlreadyRecorded`, `ErrNoSuchJob`). The importer *describes* items (`Item`); `Classify` decides server-side, in Plan. Precedence: never-imported (§6.4: tenant-owner, `authz.NeverCrosses`/platform-only permissions, tier0 or unresolvable scope, credential, raw SQL, open request → `not_supported`) > script body (`manual`, HTML-escaped bounded text, never audited) > the importer's declared class. An importer cannot declare `manual`.
- **Tier0 fails closed.** `Tier0Resolver` decides whether a scope GUID is or sits under tier0; an error, a malformed GUID or no resolver at all makes the item `not_supported`. `Register` currently passes **no resolver**, so every directory-scoped grant is `not_supported` until the real resolver (tier0 designations, `ad-expert` on the set) is wired: follow-up ticket.
- **Inert:** no authorisation path reads the two tables; test `proposal_is_inert` checks the evaluator's decision and `authz_assignments` are unchanged.
- **CSV export:** `Service.ExportFidelityCSV` (requires `migration.import` via `Service.Authz`, deny by default) writes through the shared `export/csv` encoder, so formula leads are neutralised.

## Not here (follow-ups)

The `platform/jobs` kind that runs a released job (no body exists until a parser does), the OpenAPI operations and HTTP handlers (`api-engineer`), closing a project, cancelling a job, the upload endpoint that streams to quarantine and computes the SHA-256, and operator-lowerable limits.

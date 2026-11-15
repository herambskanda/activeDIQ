---
title: "Module: migration (intake)"
date: 2026-11-14
updated: 2026-11-14
status: review
owner: heramb
author: backend-engineer
ticket: T-2060
tier: server
---

# Module `migration` — intake

**Purpose.** The base every ManageEngine importer sits on (spec [e2-11](../../../product/specs/e2-11-migration-importer.md) §6.1, §7, §9): the migration project, the import job that starts `quarantined`, the size gate that decides before any byte is read, and the quotas. No format parser, proposal or UI yet.
**Capabilities required:** none (importers need no directory access, spec §9). **Permission:** `migration.import` (not control-plane; the tenant may delegate it).

## Owned tables (migration 0081, both tenant tables with forced RLS, `config` write class)

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

## Not here (follow-ups)

The `platform/jobs` kind that runs a released job (no body exists until a parser does), the OpenAPI operations and HTTP handlers (`api-engineer`), closing a project, cancelling a job, the upload endpoint that streams to quarantine and computes the SHA-256, and operator-lowerable limits.

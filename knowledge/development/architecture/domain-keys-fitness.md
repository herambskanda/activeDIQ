---
title: "fitness-domain-keys: X3 keying, X4 secrets and X5 append-only enforced in CI"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
ticket: T-0050
sources_last_checked: 2026-10-02
---

# fitness-domain-keys

The job that makes the cross-cutting invariants of the [domain model](../domain/domain-model.md) §0 fail the
build instead of relying on review. Code: `tools/fitness/domainkeys/`; the declarations it reads:
`internal/platform/tablekind/`; the secret-attribute set: `internal/connector/secretattr/`.

```
make fitness-domain-keys                      # = go run ./tools/fitness/domainkeys, part of make fitness
go run ./tools/fitness/domainkeys -pg 18      # one PostgreSQL version
go test ./tools/fitness/domainkeys/...        # a failing fixture per rule
```

It runs against the **migrated schema**: the real migrations, applied as the owner role to throw-away
PostgreSQL 16 and 18 containers, through the harness shared with `fitness-tenancy`
(`tools/fitness/pgharness`, [tenancy-fitness.md](tenancy-fitness.md)). Docker is required; there is no
silent skip. A violation names the table and the rule: `X5 public.audit_event [runtime-update]: …`.

## The table registry (there is no list in the check)

Every package that owns tables declares each one in code:

```go
var _ = tablekind.Declare(tablekind.Table{
    Name: "public.change_record", Entity: "DM-18", Kind: tablekind.Directory, AppendOnly: true,
})
```

`Kind` is `P`, `T` or `D` (the domain model's own notation); `AppendOnly` is X5; `Sealed` lists the
ciphertext columns (X4); `NameOK` lists reviewed columns whose name trips X3 or the X5 state-column rule but
which hold neither. The job reads the `Declare` calls from Go source **without building or running it**, so
the literal must be statically readable. The sealed columns of DM-02, DM-11, DM-37, DM-63, DM-82 and DM-85
are declared this way too, so the X4 allow-list comes from the same registry as the kinds.

## The checks

| Check | What fails the build | Rule names |
| --- | --- | --- |
| X3 | On a `D` table, a primary key, unique index, exclusion constraint or foreign key uses a column that holds a DN, SID, sAMAccountName, UPN or display name (by name, or by `COMMENT ON COLUMN … IS 'diq:holds=dn\|sid\|sam\|upn\|name'`); or any foreign key references such a column of a `D` table. Directory references are `(tenant_id, connection_id, object_guid)` | `key-identity-column`, `fk-identity-column` |
| X4 | A column is named for, or annotated (`diq:attr=<attr>`) as holding, a `SecretAttrs` attribute (unicodePwd, ms-Mcs-AdmPwd, msLAPS-Password, msFVE-RecoveryPassword, …) and is not a declared `Sealed` column; a `Sealed` column that is not `bytea`. Safe-primitives §3.7, LF-38 | `secret-attr-column`, `sealed-type` |
| X5 | On an append-only table (DM-18 ChangeRecord, DM-80 AuditEvent, DM-66 ApprovalDecision, DM-81 ChainCheckpoint, DM-24 ConnectionVerification with its findings, DM-26 SyncCycle with DcObservation, DM-25 Tier0Override, insert-only): the runtime role, or any other non-owner role, holds UPDATE (table or column), DELETE or TRUNCATE (only the retention role deletes); a lifecycle-state column (`state`, `status`, …) exists, because states are derived (2b); the DM-25.I6 retention property test `TestProperty_DM25_I6…` is absent | `runtime-update`, `runtime-update-column`, `runtime-delete`, `runtime-truncate`, `grant-update`, `grant-delete`, `grant-truncate`, `state-column`, `property-missing` |
| REG | A product table is undeclared; a declaration is stale, duplicated, unreadable or not a literal; a declared kind or `AppendOnly` disagrees with the domain-model heading (entity unknown, `kind-mismatch`, `append-only-missing`, `append-only-unfounded`) or with the tenancy exemption registry (a `P` table must be a registered global table and only those); a `NameOK` or `Sealed` entry that is not needed | `table-undeclared`, `declaration-*`, `kind-*`, `exemption-stale`, `migration-name`, `migrations-apply` |

Partitions are judged with their root. `activediq_retention` is the role allowed to DELETE append-only
records; nothing creates it yet and the check only exempts the name (`-retention-role`).

## Adding a table

Declare it next to its owner code and migration. A new `D` table with a DN-keyed unique index, a column called
`unicodepwd`, or a runtime `GRANT UPDATE` on an append-only table is a failed build with the rule above.
Changing the domain model's kind or append-only claim means changing the model first; the job reads its
headings.

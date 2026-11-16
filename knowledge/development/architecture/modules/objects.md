---
title: "Module: objects — Template (DM-50) and NamingFormat (DM-51)"
date: 2026-11-05
updated: 2026-11-15
status: draft
owner: heramb
author: backend-engineer
ticket: T-1582
tier: server
binding_sources: domain-model.md DM-50, DM-51; ADR-0003; ADR-0005 rules 2 and 4
---

# Module `objects`

**Purpose.** The versioned definitions an object-creation or object-modification Operation is planned
against: which fields a form shows, edits or requires, and how names (sAMAccountName, UPN prefix, CN,
displayName, mail alias) are derived. Plan-time checks only; the directory is never read here.
**Owner:** backend-engineer. **Epic:** E-003. **Tickets:** T-1582 (this package); module registration and
the racing-create lab test are follow-ups under ADR-0015.
**Capabilities required (`Requires()`):** none yet. **Platform matrix:** windows / linux-oci / saas: same.

> **State.** `internal/modules/objects/` is a library package (T-1582): it has no `Module` yet and does not
> register contributions. Registration is specified by ADR-0015 D2: `objects` registers as a Module with its stores
> and its Template/NamingFormat definition Actions of target `store`, plus this page.

**Ownership rule (ADR-0015 D2).** `objects` owns **no directory-writing Action**. The create/modify Actions
(`ad.user.create`, `ad.user.update`, ...) are owned by `ad`, the module that owns their target, and *consume*
`objects` definitions. A future Entra or LDAP target brings its own Action over the same definitions. `objects` may
own only `store` Actions on its own tables.

**Plan order (ADR-0015 D1), fixed.** A Plan that consumes a Template runs: **TemplateGate**
(`pc.Templates.CheckTemplate`, a kernel port bound to the request's chain by the Runner; refusal is
`template_not_permitted`), then **`Template.CheckInput`**, then **`NamingFormat.Render`**, then the first
directory read. This package supplies `CheckInput` and `Render`; it never imports `rbac` and never names a chain.

## Owned tables

| Table | Entity | Migration | Retention |
| --- | --- | --- | --- |
| `objects_templates` | DM-50 | 0073 | Tenant-keyed, RLS. One row per version; no runtime DELETE. |
| `objects_naming_formats` | DM-51 | 0073 | Same. |

Lifecycle: template `draft -> published -> archived`; naming format `draft -> active -> archived`. At most
one draft per definition; saving replaces its body; the next save after publish opens version n+1. A DB
guard trigger makes a published version immutable (DM-50.I1; error code AD403). A Template pins the exact
NamingFormat version it uses, and `Publish` refuses a pin that is a draft or of the wrong purpose.

## Public interface

- `Templates` / `NamingFormats` (`public.go`): `SaveDraft`, `Publish`/`Activate`, `Archive` (each takes a
  `step.Step`, so the change commits with its audit event, ADR-0005 rule 2); `Get`, `Latest`, `List`
  (take the caller's `store.Tx`, so a Plan's read-only transaction works).
- `Template.Validate`, `Template.CheckInput` (mandatory, hidden and read-only violations, each naming the
  field), `Template.Effective` (defaults), `Template.ContainerAllowed` (OU objectGUIDs, DM-50.I4).
- `NamingFormat.Validate`, `Render` (first alternative whose condition holds, token rendering, DM-51.I1
  length and character check per purpose), `Candidate` (propose the next suffixed name).

## Plan-time versus DC-time

| Check | Where | Why |
| --- | --- | --- |
| Mandatory, hidden, read-only field rules | Plan, here, pure | Blocks the item before any directory read. |
| Name length and character set (DM-51.I1) | Plan, here, pure | Deterministic from the format and the input. |
| Uniqueness of sAMAccountName, UPN, CN-in-container (DM-51.I2/I7) | **The DC's atomic create** | ADR-0005 rule 4. A lookup here would race. The caller learns a name is taken from `entryAlreadyExists`; `Candidate` only proposes the next suffix. |
| Duplicate-check attributes and scope | Advisory, evaluated by the Action | Never decides uniqueness of the keyed names. |

## Invariants

- Persistence is constant SQL with bind parameters, tenant-scoped; the package does not name pgx.
- Errors are typed (`ErrNotFound`, `ErrConflict`, `ErrPurpose`, `*ViolationError`) and carry no
  definition content.
- No LDAP filter, DN or PowerShell is built here; names leave as plain values for the connector's safe
  builders.

## Not yet modelled

Module registration (ADR-0015 follow-up), the Template `rules[]` condition AST and `post_steps[]` of DM-50,
per-class `Limits.SAMMax` (only the user default of 20 exists), and the racing-create lab test (owned with the `ad` create Action).

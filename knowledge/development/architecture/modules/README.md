---
title: "Module pages: index and template"
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
author: solution-architect
ticket: T-0145
binding_sources: ADR-0003 (ratified), blueprint v0 (review)
---

# Module pages

Every server module `internal/modules/<id>/` and every agent module `internal/agentmodules/<id>/`
has one page here, `<id>.md`. Every page here has a module. `fitness-modules` **M3** fails the
build on either mismatch
([ADR-0003](../../decisions/0003-module-system-extension-points-only-on-ramp.md) rule 3), so the
map cannot lag the tree. This `README.md` is the index and the template. It is not a module page,
and M3 ignores it (`README` cannot match the module-ID pattern `^[a-z][a-z0-9]{1,30}$`).

**Who writes a page.** The ticket that creates the module writes its page in the same change. Every
later ticket that changes what the page lists (tables, Actions, datasets, permissions, …) updates
it in the same change. The code reviewer checks the page against the diff. solution-architect
checks the whole set in the weekly comprehension check.

**What a page is not.** It is not a spec. Behaviour, acceptance criteria and parity live in the
module's PRD or feature spec under `knowledge/product/`, and the page links to it. The page records
**the module's shape**: what it owns, what it registers, and what it depends on. This is the
information a reviewer needs to answer "does this change belong here, and does it obey ADR-0003?".

## Index

No module exists yet. The planned server modules are in [blueprint §5.4](../blueprint.md#54-server-feature-modules-internalmodulesid)
and the agent modules in §5.5. `connections` and `objects` come first (ADR-0003 rule 8). Add a row
here when a page is created.

| Module | Tier | Owner | Page | Spec |
| --- | --- | --- | --- | --- |
| — | — | — | — | — |

## Template

Copy everything below the line into `<id>.md`, replace each placeholder, and delete the guidance in
*italics*. Write "none" where a section is empty. Do not delete a section: an empty section is a
fact the reviewer needs.

---

```markdown
---
title: "Module: <id>"
date: YYYY-MM-DD
updated: YYYY-MM-DD
status: draft | review | accepted
owner: heramb
author: <agent>
ticket: T-NNNN            # the ticket that created the module
tier: server | agent
---

# Module `<id>`

**Purpose.** One or two sentences: the job this module does for an admin.
**Owner:** <agent> (blueprint §5.4 or §5.5). **Epic:** E-x.y. **Spec:** [<spec>](../../../product/specs/<spec>.md).
**Parity:** ADM-### … (feature IDs this module implements).
**Capabilities required (`Requires()`):** `<capability.ID>` … *(none means it loads in every profile)*.
**Platform matrix:** windows / linux-oci / saas: same | differs. *If it differs, cite the ADR that
declares the asymmetry (blueprint §3.4). An undeclared asymmetry is a defect.*

## Owned tables

*Every table this module owns. Each migration is `migrations/NNNN_<id>_<what>.sql` (ADR-0003 rule 6).
A module never owns a table a lower layer reads: if the kernel, the directory domain or the
connector needs the data, it belongs below and this module writes it through the owner's Go API
(§ "Writes to other owners" below).*

| Table | Entity (DM-nn) | Migration | Partitioned | Retention |
| --- | --- | --- | --- | --- |

## Contributions (what `Register` registers)

*Every ID starts with `<id>.` (`module.Boot` rejects anything else). One row per contribution.*

| Kind (Registrar method) | ID | Notes |
| --- | --- | --- |
| API (EP-2) | tag `<id>` | OpenAPI file `api/openapi/<id>.yaml` |
| Action (EP-3) | `<id>.<class>.<verb>` | permission; reversibility; named secret ops if any |
| Permission (EP-6) | `<id>.<…>` | scope kinds it applies over |
| ScopeEvaluator (EP-6) | scope kind | at most one per scope kind |
| AuditKind (EP-7) | `<id>.<…>` | including setting changes |
| Dataset (EP-8) | `<id>.<…>` | tables, all owned by this module |
| Job (EP-5) | `<id>.<…>` | schedule; lease; idempotency |
| Sink (EP-9) | `<id>.<…>` | |
| AuthMethod (EP-10) | `<id>.<…>` | |
| ApprovalGate (EP-4) | `<id>.<…>` | non-default gates only |

*Agent modules: replace this table with the EP-13 contract items (`activediq.<id>.v1` services,
event sources, policies) as T-0040 defines them.*

## Dependencies

*Server modules get exactly `New(platform.Deps, directory.Services)`. List the fields this module
uses, so a reviewer can see the real coupling.*

- **`platform.Deps` fields used:** `operation`, `audit`, … *(each with one line on what for)*
- **`directory.Services` fields used:** `inventory`, `client`, `connection` *(and what for)*
- **Other modules' Actions called by ID:** `<other>.<class>.<verb>` … *(never an import, ADR-0003 rule 2)*
- **Datasets consumed:** `<owner>.<dataset>` …
- **Writes to other owners:** *each write to a table this module does not own, with the owner's Go
  API or port it goes through (for example `directory/connection`'s Go API, reached via
  `directory.Services`).*
- **Third-party libraries:** *each library with its licence-register row. Name any library that
  starts goroutines, timers or listeners: M4 cannot see those, so the reviewer checks this list
  (ADR-0003 "Not automatable").*

## Web module

`web/src/modules/<id>/` — routes, palette actions, search-result renderers *(or "none": a web module
always has this server module, never the reverse requirement)*.

## Security notes

*Secrets it touches (only as `secret.Secret`), Tier-0 reach, which writes are irreversible, which
safe primitives it uses (`ldapfilter`, `dn`, SD, …). Link the threat-model section if one exists.*

## Changelog

- YYYY-MM-DD · T-NNNN · created.
```

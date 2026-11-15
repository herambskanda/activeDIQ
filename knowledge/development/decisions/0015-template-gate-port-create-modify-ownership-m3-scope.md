---
title: "ADR-0015: TemplateGate is a kernel port on PlanContext; `ad` keeps the create/modify Actions; fitness-modules M3 is built in two cuts; ErrNameInUse is typed"
date: 2026-11-15
updated: 2026-11-15
status: proposed
owner: heramb
author: solution-architect
kind: technical
ticket: T-2162
fitness: TG1–TG3 (template-gate), OW1 (ownership), M3a/M3b (fitness-modules), NU1 (name-in-use) — to be built; follow-up tickets below
---

# ADR-0015: TemplateGate port, create/modify ownership, M3 scope, typed ErrNameInUse

**Status:** proposed 2026-11-15, for factory-director review of T-2162. `accepted` only when TG1–TG3,
OW1, M3a/M3b and NU1 run green in `make ci` on `main`.
**Kind:** technical (no price, packaging, deployment or platform change).
**Builds on / amends:** ADR-0003 (extension points; M3 text), ADR-0005 (operation pipeline, rules 2, 4, 5),
ADR-0013 (Registrar). Unblocks T-2142.

## Context

T-2142 stopped on four questions:

1. `operation.PlanContext` carries `Tx`, `Facts`, `Pins` only. The requester `authority.Chain` is known to
   the Runner (`op.Chain`, `submit.go`, `runner.go`) but is not reachable from `Plan`, and
   `platform.Deps.Authz` is the narrow `operation.Authorizer`. So `rbac.Authorizer.CheckTemplate`
   (T-1600, ADM-132) has no caller. A module that imported `rbac` and passed a chain itself would
   bypass the kernel and could pass the wrong chain.
2. `internal/modules/ad` already owns `ad.user.create/update/delete/move/rename/restore`, which call
   `objects.Template.CheckInput` and `NamingFormat.Render` in `planCreate` before the first directory read.
3. `fitness-modules` M3 is text in ADR-0003 only; `tools/fitness/modules` implements the T-0014 subset and M7.
4. Rule-5 `NameInUse` (`connector/write`: `invalid("5","NameInUse",…)`) reaches `ad.writeError` untyped.

## Decision

**D1. TemplateGate is a kernel port, bound to the request's chain by the Runner.**
`operation` declares

```go
// TemplateGate refuses a Template the requester's authority does not permit (ADM-132).
type TemplateGate interface {
    CheckTemplate(ctx context.Context, perm authz.Permission, template string) error
}
```

`PlanContext` gains `Templates TemplateGate`. `Config` gains `TemplateAuthz` (the unbound form,
`CheckTemplate(ctx, chain, perm, template)`; `*rbac.Authorizer` satisfies it structurally). Both Runner
paths (`submit.go`, `runner.go`) build `PlanContext.Templates` as a closure over `op.Chain` and the
request's tenant context, exactly as `pinnedReader` binds pins: **a Plan cannot name the chain**. A nil
`TemplateAuthz` yields a gate that **denies** (fail closed). A refusal is returned as `*PlanRefusal{Code:
"template_not_permitted"}`, so a preview shows a blocked entry and a submit audits the denied attempt (rule 4).
`compose/server/operation.go` wires `rbacAuthorizer` into `Config.TemplateAuthz`; no module imports `rbac`.
Order inside a Plan is fixed: **TemplateGate, then CheckInput, then Render, then the first read**.

**D2. `ad` keeps the create/modify Actions; `objects` does not get a second set.**
Action IDs are `<owner>.<noun>.<verb>` and stable (X6); `ad.user.create` is already shipped and keyed in
audit, so moving it would rename history. `objects` is the definitions library (Template, NamingFormat);
the Actions that *consume* it live with the directory they write to, so a future Entra or LDAP target
brings its own Action over the same `objects` definitions (parameterise, don't clone). Therefore:
`objects` registers as a Module (stores, Template/NamingFormat definition Actions of target `store`, its
architecture page) and **owns no directory-writing Action**. `ad`'s `planCreate` and the modify Plan call
`pc.Templates.CheckTemplate` before `loadTemplate`. Nothing is moved or deleted.
Rule for the future: an Action is owned by the module that owns its target; `objects` may own only `store`
Actions on its own tables.

**D3. fitness-modules M3 is built in two cuts.** M3 as written has five unrelated checks. Cut **M3a**
(blocks T-2142's AC1): a module package imported outside the generated file of `compose/server` or
`compose/agent`; a `.gen.go` lacking the generated header; module lists regenerated to different bytes
(`tools/gen/modules`); a module with no architecture page or a page with no module. Cut **M3b**: module-ID
pattern, top-level package-name uniqueness across the four roots, `store/owners/owners.gen.go`
regeneration, web-module-has-server-module. M3a ships first with failing fixtures in `check_test.go`. T-0990
still carries M1, M2, M4–M6, M8–M12.

**D4. `ErrNameInUse` is a typed sentinel.** `directory/client` declares `ErrNameInUse`; `client.MapError`
maps rule-5 `NameInUse` and connector `CodeNameInUse` (entryAlreadyExists) to it. `ad.writeError` returns
`fmt.Errorf("%w: name_in_use", operation.ErrInvalid)` wrapping `client.ErrNameInUse`, so
`errors.Is(err, client.ErrNameInUse)` and `errors.Is(err, operation.ErrInvalid)` both hold. In a race,
exactly one Apply succeeds and the other fails `name_in_use`; never a retry, never an overwrite.

## Options considered

- **Pass `authority.Chain` into `PlanContext`.** Rejected: any Plan could then call any authorisation with
  any chain; the bound closure removes that degree of freedom and matches the `PinnedFacts` pattern.
- **Widen `operation.Authorizer` with `CheckTemplate`.** Rejected: every Store Action's test double must
  grow a method, and the chain is still not in Plan.
- **Module imports `rbac` directly.** Rejected: bypasses the kernel, breaks ADR-0003 layering.
- **Move create/modify to `objects` and delete `ad`'s.** Rejected: renames shipped Action IDs and audit
  kinds, clones nothing but breaks Entra/LDAP parameterisation, and costs a migration for no capability.
- **Build all of M3 in one ticket.** Rejected: delays T-2142 on unrelated checks.

## Consequences

Plans stay read-only and cannot choose the chain. Every Template-using Action has one line to call and a
fitness check that it does. `objects.md` loses its "T-1631 will add Actions" note and states the rule in D2.
Tests that build a `PlanContext` by hand leave `Templates` nil; the test helper supplies an allow/deny fake.

## Fitness function

- **TG1** (unit, `operation`): a Plan run by either Runner path sees a gate bound to `op.Chain`; nil
  `TemplateAuthz` denies; a refusal becomes `template_not_permitted`.
- **TG2** (`tools/fitness/modules`, new rule): any `Plan` in `internal/modules/**` that references
  `objects.Template`/`TemplateRef` must call `Templates.CheckTemplate` before the call to `CheckInput` or the first `Facts`.
  Failing fixture included.
- **TG3** (import rule): `internal/modules/**` must not import `internal/platform/rbac`.
- **OW1**: an Action whose `Descriptor.Target != TargetStore` and whose ID prefix is `objects.` fails the build.
- **M3a / M3b**: as D3.
- **NU1**: a table test: rule-5 `NameInUse` and `CodeNameInUse` map to `client.ErrNameInUse`; the lab test
  (T-2142 AC4) asserts exactly one of two racing Applies fails with it.

## Follow-ups (tickets)

Platform port (T-2163), M3a fitness (T-2164), ad wiring + ErrNameInUse + objects Module + lab test (T-2142,
narrowed), M3b (T-2165), architecture-map update (T-2166).

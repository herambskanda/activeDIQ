---
title: "ADR-0003: Features enter only as modules through a typed Registrar; the core imports no module, every table has one owner, and CI enforces the import graph"
date: 2026-10-02
updated: 2026-10-02
status: proposed
owner: heramb
kind: technical
ticket: T-0045
fitness: fitness-modules
---

# ADR-0003: Features enter only as modules through a typed Registrar; the core imports no module, every table has one owner, and CI enforces the import graph

**Status:** proposed. The factory-director ratifies it when reviewing T-0045, then files a `notice`. It becomes `accepted` when `fitness-modules` (M1–M12 below) runs green in `make ci` on `main`.
**Kind:** technical. It changes nothing a customer, partner or the brand would notice. It decides where code goes and what CI rejects.
**Deciders:** solution-architect (author); factory-director (ratifier). **Ticket:** T-0045. **Parity / scope refs:** none directly. It serves every capability family in blueprint §15.

> Amendments (ratified ADRs only): none.

## Context

**What this ADR makes binding.** The [architecture blueprint](../architecture/blueprint.md) (§2, §4, §5) describes a module system:
- layered imports: `platform ← directory ← modules ← compose/cmd`;
- a typed Registrar as the only way a server module contributes anything;
- generated module lists in the composition root;
- one owning package per table;
- the same rules for agent modules and web screens.

The blueprint is design direction. Its §2 says these rules "become binding through T-0045". Until then, code review alone applies them. Product code starts in M2, and the first two server modules (`connections`, `objects`) are on the checkpoint 2a critical path (`knowledge/business/scoping/m2-plan.md` §3). So the rules must be binding, and enforced, before that code lands.

**Precedent: PatchIQ ran this experiment and recorded the result.** UEM [ADR-0002](../../../../UEM/knowledge/development/decisions/0002-extension-points-precede-features.md) and the PatchIQ postmortem (`../UEM/knowledge/development/legacy/patchiq-postmortem.md` §5–§6, §11) give the evidence:
- **Two tiers got their extension point before their features.** The hub (`verticals.Vertical`) and the agent (`agent.Module`) both did. Adding a capability there was additive.
- **The server got the same interface after its features.** `internal/server/module.go` defined a module contract with zero implementations and zero callers. Instead, `cmd/server/main.go` hand-built 36 subpackages and passed them to a `NewRouter` with **53 parameters**. 94 of 156 API handler files imported the store directly.
- **An "Accepted" ADR had no implementation** (postmortem §11 #4).

Neither a document nor an interface enforces itself. UEM ADR-0002 drew four rules from this:
1. the extension point comes first;
2. the first two features on each tier go through it;
3. core wiring never names a module and takes no module-typed parameters or boxes of them;
4. "accepted" means enforced in CI.

This ADR adopts those rules and adds what activeDIQ needs beyond UEM's case.

**What is specific to activeDIQ, and why the decision is not just "copy UEM ADR-0002".**
- **Planes are separated by the link graph.** [ADR-0002](0002-deployment-model.md) rule 2 puts `edge` in the user-access plane, which is "assumed compromised", and puts the DC agent in Tier 0. A module system that lets any package import any other lets the connector's credential code into the edge binary through one innocent import. So binary hygiene, meaning what each `cmd/` binary may *link*, is part of the module system here. The factory-director's T-0004 review named two gaps:
  - agent modules can reach `store` through `directory/inventory`;
  - `connector/credential/sealed` and `platform/keys` must be checked out of `cmd/connector`, not just stated.
- **Tables are where PatchIQ's boundary actually broke.** Handlers called generated SQL directly, so every package could read every table, and there was no service boundary to refactor toward. ADR-0002 T5 already confines SQL that names a *registered-global* table to its owning package. This ADR generalises that rule to every table.
- **"Feature" has more homes here than in UEM.** Code can land in `platform`, `directory`, `connector`, `compose` or `cmd`. A rule that only says "features are modules" is bypassed by filing a feature as kernel. The on-ramp is only the *only* on-ramp if the other homes are closed.
- **A scaffold already exists.** T-0014 built:
  - `internal/platform/module`, with a `Registrar` **interface** that has one method, `Action`;
  - a first `tools/fitness/modules` that checks blueprint §2 rules 1–5, 7 and 8 by parsing imports.

  This ADR decides the final shape. The scaffold migrates to it (follow-on tickets).

**Mechanisms available in Go, and the constraints that bind them.**
- ADR-0001 requires cgo-free Go cross-built for Windows and Linux (`fitness-stack` F2).
- Go's `internal/` rule stops only *outside* modules from importing our packages ([Go 1.4 internal packages](https://go.dev/doc/go1.4#internalpackages)). Layering inside the module is ours to enforce.
- The standard `plugin` package is "supported only on Linux, FreeBSD, and macOS" and needs every part built with "exactly the same version of the toolchain, the same build tags" ([pkg.go.dev/plugin](https://pkg.go.dev/plugin)). That rules it out for a Windows-first product.

## Decision

We will make **modules registered through a typed Registrar the only way a feature enters any tier**. We will close every other home a feature could take. We will give every table exactly one owning package. And we will enforce all of it with `fitness-modules` in `make ci`. Nine rules follow.

### Rule 1: The import graph

Every Go package in the repository belongs to exactly one **class** below. The matrix is an allowlist: an import between our own packages that the matrix does not allow fails CI. **A package that matches no class also fails** (M1), so a new directory cannot slip in unclassified. Imports of the standard library are always allowed. Imports of third-party modules are governed by the stack manifest and `fitness-stack`, not by this matrix.

**The classes.** The first matching line wins.

| Class | Packages |
| --- | --- |
| **kernel root** | `internal/platform` itself. It declares `platform.Deps` (rule 4) and aggregates kernel services |
| **kernel** | every package under `internal/platform/` |
| **directory root** | `internal/directory` itself. It declares `directory.Services` (rule 4), which holds `inventory`, `connection` and `client`. It is therefore a **directory service** for every rule that names that class, so agent modules and the connector can never import it |
| **directory primitives** | `internal/directory/{ldapfilter,dn,model}` and everything under `internal/directory/attr/` |
| **directory services** | every other package under `internal/directory/` (`inventory`, `sync`, `client`, `connection`, …) |
| **connector** | `internal/connector` and everything under it |
| **server module** | `internal/modules/<id>` and everything under it. The doc-only root `internal/modules` imports nothing and is imported by nothing |
| **agent module** | `internal/agentmodules/<id>` and everything under it. The doc-only root `internal/agentmodules` imports nothing and is imported by nothing |
| **role package** | `internal/compose/<role>` (`server`, `connector`, `edge`, `agent`; later `radius`, `fpolicy`, `t0connector`) |
| **`compose/config`**, **`compose/profile`** | the config loader and the manifest data |
| **`webui`** | `internal/webui` (the `go:embed` package for the built console) |
| **`migrations`** | the repository-root `migrations` package (`embed.go`, rule 6) |
| **proto: skenzeriq** / **proto: activediq** | generated code under `internal/proto/skenzeriq/` and `internal/proto/activediq/` |
| **`cmd/<role>`** | each `main` package |
| **tools: inspect** | `tools/fitness/**` and `tools/gen/**` |
| **tools: other**, **lab** | every other package under `tools/`, and every package under `lab/` |
| **garage** | every package under `garage/` |

**The matrix.** ✓ means allowed. — means it fails.

| Importer ↓ may import → | kernel root | kernel | dir. primitives | dir. root + services | connector | server module | agent module | role pkg | `config` | `profile` | `webui` | `migrations` | proto: skenzeriq | proto: activediq |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| kernel root | — | ✓ | — | — | — | — | — | — | — | — | — | — | ✓ | — |
| kernel | — | ✓ | — | — | — | — | — | — | — | — | — | — | ✓ | — |
| directory primitives | — | ✓ ¹ | ✓ | — | — | — | — | — | — | — | — | — | ✓ | ✓ |
| directory root + services | — | ✓ | ✓ | ✓ | — | — | — | — | — | — | — | — | ✓ | ✓ |
| connector | — | ✓ ¹ | ✓ | — | ✓ | — | — | — | — | — | — | — | ✓ | ✓ |
| server module `<id>` | ✓ | ✓ | ✓ | ✓ | — | own `<id>` only | — | — | — | — | — | — | ✓ | ✓ |
| agent module `<id>` | — | ✓ ¹ | ✓ | — | — | — | own `<id>` only | — | — | — | — | — | ✓ | ✓ |
| role package | `server` only | ✓ ¹ | ✓ | ✓ ¹ | `server`, `connector`, `t0connector` only | `server`'s generated file only (rule 3) | `agent`'s generated file only | — | ✓ | ✓ | `server` only | `server` only | ✓ | ✓ |
| `compose/config` | — | `platform/capability` only | — | — | — | — | — | — | — | ✓ | — | — | — | — |
| `compose/profile` | — | `platform/capability` only | — | — | — | — | — | — | — | — | — | — | — | — |
| `webui`, `migrations` | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| proto: skenzeriq | — | — | — | — | — | — | — | — | — | — | — | — | ✓ | — |
| proto: activediq | — | — | — | — | — | — | — | — | — | — | — | — | ✓ | ✓ |
| `cmd/<role>` | — | — | — | — | — | — | — | own `<role>` only | ✓ | — | — | — | — | — |
| tools: inspect | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| tools: other, lab | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| garage | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

¹ Rule 7 narrows this per binary. For example, an agent module or the connector may import no kernel package that reaches `store`, and `compose/connector`, `compose/edge` and `compose/agent` may link no directory service.

Further rules on the graph:
- **Only two places import the aggregating roots.** `internal/platform` and `internal/directory` are imported only by server modules and `compose/server`. No kernel, directory or connector package imports either root (Go's cycle rule already forbids most of these cases; M1 states it for all of them).
- **Agent modules are like the connector.** They import directory primitives and kernel packages, never the directory root or directory services (`inventory`, `sync`, `client` and `connection` reach `store`). This closes director note (1) on T-0004.
- **Nothing outside them imports `garage/`, `tools/`, `lab/` or `third_party/`.** The `garage` and `tools: inspect` rows only let those packages import others. No row lets a product package import them. Inside a zone, packages may import each other: `tools/**` imports `tools/**` (for example `tools/fitness/tenancy` → `tools/fitness/tenancy/registry`, `tools/vettool` → `tools/analyzers`), `lab/**` imports `lab/**`, and a garage prototype imports its own packages. Code under `third_party/<name>/` is imported only as its register row in the stack manifest allows (ADR-0001 rule 5).
- **`webui` and `migrations` are leaves.** They embed files and import only the standard library. Only `compose/server` imports them: it mounts the console through `apihost` and injects the migration step into `update` (blueprint §5.1).
- **Exceptions, the complete list:**
  - **Tests.** A `_test.go` file obeys its package's row, including external `_test` packages. There is no test exception for the graph. A test that needs another module means the contract is missing something. Cross-module behaviour is tested in `internal/compose/server` tests, which boot modules through the generated list. Test doubles for kernel contracts live in kernel test kits (`internal/platform/<pkg>/<pkg>test`), which are kernel packages and obey the kernel row.
  - **`tools: inspect`** may import any package in order to inspect it. Rule 7 then requires that no `cmd/` binary links anything under `tools/`.
  - **`garage`** may import anything, because nothing imports it and no binary links it (rule 7). Its owner and expiry are enforced by the garage rules, not here.
  - **No other exception exists.** The import graph has no exemption registry (M11 refuses entries for M1). A new class, row or column, such as a later `cmd/radius` row, is an **amendment to this ADR** recorded on its Amendments line by solution-architect. Removing a rule takes a superseding ADR.

### Rule 2: Modules are islands

- A server module never imports another server module.
- An agent module never imports another agent module.
- Neither kind imports the other kind, `compose`, or `cmd`.
- Modules cooperate only through kernel registries, by ID:
  - an Action by `ActionID` (blueprint §4.2);
  - a report dataset;
  - an audit kind;
  - a notification sink;
  - a job kind.

  For example, a leaver policy in `lifecycle` composes `objects.user.disable` and `m365.licence.remove` by ID. It does not import either module.

### Rule 3: Only generated lists name a module

There are three lists. Nobody edits them by hand:
- `internal/compose/server/modules.gen.go`;
- `internal/compose/agent/modules.gen.go`;
- `web/src/app/modules.gen.ts`.

`tools/gen/modules` (one generator, three outputs) writes them from the directory tree:
- every directory `internal/modules/<id>/` holding a non-test Go package;
- every `internal/agentmodules/<id>/`;
- every `web/src/modules/<id>/index.ts`.

Each file starts with `// Code generated by tools/gen/modules; DO NOT EDIT.` (the [Go convention](https://pkg.go.dev/cmd/go#hdr-Generate_Go_files_by_processing_source)). The rule has five parts:
- **Who may import a module.** No file except these three may import a module package. In `compose/server` and `compose/agent`, only the generated file may.
- **Staleness fails.** CI regenerates all three lists into memory and compares them byte for byte with the committed files. Any difference fails.
- **IDs are names.** A module ID matches `^[a-z][a-z0-9]{1,30}$`, is the directory name, and is also the module's OpenAPI tag (T-0046) and its web module ID. At boot, `module.Boot` rejects a module whose `ID()` differs from the ID the generated list recorded for it.
- **Web modules have server modules.** Every `web/src/modules/<id>` matches an `internal/modules/<id>`. Shell-only screens belong in `web/src/app`.
- **Every module has a page.** Every `internal/modules/<id>` and `internal/agentmodules/<id>` has `knowledge/development/architecture/modules/<id>.md`, and every page has a module (blueprint §5 already requires the page). The map cannot lag the tree.

### Rule 4: The server module contract and the Registrar (EP-1)

```go
// internal/platform/module
type ID string

type Module interface {
    ID() ID
    Requires() []capability.ID      // the module loads only if every capability is enabled
    Register(r *Registrar) error    // called exactly once, at boot; the only way to contribute anything
}

// Registrar is a concrete type owned by platform/module. Its fields are unexported, so it cannot be
// built outside the package, and its zero value refuses every call.
type Registrar struct{ /* owner ID, closed flag, collected contributions */ }

func (r *Registrar) Action(a operation.Action) error        // EP-3
func (r *Registrar) API(h apihost.TagHandlers) error        // EP-2 (shape: T-0046)
func (r *Registrar) Job(k jobs.Kind) error                  // EP-5, includes schedules
func (r *Registrar) Permission(p authz.Permission) error    // EP-6
func (r *Registrar) ScopeEvaluator(e authz.ScopeEvaluator) error
func (r *Registrar) AuditKind(k audit.Kind) error           // EP-7
func (r *Registrar) Dataset(d report.Dataset) error         // EP-8
func (r *Registrar) Sink(s notify.Sink) error               // EP-9
func (r *Registrar) AuthMethod(m authn.Method) error        // EP-10
func (r *Registrar) ApprovalGate(g operation.Gate) error    // EP-4

// Boot builds one Registrar per module, calls Register, closes every Registrar and returns the
// validated contributions. Only internal/compose/server calls it.
func Boot(ctx context.Context, mods []Entry, enabled capability.Set) (*Contributions, error)
type Entry struct { ID ID; Module Module }                  // what the generated list builds
```

**Each method arrives with its extension point.** A Registrar method is added by the ticket that builds its extension point (EP-2 to EP-10, blueprint §4). The interface never names a type that does not exist yet. That is what the scaffold does now, and it stays.

**The Registrar is a concrete struct, not an interface.** This supersedes the scaffold. Only the kernel's implementation can do the following:
- attribute every contribution to its module ID;
- enforce namespacing;
- refuse calls after boot.

A substitutable interface would let a test double, or a module's own wrapper, skip all three. Tests get a real Registrar from the test kit `internal/platform/module/moduletest`, through `moduletest.Register(m) (*module.Contributions, error)`.

**What `Boot` validates, failing start-up on any error:**
- **Namespacing.** Every contributed ID starts with `<moduleID>.`. This covers Action IDs, permissions, audit kinds, job kinds and dataset IDs. An `API` tag equals the module ID.
- **No duplicates.** A duplicate ID fails. At most one `ScopeEvaluator` per scope kind and one non-default `ApprovalGate`. The gate's interplay with Actions is T-0047's to decide.
- **Closed after boot.** `Register` is called once. A Registrar used after `Boot` returns gives `ErrClosed`, so a module that stashes `r` gains nothing.
- **Capabilities.** A module whose `Requires()` is not satisfied is not constructed into the contributions. No other code asks which profile it is running in (ADR-0002 P1).
- **Dataset tables.** A `Dataset` may name only tables its module owns, according to the generated ownership map (rule 6). `Boot` checks this, so a violation **fails start-up**. CI sees the failure first, because the `compose/server` boot test runs `Boot` over every module in the generated list. The same function checks the datasets that kernel and directory packages export (for example `inventory.Datasets()`), with the exporting package's owner key, when `compose/server` hands them to `report`. The map lives in the data-only leaf package `internal/platform/store/owners`, so `platform/module` does not link `store`.

**Modules have no lifecycle methods.** There is no `Init`, `Start` or `Stop`. A server module owns no goroutines, listeners or timers, which means no goroutine or timer it starts outlives the call that started it.
- Background, periodic and long-running work is a registered `Job` kind or schedule. It runs on `platform/jobs`, which carries the tenant and the leases.
- Request handling goes through `API`.
- This is stricter than PatchIQ's server contract (`Init/Start/Stop`, postmortem §6). It keeps every running piece of work tenant-carrying and visible to the job engine.
- If a module needs something this cannot express, the Registrar gains a method through the EP ticket that needs it. It never gains a side channel.
- **What CI checks (M4), and what it cannot.** Non-test code under `internal/modules/**` contains no `go` statement anywhere, not only in `Register`. It also makes no reference to `time.AfterFunc`, `time.NewTicker`, `time.NewTimer` or `time.Tick`. Request-scoped concurrency that joins before it returns uses a kernel helper. The first ticket that needs one adds it to the kernel; modules never write a raw `go`. A goroutine started *inside a library function* that a module calls cannot be seen by a syntax check, so it is listed under "Not automatable".

**How dependencies reach a module.** This is UEM ADR-0002 rule 3. Each server module package exports exactly one constructor:

```go
func New(deps platform.Deps, dir directory.Services) module.Module
```

- **`platform.Deps`** lives in package `internal/platform`, the one kernel package that aggregates the others. It is a fixed struct of kernel services: operation, audit, authz, jobs, report, notify, keys, blob, telemetry, …
- **`directory.Services`** lives in package `internal/directory`. It is a fixed struct holding `inventory`'s read API, the `client`, and the `connection` registry with its credential port (rule 6, F1).
- **Both grow per kernel service, never per module.** A field's type must be declared in a kernel or directory package listed in the blueprint catalogue (rule 8). A field typed by an interface declared in the aggregating package itself is how a "service for one module" sneaks in, so it fails.
- **The generated list is the only caller.** It calls `New` for each module and passes the same two values to every module.
- **The boxed bypass is closed by construction.** A struct, slice or map of concrete module types cannot appear anywhere: rule 3 means no package but the generated list can *name* a module type. The bounded parameter list (≤ 8, M5) catches a growing constructor anywhere else in `internal/`.

**Agent and web tiers follow the same rules, with tier-specific shapes.**
- **Agent.** The agent module contract (EP-13, `skenzeriq.agent.v1`) and the host's dependency struct are T-0040's to specify. This ADR binds the rules around them:
  - the generated list;
  - one fixed constructor signature per tier, never module-typed parameters;
  - no lifecycle outside the contract;
  - no module-to-module imports;
  - the rule 1 row and the rule 7 `cmd/agent` row.
- **Web.** Each `web/src/modules/<id>/index.ts` exports one `WebModule` value built with `defineModule({ id, routes, palette, searchResults })` from `web/src/app`.
  - `web/src/app` and `web/src/ds` never import `web/src/modules/*`, except that `app` imports the generated `modules.gen.ts`.
  - Web modules never import each other.
  - Screens get data only through the generated client `web/src/api` (T-0046).

### Rule 5: The other homes of a feature are closed

The on-ramp is the only on-ramp only if a feature cannot be filed anywhere else:

| Home | What closes it |
| --- | --- |
| `cmd/<role>` | It imports only its own `compose/<role>`, `compose/config` and the standard library (about 20 lines, blueprint §1). |
| `internal/compose/**` | It declares no type that satisfies an extension-point interface. It does not reference `net/http`'s `ServeMux`, `Handle` or `HandleFunc` (`apihost` owns the mux). It hands the kernel hosts only two kinds of contribution: values from `module.Boot`'s result, and values that kernel or directory packages export for their own extension points (for example `inventory.Datasets()`). It builds none itself. |
| `internal/platform/**`, `internal/directory/**`, `internal/connector/**` | **The catalogue is closed.** Every top-level package under these roots must have a row in blueprint §5.1, §5.2 or §5.3. A new kernel, directory or connector package therefore needs a blueprint change, reviewed by solution-architect. That review asks whether it is really core. |
| Kernel host packages | **They expose no back door.** An exported function or method in `internal/platform/**` that takes an extension-point type may be called only from `internal/platform/**` and `internal/compose/**`. The types are `module.Module` (EP-1) and `operation.Action`, `jobs.Kind`, `report.Dataset` and the others; the list is kept in the fitness configuration. A module therefore cannot hand itself to a host directly. It goes through the Registrar. **The one sanctioned exception is the test kit:** `moduletest.Register(m)` takes a `module.Module` and may be called from `_test.go` files anywhere. It builds a real, private `Registrar`, runs the `Boot` validations for that one module and returns the contributions to the test. It touches no host, so nothing it does reaches a running process. No other kernel function is exempt. |
| Inside a module | No `func init()` in `internal/modules/**` or `internal/agentmodules/**`, so there is no self-registration side channel. No `net.Listen`, `http.ListenAndServe`, `http.Handle`, `http.HandleFunc` or `http.DefaultServeMux`. No `go` statement and no timer constructor in server-module non-test code (rule 4). Agent modules run inside the agent host, whose contract (T-0040) decides what long-running work they may do. |

### Rule 6: One owner per table

- **The migration filename names the owner.** `migrations/NNNN_<owner>_<what>.sql`. The `<owner>` segment is an **owner key**. It must resolve to exactly one **top-level package** under one of the four **owner roots**:
  - `internal/platform/<key>`;
  - `internal/directory/<key>`;
  - `internal/connector/<key>`;
  - `internal/modules/<key>`.

  The key is that package's directory name (`[a-z][a-z0-9]*`, no separators). Subpackages never own on their own: `credential/sealed`, `store/reportsql` and `fleet/dial` belong to the key of their top-level package. The check fails if no package resolves, or if two would. **Top-level names are therefore unique across the four roots**, which M3 checks for every package whether or not it owns a table yet. For example, a module may not be called `client`. The first migration becomes **`0001_tenant_tenants.sql`**: `tenants` is owned by `internal/platform/tenant`, and `platform` is not a package. No product migration exists yet, so the rename is free. It touches only a `fitness-tenancy` fixture and `tenancy-fitness.md` (T-0144).
- **The owner of code is its top-level package.** All code under `internal/<root>/<key>/**` has owner key `<key>`, for each of the four roots. Code anywhere else (`compose`, `cmd`, the aggregating roots, agent modules) owns no table and may contain no SQL that names one.
- **Where an owner's SQL may run is rule 7's business, not rule 6's.** An owner whose top-level package is linked by a satellite binary keeps its SQL in a server-only subpackage under the same key, and `compose/server` wires that subpackage in. This applies to `update` (DM-03 Node, DM-05 Release), `fleet` (DM-12 Component) and `credential` (DM-11, SQL only in `credential/sealed`). The rule 7 rows then prove that `cmd/connector` and `cmd/agent` never link it.
- **A migration owns what it creates and touches only that.** It owns the tables, partitions, views, types, sequences and functions it creates. It may alter, index, grant on, add policies to or write rows into only objects its owner owns.
  - It **may** `REFERENCES` another owner's table, because foreign keys (every tenant table references `tenants`) are a dependency, not ownership. **The reference must not point upward, though.** A kernel-owned table references only kernel-owned tables, which keeps the platform extractable (ADR-0002, "The boundary with UEM"). No table outside a module references a module-owned table. A link that does point upward is an **opaque typed reference** with no foreign key, resolved through the owning module's registered extension point. DM-36's `scope_id`, which `authz` resolves through `delegation`'s `ScopeEvaluator`, is the model case. M8b checks this from the catalog.
  - A partition belongs to its parent's owner.
  - A view may select only its owner's tables. Cross-owner reads are datasets, not views.
- **Query SQL references only the owner's tables.** This covers sqlc query files, the SQL constants handed to `store`, and generated `sqlcdb/` code. Other packages read through the owner's Go API or a registered report dataset.
  - The report compiler `internal/platform/store/reportsql` is the one place that emits SQL spanning owners. It does so only from registered datasets, whose tables are checked against their registering package (rule 4, `Boot`). Which joins between datasets it may compile is the report engine's design (reporting-engineer, T-0026 / E2.6).
- **A module never owns a table that a lower layer reads.** The kernel, the directory domain and the connector cannot import a module (rule 1), so they could reach such a table only through SQL or an upward reference, and both fail. Data the layers below need is therefore owned below and written by the module through that owner's Go API, inside the module's Actions. Rule 9 applies this to every entity in the domain model.
- **Writes of secret material go in through a port, and only metadata comes out.** DM-11's table is owned by `connector/credential`, but `connections` must create, rotate and revoke credentials, and modules cannot import the connector (rule 1). So `directory/connection` declares a credential **port**: an interface that accepts secret material only as `secret.Secret`, returns only public metadata (a `directory/model` type), and has no method that returns secret material. `credential/sealed` implements it. `compose/server` hands it to `directory/connection` as a value, exactly as it hands the embedded transport to `directory/client` (blueprint §2 rule 3), and modules reach it through `directory.Services`. Unsealing stays under `internal/connector/` (DM-11.I1). The method set belongs to the `connections` build ticket, and security-architect reviews it there (T-0007 owns custody).
- **An ownership map is generated.** `tools/gen/modules` also writes `internal/platform/store/owners/owners.gen.go` (table → owner key), a data-only package that imports nothing. The dataset check in `Boot` and the static check both read it.
- **Exemptions are registered.** A cross-owner data migration, for example a backfill, needs an entry in `tools/fitness/modules/exempt.json`. The entry carries a reason, the ticket and an expiry date. Entries that lack a reason or ticket, are expired, or are stale fail (M11).

This generalises ADR-0002 T5's global-table rule. T5 stays as it is.

### Rule 7: Binary hygiene

`go list -deps ./cmd/<role>` is evaluated for `GOOS=windows` and `GOOS=linux` (amd64; arm64 where the binary ships). It must contain none of the following:

| Binary | Must not contain | Why |
| --- | --- | --- |
| every `cmd/*` | `tools/**`, `garage/**`, `lab/**` | dev tooling and prototypes never ship |
| `cmd/server` | `internal/agentmodules` | agent code runs on customer hosts, never in the server |
| `cmd/connector` | `internal/modules`, directory services, `platform/apihost`, `internal/webui`, `platform/store`, `platform/keys`, `connector/credential/sealed` | a remote connector serves no API, has no database and holds only local credentials. "Sealed only in the server" is checked here, not just stated (blueprint §7.3; director note (2) on T-0004) |
| `cmd/edge` | `internal/modules`, `internal/connector`, directory services, `platform/store`, `platform/keys`, the directory protocol libraries | user-access plane, "assumed compromised" (ADR-0002 rule 2) |
| `cmd/agent` | `internal/modules`, `internal/connector`, directory services, `platform/apihost`, `platform/store`, `platform/keys`, `internal/webui` | it runs on a DC (Tier 0): no server code, no credential code |
| `cmd/t0-connector` [post-v1] | `internal/modules`, directory services, `platform/apihost`, `internal/webui`, `platform/store` | control plane, alone on its host |

- **The class names mean what rule 1 says.** "Directory services" includes the directory root `internal/directory`. The kernel root `internal/platform` links `store` and `keys`, so the `store` and `keys` entries already keep it out of every satellite. `migrations` and `webui` can reach a binary only through `compose/server` (rule 1).
- **New binaries add their rows.** `cmd/radius` and `cmd/fpolicy` add rows in the tickets that build them, and a `cmd/<role>` with no row fails.
- **The protocol libraries are named in one place.** They are the stack manifest's list (`tools/fitness/stack/manifest.json`), which ADR-0002 P3 also uses.
- **Satellite-linked kernel packages import no `store`.** These are `agent`, `fleet/dial`, `update`, `telemetry`, `secret`, `proc` and `capability`. The `cmd/agent` and `cmd/connector` rows enforce this with no separate rule. The server-only steps are injected by `compose/server`.

### Rule 8: The first two features on each tier ship as modules

The extension point for a tier is merged before that tier's first feature. The first two features ship through it:
- **server:** `connections` and `objects`, through EP-1;
- **agent:** `addc` and `fileserver`, through EP-13;
- **web:** the `objects` and `helpdesk` screens, through EP-15.

If the contract cannot carry them, the contract is wrong, and it is fixed while that is cheap.

Rules 1–5 make this structural: there is nowhere else for those features to go. The sequencing half, "the contract exists first", is carried by ticket dependencies. The build tickets for these six depend on their extension-point ticket, and the reviewer of the first module's ticket checks that the module needed no kernel change other than adding a Registrar method.

### Rule 9: The contract is validated on paper before it is frozen

UEM ADR-0002 rule 5 warns against fitting a contract to two instances of one shape. `connections` and `objects` are both "CRUD plus Actions". Before `platform/module` is marked frozen (a `// Frozen:` doc line plus a blueprint note), its shape is checked against the modules that do not look like them. The table below is that check for the server tier. It is recorded here, so the freeze gate is this ADR's own text, and it was done at drafting:

| Module (blueprint §5.4) | Shape | Carried by | Finding |
| --- | --- | --- | --- |
| `connections` | onboarding, enrollment, bindings | `API`, `Action`, `Permission`, `AuditKind` | **F1.** Every table `connections` manages is read by a lower layer, so `connections` **owns no table**. It writes them all inside its Actions, through the owners' Go APIs reached via `directory.Services`. The owners: DM-10 Connection, DM-13 ConnectorBinding and DM-21 HybridLink go to a **new directory service, `directory/connection`**, the connection registry. `client` reads it to resolve binding → transport, `sync` reads the attribute set and suspension, and `inventory` reads the deletion settings, takeover attestation (DM-20.I4(f)) and confirmed links (DM-20.I4). DM-11 DirectoryCredential goes to `connector/credential`, with SQL only in `credential/sealed`, written through the credential port (rule 6). DM-14 NamingContext stays with `inventory` and DM-19 SyncCursor with `sync`. A separate registry package keeps tenant configuration out of the transport client, and lets `inventory` read it without depending on `client`. The import order is `sync` → `inventory` → `connection`, and `client` → `connection`. |
| `objects`, `helpdesk`, `m365`, `hardening` | Actions per class × verb | `Action` (+ `API`, `Permission`, `AuditKind`) | Fits. Class definitions are data inside `objects`. |
| `reports` | pure consumer: others' datasets, schedules, delivery | `Job` (schedules), `API`; consumes `report` and `notify` via `Deps`; act-on-results calls Actions by ID | Fits with **no writes of its own**. The dataset registry is a kernel read API, not a module import. |
| `workflow` | long-running requests, SLAs, approvals | `ApprovalGate`, `Job` (SLA timers) | Fits. A module *implementing* a kernel extension point the kernel consumes is the inversion the Registrar exists for. |
| `delegation` | owns the directory scope evaluator | `ScopeEvaluator`, `Action` | **F2.** Role and assignment tables are owned by `platform/authz` (blueprint §5.1). `delegation` changes them through `authz`'s Go API inside its Actions, and evaluates directory scopes. |
| `lifecycle` | scheduled and triggered composition of others' Actions | `Job` (schedules), Actions by ID | **F3.** Attribute-change-triggered automation needs a change feed. Until an EP ticket adds a Registrar method for it, it is a job that reads the inventory change history (EP-8) by watermark. It never subscribes by importing `sync`. |
| `history` | reads inventory history and our audit; undo | datasets (EP-8), `operation.Undo` via `Deps` | Fits through datasets. No cross-owner view. |
| `search` | reads the Action catalogue and inventory | `API`; `operation.Catalogue()` and the inventory read API via `Deps` | **F4.** `operation` must expose a read-only catalogue of registered Actions. That is a kernel service, never a module import. The search index technique stays open (blueprint §16). |
| `migration`, `itsm` | importers and adapters, one shape each | `Job`, Actions by ID | Fits. Variants are parameters (blueprint §4). `migration` takes its MIG-18 baseline by calling `history`'s snapshot Action by ID, never by reading DM-22. |
| `helpdesk` × `objects` | generated passwords | Actions by ID | **F5.** DM-52 PasswordGenerationPolicy is owned by `helpdesk`, but `objects` also needs a generated password when it creates a user (ADM-021). `objects` must not read `helpdesk`'s table. Its create flow composes `helpdesk`'s password-set Action by ID, which generates the password inside `helpdesk` and returns no secret to `objects`. The user-lifecycle spec (DM §11 Q4) may choose the step order. It may not choose a cross-module read. |

**Every domain-model owner line, run through rule 6.** This covers [domain model v0](../domain/domain-model.md) (T-0006). Each owner line was tested against three conditions:
- **(a)** it resolves to exactly one owner key under the four roots;
- **(b)** no lower layer reads a module-owned table, and no foreign key points upward;
- **(c)** it has no split owner.

`R` entities (DM-33 Permission, DM-40 Action, DM-70 Dataset) are registries, not tables, so they are out of scope.

| Entities | Owner key (root) | (a) | (b) | (c) | Note |
| --- | --- | --- | --- | --- | --- |
| DM-01 Tenant | `tenant` (platform) | ✓ | ✓ | ✓ | Every tenant table references it, which is a downward reference. |
| DM-02 TenantKey | `keys` (platform) | ✓ | ✓ | ✓ | Sealing callers use `keys`' Go API. |
| DM-03 Node, DM-05 Release | `update` (platform) | ✓ | ✓ | ✓ | `update` is satellite-linked, so its SQL sits in a server-only subpackage under key `update` that `compose/server` wires (rule 6, rule 7). |
| DM-04 HostnameBinding | `apihost` (platform) | ✓ | ✓ | ✓ | |
| DM-06 Lease, DM-43 Job, DM-44 Schedule | `jobs` (platform) | ✓ | ✓ | ✓ | `sync` holds leases through `jobs`' API. DM-44 `owner_ref` is an opaque typed reference. River's tables are owned by `jobs`, the only importer of River (ADR-0002 T5). |
| DM-10 Connection, DM-13 ConnectorBinding, DM-21 HybridLink | `connection` (directory) | ✓ | ✓ | ✓ | **Changed from `modules/connections`** (F1). DM-10 `credential_id` references DM-11, which is a directory → connector reference. That is not upward in the rule 6 sense (neither kernel nor module). |
| DM-11 DirectoryCredential | `credential` (connector) | ✓ | ✓ | ✓ | **The split owner is removed.** The metadata row is no longer owned by `modules/connections`. One table, one owner; SQL only in `credential/sealed`; writes go through the credential port (rule 6). |
| DM-12 Component | `fleet` (platform) | ✓ | ✓ | ✓ | Enrollment SQL is server-side only (blueprint §2 rule 7). `fleet/dial` has none. |
| DM-14 NamingContext, DM-15 DomainController, DM-16 DirectoryObject, DM-17 Link, DM-18 ChangeRecord, DM-20 Correlation, DM-23 GpLink | `inventory` (directory) | ✓ | ✓ | ✓ | DM-21 is read through `connection`'s API (F1). |
| DM-19 SyncCursor | `sync` (directory) | ✓ | ✓ | ✓ | Its `lease_fencing_token` comes through `jobs`' API. |
| DM-22 Snapshot | `history` (module) | ✓ | ✓ | ✓ | Only `history`'s own Actions read it. Restoring is an Operation (X9) that runs `history`'s Action. |
| DM-30 Account, DM-31 Session, DM-32 ApiToken, DM-37 AuthenticatorEnrollment | `authn` (platform) | ✓ | ✓ | ✓ | |
| DM-34 Role, DM-36 RoleAssignment | `authz` (platform) | ✓ | ✓ | ✓ | F2. `scope_id` (DM-35) and the automation-policy `subject` (DM-60) are opaque typed references with no foreign key, as rule 6 requires. |
| DM-35 DelegationScope | `delegation` (module) | ✓ | ✓ | ✓ | `authz` never reads it. It calls `delegation`'s registered `ScopeEvaluator`. |
| DM-38 CallerVerification, DM-52 PasswordGenerationPolicy | `helpdesk` (module) | ✓ | ✓ | ✓ | Only `helpdesk`'s Actions read them. For `objects`, see F5. |
| DM-41 Operation, DM-42 OperationItem | `operation` (platform) | ✓ | ✓ | ✓ | |
| DM-50 Template, DM-51 NamingFormat, DM-53 AttributeList | `objects` (module) | ✓ | ✓ | ✓ | `lifecycle` and `migration` use them by passing IDs to `objects`' Actions. |
| DM-60 AutomationPolicy, DM-61 PolicyProgress, DM-62 AutomationRun, DM-63 DataSource | `lifecycle` (module) | ✓ | ✓ | ✓ | DM-63's sealed credentials are unsealed through `keys` by `lifecycle`'s own runner. |
| DM-64 WorkflowDefinition, DM-65 Request, DM-66 ApprovalDecision | `workflow` (module) | ✓ | ✓ | ✓ | `operation` reaches them only through the registered `ApprovalGate`. |
| DM-71 ReportDefinition, DM-72 ReportRun, DM-73 ReportSchedule | `reports` (module) | ✓ | ✓ | ✓ | `report` (kernel) holds the dataset registry and AST types, and no tables of `reports`. |
| DM-80 AuditEvent, DM-81 ChainCheckpoint | `audit` (platform) | ✓ | ✓ | ✓ | |
| DM-82 NotificationChannel, DM-83 NotificationTemplate, DM-84 Delivery | `notify` (platform) | ✓ | ✓ | ✓ | |
| DM-85 ItsmConnection | `itsm` (module) | ✓ | ✓ | ✓ | |

**Result.** After F1 and F5, every entity passes. Four owner lines in the domain model change: DM-10, DM-13 and DM-21 move to `directory/connection`, and DM-11 drops its split-owner clause. T-0145 amends the domain model and adds the `directory/connection` row to blueprint §5.2, which M7 requires before the package can exist.

The agent tier's paper check belongs to T-0040 (U4 contract-freeze gate in ADR-0002). The web tier's belongs to the first web-module ticket.

## Alternatives considered

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **Explicit hand-written wiring in `compose/server`**, checked by review and an arity ceiling | Everything visible in one file. No generator, no `go generate` step. A compile error points at the line. It is what most Go services do, and with ten modules it reads well. | The hand list is the one place in core that grows per module. It is where PatchIQ's `NewRouter` grew to 53 parameters, one "just this once" at a time. A generated list keeps the visibility (it is a committed file) and removes the edit. |
| **Hand-written list plus a CI check that it matches the tree** | The same enforcement as generation, without a generator. | Almost equivalent. The generator wins because the list's only allowed content is mechanical. Writing it by hand invites one extra argument "for this module only". A generator also writes the ownership map (rule 6) from the same walk. |
| **`init()`-based self-registration** (the `database/sql` driver pattern), with blank imports | Idiomatic Go. Adding a module touches no central file except one blank import. | Registration happens at import time into global mutable state. Order is implicit. Tests leak registrations across packages. A module can register at any time, so "closed after boot" cannot be enforced. Rule 5 bans `init()` in modules for exactly this reason. |
| **A DI framework**: [uber-go/fx](https://github.com/uber-go/fx) (runtime, reflection) or [google/wire](https://github.com/google/wire) (compile-time codegen) | Mature dependency graphs. Wire gives generated, type-checked wiring. Fx gives lifecycle hooks for free. | Fx resolves the graph at runtime by reflection, and any package may provide any type. That defeats a statically checked import graph, and lifecycle hooks are what rule 4 deliberately withholds. Wire's injector still lists provider sets centrally (a growing list in core), and it adds a dependency we would need to register. Our need is narrow: one constructor shape and one list. A small generator covers it. |
| **Out-of-process modules** (gRPC plugins, e.g. [hashicorp/go-plugin](https://github.com/hashicorp/go-plugin)) | Crash and memory isolation between modules. Third-party modules. Independent release cadence. | Large up-front cost (process supervision, versioned contracts per module, packaging in the MSI). It adds attack surface on a Tier-0 product. No third-party module requirement exists. The licence would need a register row. **Revisit** when partner-built modules become a requirement. The Registrar's typed contributions are the seam such a host would wrap. |
| **The standard `plugin` package** (`.so` loaded at runtime) | In-process dynamic loading with no IPC. | Not supported on Windows ([pkg.go.dev/plugin](https://pkg.go.dev/plugin)), which is our first profile. It requires an identical toolchain and build tags across parts. It needs cgo `[UNVERIFIED]`, which ADR-0001 F2 forbids. |
| **Schema-per-owner in PostgreSQL**, with per-owner database roles instead of static table-ownership checks | The database itself enforces ownership. A grant cannot be bypassed by a clever string. | ADR-0002 fixes two database roles (owner and runtime, T3). Every tenant table already depends on RLS under the one runtime role. Per-module roles would mean per-module connections or `SET ROLE` inside `WithTenantTx`, which is a second security-relevant session variable beside `app.tenant_id`. **Revisit** if a module ever needs a different trust level for its data, for example if secrets move into their own schema. |
| **Defer: review-only enforcement until the second module exists** | No fitness work before the first feature, and a faster start for M2. | UEM ADR-0002's evidence is this exact path: the interface existed, review existed, and the 53-parameter constructor happened anyway. A first `fitness-modules` already runs on the scaffold (T-0014). The marginal cost of the full set is one ticket. |

## Consequences

**Positive**
- **Adding a server module edits no file outside its own directory, its migration, its OpenAPI file and its architecture page.** The generated list and ownership map update themselves.
- **Planes are enforced by the link graph.** A credential, store or connector package that drifts into `edge` or the DC agent fails CI before review.
- **Table boundaries hold, so a later module split or a DB-level move stays possible.** Examples are schema-per-owner, or extracting `platform` for UEM (ADR-0002, "The boundary with UEM").
- **A newcomer can find where a change goes.** Every module has a page, the catalogue is closed, and the map cannot lag the tree.
- **Checkpoint 2a doubles as the proof that the contract works**, because `connections` and `objects` ship as modules.

**Negative**
- **A generator step in the dev loop.** Forgetting `make gen` fails CI with a "stale" message. That is mild, and the fix is one command.
- **Modules cannot share code with each other.** Shared logic either moves into the kernel, which needs a catalogue row and solution-architect review, or is duplicated. Some duplication is the accepted price. Kernel growth pressure is the risk to watch, because "make it kernel" becomes the new escape hatch. The closed catalogue makes every such move a reviewed decision.
- **No module lifecycle hooks.** Work that "just needs a goroutine" must be modelled as a job. Some things, such as in-memory caches, become jobs plus kernel caches, or wait for a Registrar method.
- **Cross-owner reads cost more.** No convenient join across owners in a module's SQL. It goes through a Go API or a dataset, which is slower to write and sometimes slower to run.
- **The first migration's name changes** to `0001_tenant_tenants.sql`. Top-level package names must be unique across `internal/{platform,directory,connector,modules}`, so a module ID may not reuse a kernel, directory or connector package name.
- **The scaffold migrates.** The `Registrar` interface becomes a concrete struct with `Boot`. This is small (one method today).
- **Static SQL ownership checks have limits.** A table named only in a runtime-assembled string escapes them. That is mitigated because dynamic SQL outside `reportsql` is already banned (safe-primitives P5, FF-SP rules).

**Follow-on work** (filed with this ADR)
- **T-0141** (devops-engineer): implement `fitness-modules` M1–M12 in full in `tools/fitness/modules/`, and extend it beyond the T-0014 version. Also `tools/gen/modules` with its staleness check, and `make gen`.
- **T-0144** (backend-engineer):
  - migrate `internal/platform/module` to the rule 4 contract (concrete `Registrar`, `Boot`, `Entry`, namespacing, closing, `moduletest`);
  - add the empty `platform.Deps` and `directory.Services`;
  - rename the tenancy fixture to `0001_tenant_tenants.sql` and update `tenancy-fitness.md`.
- **T-0145** (solution-architect): update the architecture map so it restates this ADR:
  - blueprint §2 (the rule 1 matrix, agent modules → primitives only, rule 7 rows) and §4.1 (`Boot`, no lifecycle);
  - §16 and §17 rows;
  - findings F1–F5 into §5, including the new §5.2 row for `directory/connection` (the connection registry and credential port), which M7 requires before the package can exist;
  - §7.3: the credential port, and the fact that `connector/credential` owns DM-11;
  - **the domain model's owner lines** (widened by the director's T-0045 review): DM-10, DM-13 and DM-21 → `directory/connection`; DM-11 → `connector/credential` alone, dropping the metadata-row clause;
  - create `architecture/modules/README.md`.
- **Decisions this leaves open:**
  - the agent module contract (T-0040);
  - the `API` registration shape (T-0046);
  - gates and the Action catalogue API (T-0047);
  - the credential port's method set (the `connections` build ticket, with security-architect review; custody: T-0007);
  - the change-feed Registrar method (F3), added by the first ticket that needs triggered automation.

**Revisit when**
- third-party or partner-built modules become a requirement (out-of-process host);
- a module's data needs a different trust level from the runtime role (schema-per-owner);
- the kernel catalogue grows by more than about five packages in a milestone without new extension points, which is a sign that features are being filed as core;
- UEM's core contract is ready for convergence (D-0003), when the Registrar may become a skenzeriq-wide type.

## Fitness function

**Job:** `fitness-modules`. It lives in `tools/fitness/modules/`, runs as `go run ./tools/fitness/modules` in `make fitness` (and so in `make ci`), and is owned by devops-engineer (T-0141).

Every check has a failing fixture in `check_test.go`, so a check that silently matches nothing is itself a failure. Checks M1–M7 and M10–M12 need no database and run everywhere. M8b and M9b need a PostgreSQL container or the Go toolchain's `go list`, in the way `fitness-tenancy` does. M8b is skipped, and reported as skipped, only where `fitness-tenancy` would be.

| Check | Fails when | Bypass it closes |
| --- | --- | --- |
| **M1** Import graph | A Go package matches no rule 1 class. Any import between our packages outside the rule 1 matrix, test files included. Anything outside its own zone imports `garage/`, `lab/` or `tools/`, or imports `third_party/` other than as the stack manifest allows. A package other than a server module or `compose/server` imports `internal/platform` or `internal/directory` (the aggregating roots). | A feature reaching sideways or upward (PatchIQ: 94 handlers importing the store). |
| **M2** Module islands | A server or agent module imports another module, or the other module kind, `compose` or `cmd`. | Modules coupling directly instead of by ID. |
| **M3** Generated lists | A module package is imported anywhere except the generated file of `compose/server` or `compose/agent`. A `.gen.go`/`.gen.ts` lacks the generated header. Regenerating any of the three lists or `store/owners/owners.gen.go` gives different bytes. A module ID breaks the pattern. Two top-level packages under `internal/{platform,directory,connector,modules}` share a name. A web module has no server module. A module has no architecture page, or a page has no module. | Hand-wired module lists, and the map lagging the tree. |
| **M4** Registrar only | Any package under `internal/modules/**` or `internal/agentmodules/**` has a `func init()`. A server **module root package** (`internal/modules/<id>`) exports a function named `New` whose signature is not exactly `func New(platform.Deps, directory.Services) module.Module`, or exports none, or exports any other function returning `module.Module`. No **subpackage** under `internal/modules/<id>/` exports a function returning `module.Module`; subpackages may otherwise export what they like, since only their own module can import them (rule 2). The agent equivalents use T-0040's signature. Non-test code under `internal/modules/**` contains a `go` statement or references `time.AfterFunc`, `time.NewTicker`, `time.NewTimer` or `time.Tick`. Module code references `net.Listen`, `http.ListenAndServe`, `http.Handle`, `http.HandleFunc` or `http.DefaultServeMux`. A function in the configured extension-point-type list (`module.Module` included) is called from outside `internal/platform/**` and `internal/compose/**`, except `moduletest.Register` called from a `_test.go` file. A type declared in `internal/compose/**` implements an extension-point interface. `compose/**` references `http.ServeMux`, `http.Handle` or `http.HandleFunc`. `module.Boot` is called outside `compose/server`. `module.Registrar` gains exported fields or an exported constructor. | Self-registration, direct host registration, features hidden in compose. |
| **M5** No growing constructor | An exported function or method in `internal/**` (non-generated, non-test) has more than 8 parameters. A field of `platform.Deps` or `directory.Services` is typed by an interface declared in the aggregating package itself, or by a package that is not in the catalogue. | `NewRouter`-style growth. The boxed form (a struct of modules) is closed by M3, because no package can name a module type. |
| **M6** Composition root | A package outside `cmd/`, `internal/compose/**` or `tools/` imports `internal/compose/**`. Role packages import each other. `profile` imports anything but `platform/capability`. `cmd/<role>` imports anything but its own `compose/<role>`, `compose/config` and the standard library. | Wiring leaking out of the root; the profile becoming code. |
| **M7** Closed catalogue | A top-level package directory under `internal/platform/`, `internal/directory/` or `internal/connector/` has no row in blueprint §5.1, §5.2 or §5.3 (matched by the backticked package name in the table's first column). | Filing a feature as "core". |
| **M8a** Table ownership, static | A migration filename's owner key resolves to zero or more than one top-level package under the four owner roots. A sqlc query file, a SQL string constant or generated `sqlcdb` code under owner *K* names a table that `owners.gen.go` assigns to another owner, or SQL appears in a package that owns nothing (rule 6), by token scan of `FROM`/`JOIN`/`INTO`/`UPDATE`/`TABLE`/`ON` positions. This reuses the scanner of ADR-0002 T5's `global-table-sql`. | Cross-owner SQL. |
| **M8b** Table ownership, catalog | With migrations applied one by one into PostgreSQL, a `ddl_command_end` event trigger records each migration's objects through [`pg_event_trigger_ddl_commands()`](https://www.postgresql.org/docs/16/functions-event-triggers.html). A migration then alters, indexes, adds a policy to or grants on another owner's object, creates a partition of it, or creates a view over it. A foreign key points upward: from a kernel-owned table to a non-kernel table, or from a non-module table to a module-owned one (read from `pg_constraint`). Each query file is planned with [`EXPLAIN (GENERIC_PLAN, FORMAT JSON)`](https://www.postgresql.org/docs/16/sql-explain.html) (PG16+, our floor), and its plan touches another owner's relation, including through views. `owners.gen.go` disagrees with the recorded ownership. | What a token scan misses: views, quoting, schema-qualified names. |
| **M9** Binary hygiene | (a) The conservative import walk (build constraints ignored, so a superset) finds a rule 7 forbidden package in a binary's graph. (b) `go list -deps` for `GOOS=windows` and `GOOS=linux` finds a forbidden package or protocol library. A `cmd/<role>` has no row. | Credential, store or connector code linked into the edge or DC agent through a transitive import. |
| **M10** Web mirror | `web/src/app` or `web/src/ds` imports `web/src/modules/*`, other than `app` importing `modules.gen.ts`. A web module imports another web module. A web module imports something outside `web/src/app`, `web/src/ds`, `web/src/api` or its own directory and registered packages. | Shell code naming screens. |
| **M11** Exemptions | An entry in `tools/fitness/modules/exempt.json` has no reason, no ticket, an expired date, or names a subject that no longer violates anything. An entry targets M1, M2, M3, M6 or M9, which admit no exemptions. | Exemptions becoming permanent. |
| **M12** Self-test | A check has no failing fixture, or the job finds zero packages or zero migrations where the tree has some. | A fitness function that silently checks nothing. This is the `fitness-stack` precedent. |

**Overlaps, deliberately kept.**
- M1's kernel row asserts the same thing as ADR-0002 U2 (`fitness-profiles`). Both may fail on the same import; that is harmless.
- M9's protocol-library rows complement P3, which checks the same libraries at package level rather than binary level.

**Not automatable, and who checks it.** The sequencing half of rule 8 ("the extension point merged before the first feature") is a ticket-dependency fact, not a code fact. The project-manager keeps the dependency edges. The code-reviewer of the first `connections` and `objects` build tickets confirms that the only kernel change in each was a Registrar method. The second gap is a goroutine or timer started *inside a library function* that a server module calls (rule 4). M4 sees only `go` statements and timer constructors in module code. The code-reviewer checks every new third-party call in module code for this, and the module's architecture page lists any library that starts background work. Everything else in this ADR is checked by M1–M12.

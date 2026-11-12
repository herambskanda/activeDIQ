---
title: "ADR-0013: compose/server wires modules only through the Registrar; builders move into modules, and rule 2.5 admits no exemption"
date: 2026-11-12
updated: 2026-11-12
status: ratified
ratified_on: 2026-11-12
ratified_by: factory-director
kind: technical
ticket: T-1863
fitness: fitness-modules (M3, M11, M14)
---

# ADR-0013: compose/server wires modules only through the Registrar; builders move into modules, and rule 2.5 admits no exemption

**Status:** ratified 2026-11-12 on the T-1863 review (notice to the CEO); `accepted` only when M14 and the tightened M11 (below) run green in `make ci` and `go run ./tools/fitness/modules` exits 0 on main.
**Kind:** technical (internal seams, nothing a customer or the brand sees). **Deciders:** solution-architect (author), factory-director (ratifier). **Ticket:** T-1863. Subsumes T-1048, T-1658, T-1133.

## Context

`go run ./tools/fitness/modules` fails on main. After T-1859 fixed 16 of 40 violations, the remaining 24 are all blueprint §2.5: `internal/compose/server` (and `/entra`) names `internal/modules/{connections,directory,reports,reports/*,inventory,delegation,notify,compliance}` outside the generated `modules.gen.go`. The cause is in the T-1859 note and the code:

- `buildDirectory`, `buildReports` and `buildAttestation` build module services by hand and bind their `apihost.TagHandlers`. They sit in `compose/server` because the Registrar has no `API` or `Permission` method yet. The module package doc says these arrive "with the ticket that builds the extension point" (blueprint §4.1), and no such ticket was cut before the first features shipped. This is the PatchIQ pattern the postmortem §5–§6 warns about: a designed interface bypassed by the first feature.
- `catalogue.go` reads permission constants from three modules to build the permission catalogue. EP-6 says that catalogue is what modules register.
- `compose/server/entra` is the Entra adapter set of the `connections` module (it imports only `connections`), filed in the composition root.
- About twelve compose tests construct modules directly.

ADR-0003 already decides the target: modules contribute only through the Registrar (rule 4, EP-1/2/6), only the generated list names a module (rule 3, M3), and **M3 admits no exemptions** (M11 refuses entries for M1, M2, M3, M6, M9). Blueprint §4.1 already lists `Registrar.API` and `Registrar.Permission`. Option (b) from the ticket, an exemption list, would therefore need an ADR that supersedes part of ADR-0003 and weakens the one check that exists to stop this drift.

## Decision

We will take option (a). Module services are built inside the module, contributed through the Registrar, and `compose/server` names no module outside `modules.gen.go`.

1. **Registrar gains `API(apihost.TagHandlers)` (EP-2) and `Permission(authz.Permission)` (EP-6)**, exactly as blueprint §4.1 specifies. `Boot` validates: the tag equals the module ID and is unique; the permission ID is `<moduleID>.`-namespaced (as for Actions), unique, and every `x-permission` in the mounted contract is in the catalogue. `Contributions` exposes the tags and permissions. `compose/server` mounts `Contributions.API` on the host and builds the permission catalogue from `Contributions.Permissions` plus the kernel's own, in place of the `moduleOperationPermissions` constants list. A module that is unconfigured (e.g. attestation without `AttestClientID`) registers nothing for that route; it does not hand compose a nil.
2. **A module builds its own services in `Register`**, from kernel ports. The ports it needs (DB, jobs registry, audit sink, authorizer, read-scope producer, step-up, egress client, blob directory, the attestation config) are fields of `platform.Deps` or `directory.Services`, typed by kernel or directory packages only, never by an interface declared for one module (M5). Where a value is only known after construction (the read-scope producer is `rbac.ReadScopes` behind a transaction), the kernel type carries it. Nothing here adds a field per module.
3. **Move, don't wrap:**
   - `buildDirectory` and the search wiring move into `modules/directory`. Universal search is the `internal/directory/search` package after T-1859, so no module-to-module import is involved.
   - `buildReports`, `reportLibrary`, the retention starter and the freshness adapter move into `modules/reports`; report retention runs as a registered `Job` (EP-5), as rule 4 requires.
   - `buildAttestation` and `compose/server/entra` move into `modules/connections` (the adapters to `modules/connections/entra`, a subpackage only its module imports).
   - `catalogue.go` and `readscopes.go` keep only kernel-typed code. Anything that names a module type goes to that module.
4. **Tests.** A `compose/server` test (any `_test.go`) names no module package either. A test of one module's behaviour lives in that module's package, using the module's own test kit. A cross-module boot or catalogue test asserts on `module.Boot` over `generatedModules(…)` and reads `Contributions` (permissions, Actions, tags); it needs no module import. A module test that needs PostgreSQL uses `storetest`, as the kernel suites do. Test harness duplicated by T-1859 (`inv_harness_test.go`) becomes an exported test kit in `directory/inventory/invtest`.
5. **No exemption list for §2.5.** M11 states it explicitly: an `exempt.json` entry that targets rule 2.5 (or M3) fails. A narrower escape needs a superseding ADR, not an entry.
6. **Sequencing is not optional.** The Registrar methods merge first; each builder moves in its own change that deletes the compose copy in the same change (CLAUDE rule 6). The check is never weakened to let an intermediate state pass: T-1859 reaches exit 0 only when the last move lands.

## Alternatives considered

| Alternative | What it would buy us | Why not |
| --- | --- | --- |
| (b) Ratified exemption list in the check (prod wiring files plus compose tests) | Exit 0 today at the cost of a few lines of check code and no module changes. Its best form is a short, dated allowlist in `exempt.json` with M11 expiry. | It needs a superseding amendment to ADR-0003, which says M3 admits none. It keeps the hand-wired services, so the next module copies them and the list grows; that is how PatchIQ's central wiring reached 53 parameters. The Registrar methods would still be built later, so the exemption is only a delay. |
| (b′) Carve out only `compose/server/*_test.go` | Tests are never shipped; rewriting twelve of them costs real time. | Tests are where cross-module reach starts: a test that builds the module graph by hand teaches the next prod file to. Moving them is mostly mechanical (decision 4) and the Boot-over-generated-list test is the better test. |
| A second generated file (`wiring.gen.go`) that may name modules and builds their services | Exit 0 with no Registrar change. | It is a bigger composition surface with the same hand-built wiring, generated. Rule 3 says the generated file builds `New(deps, dir)` and nothing else, so it would also need a new rule. It moves the bypass, not removes it. |
| Re-export module constructors through a kernel package | Compose would import the kernel package, not the module. | A laundering import. M1/M3 would pass and the design would be violated. |

## Consequences

- **Negative:** `platform.Deps` gains ports (watch M5's rule that a field is typed by a catalogued kernel package). The module move is real work across four modules and about twelve tests. Boot order matters: `Contributions` must exist before the API host and permission catalogue are built, so `server.go` is reordered.
- **Positive:** `compose/server` shrinks to kernel wiring; a new module's routes and permissions need only its `Register`; the permission catalogue cannot drift from the code that checks permissions; the Entra adapters sit with the module that owns them.
- **Blueprint:** §4.1 notes that `API` and `Permission` are now built (this ADR) and §5.4 `connections`/`reports`/`directory` rows list EP-2/EP-6. Revisit when a module needs a contribution the Registrar cannot express (add a method, never a side channel).

## Fitness function

`fitness-modules` (`tools/fitness/modules`, in `make ci`). No new job.

- **M3 (existing, rule 2.5):** unchanged. Any non-generated file under `compose/server` or `compose/agent`, tests included, that names a module package fails. It must exit 0 on main; that is acceptance for T-1859.
- **M11 (tightened):** an `exempt.json` entry targeting rule 2.5 or M3 fails, with a fixture in `check_test.go`.
- **M14 (new): Registrar contributions.** A module that mounts a handler or permission by any route other than `Registrar.API`/`Permission` fails: a `Boot` test over `generatedModules` asserts every tag in the merged OpenAPI document has exactly one registering module, and every `x-permission` is in `Contributions.Permissions`. `compose/server` code references neither `apihost.TagHandlers` construction of a module's `Bind()` nor a module's permission constant (both are module names, so M3 already catches the imports; the Boot test catches a hand-mounted tag built from kernel types). Failing fixture: a module that registers a permission outside its namespace, a duplicate tag, and an `x-permission` missing from the catalogue.

The ADR becomes `accepted` when M3 exits 0 on main, the M11 fixture and M14 test run in `make ci`, and no `exempt.json` entry targets rule 2.5.

## Follow-ups (tickets)

See the T-1863 advance note for ids: Registrar `API`/`Permission` with Boot validation; the four builder moves; compose test relocation; M11/M14 fitness work; blueprint §4.1 amendment (done with this ADR).

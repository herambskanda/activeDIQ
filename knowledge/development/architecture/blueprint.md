---
title: "Architecture blueprint v0"
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
ticket: T-0004
binding_sources: ADR-0001 (ratified), ADR-0002 (ratified), ADR-0003 (ratified), safe-primitives.md (review)
---

# activeDIQ architecture blueprint v0

This is the map every engineer works from. It shows where a change belongs, which rules it must obey,
and who owns each part. Read it once end to end (an afternoon). After that, use §5 (component
catalogue) and §15 (feature → component) as lookup tables.

**What is binding.** The blueprint restates three ratified ADRs and cites them:
- [ADR-0001](../decisions/0001-technology-stack.md): stack and language zones;
- [ADR-0002](../decisions/0002-deployment-model.md): profiles, roles, tenancy and the connector contract;
- [ADR-0003](../decisions/0003-module-system-extension-points-only-on-ramp.md): the module system,
  import graph, table ownership and binary hygiene (§1 migrations row, §2, §4.1, §5, §7.3, §7.5).

It also applies the [safe-primitives spec](safe-primitives.md). Those documents delegated several
**paths** to this blueprint, and it **fixes** them in §1.1. Everything else here is design direction.
Where a direction needs its own ADR, the queued ticket is named: API contract **T-0046**,
operation pipeline and audit trail **T-0047**. If this blueprint and a ratified
ADR disagree, the ADR wins and this file is the bug.

**Notation.** `[OPEN → T-xxxx]` means the item is decided in that ticket. `[M3]` means the item
arrives in that milestone; it is drawn here so that v1 code does not block it. Owner names are
factory agents (`.claude/agents/`).

---

## 0. The system on one page

```
  Admins / help desk (browser)     Integrations (ServiceNow, SDP, scripts)    End users [M4]
            | HTTPS                          | HTTPS + API token                  | HTTPS
            v                                v                                    v
+--------------------------- server process  (cmd/server) ---------------------+  +-- edge [M4] --+
|  apihost: HTTP, authn, strict JSON, problem types, embedded web UI           |<-| stateless,    |
|      ^ generated handlers (api/openapi/)                                     |  | no secrets,   |
|  +-------------- feature modules  internal/modules/<id>/ ------------------+ |  | alone in its  |
|  | connections  objects  helpdesk  delegation  lifecycle  workflow         | |  | process       |
|  | reports  history  search  m365  itsm  migration  hardening              | |  +---------------+
|  +------ register ONLY through the Registrar (EP-1); never import each other| |  (server tunnels
|         |                                     |                             |   out to edge)
|  +------v------- directory domain ---------+  +------v------ platform kernel (extractable) ------+
|  | ldapfilter dn attr model inventory conn.|  | tenant store(+reportsql) authn authz audit jobs  |
|  | sync  client --(connector contract)--+  |  | operation notify report keys secret blob proc    |
|  +--------------------------------------|--+  | pslit fleet(gateway) update telemetry module     |
|   embedded transport (compose/server)   |     +---------------------------------------------------+
|  +--------------------------------------v-- connector role  internal/connector/ ----------------+
|  | contract service | providers: ad (ldap, kerberos, scope, psx) | entra (graph) | custody      |
|  +-----+---------------------------------------------+------------------------------------------+
+--------|---------------------------------------------|--------------^-------------^-------------+
         | LDAPS / Kerberos + CBT (signed, sealed)     | HTTPS Graph  | gRPC mTLS    | SQL (pgx)
         v                                             v              | (dial-in)    v
  +------------------+                     +-----------------+        |      +-------------------+
  | Domain           |<-- LDAPS -----------| Microsoft Entra |        |      | PostgreSQL 16/18  |
  | controllers      |   remote connector  | ID / Graph      |        |      | (only stateful    |
  | (never host the  |   (cmd/connector,   +-----------------+        |      |  service) + blob  |
  |  server)         |    other site/forest)----- dials out ----------+      |  store (fs / S3)  |
  |  LSASS: passfilt |                                                |      +-------------------+
  |   --pipe--> agent [M3] (cmd/agent: skenzeriq host + addc module)  -+
  +------------------+   file servers: agent + fileserver module [M3] -+
                         GPMC host [M3]: OPEN, §13 -------------------+
```

Three things in this picture are the architecture:
- **The public API is the product boundary.** Everything a human or a script does is an OpenAPI
  operation. The web console is one client of that API and has no private endpoints.
- **The connector is the only path to a directory.** Directory credentials exist only inside it,
  and it reaches a directory only through typed operations (ADR-0002 rule 3).
- **Modules plug into the kernel, never the reverse.** `platform` imports nothing above it, so it
  can later be extracted and shared with UEM (D-0003).

---

## 1. Repository map

One Go module sits at the repository root; its module path is `github.com/skenzeriq/activediq` (set by T-0014, which also built the skeleton of this map; see [ci-gates](../standards/ci-gates.md)). Go's `internal/`
rule allows any package in the module to import `internal/…`, and nothing outside it can
([Go 1.4 internal packages](https://go.dev/doc/go1.4#internalpackages)). The layering in §2 is
therefore ours to enforce. The compiler does not do it for us.

| Path | What lives there | Tier (ADR-0001) | Owner |
| --- | --- | --- | --- |
| `cmd/<role>/` | One `main` package per process kind: `server`, `connector`, `edge`, `radius`, `fpolicy`, `t0-connector`, `agent`. Each one is about 20 lines: load config, call **its own** role package `internal/compose/<role>`, run | S, A | backend-engineer |
| `internal/compose/` | **The composition root** (with `cmd/`). Nothing else imports any package under it (ADR-0002 P1). It has three kinds of package: <ul><li>`profile`: the manifest types and the three manifests (`windows`, `linux-oci`, `saas`) as **data only**. It imports no implementation package (§3.2).</li><li>`config`: the config loader, the only reader of environment variables.</li><li>one **role package** per binary: `server`, `connector`, `edge`, `agent`; later `radius`, `fpolicy`, `t0connector`. Each wires its own role's adapters and imports only what its binary may link (§2 rule 7). `server` and `agent` hold the **generated** module list for their tier. Role packages never import each other.</li></ul> | S, A | backend-engineer (shape: solution-architect) |
| `internal/platform/` | **The extractable platform root** (ADR-0002, "The boundary with UEM"). It is the kernel, and it imports no directory-domain or module package. The root package declares `platform.Deps` (§4.1) | S, A | backend-engineer (per package, §5) |
| `internal/directory/` | **The directory domain.** It holds the safe primitives P1–P3, the object model, the inventory (sync store), the sync ingester, the connection registry and the connector-contract client. The root package declares `directory.Services` (§4.1) | S, A | directory-engineer |
| `internal/connector/` | **The connector root.** It is the only place that imports directory protocol and Graph libraries, and the only place that unseals directory credentials (ADR-0002 rule 3) | S | directory-engineer |
| `internal/modules/<id>/` | Server feature modules, one directory each (§5.4), each with a page `architecture/modules/<id>.md` ([template](modules/README.md)) | S | per module |
| `internal/agentmodules/<id>/` | Agent modules `addc` and `fileserver` [M3]. `mgmthelper` exists only if the M3 GPO spec chooses it (§13) | A | windows-engineer |
| `internal/proto/` | Generated Go code for `proto/`. Never hand-edited | S, A | api-engineer |
| `internal/webui/` | `go:embed` package for the built web assets. Embed patterns cannot use `..` ([embed](https://pkg.go.dev/embed)), so the build copies `web/dist` here. Only `compose/server` imports it | S | frontend-engineer |
| `proto/` | Protobuf sources: `skenzeriq/agent/v1` (shared host contract, T-0040), `activediq/connector/v1`, `activediq/<agent-module>/v1` | — | api-engineer; contracts: solution-architect |
| `api/openapi/` | The public API contract. It is the source of truth, with one file per module tag, bundled at build time [OPEN → T-0046] | — | api-engineer |
| `migrations/` | One forward-only SQL sequence, `NNNN_<owner>_<what>.sql`, plus `embed.go`. `<owner>` is an **owner key**: the directory name of exactly one top-level package under `internal/platform`, `internal/directory`, `internal/connector` or `internal/modules` (ADR-0003 rule 6, §2 rule 6). The first migration is **`0001_tenant_tenants.sql`**: it creates `tenants` (ADR-0002 rule 4), owned by `internal/platform/tenant` | S | backend-engineer |
| `web/` | The React + TypeScript console: `src/app` (shell), `src/modules/<id>` (screens), `src/ds` (design system, T-0043), `src/api` (generated client), `e2e/` (Playwright) | W | frontend-engineer; `src/ds`: component-designer |
| `native/` | A Rust workspace: `passfilt` (LSASS), `credprov` (LogonUI) and `shared` (`Secret`, policy evaluator, corpus runner) [M4] | N | windows-engineer |
| `sidecars/<name>/` | .NET 10 + PowerShell 7.6 typed adapters. The names reserved are `pshost` (shared host), `exchange` and `gpmc`. Each is declared in the stack manifest when it is first built | X | windows-engineer (host); backend-engineer (`psx` client) |
| `packaging/` | `windows/` (MSI, toolchain per T-0039) and `oci/` (Dockerfiles, Compose). No script custom actions in the MSI | — | devops-engineer |
| `testdata/safe-primitives/` | The primitive corpus, one `<unit>.jsonl` per unit (safe-primitives §8). Read by the Go and Rust implementations | — | directory-engineer (corpus), test-engineer |
| `tools/` | `fitness/<job>/` (CI jobs), `analyzers/` (go/analysis passes `dnstring`, `sqlconst`, `secretjson`), `vettool/`, `gen/` (code generators), `playwright/` (screenshot, record and E2E runner; Node, dev-time only, T-0011) | L | devops-engineer |
| `lab/` | The Samba AD lab, seed data, Windows lab automation (T-0012) | L | devops-engineer, test-engineer |
| `third_party/<name>/` | Copied third-party code, each with its LICENSE file (ADR-0001 rule 5) | — | devops-engineer |
| `garage/<name>/` | Prototypes with an owner and an expiry date. Never imported | — | its owner |

### 1.1 Paths this blueprint fixes

The earlier documents named these paths provisionally. They are now final, and T-0048 updated the
skills and the safe-primitives spec to match.

| Provisional (where) | Final |
| --- | --- |
| Zone roots `web/ native/ sidecars/ lab/ tools/ third_party/` (ADR-0001 rule 1) | **Kept.** ADR-0001 allows TypeScript only under `web/`, so Playwright suites move to `web/e2e/`. The `windows/` root in the engineering-standards skill becomes `native/` (tier N) plus `internal/agentmodules/` (tier A) |
| `tools/fitness/stack/` + `manifest.json` (ADR-0001) | **Kept.** Likewise `tools/fitness/tenancy/` and `tools/fitness/profiles/` (ADR-0002). Added: `tools/fitness/modules/` (ADR-0003, T-0141) |
| Composition root "`cmd/<role>/` + a compose package" (ADR-0002 rule 1) | `cmd/<role>/` + `internal/compose/`, split by role: `internal/compose/<role>/` (one wiring package per binary; `server` and `agent` also hold `modules.gen.go`), `internal/compose/profile/{windows,linuxoci,saas}.go` (manifest data, no implementation imports) and `internal/compose/config/` (the loader) |
| Platform root "`internal/platform/`" (ADR-0002) | **Kept**, with the package list in §5.1 |
| Connector root (ADR-0002 rule 3) | `internal/connector/` |
| Data-access package `store` (ADR-0002; safe-primitives P5) | `internal/platform/store`. Its entry points are **`WithTenantTx`** (the ADR-0002 name; the safe-primitives spec's `WithTenant` is renamed) and `WithPlatform`. Exemption registry: `internal/platform/store/exempt`. Report compiler: `internal/platform/store/reportsql` |
| `ldapfilter`, `dn`, `attr` (safe-primitives P1–P3) | `internal/directory/ldapfilter`, `internal/directory/dn` (incl. `ObjectRef`, `GUIDRef`), and `internal/directory/attr/{guid,sid,filetime,gentime,flags,unicodepwd}` |
| `Secret` (P3 §5.6) | `internal/platform/secret`. The platform needs it for key material and MFA seeds; the corpus unit stays `attr.unicodepwd` |
| `scope` and `SecureConn` (P1 §3.6, P3 §5.6) | `internal/connector/ad/scope` and `internal/connector/ldap`. Both attach controls or touch the LDAP library, so they sit under the connector root |
| `psx` / `pslit` / `proc` (P4) | `psx` client: `internal/connector/psx` (the connector drives sidecars, ADR-0002 rule 3). `pslit`: `internal/platform/pslit`. `proc`: `internal/platform/proc` |
| Corpus root `testdata/safe-primitives/` (P §8) | **Kept** |
| Exemption registry `internal/platform/tenancy/exempt.go` (adr skill) | `internal/platform/store/exempt` |

---

## 2. Layers and import rules: core never imports modules

This section restates [ADR-0003](../decisions/0003-module-system-extension-points-only-on-ramp.md)
(ratified 2026-10-02) and keeps the rule numbers other documents cite ("§2 rule 7"). The ADR
numbers its own rules differently, so each rule below names its ADR rule. If the two disagree, the
ADR wins and this section is the bug. `fitness-modules` M1–M12 enforce the rules (T-0141). Until
it lands, the T-0014 job in `tools/fitness/modules/` enforces a subset, and code review the rest.

```
 cmd/<role> --> compose/<role> (+ compose/config; profile is data)      every cmd/<role>: own role pkg only
                   | server: generated module list, directory services, connector (embedded
                   |         transport, credential/sealed), apihost, store, keys, webui, migrations
                   v
 internal/modules/<id>         internal/agentmodules/<id>        internal/connector/**
  kernel root + kernel,         kernel ¹, directory primitives,   kernel ¹, directory primitives,
  directory root + services     protos; own <id> only             itself, protos
  + primitives; own <id> only          |                                |
          |                            |                                |
          v                            |                                |
 internal/directory (root: Services)   |                                |
  services: inventory sync client connection                            |
  kernel, primitives, services, protos |                                |
          |                            v                                v
          +------> directory primitives: ldapfilter dn model attr/*  (kernel ¹, primitives, protos)
          |                            |
          v                            v
 internal/platform (root: Deps) and kernel packages --> internal/proto/skenzeriq/*
  (imports no layer above it and no activediq proto)
 ¹ narrowed per binary by rule 7
```

### 2.1 The import graph (ADR-0003 rule 1)

Every Go package belongs to exactly one **class**. The matrix is an allowlist: an import between
our own packages that it does not allow fails CI, and **a package that matches no class fails
too** (M1). Standard-library imports are always allowed. Third-party imports are governed by the
stack manifest and `fitness-stack`, not by this matrix.

**Classes.** The first matching line wins.

| Class | Packages |
| --- | --- |
| **kernel root** | `internal/platform` itself. It declares `platform.Deps` (§4.1) and aggregates kernel services |
| **kernel** | every package under `internal/platform/` |
| **directory root** | `internal/directory` itself. It declares `directory.Services` (§4.1), which holds `inventory`, `connection` and `client`. It counts as a **directory service** wherever a rule names that class, so agent modules and the connector can never import it |
| **directory primitives** | `internal/directory/{ldapfilter,dn,model}` and everything under `internal/directory/attr/` |
| **directory services** | every other package under `internal/directory/` (`inventory`, `sync`, `client`, `connection`, …) |
| **connector** | `internal/connector` and everything under it |
| **server module** | `internal/modules/<id>` and everything under it. The doc-only root `internal/modules` imports nothing and is imported by nothing |
| **agent module** | `internal/agentmodules/<id>` and everything under it. The doc-only root `internal/agentmodules` imports nothing and is imported by nothing |
| **role package** | `internal/compose/<role>` (`server`, `connector`, `edge`, `agent`; later `radius`, `fpolicy`, `t0connector`) |
| **`compose/config`**, **`compose/profile`** | the config loader and the manifest data |
| **`webui`** | `internal/webui` (the `go:embed` package for the built console) |
| **`migrations`** | the repository-root `migrations` package (`embed.go`) |
| **proto: skenzeriq** / **proto: activediq** | generated code under `internal/proto/skenzeriq/` and `internal/proto/activediq/` |
| **`cmd/<role>`** | each `main` package |
| **tools: inspect** | `tools/fitness/**` and `tools/gen/**` |
| **tools: other**, **lab** | every other package under `tools/`, and every package under `lab/` |
| **garage** | every package under `garage/` |

**Matrix.** ✓ means allowed; — means it fails.

| Importer ↓ may import → | kernel root | kernel | dir. primitives | dir. root + services | connector | server module | agent module | role pkg | `config` | `profile` | `webui` | `migrations` | proto: skenzeriq | proto: activediq |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| kernel root | — | ✓ | — | — | — | — | — | — | — | — | — | — | ✓ | — |
| kernel | — | ✓ | — | — | — | — | — | — | — | — | — | — | ✓ | — |
| directory primitives | — | ✓ ¹ | ✓ | — | — | — | — | — | — | — | — | — | ✓ | ✓ |
| directory root + services | — | ✓ | ✓ | ✓ | — | — | — | — | — | — | — | — | ✓ | ✓ |
| connector | — | ✓ ¹ | ✓ | — | ✓ | — | — | — | — | — | — | — | ✓ | ✓ |
| server module `<id>` | ✓ | ✓ | ✓ | ✓ | — | own `<id>` only | — | — | — | — | — | — | ✓ | ✓ |
| agent module `<id>` | — | ✓ ¹ | ✓ | — | — | — | own `<id>` only | — | — | — | — | — | ✓ | ✓ |
| role package | `server` only | ✓ ¹ | ✓ | ✓ ¹ | `server`, `connector`, `t0connector` only | `server`'s generated file only | `agent`'s generated file only | — | ✓ | ✓ | `server` only | `server` only | ✓ | ✓ |
| `compose/config` | — | `platform/capability` only | — | — | — | — | — | — | — | ✓ | — | — | — | — |
| `compose/profile` | — | `platform/capability` only | — | — | — | — | — | — | — | — | — | — | — | — |
| `webui`, `migrations` | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| proto: skenzeriq | — | — | — | — | — | — | — | — | — | — | — | — | ✓ | — |
| proto: activediq | — | — | — | — | — | — | — | — | — | — | — | — | ✓ | ✓ |
| `cmd/<role>` | — | — | — | — | — | — | — | own `<role>` only | ✓ | — | — | — | — | — |
| tools: inspect | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| tools: other, lab | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| garage | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

¹ Rule 7 narrows this per binary: an agent module or the connector may import no kernel package
that reaches `store`, and `compose/connector`, `compose/edge` and `compose/agent` link no directory
service.

- **Only server modules and `compose/server` import the aggregating roots** `internal/platform`
  and `internal/directory`.
- **Agent modules sit where the connector sits:** kernel packages and directory primitives, never
  the directory root or a directory service (`inventory`, `sync`, `client` and `connection` reach
  `store`).
- **Nothing outside a zone imports `garage/`, `tools/`, `lab/` or `third_party/`.** Inside a zone,
  packages may import each other (`tools/**` → `tools/**`, `lab/**` → `lab/**`, a garage prototype
  → its own packages). `third_party/<name>/` is imported only as its stack-manifest row allows
  (ADR-0001 rule 5).
- **`webui` and `migrations` are leaves.** They import only the standard library, and only
  `compose/server` imports them.
- **Exceptions, the complete list.** Tests obey their package's row, external `_test` packages
  included; cross-module behaviour is tested in `internal/compose/server`, and kernel test doubles
  live in kernel test kits (`internal/platform/<pkg>/<pkg>test`). `tools: inspect` may import
  anything to inspect it, and `garage` may import anything, because no binary links either (rule 7).
  There is no exemption registry for the graph. A new class, row or column (a later `cmd/radius`
  row, say) is an amendment to ADR-0003.

### 2.2 Rules

1. **`platform` imports only** kernel packages, `internal/proto/skenzeriq/…`, the standard library
   and registered dependencies (ADR-0003 rule 1; ADR-0002 U2). It never imports `directory`,
   `connector`, `modules`, `compose` or `internal/proto/activediq/…`. `fleet` carries product
   contracts through an opaque tunnel (§7.2), so it never needs one. When the kernel needs
   directory-owned data, it declares a **port** that a directory package implements (§7.5).
2. **`directory` imports only** kernel packages, its own packages and protos (ADR-0003 rule 1).
   Primitives never import a directory service. Inside the services the order is
   `sync` → `inventory` → `connection` and `client` → `connection` (ADR-0003 F1, §5.2). It never
   imports `connector`, `modules` or `compose`.
3. **`connector` imports only** kernel packages, directory primitives, its own packages and
   protos (ADR-0003 rule 1). Outside `internal/connector/`, exactly three packages import it:
   - `internal/compose/server`, for the embedded transport and the sealed-credential source;
   - `internal/compose/connector`, for the remote role and local credentials;
   - `internal/compose/t0connector` [post-v1].

   `tools: inspect` may also import it. `compose/server` hands the embedded transport to
   `directory/client`, and the credential port to `directory/connection`, as values (§7.3).
   Credential custody therefore holds by construction.
4. **Modules are islands** (ADR-0003 rule 2). A server module never imports another server module,
   an agent module never imports another agent module, and neither imports the other kind,
   `compose` or `cmd`. They cooperate only through kernel registries, by ID: an Action by
   `ActionID` (§4.2), a report dataset, an audit kind, a notification sink or a job kind. A leaver
   policy composes `objects.user.disable` and `m365.licence.remove` by Action ID.
5. **Only the generated lists name a module** (ADR-0003 rule 3). There are three lists:
   - `internal/compose/server/modules.gen.go` (server modules);
   - `internal/compose/agent/modules.gen.go` (agent modules);
   - `web/src/app/modules.gen.ts` (web modules).

   `tools/gen/modules` writes them from the directory tree, with the header
   `// Code generated by tools/gen/modules; DO NOT EDIT.`, and CI regenerates them and fails on
   any difference. No other file imports a module package. A module ID matches
   `^[a-z][a-z0-9]{1,30}$`, is its directory name, its OpenAPI tag and its web module ID. Every
   web module has a server module, and every server and agent module has a page
   `architecture/modules/<id>.md` ([template](modules/README.md)), and every page a module.
   Nothing takes a module-typed parameter, a struct of modules or a growing constructor
   (postmortem §6: `NewRouter`, 53 parameters; M5 caps exported functions at 8 parameters).
6. **One owner per table** (ADR-0003 rule 6; it generalises ADR-0002 T5).
   - **The owner key** is the `<owner>` segment of `migrations/NNNN_<owner>_<what>.sql`. It is the
     directory name of exactly one top-level package under `internal/platform`,
     `internal/directory`, `internal/connector` or `internal/modules`. Subpackages never own on
     their own (`credential/sealed`, `store/reportsql` and `fleet/dial` belong to their top-level
     key), and top-level names are unique across the four roots (so no module may be called
     `client`). `compose`, `cmd`, the aggregating roots and agent modules own no table and contain
     no SQL that names one.
   - **Satellite-linked owners** (`update`, `fleet`, `credential`) keep their SQL in a server-only
     subpackage under the same key, wired by `compose/server`, so rule 7 keeps it out of
     `cmd/connector` and `cmd/agent`.
   - **A migration owns what it creates and touches only that.** It may `REFERENCES` another
     owner's table, but never upward: kernel-owned tables reference only kernel-owned tables, and
     no non-module table references a module-owned one. An upward link is an opaque typed reference
     with no foreign key, resolved through the owning module's registered extension point (DM-36
     `scope_id`). Partitions belong to the parent's owner, and a view selects only its owner's
     tables.
   - **Query SQL references only the owner's tables.** Other packages read through the owner's Go
     API, a registered report dataset, or a kernel port (§7.5). `store/reportsql` is the one place
     that emits SQL spanning owners, and only from registered datasets.
   - **No lower layer reads a higher layer's table** (ADR-0003 rule 9 (b), as amended by F6). Data
     a lower layer needs is owned below and written by the module through that owner's Go API,
     inside its Actions (§5.6).
   - **The ownership map** `internal/platform/store/owners/owners.gen.go` (table → owner key) is
     generated with the module lists. Cross-owner data migrations need an entry with a reason, a
     ticket and an expiry in `tools/fitness/modules/exempt.json`.
7. **Binary hygiene** (ADR-0003 rule 7). Planes are separated by the link graph, not only by the
   manifest (ADR-0002 rule 2). `go list -deps ./cmd/<role>`, for `GOOS=windows` and `GOOS=linux`,
   must contain none of the packages listed for it:

   | Binary | Must not contain | Why |
   | --- | --- | --- |
   | every `cmd/*` | `tools/**`, `garage/**`, `lab/**` | dev tooling and prototypes never ship |
   | `cmd/server` | `internal/agentmodules` | agent code runs on customer hosts, never in the server |
   | `cmd/connector` | `internal/modules`, directory services, `platform/apihost`, `internal/webui`, `platform/store`, `platform/keys`, `connector/credential/sealed` | a remote connector serves no API, has no database and holds only local credentials. "Sealed only in the server" is checked, not just stated (§7.3) |
   | `cmd/edge` | `internal/modules`, `internal/connector`, directory services, `platform/store`, `platform/keys`, the directory protocol libraries | user-access plane, "assumed compromised" (ADR-0002 rule 2) |
   | `cmd/agent` | `internal/modules`, `internal/connector`, directory services, `platform/apihost`, `platform/store`, `platform/keys`, `internal/webui` | it runs on a DC (Tier 0): no server code, no credential code |
   | `cmd/t0-connector` [post-v1] | `internal/modules`, directory services, `platform/apihost`, `internal/webui`, `platform/store` | control plane, alone on its host |

   "Directory services" includes the directory root. The kernel root links `store` and `keys`, so
   those entries keep it out of every satellite. The protocol libraries are the stack manifest's
   list (`tools/fitness/stack/manifest.json`). `cmd/radius` and `cmd/fpolicy` add their rows in the
   tickets that build them; a `cmd/<role>` with no row fails. For the rows to hold, the kernel
   packages that satellites link (`agent`, `fleet/dial`, `update`, `telemetry`, `secret`, `proc`,
   `capability`) import no `store`. Server-only steps are injected by `compose/server`: migrations
   in `update`, enrollment records in `fleet`.
8. **Web mirrors the server** (ADR-0003 rules 3–4, M10). Each `web/src/modules/<id>/index.ts`
   exports one `WebModule` built with `defineModule({ id, routes, palette, searchResults })` from
   `web/src/app`. `web/src/app` and `web/src/ds` never import `web/src/modules/*`, except that `app`
   imports the generated `modules.gen.ts`. Web modules never import each other, and get data only
   through the generated client `web/src/api` (T-0046).

**The other homes of a feature are closed** (ADR-0003 rule 5), so the Registrar stays the only
on-ramp:
- `cmd/<role>` imports only its own role package, `compose/config` and the standard library.
- `internal/compose/**` declares no type that implements an extension-point interface, never
  touches `http.ServeMux`, `Handle` or `HandleFunc`, and hands the kernel hosts only `module.Boot`'s
  result and what kernel or directory packages export for their own extension points (for example
  `inventory.Datasets()`).
- `internal/platform/**`, `internal/directory/**` and `internal/connector/**` form a **closed
  catalogue**: every top-level package needs a row in §5.1, §5.2 or §5.3 (M7), so a new core
  package is a reviewed blueprint change.
- Kernel hosts expose no back door: a kernel function that takes an extension-point type is
  callable only from `internal/platform/**` and `internal/compose/**`. The one exception is
  `moduletest.Register(m)`, from `_test.go` files.
- Module code has no `func init()`, no listener (`net.Listen`, `http.ListenAndServe`,
  `http.Handle`, `http.HandleFunc`, `http.DefaultServeMux`), and, in server modules, no `go`
  statement and no timer constructor (§4.1).

**sqlc and the driver boundary (a precision for T-0033 and T-0036).** With `sql_package: "pgx/v5"`,
sqlc's generated code imports pgx and uses pgx types directly
([sqlc: using Go and pgx](https://docs.sqlc.dev/en/latest/guides/using-go-and-pgx.html)). So the
"SQL driver only in the data-access package" rule (FF-SP1) means two things.
`pgxpool` and `pgx.Connect`/`ConnConfig` appear only in `internal/platform/store`. Other pgx
packages appear only in `store` and in **generated** `sqlcdb/` packages, where every file carries
sqlc's generated-code header. Hand-written code outside `store` never imports pgx. This is
consistent with ADR-0002 T5, which bans pool and connection types.

---

## 3. Processes, roles and profile composition

### 3.1 Roles and binaries

Each role in ADR-0002 rule 2 has a `cmd/` binary, and each binary has its own role package under
`internal/compose/`. Roles are linked at build time, not chosen at runtime. A role package imports
only what its binary may link, so credential-free roles never carry credential code (§2 rule 7).
Roles that share a process are wired by the role package of the binary that hosts them. For
example, `compose/server` wires the embedded `connector`.

| Role | Binary | Plane (ADR-0002) | May share a process with | Milestone |
| --- | --- | --- | --- | --- |
| `server` | `cmd/server` | management | `connector`, `radius`, `fpolicy` (linked into `cmd/server`) | M2 |
| `connector` | `cmd/connector` when remote; inside `cmd/server` when embedded | management | as above | M2 (both transports, P3) |
| `edge` | `cmd/edge` | user access | **nothing** | M4 |
| `radius` | `cmd/radius`, or linked into `cmd/server` | user access | `server`, `connector`, `fpolicy` | M4 |
| `fpolicy` | `cmd/fpolicy`, or linked into `cmd/server` | management | `server`, `connector`, `radius` | M5 (E5.5 NAS auditing; pulled into M3 only if a pilot needs it, roadmap-skeleton.md) |
| `t0-connector` | `cmd/t0-connector` | control | **nothing**; own host; never in the SaaS cell | after v1 (FD-11) |
| `agent` | `cmd/agent` (skenzeriq host + generated agent-module list) | control on a DC; management elsewhere | **nothing**; on the host it serves | M3 |

### 3.2 The manifest

A manifest is a typed Go value inside `internal/compose/profile/`. Only packages in the
composition root read it (P1). `profile` is **data only**. It imports the standard library and
`platform/capability`, a leaf package of IDs. It never imports an implementation package, so
importing it links no adapter, module or connector code into any binary.

```go
type Manifest struct {
    Processes    []Process        // {Binary: "server", Roles: [Server, Connector{Providers: [AD, Entra]}]}
    Adapters     Adapters         // one enum per kind, declared in profile: KeyProvider, SecretSource, BlobStore,
                                  //   ServiceHost, UpdateCourier, Kerberos (e.g. KeyProvider = DPAPING | TPM2 | KMS | …)
    Capabilities []capability.ID  // named for the capability: "directory.ad", "tenant-provisioning", …
    Exceptions   []Exception      // declared asymmetries, each citing a ratified ADR (P1)
}
```

Each role package maps the adapter enums to implementations, and only for the adapters its binary
uses. A module declares the capabilities it `Requires()`. `compose/server` (and `compose/agent`)
loads a module only when its capabilities are enabled. No other code asks "which profile am I?".

### 3.3 Per-profile composition

```
windows (MSI, v1)                      linux-oci (images, v1)                 saas (CI only, not shipped)
+------------------------------+       +------------------------------+       +---- our cell (per region) -------+
| Windows service: cmd/server  |       | container: cmd/server        |       | N x cmd/server (stateless)       |
|  roles: server + connector   |       |  roles: server + connector   |       |  roles: server + connector       |
|  providers: ad, entra        |       |  providers: ad, entra        |       |  providers: entra ONLY (P1)      |
|  kerberos: sspi (gMSA)       |       |  kerberos: krb5 (AES keytab) |       |  keys: KMS; tenant-provisioning  |
|  keys: DPAPI-NG / TPM        |       |  keys: TPM2|KMS|Vault|pass   |       | managed PostgreSQL   edge (ours) |
|  servicehost: winsvc         |       |  servicehost: oci            |       +-------------^--------------------+
| PostgreSQL 18 (bundled) or   |       | customer PG 16+ or upstream  |                     | mTLS, dial-out
|  customer PG 16+             |       |  PG 18 image (by digest)     |       +---- customer site ---------------+
+------------------------------+       +------------------------------+       | cmd/connector (providers: ad)    |
optional, any host (both self-hosted profiles):                               |  gMSA or keytab; AD creds stay   |
  cmd/connector (other forest, DMZ, branch, redundancy; ADM-210)              | cmd/agent [M3]                   |
  cmd/edge [M4], cmd/agent [M3] on DCs, file servers, member server           +----------------------------------+
```

Self-hosted installs have exactly one tenant, created at install time. They run the same RLS code
path as SaaS (ADR-0002, "Where tenancy lives").

### 3.4 Platform matrix per capability

**Asymmetry follows the host, never the profile.** Where a capability needs Windows, it runs on a
customer Windows host that both profiles can reach. Adapters may differ between profiles;
capabilities may not (ADR-0002 rule 1).

| Capability | `windows` | `linux-oci` | `saas` | Note |
| --- | --- | --- | --- | --- |
| AD read/write, sync | sspi adapter | krb5 adapter | on-site connector | Same contract. T-0023 (CBT) gates the krb5 path |
| Entra / Graph | in-server connector | same | cell connector | Certificate sealed under the tenant data key |
| Windows LAPS **decryption** (ADM-060) | DPAPI-NG native `[UNVERIFIED]` | **spike E1.4(d)** | on-site connector | If the Linux spike fails, decryption runs in a Windows-hosted remote `connector`. It never becomes a profile conditional |
| Console SSO by SPNEGO | acceptor in connector (gMSA) | acceptor in connector (keytab) | on-site connector | Only if the PRD offers it (ADR-0002 rule 3) |
| On-prem Exchange cmdlets (ADM-026, 070) | a Windows-hosted remote `connector` drives `sidecars/exchange` | same | same | Only under FD-04. The connector holds the identity (ADR-0002 rule 3) |
| GPMC reports and backups | a customer Windows host; which component drives `sidecars/gpmc` is `[OPEN → M3 GPO spec]` (§13) | same | same | M3. Custody favours a Windows-hosted remote `connector` |
| DC agent, password filter | DCs | DCs | DCs | M3/M4. A DC is always Windows |
| Credential provider | Windows 11 x64/ARM64 endpoints | same | same | M4 |
| Product DB backup (ADM-158) | bundled PG: scheduled | customer PG: theirs | managed | `[OPEN → E2.12 PRD]` |

---

## 4. Extension points: the only on-ramps

An extension point is built before the first feature on its tier, and the first two features on
each tier ship through it (UEM ADR-0002 rules 1–2). These are the first two:
- **server:** `connections` and `objects`;
- **agent:** `addc` and `fileserver`;
- **web:** the `objects` screens and the `helpdesk` screens.

| # | Extension point | Interface home | Implemented by (v1 first) | Later | Built before |
| --- | --- | --- | --- | --- | --- |
| EP-1 | **Module** (+ Registrar) | `platform/module` | every `internal/modules/*` | — | first server feature |
| EP-2 | **API handlers** for one OpenAPI tag | `platform/apihost` | each module | — | first endpoint (T-0046) |
| EP-3 | **Action** (plan, apply, verify, inverse) | `platform/operation` | `objects`, `helpdesk`, `m365`, `lifecycle`, `delegation`, `hardening` | GPO, file-server ACLs | first write (T-0047) |
| EP-4 | **Approval gate** | `platform/operation` | `platform` default (permission-only), `workflow` | ITSM-driven approval | first write |
| EP-5 | **Job kind** (tenant-carrying) | `platform/jobs` | operation runner, sync, notifications; module schedules and timers (`reports`, `lifecycle`, `workflow`, `itsm`, `migration`) | — | first job |
| EP-6 | **Permission + scope evaluator** | `platform/authz` | every module declares permissions; `delegation` evaluates directory scopes | UEM device scopes | first endpoint |
| EP-7 | **Audit event kind** | `platform/audit` | every Action and auth event | — | first write |
| EP-8 | **Report dataset** | `platform/report` | `directory/inventory` (objects, groups, per-DC values), `platform/audit` | DC events [M3] | first report |
| EP-9 | **Notification sink** | `platform/notify` | email, SMS gateway, SIEM (syslog/CEF/HTTP) | webhooks, Teams/Slack [M3] | first notification |
| EP-10 | **Authentication method** (enroll, verify) | `platform/authn` | password + TOTP, WebAuthn, email/SMS OTP (ENH-09), SAML/OIDC SP | push [M4], RADIUS | first sign-in |
| EP-11 | **Directory provider** (typed ops + capabilities) | `connector/provider` | `ad`, `entra` | generic LDAP, Google | first directory call |
| EP-12 | **Platform adapters** (key provider, secret source, blob, service host, update courier, Kerberos) | `platform/keys`, `platform/blob`, …; `connector/kerberos` | per manifest (§3.3) | HSM | M1 skeleton |
| EP-13 | **Agent module** (`skenzeriq.agent.v1`) | `platform/agent` | `addc`, `fileserver` | `mgmthelper` (only if the M3 GPO spec chooses it, §13), UEM modules | first agent feature (T-0040) |
| EP-14 | **Event source** and **detection rule** | `platform/events` [M3] | `addc`, `fileserver` | WEF, FPolicy | first M3 audit feature |
| EP-15 | **Web screen module** | `web/src/app` | `objects`, `helpdesk` | — | first screen |

Inside a module, variants share one shape and differ only by parameters:
- object classes (user, group, computer, contact, OU) are **data** in `objects`;
- ITSM systems are one adapter shape in `itsm`;
- migration sources are one importer shape in `migration`;
- report definitions are **data** (ASTs), never code.

### 4.1 Module contract (server)

This restates [ADR-0003](../decisions/0003-module-system-extension-points-only-on-ramp.md) rule 4
(EP-1). `internal/platform/module` is built to this shape (T-0144): the concrete `Registrar`,
`Boot`, `moduletest`, an empty `platform.Deps` and an empty `directory.Services`.

```go
// internal/platform/module
type ID string                      // ^[a-z][a-z0-9]{1,30}$: the directory name, OpenAPI tag and web module ID

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

- **Each method arrives with its extension point.** The ticket that builds EP-2 … EP-10 adds the
  matching Registrar method, so the type never names something that does not exist yet.
- **Concrete, not an interface.** Only the kernel's own `Registrar` can attribute each
  contribution to its module, enforce namespacing and refuse calls after boot. A substitutable
  interface would let a wrapper or test double skip all three. Tests get a real one through the
  kit `internal/platform/module/moduletest`: `moduletest.Register(m) (*module.Contributions, error)`
  runs the `Boot` validations for one module and touches no host.
- **What `Boot` validates** (any failure stops start-up):
  - **namespacing:** every contributed ID (Actions, permissions, audit kinds, job kinds, datasets)
    starts with `<moduleID>.`, and an `API` tag equals the module ID;
  - **no duplicates:** a duplicate ID fails; at most one `ScopeEvaluator` per scope kind and one
    non-default `ApprovalGate` (its interplay with Actions: T-0047);
  - **closed after boot:** `Register` runs once, and a Registrar used after `Boot` returns gives
    `ErrClosed`, so a module that stashes `r` gains nothing;
  - **capabilities:** a module whose `Requires()` is unmet is not constructed into the
    contributions; no other code asks which profile is running (ADR-0002 P1);
  - **dataset tables:** a `Dataset` names only tables its module owns, per
    `store/owners/owners.gen.go` (§2 rule 6). The same check runs on datasets that kernel and
    directory packages export (`inventory.Datasets()`), with the exporter's owner key, when
    `compose/server` hands them to `report`. The `compose/server` boot test runs `Boot` over every
    generated module, so CI sees a violation first;
  - **ID match:** a module whose `ID()` differs from the ID the generated list recorded fails.
- **No lifecycle methods.** There is no `Init`, `Start` or `Stop`, and a server module owns no
  goroutines, listeners or timers. Background, periodic and long-running work is a registered
  `Job` kind or schedule on `platform/jobs`, which carries the tenant and the leases. Requests go
  through `API`. M4 fails non-test module code that contains a `go` statement or references
  `time.AfterFunc`, `time.NewTicker`, `time.NewTimer` or `time.Tick`. Request-scoped concurrency
  that joins before it returns uses a kernel helper, added by the first ticket that needs it. A
  library that starts background work is listed on the module's page, because no syntax check can
  see it. If a module needs something this cannot express, the Registrar gains a method through an
  EP ticket, never a side channel. This is stricter than PatchIQ's `Init/Start/Stop` (postmortem §6).

**How dependencies reach a module.** Each server module root package exports exactly one
constructor, and no subpackage exports anything that returns `module.Module` (M4):

```go
func New(deps platform.Deps, dir directory.Services) module.Module
```

- **`platform.Deps`** (package `internal/platform`) is a fixed struct of kernel services:
  operation, audit, authz, jobs, report, notify, keys, blob, telemetry, …
- **`directory.Services`** (package `internal/directory`) is a fixed struct holding `inventory`'s
  read API, the `client`, and the `connection` registry with its credential port (§5.2, §7.3).
- **Both grow per kernel or directory service, never per module.** A field's type must come from a
  catalogue package (§5.1, §5.2); a field typed by an interface declared in the aggregating package
  itself fails M5, because that is how a "service for one module" sneaks in.
- **The generated list is the only caller.** It passes the same two values to every module's
  `New`. No package but the generated list can name a module type, so a struct, slice or map of
  modules cannot be written anywhere.

**Agent and web tiers** follow the same rules with their own shapes. The agent module contract
(EP-13, `skenzeriq.agent.v1`) and its dependency struct are T-0040's; ADR-0003 binds the generated
list, one fixed constructor signature, no lifecycle outside the contract and no module-to-module
imports. Web modules: §2 rule 8.

### 4.2 Action contract: one shape for every write (ENH-04)

```go
// internal/platform/operation
type Action interface {
    ID() ActionID                                   // "objects.user.create"
    Permission() authz.Permission
    Schema() schema.Ref                             // OpenAPI component: shared by API, workflow, automation, palette
    Plan(ctx, in Input) (Plan, error)               // dry run: live reads, diff, reversibility, approvals needed; no writes
    Apply(ctx, p Plan) (Outcome, error)             // via the connector contract; idempotent per (operation, step)
    Verify(ctx, o Outcome) error                    // read-back from the same DC
    Inverse(o Outcome) (Input, Reversibility)       // undo input, or Irreversible{reason} (e.g. passwords)
}
```

The same Action serves a single edit, a 50,000-row CSV, a workflow step, an automation policy,
act-on-report-results and the command palette. **No directory write is reachable except from an
Action's `Apply`** (T-0047 fitness).

---

## 5. Component catalogue

Every component has an owner, an interface and its extension points (EP numbers refer to §4).
The catalogue is **closed** (ADR-0003 rule 5, M7): every top-level package under
`internal/platform/`, `internal/directory/` and `internal/connector/` has a row in §5.1, §5.2 or
§5.3, matched by the backticked name in the first column, and a new one needs a blueprint change
reviewed by solution-architect. When a ticket adds a server or agent module, it also writes
`architecture/modules/<id>.md` from the [module page template](modules/README.md). M3 fails a
module without a page and a page without a module. Table ownership follows §2 rule 6; the findings
that placed each table are in §5.6.

### 5.1 Platform kernel (`internal/platform/`, extractable)

The root package `internal/platform` declares `platform.Deps` (§4.1). Only server modules and
`compose/server` import it.

| Package | Owner | Interface (what others call) | EPs |
| --- | --- | --- | --- |
| `tenant` | backend-engineer | `tenant.ID`, which only authn, the job wrapper, registered platform paths and tests may mint (ADR-0002 rule 5) | — |
| `store` (+`exempt`, `owners`, `sqlcdb` conventions) | backend-engineer | `WithTenantTx(ctx, tenant.ID, fn)`, `WithPlatform(ctx, reason, fn)`, `LikePattern`, per-transaction `statement_timeout`; the raw pool is unexported. `store/owners` is the generated, data-only table → owner-key map (`owners.gen.go`, §2 rule 6) that `module.Boot` and `fitness-modules` read; it imports nothing | — |
| `store/reportsql` | reporting-engineer (security-architect reviews every change, P5 rule 3) | `Compile(ast, dataset, scope) (sql, args)`, the only dynamic SQL | consumes EP-8 |
| `module` | backend-engineer | `Module`, the concrete `Registrar`, `Boot`, `Entry`, `Contributions`, `ErrClosed` (§4.1); test kit `module/moduletest` (`Register(m)`) | hosts EP-1 |
| `capability` | backend-engineer (IDs: solution-architect) | `capability.ID` constants and `Set.Enabled(id)`. It is a leaf package with no behaviour. Manifests list IDs (`compose/profile`), modules return them from `Requires()` (§4.1), and role packages filter modules by them | supports EP-1 |
| `apihost` | api-engineer | HTTP server, auth middleware, strict JSON, problem types, rate limits, static UI mount | hosts EP-2 |
| `authn` | backend-engineer; security-architect reviews | sessions, API tokens (ADM-141), SAML/OIDC SP (library `[OPEN]`, ADR-0001), MFA (ADM-142), mTLS principals. Owns DM-30 Account, DM-31 Session, DM-32 ApiToken, DM-37 AuthenticatorEnrollment. Declares the **read port `authn.DirectoryAnchors`** (`Resolve`, `Matched`; §7.5, ADR-0003 F6), implemented by `directory/inventory`, through which DM-30.I5 binds SSO accounts and checks `matched` correlations. Declares `authn.DirectoryRef`, which `authz` reuses | hosts EP-10 |
| `authz` | backend-engineer; security-architect reviews the membership port | `Authorize(principal, permission, target) Decision`; roles = sets of permissions; assignments = principal × role × scope. **Owns DM-34 Role and DM-36 RoleAssignment** (ADR-0003 F2); `delegation` changes them through `authz`'s Go API inside its Actions. `scope_id` and automation-policy subjects are opaque typed references, resolved through the registered `ScopeEvaluator`. Declares the **read port `authz.Membership`** (`GroupsOf`, `Matched`; §7.5, F6), implemented by `directory/inventory`, for DM-36.I2 group subjects | hosts EP-6 |
| `operation` | backend-engineer | `Plan`, `Submit`, `Approve`, `Undo`, operation state; bulk chunking on `jobs`. **`Catalogue()`**: a read-only view of the registered Actions (ID, permission, schema), which `search` uses for the palette (ADR-0003 F4; its shape: T-0047). Owns DM-41 Operation and DM-42 OperationItem | hosts EP-3, EP-4 |
| `jobs` | backend-engineer | tenant-carrying job wrapper, leases for singleton work, schedules. **The only importer of River** (T5) | hosts EP-5 |
| `audit` | backend-engineer | `Append(kind, event)`: one hash chain per tenant (ADR-0002), export and verify, SIEM stream | hosts EP-7; implements EP-8 |
| `report` | reporting-engineer | dataset registry, report-definition AST types, the run API | hosts EP-8 |
| `notify` | backend-engineer | `Send(template, recipients)`, delivery records, egress-proxy setting (ADM-205) | hosts EP-9 |
| `keys` | backend-engineer; security-architect reviews | KEK from the key-provider adapter, tenant data keys, `Seal`/`Unseal[T]`, key shredding on tenant delete | EP-12 |
| `secret` | directory-engineer (P3) | the `Secret` type: redacted, not serialisable | — |
| `blob` | backend-engineer | `Put`/`Get` with tenant-prefixed keys; adapters `fs`, `s3` (client library `[OPEN]`) | EP-12 |
| `proc`, `pslit` | backend-engineer (P4) | constant-argv process runner; display-only PowerShell rendering | — |
| `fleet` | backend-engineer | the gRPC mTLS gateway for connectors and agents (server side): enrollment (the first registered platform path), certificate SAN → tenant + component, endpoint lists. It is **contract-agnostic**. For each enrolled component it exposes a tunnel over the component-initiated connection, which implements [`grpc.ClientConnInterface`](https://pkg.go.dev/google.golang.org/grpc#ClientConnInterface) for server-initiated calls, and a [`grpc.ServiceRegistrar`](https://pkg.go.dev/google.golang.org/grpc#ServiceRegistrar) for calls the component makes. Product contracts bind to the tunnel from outside the platform root: `directory/client` binds the generated `activediq.connector.v1` client, and the server module that owns an agent module's contract binds `activediq.<module>.v1`. The platform root therefore never imports `internal/proto/activediq/…` (§2 rule 1, ADR-0002 U2) | hosts transport for EP-11 (remote) and EP-13 |
| `fleet/dial` | backend-engineer | the component side, linked by `cmd/connector` and `cmd/agent`: enrollment client, mTLS dial-out, and serving the reverse tunnel. No `store` (§2 rule 7) | — |
| `agent` | windows-engineer | the skenzeriq agent host inside `cmd/agent`: lifecycle, outbox, update, health (T-0040) | hosts EP-13 |
| `update` | backend-engineer; devops-engineer owns the release pipeline | fetch → verify (one verifier) → stage → apply → health check → rollback; couriers `online`/`offline`. The server's migration step is injected by `compose/server`, so `update` imports no `store` and links into `cmd/connector` and `cmd/agent` (§2 rule 7) | EP-12 |
| `telemetry` | backend-engineer | `slog` JSON with tenant ID, metrics; no mandatory egress (P6) | — |
| `export` encoders | reporting-engineer | CSV/XLSX/PDF/HTML encoders with formula neutralisation (spec T-0029) | — |
| `events` [M3] | backend-engineer (pipeline); directory-engineer (sources) | `Source` (decodes a batch from an agent module, and later from WEF or FPolicy, into normalised events), `Rule` (match → alert through `notify`), and writes to partitioned event tables if T-0026 passes ADR-0001 rule 3 | hosts EP-14; implements EP-8 (DC events) |

### 5.2 Directory domain (`internal/directory/`)

The root package `internal/directory` declares `directory.Services` (§4.1): `inventory`'s read
API, the `client`, and the `connection` registry with its credential port. Only server modules and
`compose/server` import it. Inside the services the import order is `sync` → `inventory` →
`connection` and `client` → `connection` (ADR-0003 F1).

| Package | Owner | Interface | EPs |
| --- | --- | --- | --- |
| `ldapfilter`, `dn`, `attr/*` | directory-engineer | the safe primitives P1–P3 (safe-primitives §3–§5) | — |
| `model` | directory-engineer (semantics: ad-expert, T-0006) | `Connection` (AD forest, Entra tenant), `NamingContext`, `Object{GUID, class, parent GUID, DN-for-display}`, `ObjectRef`, link types | — |
| `inventory` | directory-engineer | current state, link graph, GUID ancestry, per-DC values, AD↔Entra correlation, change history (§12). Read API for modules. Owns DM-14 NamingContext, DM-15 DomainController, DM-16 DirectoryObject, DM-17 Link, DM-18 ChangeRecord, DM-20 Correlation, DM-23 GpLink. Reads the connection's deletion settings, takeover attestation and confirmed HybridLinks through `connection`'s API. **Implements the kernel read ports** `authz.Membership` and `authn.DirectoryAnchors` directly (§7.5, F6). Exposes change history by watermark, which is how `lifecycle` sees attribute changes until a change-feed Registrar method exists (F3) | implements EP-8 |
| `sync` | directory-engineer | full sync, then DirSync / Graph delta per naming context or tenant, under a lease (ADR-0002 rule 6); the cookie is stored in our database, so the connector stays stateless. **Owns DM-19 SyncCursor** (the cookie table; its fencing token comes through `jobs`' API). Reads the attribute set and suspension from `connection` | EP-5 job |
| `client` | directory-engineer | `Directory` (the generated connector-contract client); binding → transport resolution, from data rather than configuration, reading DM-13 bindings through `connection`'s API; capability check before Plan. Owns no table | consumes EP-11 |
| `connection` | directory-engineer; security-architect reviews the credential port | **The connection registry** (ADR-0003 F1). **Owns DM-10 Connection, DM-13 ConnectorBinding and DM-21 HybridLink**: tenant configuration that `client`, `sync` and `inventory` read, kept out of the transport client so `inventory` need not depend on `client`. Its Go API is the only writer; the `connections` module calls it inside its Actions, through `directory.Services`. Declares the **credential port** (§7.3), implemented by `connector/credential/sealed` and handed in by `compose/server`. Importers: `client`, `sync`, `inventory`, and modules through `directory.Services` | — |

### 5.3 Connector root (`internal/connector/`)

| Package | Owner | Interface | EPs |
| --- | --- | --- | --- |
| `service` | directory-engineer | implements `activediq.connector.v1` for both transports (§7.1). `service.New(providers, credentialSources)` is one constructor; the two role packages call it with different parameters | — |
| `provider` | directory-engineer (contract: solution-architect) | the `Provider` interface: `Describe() Capabilities` plus the typed operations `service` dispatches to. A provider declares which contract operations and named secret ops it supports, and `directory/client` checks them before `Plan` | hosts EP-11 |
| `provider/ad` | directory-engineer | AD ops over `ldap`, `kerberos`, `ad/scope`; later SMB (`go-smb2`) and MS-RPC (`go-msrpc`), each with a register row first | implements EP-11 |
| `provider/entra` | directory-engineer | Graph ops, including delta queries ([user: delta](https://learn.microsoft.com/en-us/graph/api/user-delta)). SDK or thin client `[OPEN]` (ADR-0001) | implements EP-11 |
| `ldap` | directory-engineer | DC locator, LDAPS/StartTLS, `SecureConn`, paging, ranged reads, DC affinity | — |
| `kerberos` | directory-engineer | `GSSAPIClient` with adapters `sspi` (GOOS=windows platform adapter) and `krb5` (go-krb5, T-0023) | EP-12 |
| `credential` | directory-engineer; security-architect reviews | **Owns DM-11 DirectoryCredential** alone, with its SQL only in `credential/sealed` (§2 rule 6). The credential types and a `Source` interface. Its types are nameable only here (P3). Two sources: `credential/local` (gMSA through the process identity, keytab file, OS-protected certificate), used by both roles; and `credential/sealed` (Entra certificate and AD password fallback, unsealed with `keys` inside the caller's `WithTenantTx`), used **only** by the embedded connector, wired by `compose/server`. `credential/sealed` also implements `directory/connection`'s credential port (§7.3) | — |
| `psx` | backend-engineer | typed sidecar client over `proc` (safe-primitives §6.1) | — |

### 5.4 Server feature modules (`internal/modules/<id>/`)

| Module | Owner | API tag / Actions / datasets (interface) | EPs (§4) | Epic |
| --- | --- | --- | --- | --- |
| `connections` | directory-engineer | AD forest and Entra tenant onboarding; connector enrollment and binding; connection settings (signing, CBT, DC affinity). **Owns no table** (F1): it writes DM-10, DM-13 and DM-21 through `directory/connection`'s API and credentials through the credential port, inside its Actions | EP-1, 2, 3 (onboarding, binding and settings changes), 6, 7. Reads provider capabilities through `directory/client` (EP-11) | E2.7, E2.12 |
| `objects` | backend-engineer | create/modify/move/rename/delete/restore for users, groups, computers, contacts and OUs, with class definitions as data; templates, naming formats, rules, duplicate checks, copy; bulk and CSV planning. Owns DM-50, DM-51, DM-53. A user create that needs a generated password composes `helpdesk`'s password-set Action by ID and never reads DM-52 (F5) | EP-1, 2, **3** (one Action per class × verb; class definitions are data), 6, 7 | E2.2, E2.3 |
| `helpdesk` | backend-engineer | reset, unlock, random passwords, password options; LAPS/BitLocker reads (named secret ops); the reset console with caller verification (EP-10). Owns DM-38 and DM-52; its password-set Action generates the password inside `helpdesk` and returns no secret to its caller (F5) | EP-1, 2, **3** (reset, unlock, named secret reads), 6, 7. Uses EP-10 for caller verification | E2.5 |
| `delegation` | backend-engineer | roles, technicians, scopes (OU/group/site/domain, include/exclude, cross-domain); implements the directory scope evaluator (EP-6). Owns DM-35 DelegationScope only; roles and assignments are `authz`'s tables, changed through `authz`'s Go API inside its Actions (F2) | EP-1, 2, **3** (role and scope assignment changes; T-0047), **6** (implements the directory scope evaluator), 7 | E2.5 |
| `lifecycle` | backend-engineer | joiner/mover/leaver policies (HR, CSV, DB), scheduled automation, cleanup policies, expiry reminders; it composes Actions by ID. Attribute-change triggers are a job reading inventory change history by watermark until a change-feed Registrar method exists; it never imports `sync` (F3) | EP-1, 2, **3** (policies compose other modules' Actions by ID), 5 (policy schedules), 6, 7. Uses EP-9 (reminders) | E2.9 |
| `workflow` | backend-engineer | requests, review, approval, SLAs, assigning rules, manager approvers; implements EP-4 | EP-1, 2, **4** (approval gate), 5 (SLA timers, escalations), 6, 7. Uses EP-9 | E2.8 |
| `reports` | reporting-engineer | canned library (data), builder, schedules, exports, act-on-results (→ EP-3), ME crosswalk. Owns DM-71–73 and writes no other owner's data | EP-1, 2, 5 (schedules), 6, 7. **Consumes EP-8**; calls EP-3 by Action ID (act on results); uses EP-9 (delivery) | E2.6 |
| `history` | backend-engineer | object timeline (inventory history joined with our audit), undo entry point, baseline snapshot (MIG-18) | EP-1, 2, 6, 7. Consumes EP-8 (inventory history, audit); calls EP-3 through `operation.Undo` | E2.4 |
| `search` | backend-engineer | universal search over inventory with RBAC trimming; palette action catalogue from `operation.Catalogue()` (F4), never a module import; dashboard tiles | EP-1, 2, 6, 7. Reads the EP-3 Action catalogue for the palette | E2.1 |
| `m365` | directory-engineer | licences and other Entra-only actions; EXO mailboxes [M5] | EP-1, 2, **3** (licence and other Entra-only Actions on `provider/entra`), 6, 7 | E2.7 |
| `itsm` | backend-engineer | ServiceNow and ServiceDesk Plus as one adapter shape | EP-1, 2, 5 (outbound status sync), 6, 7. Submits requests as EP-3 Actions by ID; ITSM-driven approval (EP-4) later | E2.10 |
| `migration` | backend-engineer | ADMP importers, fidelity report, parallel-run comparator, job-ownership lock (ENH-02) | EP-1, 2, 5 (import and parallel-run jobs), 6, 7. Writes what it imports through the owning modules' Actions by ID (EP-3 caller; scope of configuration Actions: T-0047) | E2.11 |
| `hardening` | directory-engineer; security-architect designs | least-privilege wizard (ENH-08, needs SD primitive T-0028), hardening score | EP-1, 2, **3** (applies and removes the delegated rights it generates), 6, 7 | E2.13 |

Every module implements EP-1 (it is a module), EP-2 (its API tag), EP-6 (it declares
permissions) and EP-7 (its audit kinds, including its own setting changes). The column lists
these for completeness and marks in bold the EPs that define the module's role.

### 5.5 Other processes and tiers

| Component | Owner | Interface | EPs |
| --- | --- | --- | --- |
| `internal/compose/<role>`, `profile`, `config` | backend-engineer (shape: solution-architect) | each role package exports one `Run(ctx, config.Config) error`, which `cmd/<role>` calls; `profile.Manifest` values (data); `config.Load()`. Role packages never import each other (§1, §2 rules 3, 5, 7) | instantiates EP-1 / EP-13 through the generated lists; maps EP-12 adapter enums to implementations |
| `cmd/edge` [M4] | backend-engineer; security-architect reviews | serves the public SSPR flows; the server tunnels out to it. No credentials, no `store` (§2 rule 7) | — |
| `cmd/radius` [M4], `cmd/fpolicy` [M5, E5.5], `cmd/t0-connector` [post-v1] | backend-engineer / directory-engineer | each has its own role package `internal/compose/<role>` and links only kernel packages plus its role's code | EP-10 / EP-14 / EP-11 |
| `internal/agentmodules/addc` [M3] | windows-engineer | Security-log subscription, password-filter IPC, policy cache (`activediq.addc.v1`) | implements EP-13, EP-14 |
| `internal/agentmodules/fileserver` [M3] | windows-engineer | ACL reads and writes through the security-descriptor primitive (T-0028), and file-access auditing. Like every agent module it calls `proc` only, never `psx` (§7.4) | implements EP-13, EP-14 |
| `internal/agentmodules/mgmthelper` [M3, `OPEN`] | windows-engineer | Exists only if the M3 GPO spec chooses an agent module with its own constrained identity, rather than a Windows-hosted remote connector driving `sidecars/gpmc` (custody favours the connector, §13). If chosen, that spec also decides how it reaches `sidecars/gpmc`, because `psx` sits under the connector root, which agent modules may not import (§2 rule 3) | would implement EP-13 |
| `native/passfilt` [M4], `native/credprov` [M4] | windows-engineer | LSASS / LogonUI DLLs (ADR-0001 tier N, spikes T-0024/T-0025) | — |
| `sidecars/*` | windows-engineer | typed request/response over stdio, launched by `proc` with constant argv; never listens on a port | — |
| `web/` | frontend-engineer; `src/ds` component-designer | console shell and module screens over the generated client | hosts EP-15 |
| `packaging/` | devops-engineer | MSI and OCI artefacts in one signed release manifest (ADR-0002 rule 7) | — |
| `tools/fitness/*` | devops-engineer (`tenancy`: backend-engineer, T-0036) | CI jobs, §17 | — |

### 5.6 Ownership findings (ADR-0003 rule 9)

ADR-0003 checked the module contract and every domain-model owner line against modules that do not
look like `connections` and `objects`. The pass conditions: each owner line resolves to exactly
one owner key; **no lower layer reads a higher layer's table** and no foreign key points upward;
no entity has a split owner. These findings changed the map:

| # | Finding | Where it lands |
| --- | --- | --- |
| **F1** | Every table `connections` manages is read by a lower layer, so `connections` owns no table. DM-10 Connection, DM-13 ConnectorBinding and DM-21 HybridLink move to the new directory service `directory/connection`. DM-11 DirectoryCredential belongs to `connector/credential` alone (SQL only in `credential/sealed`), written through the credential port. DM-14 NamingContext stays with `inventory`, DM-19 SyncCursor (the change-feed cookie) with `sync` | §5.2 `connection`, `sync`; §5.3 `credential`; §5.4 `connections`; §7.3 |
| **F2** | Role and assignment tables (DM-34, DM-36) are owned by `platform/authz`. `delegation` changes them through `authz`'s Go API inside its Actions and evaluates directory scopes through its registered `ScopeEvaluator` | §5.1 `authz`; §5.4 `delegation` |
| **F3** | Attribute-change-triggered automation needs a change feed. Until an EP ticket adds a Registrar method for it, `lifecycle` runs a job that reads inventory change history (EP-8) by watermark. It never subscribes by importing `sync` | §5.2 `inventory`; §5.4 `lifecycle`; §16 |
| **F4** | `search` needs the Action list for the palette. `operation` exposes a read-only `Catalogue()`, a kernel service reached through `platform.Deps`, never a module import | §5.1 `operation`; §5.4 `search` |
| **F5** | `objects` needs a generated password at user create, but DM-52 belongs to `helpdesk`. `objects` composes `helpdesk`'s password-set Action by ID, which generates the password inside `helpdesk` and returns no secret | §5.4 `objects`, `helpdesk` |
| **F6** (amendment) | The kernel needs directory-owned data: `authz` resolves group-subject membership from inventory (DM-36.I2), and `authn` gates SSO bindings on a `matched` correlation (DM-30.I5 → DM-20.I4). The kernel declares read ports (`authz.Membership`, `authn.DirectoryAnchors`), `directory/inventory` implements them directly, and `compose/server` wires them | §5.1 `authz`, `authn`; §5.2 `inventory`; §7.5 |

---

## 6. API boundary: the public API is the product boundary

- **Every capability is an OpenAPI operation first.** The console, ITSM integrations, customer
  scripts and later the PowerShell module and MCP (ENH-11, M3) all use the same operations. The
  web client is generated, and the console has **no private endpoints**. The exceptions are not
  product API: auth callbacks, health, static assets and the `fleet` gRPC gateway (T-0046).
- **Tenant never travels in the API.** It comes from the authenticated principal (ADR-0002, Request
  row). A `tenant_id` or `X-Tenant-*` field in the contract fails T5.
- **Strict decoding at the edge.** Invalid UTF-8 and lone surrogates are rejected, never repaired
  (safe-primitives R3; `lessons.md`, encoding/json v1).
- **Server-built values only (tier W implements no primitive, safe-primitives §2.1):**

| Kind | API → web | web → API |
| --- | --- | --- |
| Object | `{guid, dn, rdns:[{type,value}]}`; `dn` and `rdns` are for display, rendered by `dn` | `guid` only (`GUIDRef`), never a DN string |
| Filter | `{ast, text}`; `text` is the canonical P1 rendering | a filter AST, or `{adminText}` for `ParseAdminFilter` |
| PowerShell | `DisplayOnlyPowerShell`, rendered by `pslit` | nothing |
| SQL | nothing | a report-definition AST |

  FF-SP3 scans `web/` for DN/filter-shaped literals, quote doubling and DN string splitting.
- **Each operation declares its permission** (`x-permission`), which `authz` checks. Object-level
  scope is checked again inside the Action (§11).

---

## 7. The directory-connector layer and safe primitives

### 7.1 The connector contract (`proto/activediq/connector/v1`)

A versioned protobuf service of **typed** operations. It has no free-form query verb and no script
verb (ADR-0002 rule 3).

| Group | Operations (read side finalised in [connector-contract.md](connector-contract.md); write, secret and auth rows remain a sketch) |
| --- | --- |
| Discover | `Describe` (provider kind, capabilities, naming contexts, DCs, health), `DescribeSchema` (attribute syntax and flags per class) |
| Read | `ScopedSearch{connection, delegation roots: GUIDRef[], filter AST, attrs, page}`, `Read{ObjectRef, attrs}`, `ReadPerDC{ObjectRef, attrs}` (exact last logon, ADM-084) |
| Write | `Apply{op: Create, Modify, Move, Rename, Delete, Restore, MemberAdd, MemberRemove, SetPassword(Secret), Unlock, AssignLicenses…; idempotency key; acting principal; DC hint}` returns read-back state |
| Named secret ops | `ReadSecret{LAPS, BitLocker}`: each has its own capability and audit kind (safe-primitives §3.7) |
| Change feed | `ChangeFeed{naming context or Entra tenant, cookie}` returns a stream of batches + new cookie (DirSync / Graph delta). `SecretAttrs` are stripped before they leave the connector |
| Auth | `VerifyUser` / SPNEGO acceptor for console sign-in with AD identity (ADR-0002 rule 3) |

Escape controls such as ASQ, phantom root, show-deleted and the Global Catalog exist only inside
named operations (`GroupMembersExpand`, `ForestWideLookup`, `RestoreDeleted`, `ChangeTracking`), as
safe-primitives §3.6 requires.

### 7.2 Transports and binding

```
   server-side caller (Action, sync)
              |
     directory/client  -- resolves the binding (tenant data): connection -> connector(s)
        |                                   |
   embedded transport                  remote transport
   (in-process call to the same        (cmd/connector dials OUT to fleet over mTLS;
    connector/service; same proto      the server multiplexes the same RPCs over the
    messages; wired by                 connector-initiated stream; tenant from cert SAN;
    compose/server)                    fleet tunnel, bound by directory/client)
        |                                   |
        +-------------- connector/service ---+---> provider/ad | provider/entra
```

- **Same contract, same conformance suite.** Both transports run the provider conformance suite
  against the Samba lab on every merge (P3).
- **Redundancy (ADM-210).** A connection may bind several connectors. `client` picks a healthy
  one. Each operation keeps its DC affinity for read-your-writes (FEAS §1.1).
- **The embedded connector has no identity of its own.** It runs inside the caller's
  `WithTenantTx` and unseals only that tenant's credentials (ADR-0002).
- **`fleet` does not know the contract.** For each enrolled connector, `fleet` exposes a
  contract-agnostic tunnel, a `grpc.ClientConnInterface` over the connection the connector opened.
  `directory/client` binds the generated `activediq.connector.v1` client to that tunnel. The
  platform root therefore never imports `internal/proto/activediq/…` (§2 rule 1, ADR-0002 U2).
  Agent-module contracts bind to the same tunnel from the server module that owns them (§5.1).

### 7.3 Credential custody

Directory credential types are declared in `connector/credential`, and only code under
`internal/connector/` can name them, unseal them or log about them. The credentials are the gMSA
(no secret), the keytab, the Entra certificate private key and any AD password fallback. No API
response ever carries one (P3; FEAS §2.5).

There are two credential sources, and the role packages decide which one a binary links:
- **Local** (`credential/local`): the gMSA through the process identity, a keytab file, or an
  OS-protected certificate on the connector's own host. Both roles use it.
- **Sealed** (`credential/sealed`): the Entra certificate and any AD password fallback, stored
  sealed in PostgreSQL and unsealed with `keys` inside the caller's `WithTenantTx`. Only the
  embedded connector uses it, because only `compose/server` wires it. A remote connector therefore
  links no `store` (§2 rule 7).

**Who owns the rows, and how secrets get in** (ADR-0003 rule 6, F1). DM-11 DirectoryCredential
is owned by `connector/credential` alone, and its SQL lives only in `credential/sealed`. The
`connections` module must create, rotate and revoke credentials, but modules cannot import the
connector (§2 rule 3, §2.1). So the write path is a **credential port**:

```
 connections (module, inside its Actions)
      |  directory.Services.Connection  -> credential port (interface declared in directory/connection)
      v
 directory/connection   -- port: secret material IN only as secret.Secret; public metadata OUT
      |                    (a directory/model type); no method returns secret material
      v  (value handed in by compose/server, as it hands the embedded transport to directory/client)
 connector/credential/sealed  -- seals with keys, stores DM-11, unseals only for the embedded connector
```

- The port's method set (create, rotate, revoke, describe) is fixed by the `connections` build
  ticket, and security-architect reviews it there; custody is T-0007's.
- Unsealing stays under `internal/connector/` (DM-11.I1). `cmd/connector` never links
  `credential/sealed` or `keys` (§2 rule 7), so "sealed only in the server" is checked, not just
  stated.

A remote connector that needs more than a local credential (an Entra certificate or a password
fallback on a remote host) is `[OPEN → T-0007]`.

### 7.4 Where each primitive lives and who uses it

| Primitive | Package | Used by | Not by |
| --- | --- | --- | --- |
| P1 filter AST, renderer, admin-filter parser | `directory/ldapfilter` | modules (build ASTs), `connector` (render), `reports` (admin filters) | `web` |
| P2 DN, `ObjectRef`, `GUIDRef` | `directory/dn` | everyone server-side. It implements RFC 4514 itself and **does not wrap go-ldap's `ParseDN`**, because ADR-0002 keeps protocol libraries in the connector root. The go-ldap round-trip oracle runs from a test under `internal/connector/ldap` | `web` |
| P3 codecs | `directory/attr/*` | `connector` (decode), `inventory`, modules | `web` |
| `Secret` | `platform/secret` | `helpdesk`, `connector`, `keys`, `authn` | logs, audit details, errors, JSON |
| Scoped search, controls | `connector/ad/scope` | `provider/ad` only | feature code (it gets `ScopedSearch` via the contract) |
| P4 `psx` / `proc` / `pslit` | `connector/psx`, `platform/proc`, `platform/pslit` | connector (sidecars), update client, API (display) | agents call `proc` only |
| P5 SQL | `platform/store`, `store/reportsql` | everyone through sqlc + `WithTenantTx` | hand-written SQL text (FF-SP2 `sqlconst`) |
| Tier N subset | `native/shared` | `passfilt`, `credprov` | — (it runs the same corpus) |

The corpus lives at `testdata/safe-primitives/<unit>.jsonl`. Every implementation in every tier runs
the records for the units it implements (FF-SP4).

### 7.5 Ports: how a lower layer reads data it does not own

A lower layer can neither import a higher one (§2 rules 1–3) nor run SQL on another owner's tables
(§2 rule 6). When it needs that data, the **consumer declares a port** (an interface in its own
package), **the owner implements it directly** (no adapter type in `compose`, which M4 forbids),
and **`compose/server` wires the owner's value into the consumer**. The same shape serves both
directions in which data crosses a boundary:

| Port | Declared in (consumer) | Implemented by (owner) | Data | Semantics review |
| --- | --- | --- | --- | --- |
| credential port | `directory/connection` | `connector/credential/sealed` | DM-11 writes in (`secret.Secret`), metadata out (§7.3) | `connections` build ticket, security-architect |
| `authz.Membership` | `platform/authz` | `directory/inventory` | DM-16, DM-17, DM-20 for group subjects (DM-36.I2) | **`authz` build ticket, security-architect** (it is the authorization path) |
| `authn.DirectoryAnchors` | `platform/authn` | `directory/inventory` | DM-16, DM-20 for SSO bindings (DM-30.I5) | `authn` build ticket, security-architect |

The kernel ports (ADR-0003 F6) name kernel types only, because the kernel may not import
`directory/model`. `authn` declares `DirectoryRef{Connection, Plane, Object}`: a connection ID, the
directory plane (`PlaneAD` or `PlaneEntra`) and an object ID (objectGUID for AD, Graph object ID for
Entra), opaque to the kernel. `authz` reuses it. `Plane` is what lets `authz` tell a
**correlation-derived** grant (DM-36.I2: the group lives in the other plane from the account's
sign-in identity, so it never carries `tenant-owner` or `control_plane` and, for an `sso` account,
counts only in a session that verified the authority factor, DM-30.I6) from a same-plane one
without reading a connection table.
The method sets the build tickets start from:

```go
// internal/platform/authz
type Membership interface {
    // GroupsOf returns the groups, in member's own plane, through which member can hold a
    // group-subject grant (DM-36.I2): transitive directory membership including primary-group edges,
    // deactivated links excluded, security-enabled and non-public groups only, AD groups whose DACL
    // lets a broad principal change membership excluded (TM-D18), FSP members resolved to
    // connected-forest objects, sIDHistory not followed. authz reaches the other plane by calling
    // GroupsOf on the objects Matched returns; every group it gets that way is correlation-derived.
    GroupsOf(ctx context.Context, t tenant.ID, member authn.DirectoryRef) ([]authn.DirectoryRef, error)
    // Matched returns the objects in other connections that obj has a `matched` correlation with
    // (DM-20.I4). A `candidate` correlation is never returned.
    Matched(ctx context.Context, t tenant.ID, obj authn.DirectoryRef) ([]authn.DirectoryRef, error)
}

// internal/platform/authn
type DirectoryAnchors interface {
    // Resolve returns the directory object an SSO anchor claim names: `oid` with a `tid` that matches
    // an Entra connection, or `onprem_sid` (resolved once at binding, then stored as the GUID, X3).
    Resolve(ctx context.Context, t tenant.ID, a Anchor) (DirectoryRef, error)
    // Matched reports whether the Entra object and the AD object have a `matched` correlation (DM-20.I4).
    Matched(ctx context.Context, t tenant.ID, entra, ad DirectoryRef) (bool, error)
}
```

These answer from inventory state. DM-20.I5 also requires a **live** re-check of gate conditions
(a)–(e) at sign-in and at Plan. `inventory` does not import `client` (the F1 order), so whether
that live read is a method of these ports or a separate port on `directory/client` is decided in
the `authn` and `authz` build tickets with security-architect. Either way it crosses the layer
through a port, never through an import.

---

## 8. Job and operation engine

```
 API / workflow / automation / palette / report results
        | Input (schema from OpenAPI)
        v
 Plan (dry run: live read via connector, diff, reversibility, approvals needed)  -- no writes
        v
 Approval gate (EP-4): permission-only (default) or workflow (request -> review -> approve, SLAs)
        v
 Execute: jobs (River via platform/jobs) -> chunked Apply -> checkpoint -> resume after crash
        v
 Verify (read-back from the same DC)  -> audit (hash chain) + undo record -> notify
```

- **Every step is tenant-scoped.** Job arguments carry `tenant_id`, and the wrapper opens
  `WithTenantTx` before the body runs (ADR-0002, Jobs row).
- **Idempotency.** Each `(operation, step)` has a key, so a retried chunk never double-applies.
- **Partial failure is visible.** A bulk job reports per-row results and never "succeeds" over
  skipped rows (engineering-standards §4).
- **Undo** plans the `Inverse` of a recorded outcome as a new operation. It goes through the same
  approval and verification. Irreversible steps, such as passwords, are flagged at Plan time
  (ENH-04 risk).
- **Singleton work** (sync per naming context, schedulers) holds a lease in PostgreSQL, so any
  node can run it (ADR-0002 rule 6).
- The state machine and guarantees are decided in T-0047.

---

## 9. Audit pipeline

There are three streams. v1 ships the first two.

| Stream | What it records | Source | Store | Milestone |
| --- | --- | --- | --- | --- |
| **Our audit trail** | every Action step, sign-in, permission change and setting change, with the acting principal | `platform/audit` | append-only tenant table; one hash chain per tenant; export + offline verify; SIEM forwarding via EP-9 (ADM-198) | v1 (ADM-137, 138; ADA-112; RMP-043) |
| **Directory change history** | what changed and when, including changes made outside activeDIQ, with originating DC and version, but not *who* | `directory/sync` (DirSync/Graph delta + replication metadata) | `inventory` history (§12) | v1 (ADM-005, without "who" for native changes, E2.4) |
| **DC events** | *who* made a change (5136/4738/4728…), logons, lockouts | `addc` agent module → `fleet` → event pipeline (EP-14) | partitioned event tables, if T-0026 passes ADR-0001 rule 3 | M3 |

The `history` module joins the streams on `objectGUID` and time. An activeDIQ change is linked by
operation ID, and a native change by the correlated event from M3 on (FEAS §4.4 flow 3).

---

## 10. Reporting

- **A report is data:** a definition AST over a **dataset** (EP-8). The canned library and the ME
  report crosswalk (MIG-05) are shipped definitions, not code.
- **One compiler.** `store/reportsql` turns `(AST, dataset, scope)` into SQL text + arguments. It is
  the only dynamic SQL in the product. Identifiers come only from the dataset's pre-quoted registry,
  and operators are enums (P5 rules 3, 13).
- **Authorization is in the query.** The compiler injects the caller's scope as a GUID-ancestry
  predicate, so counts and pages come after authorization (safe-primitives LF-39).
- **Freshness.** Inventory is kept current by the change feed. "Exact last logon" uses per-DC
  values (ADM-084). A report says how fresh its data is, never "live" when it is not.
- **Scheduling** uses `jobs`, **delivery** uses `notify`, **exports** use `platform/export`
  (T-0029), and **act-on-results** hands the selected GUIDs to an Action's `Plan` (ADM-098).

---

## 11. Authentication, RBAC and delegation

- **Principals:** console users (technicians), API tokens, connectors and agents (mTLS), and
  anonymous end-user flows (resolved by hostname binding, ADR-0002).
- **Sign-in:** SAML/OIDC SSO (ADM-143). Local break-glass accounts always require MFA (ADM-142).
  AD-identity sign-in goes through the connector's `VerifyUser`/SPNEGO, never through an LDAP bind
  from platform code. HTTPS only and no default credentials (ADM-145).
- **RBAC:** modules declare permissions (EP-6). A role is a set of permissions. An assignment is
  principal (or group) × role × scope. Built-in roles ship as data (ADM-126).
- **Delegation scopes** (ADM-127–130) are evaluated by `delegation` against GUID ancestry in
  `inventory`. Action `Plan` re-reads the target's live parent chain from the DC before it applies,
  so a moved object cannot escape its scope between check and write.
- **Help-desk caller verification (ENH-09):** an EP-10 method (email/SMS OTP to contact data
  already held in AD or HR, or TOTP) gates `helpdesk` Actions. The factor used is recorded in the
  same audit event as the reset.
- **Our own AD identity holds delegated rights only** (ADR-0002 rule 9). `hardening` generates and
  verifies those rights (ENH-08, FD-08).
- **Per-technician attribution in AD's own logs** (ADM-134 leapfrog). Our audit trail always records
  the technician. How AD's own logs show the technician is still open. The options are Kerberos
  constrained delegation (S4U2Proxy) from the connector identity, and per-session technician
  credentials held only in connector memory. `[OPEN → ADM-134 spec + T-0007]`

---

## 12. Storage

- **PostgreSQL is the only stateful service** (ADR-0001 rule 3). Tenancy rules from migration 1
  (ADR-0002, "Where tenancy lives"):
  - tenant-led primary keys and unique indexes;
  - composite foreign keys;
  - RLS + `FORCE` on every table and partition;
  - `security_invoker` views;
  - no materialized views over tenant tables.
- **Directory objects are keyed by `(tenant_id, connection_id, object_guid)`, never by DN.** DNs
  change on move and rename, so a DN is stored as a current, display-only attribute. Parent and
  ancestry are GUIDs. Entra objects use their Graph object ID. AD↔Entra correlation records the
  source anchor. Graph's `onPremisesImmutableId` "is used to associate an on-premises Active
  Directory user account to their Microsoft Entra user object", and `onPremisesSyncEnabled` says
  whether AD is the source of authority
  ([user resource](https://learn.microsoft.com/en-us/graph/api/resources/user)). The source of
  authority drives the hybrid view (ADM-169).
- **History is built for audit queries over years.** Rows are append-only, one per attribute change:
  `(object_guid, attribute, old, new, observed_at, usn, originating_dsa, source = sync | operation:<id> | event:<id>)`.
  - The table is partitioned by time; retention is per tenant (ADM-206).
  - It is indexed for "everything about object X", "every change to attribute A in a period" and
    "everything operation O did".
  - Secret attributes are never stored (LF-38).
  - Exact shapes: T-0006 (domain model) and T-0026 (ingest benchmark).
- **Blobs** (baseline snapshots, exports, GPO backups [M3]) go through `platform/blob` with
  tenant-prefixed keys. Adapters are `fs` (default) and a customer-supplied S3-API store. We never
  ship an object-store server (lessons: MinIO).
- **Keys:** the KEK comes from the profile's adapter; each tenant has a data key; directory
  credentials and agent-policy signing keys are sealed under it (ADR-0002, Keys row).
- **Configuration:** platform scope comes from the installer and config file. Tenant scope is set
  only through the API (ADR-0002, Configuration row).

---

## 13. Windows-native components and how they talk to the server

| Component | Runs in / on | Talks to | How | Contract | When |
| --- | --- | --- | --- | --- | --- |
| Server MSI | a Windows member server, WS2019+; **refuses a DC** (ADR-0002 rule 9) | — | installs `cmd/server` as a service under a gMSA, plus bundled PostgreSQL | release manifest | M2 |
| Remote `cmd/connector` | any Windows or Linux host near the DCs | server `fleet` | dials out over gRPC mTLS; enrolls once; the certificate SAN names tenant + component | `activediq.connector.v1` | M2 |
| `cmd/agent` + `addc` | every DC | server `fleet` | dials out over mTLS; no listening port (ADR-0001 tier A) | `skenzeriq.agent.v1` + `activediq.addc.v1` (T-0040) | M3 |
| Password filter `native/passfilt` | LSASS on writable DCs | the `addc` module on the same DC | local named pipe ACL'd to the agent's service SID; no network I/O in the LSASS path; policy is a signed document cached by the agent | IPC format: T-0024 + T-0040 | M4 |
| Credential provider `native/credprov` | LogonUI on endpoints | SSPR API (through `edge` or direct) | pinned TLS | SSPR API (OpenAPI) | M4 |
| `fileserver` agent module (and `mgmthelper`, only if chosen below) | file servers (`mgmthelper`: one member server) | server `fleet` | as `addc` | `activediq.<module>.v1` | M3 |
| Sidecars `gpmc`, `exchange` | the host that drives them | the Go process that launched them | stdio typed messages; `AddCommand`/`AddParameter` only; constant argv (FF-SP8/9) | `psx` op manifest | M3 / FD-04 |

`mgmthelper` raises one open identity question. GPMC work needs a directory identity, and ADR-0002
rule 3 says only the connector holds one. The M3 GPO spec therefore decides between two designs: a
Windows-hosted remote connector that drives `sidecars/gpmc`, or an agent module that runs under its
own constrained identity. Custody favours the first. `[OPEN → M3 GPO spec]`

---

## 14. Key data flows

1. **Inventory.** `sync` takes the lease for a naming context and calls `ChangeFeed`. The connector
   pages and runs DirSync (or Graph delta) and strips secret attributes. `inventory` writes the
   current state and history rows in one `WithTenantTx` together with the new cookie. Search,
   reports and the UI read `inventory`.
2. **A write** (e.g. bulk modify, ADM-034). API → `authz` (permission) → `Action.Plan` (live read,
   scope re-check, diff) → UI shows the preview → gate → `operation` enqueues chunks → `Apply`
   through `client` → connector, pinned to one DC, idempotent → `Verify` → `audit` (chain + undo
   record) → `notify`. The change also reaches `inventory` through the change feed and is linked to
   the operation ID.
3. **Help-desk reset** (ADM-136 + ENH-09). The technician opens the caller → `authn` sends an OTP
   to the caller's contact data from `inventory` → the caller reads the code back → `helpdesk`
   `reset+unlock` Action (`SetPassword(Secret)` with the policy-hints control) → one audit event
   that records the verification factor. The target is ≤ 3 interactions (ENH-01 budget).
4. **Scheduled report** (ADM-101). `jobs` fires → `reportsql` compiles with the owner's scope →
   `export` encodes → `notify` delivers and records the delivery.
5. **Remote connector.** An admin creates an enrollment token (`connections`) → the connector dials
   `fleet` and gets a certificate (tenant + component in the SAN) → the binding is set as tenant
   data → operations flow over the connector-initiated stream.
6. **Update** (ADM-209, ENH-07). The courier (online or offline bundle) fetches → the one verifier
   checks the signed release manifest → stage → expand-only migrations under the owner role, behind
   a lease → node-by-node restart → health check → automatic rollback on failure. The OCI apply
   mechanism, which has no Docker-socket access, is `[OPEN → ENH-07 spec]`.

---

## 15. Traceability: P1 must-have parity features → component

There are 83 rows with `phase = P1` and `importance = must` in
[`feature-parity-matrix.csv`](../../business/competitive-analysis/feature-parity-matrix.csv).
"Primary" is where the behaviour is implemented. "Also" lists the components it relies on.

| Feature IDs | Primary component | Also |
| --- | --- | --- |
| ADM-001 | `web` shell (task-first console, palette) + `search` | EP-3 action catalogue |
| ADM-003 | `search` | `inventory`, `authz` trimming |
| ADM-004 | `web/src/modules/objects` (object page) | `objects`, `history`, `inventory` |
| ADM-005 | `history` | `inventory` history, `audit`, `sync` |
| ADM-008, 016, 024, 033, 048, 050, 055, 056 | `objects` (class definitions as data) | `operation`, `client` → `provider/ad` |
| ADM-010, 011, 034 | `objects` (bulk and CSV planning) | `operation` chunking on `jobs`; ENH-04 preview and undo |
| ADM-012, 013, 015, 017, 018, 020, I360-004 | `objects` (templates, rules, naming, duplicate check) | `ScopedSearch` for duplicate checks; the DC decides uniqueness (R9) |
| ADM-023 | `objects` | `provider/ad` SMB + SD primitive (T-0028) for home and profile folders; `go-smb2` register row first |
| ADM-027 | `objects` (one flow for AD + Entra) | `provider/entra`, `m365` licence Action |
| ADM-038 | `objects` (`RestoreDeleted`, a named op) | `connector/ad/scope` (show-deleted control only here) |
| ADM-057 | `objects` (computer reset/restore) | `provider/ad` |
| ADM-021, 022 | `helpdesk` (password generator, secure options) | `platform/secret` |
| ADM-060 | `helpdesk` (`ReadSecret` LAPS/BitLocker) | `connector` named secret ops; spike E1.4(d) (§3.4) |
| ADM-136 | `helpdesk` + `authn` caller verification (ENH-09) | `audit` |
| ADM-083, 085, 086, 087, 093, 099 | `reports` (definitions as data) | `platform/report`, `store/reportsql`, `inventory` dataset |
| ADM-084 | `reports` | `ReadPerDC` + per-DC values in `inventory` |
| ADM-097 | `reports` (builder) + `web/src/modules/reports` | `reportsql` |
| ADM-098 | `reports` → `operation` (act on results) | EP-3 Actions of other modules, by ID |
| ADM-100 | `reports` | `platform/export` (T-0029) |
| ADM-101 | `reports` | `jobs`, `notify` |
| ADM-125, 126, 127, 128, 129, 130, I360-020, ERP-014, RMP-042 | `delegation` | `authz` (EP-6), `inventory` ancestry |
| ADM-134 | `audit` + `delegation` | `connector` acting principal; AD-side attribution `[OPEN]` (§11) |
| ADM-137, 138, ADA-112 | `platform/audit` | `reports` dataset |
| RMP-043 | `platform/audit` | `notify` SIEM sink |
| ADM-142, 143, 145, ADA-111, ADA-116, ADSS-126, RMP-044, M365-018, ERP-017 | `platform/authn` + `apihost` hardening | `connector` SPNEGO/`VerifyUser`; T-0007 |
| ADM-146, 148 | `lifecycle` (cleanup) | `reports` → act on results; `objects` Actions |
| ADM-159 | `connections` (Entra onboarding: customer app registration, certificate) | `keys`, `connector/credential` |
| ADM-161, M365-005 | `m365` | `provider/entra` |
| ADM-162, 164, M365-007 | `objects` on the Entra provider | `provider/entra` |
| ADM-169 | `inventory` correlation + `web/src/modules/objects` hybrid view | `sync` (Graph delta) |
| I360-003 | `sync` (Graph delta) | `provider/entra` |
| I360-002 | `sync` + remote connector (outbound-only, DirSync) | `fleet`, §7.2 |
| ADM-188, 189 | `api/openapi` + `apihost` | T-0046 |
| ADM-204 | `platform/notify` | each module's templates |
| ADM-205 | `platform/notify` (mail, SMS gateway, egress proxy) | — |
| ADM-209, RMP-046 | `platform/update` + `packaging/` release train | ENH-07 spec, T-0027 signing |
| ADM-210 | `compose/server` (stateless nodes) + `directory/client` (redundant connector bindings) | leases (`jobs`), PostgreSQL HA (customer) |
| ADM-212 | `connections` + `connector/ldap` (LDAPS, signing, CBT, DC affinity) | T-0023 |

**v1 pulls (FD-02, ADMP must rows from P2):**
- ADM-039, 041, 042, 043, 044, 104, 105, 107, 147 → `lifecycle`.
- ADM-047 → `lifecycle` + `notify`.
- ADM-114 → `lifecycle` + `audit`.
- ADM-116, 117, 118, 120, 121 → `workflow` (EP-4).
- ADM-191, 192 → `itsm`.
- ADM-198 → `audit` + `notify` SIEM sink.
- ADM-026 and ADM-070 (conditional, FD-04) → `sidecars/exchange` on a Windows-hosted connector.

**v1 pulls (FD-03, five P2 should rows):**
- ADM-040 (database-driven provisioning) → `lifecycle`. A database is one more source in the
  importer shape that HR and CSV use. Each database driver needs a licence-register row first
  (ADR-0001).
- ADM-106 (automation sent through approval) → `lifecycle` + `workflow`. Automation submits
  operations, and they pass the EP-4 gate like any other operation.
- ADM-119 (workflow SLAs and escalations) → `workflow` (EP-5 timers) + `notify`.
- ADM-009 (cloud-only accounts) → `objects` on `provider/entra` + `m365`. FD-03 pulls the Graph
  half only. Google Workspace would be a later EP-11 provider.
- ADM-160 (M365 bulk create/modify, guests) → `objects` bulk and CSV planning on `provider/entra`.

---

## 16. Open, and where it gets decided

| Item | Decided in |
| --- | --- |
| ~~Module system, import DAG, generated lists, table ownership, `fitness-modules`~~ | **Decided:** [ADR-0003](../decisions/0003-module-system-extension-points-only-on-ramp.md), ratified 2026-10-02 (T-0045); restated in §2, §4.1, §5, §7.3, §7.5 |
| ~~`platform/module` migration to the concrete `Registrar`, `Boot`, `moduletest`; empty `platform.Deps` and `directory.Services`; `0001_tenant_tenants.sql`~~ | **Done:** T-0144 |
| Credential port method set (create, rotate, revoke, describe) | the `connections` build ticket, security-architect reviews (custody: T-0007) |
| `authz.Membership` and `authn.DirectoryAnchors` semantics, and where the DM-20.I5 live re-check sits (§7.5) | the `authz` and `authn` build tickets, security-architect reviews (ADR-0003 F6) |
| Change-feed Registrar method for attribute-triggered automation (ADR-0003 F3) | the first ticket that needs triggered automation (E2.9) |
| Shape of `operation.Catalogue()` (ADR-0003 F4) and gate interplay with Actions | T-0047 |
| Freeze of `platform/module` (`// Frozen:` line), after the rule 9 paper check and the first two modules | solution-architect, once `connections` and `objects` have shipped through EP-1 (ADR-0003 rules 8–9) |
| OpenAPI layout, generators, router, versioning, strict JSON, `x-permission`; the Registrar's `API` registration shape (`apihost.TagHandlers`) | **T-0046** (ADR) |
| Action contract, operation state machine, audit-trail guarantees; whether configuration writes (templates, roles, policies, `migration` imports) are Actions | **T-0047** (ADR) |
| Paths in skills and safe-primitives.md | **T-0048** (chore) |
| Agent host and module contract (EP-13, its constructor signature and dependency struct, and the agent tier's rule 9 paper check); password-filter IPC | T-0040 (+ T-0024) |
| Entities, lifecycle states, inventory and history shapes | T-0006, T-0026 |
| Trust boundaries per profile; Graph permissions; delegated-rights verification; ADM-134 attribution; edge surface; remote-connector credentials beyond gMSA/keytab (§7.3) | T-0007 |
| Security-descriptor primitive (ADM-023, ENH-08, `fileserver`) | T-0028 |
| Output encoders | T-0029 |
| CBT bind on go-krb5 (Samba proven by T-0023; go-krb5 pinned to a `main` commit per ADR-0001 erratum E1); WS2025 proof; LAPS from Linux | T-0133; E1.4(d) |
| Repository scaffold implementing §1 | T-0014 |
| Update protocol and rings; OCI apply mechanism | ENH-07 spec (M2 plan, T-0031) |
| Bundled DB standby and DB backup on `linux-oci` | E2.12 PRD (T-0031) |
| SAML library; Graph SDK vs thin client; S3 client; go-smb2; go-msrpc | the first ticket that needs each one, with a licence-register row first (ADR-0001) |
| `mgmthelper` identity vs connector-driven GPMC | M3 GPO spec |
| Search index technique (no second store) | search spec (E2.1) |

---

## 17. Enforcement summary

| Rule | Check | Ticket |
| --- | --- | --- |
| Language zones, cgo-free Go, one stateful service, licence register, declared exceptions | `fitness-stack` F1–F5 (`tools/fitness/stack/`, in `make ci`) | T-0022 (done) |
| Tenancy from migration 1, RLS, roles, isolation, static tenancy checks (incl. FF-SP7) | `fitness-tenancy` T1–T5 (`tools/fitness/tenancy/`, in `make ci`; rules: [tenancy-fitness.md](tenancy-fitness.md)) | T-0036 (done) |
| Profiles by composition, planes, both transports, UEM boundary, platform root extractable | `fitness-profiles` P1–P7, U1–U4 | T-0038 |
| Module system (ADR-0003): import graph, module islands, generated lists and module pages, Registrar only, constructor bound, composition root, closed catalogue, table ownership (static and catalog), binary hygiene, web mirror, exemptions, self-test (§2, §4.1, §5) | `fitness-modules` M1–M12 (`tools/fitness/modules/`, in `make ci`; the T-0014 subset of §2 rules 1–5, 7, 8 runs today) | T-0141 (ADR-0003 becomes `accepted` when it is green) |
| Public API: routes ⊆ OpenAPI, `x-permission`, generated client | API fitness | T-0046 → its fitness ticket |
| Writes only via `Action.Apply`; audit chain verifies | operation fitness | T-0047 → its fitness ticket |
| Safe primitives: imports, banned APIs, literal shapes, corpus, fuzz, oracles, `psx` manifest | FF-SP1–SP9 | T-0033, T-0034 |

Rows marked "done" run in `make ci` today; the others do not yet, or run only in part. This
blueprint moves to `accepted` when a human has read it end to end. The rules it states become
*enforced* only as each row's check goes green in `make ci`.

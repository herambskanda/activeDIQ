---
title: "Architecture blueprint v0"
date: 2026-10-02
updated: 2026-11-07
status: review
owner: heramb
ticket: T-0035, T-0041, T-0107, T-0212, T-0874, T-0915, T-0993, T-1093, T-1221, T-1729
binding_sources: ADR-0001 (ratified), ADR-0002 (ratified), ADR-0003 (ratified), ADR-0004 (ratified), ADR-0005 (ratified), ADR-0010 (accepted), ADR-0011 (ratified), safe-primitives.md (review), modules/reports.md (draft)
---

# activeDIQ architecture blueprint v0

This is the map every engineer works from. It shows where a change belongs, which rules it must obey,
and who owns each part. Read it once end to end (an afternoon). After that, use §5 (component
catalogue) and §15 (feature → component) as lookup tables.

**What is binding.** The blueprint restates five ratified ADRs and cites them:
- [ADR-0001](../decisions/0001-technology-stack.md): stack and language zones;
- [ADR-0002](../decisions/0002-deployment-model.md): profiles, roles, tenancy and the connector contract;
- [ADR-0003](../decisions/0003-module-system-extension-points-only-on-ramp.md): the module system,
  import graph, table ownership and binary hygiene (§1 migrations row, §2, §4.1, §5, §7.3, §7.5);
- [ADR-0004](../decisions/0004-public-api-contract-openapi-first.md): the public API contract: `api/openapi/` layout, the
  in-house generator `tools/gen/api`, `apihost` on `net/http.ServeMux`, strict `encoding/json/v2`,
  one `x-permission` per operation and one `/api/v1` that only grows (§1, §4.1 EP-2, §6, §16, §17);
- [ADR-0005](../decisions/0005-operation-pipeline-and-audit-trail.md): the Action contract, the
  step token, the operation pipeline and the audit trail (§2.3, §4.2, §5.1, §7.5, §8, §9).

It also applies the [safe-primitives spec](safe-primitives.md). Those documents delegated several
**paths** to this blueprint, and it **fixes** them in §1.1. Everything else here is design direction.
Where a direction needs its own ADR, the queued ticket is named. If
this blueprint and a ratified ADR disagree, the ADR wins and this file is the bug.

**Notation.** `[OPEN → T-xxxx]` means the item is decided in that ticket. `[M3]` means the item
arrives in that milestone; it is drawn here so that v1 code does not block it. Owner names are
factory agents (`.claude/agents/`).

**Ticket IDs.** The board was re-cut on 2026-10-21 (T-0031). A bare `T-xxxx` names a live ticket
(checked by T-0041: the jobs builds, `apihost`, the TM §7.6 amendment, the API fitness rows). An
`old T-xxxx` is an earlier-board number that no longer names that work; do not look it up on the live
board. Work an old ID delivered is marked delivered. ADR-0004's old-to-new table maps the API ones.

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
|  | ldapfilter dn attr model inventory conn.|  | tenant authority store authn authz audit personal|
|  | sync  client --(connector contract)--+  |  | jobs operation notify report keys secret proc    |
|  +--------------------------------------|--+  | blob pslit fleet(gateway) update telemetry module|
|   embedded transport (compose/server)   |     +---------------------------------------------------+
|  +--------------------------------------v-- connector role  internal/connector/ ----------------+
|  | service | read write rights tier0 | EP-11 provider: ad, entra | ad gssapi graph psx | custody|
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

One Go module sits at the repository root; its module path is `github.com/skenzeriq/activediq` (set by old T-0014, which also built the skeleton of this map; see [ci-gates](../standards/ci-gates.md)). Go's `internal/`
rule allows any package in the module to import `internal/…`, and nothing outside it can
([Go 1.4 internal packages](https://go.dev/doc/go1.4#internalpackages)). The layering in §2 is
therefore ours to enforce. The compiler does not do it for us.

| Path | What lives there | Tier (ADR-0001) | Owner |
| --- | --- | --- | --- |
| `cmd/<role>/` | One `main` package per process kind: `server`, `connector`, `edge`, `radius`, `fpolicy`, `t0-connector`, `agent`. Each one is about 20 lines: load config, call **its own** role package `internal/compose/<role>`, run. Every `main` (except `auditverify`) makes `platform/prochardening.Apply(os.Getenv)` its first statement and exits 2 on error: RLIMIT_CORE 0, PR_SET_DUMPABLE 0, refuse GOTRACEBACK=crash (TM-TB16-T6); `prochardening/fitness_test.go` enforces it for every `package main` under `cmd/...`. One `main` package is not a role: `cmd/auditverify`, the offline audit verifier `adq-audit-verify` (§9), which links only `platform/audit/canon`, `platform/audit/chain` and the standard library (ADR-0005 rule 11; ADR-0003 amendment) | S, A | backend-engineer |
| `internal/compose/` | **The composition root** (with `cmd/`). Nothing else imports any package under it (ADR-0002 P1). It has three kinds of package: <ul><li>`profile`: the manifest types and the three manifests (`windows`, `linux-oci`, `saas`) as **data only**. It imports no implementation package (§3.2).</li><li>`config`: the config loader, the only reader of environment variables.</li><li>one **role package** per binary: `server`, `connector`, `edge`, `agent`; later `radius`, `fpolicy`, `t0connector`. Each wires its own role's adapters and imports only what its binary may link (§2 rule 7). `server` and `agent` hold the **generated** module list for their tier. Role packages never import each other.</li></ul> | S, A | backend-engineer (shape: solution-architect) |
| `internal/platform/` | **The extractable platform root** (ADR-0002, "The boundary with UEM"). It is the kernel, and it imports no directory-domain or module package. The root package declares `platform.Deps` (§4.1) | S, A | backend-engineer (per package, §5) |
| `internal/directory/` | **The directory domain.** It holds the safe primitives P1–P3, the object model, the inventory (sync store), the sync ingester, the connection registry and the connector-contract client. The root package declares `directory.Services` (§4.1) | S, A | directory-engineer |
| `internal/connector/` | **The connector root.** It is the only place that imports directory protocol and Graph libraries, and the only place that unseals directory credentials (ADR-0002 rule 3) | S | directory-engineer |
| `internal/modules/<id>/` | Server feature modules, one directory each (§5.4), each with a page `architecture/modules/<id>.md` ([template](modules/README.md)) | S | per module |
| `internal/agentmodules/<id>/` | Agent modules `addc` and `fileserver` [M3]. `mgmthelper` exists only if the M3 GPO spec chooses it (§13) | A | windows-engineer |
| `internal/proto/` | Generated Go code for `proto/`. Never hand-edited | S, A | api-engineer |
| `internal/platform/apihost/` and the `api` packages | `apihost` (EP-2 host, router, middleware chain, the one body decode path) with `apihost/apitypes` (hand-written scalars and `Opt`, generated shared types and problem constructors) and `apihost/spec` (the bundle). Each tag's generated types, decoders, validators, `Handlers` interface and `Bind` live in its owner's `api` package: `internal/modules/<id>/api/`, `internal/platform/<pkg>/api/`. Files `*.gen.go`, never hand-edited ([ADR-0004](../decisions/0004-public-api-contract-openapi-first.md) rule 4) | S | api-engineer; each `api` package: its owner |
| `internal/platform/limiter/` | `limiter` (implements `apihost.Limiter`, threat model §7.8 / TM-D22): per-IP token buckets keyed by network prefix (IPv4 /32, IPv6 /64, configurable; unparseable and overflow buckets), per-principal buckets through the `PrincipalStore` port. Ships `MemoryStore` (one node only) and `PGStore` (T-0274: table `platform_rate_buckets`, DM-07, one atomic upsert on the database clock; key = class, tenant, principal). A store error refuses the request; `RequireShared` and `ACTIVEDIQ_NODES` / `ACTIVEDIQ_PRINCIPAL_STORE` make the server refuse to start with the memory store on more than one node. Mounted in the server ports as `Ports.Limits` (T-0277; Authn/Authz/StepUp stay fail-closed until the auth kernel) | S | backend-engineer |
| `internal/platform/egress/` | `egress` (threat model §5.9 TM-TB9-T1 / TM-F-EGRESS): the one outbound HTTP client. Resolve once, refuse loopback, link-local, private, CGNAT, multicast, reserved and cloud-metadata addresses unless the operator allow-lists the range (metadata is never allow-listable), dial the vetted IP literal (no rebinding), vet every redirect hop (https to http refused, cross-origin hops drop request headers), verified TLS 1.2+ with no skip option, no proxy, no NTLM. FF-SP2 rule `outbound-http` flags `net/http` clients/transports and raw dialers elsewhere; `internal/connector/graph` is a named temporary exemption until it migrates | S | backend-engineer |
| `internal/platform/webhook/` | `webhook` (threat model §5.9 TM-TB9-T9): Standard Webhooks signing and delivery. `Signer` (HMAC-SHA256 over `id.timestamp.body`, several secrets during rotation), `Verify` (5-minute replay window both directions, constant-time compare; also the reference for receivers and tests), `Sender.Send` is the only delivery path: it requires a Signer, signs every attempt and sends through `egress.Client` only. `Secret` never prints | S | api-engineer |
| `internal/platform/updateverify/` | `updateverify` (ENH-07, spec `enh-07-signed-update-protocol.md` §3, TM-D12 rules 1-4 and 7; T-0645): the one update verifier, stdlib only. `Verifier.Verify(Input)` is the only entry point for every courier and every consumer (server, connector, agent), each with its own pinned root. Chain root (old threshold and new) -> timestamp -> snapshot -> targets -> artefact; Ed25519 over the exact `signed` bytes; metadata size limits; artefact streamed into a `Quarantine` outside the data path with signed length (aborts at length+1) and SHA-256 checked, optional `PlatformCheck` (Authenticode/OCI) before the path is returned; nothing is extracted. `FloorStore` port holds rollback/freeze memory (metadata versions, newest signing time, committed product version); `Dual` = database half + host half (`FileFloor`), Load takes the maximum and heals the lower half. Refusals are `*Refusal` with the closed `Reason` enum tamper, rollback, freeze, revoked_key, unsigned_by_root, withdrawn (the `update.refused` audit reasons). Test `TestAC8NoSecondVerifier` fails on a second verifier in the tree. The Postgres half is the sibling package `updateverify/floorpg` (T-0653; keeps this package stdlib only): `Store` over the single-row registered-global table `update_verifier_floor` (migration 0054), raised by GREATEST in one upsert, with a guard trigger that refuses any lowering (even by the owner) and no DELETE/TRUNCATE for the runtime role. Out of scope: couriers, apply (T-0553), signing pipeline (T-0140/T-0141) | S | backend-engineer |
| `internal/webui/` | `go:embed` package for the built web assets. Embed patterns cannot use `..` ([embed](https://pkg.go.dev/embed)), so the build copies `web/dist` here. Only `compose/server` imports it | S | frontend-engineer |
| `proto/` | Protobuf sources: `skenzeriq/agent/v1` (shared host contract, old T-0040), `activediq/connector/v1`, `activediq/<agent-module>/v1` | — | api-engineer; contracts: solution-architect |
| `api/openapi/` | The public API contract and its only source of truth ([ADR-0004](../decisions/0004-public-api-contract-openapi-first.md) rule 1): `openapi.yaml` (root), `shared/*.yaml` (components used by more than one tag), `modules/<id>.yaml` (one per module that serves API, tag = module ID), `platform/<pkg>.yaml` (one per kernel package that serves API, tag `platform.<pkg>`), `policy.yaml` (the contract's security policy, rule 9) and `.vacuum.yaml`. `tools/gen/api` bundles it into `internal/platform/apihost/spec/openapi.gen.json` (committed, embedded, served as `getApiDocument`), the one input of every generator and check ([api-pipeline.md](api-pipeline.md)) | — | api-engineer; `modules/<id>.yaml` and `platform/<pkg>.yaml`: their owner; `policy.yaml`: security-architect |
| `migrations/` | One forward-only SQL sequence, `NNNN_<owner>_<what>.sql`, plus `embed.go`. `<owner>` is an **owner key**: the directory name of exactly one top-level package under `internal/platform`, `internal/directory`, `internal/connector` or `internal/modules` (ADR-0003 rule 6, §2 rule 6). The first migration is **`0001_tenant_tenants.sql`**: it creates `tenants` (ADR-0002 rule 4), owned by `internal/platform/tenant` | S | backend-engineer |
| `web/` | The React + TypeScript console: `src/app` (shell), `src/modules/<id>` (screens), `src/ds` (design system, old T-0043), `src/api` (only `schema.gen.d.ts` from openapi-typescript and the hand-written `client.ts` over openapi-fetch; nothing else in `web/src` calls the network, ADR-0004 rule 12), `e2e/` (Playwright, run from `web/` with its own pinned copy; `src/app/shell.tsx` first asks `GET /auth/csrf` whether a session exists (none: `/sign-in?next=<requested path>`, `src/app/sign-in.tsx`: break-glass password, then TOTP code or a security key via WebAuthn challenge/verify, `src/app/session.ts`), then matches `location.pathname` to a registered route (`collectContributions` in `src/app/modules.ts` returns routes, palette entries and search-result renderers; start-up throws on a duplicate or a palette entry naming an unregistered route; ESLint enforces rule 8 for `src/app`, `src/ds` and between modules, by resolving each import (`eslint/module-boundary.js`, tested for nested folders and `../../modules/<other>`); T-1099) and the first screen is `src/modules/directory` at `/directory/users?q=`, its search text kept in the URL; **`src/modules/reports` (T-0966)** at `/reports` (library, `?q=&category=`) and `/reports/<id>` (a report opens and runs with no Generate step; `/` searches names, ManageEngine names and categories; the view state is in the URL), reached through prefix routes (`/*`, `matchRoute`) and `src/app/location.ts` (`navigate`, `useLocation`)) | W | frontend-engineer; `src/ds`: component-designer |
| `native/` | A Rust workspace: `passfilt` (LSASS), `credprov` (LogonUI) and `shared` (`Secret`, policy evaluator, corpus runner) [M4] | N | windows-engineer |
| `sidecars/<name>/` | .NET 10 + PowerShell 7.6 typed adapters. The names reserved are `pshost` (shared host), `exchange` and `gpmc`. Each is declared in the stack manifest when it is first built | X | windows-engineer (host); backend-engineer (`psx` client) |
| `packaging/` | `windows/` (MSI, toolchain per old T-0039) and `linux-oci/` (Dockerfiles, Compose; ADR-0002 E-3). No script custom actions in the MSI | — | devops-engineer |
| `testdata/safe-primitives/` | The primitive corpus, one `<unit>.jsonl` per unit (safe-primitives §8). Read by the Go and Rust implementations | — | directory-engineer (corpus), test-engineer |
| `tools/` | `fitness/<job>/` (CI jobs), `analyzers/` (go/analysis passes `dnstring`, `sqlconst`, `secretjson`, `tmplconst`, `constdisp`, `odataname`, `graphurl`, `nestedtx`, and `policy/`, the table of primitive homes; `fitness/safeprim/` runs them, old T-0033), `vettool/`, `gen/` (code generators; `gen/api` is the in-house OpenAPI generator, ADR-0004 rule 4), `apitools/` (its own `go.mod` pinning vacuum and oasdiff, kept out of the product module), `playwright/` (screenshot, record and E2E runner; Node, dev-time only, old T-0011) | L | devops-engineer |
| `lab/` | The Samba AD lab, seed data, Windows lab automation (old T-0012) | L | devops-engineer, test-engineer |
| `third_party/<name>/` | Copied third-party code, each with its LICENSE file (ADR-0001 rule 5) | — | devops-engineer |
| `garage/<name>/` | Prototypes with an owner and an expiry date. Never imported | — | its owner |

### 1.1 Paths this blueprint fixes

The earlier documents named these paths provisionally. They are now final, and old T-0048 updated the
skills and the safe-primitives spec to match.

| Provisional (where) | Final |
| --- | --- |
| Zone roots `web/ native/ sidecars/ lab/ tools/ third_party/` (ADR-0001 rule 1) | **Kept.** ADR-0001 allows TypeScript only under `web/`, so Playwright suites move to `web/e2e/`. The `windows/` root in the engineering-standards skill becomes `native/` (tier N) plus `internal/agentmodules/` (tier A) |
| `tools/fitness/stack/` + `manifest.json` (ADR-0001) | **Kept.** Likewise `tools/fitness/tenancy/` and `tools/fitness/profiles/` (ADR-0002). Added: `tools/fitness/modules/` (ADR-0003, old T-0141) |
| Composition root "`cmd/<role>/` + a compose package" (ADR-0002 rule 1) | `cmd/<role>/` + `internal/compose/`, split by role: `internal/compose/<role>/` (one wiring package per binary; `server` and `agent` also hold `modules.gen.go`), `internal/compose/profile/{windows,linuxoci,saas}.go` (manifest data, no implementation imports) and `internal/compose/config/` (the loader) |
| Platform root "`internal/platform/`" (ADR-0002) | **Kept**, with the package list in §5.1 |
| Connector root (ADR-0002 rule 3) | `internal/connector/` |
| Data-access package `store` (ADR-0002; safe-primitives P5) | `internal/platform/store`. Its entry points are **`WithTenantTx`** (the ADR-0002 name; the safe-primitives spec's `WithTenant` is renamed) and `WithPlatform`. Exemption registry: `internal/platform/store/exempt`. Report compiler: `internal/platform/store/reportsql`. Install preflight (ADR-0011 rule 4, T-1128): `internal/platform/store/preflight` — a read-only check on the migration role's connection that refuses to migrate when `pg_trgm` is unavailable or not creatable, or the database is not UTF8, and warns on a C/POSIX ctype; every migration applier calls it first (`storetest.Apply` does; the product's migration runner must, see T-1316) |
| `ldapfilter`, `dn`, `attr` (safe-primitives P1–P3) | `internal/directory/ldapfilter`, `internal/directory/dn` (incl. `ObjectRef`, `GUIDRef`), and `internal/directory/attr/{guid,sid,filetime,gentime,flags,unicodepwd}`, plus the decode-only `userParameters` decoder `internal/directory/attr/tsprops` (**planned**, T-1566; safe-primitives §5.7, connector-contract §5.9; one importer, §7.4); P6 `internal/directory/sd` (read half: decoder, SD_FLAGS control, `Grants`) |
| `odata` (safe-primitives P8, [safe-primitives-odata.md](safe-primitives-odata.md)) | `internal/directory/odata`, with `graphschema` (Graph property declarations) and `odatatest` (strict parser: round-trip oracle and the fake Graph's request parser) beneath it |
| `Secret` (P3 §5.6) | `internal/platform/secret`. The platform needs it for key material and MFA seeds; the corpus unit stays `attr.unicodepwd` |
| `scope` and `SecureConn` (P1 §3.6, P3 §5.6) | **Amended by T-0993 to match the tree.** Raw search, the closed general-search control set (`ad.CheckControls`), scoped search and GC resolution: `internal/connector/ad` (`search.go`, `scoped.go`, `gc.go`). The escape-control named-operation table (LF-30, ASQ, show-deleted, phantom root): `internal/connector/ad/scope`, **planned**, created by the first named operation that sets one (ADM-038 `RestoreDeleted`); `tools/analyzers/policy.Scope` already confines the escape OIDs to it. `SecureConn`: `internal/directory/attr/unicodepwd` (built; it proves TLS state through a `Link` interface and imports no LDAP library). The planned `internal/connector/ldap` package is withdrawn: the AD session layer is `connector/ad`. safe-primitives.md follows in T-1007 |
| `psx` / `pslit` / `proc` (P4) | `psx` client: `internal/connector/psx` (the connector drives sidecars, ADR-0002 rule 3). `pslit`: `internal/platform/pslit`. `proc`: `internal/platform/proc` |
| Corpus root `testdata/safe-primitives/` (P §8) | **Kept** |
| Exemption registry `internal/platform/tenancy/exempt.go` (adr skill) | `internal/platform/store/exempt` |

---

## 2. Layers and import rules: core never imports modules

This section restates [ADR-0003](../decisions/0003-module-system-extension-points-only-on-ramp.md)
(ratified 2026-10-02) and keeps the rule numbers other documents cite ("§2 rule 7"). The ADR
numbers its own rules differently, so each rule below names its ADR rule. If the two disagree, the
ADR wins and this section is the bug. `fitness-modules` M1–M12 enforce the rules (old T-0141, lost in renumbering; T-0991 landed M7, T-0990 owns
the rest). Until they land, the job in `tools/fitness/modules/` enforces a subset (rules 1–5, 7, 8 and M7), and code review the rest.

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
          +------> directory primitives: ldapfilter dn odata model attr/*  (kernel ¹, primitives, protos)
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
| **directory primitives** | `internal/directory/{ldapfilter,dn,odata,model}` and everything under `internal/directory/attr/` |
| **directory services** | every other package under `internal/directory/` (`inventory`, `sync`, `client`, `connection`, …) |
| **connector** | `internal/connector` and everything under it |
| **server module** | `internal/modules/<id>` and everything under it. The doc-only root `internal/modules` imports nothing and is imported by nothing |
| **agent module** | `internal/agentmodules/<id>` and everything under it. The doc-only root `internal/agentmodules` imports nothing and is imported by nothing |
| **role package** | `internal/compose/<role>` (`server`, `connector`, `edge`, `agent`; later `radius`, `fpolicy`, `t0connector`) |
| **`compose/config`**, **`compose/profile`** | the config loader and the manifest data |
| **`webui`** | `internal/webui` (the `go:embed` package for the built console) |
| **`migrations`** | the repository-root `migrations` package (`embed.go`) |
| **proto: skenzeriq** / **proto: activediq** | generated code under `internal/proto/skenzeriq/` and `internal/proto/activediq/` |
| **`cmd/auditverify`** | the offline audit verifier's `main` package (ADR-0005 rule 11). It is a tool for auditors, not a role, and runs on Windows, Linux and macOS with no install |
| **`cmd/<role>`** | each other `main` package |
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
| `cmd/auditverify` | — | `platform/audit/canon`, `platform/audit/chain` only | — | — | — | — | — | — | — | — | — | — | — | — |
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
   - `internal/compose/connector`, for the remote role and local credentials (T-0665: `connector.Run`
     serves one composite ConnectorServer on the dial-out tunnel, with no listener; the tunnel client
     is the contract-agnostic `internal/platform/fleet/tunnelclient` over `fleet.Frame`, also used by
     `compose/agent`, and the `activediq.fleet.v1` binding (frame conversion, the `Tunnel` stream and
     call) is the one shared package `internal/compose/tunnelbind`, handed in as `Config.Open`; T-0946);
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
   - **The ownership map** `internal/platform/store/owners/owners.gen.tsv` (table → owner key and
     write class) is generated from the migrations by `tools/gen/modules` (`make gen-modules`; `gen-modules-check` in `make ci`, T-0997). Cross-owner data migrations need an entry
     with a reason, a ticket and an expiry in `tools/fitness/modules/exempt.json`.
   - **Every table has a write class** (ADR-0005 rule 10; ADR-0003 amendment). `config` means the
     product makes a *widening decision* to it: a principal chooses a value that can, by itself,
     widen what anyone may do, see or keep, from any surface (request, Action, anonymous route, job,
     fleet listener or CLI). Those writes are Actions, except a closed set of no-Step widening writes
     (bootstrap and host CLI, the takeover attestation callback, the end-user enrolment page).
     `system` means bookkeeping written by its owner: values read or derived, narrowing-only or
     releasing-only writes, and an account's own first factor inside its sign-in (the closed list in
     ADR-0005 rule 10, T-1221). The class is declared
     beside the migration that creates the table, one line per table: `-- write-class: <table>
     config|system`. A partition takes its parent's class. `tools/gen/modules` copies it into the
     ownership map.
   - **The O3 rule: a `step.Step` at the package boundary** (ADR-0005 rule 10, T-1221). Each SQL
     write to a `config` table must have a guarded root. The root can be an exported function
     that takes a `step.Step` and writes only in `Step.Tx()`, or an unexported helper called
     directly, and only, from guarded functions of its own package (the `settings.Store.Set` →
     `set(tx)` shape). Otherwise it must be a `system` row of
     `tools/fitness/operation/o3-writers.json`, whose named `callers` are the only functions
     allowed to reference it. Existing violations are `convert` rows naming their conversion
     ticket (T-1228 to T-1232, T-1246), and O3 prints them as pending. O3 also fails a table with no
     class.
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
   | `cmd/auditverify` | any package of this module except `platform/audit/canon` and `platform/audit/chain`; any third-party module | an auditor runs it on their own machine; it must be small enough to read and must trust nothing in the product (ADR-0005 rule 11). Also checked for `GOOS=darwin` |

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
   through the generated client `web/src/api` (ADR-0004 rule 12).

**The other homes of a feature are closed** (ADR-0003 rule 5), so the Registrar stays the only
on-ramp:
- `cmd/<role>` imports only its own role package, `compose/config` and the standard library.
  `cmd/auditverify` imports only `platform/audit/canon`, `platform/audit/chain` and the standard
  library.
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

**sqlc and the driver boundary (a precision for old T-0033 and old T-0036).** With `sql_package: "pgx/v5"`,
sqlc's generated code imports pgx and uses pgx types directly
([sqlc: using Go and pgx](https://docs.sqlc.dev/en/latest/guides/using-go-and-pgx.html)). So the
"SQL driver only in the data-access package" rule (FF-SP1) means two things.
`pgxpool` and `pgx.Connect`/`ConnConfig` appear only in `internal/platform/store`. Other pgx
packages appear only in `store` and in **generated** `sqlcdb/` packages, where every file carries
sqlc's generated-code header. Hand-written code outside `store` never imports pgx. This is
consistent with ADR-0002 T5, which bans pool and connection types.

### 2.3 The kernel import DAG (ADR-0005 rule 13)

Inside the kernel, rule 1 allows any import Go's cycle rule permits. The write path needs more: the
write APIs of `authz`, `authn`, `notify`, `audit` and `personal` take a step token, and `operation`
calls all of them, which is an import cycle unless the types are placed with care. ADR-0005 rule 13
places them in a `dag` block, and **`fitness-operation` O9 parses that block from the ADR** and
fails any import among the listed packages that it does not allow. The copy below is for reading;
if it differs from the ADR, the ADR wins. Imports of the standard library and of kernel packages
the block does not list (`keys`, `blob`, `telemetry`, `secret`, `capability`) stay under rule 1.

```
# package          -> kernel packages it may import (among those listed in this block)
audit/canon        -> (none)
audit/chain        -> audit/canon
tenant             -> (none)
authority          -> tenant
store              -> tenant
operation/step     -> authority, store, tenant
jobs               -> store, tenant
personal           -> audit/canon, authority, operation/step, store, tenant
notify             -> authority, jobs, operation/step, store, tenant
audit              -> audit/canon, audit/chain, authority, jobs, notify, operation/step, personal, store, tenant
authz              -> audit, authority, operation/step, store, tenant
authn              -> audit, authority, jobs, notify, operation/step, store, tenant
operation          -> audit, audit/canon, authn, authority, authz, jobs, notify, operation/step, personal, store, tenant
module             -> authz, operation
authz/actions      -> authz, operation, (anything operation may import)
authn/actions      -> authn, operation, (anything operation may import)
authn/throttlejob  -> authn, jobs, store, tenant
notify/actions     -> notify, operation, (anything operation may import)
audit/actions      -> audit, operation, (anything operation may import)
personal/actions   -> personal, operation, (anything operation may import)
personal/erasure   -> personal, operation, (anything operation may import)
```

Read it bottom-up:
- **Leaves.** `audit/canon` and `audit/chain` use the standard library only, so `cmd/auditverify`
  links nothing else. `authority` holds the identity and facts types (`Principal`, `Chain`,
  `TargetRef`, `Pins`, `FactsQuery`, `Facts`). `operation/step` holds the token every write API
  takes; importing it does not import `operation`.
- **`store` imports no audit code.** The chain runs as audit's commit hook (§9).
- **`personal` sits below `audit`**, which carries its references, exports its values and purges
  them. Code that needs both lives above them, in `personal/actions` and `personal/erasure`.
- **`operation` is on top.** Inside the kernel only `module` and the `<pkg>/actions` subpackages
  import it. A kernel package never exports its own Actions; they live in `<pkg>/actions`, and
  `compose/server` hands their `All()` to the operation host (ADR-0003 rule 5, as for
  `inventory.Datasets()`).
- **Outside the kernel**, `directory/client` imports `operation/step` and `authority` (a
  directory → kernel import, which rule 1 allows) and implements `operation.LiveFacts`
  structurally, without importing `operation` (§7.5).

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
| AD read/write, sync | sspi adapter | krb5 adapter | on-site connector | Same contract. old T-0023 (CBT) gates the krb5 path |
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
| EP-2 | **API handlers** for one OpenAPI tag | `platform/apihost` | each module | — | first endpoint (ADR-0004 rule 5) |
| EP-3 | **Action** (plan, apply, verify, inverse) for every write a principal makes, to a directory or to our configuration (§4.2) | `platform/operation` | `objects`, `helpdesk`, `m365`, `lifecycle`, `delegation`, `hardening`, `connections`, `workflow`, `reports`; kernel Actions from `authz`, `authn`, `notify`, `audit`, `personal` (`<pkg>/actions`) | GPO, file-server ACLs | first write (ADR-0005, old T-0153) |
| EP-4 | **Approval gate** (§8) | `platform/operation` | `platform` default (permission-only, plus the kernel single approval), `workflow` | ITSM-driven approval | first write (ADR-0005 rule 8) |
| EP-5 | **Job kind** (tenant-carrying) | `platform/jobs` | operation runner, sync, notifications; module schedules and timers (`reports`, `lifecycle`, `workflow`, `itsm`, `migration`) | — | first job |
| EP-6 | **Permission + scope evaluator** | `platform/authz` | every module declares permissions; `delegation` registers one `ScopeEvaluator` per directory root kind, from which `rbac.ReadScopes` builds the `authz.ReadScope` (§11) | UEM device scopes | first endpoint |
| EP-7 | **Audit event kind** | `platform/audit` | every Action and auth event | — | first write |
| EP-8 | **Report dataset** | `platform/report` | `directory/inventory` (`inventory.Datasets()`: users, computers, groups, group members, OUs, contacts), `platform/audit`. Per-DC values are not a dataset: they are read live through the port `report.PerDCReader` (§10) | DC events [M3] | first report |
| EP-9 | **Notification sink** | `platform/notify` | email, SMS gateway, SIEM (syslog/CEF/HTTP) | webhooks, Teams/Slack [M3] | first notification |
| EP-10 | **Authentication method** (enroll, verify) | `platform/authn` | password + TOTP, WebAuthn, email/SMS OTP (ENH-09), SAML/OIDC SP | push [M4], RADIUS | first sign-in |
| EP-11 | **Directory provider**: the per-binding adapter every connector handler reaches a directory through (core: identity and the guard's live facts; optional facets per contract group; capabilities derived from the facets). Write kinds are rows of `write`'s operation table, not provider methods (§4.3) | `connector/provider` (extraction T-1005; until it merges the guard's port is `write.Provider`, an acknowledged bypass) | `ad`, `entra` | generic LDAP, Google | the second provider on any handler (T-0993: missed for the first; T-0615, T-0929 depend on T-1005) |
| EP-12 | **Platform adapters** (key provider, secret source, blob, service host, update courier, Kerberos) | `platform/keys`, `platform/blob`, …; Kerberos: `connector/ad/gssapi` (krb5 built; `sspi` planned as a `GOOS=windows` file there, T-0993) | per manifest (§3.3) | HSM | M1 skeleton |
| EP-13 | **Agent module** (`skenzeriq.agent.v1`) | `platform/agent` | `addc`, `fileserver` | `mgmthelper` (only if the M3 GPO spec chooses it, §13), UEM modules | first agent feature (old T-0040) |
| EP-14 | **Event source** and **detection rule** | `platform/events` [M3] | `addc`, `fileserver` | WEF, FPolicy | first M3 audit feature |
| EP-15 | **Web screen module** | `web/src/app` | `objects`, `helpdesk` | — | first screen |

Inside a module, variants share one shape and differ only by parameters:
- object classes (user, group, computer, contact, OU) are **data** in `objects`;
- ITSM systems are one adapter shape in `itsm`;
- migration sources are one importer shape in `migration`;
- report definitions are **data** (ASTs), never code.

### 4.1 Module contract (server)

This restates [ADR-0003](../decisions/0003-module-system-extension-points-only-on-ramp.md) rule 4
(EP-1). `internal/platform/module` is built to this shape (old T-0144): the concrete `Registrar`,
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
func (r *Registrar) API(h apihost.TagHandlers) error        // EP-2 (shape: ADR-0004 rule 5; the argument is the module's own generated api.Bind(…))
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
    non-default `ApprovalGate` (how it routes operations: ADR-0005 rule 8, §8);
  - **closed after boot:** `Register` runs once, and a Registrar used after `Boot` returns gives
    `ErrClosed`, so a module that stashes `r` gains nothing;
  - **capabilities:** a module whose `Requires()` is unmet is not constructed into the
    contributions; no other code asks which profile is running (ADR-0002 P1);
  - **dataset tables:** a `Dataset` names only tables its module owns, per
    `store/owners/owners.gen.tsv` (§2 rule 6). The same check runs on datasets that kernel and
    directory packages export (`inventory.Datasets()`), with the exporter's owner key, when
    `compose/server` hands them to `report`. The `compose/server` boot test runs `Boot` over every
    generated module, so CI sees a violation first;
  - **ID match:** a module whose `ID()` differs from the ID the generated list recorded fails;
  - **Actions** (ADR-0005 rule 1): an Action whose ID is not namespaced by its owner, whose
    `AuditKind` is not registered by the same owner, or whose `Permission` is not in the EP-6
    catalogue fails. The same check runs on the kernel's own Actions (`<pkg>/actions.All()`),
    which `compose/server` hands to the operation host.
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
(EP-13, `skenzeriq.agent.v1`) and its dependency struct are old T-0040's; ADR-0003 binds the generated
list, one fixed constructor signature, no lifecycle outside the contract and no module-to-module
imports. Web modules: §2 rule 8.

### 4.2 Action contract: one shape for every write (ENH-04)

This restates [ADR-0005](../decisions/0005-operation-pipeline-and-audit-trail.md) rules 1, 2, 9
and 10 (EP-3). If the two disagree, the ADR wins.

```go
// internal/platform/operation
type Action interface {
    Describe() Descriptor
    // Plan is the dry run: live reads, the diff, preconditions, reversibility. It cannot write:
    // PlanContext has no write method and its database transaction is READ ONLY.
    Plan(ctx context.Context, pc PlanContext, in Input) ([]StepPlan, error)
    // Apply performs one planned step. The step.Step is the only key to a write.
    Apply(ctx context.Context, s step.Step, p StepPlan) (Outcome, error)
    // Verify compares the read-back with the plan's after-state.
    Verify(ctx context.Context, s step.Step, p StepPlan, o Outcome) (Verdict, error)
    // Inverse returns the input that undoes this step, or ErrIrreversible with a reason.
    Inverse(p StepPlan, o Outcome) (Input, error)
}

type Descriptor struct {
    ID            ActionID          // "<owner>.<noun>.<verb>", stable and never reused
    Version       int               // bumped when Plan/Apply semantics change; recorded on every step
    Permission    authz.Permission  // checked at Plan and again at Apply
    Input         SchemaRef         // the OpenAPI component: API, workflow, automation, palette
    Target        TargetKind        // Directory(ad | entra) or Store
    Reversibility Reversibility     // worst case: Reversible | Lossy | Irreversible
    AuditKind     audit.Kind        // the step event kind (EP-7), declared by the same owner
    StepUp        bool              // submit needs a fresh MFA (TM-D16)
    SecretInput   bool              // the input carries a secret.Secret
}
```

- **One shape for every write a principal makes.** The same Action serves a single edit, a
  50,000-row CSV, a workflow step, an automation policy, act-on-report-results, the command
  palette, undo, and **every change to activeDIQ's own configuration** (connections, channels,
  accounts, roles, scopes, templates, definitions, schedules, retention, sinks, tenant settings,
  erasure requests). Configuration Actions have `Target: Store` and run inline in the request when
  the gate allows. **System bookkeeping is not an Action** (sign-in and sessions, bootstrap,
  enrollment handshakes, sync and inventory, job and operation bookkeeping, runs and deliveries,
  audit events and checkpoints, key rotation); ADR-0005 rule 10 keeps the closed list, and adding
  to it is an amendment.
- **Typed, not untyped.** `operation.Define[In, P, Out](...)` turns typed functions into an
  `Action`. `Input`, `StepPlan.Payload` and `Outcome` encode in `adq-canon/1` (§9), because the
  plan hash and the audit record cover them.
- **`StepPlan`** holds the target (`connection_id` + `objectGUID`, or a planned parent GUID and
  RDN for a create), the diff (attribute: before → after), the preconditions Apply enforces, the
  DC pins (§8), the step's own reversibility class with a reason, and the item's **phase** (phase
  n+1 starts only after phase n is terminal, e.g. "create OU" before "create users in it").
- **Reversibility.** `Reversible` restores the before-state exactly; `Lossy` restores declared
  fields only and the plan names what is lost; `Irreversible` has no inverse (a password set, an
  Entra hard delete, a sent message). The Descriptor states the worst case and Plan the class per
  step. **The preview, the gate and the API response show `Lossy` and `Irreversible` steps before
  anything runs.**
- **The plan hash** is SHA-256 over the canonical form of the Action IDs and versions and every
  item's target, diff, preconditions, phase and reversibility, with a flag per secret input. It
  never covers a secret value, the DC pins or `plan_valid_until`. Approvals bind to it.
  `plan_valid_until` defaults to 1 hour for directory Actions and 24 hours for `Store` Actions; an
  expired plan is re-planned, and an unchanged hash keeps its approvals.
- **Transient secrets.** A secret input (a typed password, a CSV password column) is stored only
  sealed in `operation_secret` (TM-D7 seal, associated data includes the step key), with its own
  TTL of at most 72 hours, deleted in the step's recording transaction and at every terminal state.
  It never appears in a plan, diff, event, export, inverse input or log.
- **Registration.** Modules call `Registrar.Action(a)` (§4.1). Kernel Actions live in
  `internal/platform/<pkg>/actions` and directory Actions in their package's export, handed to the
  operation host by `compose/server` (§2.3). `operation.Catalogue()` is the read-only list of
  registered Descriptors that `search` shows in the palette.

**The step token: the only key to a write.**

```go
// internal/platform/operation/step: a leaf below every write API (§2.3).
type Step struct{ s *state }                              // minted only by the operation runner; zero value refused
func (s Step) Key() Key                                   // (operation, item, step)
func (s Step) Attempt() int                               // the fencing number (§8)
func (s Step) Operation() OperationID
func (s Step) Actor() authority.Chain                     // the initiator chain, never the approver's authority
func (s Step) DC(nc authority.NamingContextID) DCRef      // the pin; none for Entra
func (s Step) Tx() store.Tx                               // Store Actions only: the recording transaction
func (s Step) FactsQuery() authority.FactsQuery           // what the Apply-time re-check reads live
func (s Step) Recheck(ctx context.Context, f authority.Facts) (Clearance, error)
```

- **Every write API takes a `Step`.** `directory/client`'s write methods (`client.Write(ctx, s,
  op)`) and the exported write functions of every `config`-class table (§2 rule 6) take one. A
  directory write outside an Action therefore does not compile.
- **A Step opens only the planned write.** It carries a digest of the planned target and operation
  (secret values excluded, their presence included). `client.Write` recomputes the digest of the
  operation it is handed and refuses a mismatch, and the connector checks it again.
- **The pipeline, not Action code, re-checks authorisation.** `client.Write` reads the facts
  `FactsQuery()` names on the pins, calls `Recheck`, and sends only with the returned `Clearance`,
  which is bound to the step's key and plan digest and dies with the Step. The connector-contract
  write RPC is reachable only through a function that takes a `Clearance`. For `Store` Actions
  the runner re-checks inside the transaction (§8).
- **One minter.** `step.TakeMinter()` returns the minter once; `operation` takes it at package
  initialisation, and the `compose/server` boot test asserts that it did.
- **A Step cannot escape.** It is never stored in a field, global, map, slice or channel, never
  captured by a closure, and never passed to a function without a `Step` parameter (O1). The
  runner revokes it when Apply or Verify returns, so a smuggled copy is dead.
- **Named secret reads** (LAPS, BitLocker) are reads with their own audit kind and take no Step. A
  LAPS *reset* is a write, so it is an Action.

### 4.3 EP-11: the directory provider (decided in T-0993)

**What happened.** EP-11 was drawn as `connector/provider`: "`Describe() Capabilities` plus the typed
operations `service` dispatches to", to be built before the first directory call. It was not built.
The first features were built beside it instead. Each connector handler declared its own port over
the one `ad.Session`: the Tier-0 guard's `write.Provider` (with `ADProvider`, `EntraProvider` and
`SessionDC`), `read.Source`/`read.ADSource`, and `rights.ADDirectory`. The two composition roots
(`compose/connector/backend.go` and `compose/server/labbootstrap_lab.go`) each wire the handlers by
hand. This is the PatchIQ pattern (postmortem §5–§6): one shape per consumer, and assembly cloned per
binary.

**Options considered.**
- **(1) Amend: EP-11's home is `connector/write.Provider`. Rejected.** That interface is the guard's
  port (`Kind`, `Identity`, `Classify`, `Anchors`, `PropertyGuard`). It is not a directory provider.
  If it were declared EP-11, `read`, `rights` and every future handler would import `write` to reach
  a directory (`read` already does). The guard package would become everyone's dependency, and the
  other two per-handler ports would remain.
- **(2) Extract `connector/provider` exactly as first drawn, with typed operations on the provider.
  Rejected in part.** Typed write bodies cannot live in a provider. TM-F-T0GUARD (enforced by
  `write/fitness_test.go`) puts every directory write call in `write/ops`, behind an `Authorised`
  token that only the guard mints. Write operations on `provider/ad` would either break that rule or
  need a second guard.
- **(3) Extract `connector/provider` with an amended shape. Chosen.** The provider is the
  per-binding *adapter*. Policy stays where it is: the Tier-0 classifiers in `tier0`, the rights
  checks in `rights` and the guard in `write`. The transport-neutral protocol logic stays in the
  handlers.

**The contract (`internal/connector/provider`, built by T-1005).**
- **Core, which every provider implements:** `Kind()`, `Identity()`, and the guard's live facts
  `Classify`, `Anchors` and `PropertyGuard`. These are the methods of today's `write.Provider`,
  moved here with their value types (`Verdict`, `Anchors`, `PropertyGuard`, `PinStore`) and their
  fail-closed errors. Every Read header and every write passes the guard, so a provider without the
  core cannot serve anything.
- **Facets, one interface per contract group, all declared in `provider`:** `DCBound` (`BoundDC`;
  a directory with DCs implements it, and the handlers pin on it), `ObjectReader` (Read and
  ScopedSearch), `RightsSource` (what `VerifyConnection` reads). Later groups add their facet here:
  `ChangeFeed`, `NamedSecrets`, `UserVerifier`. A handler asserts the facet it needs at
  construction. A missing facet means the group answers `CAPABILITY_UNSUPPORTED`; it never causes a
  nil dereference.
- **Capabilities are derived, never declared.** `provider.Supports(p)` builds the provider's
  Describe rows from the facets it implements. The write group's rows come from `write`'s operation
  table. No other code constructs an `OperationSupport` (M13d). A provider therefore cannot claim
  a group it does not implement.
- **Behaviour differs by facet, not by kind.** Handlers never branch on `ProviderKind`. Today's
  `isAD` branches in `write/handler.go` become `DCBound` checks (M13c).
- **Write kinds are rows, keyed by `(ProviderKind, WriteKind)`,** in `write`'s operation table, with
  bodies only in `write/ops`. A provider variant gains a write kind by adding rows there, through
  the guard, and by nothing else.
- **Policy keeps its per-kind halves.** `tier0` (C1–C19, E1–E5) and `rights` (V1–V9, EV1–EV5)
  hold the AD and Entra rules as security policy, which security-architect owns. A provider wires
  live reads into them and holds no policy of its own.
- **Variants:** `provider/ad` (over one `*ad.Session`: the core, `DCBound`, `ObjectReader` and
  `RightsSource` are all built from the same session, so the rule 5 / Read-pin same-DC invariant is
  enforced by the single constructor) and `provider/entra` (over `graph`). Only the composition
  roots import a variant (M13a).
- **One assembly:** `connector/service.New(p, deps)` builds the handlers over `p` and returns the
  one composite `ConnectorServer`. `compose/connector` (remote) and `compose/server` (embedded) both
  call it with different parameters. Neither assembles the handlers itself.

**Matrix: contract group × provider** (asymmetry is stated, not accidental; §3.4):

| Group | `ad` | `entra` | Note |
| --- | --- | --- | --- |
| Guard core (Classify, Anchors, PropertyGuard) | built (`write.ADProvider`) | built (`write.EntraProvider`, not yet mounted) | moves to `provider/*` in T-1005 |
| `DCBound` (pin, rule 5) | built (`write.SessionDC`) | never: Entra has no DC (§8, per-provider verify window) | — |
| `ObjectReader` (Read, ScopedSearch) | built (`read.ADSource`) | planned; its spec fixes a provider-neutral entry type first (the facet returns `*ad.Entry` until then) | — |
| `RightsSource` (VerifyConnection) | built (`rights.ADDirectory`) | rules built (`rights.VerifyEntra`), not mounted: T-0615 (depends on T-1005) | — |
| Write kinds | none registered yet (`operations` is empty) | none | each kind has its own spec ticket |
| Describe | not served yet | not served yet | derived via `provider.Supports`; conformance CC-DESC in T-0929 (depends on T-1005) |

**Fitness (M13 in `fitness-modules`, T-1006):** (a) only `internal/compose/**`,
`connector/conformance` and tests import `provider/<variant>`; (b) no interface outside `provider`
declares the core pair `Kind() ProviderKind` + `Identity() *DirectoryIdentity`; (c) no
`ProviderKind` comparison in `read`, `write`, `rights` or `service` (keys of the write operation
table are allowed); (d) `OperationSupport` is constructed only in `provider` and `write`. Until T-1005
merges, M13 prints `pending` and lists today's violations. `pending` is not a pass.

**Consequences.** The interim shape (`write.Provider`) stays on main until T-1005. No new handler,
provider variant or Entra group may be added before then: T-0615 and T-0929 depend on T-1005. The
withdrawn planned packages are `ldap` (its content is `connector/ad`; StartTLS is refused by
design) and `kerberos` (`connector/ad/gssapi` holds the GSSAPI client; `sspi` will be a
`GOOS=windows` file there). §5.3 lists only built and still-planned packages.

---

## 5. Component catalogue

Every component has an owner, an interface and its extension points (EP numbers refer to §4).
The catalogue is **closed** (ADR-0003 rule 5, M7): every top-level package under
`internal/platform/`, `internal/directory/` and `internal/connector/` has **exactly one** row in its
own section (§5.1, §5.2 or §5.3 respectively), and a new one needs a blueprint change reviewed by
solution-architect. **Matching rule (M7, T-0915):** a row's names are the backticked tokens in its
first column once parenthesised text is removed; a name containing `/` (`store/reportsql`,
`fleet/dial`, `attr/*`) is a subpackage row and does not count; a `(+sub)` mention does not count;
a name with no directory yet is a planned package and is allowed. Test support that must live under
a product root (only `labadmin` today) still gets a row, marked as such, with the check that keeps it
out of shipping binaries. `fitness-modules` enforces M7 (T-0991, `tools/fitness/modules/catalogue.go`): a missing, duplicated or wrong-section row fails `make fitness`, naming the package and the section it needs. When a ticket adds a server or agent module, it also writes
`architecture/modules/<id>.md` from the [module page template](modules/README.md). M3 fails a
module without a page and a page without a module. Table ownership follows §2 rule 6; the findings
that placed each table are in §5.6.

### 5.1 Platform kernel (`internal/platform/`, extractable)

The root package `internal/platform` declares `platform.Deps` (§4.1). Only server modules and
`compose/server` import it.

| Package | Owner | Interface (what others call) | EPs |
| --- | --- | --- | --- |
| `tenant` | backend-engineer | `tenant.ID`, which only authn, the job wrapper, registered platform paths and tests may mint (ADR-0002 rule 5) | — |
| `authority` | backend-engineer; security-architect reviews `Facts` | **Leaf types for authorisation** (ADR-0005 rule 13): `Principal`, `Chain` (the initiator chain: requester, automation policy, API token), `TargetRef`, `NamingContextID`, `Pins`, `FactsQuery`, `Facts` (existence and kind, GUID ancestry, membership per asked group and AU as `member`, `not_member` or `unknown`, `isManagementRestricted`, correlation state and the correlated AD object's ancestry, the Tier-0 flag). No behaviour; imports only `tenant`. The step token and the `operation.LiveFacts` port expose these types, and `authz` evaluates them | — |
| `store` (+`exempt`, `owners`, `sqlcdb` conventions) | backend-engineer | `WithTenantTx(ctx, tenant.ID, fn)`, `WithPlatform(ctx, reason, fn)`, `LikePattern`, per-transaction `statement_timeout`; the raw pool is unexported. Two neutral mechanisms for the audit chain (ADR-0005 rule 11), with no audit code and no SQL naming an audit table: a **per-transaction slot** (`store.NewSlot[T]()`, keyed by a value only its creator holds) and **one `BeforeCommit` hook**, set once by `compose/server` when it opens the store (a second set panics). `WithTenantTx` runs the body, then the hook, then `COMMIT`; it refuses nested calls and transaction-control SQL (`COMMIT`, `ROLLBACK`, `SAVEPOINT`) inside a body. `store/owners` is the generated, data-only table → owner key + write class map (`owners.gen.tsv`, embedded; data not Go source so the key-table scans of ADR-0007 P8 and FF-KEY-2 need no exemption, T-1155; §2 rule 6) that `module.Boot` and the fitness jobs read; it imports nothing | — |
| `store/reportsql` | reporting-engineer (security-architect reviews every change, P5 rule 3) | **The only producer of dynamic SQL** ([modules/reports.md §5](modules/reports.md)). `NewRegistry(opt reportsql.Options, ds ...report.Dataset) (*Registry, error)` pre-quotes every registered dataset once (T-0957: `Options{Schema, SecretKey}`); `(*Registry).Dataset(id report.DatasetID) (Dataset, bool)`. `Compile(q report.Query, ds reportsql.Dataset, scope authz.ReadScope, in reportsql.Inputs) (reportsql.Query, error)` renders the AST, the read scope and the admin's narrowing; `CompileCount` has the same signature and yields `SELECT count(*)` over the same `FROM` and `WHERE`. `reportsql.Query` holds the `CompiledSQL` text and bound arguments in unexported fields, and only this package can build one (RP1). `Exec(ctx, tx store.Tx, q reportsql.Query, batch int, fn func(ctx, []report.Row) error) (int64, error)` runs it as one server-side cursor in the caller's transaction. The only package besides `authz` that reads `ReadScope.Terms`/`.Token` (RP2); inside `modules/reports`, only `reports/run` calls `Compile`, `CompileCount` or `Exec` (RP3). **Planned (ADR-0011, T-1095):** `CompileSearch(src SearchSource, q SearchQuery, scope authz.ReadScope) (Query, error)`, the universal-search statement over the inventory-registered `SearchSource`, with its scope position filled by the same `planScope`/`scopeSQL`; called only from `internal/directory/inventory` (SE1) | consumes EP-8; renders the EP-6 `authz.ReadScope` |
| `export` (+`export/cellsafe`, `export/csv`, `export/xlsx`, `export/pdf`, `export/pdf/pdftest`) | reporting-engineer (security-architect reviews every change, P7) | Typed `Cell`/`Column`/`Source`; `Run` and `RunToBlob` stream a `Source` through an `Encoder` into the blob store with a row cap and a `RenderReport`. `cellsafe.Classify` is the only formula-lead decision; `csv.NewWriter`/`NewReader` (TAB-neutralised, reversible), `xlsx.NewWriter` (`archive/zip`, inline strings, `quotePrefix`, no formula/link API). `pdf.NewWriter` is a hand-built streaming PDF writer (standard Helvetica, hex strings only, no action, link, annotation, attachment or form API; T-0964); its independent oracle is `pdf/pdftest` (test support). The HTML export is `htmlx.Writer` (own row below) | consumes EP-12 (`blob`) |
| `corpus` (+`corpustest`) | devops-engineer | The safe-primitives corpus loader and report types; test kit `corpus/corpustest` (`Run`, `Seed`, `ConstantArgv`) that every primitive's tests call (FF-SP4/5/8, safe-primitives §8). Stdlib only | — |
| `tablekind` | devops-engineer (kinds and rules: solution-architect) | `tablekind.Declare(Table{Name, Entity, Kind, AppendOnly})`: every table owner declares each of its tables beside its owner code, and `fitness-domain-keys` (domain-model X3–X5; T-0050) reads the declarations from source and checks the migrated schema against them. A leaf with no state that any kernel or domain package may import | — |
| `module` | backend-engineer | `Module`, the concrete `Registrar`, `Boot`, `Entry`, `Contributions`, `ErrClosed` (§4.1); test kit `module/moduletest` (`Register(m)`) | hosts EP-1 |
| `capability` | backend-engineer (IDs: solution-architect) | `capability.ID` constants and `Set.Enabled(id)`. It is a leaf package with no behaviour. Manifests list IDs (`compose/profile`), modules return them from `Requires()` (§4.1), and role packages filter modules by them | supports EP-1 |
| `apihost` | api-engineer | HTTP server, auth middleware, strict JSON, problem types, rate limits, static UI mount | hosts EP-2 |
| `apitls` | api-engineer; security-architect reviews | The API listener's TLS identity (TM-TB1-T2, TM-F-HOST; T-0065): a per-install self-signed certificate generated on first boot and kept owner-only in the API TLS directory (in memory only for loopback development and tests), with its SHA-256 fingerprint exposed for first-connect pinning. No plaintext fallback. Only `compose/server` calls it | supports EP-2 |
| `health` (+`health/api`) | api-engineer | The anonymous probes `/health/live` and `/health/ready` (AN-1, tag `platform.health`; T-0034, T-0316): body `{"status":"ok"}` or a problem with no detail; each check timeout-bounded, one probe round at a time, result reused for a short TTL, reasons to the server log only. Mounted by `compose/server` (`health.go`: readiness = `store.DB.Ping`; served at `/api/v1/health/*`, T-0994); the root `/healthz` and `/readyz` non-API routes are not served yet | implements EP-2 |
| `httpx` (+`httpx/authnhttp`, `httpx/negotiatehttp`, `httpx/ssohttp`) | backend-engineer; security-architect reviews | HTTP response primitives that must not be hand-built: `Attachment`, `Headers` and `PartHeaders` (the header of one MIME part of an outgoing message, used by `notify/mail`; the part's base name is cut to `MaxPartEncodedBase` encoded octets so no header line exceeds 998 octets, O7/EM-12, T-1173) are the only setters of `Content-Disposition` (safe-primitives P7; FF-SP2 `content-disposition-literal`; T-0046). The subpackages are `authn`'s HTTP bindings (ADR-0004 A6): `authnhttp` (`__Host-` cookies, CSRF), `negotiatehttp` (AN-9, RFC 4559), `ssohttp` (AN-3) | — |
| `htmlx` | reporting-engineer (security-architect reviews every change, P7) | The HTML export (T-0964; safe-primitives §12.5): `htmlx.Writer` is an `export.Encoder` that streams a static page from embedded `html/template` files — a CSP meta first (`default-src 'none'`, the one `<style>` pinned by hash; `StyleSHA256()` feeds `httpx.WithStyleSHA256` for the download header), no script, URL, link or form, every value in `<bdi>` with HTML escaping, text cells typed as text for Excel, control characters shown as `⟨U+XXXX⟩`. Its policy "home" is the `html` safe-primitive unit; the unit's corpus also runs `httpx.Attachment` records | — |
| `limiter` | backend-engineer | Implements `apihost.Limiter` (TM §7.8, TM-D22; T-0054, T-0274): per-IP buckets keyed by network prefix in node memory, per-principal buckets through the `PrincipalStore` port (`MemoryStore`, one node; `PGStore` over `platform_rate_buckets`, migration 0011). Refuses to start with the memory store on more than one node. Detail in §1 | implements the `apihost.Limiter` port of EP-2's host |
| `setup` (+`setup/api`) | backend-engineer; security-architect reviews | The one-time first-run setup secret (TM-TB16-T7, AN-4; T-0636): a 256-bit secret in an owner-only file in a 0700 subdirectory of the API TLS directory, claimed exactly once by atomic rename and never reissued; route under tag `platform.setup`, plus the `setup show` CLI. Self-hosted single node only: multi-node and SaaS tenants are provisioned by the control plane and have no first-run claim | implements EP-2 |
| `opsmetrics` | backend-engineer; security-architect reviews | The operator `/metrics` endpoint (T-0533). Its series name every tenant, so it is served only on the separate ops listener and accepts only that listener's operator bearer token; no tenant authenticator reaches it | — |
| `egress` (+`egress/oidchttp`) | backend-engineer; security-architect reviews | The one outbound HTTP client (TM §5.9 TM-TB9-T1, TM-F-EGRESS; T-0160): resolve, vet, pin; private and metadata ranges refused unless allow-listed (metadata never); redirect policy; verified TLS 1.2+; no proxy, no NTLM. FF-SP2 `outbound-http` flags every other client. `oidchttp` adapts it to the `net/http`-free seam of `authn/sso/oidc`. Detail in §1 | — |
| `webhook` | api-engineer | Standard Webhooks signing, verification and delivery (TM-TB9-T9): `Signer` (several secrets during rotation), `Verify`, and `Sender.Send`, the only delivery path, which signs every attempt and sends through `egress` only. Detail in §1 | serves EP-9's webhook sink [M3] |
| `authn` (+`authn/actions`, `authn/throttlejob`) | backend-engineer; security-architect reviews | sessions, API tokens (ADM-141), SAML/OIDC SP (libraries per SSO-D2, `console-sso.md` §3.1: OIDC verifies with `go-jose/v4` directly, go-oidc unused; SAML on `russellhaering/goxmldsig` ≥ v1.6.0 with `beevik/etree` and `mattermost/xml-roundtrip-validator`, gosaml2 not imported; parsing fenced to `sso/oidc` and `sso/saml` by FIT-SSO-1), MFA (ADM-142), mTLS principals. Owns DM-30 Account, DM-31 Session, DM-32 ApiToken, DM-37 AuthenticatorEnrollment. **Session store (T-0194, `internal/platform/authn`):** table `authn_sessions` (DM-31, tenant table with RLS); the token is `<tenant>.<256-bit secret>` and only its SHA-256 is stored; idle and absolute expiry from a per-tenant `Policy` validated against platform `Bounds`; concurrent limit with `EvictOldestCreated` or `EvictLeastRecentlyUsed`, serialised per account by an advisory lock; `RevokeAccount(reason)` ends all of an account's sessions for every node. **Lifecycle wiring (T-0363):** `Config.Audit` is required (Store refuses to build without it); `Revoke`/`RevokeAccount` take the acting chain; `RevokeAccountTx` and the tx-coupled `OnAccountDisabled`/`OnRoleChanged`/`OnPasswordReset`/`OnMFAReset` revoke inside the caller's tenant transaction (commit/rollback together) with the reason matching the event; every create, eviction (`concurrent_limit`), expiry and revoke emits an `authn.session.*` audit event in the same tx (actor, account, handle, reason; never token or hash); an owner-role `Purger` (`store.OpenMaintenance`) deletes ended rows past retention (min 24h, default 90d), never active ones, and emits `authn.sessions.purged`. Callers of the `On*` methods and the scheduled Purger job are T-0403. No HTTP (cookie/CSRF are the next ticket). Account changes an administrator makes are Actions (`authn.account.*` in `authn/actions`) through write functions that take a `step.Step`; sign-in, sessions and first-sign-in enrolment are bookkeeping (ADR-0005 rule 10). Declares the **read port `authn.DirectoryAnchors`** (`Resolve`, `Matched`; §7.5, ADR-0003 F6), implemented by `directory/inventory`, through which DM-30.I5 binds SSO accounts and checks `matched` correlations. Declares `authn.DirectoryRef`, which `authz` reuses. **DM-30 account store (T-0400):** table `authn_accounts` (tenant table, RLS forced; kind `local`/`sso`/`directory`); `directory_ref` = `connection_id` + objectGUID, never a DN; SSO accounts carry issuer+subject and the `oid`(+`tid`)/`onprem_sid` anchor columns; CHECKs tie kind to the ref/SSO/anchor fields; the `Accounts` store offers `Create`, `Get`, `LookupSSO`, `Bind` (bind-once, never rebinds) and `SetState`; a guard trigger refuses rewriting identity or binding, treats `deleted` as final, and the runtime role has no DELETE; `NewAccounts(db, sessions, owners)` (the `OwnerSource` port is required; `rbac.Owners` implements it); `SetState(…, by authority.Chain)` to `disabled`/`deleted` calls `Store.OnAccountDisabled` in the same tx, and `Bind(…, by)` and `SetState` append `authn.account.bound` / `authn.account.state_changed` (actor chain, account, anchor kind, connection+GUID, from/to) in the same tx, so a revoke or audit failure rolls the change back (DM-31.I2; sock-puppet rule c); audited admin rebind (I5) is a follow-up. **Last tenant-owner (DM-30.I4, T-0405):** `SetState` of an active account to `disabled`/`deleted` first calls `OwnerSource.TenantOwners`, which (in `rbac`, the owner of the authz tables) takes the per-tenant advisory xact lock `authz.tenant-owner:<tenant>` and returns holders of the built-in `tenant-owner` role through a live assignment; if the target is the only holder that is an active account, nothing changes, the tx commits only an `authn.account.state_refused` event (outcome `denied`, reason `last_tenant_owner`) and `SetState` returns `ErrLastOwner`. Concurrent removals serialise on that lock (exactly one wins). Any future owner-assignment revoke must call `TenantOwners` first to take the same lock. **Session epoch (T-0429):** `authn_accounts.session_epoch` (migration 0020) is bumped under the row's exclusive lock by `RevokeAccountTx` for password reset, MFA reset and role change; a sign-in reads `Store.Epoch`/`EpochTx` BEFORE verifying a credential and passes it in `CreateInput.Epoch` (or `BeginInput.Epoch`, stored as `authn_pending_signins.account_epoch`), and `createTx` re-checks it FOR SHARE on the same row, refusing with `ErrCredentialsChanged`; a missing epoch is `ErrInvalid` (fail closed). `Rotate` revokes the old session and mints the new one in one tx under that lock. **AN-10 refusals and pending purge (T-0418):** `SecondFactor.VerifyTOTP(ctx, h, code, from)` takes the attempt's source address and `SecondFactor.Audit` (required); every refusal of a live pending sign-in appends `authn.secondfactor.refused` (outcome `denied`; reasons `wrong_code`, `code_replayed`, `factor_paused`, `account_disabled`, `no_totp_enrolment`, `credentials_changed`, `factor_refused_policy`) in its own committed tx after the attempt's tx rolls back, and the call that ends a pending sign-in (`pending_expired`, `attempts_exhausted`) appends it in the same tx as the `dead` marking; details are account, attempt, first factor, first-factor IP and source IP, never the code or handle. **Passkey lock (P1, T-0852):** before any code is evaluated, `VerifyTOTP` takes the account row FOR SHARE and refuses with `factor_refused_policy` (same `ErrSecondFactorRefused`, uniform 401) when the account has an active `second_factor` WebAuthn credential; no TOTP step is spent and no enrolment budget charged, the attempt is still charged to the pending sign-in; `insertCredential` takes the row FOR UPDATE for `second_factor`, so an activation and a TOTP sign-in serialise (FP-T8). P2-P4 and the rest are T-0784. Unknown or already-ended handles are not audited (no account to name; flood control). `Purger.PurgePending` deletes ended pending rows (and active rows expired) past retention on the owner role and emits `authn.pending.purged`; scheduling is T-0403. **Pending begun (T-0439):** `NewPendingStore(db, sink, clock)` requires an audit sink (bound to db); `PendingStore.Begin` appends `authn.pending.begun` (account, first factor, client IP; never handle or hash) in the same tx as the row insert, so an audit failure leaves no pending row and a first-factor-passed, MFA-abandoned sign-in stays visible after `PurgePending`. **TOTP failure budget (T-0361, DM-37):** `authn_totp_failures` (one row per refused code, RLS) and `paused_until`, `expires_at`, `confirm_attempts` on the enrolment; every attempt is charged before the code is evaluated, in a separate committed transaction on a dedicated small pool through `store.WithTenantSeparate` (the only module allowed to; ADR-0005 amendment 2026-10-26), so a caller that rolls back cannot erase it and parallel guesses cannot exceed the budget; triggers in migration 0015 make the pause, the counters and the failure rows tamper-resistant for the app role **Step-up (T-0199, TM §7.4):** `authn.StepUp` implements `apihost.StepUpChecker`: `Fresh` is true only for a `KindSession` principal (`Principal.SessionID`) whose active session's `mfa_at` is inside the tenant's window (`StepUpWindows`, default 5 min, bounds 1–15 min, out of bounds is an error, never clamped); API tokens are never fresh. `Reverify(token, totp)` verifies a console-MFA enrolment only, moves `mfa_at` to now on success, and on refusal clears `authority_factor_at` (DM-31.I3) in a committed tx with an `authn.stepup.failed` event (budget per T-0361). Which operations need it is not decided in authn: it is `operation.Descriptor.StepUp` plus the policy `stepUp` list; `Test_stepup_flag_catalogue_matches_table` (compose/server) pins the §7.4 table to the catalogue. Not wired yet: compose still injects `denyStepUp` until the authn Authenticator lands **Authority factor (T-0283, TM-D19 rules 1-2):** migration `0048`; `authn.AuthorityFactors` (`Approve`, `BeginEnrol`/`FinishEnrol`, `Reset`/`Remove`, `BeginVerify`/`Verify`). Enrolment needs exactly one anchor outside Entra: a connector `ADProver.VerifyUser` proof (port; nil refuses, fail closed) or a single-use tenant-owner approval given with step-up; reset/remove are tenant-owner-with-step-up only (`OwnerSource`, direct assignments, so no Entra-derived role qualifies); every change is audited (`authn.authority.*`) and queues notices to the account and all owners. `Session.AuthorityCurrent` (`authority_factor_at >= mfa_at`) flows `authnhttp` → `apihost.Principal.AuthorityFactor` → ctx (`authority.WithAuthorityFactor`) → `rbac.Authorizer` → `authz.Principal.AuthorityFactor`; `hybridCheck` refuses correlation-derived assignments without it (`authority_factor_missing`), Entra-side and direct grants unaffected. HTTP routes, notice delivery, the connector `VerifyUser` and the async operation runner carrying the fact are follow-ups. **Session CSRF value (T-0854):** `Principal.CSRF` = `CSRFValue(session token)` is set by the `authnhttp` Authenticator, read only by `authn.Handlers.GetCSRFToken`, and redacted by `Principal`'s `String`/`GoString`/`LogValue`; `authn.CSRFHeader` is the single header-name constant `authnhttp` aliases. | **SSO routes (T-0203):** migration `0046` `authn_sso_transactions`; `authn/sso/signin` (Start/Callback core, `TxStore`), `httpx/ssohttp`, `NonAPIResult.Handoff`; see console-sso.md 7.3 | hosts EP-10 |
| `authz` (+`authz/actions`) | backend-engineer; security-architect reviews the membership port | `Authorize(principal, permission, target) Decision`, evaluated for the **initiator chain** over live `authority.Facts` at Plan and again at Apply (ADR-0005 rule 7); `FactsQuery(chain, permission, connection)` names every include and exclude root that could decide a target, plus the Tier-0 facts; roles = sets of permissions; assignments = principal × role × scope. Role and assignment changes are Actions (`authz.*` in `authz/actions`) through write functions that take a `step.Step`. **Owns DM-34 Role and DM-36 RoleAssignment** (ADR-0003 F2); `delegation` changes them through `authz`'s Go API inside its Actions. `scope_id` and automation-policy subjects are opaque typed references, resolved through the registered `ScopeEvaluator`. Declares the **read port `authz.Membership`** (`GroupsOf`, `Matched`; §7.5, F6), implemented by `directory/inventory`, for DM-36.I2 group subjects | hosts EP-6 |
| `rbac` | backend-engineer; security-architect reviews | RBAC persistence and the operation `Authorizer` over `authz.Evaluator` ([modules/rbac.md](modules/rbac.md)): roles, assignments and their roots (DM-34 to DM-36; root kinds `naming_context`, `ou_subtree`, `ou_one_level` (T-0881), `entra_tenant`, `tier0_scope`, `tenant`), `BuiltInRoles()`. **The only producer of directory read scopes:** `ReadScopes.For(ctx, tx store.Tx, t tenant.ID, chain authority.Chain, perm authz.Permission) (authz.ReadScope, error)` (T-0882). It builds one grant per assignment from the EP-6 `ScopeEvaluator`s that `delegation` registers, plus the token layer (§11; [modules/reports.md §4](modules/reports.md)). Besides `authz`, it is the only caller of `authz.NewReadScope` (RP2) | consumes EP-6 |
| `operation` (+`operation/step`) | backend-engineer; security-architect reviews `operation/step` and the approval rules | The pipeline (ADR-0005, §4.2, §8): `Action`, `Descriptor`, `StepPlan`, `PlanContext`, `Outcome`, `Verdict`, `Define`, `Gate`, `Approvals`; `Plan`, `Submit`, `Approve`, `Undo`; the runner, the kernel holds and the single approval; the transition function (`transitions.go`, the only writer of a state column); the job kinds `operation.plan`, `.apply`, `.verify`, `.reconcile`, `.sweep`. **`Catalogue()`**: the read-only list of registered Descriptors, which `search` uses for the palette (ADR-0003 F4). Declares the **port `operation.LiveFacts`** (§7.5), implemented by `directory/client`. `operation/step` is the leaf every write API takes: `Step`, `Key`, `OperationID`, `Clearance`, `DCRef`, the plan-digest function (defined in the leaf `operation/digest`, which imports only `authority` so the connector binary can recompute a digest without linking `store`; `step` re-exports it) and the single minter (§4.2). Owns DM-41 Operation, DM-42 OperationItem and `operation_secret`; test kit `operation/operationtest` (`Contract`, `Check`, `FakeDirectory`, the coverage record `build/operationtest/contract-coverage.jsonl`; T-1222): drives an Action through the real `Runner` against a fake directory and a rolled-back store and checks O7's Plan-read-only, idempotent-Apply and Verify-after-drop clauses (the inverse, `Lossy` and audit-event clauses follow) | hosts EP-3, EP-4 |
| `jobs` | backend-engineer | tenant-carrying job wrapper, leases for singleton work, schedules, transactional insert (a job enqueued in the caller's transaction). A kind runs inside one wrapper transaction (the default) or declares **`ManagedTx`** and receives a tenant-bound `TenantTx` runner, opening its own short transactions (ADR-0002 Jobs row as amended by ADR-0005 rule 6; old T-0084). **Owns the job table `jobs`**: our own `SKIP LOCKED` queue, global and registered, reached only through `store` (ADR-0002 Jobs row, amended 2026-10-02; §8 Job queue) | hosts EP-5 |
| `audit` (+`audit/canon`, `audit/chain`, `audit/actions`) | backend-engineer; security-architect reviews | `Kind`, the event envelope, `Append(tx, kind, event)` (into audit's per-transaction slot), `Chainer.BeforeCommit` (the commit hook `compose/server` installs on `store`), `InitTenant` (the genesis head row and first checkpoint key, run by tenant provisioning), signed checkpoints, export, forwarding to EP-9 sinks, retention purges (§9; ADR-0005 rule 11). **Owns `audit_head`, `audit_event`, `audit_checkpoint` and `audit_checkpoint_key` (migration 0007), and all the chain SQL.** `audit.NewChainer(db)` installs the hook and returns the `Sink`; `NewCheckpointer(chainer, KeySource, anchors...)` signs, rotates and anchors; `NewExporter` builds `adq-audit-export/1` bundles (T-0132). `audit/canon` is `adq-canon/1` and `audit/chain` is chain and checkpoint verification, both standard-library only and linked by `cmd/auditverify`. Retention and SIEM-sink changes are Actions in `audit/actions` | hosts EP-7; implements EP-8 |
| `report` | reporting-engineer | EP-8 host, pure types with no SQL driver (FF-SP1; [modules/reports.md §2–§3](modules/reports.md)): `Dataset`, `Column`, `Fragment`, `Definition`, `Query` (the AST a run executes), `Resolve`, `Cell`, `SortKey`, `Narrowing`, `Freshness`, `Label`, `Host` (`report.NewHost`, which takes `inventory.Datasets()` under the owner key `inventory` and the datasets modules register through `Registrar.Dataset`), and the port **`PerDCReader`**, implemented over the connector's `ReadPerDC` (modules/reports.md §6.5). The run record, stored rows and run API belong to `modules/reports` (ADR-0010), not here | hosts EP-8 |
| `notify` (+`notify/actions`) | backend-engineer | `Send(template, recipients)`, delivery records, alerts, egress-proxy setting (ADM-205). Appends no audit event itself: channel and SMTP changes are Actions (`notify.channel.*` in `notify/actions`), which the runner audits | hosts EP-9 |
| `personal` (+`personal/actions`, `personal/erasure`) | backend-engineer; security-architect reviews | **Erasable personal values** (ADR-0005 rule 12): `PersonalRef` (subject reference, `value_id`, field, salted HMAC-SHA-256 commitment), `Put`, `Resolve`, `Erase`, `PurgeValues`, and the **erasure register** outside the database (in `blob`), which the restore runbook replays. Owns `personal_subject` (the per-subject salt), `personal_hold` (legal holds, independent of the salt row; `SetHold`/`ReleaseHold`/`LockHolds` serialise with the retention purge on a tenant advisory lock, T-0587) and `personal_value`. Every append-only record (DM-80 events, DM-18 change records, DM-66 comments) stores `PersonalRef`s through this API. `personal/actions` holds `personal.subject.erase`; `personal/erasure` runs the purge- and account-deletion triggers. Both sit above `audit` and `operation` (§2.3) | — |
| `keys` | backend-engineer; security-architect reviews | KEK from the key-provider adapter, tenant data keys, `Seal`/`Unseal[T]`, key shredding on tenant delete | EP-12 |
| `secret` | directory-engineer (P3) | the `Secret` type: redacted, not serialisable, v2-only `UnmarshalJSONFrom` (`secret/secretjson` is the decode entry). The corpus unit `attr.unicodepwd` has one implementation, `go/attr-unicodepwd` (`attr/unicodepwd`: encode-only codec, `SecureConn`; covers `secret`), which runs every record including the decode-path `PW-J*` ones | — |
| `blob` | backend-engineer | `Store`: `Put`/`Get`/`Delete`/`Sweep` (expiry); every call takes a `tenant.ID` and a tenant-relative, validated key, and the adapter derives the tenant prefix, so a caller never names a path. Adapters: `fs` (old T-0090: `<root>/<tenant>/<hh>/<sha256(key)>.blob` through `os.Root`, one self-describing file per blob), `s3` (client library `[OPEN]`) | EP-12 |
| `proc`, `pslit` | backend-engineer (P4) | constant-argv process runner; display-only PowerShell rendering | — |
| `fleet` | backend-engineer | the gRPC mTLS gateway for connectors and agents (server side): enrollment (the first registered platform path), certificate SAN → tenant + component, endpoint lists. It is **contract-agnostic**. For each enrolled component it exposes a tunnel over the component-initiated connection, which implements [`grpc.ClientConnInterface`](https://pkg.go.dev/google.golang.org/grpc#ClientConnInterface) for server-initiated calls, and a [`grpc.ServiceRegistrar`](https://pkg.go.dev/google.golang.org/grpc#ServiceRegistrar) for calls the component makes. Product contracts bind to the tunnel from outside the platform root: `directory/client` binds the generated `activediq.connector.v1` client, and the server module that owns an agent module's contract binds `activediq.<module>.v1`. The platform root therefore never imports `internal/proto/activediq/…` (§2 rule 1, ADR-0002 U2) | hosts transport for EP-11 (remote) and EP-13 |
| `fleet/dial` | backend-engineer | the component side, linked by `cmd/connector` and `cmd/agent`: enrollment client, mTLS dial-out, and serving the reverse tunnel. No `store` (§2 rule 7) | — |
| `agentpolicy` (+`agentpolicy/signer`, `agentpolicy/rotation`) | backend-engineer; security-architect reviews | The ADR-0007 trust format (T-0556): canonical signed encodings, `AddcPolicy` with the bounds of agent-host-addc-contract §3 enforced on decode, and the agent-side `Verifier` (P1–P7) that the agent module links instead of a copy. The root is pure. `signer` is the only code that opens the sealed policy key (P8) and owns DM-86 to DM-88; `rotation` is the daily keyset job. Detail in [modules/agentfleet.md](modules/agentfleet.md); migration owner key: T-0992 | serves EP-13; `rotation` implements EP-5 |
| `agentingest` | backend-engineer; security-architect reviews | Stores the `AppendEvents` batches of agent modules (agent-host contract §2 S1, TM-D24; T-0556): tenant, component and kind come from the verified client certificate (`fleet.IdentityFrom`) and `Batch` has no field for them; idempotent on `agent_seq` for identical content only (`ErrSeqDivergence` otherwise). Owns DM-89 `agent_event`, append-only; migration owner key: T-0992 | serves EP-13 |
| `agent` | windows-engineer | the skenzeriq agent host inside `cmd/agent`: lifecycle, outbox, update, health (old T-0040) | hosts EP-13 |
| `update` | backend-engineer; devops-engineer owns the release pipeline | fetch → verify (one verifier) → stage → apply → health check → rollback; couriers `online`/`offline`. The server's migration step is injected by `compose/server`, so `update` imports no `store` and links into `cmd/connector` and `cmd/agent` (§2 rule 7) | EP-12 |
| `updateverify` (+`updateverify/floorpg`) | backend-engineer; security-architect reviews | The one ENH-07 update verifier (T-0645, T-0653): `Verifier.Verify(Input)` for every courier and consumer, each with its pinned root; signed chain, quarantine, rollback and freeze floor (`FloorStore`, `Dual`). Stdlib only, so it links into server, connector and agent; `floorpg` owns `update_verifier_floor` (migration 0054). `TestAC8NoSecondVerifier` fails on a second verifier. Detail in §1 | serves EP-12 (update courier) |
| `prochardening` | backend-engineer; security-architect reviews | `Apply(getenv)`: RLIMIT_CORE 0, PR_SET_DUMPABLE 0, refuse `GOTRACEBACK=crash` (TM-TB16-T6; T-0644). The first statement of every `cmd/*` main except `auditverify`; `prochardening/fitness_test.go` enforces it (§1) | — |
| `ownerfile` | directory-engineer; windows-engineer owns the Windows half; security-architect reviews | Creates and repairs files only the service identity may read or write (connector contract §8.3a; T-0242). POSIX: 0600, owned by the effective uid. Windows: an explicit protected DACL (process user SID and SYSTEM) built with the typed security-descriptor API, never SDDL. A file owned by anyone else is refused, never corrected. Also `Dir` (T-1315): a verified, held state directory (parent trust, no-follow, handle-relative `ReadFile`/`WriteFile`) used by `fleet/dial`. Used by `connector/rights`, `connector/write` and `fleet/dial` | — |
| `telemetry` | backend-engineer | `slog` JSON with tenant ID, metrics; no mandatory egress (P6) | — |
| `events` [M3] | backend-engineer (pipeline); directory-engineer (sources) | `Source` (decodes a batch from an agent module, and later from WEF or FPolicy, into normalised events), `Rule` (match → alert through `notify`), and writes to partitioned event tables if old T-0026 passes ADR-0001 rule 3 | hosts EP-14; implements EP-8 (DC events) |

### 5.2 Directory domain (`internal/directory/`)

The root package `internal/directory` declares `directory.Services` (§4.1): `inventory`'s read
API, the `client`, and the `connection` registry with its credential port. Only server modules and
`compose/server` import it. Inside the services the import order is `sync` → `inventory` →
`connection` and `client` → `connection` (ADR-0003 F1).

| Package | Owner | Interface | EPs |
| --- | --- | --- | --- |
| `ldapfilter`, `dn`, `attr` (+`attr/*`) | directory-engineer | the safe primitives P1–P3 (safe-primitives §3–§5) | — |
| `sd` | directory-engineer; security-architect reviews | Safe primitive P6 ([safe-primitives-security-descriptor.md](safe-primitives-security-descriptor.md); T-0149): a strict decoder for self-relative MS-DTYP security descriptors (`Decode` is the only reader of `Raw`), the `SD_FLAGS` control, and the three-valued `Grants` helper; the write half `PlanDACL`/`PlanInheritance` yields a `DACLWrite` only they can fill (DACL-only). No SDDL parser and no constructor from a string; corpus units `sd.read`, `sd.write` | — |
| `gplink` | directory-engineer (semantics: ad-expert) | The DM-23.I1 codec for `gPLink` (T-0093): strict parse of `[LDAP://<GPO DN>;<options>]` entries (GPO named by its `cn={GUID}` RDN; disabled and enforced flags; stored order kept). A value that does not parse is an error and callers treat it as Tier-0 (contract §8.1 C9). Shared by `connector/tier0` and the write path's Plan/Apply step 7 so links are read one way | — |
| `odata` (+ `graphschema`, `odatatest`) | directory-engineer | safe primitive P8: filter AST, query options, key/path renderer (safe-primitives-odata §2–§3) | — |
| `model` | directory-engineer (semantics: ad-expert, old T-0006) | `Connection` (AD forest, Entra tenant), `NamingContext`, `Object{GUID, class, parent GUID, DN-for-display}`, `ObjectRef`, link types | — |
| `inventory` | directory-engineer | current state, link graph, GUID ancestry, per-DC values, AD↔Entra correlation, change history (§12). Read API for modules. Owns DM-14 NamingContext, DM-15 DomainController, DM-16 DirectoryObject, DM-17 Link, DM-18 ChangeRecord, DM-20 Correlation, DM-23 GpLink. Reads the connection's deletion settings, takeover attestation and confirmed HybridLinks through `connection`'s API. **Implements the kernel read ports** `authz.Membership` and `authn.DirectoryAnchors` directly (§7.5, F6). Exposes change history by watermark, which is how `lifecycle` sees attribute changes until a change-feed Registrar method exists (F3). DM-18 old and new values are stored as `PersonalRef`s through `platform/personal`, so erasure reaches them (ADR-0005 rule 12; old T-0065) | implements EP-8 |
| `invhost` | directory-engineer; security-architect reviews | `InventoryHost`, the typed host value (safe-primitives §6.3, PROC-14, PROC-17; T-0584): obtainable only from a DC found by DNS SRV and confirmed by its nTDSDSA object (`DCSource`), or from an audited admin registration (`Service.Register`, direct human requester only). `Service.Resolve` treats a candidate string as a lookup key and refuses, audited, anything not in inventory before any dial. Owns DM-27 `inventory_servers` (migration owner key: T-0992). Imports no transport. No caller outside the package yet; its first users are the SMB and sidecar paths | — |
| `sync` | directory-engineer | full sync, then DirSync / Graph delta per naming context or tenant, under a lease (ADR-0002 rule 6); the cookie is stored in our database, so the connector stays stateless. **Owns DM-19 SyncCursor** (the cookie table; its fencing token comes through `jobs`' API). Reads the attribute set and suspension from `connection`. **Built so far (T-1189):** the pure entry → `inventory.Observation` mapping and the closed attribute list a sync requests (`internal/directory/sync`, no I/O, no secret in the list); **Cursor store (T-1190):** DM-19 `sync_cursors`, one row per connection and partition, every write fenced by the platform lease's token. **Full read (T-1191, `engine*.go`):** `Engine.FullCycle(tenant, connection, LeaseFunc)` reads every *managed domain* NC of an ACTIVE AD connection (draft, suspended, retired or non-AD is a typed refusal before any connector call; configuration, schema and application NCs are `ErrNotDomainNC`) through the connector's `ScopedSearch`, in two passes pinned to one DC: a pre-scan of `objectClass` + `objectSid` (32 bytes per object of parent links and the groups' SIDs, so a stored ancestry chain is whole whatever order entries arrive in and `primaryGroupID` resolves), then the main pass mapped by the T-1189 mapper and ingested in 500-object batches through `inventory.Ingester` (one tenant transaction per batch, `MoreBatches` on all but the last, `PassNCs` and `Store.CompleteScan` on the last, so the pass and the cursor move together). One lease and one cursor per NC (`LeaseFunc` is asked per `LeaseName`); an already-incremental cursor is skipped; a failed domain keeps its committed batches, records no pass, and is joined into the error while the other domains still run; fenced, cancelled or port failures abort. `CompleteScan` writes no cookie: an incremental cursor with none means "prime the change feed". Malformed entries are counted by (attribute, code) and skipped; no directory value is logged. Memory is the pre-scan link map only (about 6 MiB at 100k objects). Not built: the job/scheduler that calls it and supplies leases, the production `Domains` (DM-14 managed set), ranged `member` completion, fetching `SchemaSecrets`, the change feed | EP-5 job |
| `client` | directory-engineer; security-architect reviews the write path | `Directory` (the generated connector-contract client); binding → transport resolution, from data rather than configuration, reading DM-13 bindings through `connection`'s API; capability check before Plan. **The write path** (ADR-0005 rule 2): every write method takes a `step.Step` (`client.Write(ctx, s, op)`), recomputes the plan digest, reads the facts the step names on its pins, calls `Step.Recheck`, and sends the conditional write only with the returned `Clearance`; the generated write client is referenced nowhere else. **Lab builds only** (`-tags lab`, T-0795): `labsource_lab.go` holds the in-process connector (`DialInProcess` over a `ConnectorServer`, returning an opaque `LabConnector`) and `LabSource`, the `ConnectorSource` the lab bootstrap in `compose/server` serves seeded lab connections from; the composition root builds only the server side and never names the generated client (O2). **Implements the kernel port `operation.LiveFacts`** structurally (§7.5). Owns no table | consumes EP-11 |
| `connection` | directory-engineer; security-architect reviews the credential port | **The connection registry** (ADR-0003 F1). **Owns DM-10 Connection, DM-13 ConnectorBinding and DM-21 HybridLink**: tenant configuration that `client`, `sync` and `inventory` read, kept out of the transport client so `inventory` need not depend on `client`. Its Go API is the only writer; the `connections` module calls it inside its Actions, through `directory.Services`. Declares the **credential port** (§7.3), implemented by `connector/credential/sealed` and handed in by `compose/server`. Importers: `client`, `sync`, `inventory`, and modules through `directory.Services` | — |

**`connection` built so far (T-0099).** Migration `0004_connection_connections.sql` (`connections`, the first tenant table: forced RLS, `tenant_id` leading every key) and `internal/directory/connection`: `Store` (Create, Get, List, Transition, SetDirectoryIdentity; each takes the caller's `WithTenant` transaction and refuses to run without a tenant context) and `Registry` (the same bound to a `store.DB`, held in `directory.Services.Connection`). The DM-10 lifecycle is the declared `edges` table in `transitions.go`; a pair not listed is `ErrIllegalTransition`, and a stale `from` is `ErrStateConflict` (compare-and-set under a row lock). I1 is enforced in Go and by the `connections_guard` trigger, I2 by the partial unique index `connections_live_identity` (violation → `duplicate_identity`), I13 `retired_at` from the ordering stamp. `ConnectorClient` is declared as a port with no implementation yet. **DM-21 (T-0168).** Migration `0005_connection_hybrid_links.sql` (`hybrid_links`, forced RLS; insert guard allows only declared→`confirmed` or discovered→`proposed`, so discovery cannot bootstrap trust, DM-21.I2; update guard is the SQL twin of `linkEdges`; sides must be an `ad_forest` and an `entra_tenant` connection of the tenant). `Store` gains Declare/Discover/Get/Transition/ListHybridLinks, `ConfirmedLink` and `HasLink`; `Registry` implements the read port `connection.HybridLinks` (`Confirmed`, `HasHybridLink`: errors, never a false, on failure; a `proposed` or `confirmed` link counts for `HasHybridLink`, only `confirmed` for `Confirmed`) and `connectiontest.HybridLinks` is its in-memory fake. The confirm permission (`connections.hybrid_link.confirm` over both scopes) and the audited Operation belong to the `connections` Action. **Verification and the activation gate (T-0100).** Migration `0009_connection_verifications.sql`: DM-24 `connection_verifications` + `connection_verification_findings` and DM-25 `connection_tier0_overrides`, all tenant tables with forced RLS, append-only (UPDATE/DELETE/TRUNCATE revoked, backed by a trigger), the override's evidence run tied to its connection and credential by a composite foreign key, and the I8 pointer `connections.last_verification_id` a foreign key to DM-24. In `internal/directory/connection`: `Store.RecordVerification` (moves the I8 pointer in the same transaction), `Qualifies` (I9) and `WriteGateOpen` (I11) in `gate.go` (15-minute `FreshnessWindow`), `AcknowledgeTier0Override` / `Tier0OverrideInForce` (DM-25 states are derived, never stored) and `Store.Activate`, the single door into `active`; `Health` / `Registry.Health` (Tier-0 banner, excessive and missing lists, write-gate state); and `Service` (Activate, Verify, ClearOverride, RunScheduled), which calls the new `ConnectorClient.VerifyConnection` port and audits `connection.verification.completed`, `.activated` and `.rights.verdict_changed` with counts and a salted digest, never finding identifiers. The `connections` module now exists (`internal/modules/connections`) and registers the Action `connections.tier0_override.acknowledge` (step-up, platform scope, irreversible, typed text). **`VerifyConnection` adapter (T-0244).** `directory/client.Client.VerifyConnection` implements `connection.ConnectorClient`: it reads `enabled_families` and `managed_domains` from a `VerifyScopeSource`, opens the stream through the `VerifyTransport` port, and folds header, findings, tier0-set and `completed` into a `VerifyResult`. A stream with no header, a second header, a run-id mismatch, a message after `completed`, counts that disagree with `completed`, or no `completed` is an error and no result (contract §2 rule 11). The DM-24 qualifier is derived per §8.4. **Directory identity (T-0412, contract v1.3).** `completed.directory_identity` carries the forest root NC GUID (AD, V5) or tenant id (Entra, EV2); the fold fills `VerifyResult.DirectoryIdentity` and rejects a missing identity (`ErrIdentityMissing`) or a wrong-kind/malformed one (`ErrIdentityMismatch`) unless the verdict is FAILED/COULD_NOT_VERIFY. `GRPCVerifyTransport` is the gRPC `VerifyTransport`. **Scheduled check and compose wiring (T-0245).** `connection.RegisterJobs(reg, svc, interval)` registers the tenant-carrying ManagedTx kind `connection.scheduled_check`: each run queues its successor first (bucketed `UniqueKey`, `MaxAttempts` 1, cadence 24 h ceiling, shortenable never lengthened), then calls `Service.RunScheduled`, which records a DM-24 `scheduled` run per active connection and audits drift; a run that does not complete is recorded as failed by the service and is never retried. `Service` takes `WithScheduler(...)`; activation (fast path and run path) calls `ScheduleCheck` in its own transaction, so the cadence starts with `active`. `compose/server.buildConnections` builds `connection.NewService` over `connection.NewRegistry(db)`, the directory client and the audit chainer, registers the kind in the job registry the worker runs (the registry was previously empty). With no verify transport wired the client fails closed (`client.ErrNoVerifier`): the run is recorded failed and the write gate stays shut. Boot-time scheduling of connections already active is not needed (none existed before this wiring). **Stranded-run sweep (T-0247, DM-10.I10).** `Service.SweepStranded(tid, grace)` lists connections in `verifying` since before `StrandedGrace` (15 min; a run is one connector call) and records a failed run with the over-privilege check `not_run` (write gate stays shut) and returns each to draft, audited as `connection.verification.completed` by `system:sweeper`; a connection whose state moved meanwhile is skipped (compare-and-set). It runs at the start of every `connection.scheduled_check`, and the first draft → verifying claim also starts the tenant cadence so a tenant with no active connection is swept too. Still to come: the credential port (DM-11 table, retiring the replaced row, DM-11.I5) and the DM-11 foreign key on `credential_id`. Migration `0028_connection_activation_guard.sql` (T-0246) adds a trigger so the database itself refuses draft/verifying → active unless a fresh qualifying run (or an override-covered over-privilege refusal) exists, whatever the writer. **DM-13 bindings and credential change (T-0249).** Migration `0030_connection_bindings.sql`: `connector_bindings` (tenant table, forced RLS, no DELETE; target `embedded` or `component`, only `embedded` is written in v1) and a trigger `connections_guard_binding` so the database refuses draft/verifying → active with no live binding (DM-10.I3). `Store.Activate` inserts the embedded binding (idempotent) in the activating transaction; `Store.Bindings` reads them. `Service.ChangeCredential` (spec FR-21) runs a `credential_change` verification of a candidate credential on an active or suspended connection; `RecordVerification` swaps `credential_id`, the I8 pointer and `verified_at` only on a pass that read the connection's own directory identity, and otherwise keeps the evidence and the old credential. A swap audits `connection.credential.changed` (reference IDs only). `Verify` still refuses the kind.

**`authn` console sign-in path, T-0783 (AN-8 subset, AN-10; TM §7.6 rules 1-4).** `internal/compose/server` now mounts the `platform.authn` tag (`consoleStack.Tags()`): `POST /auth/break-glass/password` then `POST /auth/second-factor/totp/verify` is the only way a console session is created. Migration `0057` adds `authn_local_credentials` (argon2id PHC hash, normalised username unique per tenant), `authn_signin_throttle` (key = HMAC(per-tenant pepper, tenant and normalised name), capped table plus one overflow bucket) and `authn_signin_pepper` (sealed under the tenant DEK); all three are forced-RLS tenant tables. `authn.LocalCredentials` answers one uniform 401 for unknown, wrong, non-local, disabled and throttled accounts, runs exactly one hash verification per attempt (a fixed dummy hash for the no-account case) outside any transaction (tx 1 locks the throttle row, counts the attempt as a failure and reads the credential; tx 2 records the outcome), under a process-wide in-flight cap (`MaxConcurrent`, default 4) that refuses with a name-independent 429 and never queues, answers a store or key fault with the same 401 (fail closed), throttles (never locks) after 5 failures with 1 s doubling to a 15 min cap, holds a latency floor, reads the epoch before it verifies, and audits without the password or the submitted name. The pending sign-in is a `PendingStore` handle in the `__Host-adiq_pending` cookie and is never a session. `authnhttp.PasswordCookies` is the cookie adapter (authn imports no `net/http`). The first local account has no API: `<server binary> account init-local` (`compose/server/localaccount.go`) creates it with a TOTP enrolment (seed shown once, confirmed with a first code), seeds the built-in roles, and grants the `console-directory-reader` role (`directory.read`; T-0987: at the tenant root, which reaches activeDIQ's own store and contributes nothing to directory reads, plus one `naming_context` assignment per AD connection that is active when the command runs, on the connection's directory identity — a connection activated later is granted through the role API, and the lab sequence is seed first, `init-local` second). Every write of the CLI is attributed to the system principal `cli-account-init-local`; the role grant uses `rbac.Grants.GrantBootstrap`, which accepts only the system principal `rbac.BootstrapPrincipal` (`cli-account-init-local`; any other chain is `ErrActorNotDirect`) and borrows no human's authority; `tools/fitness/grantbootstrap` fences its callers to `localaccount.go` (T-0808). The account stays inactive until the first TOTP code is confirmed, and the password is read without echo on a terminal (`golang.org/x/term`). **Not in this change (stays with T-0200):** owner alerts on use, the CIDR allow-list and hostname refusal, the AN-8 switch-off. Only `SignOut` still answers 501 (backlog, T-0802); `GetCSRFToken` returns the session-bound value (T-0854): `authnhttp.Authenticator.Authenticate` sets `Principal.CSRF = CSRFValue(session token)`, and `authn.Handlers.GetCSRFToken` answers `{header: X-CSRF-Token, value}` for a `KindSession` principal and 401 otherwise, with `Cache-Control: no-store`; the session token itself never reaches a handler. Lab builds only (T-0855): `server account add-passkey` (`cmd/server/account_lab.go`, `compose/server/labpasskey_lab.go`) stores a credential's public key through `WebAuthnFactor.AddCredential` so the Playwright suite `web/e2e/webauthn-sign-in.spec.ts` can sign in with a Chromium virtual authenticator before the registration ceremony (T-0573) exists; `TestProductionBinaryHasNoPasskeySeeding` fails if the production binary has the command.

**WebAuthn second factor mounted, T-0853 (AN-10, ADM-142).** `compose/server` `buildConsole` now also builds `authn.NewWebAuthnFactor` (same db, pending store, session store and audit sink as the TOTP factor) into `consoleStack.WebAuthn`, and `Tags()` sets `Handlers.WebAuthn` to `authnhttp.WebAuthnCookies`, so `POST /auth/second-factor/webauthn/challenge` and `/verify` are served beside the TOTP route; the session records methods `password,webauthn`. The relying party comes from `ACTIVEDIQ_PUBLIC_URL` only (`webAuthnRelyingParty`): RP ID = the origin's hostname without port, `Origins` = exactly that one origin, no top origins (security-architect, T-0573). `ValidateAttestation` now accepts the public URL alone (the attestation still needs `ACTIVEDIQ_ATTEST_CLIENT_ID`, which needs the URL); the origin must be https with no path, user, query or fragment (T-0861 tightens this to a canonical domain-name origin, below). With the URL unset `Handlers.WebAuthn` stays a nil interface (routes 501) and `buildConsole` logs once that WebAuthn sign-in is off. Registration of credentials stays with T-0573.

**Public URL canonicalised, T-0861.** `config.ParsePublicURL` is the one parser of `ACTIVEDIQ_PUBLIC_URL`: host lowercased, explicit `:443` dropped (other ports kept in the origin, never in the RP ID), and an IP literal, a numeric-looking host, a trailing dot, an empty label, a non-ASCII host or an out-of-range port refused at start-up with an error that names `ACTIVEDIQ_PUBLIC_URL`. `Load` stores the canonical origin in `Config.PublicURL`; `webAuthnRelyingParty` (RP ID, the single origin) and `buildAttestation` (redirect URI = origin + callback path) both derive from `ParsePublicURL`, so they cannot disagree. The former `publicOrigin` helper is deleted.

**`connection` attestation, T-0280 (TM-D17, threat-model §6.8, DM-10.I7).** Migration `0035` adds to `connections` `attested_by`, `attested_at`, the two attested flag values, `attestation_max_age_seconds` (default and CHECK cap 90 days), `demoted_at` and a set-once `first_attested_at` (trigger `connections_first_attested_guard`), and the forced-RLS table `connection_attestation_attempts` (hashed single-use state, PKCE verifier, expiry). `directory/connection`: pure `EvaluateTakeover` (`unattested|attested|open|stale`, derived, never stored) and `Store`/`Registry` methods `GetTakeover`, `RecordAttestation`, `RecordDemotion`, `SetAttestationMaxAge`, `CreateAttempt`, `ConsumeAttempt`. `inventory.Evaluate` reads the state: any non-`attested` state makes every correlation of the tenant `candidate` with reason `tenant_takeover_open`. Module `connections` adds the `Attester` (`modules/connections/attest.go`: `Start`, `Callback`, `SetMaxAge`, which also needs fresh step-up; `CreateAttempt` purges expired attempts) over ports `IdP`, `Graph`, `Authorizer` and `StepUp`, permission `connections.takeover.attest` over the entra_tenant scope plus fresh step-up (§7.4). Authorization code + PKCE S256, only delegated `OnPremDirectorySynchronization.Read.All`, no `offline_access`, token `tid` must equal the connection's directory identity; the bearer is a non-printable type zeroed on every path, so no token is stored, logged or audited. Refusals are audited with machine reasons (a `Chain.Validate` failure skips the audit). **Wired by T-0440.** Adapters in `internal/compose/server/entra` (outside `internal/modules/`, because a handler package may not import `net/http`, fitness A6): `OIDCIdP` (tenant-specific `/oauth2/v2.0/token`, PKCE, decodes only `access_token`/`token_type`/`scope` so a refresh or ID token is never held; `tid`, `iss`, `aud`, `exp`, `scp` checked on a token read straight from the token endpoint, whose signature Graph validates on the read) and `GraphReader` (`GET /directory/onPremisesSynchronization`, an absent flag is an error). Both take the `egress.Client`; errors carry no input. Routes (tag `connections`, generated): `startTakeoverAttestation`, `setTakeoverAttestationMaxAge` (session principal only; the session goes to step-up), and the anonymous `completeTakeoverAttestation` (AN-11): rate-limited by source then by the tenant named in the server-issued state (`<tenantUUID>.<nonce>`, `StateTenant`; the tenant only scopes the lookup, which is by the hash of the whole state) through `WindowGate` before the Attester, and always a 303 to a fixed location. `authn.StepUp.FreshSession(tenant, session)` answers step-up for the Attester. Catalog: `connections.takeover.attest` is in `platform-administrator`; policy row `stepUp` TM-D17. `compose/server` mounts the tag only when `ACTIVEDIQ_ATTEST_CLIENT_ID` and `ACTIVEDIQ_PUBLIC_URL` are set, on the console authn stack composed by **T-0475** (`compose/server/console.go`): one `authn.Store`, the `authnhttp` cookie Authenticator (now sets `Principal.SessionID`), `authn.StepUp` as both the API step-up port and (via `sessionStepUp`) the Attester's `FreshSession`, and `consoleAuthz` as apihost's Authz port (RBAC at the tenant store root, session principals and tenant scope only, deny by default; the Attester re-authorises against the connection). `StepUp` is composed without a TOTP factor (no tenant DEK source exists in the server role yet), so `Fresh` works and `Reverify` refuses; `failClosedPorts` remains for tests. **Not proven:** the real Entra token shape and Global Administrator consent (Samba cannot; T-0474, T-0441); demotion-monitor wiring.

**`inventory` built so far (T-0167, T-0173, T-0378).** Migrations `0006_inventory_correlations.sql` (DM-20 `correlations`, DM-16.I8 `tier0_designations`) and `0012_inventory_writer.sql` (the two connection foreign keys on `correlations`, soft-deleted designations with `DELETE` revoked, DM-17 `links` member and primary-group edges, `DELETE` revoked). `internal/directory/inventory`: read ports `CorrelationSource`, `Designations`, `GroupSource` (Postgres `Reader`, `Groups` with a recursive transitive walk that terminates on circular groups, in-memory `Fake`); `Evaluate` (`gate.go`), the pure DM-20.I4 gate (a)–(g) with the I4(g) once-only markers; `Writer` (`Form` stores the verdict per observed pair, inherits markers across broken/removed; `Remove`, `Designate`/`Undesignate`, `SetMember`/`RemoveMember`, `SetPrimaryGroup`/`RemovePrimaryGroup`), which runs in the caller's tenant transaction and decides nothing about who may call it. T-0378 (contract §8.3 F3): `0022_inventory_evaluations.sql` adds `correlation_evaluations` (per-connection as-of of the last completed correlation run, forward-only, `DELETE` revoked); `Writer.RecordEvaluation` sets it and `CorrelationsFor` returns `Correlations{Links, EvaluatedAt}` (set even when there are no links; zero only before any run); `Form` now always requires `FactsAsOf`, tier0 or not. Module `internal/modules/inventory` registers the Action `inventory.tier0_designation.set` (permission `inventory.tier0_designation.manage`, step-up, human requester only, authorised against the connection's Tier-0 scope (not the object, so runner rule 7 does not block removal), audit `inventory.tier0_designation.changed`). **Tier0 revision (T-0376).** Migration `0038_inventory_tier0_revision.sql`: `inventory_tier0_revisions` (one counter row per tenant, forced RLS, `DELETE` revoked, a guard trigger refuses any non-increasing update) bumped by AFTER triggers on `tier0_designations` (added, re-activated or removed) and `correlations` (tier0 bases of either side changed, or a tier0-carrying correlation created/removed/revived; a refresh that restates the same facts does not). `Reader.Tier0Revision` implements `client.RevisionSource` (0 for a tenant never written). Group membership under a designated group is read live (F2) and is not part of the number. Composed (T-0481): `internal/compose/server/tier0.go` resolves the tenant from the request context, caches one `client.NewTier0Builder` per tenant over the connection registry, inventory reader and (when connector reads exist) `InventoryRefresher`, and is wired into the directory client; a missing required source fails startup. **DM-16 objects and populator (T-0431).** Migration `0033_inventory_objects.sql`: `directory_objects` (key `(tenant_id, connection_id, object_guid)`, forced RLS, `DELETE` revoked; time-dependent state stored as inputs only, no secret columns; a trigger keeps `cloud_seen_at` (DM-16.I9, Entra users and groups only) from being cleared or moved back and `observed_at` from moving back). `Populator.Populate` upserts a sync cycle's `Observation`s for one connection in the caller's tenant transaction (all-or-nothing validation; a late observation is counted `Stale` and ignored; `cloud_seen_at` set when an Entra user/group is cloud-only or cloud-managed), writes group `member` edges through `Writer.SetMember` (a complete read marks unseen edges removed, a delta only adds/removes the named ones) and the user's `primary_group` edge through `Writer.SetPrimaryGroup` (a changed primary group retires the old edge). `Writer.AnchorMatches` (DM-20.I1a) counts non-purged AD objects whose `ms-DS-ConsistencyGuid` or `objectGUID` equals a 16-byte anchor across the AD connections the caller names (the `connection` HybridLink port supplies them; a non-AD or foreign connection is `ErrUnknownConnection`). Not built: the connector-side producer of `Observation` (LDAP/DirSync/Graph delta), string-anchor lookup (employeeID etc.), the `tier0` classification column (T-0326), the DM-10.I7 attestation fields. **InventoryHost (T-0584, safe-primitives §6.3).** Migration `0050_inventory_servers.sql` (`inventory_servers`, tenant table, forced RLS, no UPDATE/DELETE for the runtime role, CHECK on the stored FQDN). Package `internal/directory/invhost`: `InventoryHost` has unexported fields (zero value = invalid, `IsZero`), no string constructor. `Service.Register` (admin-registered; audited `inventory.host.registered` in the same tx as the row; idempotent; invalid name is a denied `inventory.host.refused`) and `Service.Resolve` (candidate is a key only: matches a registered server or a DC the `DCSource` port reports as SRV-discovered AND nTDSDSA-confirmed, and returns the inventory's name; anything else, including a UNC `homeDirectory` host, an IP literal or an unregistered `dNSHostName`, is `ErrNotInventoryHost` before any dial, with a denied audit event carrying only a digest of the candidate). Not built: the `DCSource` implementation (DC discovery), the Action/permission that exposes registration to admins, and consumers (`proc`, SMB, SYSVOL) taking `InventoryHost` as their parameter type.

**Search hit metadata (T-1097).** `inventory.Searcher.SearchMetadata` is the one batched read after the search statement: display fields, `title`/`physicalDeliveryOfficeName`/`department` (empty until T-1129 syncs them), stored tier-0 facts (an active `tier0_designations` row, or a non-removed correlation whose own side is tier0 with an as-of) and cloud-only (Entra `nc_guid IS NULL`, `state = 'active'`, `on_prem_sync_enabled IS NOT TRUE`, not cloud-managed; groups also need the key `onPremisesSyncEnabled` in `attributes`; never `cloud_seen_at`). Locked, password and account-expiry states are not restated: user hits are read through the `inventory.users` report dataset (`reportsql.Compile` + `reportsql.ExecAll`, caller's scope, same `now`), so the chip rules are the report rules and an unread input yields no chip. `modules/search` turns the facts into chips (`PasswordExpiryWarnDays` = 14 window, most urgent first) and clears `domain` unless the permitted answer spans more than one domain.

**`directory` module (T-0668, T-0669, T-0680).** `internal/modules/directory`: `Handlers.SearchDirectoryUsers` (`GET /directory/users`, permission `directory.read`, bound by hand in `compose/server/directory.go` like the other tag handlers; the module has no Action, so it is not in `modules.gen.go`). The tenant is the authenticated principal's, never a request value. The search text reaches the directory only as a value inside a typed filter tree (`client.UserSearch`; the connector re-parses it with `ldapfilter.ParseFilterAST` and renders RFC 4515 escapes; `usersearch_filter_test.go` proves a hostile term cannot change the filter's shape). `Classifier` (TM-D17) adds `hybrid` to every user: state `not_hybrid | candidate | matched | broken | unknown` from `CorrelationSource` and `carriesAuthority` only for a matched correlation with an evaluation as-of, tier0 facts as-of, neither side tier0 and takeover protection `attested` (`Registry.GetTakeover`) — the gate of `authz.hybridCheck`, read-only; any unreadable fact is `unknown` with no authority. It reads one correlation set per returned user (at most 100 per request). `directory.read` is granted by the built-in roles `platform-administrator` and `helpdesk-operator` (re-seeding adds it to existing tenants) and is classified as a permission that may cross a correlation (`rbac/hybrid_classification_test.go`). **`Handlers.SearchDirectory` (`POST /directory/search`, T-1096, ADR-0011)** is the HTTP edge of universal search; it replaced the 501 stub. It takes the tenant and the human behind the session from the principal, refuses a token (403, like `readScope`), maps the service's errors to problems (400 `search-query-invalid` with `errors[].code`, 403, 503 `search-unavailable`) and never echoes or logs the text; a read appends no audit event. The service is `internal/modules/search` (the method sits on `directory.Handlers` because the contract tags the operation `directory`; `directory` imports `search`, never the reverse). A refused permission check is audited for every route: `compose/server/authzaudit.go` wraps the console Authorizer and appends `authz.permission.denied` (outcome `denied`, details `permission` and `scope`, requester the session's account) in the caller's tenant; an audit fault is logged and the request is still refused.

**Re-confirmation (T-0282, TM-D17 rule 4 (g)).** `Writer.PendingReconfirmation`/`Reconfirm` (directory/inventory) move a `candidate` held for `reconfirm_required` to `matched` and record `reconfirmed_by/at`; nothing else can be re-confirmed. The Action `connections.correlation.reconfirm` (module `connections`; permission `connections.correlation.reconfirm`, step-up, irreversible, target = the correlation row so runner rule 7 does not block it) additionally requires a human who holds the `tenant-owner` role right now (`rbac.Owners`, read in the runner's transaction), whatever the authorizer grants. T-0453: `rbac.BuiltInRoles` grants the permission to `tenant-owner`; migration `0043_authz_tenant_owner_reconfirm.sql` replaces the 0034 guard so the DB-read-only owner role accepts exactly that named permission (allow-list in the trigger, pinned to the catalogue by tests); existing tenants get the row on the next idempotent `SeedBuiltIns`. Install-time correlations never reach this Action: the gate matches them on the first attestation. **Live refresh (T-0480, DM-20.I5).** `client.InventoryRefresher` implements `client.LiveRefresher`: it resolves the connection under the tenant (another tenant's ref is refused before any read), reads the object's tier0 verdict live through `client.Reads`, and stores it with `inventory.Facts.RecordLiveFacts` (`Writer.RecordLiveFacts`), returning the time taken before the read. Only the object's own side moves: migration `0039_inventory_side_facts_as_of.sql` adds per-side as-ofs (`ad_facts_as_of`, `entra_facts_as_of`, NULL = `facts_as_of`), and `Link.FactsAsOf` is the older of the two, so a one-sided read never vouches for the peer's fact (the correlation job resets both). The gate verdict and evaluation as-of do not move either, so a statement resting on an older evaluation stays stale and is refused. A verdict of tier0 with no stored basis is `ErrBasisUnknown` and writes nothing (a live read yields a verdict, not a basis). Wired in compose by T-0481 when connector reads exist.
**Sync ingester gate step (T-0326, DM-20.I4 / DM-17).** Migration `0042_inventory_entra_hybrid_inputs.sql` stores the Entra gate inputs on `directory_objects` (`on_prem_sync_enabled`, `on_prem_cloud_managed`, `on_prem_sid`, `on_prem_domain_name`, `on_prem_immutable_id`; Entra only) so a later AD cycle can re-run the gate. `inventory.Ingester.Ingest` (one tenant transaction per cycle batch) calls `Populate` (objects and DM-17 `SetMember`/primary-group edges), then for each Entra tenant the cycle's connection is or feeds (`connection.Store.ListHybridLinksForEntra`) records the evaluation as-of first (oldest input read, forward-only, `ErrStale` rolls the cycle back) and judges every live correlation plus the pair an unambiguous anchor (user) or SID (group) newly resolves to: `GateInput` comes only from stored inventory, confirmed HybridLinks and the attestation derived now by `connection.EvaluateTakeover` (never attested counts as open). An ambiguous anchor forms no pair and drops a live one to `ambiguous_anchor`; a pair whose anchor no longer resolves to its AD object counts zero matches. Tier0 facts come from the `PairClassifier` port (missing = `ErrNotConfigured`, never "not tier0"). Not built: the connector-side producer of `Cycle`, compose wiring of the classifier, a delta-scoped (not full-tenant) gate pass.
**Re-confirmation (T-0282, TM-D17 rule 4 (g)).** `Writer.PendingReconfirmation`/`Reconfirm` (directory/inventory) move a `candidate` held for `reconfirm_required` to `matched` and record `reconfirmed_by/at`; nothing else can be re-confirmed. The Action `connections.correlation.reconfirm` (module `connections`; permission `connections.correlation.reconfirm`, step-up, irreversible, target = the correlation row so runner rule 7 does not block it) additionally requires a human who holds the `tenant-owner` role right now (`rbac.Owners`, read in the runner's transaction), whatever the authorizer grants. T-0453: `rbac.BuiltInRoles` grants the permission to `tenant-owner`; migration `0043_authz_tenant_owner_reconfirm.sql` replaces the 0034 guard so the DB-read-only owner role accepts exactly that named permission (allow-list in the trigger, pinned to the catalogue by tests); existing tenants get the row on the next idempotent `SeedBuiltIns`. Install-time correlations never reach this Action: the gate matches them on the first attestation. **Live refresh (T-0480, DM-20.I5).** `client.InventoryRefresher` implements `client.LiveRefresher`: it resolves the connection under the tenant (another tenant's ref is refused before any read), reads the object's tier0 verdict live through `client.Reads`, and stores it with `inventory.Facts.RecordLiveFacts` (`Writer.RecordLiveFacts`), returning the time taken before the read. Only the object's own side moves: migration `0037_inventory_side_facts_as_of.sql` adds per-side as-ofs (`ad_facts_as_of`, `entra_facts_as_of`, NULL = `facts_as_of`), and `Link.FactsAsOf` is the older of the two, so a one-sided read never vouches for the peer's fact (the correlation job resets both). The gate verdict and evaluation as-of do not move either, so a statement resting on an older evaluation stays stale and is refused. A verdict of tier0 with no stored basis is `ErrBasisUnknown` and writes nothing (a live read yields a verdict, not a basis). Wired in compose by T-0481 when connector reads exist.

### 5.3 Connector root (`internal/connector/`)

Rows marked **planned** have no directory yet. Every other row describes code on main. The EP-11 shape and the order in which the planned rows land are fixed in §4.3 (T-0993). `service`, `provider`, `provider/ad` and `provider/entra` arrive together in T-1005.

| Package | Owner | Interface | EPs |
| --- | --- | --- | --- |
| `service` | directory-engineer | **Planned (T-1005).** The one assembly of the connector: `service.New(p provider.Provider, deps)` builds the verify, read and write handlers over `p` and returns the one composite `activediq.connector.v1` `ConnectorServer` (§7.1). The remote role mounts it on the fleet tunnel registrar. The embedded role hands it to `directory/client` in-process. `compose/connector` and `compose/server` call it with different parameters. Today `compose/connector/mount.go` (`tunnelServer`) and `backend.go` do this by hand, and `compose/server/labbootstrap_lab.go` repeats the wiring; both move into `service` | consumes EP-11 |
| `read` | directory-engineer | The connector's `Read` RPC for both transports (T-0433): one object by GUID, ranged attributes streamed to the end, and the Tier-0 verdict on its header from `write`'s classifier over the same session. Pinned to the serving DC (`DcSelection.pinned_dsa_guid`, ADR-0005 rule 5) and re-checked after the read and the classification; undecidable is an error, never `false`. Wired by `compose/server` and `compose/connector`. Today it reaches AD through its own `Source` port and `ADSource`, and imports `write` for the verdict type. In T-1005 it takes `provider.Provider` and asserts the `ObjectReader` facet | consumes EP-11 |
| `wirevalue` | directory-engineer; security-architect reviews | **Planned (T-1739).** The one wire-value builder, `wirevalue.Of(desc, schema, raw)`: the syntax switch that turns raw directory bytes into a typed `AttributeValue`. `read` (`Read`, `ScopedSearch`, `ValueChunk`), the `write` `Plan` before-image and `ChangeFeed` all call it. It is a leaf package that imports neither `read` nor `write` (`read` imports `write`). It holds the `userParameters` identity gate, which runs before the syntax switch, and it is the only importer of `attr/tsprops` (connector-contract §5.9.1, TS2(c); §7.4). TS7 fails on any `AttributeValue_Octets`/`_Text` composite literal outside it | — |
| `write` (+`write/ops`) | directory-engineer; security-architect reviews | Plan and Apply of contract §8 for both transports (T-0098): `Handler.Plan`/`Apply` satisfy `directory/client.Transport`, and `Register` serves them over gRPC. Every write passes the independent Tier-0 guard (TM-D2, TM-F-T0GUARD): operation bodies live only in `write/ops` and take an `Authorised` token that only the guard mints; `fitness_test.go` fails on a write call anywhere else in `internal/connector`. Owns the write operation table, keyed by `(ProviderKind, WriteKind)` (§4.3); bodies live in `write/ops`. **Interim:** it still declares the guard's port `Provider` with `ADProvider`, `EntraProvider`, `SessionDC` and `NewADProvider`. These are the EP-11 core and move to `provider` and `provider/*` in T-1005 (§4.3). Its `isAD` branches become `DCBound` checks there | consumes EP-11 |
| `provider` | directory-engineer (contract: solution-architect) | **Planned (T-1005). Hosts EP-11 (§4.3).** The core interface `Provider` (`Kind`, `Identity`, `Classify`, `Anchors`, `PropertyGuard`) and its value types; the facets `DCBound`, `ObjectReader` and `RightsSource`, with one more per later contract group; `Supports(p)`, which derives the Describe rows from the facets. It holds no protocol code and no policy. `directory/client` checks the derived capabilities before `Plan` | hosts EP-11 |
| `provider/ad` | directory-engineer; security-architect reviews | **Planned (T-1005).** The AD provider over one `*ad.Session`. One constructor builds the core (the classifier over `tier0.SessionDirectory`, with C13 pins), `DCBound`, `ObjectReader` and `RightsSource` from that session, which holds the rule 5 / Read-pin same-DC invariant. Later, SMB (`go-smb2`) and MS-RPC (`go-msrpc`) facets, each with a register row first. Imported only by composition roots and conformance (M13a) | implements EP-11 |
| `provider/entra` | directory-engineer; security-architect reviews | **Planned (T-1005).** The Entra provider over `graph`. Today it has the core (`write.EntraProvider`); `RightsSource` comes with T-0615, and Read and delta ([user: delta](https://learn.microsoft.com/en-us/graph/api/user-delta)) facets come with their specs. Imported only by composition roots and conformance (M13a) | implements EP-11 |
| `ad` (+`ad/gssapi`) | directory-engineer; security-architect reviews | The AD session layer (contract §5.1, §5.3, TM §6.5; T-0092, T-0560): LDAPS only to a configured DC (no plaintext, no StartTLS); SASL GSSAPI bind with tls-server-end-point channel binding (`ad/gssapi`, the krb5 adapter) or the simple-bind fallback; rootDSE; typed paged search and `Read` with the constructed effective-rights attributes; scoped search; GC resolution; and the one write, `Session.WriteDACL`. Takes `ldapfilter.Filter`, `dn.ObjectRef` and `sd` types only. **This is the AD session layer, not a provider** (T-0993). The withdrawn `ldap` and `kerberos` rows and the general half of scope are built here. Planned additions here are the DC locator and DC affinity (ADM-212). The planned subpackage `ad/scope` holds only the escape-control named-operation table (§1.1, LF-30). `provider/ad` adapts this layer to EP-11 | — |
| `graph` (+ `graph/graphtest`) | directory-engineer; security-architect reviews | stdlib Microsoft Graph client for the customer's own app registration: client-credentials with a PS256 certificate assertion, tenant-GUID pinned (`tid` checked), same-origin paging, Retry-After retry, typed errors. Reads own app/SP, appRoleAssignments, keyCredentials and passwordCredentials (metadata only, never secretText or hint) of both, owners, directory roles (active + PIM eligible), role-assignable groups. Read-only. `graphtest` is the in-process fake Graph for other tickets' tests (fake-only: real Entra behaviour needs the Entra lab) | — |
| `rights` | directory-engineer; security-architect reviews | The connector's rights check behind `VerifyConnection` (contract §8.4). Entra half (`VerifyEntra`, T-0097): reads the app's own grants through `graph` and compares them with the threat-model §6.6 policy held as data in `policy_entra.go` (allow rows per family, deny list): EV3 deny-list permission or any directory role (active or PIM-eligible) refuses; EV4 missing permissions; EV5 extra permissions, extra key credentials and client secrets on the application or its service principal, owners. An unanswerable read is COULD_NOT_VERIFY, never PASS. Emits `RightsFinding`s without fingerprint (computed where `audit/canon` exists). Read-only, identifiers only. AD half (`VerifyAD`, threat-model §6.5, V7–V9) is built and served by `VerifyHandler` over `rights.ADDirectory`, its own port. In T-1005 that port becomes the `RightsSource` facet; the Entra stream (T-0615) arrives through the same facet | consumes EP-11 |
| `tier0` | directory-engineer; security-architect reviews | The connector's own Tier-0 set (TM §6.4, TM-D2 check 2): the AD classifier C1–C19 over live reads and designations (T-0093), and Entra E1–E5 over the read-only `graph` client. Fails closed: any read error or unknown answer is `tier0, unknown`. Called by `write` (the guard, and through it `read`'s header verdict) and `rights` | — |
| `credential` | directory-engineer; security-architect reviews | **Owns DM-11 DirectoryCredential** alone, with its SQL only in `credential/sealed` (§2 rule 6). The credential types and a `Source` interface. Its types are nameable only here (P3). Two sources: `credential/local` (gMSA through the process identity, keytab file, OS-protected certificate), used by both roles; and `credential/sealed` (Entra certificate and AD password fallback, unsealed with `keys` inside the caller's `WithTenantTx`), used **only** by the embedded connector, wired by `compose/server`. `credential/sealed` also implements `directory/connection`'s credential port (§7.3). **Planned.** Until it lands, the remote connector's keytab is read by `compose/connector` (`adConfig`, `local.go`) and handed to `ad.Config` as a `secret.Secret`; that code moves to `credential/local` | — |
| `psx` | backend-engineer | **Planned** (first sidecar feature, FD-04 Exchange or M3 GPMC; `tools/analyzers/policy.Psx` already reserves the home). Typed sidecar client over `proc` (safe-primitives §6.1) | — |
| `labadmin` | test-engineer | **Test support, not product.** The lab fixture connection: an admin LDAPS session that creates and deletes lab OUs and users and reads their GUIDs. It sits under the connector root only because only that root talks LDAP (ADR-0005 rule 2, O2), so lab tests elsewhere (`compose/server`) use this seam. Only `_test.go` files may import it: `connector/write/fitness_test.go` and `tools/analyzers/policy` enforce that, and no `cmd/*` links it (`go list -deps`, T-0915) | — |

### 5.4 Server feature modules (`internal/modules/<id>/`)

| Module | Owner | API tag / Actions / datasets (interface) | EPs (§4) | Epic |
| --- | --- | --- | --- | --- |
| `connections` | directory-engineer | AD forest and Entra tenant onboarding; connector enrollment and binding; connection settings (signing, CBT, DC affinity). **Owns no table** (F1): it writes DM-10, DM-13, DM-21, DM-24 and DM-25 through `directory/connection`'s API; today it registers the Tier-0 override Action (`modules.gen.go` is edited by hand until `tools/gen/modules` exists) and credentials through the credential port, inside its Actions | EP-1, 2, 3 (onboarding, binding and settings changes), 6, 7. Reads provider capabilities through `directory/client` (EP-11) | E2.7, E2.12 |
| `objects` | backend-engineer | create/modify/move/rename/delete/restore for users, groups, computers, contacts and OUs, with class definitions as data; templates, naming formats, rules, duplicate checks, copy; bulk and CSV planning. Owns DM-50, DM-51, DM-53. A user create that needs a generated password composes `helpdesk`'s password-set Action by ID and never reads DM-52 (F5) | EP-1, 2, **3** (one Action per class × verb; class definitions are data), 6, 7 | E2.2, E2.3 |
| `helpdesk` | backend-engineer | reset, unlock, random passwords, password options; LAPS/BitLocker reads (named secret ops); the reset console with caller verification (EP-10). Owns DM-38 and DM-52; its password-set Action generates the password inside `helpdesk` and returns no secret to its caller (F5) | EP-1, 2, **3** (reset, unlock, named secret reads), 6, 7. Uses EP-10 for caller verification | E2.5 |
| `delegation` | backend-engineer | roles, technicians, scopes (OU/group/site/domain, include/exclude, cross-domain). Registers the directory **`ScopeEvaluator`s** (EP-6), one per assignment root kind: `naming_context`, `ou_subtree` and `ou_one_level` at 2a, each turning a (connection, root) into an `authz.ScopeTerm` (T-0880). It does not produce read scopes itself: the one producer is `rbac.ReadScopes.For`, fed by these evaluators (§11). Owns DM-35 DelegationScope only; roles and assignments are `authz`'s tables, changed through `authz`'s Go API inside its Actions (F2) | EP-1, 2, **3** (role and scope assignment changes; ADR-0005 rule 10), **6** (registers the directory root-kind `ScopeEvaluator`s), 7 | E2.5 |
| `compliance` | backend-engineer; security-architect reviews | legal holds on personal subjects (ADR-0005 rule 11). Owns no table (F1): writes `personal_hold` through `personal.Store` inside its Actions' transactions (T-0605). Actions `compliance.hold.set` / `compliance.hold.release`, permissions of the same names (no built-in role holds either), step-up, human requester only, authorised on the `legal_hold` class, audit `compliance.hold.set` / `compliance.hold.released` with before and after. Release is the only sanctioned way to lift a hold: the runtime role can DELETE the row, and the database cannot tell that from a release | EP-3 | E2.5 |
| `lifecycle` | backend-engineer | joiner/mover/leaver policies (HR, CSV, DB), scheduled automation, cleanup policies, expiry reminders; it composes Actions by ID. Attribute-change triggers are a job reading inventory change history by watermark until a change-feed Registrar method exists; it never imports `sync` (F3) | EP-1, 2, **3** (policies compose other modules' Actions by ID), 5 (policy schedules), 6, 7. Uses EP-9 (reminders) | E2.9 |
| `workflow` | backend-engineer | requests, review, approval, SLAs, assigning rules, manager approvers; implements EP-4 | EP-1, 2, 3 (workflow-definition changes, ADR-0005 rule 10), **4** (approval gate), 5 (SLA timers, escalations), 6, 7. Uses EP-9 | E2.8 |
| `reports` | reporting-engineer | canned library (data), builder, runs, schedules, exports, act-on-results (→ EP-3), ME crosswalk. Owns DM-71–73: the library, `report_runs`, `report_run_rows` (stored results, ADR-0010), `report_exports` and the schedule tables. Writes no other owner's data. Contract: [modules/reports.md](modules/reports.md) | EP-1, 2, 3 (`reports.schedule.*` at 2a; report-definition changes when the builder lands; ADR-0005 rule 10), 5 (`reports.run`, `reports.export`, `reports.schedule.fire`, `reports.retention`), 6 (`reports.*` permissions; runs with the caller's `authz.ReadScope`), 7. **Consumes EP-8** and registers no dataset at 2a; calls EP-3 by Action ID (act on results); uses EP-9 (delivery) | E2.6 |
| `history` | backend-engineer | object timeline (inventory history joined with our audit), undo entry point, baseline snapshot (MIG-18) | EP-1, 2, 6, 7. Consumes EP-8 (inventory history, audit); calls EP-3 through `operation.Undo` | E2.4 |
| `search` | backend-engineer | universal search over inventory with RBAC trimming ([ADR-0011](../decisions/0011-universal-search-over-inventory-pg-trgm-one-scope-renderer.md), `ratified`): `directory.search` (T-1094) classifies the query with `platform/searchkey`, takes the caller's scope from `rbac.ReadScopes.For` through the composed port (T-0987) and calls the `inventory.Search(ctx, tx, tenant, scope, q)` port (T-1095), which compiles **one statement** through `reportsql.CompileSearch`: `pg_trgm` match over `inventory_search_keys`, with fuzzy candidates taken from the tenant-led trigram posting B-tree `inventory_search_trigrams` and rechecked with `<%` through a correlated per-candidate lookup (ADR-0011 rule 5a, rev 3, T-1335; postings kept by one invoker function on three statement-level triggers; fuzzy kinds `name` and `sam`, queries of 3–32 runes), trimmed by the reports `scopeSQL` in the same statement, with the scope applied before every limit, then ranked, counted and paged over admitted rows only (LF-39). A per-class work ceiling W on matched key rows gives every caller the same `refine` state with no counts (rules 12–13). Every stage reads only the tenant's own index entries under `FORCE` RLS, with no definer function or bypass, so rule 16 is met by construction (T-1335 supersedes T-1136). The query travels in a `POST` body and is never logged (rule 15). **Built (T-1096):** `internal/modules/search.Service` classifies with `searchkey.Classify` (refusal order of rule 7, on the NFKC form), asks the `ReadScopes` port (same method set as `directory.ReadScopes`; `compose/server.txReadScopes` satisfies both) for every permission the key kinds are read under (`directory.read` failing is a 403; an empty scope answers empty without reading), then in one `WithTenant` transaction calls `inventory.Searcher.Search` and the one batched `inventory.Searcher.SearchMetadata` (dn, sam, upn, mail by admitted GUID); a 2 s context deadline maps to 503. Free text is never `exact`. Paging: an HMAC-SHA256 cursor bound to the NFKC text, class set, type and every scope fingerprint, stopping at 1,000 permitted hits; the key is random per process (`NewEphemeralCursors`), so a cursor does not survive a restart or cross nodes until a key-custody key replaces it (follow-up). Wiring: `compose/server.buildSearch` (called by `buildDirectory` with the same producer it gives `Handlers.Scopes`). Logged: rune length, shapes, class set, paged flag, or the refusal code. Status chips, the disambiguator and `mail` for users are built by T-1097 (see "Search hit metadata"); `domain` is derived from the DN's DC components. It renders no scope, calls no `ReadScope.Admits`, makes no directory call, builds no SQL. Report, page and action groups come from the report library, the web Registrar (T-1099) and `operation.Catalogue()` (F4, 2b), never a module import; dashboard tiles. The live-LDAP `searchDirectoryUsers` / `client.UserSearch` path is retired by T-1127 | EP-1, 2, 6, 7. Reads the EP-3 Action catalogue for the palette. Fitness: `fitness-search` SE1–SE6 (T-1126) | E2.1 |
| `m365` | directory-engineer | licences and other Entra-only actions; EXO mailboxes [M5] | EP-1, 2, **3** (licence and other Entra-only Actions on `provider/entra`), 6, 7 | E2.7 |
| `itsm` | backend-engineer | ServiceNow and ServiceDesk Plus as one adapter shape | EP-1, 2, 5 (outbound status sync), 6, 7. Submits requests as EP-3 Actions by ID; ITSM-driven approval (EP-4) later | E2.10 |
| `migration` | backend-engineer | ADMP importers, fidelity report, parallel-run comparator, job-ownership lock (ENH-02) | EP-1, 2, 5 (import and parallel-run jobs), 6, 7. Writes what it imports through the owning modules' Actions by ID (EP-3 caller); imported configuration is configuration, so it goes through those Actions too (ADR-0005 rule 10) | E2.11 |
| `hardening` | directory-engineer; security-architect designs | least-privilege wizard (ENH-08, needs SD primitive old T-0028), hardening score | EP-1, 2, **3** (applies and removes the delegated rights it generates), 6, 7 | E2.13 |

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
| `internal/agentmodules/fileserver` [M3] | windows-engineer | ACL reads and writes through the security-descriptor primitive (old T-0028), and file-access auditing. Like every agent module it calls `proc` only, never `psx` (§7.4) | implements EP-13, EP-14 |
| `internal/agentmodules/mgmthelper` [M3, `OPEN`] | windows-engineer | Exists only if the M3 GPO spec chooses an agent module with its own constrained identity, rather than a Windows-hosted remote connector driving `sidecars/gpmc` (custody favours the connector, §13). If chosen, that spec also decides how it reaches `sidecars/gpmc`, because `psx` sits under the connector root, which agent modules may not import (§2 rule 3) | would implement EP-13 |
| `native/passfilt` [M4], `native/credprov` [M4] | windows-engineer | LSASS / LogonUI DLLs (ADR-0001 tier N, spikes old T-0024/old T-0025) | — |
| `sidecars/*` | windows-engineer | typed request/response over stdio, launched by `proc` with constant argv; never listens on a port | — |
| `web/` | frontend-engineer; `src/ds` component-designer | console shell and module screens over the generated client | hosts EP-15 |
| `packaging/` | devops-engineer | MSI and OCI artefacts in one signed release manifest (ADR-0002 rule 7) | — |
| `tools/fitness/*` | devops-engineer (`tenancy`: backend-engineer, old T-0036) | CI jobs, §17 | — |

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

Binding: [ADR-0004](../decisions/0004-public-api-contract-openapi-first.md) (rules 1–13). This
section summarises it; if the two disagree, the ADR wins. Build detail: [api-pipeline.md](api-pipeline.md).

- **Every capability is an OpenAPI operation first** (rules 12, 13). The console, ITSM integrations,
  customer scripts and later the PowerShell module and MCP (ENH-11, M3) all use the same operations
  of one contract, `api/openapi/`, written before any handler exists. The console uses only the
  client generated from the bundle and has **no private endpoints**.
- **What is not product API is a closed list** (rule 5): `/healthz` and `/readyz` (AN-1), static
  assets and the console fallback, which never answers under `/api/` or `/auth/` (AN-2), the SSO
  redirect and callback routes (AN-3), the `fleet` gRPC gateway on its own mTLS listener (AN-6) and
  [M4] the edge tunnel router's SSPR routes (AN-7). They are declared in `policy.yaml`
  `nonApiRoutes`; anything else served is a document operation. The anonymous JSON operations
  (health `getLiveness` and `getReadiness` AN-1, first-run setup AN-4, TOTP enrolment AN-5,
  [M4] SSPR AN-7, break-glass sign-in AN-8, the sign-in second factor AN-10) are operations with
  `x-permission: anonymous` and a `policy.anonymous` row.
- **One generator, one router, one on-ramp** (rules 4, 5). `tools/gen/api` (in-house; no
  oapi-codegen) emits every Go type, decoder, validator and per-tag `Handlers` interface plus `Bind`.
  A module registers with `r.API(<id>api.Bind(m))` (EP-2); `apihost` serves on `net/http.ServeMux`
  and refuses to start when a route and the embedded document disagree. A handler receives a typed
  `Input` and returns a typed `Output`: it never sees `*http.Request`, `http.ResponseWriter` or the
  raw body. `apihost` reaches `authn`/`authz`/limits/step-up through `Ports` injected by
  `compose/server`, never by import.
- **One fixed middleware chain** (rule 5): recover, trace ID, per-IP rate limit, host binding,
  query-credential refusal, body cap, `Content-Type`, authentication, CSRF (cookie sessions, unsafe
  methods), per-principal rate limit, step-up, the `x-permission` check, buffer/validate/decode,
  handler, v2 encode, secret clean-up. An unauthenticated or unauthorised body is never parsed.
- **Exactly one permission per operation** (rules 3, 9). `x-permission` is an EP-6 permission ID,
  `authenticated` or `anonymous` (the last two only with their `policy.yaml` row). `authz` checks it
  in the chain; object-level delegation scope is checked again inside the Action (§11).
- **Tenant never travels in the API** (rule 11; ADR-0002 rule 5). It comes from the authenticated
  principal. A `tenant_id` or `X-Tenant-*` field in the contract fails T5.
- **Strict JSON at the edge, one decode path** (rule 6). `apihost` is the only code that touches a
  body: it buffers it (capped, pre-sized), validates it with `jsontext` (invalid UTF-8, lone
  surrogates, duplicate names, trailing data, depth > 32, `\u0000`), decodes it through
  `secretjson.Decode` with `encoding/json/v2` and `RejectUnknownMembers`, then runs the generated
  validator. Nothing is repaired (safe-primitives R3; `lessons.md`). `encoding/json` v1 is banned in
  product code. For a secret-bearing operation it then destroys every `Secret` in the `Input` and
  zeroes the buffer (safe-primitives §5.6).
- **Errors are a closed problem catalogue** (rule 8): `application/problem+json` with
  `type: /problems/<slug>` from `shared/problems.yaml`; only `apihost` writes status codes.
- **One `/api/v1` that only grows** (rule 7). Additive changes are free; a breaking change to a
  `stable` operation ships as a new operation beside the deprecated one (`Deprecation` and `Sunset`
  headers, `x-activediq-sunset`). There is no per-resource `/api/v2`; a coordinated `/api/v2` needs
  a superseding ADR. Every operation is `preview` or `stable`.
- **Limits are declared** (rule 10): a rate class per operation, per source IP and per principal,
  with no quota and no metering; body caps by default, 64 KiB for secret-bearing operations.
- **Server-built values only (tier W implements no primitive, safe-primitives §2.1):**

| Kind | API → web | web → API |
| --- | --- | --- |
| Object | `{guid, dn, rdns:[{type,value}]}`; `dn` and `rdns` are for display, rendered by `dn` | `guid` only (`GUIDRef`), never a DN string |
| Filter | `{ast, text}`; `text` is the canonical P1 rendering | a filter AST, or `{adminText}` for `ParseAdminFilter` |
| PowerShell | `DisplayOnlyPowerShell`, rendered by `pslit` | nothing |
| SQL | nothing | a report-definition AST |

  FF-SP3 scans `web/` for DN/filter-shaped literals, quote doubling and DN string splitting. In the
  contract these wire forms are bound to the primitive's own Go type (`FilterAst`, `ReportAst`,
  `GUIDRef`, `ObjectView`), never a generated copy (ADR-0004 rule 4 binding table).

---

## 7. The directory-connector layer and safe primitives

### 7.1 The connector contract (`proto/activediq/connector/v1`)

A versioned protobuf service of **typed** operations. It has no free-form query verb and no script
verb (ADR-0002 rule 3).

| Group | Operations (read, write and rights-check groups finalised in [connector-contract.md](connector-contract.md) v1.2; named-secret and auth rows remain a sketch) |
| --- | --- |
| Discover | `Describe` (provider kind, capabilities, naming contexts, DCs, health, write kinds supported), `DescribeSchema` (attribute syntax and flags per class). Contract §4 |
| Verify | `VerifyConnection` (contract §8.4): the connector's own rights check, run as the connector identity, read-only and never gated. AD checks V1–V9, Entra checks EV1–EV5; streams a header, `RightsFinding`s, the connector's computed `tier0` set and exactly one `completed`. Its findings are the DM-24 Findings and the connector computes their fingerprints |
| Read | `ScopedSearch{connection, delegation roots: GUIDRef[], filter AST, attrs, page}`, `Read{ObjectRef, attrs}`, `ReadPerDC{ObjectRef, attrs}` (exact last logon, ADM-084) |
| Write | `Plan` and `Apply` (contract §8.1). **The envelope only**: the write kinds (create, modify, move, rename, delete, restore, member add and remove, set password, unlock, assign licences…) each arrive with their own spec ticket, which adds the kind, its `WriteChange` arm, its touched-set rule and its conformance cases. `Apply` carries the step key `(operation, item, step)`, `attempt`, `acting_principal`, `plan_digest`, the DC pin and the `TargetPrecondition` (the plan's before-state; ADR-0005 rules 2, 4, 5), plus a request-scoped `Tier0Context` (contract §8.3) and the `WriteGateOverride`. The connector re-checks the digest, derives the touched set itself, refuses any `tier0` object (TM-D2) and enforces its own write gate (contract §8.2, TM-D1) as a second check behind the server's (DM-10.I11). No field carries a credential |
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

`connector/service` and `provider/*` are planned (T-1005, §4.3). Today `compose/connector` assembles
the verify, read and write handlers over one `ad.Session` and mounts them with `tunnelServer`, and
the embedded transport exists only in lab builds (`compose/server/labbootstrap_lab.go`), which repeats
that wiring. T-1005 replaces both with one `service.New` call.

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
  ticket, and security-architect reviews it there; custody is old T-0007's.
- Unsealing stays under `internal/connector/` (DM-11.I1). `cmd/connector` never links
  `credential/sealed` or `keys` (§2 rule 7), so "sealed only in the server" is checked, not just
  stated.

A remote connector that needs more than a local credential (an Entra certificate or a password
fallback on a remote host) is `[OPEN → old T-0007]`.

### 7.4 Where each primitive lives and who uses it

| Primitive | Package | Used by | Not by |
| --- | --- | --- | --- |
| P1 filter AST, renderer, admin-filter parser | `directory/ldapfilter` | modules (build ASTs), `connector` (render), `reports` (admin filters) | `web` |
| P2 DN, `ObjectRef`, `GUIDRef` | `directory/dn` | everyone server-side. It implements RFC 4514 itself and **does not wrap go-ldap's `ParseDN`**, because ADR-0002 keeps protocol libraries in the connector root. The go-ldap round-trip oracle runs from a test under `internal/connector/ad` | `web` |
| P3 codecs | `directory/attr/*` except `tsprops` | `connector` (decode), `inventory`, modules | `web` |
| P3 `userParameters` decoder, decode-only (safe-primitives §5.7) | `directory/attr/tsprops` (**planned**, T-1566) | **`connector/wirevalue` only** (the wire-value builder's identity gate, connector-contract §5.9.1; T-1739). Everyone else gets the typed `TsPropertiesValue` | everything else: `connector/ad`, `read`, `write`, the server, `inventory`, `sync`, `reports`, the API, modules and `web`. TS2(c) fails on any other importer (`tsprops`' own tests excepted) |
| P6 security descriptors | `directory/sd` | `connector` (rights, tier0: not yet wired), modules | `web` |
| `Secret` | `platform/secret` | `helpdesk`, `connector`, `keys`, `authn` | logs, audit details, errors, JSON |
| Scoped search, general-search controls (closed set, `ad.CheckControls`), GC resolution | `connector/ad` (`scoped.go`, `search.go`, `gc.go`) | `read` (the `ScopedSearch` and `Read` RPCs, through `read.ADSource` today and the `ObjectReader` facet of `provider/ad` after T-1005), `tier0`, `rights` | feature code (it gets `ScopedSearch` via the contract) |
| Escape controls (ASQ, show-deleted, phantom root), in named operations only | `connector/ad/scope` (**planned**; the first named op creates it, LF-30) | `provider/ad` named-operation facets (`RestoreDeleted`, `GroupMembersExpand`, `ForestWideLookup`, `ChangeTracking`) | everything else; the OIDs are banned outside it (`escape-control-oid`, FF-SP2) |
| P4 `psx` / `proc` / `pslit` | `connector/psx` (planned), `platform/proc`, `platform/pslit` | connector (sidecars), update client, API (display) | agents call `proc` only |
| P5 SQL | `platform/store`, `store/reportsql` | everyone through sqlc + `WithTenantTx` | hand-written SQL text (FF-SP2 `sqlconst`) |
| Tier N subset | `native/shared` | `passfilt`, `credprov` | — (it runs the same corpus) |

The corpus lives at `testdata/safe-primitives/<unit>.jsonl`. Every implementation in every tier runs
the records for the units it implements (FF-SP4); `testdata/safe-primitives/implementations.json` declares them.

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
| `operation.LiveFacts` | `platform/operation` | `directory/client` | **live** `authority.Facts` about one target, read on the pins, for the Plan and Apply authorisation checks (ADR-0005 rule 7; §8). Unlike the two above, it never answers from inventory | old T-0153 (port) and the connector spec (per-root-kind reads, old T-0051), security-architect |

The kernel ports (ADR-0003 F6; ADR-0005 rule 7) name kernel types only, because the kernel may not import
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
(a)–(e) at sign-in and at Plan. **For writes, ADR-0005 rule 7 decides it:** the correlation gate
is one of the facts `operation.LiveFacts` reads live at Plan and again at Apply, so only `matched`
authorises. **For sign-in** it is still open: `inventory` does not import `client` (the F1 order),
so whether the sign-in read is a method of `authn.DirectoryAnchors` or a port on
`directory/client` is decided in the `authn` build ticket with security-architect. Either way it
crosses the layer through a port, never through an import.

---

## 8. Job and operation engine

This restates [ADR-0005](../decisions/0005-operation-pipeline-and-audit-trail.md) rules 3–8. The
ADR's `transitions` block is the source of the state machines (O4 compares `transitions.go` with
it); if this section and the ADR disagree, the ADR wins.

```
 API / workflow / automation / palette / report results / undo
        | Input (schema from OpenAPI); Idempotency-Key -> an existing operation on retry
        v
 Plan (READ ONLY): Action.Plan -> steps, diff, preconditions, reversibility, DC pins
        |   then authorisation over live facts per item (LiveFacts) -> blocked items, plan_hash
        |   all items skipped -> no_change (done: no gate, one completed event)
        v
 Kernel holds (blast radius, irreversible, StepUp by a token, undo of an approved op)
        v
 Gate (EP-4): permission-only (default) | workflow -> allow | hold (Request or single approval) | deny
        |   approvals bind to plan_hash; the kernel decides who may approve
        v
 approved -> queued (chunk jobs inserted in the same transaction)
        v
 per step: claim (commit: write-ahead) -> client.Write: digest, live facts on the pins, Recheck,
           conditional write with the Clearance -> record outcome + audit event (one commit)
        v
 Verify on the pin (another DC, by name, after the verify window) -> verified | verify_failed
        v
 operation terminal: succeeded | partially_succeeded | failed | cancelled -> notify
 Undo = a new operation planned from Inverse against the live state
```

**State machines.** Operation: `draft → planning → planned → (awaiting_approval) → approved →
queued → running → succeeded | partially_succeeded | failed`, with `no_change`, `plan_failed`,
`rejected` and `cancelled` as the other terminal states and `cancelling` on the way to
`cancelled`. Item: `pending → planned → running → succeeded | failed | cancelled`, or `skipped` /
`blocked` at Plan; `succeeded` and `failed` can become `undone`. Step: `planned → applying →
applied → verified | verify_failed`, or `failed` / `not_run`; `verified` and `verify_failed` can
become `undone`.
- **Partial success is never success.** A blocked item makes the result at best
  `partially_succeeded`, and `cancelled` reports applied, verified and not-run counts.
- **Nothing to change is a success.** A plan whose every item is `skipped` ends `no_change`: no
  gate, no claim, no alert, one `operation.completed` event. Blocked items with none planned end
  `plan_failed`, because a refusal must be seen.
- **The refusal happens inside `applying`.** The authorisation re-check and the precondition are
  the first thing a claimed step does; a refusal is `applying → failed` with reason `denied` or
  `stale_state`. An expired plan is re-planned; an abandoned one is `cancelled` by the sweeper.
- **A `failed` step never hides a write**, so undo inverts the `verified` and `verify_failed`
  steps. The one exception, `outcome_unknown`, is reachable only by a password step, which is
  `Irreversible`.
- **Only the transition function writes a state**, and it writes the audit event in the same
  transaction.

**Idempotency at three levels.** Submission: `(tenant, principal, Idempotency-Key)`, kept 24 hours.
Automation firing: `(policy, version, firing)`. Step: `(operation, item, step)`. A directory has no
idempotency key, so **Apply is a conditional write** whose precondition is the plan's
before-state: an AD modify deletes the planned old value and adds the new one in one atomic request
([RFC 4511 §4.6](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6)), and a create fails if
the planned name is taken. Entra, and AD operations with nothing to compare, read and compare on
the pin just before the write (a declared residual). A retry that finds the after-state in place
returns `already_applied`.

**DC affinity.** Plan pins **one writable DC per AD naming context the operation reads or
writes**, including one read only for authorisation (a correlated AD object's domain, a
`group_members` root in another domain). Plan reads, the Apply re-check, the write and Verify all
go to the pin, which gives read-your-writes. Pins are not in `plan_hash`; a re-plan keeps a healthy
pin. If the pin is lost: unclaimed steps re-pin only after their preconditions are re-read on the
new DC (else `stale_state`); `applied` steps retry Verify on the pin within the verify window, then
read back from another DC, recorded `verified` with that DC named, or `verify_failed` with reason
`dc_unavailable` (DM-15.I3, DM-42.I3). Entra has no DC: Verify retries inside a per-provider verify
window and throttling honours `Retry-After`
([Graph throttling](https://learn.microsoft.com/en-us/graph/throttling)). Default limits: four
concurrent writes per (connection, DC), four per Entra tenant, two chunk jobs per operation.

**Job queue** (`platform/jobs`; ADR-0002 Jobs row as amended 2026-10-02 by old T-0209; DM-43). The
queue is our own table, `jobs`, and every access goes through `store`.
- **Enqueue** is an `INSERT` in the caller's `store.Tx`. A `BEFORE INSERT OR UPDATE` trigger
  refuses a `tenant_id` that differs from the transaction's tenant context, and any change to
  `tenant_id`, `kind` or `args`.
- **Claim** is one registered `WithPlatform` site: `UPDATE … WHERE id IN (SELECT … FOR UPDATE
  SKIP LOCKED LIMIT n) RETURNING`. It sets `running`, bumps `attempt` and sets
  `claimed_until = now() + kind timeout + grace`.
- **The body** gets a tenant minted from the row: one `WithTenant` (the default) or a tenant-bound
  runner (`ManagedTx`, which renews the claim while it runs).
- **Recording** (completed, retry with backoff, discarded after the last attempt) is fenced on
  `id`, `attempt`, `running` and the context tenant. A default-mode kind records in the body's own
  transaction.
- **Rescuer and cleaner** are two more registered `WithPlatform` sites, singleton under a platform
  lease (DM-06). The rescuer re-queues a lapsed `running` job. The cleaner deletes finished jobs
  after their retention period.
- **Wake-up** is by polling (1 s by default). `LISTEN` would need a connection outside `store`.
- **Arguments** are typed references only, at most 4 KiB (T5 `job-args-reference`, old T-0213).
  Per-tenant quota and claim fairness come before the `saas` profile hosts a second tenant
  (old T-0214).
- **Built (T-0002).** Migration `0002_jobs_jobs.sql` (the table, its checks, the unique-key index and the
  `jobs_guard` trigger, enabled `ALWAYS`) and `internal/platform/jobs`: `Enqueue`, `Cancel`, `Claim`,
  `Complete`, `Fail`, `Discard`, `Renew`, `Rescue`, `Clean`. The guard raises SQLSTATE `AD403`, which the
  package maps to `ErrCrossTenant`.
- **Built (T-0025).** `Registry` (`registry.go`): `Register(Kind)` takes a name, a required timeout, a mode
  (`ModeDefault` / `ModeManagedTx`), a `Platform` flag and an optional `ValidateArgs`; a duplicate, a zero
  timeout or an unknown mode registers nothing. `Registry.Enqueue` replaced the package-level `Enqueue`: it
  refuses an unregistered kind (`ErrKindUnknown`) or a tenant that does not fit the kind's scope
  (`ErrKindScope`; a tenant-less job must be a platform kind) before any SQL. `Registry.Leases()` feeds `Claim`
  (timeout + 30 s grace). The wrapper is `jobs.Runner.Execute` (T-0026): a default-mode body and `Complete` share one `WithTenant` transaction; a `ManagedTx` body gets a `TenantTx` runner (no tenant parameter) and the claim is renewed every half lease; failures store a code only. Platform jobs are not run by it yet.
- **Built (T-0027).** Migration `0003_jobs_platform_leases.sql` (`platform_leases`, a registered global table, DM-06 platform shape) and `jobs.AcquireLease` / `RenewLease` / `ReleaseLease`: one upsert statement takes a free or expired lease on the database clock and bumps a monotonic fencing token, so of N concurrent callers one wins and an old holder's renew and release return `ErrLeaseLost`. `RunRescue` / `RunClean` are the worker entry points: they run `Rescue` / `Clean` only under the `jobs.rescue` / `jobs.clean` lease and release it after. Tenant leases (DM-06 tenant shape) land with their first user. Schedules (DM-44): `jobs.Schedule` (T-0951, `schedule.go`) is the recurrence value and arithmetic: `Next`, `Check` (a missed run fires once; `Decision.UniqueKey` for idempotent enqueue), injected `WallClock`, typed `ErrIntervalBelowFloor` and `ErrUnknownZone`. Still to come: the stored schedule table (`next_run_at` in UTC) and the tick that enqueues.
- **Built (T-0028).** `jobs.Worker` (`worker.go`, `NewWorker(db, reg, WorkerConfig)`, `Run(ctx)`): claims tenant kinds only (`Registry.TenantLeases()` skips platform kinds) into free slots up to `Concurrency`, runs each through `Runner.Execute`, waits `PollMin`→`PollMax` (doubling, equal jitter, injectable `Clock`/`Jitter`) on an empty queue, and ticks `RunRescue`/`RunClean` under their leases. On ctx cancel it stops claiming, waits `ShutdownGrace` for bodies, then cancels them; `Execute` returns `Interrupted` and records nothing, so the claim lapses and Rescue requeues it (`ErrDrainTimeout` if a body ignores the cancel). No process entry point calls it yet.

**Job kinds** (EP-5, all tenant-carrying, all `ManagedTx`). The OperationItem is the system of
record; a job is only a driver.

| Kind | What it does |
| --- | --- |
| `operation.plan` | plans one chunk of a bulk operation |
| `operation.apply` | runs one chunk, including a held `Store` step once approved |
| `operation.verify` | drives deferred verification of `applied` steps (Entra, or a lost DC) |
| `operation.reconcile` | per tenant, under a lease: recovers steps whose claim lapsed |
| `operation.sweep` | per tenant, under a lease: re-drives stalled operations, detects terminal operations as a backstop, abandons stale plans, deletes expired transient secrets |

- **`ManagedTx`.** The wrapper establishes the tenant and hands the body a tenant-bound `TenantTx`
  runner; the body opens short `WithTenantTx` transactions and **never holds one across a
  directory call** (ADR-0002 Jobs row as amended).
- **Chunks** default to 100 items. A chunk job's unique key `(operation, plan_revision, phase,
  chunk_no)` only de-duplicates; correctness comes from the fenced claims.
- **Fenced claims.** A step is claimed only when a concurrency slot is free: `planned → applying`
  with `FOR UPDATE SKIP LOCKED`, a new `attempt` and `claimed_until = now() + lease` on the
  database clock, renewed while the call is in flight. Every recording `UPDATE` is predicated on
  `state = 'applying' AND attempt = $n`, so a superseded attempt's late result changes nothing.
  The reconciler takes over a lapsed claim by compare-and-set, bumping `attempt`. Plan-chunk
  results are predicated on `plan_revision`.

**The life of a directory step.**
1. **Claim** (transaction 1). The claim commits before the write, after `operation.started` was
   written at `queued → running`. These commits are the **write-ahead record**.
2. **Re-check, then write** (no transaction open). `client.Write` verifies the plan digest, reads
   the facts the step names live on the pins, calls `Step.Recheck` and sends the conditional write
   with the `Clearance`. The embedded connector unseals its credential in its own short
   `WithTenantTx`; a remote connector uses its local credential.
3. **Record** (transaction 2). The step moves on and its audit events commit **in the same
   transaction**. Several steps of a chunk may be recorded together, amortising the chain lock.
- **Transient errors** (connector unreachable, DC busy, `429`) keep the step `applying` and retry
  with the same key and a new attempt. After the attempt limit the runner reads the target on the
  pin: after-state → `applied`; before-state → `failed` (`retries_exhausted`); unreadable → left
  for the reconciler.
- **Crash recovery.** A step still `applying` past `claimed_until` is reconciled from the live
  state on the pin: after-state → `applied` (`recovered: true`); before-state → re-apply with the
  same key, or `not_run` if the operation is cancelling; anything else → `failed`
  (`stale_state`). **A password step is never re-applied:** it is `applied` if `pwdLastSet` is
  later than the claim, else `failed` (`outcome_unknown`) `[LAB: Windows, old T-0051]`. No step is
  ever left `applying` silently.
- **Stalls and terminal detection.** The sweeper re-enqueues work for an operation that has
  unclaimed work but no progress within the stall window. The transaction that records an
  operation's last non-terminal item runs its terminal transition; the sweeper is the backstop.

**`Store` Actions** (configuration writes): Plan runs first, with any I/O (a connection test, an
SMTP test send). Then **one transaction** checks the version and `plan_hash`, runs the gate,
re-checks authorisation, and runs Apply and Verify with the state changes and the audit event. If
it rolls back, the outcome (`failed`, or `denied` for a refusal) and its event are recorded in a
fresh transaction, retried up to 5 times in 30 seconds under one event ID; if that fails too, the
API answers `503`, a structured `audit.record_failed` log line is written and an alerting metric
raised. On the inline path no operation row survives a `503`, so nothing applies later what the
caller was told failed. A held `Store` operation runs after approval as one `operation.apply` job.

**What AG-1 means here.** For `Store` Actions the event commits with the change, literally. For
directory Actions it is **write-ahead plus same-transaction outcome**: between the directory write
and the recording commit the change exists without its outcome event, until the commit or
reconciliation; inventory history shows it meanwhile (threat model §11, as amended).

**Authorisation at Plan and again at Apply** (ADR-0005 rule 7; threat model §7.7). The pipeline,
never Action code, evaluates role ∩ delegation scope ∩ token scope for the **initiator chain** over
**live** facts, read through `operation.LiveFacts` on the pins, never over inventory. Apply reads
them immediately before the write. An approval never widens the initiator's authority; a requester
who lost the right while waiting fails `denied`. No role touches `tier0`, at either point.

| `root_kind` | Live fact | Read on |
| --- | --- | --- |
| `naming_context`, `ou_subtree`, `ou_one_level` | the target's parent chain by `objectGUID` (source and destination parent for a move) | the pin of the target's naming context |
| `group_members` (AD) | transitive membership in each asked root group, by an `ldapfilter` in-chain filter; deactivated links never count | the pin of the group's naming context (GC or that domain's DC: `[LAB: Windows]`, old T-0051) |
| `group_members` (Entra) | transitive membership via `checkMemberGroups`, at most 20 IDs per request | the Entra connection |
| `administrative_unit` | **direct** AU membership, plus `isManagementRestricted` | the Entra connection |
| `entra_tenant` | the target exists, is not deleted and belongs to the tenant | the Entra connection |
| AD entry with `include_correlated`, Entra target | the Entra target, the correlation gate (only `matched` authorises), and the correlated AD object's parent chain or membership | the Entra connection and the pin of the AD object's naming context |

- **Facts fail closed.** Each asked root answers `member`, `not_member` or `unknown`, and `unknown`
  (a read error, a timeout, a partial batch, a hidden-membership group without
  `Member.Read.Hidden`) refuses the target whether the root is an include or an exclude. The
  connector never uses Graph advanced queries for these facts.
- **Residual.** No directory makes a write conditional on ancestry, membership or correlation.
  Verify reads the same facts again and records `verify_failed` with reason `scope_changed`, and
  alerts (`high`). It also re-runs the `tier0` guard on every touched object's live re-read and
  takes `ApplyResponse.tier0_after_write` (an empty basis included, counted at once); the re-read
  uses rule 5's verify window and DC fallback, and only a fact still `unknown` after both counts as
  `tier0`, so a lost pin with a clean fallback read stays `dc_unavailable`. A `tier0` object after the
  write is `verify_failed` `tier0_after_write`, a `critical` alert, the operation cancelled, and an
  undo the `tier0` guard refuses (ADR-0005 rule 7 as amended by T-0129, TM-D23 rule 11).

**The approval gate (EP-4) and separation of duties** (ADR-0005 rule 8).
- **One kernel default and at most one registered gate.** `permission-only` allows (Plan already
  checked the permission); `workflow` matches WorkflowDefinitions and returns `Hold` with a Request
  or `Allow`. **A gate that errors or does not answer leaves the operation `planned`** and alerts.
- **Kernel holds run first and cannot be skipped:** an automation run over `max_objects`;
  irreversible steps when "approval for irreversible changes" is on; a `StepUp` Action started by
  a principal that cannot step up (a token, a policy), refused if no approval path exists; undo of
  an operation that needed approval. A hold no WorkflowDefinition matches gets the kernel's
  **single approval**: one approver holding `operation.approve` over every item's scope, or a
  `tenant-owner`.
- **Approvals bind to `plan_hash`.** A stale hash is refused; a re-plan with the same hash keeps
  its approvals.
- **The kernel decides who may approve**, not the gate: never a principal in the initiator chain;
  only an interactive human session; step-up for `Irreversible` or `StepUp` operations; and **no
  sock-puppet** in either direction for 30 days (created, granted `operation.approve`, bound,
  added to the granting group, or had the password or sign-in binding changed by the other side
  through activeDIQ). Directory-admitted (`sso` or `directory`) accounts are created by the system,
  which is how a pilot gets an approver on day one.

**Singleton work** (sync per naming context, schedulers, reconcile, sweep, checkpoints) holds a
lease in PostgreSQL, so any node can run it (ADR-0002 rule 6).

---

## 9. Audit pipeline

There are three streams. v1 ships the first two.

| Stream | What it records | Source | Store | Milestone |
| --- | --- | --- | --- | --- |
| **Our audit trail** | every Action step and gate outcome, sign-in, permission change and setting change, audit reads and exports, with the acting principal and the on-behalf-of chain | `platform/audit` | append-only tenant tables; one hash chain per tenant, chained at commit; signed checkpoints anchored outside the host; export + offline verify; SIEM forwarding via EP-9 (ADM-198) | v1 (ADM-137, 138; ADA-112; RMP-043) |
| **Directory change history** | what changed and when, including changes made outside activeDIQ, with originating DC and version, but not *who* | `directory/sync` (DirSync/Graph delta + replication metadata) | `inventory` history (§12) | v1 (ADM-005, without "who" for native changes, E2.4) |
| **DC events** | *who* made a change (5136/4738/4728…), logons, lockouts | `addc` agent module → `fleet` → event pipeline (EP-14) | partitioned event tables, if old T-0026 passes ADR-0001 rule 3 | M3 |

The `history` module joins the streams on `objectGUID` and time. An activeDIQ change is linked by
operation ID, and a native change by the correlated event from M3 on (FEAS §4.4 flow 3).

**How our audit trail works.** This restates [ADR-0005](../decisions/0005-operation-pipeline-and-audit-trail.md)
rules 11 and 12, which implement the threat model's audit guarantees AG-1…AG-9
([threat model §11](threat-model.md)). old T-0088 builds it and publishes the byte-level format
document. If this section and the ADR disagree, the ADR wins.

**The event.** Each event carries `tenant_id`, `seq`, `at`; `kind` and `kind_version`; the actor
and the on-behalf-of chain (API token, automation policy and version, request and approvals); the
verification factor; the source component and client address; the targets (connection, GUID,
class, display snapshots); the operation, item, step, request and correlation IDs; the outcome
(`success`, `failure`, `denied`) with a reason code; typed details; `prev_hash` and `hash`.
- An inline `Store` Action writes **one** event, the step outcome. Other operations write
  `operation.planned` (only if the plan is persisted), `operation.plan_failed`, one
  `operation.item.blocked` per item, the gate events, `operation.started`, the step outcome events
  and `operation.completed` or `operation.cancelled` with counts. `not_run` and `skipped` are
  counted, not evented.
- **Canonical form `adq-canon/1`:** a deterministic, length-prefixed, tagged binary encoding
  (strictly increasing tags, minimal varints, exact UTF-8, 16-byte UUIDs, int64 UTC microseconds,
  no maps, absent fields omitted). Decoders reject anything non-canonical. It lives in
  `audit/canon` and needs only the standard library.

**The chain.**
- `body_hash = SHA-256(adq-canon/1(event without prev_hash and hash))`;
  `hash_n = SHA-256("adq-audit-chain/1" ‖ 0x00 ‖ tenant_id ‖ uint64be(seq_n) ‖ hash_{n-1} ‖ body_hash_n)`;
  `hash_0 = SHA-256("adq-audit-genesis/1" ‖ 0x00 ‖ tenant_id)`. Tenant and `seq` are inside every
  link, so an event cannot be spliced into another tenant's chain or moved within its own. The
  genesis is public, so **trust comes from anchored checkpoints**, not from the chain alone.
- **Chained at commit.** `audit.Append(tx, kind, event)` buffers the event in audit's
  per-transaction slot on `store` (§5.1). `WithTenantTx` runs the body, then the single
  `BeforeCommit` hook, which `compose/server` sets to `audit.Chainer.BeforeCommit`, then `COMMIT`.
  When the slot holds events the hook: refuses a transaction that is not `READ COMMITTED`; locks
  the tenant's `audit_head` row (`SELECT … FOR UPDATE`, its own statement, the last lock taken,
  under a `lock_timeout`; no row fails closed); stamps `at = greatest(clock_timestamp(), head.at)`,
  hashes and inserts each event into `audit_event`; and updates the head.
  [Row locks](https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS) make a
  waiting appender re-read the committed head.
- **Fail-closed wiring.** `Append` refuses a transaction whose store has no audit hook; the hook
  is set once (a second set panics); the slot is sealed when the hook starts; a body cannot issue
  `COMMIT`, `ROLLBACK` or `SAVEPOINT`. A transaction that appends nothing never takes the lock.
- **Gapless and ordered.** `seq` order is commit order and a rolled-back transaction consumes
  nothing; `at` is monotonic per tenant, so time partitions are `seq` ranges. The unique index
  `(tenant_id, seq)` is the backstop against a fork. Budget: roughly 200–1,000 audited commits
  per second per tenant on local storage, about 100 with a synchronous standby
  `[UNVERIFIED: old T-0088 load test]`.
- **The head row.** `audit.InitTenant` runs in a new tenant's first `WithTenantTx`, called by the
  tenant-provisioning path (old T-0037), and inserts `(seq 0, hash_0)`, the first checkpoint key and
  two events. The runtime role holds `INSERT` and `UPDATE` on `audit_head` only, fenced by the
  primary key, no `DELETE`, and a genesis-only `BEFORE INSERT` trigger that recomputes `hash_0`
  and sets `at` itself. On `audit_event` and `audit_checkpoint` it holds only `INSERT` and
  `SELECT`.

**Signed checkpoints and anchoring** (DM-81, AG-6).
- Each tenant has an Ed25519 checkpoint key ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)),
  sealed under the tenant data key, with a **validity window in the chain**
  (`audit.checkpoint_key.created` / `.retired`). Routine rotation is yearly or on demand; the
  old key cross-signs the new key's chained `key.created` event (ADR-0005 rule 11); rotation
  after a suspected compromise is not cross-signed and goes to every sink at once.
- The `audit.checkpoint` job (per tenant, under a lease) signs the head every 1,000 events or 5
  minutes if anything was appended, plus the last event of every time partition, the head before
  every export, and the head on clean shutdown. The signed statement is `adq-canon/1` of
  `{tenant_id, seq, hash, signed_at, key_id, prev_checkpoint_seq, prev_checkpoint_hash}` under the
  domain string `adq-audit-checkpoint/1`.
- **Anchors leave the host:** every checkpoint and key event goes to every SIEM sink as its own
  message; every export ends at a fresh checkpoint and carries all checkpoints in its range; the
  console shows the latest checkpoint hash and key fingerprint for out-of-band recording. **Seven
  days with no anchor alerts `tenant-owner` accounts.** Root on the host can rewrite only the tail
  after the last checkpoint that left the host.

**Export and the offline verifier** (AG-7, AG-8).
- `adq-audit-export/1` holds a manifest (tenant, `seq` range, format versions, key fingerprints
  and their chained windows), the canonical events, the checkpoints, and a personal side file
  (values and salts; a pseudonymous export omits both). Exporting needs step-up and is audited;
  reading the audit trail is audited and needs no step-up.
- **`adq-audit-verify`** (`cmd/auditverify`) is a standard-library Go binary for Windows, Linux
  and macOS, published with each release, linking only `audit/canon` and `audit/chain` (§2 rule
  7). It checks encoding, `seq` continuity, every link from genesis or a retained checkpoint, every
  signature against the key windows, the anchors, every personal value against its commitment,
  that every missing value is explained by an erasure event tied to an erase step or trigger, and
  that every retention gap is explained by a purge event. **It needs a trust root** (a fingerprint
  pinned out of band, or an anchor); without one it reports `UNANCHORED`, never `OK`.

**Retention and SIEM.**
- Retention is a tenant setting per record class (ADM-206). Purges run on the maintenance path
  under the owner role, one time partition at a time (its last `seq` is a checkpoint), only with a
  recorded archive export unless `purge_without_archive` is on (a step-up, audited setting). Each
  purge appends `audit.retention.purged` and deletes, through `personal`, the personal values only
  the purged events reference and the salts of subjects left with no values and no hold.
  **Checkpoints are never purged.**
- `audit.forward` (per tenant and sink) reads by `seq` watermark and sends events, checkpoints and
  key events through EP-9 sinks, at least once, de-duplicated by `seq`, **never on the write
  path**. A sink more than 15 minutes behind, or failing repeatedly, alerts. Sink changes need
  step-up. Forwarded events carry personal values in clear unless the sink is `pseudonymous`.
- **Built (T-0304).** `audit.RegisterJobs` registers both kinds (ManagedTx, EP-5). Each run queues its
  successor first, keyed by interval bucket (`t<unix/interval>`), so the cadence cannot pile up or
  fork and survives a failed run; `Jobs.ScheduleCheckpoint` (also `Checkpointer.StartCadenceOnInit`) and
  `ScheduleForward` start it. `audit.checkpoint` takes the platform lease `audit.checkpoint.<tenant>`
  and signs when 1,000 events or 5 minutes have passed; signing also takes a per-tenant advisory
  transaction lock, so a worker whose lease lapsed mid-run cannot fork the checkpoint chain.
  `audit.forward` takes `audit.forward.<tenant>.<sink>`, sends events then the checkpoints they
  cover through the `ForwardSink` port in batches of 500, and advances `audit_forward_cursor`
  (migration 0012) only after `Deliver` returns nil. A failure stores `sink_unavailable` on the job
  (Backoff retry) and in the cursor (`GetForwardStatus`: lag, failures). Not yet: the T-0139
  encoders and concrete sinks (adapters implement `ForwardSink`), the lag/7-day alerts, and wiring in
  `compose/server` (its registry is still empty).

**Personal values are erasable** (ADR-0005 rule 12; DM X11).
- **The chained form holds no clear personal value.** It holds a `PersonalRef`: a subject
  reference (`dir:<connection>:<objectGUID>`, `acct:<account_id>`), a `value_id`, the field, and
  `commitment = HMAC-SHA-256(key = subject_salt, msg = adq-canon/1({"adq-personal/1", value_id, field, value}))`.
  The clear value lives in `platform/personal` (`personal_value`) and the 256-bit salt in
  `personal_subject`; the runtime role cannot `UPDATE` either.
- **Personal** means display snapshots (DN, name, UPN, mail, sAMAccountName), client addresses,
  free text, and attribute values the attribute catalogue classes `personal`; **an unknown
  attribute is personal by default**. GUIDs and SIDs stay in clear: the result is pseudonymised,
  not anonymised ([GDPR Art. 4(5)](https://eur-lex.europa.eu/eli/reg/2016/679/oj)).
- **Erasure** deletes a subject's salt and values; the event, its GUIDs and its hash remain, the
  chain still verifies, and the UI shows `[erased]`. It appends `personal.subject.erased`, which
  must reference a verified `personal.subject.erase` step or a recorded trigger. Triggers: the
  ADM-207 setting on a directory-object purge, an explicit `tenant-owner` request (step-up,
  `Irreversible`), and deletion of an activeDIQ account. A legal `hold` blocks all three.
- **One shape for every append-only record.** DM-80 events, DM-18 change records (old T-0065) and
  DM-66 comments all store `PersonalRef`s through `personal`'s Go API. Mutable records are erased
  in place.
- **What erasure cannot reach:** SIEM copies, earlier non-pseudonymous exports and database
  backups keep values until they expire. So every erasure is also written to an **erasure register
  in the blob store, outside the database**, and **the restore runbook replays the register after
  every restore**, so a restore cannot resurrect an erased subject. That step belongs to the E2.12
  backup and restore runbook (§16).

---

## 10. Reporting

The build contract is [modules/reports.md](modules/reports.md) (T-0865). Result storage is
[ADR-0010](../decisions/0010-report-results-stored-as-rows-in-postgres.md) (`accepted` 2026-11-01, T-0968). This
section summarises both, and the names and signatures in it are copied from the module page. If
they differ, the module page wins, and this section is corrected in the same change.

- **A report is data:** a `report.Definition`, an AST over one registered **dataset** (EP-8). The
  canned library and the ME report crosswalk (MIG-05) are shipped definitions, not code. No report
  accepts LDAP filter text or any other text that is executed (FR-05).
- **Datasets** live in `report.Host`. `compose/server` hands `inventory.Datasets()` to
  `report.NewHost` under the owner key `inventory`. Modules add datasets through
  `Registrar.Dataset` (§4.1). `Boot` checks that each dataset names only its owner's tables. At 2a,
  `reports` registers no dataset of its own: it consumes inventory's.
- **One compiler.** `store/reportsql` is the only producer of dynamic SQL (§5.1):
  - `reportsql.NewRegistry(opt reportsql.Options, ds ...report.Dataset) (*reportsql.Registry, error)` pre-quotes every
    identifier once;
  - `reportsql.Compile(q report.Query, ds reportsql.Dataset, scope authz.ReadScope, in reportsql.Inputs) (reportsql.Query, error)`
    renders the query, and `CompileCount` (same signature) renders its count;
  - `reportsql.Exec(ctx, tx, q, batch, fn)` runs the result as one server-side cursor in the
    caller's transaction.

  Operators, sort directions and value types are enums, and every value is a bind parameter (P5
  rules 3 and 13). Inside `modules/reports`, only `reports/run` calls `Compile`, `CompileCount` or
  `Exec` (RP3).
- **Authorisation is in the query.** Scope reaches the compiler only as an **`authz.ReadScope`**:
  - a union of grants, one per assignment, each made of include and exclude terms of kind
    `naming_context`, `ou_subtree` or `ou_one_level`;
  - AND-ed with an optional token layer.

  The one producer is `rbac.ReadScopes.For` (§11). **Only `store/reportsql` renders the terms into
  SQL**: `ReadScope.Terms` and `.Token` may be called only in `authz` and `store/reportsql` (RP2).
  The terms render over GUID ancestry in inventory, and a row whose ancestry is not
  `ancestry_complete` is out of scope, so counts and pages come after trimming (safe-primitives
  LF-39, FR-07). Rendering fails closed. An empty scope, an unknown kind, a zero root or an
  incomplete ancestry compiles to `FALSE`: the run succeeds with zero rows, and its
  `scope_applied` records the reason. The admin's `report.Narrowing` can only narrow (AND).
  RP6 proves that the compiled SQL admits exactly what the per-target oracle
  `authz.Evaluator.AuthorizeRead` admits (modules/reports.md §4).
- **Results are stored rows** (ADR-0010). A run (DM-72, `report_runs`) streams its compiled query
  once into `report_run_rows`, a table owned by `modules/reports` (RLS + `FORCE`), and flips to
  `succeeded` in the same commit.
  - Pages, sorts, totals, exports, digests and deliveries read the stored rows with static SQL and
    never re-query a dataset. The total is `row_count`, never a `COUNT(*)`.
  - A stored run is readable only by its runner, and only while the runner's read-scope
    fingerprint equals the one the rows were trimmed with (modules/reports.md §6.6).
  - Rows expire with the run (7 days, `[PROPOSED]`). An expired run is re-run, never served.
- **Per-DC values are read live.** USR-04 and PWD-03 call the port `report.PerDCReader`. It is
  implemented over the connector's `ReadPerDC` through `directory.Services` (row P5 of the module
  page). The connector fans one read per candidate object out over the domain's DCs. A read cap is
  checked before any read happens. Scope trimming has already happened in SQL, and the per-DC
  values fill the stored rows. The port keeps a later stored per-DC dataset possible without
  touching the module.
- **Freshness.** Each run records its `as_of`, and a label taken from inventory's per-NC
  last-successful-pass watermarks (`inventory.Freshness`, row P1). A report says how fresh its
  data is, never "live" when it is not (DM-72.I1, ADM-084).
- **Scheduling** uses `jobs` (DM-44, row P4). A firing creates a run with the schedule owner's
  authority at that moment. **Delivery** uses `notify` (DM-84 Delivery, row P3), and a delivery
  link is authorised by its Delivery row. **Exports** serialise the stored rows through the
  `platform/export` encoders into `blob`. Their digest equals the run's (RP5), and export code
  never calls `reportsql`. **Act-on-results** hands the selected GUIDs to an Action's `Plan`
  (ADM-098, after 2a).
- **Enforcement:** `fitness-reports` RP1–RP11 (§17).

---

## 11. Authentication, RBAC and delegation

- **Principals:** console users (technicians), API tokens, connectors and agents (mTLS), and
  anonymous end-user flows (resolved by hostname binding, ADR-0002).
- **Sign-in:** SAML/OIDC SSO (ADM-143). Local break-glass accounts always require MFA (ADM-142).
  AD-identity sign-in goes through the connector's `VerifyUser`/SPNEGO, never through an LDAP bind
  from platform code. HTTPS only and no default credentials (ADM-145).
- **RBAC:** modules declare permissions (EP-6). A role is a set of permissions. An assignment is
  principal (or group) × role × scope. Built-in roles ship as data (ADM-126).
- **Delegation scopes for reads and lists** (ADM-127–130) have one producer:
  `rbac.ReadScopes.For(ctx, tx, tenant, chain, perm) (authz.ReadScope, error)` (T-0882).
  - **Grants.** It builds one grant for each assignment the account holds, directly or through
    its groups. Each include and exclude root becomes an `authz.ScopeTerm` through the EP-6
    `ScopeEvaluator` that `delegation` registers for that root kind: `naming_context`,
    `ou_subtree` or `ou_one_level` (T-0880, T-0881).
  - **Kinds with no evaluator contribute nothing.** A root kind with no evaluator (`entra_tenant`,
    `tier0_scope`, `tenant`, …) adds nothing to a directory read, and the reason is recorded. An
    assignment with an exclude of an unknown kind is dropped whole.
  - **Tokens.** An API token's scope is a separate layer, AND-ed with the grant union and never
    merged into it.
  - Tier-0 does not narrow reads (DM-35.I5), and correlation-derived (`Via`) grants contribute
    nothing at 2a.
  - **One producer, one renderer.** Only `rbac` and `authz` may construct a read scope
    (`authz.NewReadScope`, RP2). The scope is rendered into SQL only by `store/reportsql` (§10).
    The old per-object post-filter over candidates is deleted (T-0882). The per-target oracle is
    `authz.Evaluator.AuthorizeRead`, and RP6 checks the compiled SQL against it.
  - The full rules are in [modules/reports.md §4](modules/reports.md).
- **Delegation scopes for writes.** The pipeline evaluates them at Plan and again
  immediately before the write over **live** facts on the pinned DC, per root kind (ancestry,
  group and AU membership, correlation), so a moved or removed object cannot escape its scope
  between check and write (§8; ADR-0005 rule 7).
- **Help-desk caller verification (ENH-09):** an EP-10 method (email/SMS OTP to contact data
  already held in AD or HR, or TOTP) gates `helpdesk` Actions. The factor used is recorded in the
  same audit event as the reset.
- **Our own AD identity holds delegated rights only** (ADR-0002 rule 9). `hardening` generates and
  verifies those rights (ENH-08, FD-08).
- **Per-technician attribution in AD's own logs** (ADM-134 leapfrog). Our audit trail always records
  the technician. How AD's own logs show the technician is still open. The options are Kerberos
  constrained delegation (S4U2Proxy) from the connector identity, and per-session technician
  credentials held only in connector memory. `[OPEN → ADM-134 spec + old T-0007]`

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
  - `old` and `new` are stored as `PersonalRef`s through `platform/personal`, so erasure reaches
    history too (§9; ADR-0005 rule 12; old T-0065).
  - Exact shapes: old T-0006 (domain model) and old T-0026 (ingest benchmark).
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
| `cmd/agent` + `addc` | every DC | server `fleet` | dials out over mTLS; no listening port (ADR-0001 tier A) | `skenzeriq.agent.v1` + `activediq.addc.v1` (old T-0040) | M3 |
| Password filter `native/passfilt` | LSASS on writable DCs | the `addc` module on the same DC | local named pipe ACL'd to the agent's service SID; no network I/O in the LSASS path; policy is a signed document cached by the agent | IPC format: old T-0024 + old T-0040 | M4 |
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
2. **A write** (e.g. bulk modify, ADM-034). API (`Idempotency-Key`) → `operation` plans: the
   Action's `Plan` (live read on the pinned DC, diff, reversibility), then authorisation of every
   item over live facts → UI shows the preview with `Lossy` and `Irreversible` steps → kernel holds
   and gate (approvals bind to `plan_hash`) → `operation` enqueues chunk jobs → per step: claim
   (write-ahead commit) → `client.Write` (digest, live re-check, `Clearance`) → connector, pinned,
   conditional write → record the outcome with its audit event in one commit → `Verify` on the pin
   → `notify` (§8). The change also reaches `inventory` through the change feed and is linked to
   the operation ID.
3. **Help-desk reset** (ADM-136 + ENH-09). The technician opens the caller → `authn` sends an OTP
   to the caller's contact data from `inventory` → the caller reads the code back → `helpdesk`
   `reset+unlock` Action (`SetPassword(Secret)` with the policy-hints control) → one audit event
   that records the verification factor. The target is ≤ 3 interactions (ENH-01 budget).
4. **Scheduled report** (ADM-101).
   - `jobs` fires `reports.schedule.fire`, which creates a run with the schedule owner's
     authority (`rbac.ReadScopes.For`; a disabled owner pauses the schedule).
   - `reports.run` compiles with that scope through `reportsql` and stores the rows (ADR-0010).
   - `reports.export` serialises the stored rows through `export`.
   - `notify` delivers and records the DM-84 Delivery, which authorises the delivery links.
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
| ADM-023 | `objects` | `provider/ad` SMB + SD primitive (old T-0028) for home and profile folders; `go-smb2` register row first |
| ADM-027 | `objects` (one flow for AD + Entra) | `provider/entra`, `m365` licence Action |
| ADM-038 | `objects` (`RestoreDeleted`, a named op) | `connector/ad/scope` (show-deleted control only here) |
| ADM-057 | `objects` (computer reset/restore) | `provider/ad` |
| ADM-021, 022 | `helpdesk` (password generator, secure options) | `platform/secret` |
| ADM-060 | `helpdesk` (`ReadSecret` LAPS/BitLocker) | `connector` named secret ops; spike E1.4(d) (§3.4) |
| ADM-136 | `helpdesk` + `authn` caller verification (ENH-09) | `audit` |
| ADM-083, 085, 086, 087, 093, 099 | `reports` (definitions as data; [modules/reports.md](modules/reports.md)) | `platform/report`, `store/reportsql`, `inventory` datasets, `authz.ReadScope` from `rbac` |
| ADM-084 | `reports` | `report.PerDCReader` over the connector's live `ReadPerDC` (modules/reports.md §6.5) |
| ADM-097 | `reports` (builder) + `web/src/modules/reports` | `reportsql` |
| ADM-098 | `reports` → `operation` (act on results) | EP-3 Actions of other modules, by ID |
| ADM-100 | `reports` (exports serialise stored run rows, ADR-0010) | `platform/export`, `blob` |
| ADM-101 | `reports` | `jobs` (DM-44), `notify` (DM-84 Delivery) |
| ADM-125, 126, 127, 128, 129, 130, I360-020, ERP-014, RMP-042 | `delegation` (root-kind `ScopeEvaluator`s) | `authz` (EP-6), `rbac.ReadScopes`, `inventory` ancestry |
| ADM-134 | `audit` + `delegation` | `connector` acting principal; AD-side attribution `[OPEN]` (§11) |
| ADM-137, 138, ADA-112 | `platform/audit` | `reports` dataset |
| RMP-043 | `platform/audit` | `notify` SIEM sink |
| ADM-142, 143, 145, ADA-111, ADA-116, ADSS-126, RMP-044, M365-018, ERP-017 | `platform/authn` + `apihost` hardening | `connector` SPNEGO/`VerifyUser`; old T-0007 |
| ADM-146, 148 | `lifecycle` (cleanup) | `reports` → act on results; `objects` Actions |
| ADM-159 | `connections` (Entra onboarding: customer app registration, certificate) | `keys`, `connector/credential` |
| ADM-161, M365-005 | `m365` | `provider/entra` |
| ADM-162, 164, M365-007 | `objects` on the Entra provider | `provider/entra` |
| ADM-169 | `inventory` correlation + `web/src/modules/objects` hybrid view | `sync` (Graph delta) |
| I360-003 | `sync` (Graph delta) | `provider/entra` |
| I360-002 | `sync` + remote connector (outbound-only, DirSync) | `fleet`, §7.2 |
| ADM-188, 189 | `api/openapi` + `apihost` | ADR-0004 (both map onto `/api/v1`, rule 7) |
| ADM-204 | `platform/notify` | each module's templates |
| ADM-205 | `platform/notify` (mail, SMS gateway, egress proxy) | — |
| ADM-209, RMP-046 | `platform/update` + `packaging/` release train | ENH-07 spec, old T-0027 signing |
| ADM-210 | `compose/server` (stateless nodes) + `directory/client` (redundant connector bindings) | leases (`jobs`), PostgreSQL HA (customer) |
| ADM-212 | `connections` + `connector/ad` (LDAPS, CBT and GSSAPI bind built in T-0092/T-0560; DC locator and DC affinity planned there) | old T-0023 |

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
| ~~Module system, import DAG, generated lists, table ownership, `fitness-modules`~~ | **Decided:** [ADR-0003](../decisions/0003-module-system-extension-points-only-on-ramp.md), ratified 2026-10-02 (old T-0045); restated in §2, §4.1, §5, §7.3, §7.5 |
| ~~`platform/module` migration to the concrete `Registrar`, `Boot`, `moduletest`; empty `platform.Deps` and `directory.Services`; `0001_tenant_tenants.sql`~~ | **Done:** old T-0144 |
| Credential port method set (create, rotate, revoke, describe) | the `connections` build ticket, security-architect reviews (custody: old T-0007) |
| `authz.Membership` and `authn.DirectoryAnchors` semantics, and where the DM-20.I5 live re-check sits (§7.5) | the `authz` and `authn` build tickets, security-architect reviews (ADR-0003 F6) |
| Change-feed Registrar method for attribute-triggered automation (ADR-0003 F3) | the first ticket that needs triggered automation (E2.9) |
| ~~Shape of `operation.Catalogue()` (ADR-0003 F4) and gate interplay with Actions~~ | **Decided:** ADR-0005 rules 1 and 8; restated in §4.2, §8 |
| Freeze of `platform/module` (`// Frozen:` line), after the rule 9 paper check and the first two modules | solution-architect, once `connections` and `objects` have shipped through EP-1 (ADR-0003 rules 8–9) |
| ~~OpenAPI layout, generators, router, versioning, strict JSON, `x-permission`; the Registrar's `API` registration shape (`apihost.TagHandlers`)~~ | **Decided:** [ADR-0004](../decisions/0004-public-api-contract-openapi-first.md), ratified 2026-10-02 (old T-0046, D-0014); restated in §1, §4.1 EP-2, §6. Generator and skeleton delivered (old T-0147) |
| `apihost` itself: `Build`, `Ports`, the middleware chain, the rule 6 decode and secret clean-up; the `secretjson` allowance for `apihost` | T-0033 |
| TM §7.6 amendment for break-glass and SPNEGO sign-in routes; `policy.yaml` seeding (`anonymous`, `authenticated`, `secretResponses`, `stepUp`); default numbers per rate class (TM-Q2) | T-0032 (security-architect) |
| Published deprecation and support window for `/api/v1` (ADR-0004 rule 7; leaves the building) | T-0036 (decision prep for the CEO, before GA) |
| ~~Action contract, operation state machine, audit-trail guarantees; whether configuration writes (templates, roles, policies, `migration` imports) are Actions~~ | **Decided:** [ADR-0005](../decisions/0005-operation-pipeline-and-audit-trail.md), ratified 2026-10-02 (old T-0047, D-0015): configuration writes are Actions; restated in §2.3, §4.2, §5.1, §7.5, §8, §9 |
| Operation kernel: `platform/operation`, `operation/step`, `platform/authority`, the `LiveFacts` port, `operationtest` | old T-0153 (security-architect reviews) |
| Audit chain, head row, checkpoints and key windows, export, `adq-audit-verify`, `platform/personal` and its erasure register; byte-level format document for `adq-canon/1`, `adq-audit-export/1` | old T-0088 |
| `ManagedTx` job mode and transactional insert; kernel tenant initialisers (`audit.InitTenant`) on the provisioning path | old T-0084; old T-0037 |
| Per-root-kind live reads (GC vs that domain's DC for cross-domain groups), hidden-membership detection, Graph ETags for conditional writes, Graph read-after-write lag, `pwdLastSet` on reset, AD result codes for single-valued modifies | connector spec and lab, old T-0051 (ad-expert) |
| Default for ADM-207 erasure, legal-hold UX, minimum retention; customer wording of "pseudonymised" | audit and compliance PRD |
| Restore runbook step: **replay the erasure register after every restore** (ADR-0005 rule 12) | E2.12 backup and restore runbook |
| Paths in skills and safe-primitives.md | **old T-0048** (chore) |
| Agent host and module contract (EP-13, its constructor signature and dependency struct, and the agent tier's rule 9 paper check); password-filter IPC | old T-0040 (+ old T-0024) |
| Entities, lifecycle states, inventory and history shapes | old T-0006, old T-0026 |
| Trust boundaries per profile; Graph permissions; delegated-rights verification; ADM-134 attribution; edge surface; remote-connector credentials beyond gMSA/keytab (§7.3) | old T-0007 |
| Security-descriptor primitive (ADM-023, ENH-08, `fileserver`) | old T-0028 |
| Output encoders | old T-0029 |
| CBT bind on go-krb5 (Samba proven by old T-0023; go-krb5 pinned to a `main` commit per ADR-0001 erratum E1); WS2025 proof; LAPS from Linux | old T-0133; E1.4(d) |
| Repository scaffold implementing §1 | old T-0014 |
| Update protocol and rings; OCI apply mechanism | ENH-07 spec (M2 plan, old T-0031) |
| Bundled DB standby and DB backup on `linux-oci` | E2.12 PRD (old T-0031) |
| SAML library; Graph SDK vs thin client; S3 client; go-smb2; go-msrpc | the first ticket that needs each one, with a licence-register row first (ADR-0001) |
| `mgmthelper` identity vs connector-driven GPMC | M3 GPO spec |
| ~~Search index technique (no second store)~~ | **Decided:** ADR-0011 (`ratified`, T-1093): inventory + `pg_trgm`, one statement through `reportsql.CompileSearch`; rev 3 (T-1314): fuzzy probe through a tenant-led trigram posting table, because `pg_trgm` operators are not leakproof under RLS (T-1335). Still open from it: Entra read-scope kind (T-1131), recents (T-1130), identifiers outside the 2a sync set (T-1129) |

---

## 17. Enforcement summary

| Rule | Check | Ticket |
| --- | --- | --- |
| Language zones, cgo-free Go, one stateful service, licence register, declared exceptions | `fitness-stack` F1–F5 (`tools/fitness/stack/`, in `make ci`) | old T-0022 (done) |
| Tenancy from migration 1, RLS, roles, isolation, static tenancy checks (incl. FF-SP7) | `fitness-tenancy` T1–T5 (`tools/fitness/tenancy/`, in `make ci`; rules: [tenancy-fitness.md](tenancy-fitness.md)) | old T-0036 (done) |
| Domain-model keying and append-only (domain-model §0): directory tables keyed by GUID never DN/SID/name (X3), no secret-attribute columns outside sealed ones (X4), append-only tables never UPDATE-able, no state column (X5), table kinds declared in code | `fitness-domain-keys` X3–X5, REG (`tools/fitness/domainkeys/`, in `make ci`; rules: [domain-keys-fitness.md](domain-keys-fitness.md)) | old T-0050 |
| Profiles by composition, planes, both transports, UEM boundary, platform root extractable | `fitness-profiles` (`tools/fitness/profiles/`, in `make ci`): P1, P7, U1, U2 run today; P2-oci, P2-msi, P3–P6, U3 and U4 are in its activation table and become mandatory when their subject lands, or print `ACTIVE, DEFERRED` while an ADR-approved, expiring deferral covers the gap (ADR-0002 E-3) | old T-0038 (done) |
| Module system (ADR-0003): import graph, module islands, generated lists and module pages, Registrar only, constructor bound, composition root, closed catalogue, table ownership (static and catalog), binary hygiene, web mirror, exemptions, self-test (§2, §4.1, §5) | `fitness-modules` M1–M13 (`tools/fitness/modules/`, in `make ci`; the old T-0014 subset of §2 rules 1–5, 7, 8 runs today; M13 is EP-11 the only provider on-ramp, §4.3) | T-0991 (M7), T-0990 (the rest; old T-0141), T-1006 (M13) (ADR-0003 becomes `accepted` when it is green) |
| Public API (ADR-0004): layout and bundle, dialect, one permission per operation, route set per profile and hostname with an HTTP probe, generated client and server, strict JSON (static, type closure, corpus, ajv cross-check), secrets out, versioning, problems, limits, policy hygiene, responses conform (§1, §6) | `fitness-api` A1–A14 (`tools/fitness/api/`, in `make ci`; A9 is T5 in `fitness-tenancy`). A1 and A13 run today; every other check prints `inactive` until its input exists ([ci-gates](../standards/ci-gates.md)) | A1, A13: T-0011 (done); static half: T-0017; runtime half: T-0018 (ADR-0004 becomes `accepted` when none is inactive and all are green) |
| Operation pipeline (ADR-0005): step escape, write surface, configuration writes and table write classes, state machine, registry and contract coverage, contract and pipeline behaviour, kernel DAG (§2.3, §4.2, §8) | `fitness-operation` O1–O9 (`tools/fitness/operation/`) | old T-0154 (ADR-0005 becomes `accepted` when both rows are green) |
| Audit trail (ADR-0005; threat-model TM-F-AUDIT): role grants and the genesis trigger, AG-1/AG-2 and hook wiring, concurrency, seeded-tenant verify, tamper corpus, anchoring, classification, AG-8 coverage, retention (§9) | `fitness-audit` A1–A9 (`tools/fitness/audit/`) | old T-0154 |
| Reports (ADR-0010; [modules/reports.md §9](modules/reports.md)): `reportsql` provenance, one read-scope producer and one renderer, compiler calls confined to `reports/run`, stored runs immutable and expired runs not served, export digest equals run digest, compiled scope equals the per-target oracle, library lock, derived columns, run reads bound to runner and scope, delivery links bound to the Delivery row, no dataset reveals anything outside scope (§10) | `fitness-reports` RP1–RP11 (`tools/fitness/reports/`, in `make ci`; RP1 runs inside FF-SP2 `sqlconst`; [runbook](../runbooks/reports-fitness.md)). A check whose code has not landed prints `pending`, which is not a pass | T-0873 (done). ADR-0010 `accepted` 2026-11-01 at row B14 of the module page (T-0968): RP3–RP5 green in `make ci` |
| Universal search (ADR-0011): one scope renderer (`Terms`/`Token` only in `reportsql`; no `Admits`/`SearchRoots` callers; `CompileSearch` only from `inventory`; no SQL re-deriving scope from the RBAC tables), no `LIKE`/regex or string-built search SQL, no views or functions over the RBAC tables, `inventory_search_keys` and `inventory_search_trigrams` read only by the template (the one listed function over them is the invoker trigger function `inventory_search_trigrams_sync`, with a fixed `search_path`, attached by exactly three statement-level triggers), every index on those two tables leads with `tenant_id`, trigram operators and functions only in the template (plus `show_trgm` in that function); fuzzy plan under `FORCE` RLS uses the posting primary key (index, index-only or bitmap) and a correlated recheck, with no Seq Scan on the key, posting or object tables, and the longest (32-rune) fuzzy query stays inside the timeout; a two-tenant test shows identical rows examined and blocks read per relation with the other tenant empty, equal and 10× (T-1335); search scope equals the read oracle below and above the work ceiling, hostile, folding and secret-attribute vectors, bounded rows examined (asserted on the scan nodes), p95 ≤ 200 ms at 50k objects | `fitness-search` SE1–SE5 (`tools/fitness/search/`, in `make ci`; SE6 in `make fitness-nightly` as `fitness-search-nightly`; [runbook](../runbooks/search-fitness.md)). A check whose code has not landed prints `pending`, which is not a pass | T-1126 (done); T-1335 AC7 extends SE1/SE3/SE5 for the posting table. ADR-0011 becomes `accepted` when SE1–SE5 are green with none pending and SE6 has passed once |
| Safe primitives: imports, banned APIs, literal shapes, corpus, fuzz, oracles, `psx` manifest; the one secret decode path (`secretjson`: decode only via `secretjson.Decode`, called only from `apihost`, no string tokens in a `Secret` decoder; safe-primitives §5.6, ADR-0004 rule 6) | FF-SP1–SP9 (`fitness-safeprim`, in `make ci`) | delivered under the earlier board numbering (old T-0033, old T-0034) |

Rows marked "done" run in `make ci` today; the others do not yet, or run only in part. This
blueprint moves to `accepted` when a human has read it end to end. The rules it states become
*enforced* only as each row's check goes green in `make ci`.

**Permission catalogue, T-0063.** `compose/server/catalogue.go` replaces the hand-listed `apiCatalogue`: `permissionCatalogue()` is the union of every `rbac.BuiltInRoles` permission and the module-declared operation permissions (`moduleOperationPermissions`, named by the owners' constants), sorted and unique. It is passed to `apihost.Build` (an operation whose `x-permission` is missing fails Build) and to `consoleAuthz`, which denies a permission outside it before RBAC is asked. The policy comes from the embedded `policy.yaml` (`apihost.LoadPolicy`); a malformed file fails boot with an `apihost: policy` error. `failClosedPorts` and the deny stubs moved to `failclosed_test.go` (tests only).

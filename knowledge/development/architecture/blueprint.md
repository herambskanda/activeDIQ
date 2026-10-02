---
title: "Architecture blueprint v0"
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
ticket: T-0004
binding_sources: ADR-0001 (ratified), ADR-0002 (ratified), safe-primitives.md (review)
---

# activeDIQ architecture blueprint v0

This is the map every engineer works from. It shows where a change belongs, which rules it must obey,
and who owns each part. Read it once end to end (an afternoon). After that, use §5 (component
catalogue) and §15 (feature → component) as lookup tables.

**What is binding.** The blueprint restates two ratified ADRs and cites them:
- [ADR-0001](../decisions/0001-technology-stack.md): stack and language zones;
- [ADR-0002](../decisions/0002-deployment-model.md): profiles, roles, tenancy and the connector contract.

It also applies the [safe-primitives spec](safe-primitives.md). Those documents delegated several
**paths** to this blueprint, and it **fixes** them in §1.1. Everything else here is design direction.
Where a direction needs its own ADR, the queued ticket is named: module system **T-0045**, API
contract **T-0046**, operation pipeline and audit trail **T-0047**. If this blueprint and a ratified
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
|  | ldapfilter dn attr  model  inventory    |  | tenant store(+reportsql) authn authz audit jobs  |
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
| `internal/platform/` | **The extractable platform root** (ADR-0002, "The boundary with UEM"). It is the kernel, and it imports no directory-domain or module package | S, A | backend-engineer (per package, §5) |
| `internal/directory/` | **The directory domain.** It holds the safe primitives P1–P3, the object model, the inventory (sync store), the sync ingester and the connector-contract client | S, A | directory-engineer |
| `internal/connector/` | **The connector root.** It is the only place that imports directory protocol and Graph libraries, and the only place that unseals directory credentials (ADR-0002 rule 3) | S | directory-engineer |
| `internal/modules/<id>/` | Server feature modules, one directory each (§5.4) | S | per module |
| `internal/agentmodules/<id>/` | Agent modules `addc` and `fileserver` [M3]. `mgmthelper` exists only if the M3 GPO spec chooses it (§13) | A | windows-engineer |
| `internal/proto/` | Generated Go code for `proto/`. Never hand-edited | S, A | api-engineer |
| `internal/webui/` | `go:embed` package for the built web assets. Embed patterns cannot use `..` ([embed](https://pkg.go.dev/embed)), so the build copies `web/dist` here. Only `compose/server` imports it | S | frontend-engineer |
| `proto/` | Protobuf sources: `skenzeriq/agent/v1` (shared host contract, T-0040), `activediq/connector/v1`, `activediq/<agent-module>/v1` | — | api-engineer; contracts: solution-architect |
| `api/openapi/` | The public API contract. It is the source of truth, with one file per module tag, bundled and compiled to Go and TypeScript by `tools/gen/api` ([api-pipeline.md](api-pipeline.md), T-0147) | — | api-engineer |
| `migrations/` | One forward-only SQL sequence, `NNNN_<owner>_<what>.sql`, plus `embed.go`. `0001` creates `tenants` (ADR-0002 rule 4). The owning package is in the filename (§2 rule 6) | S | backend-engineer |
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
| `tools/fitness/stack/` + `manifest.json` (ADR-0001) | **Kept.** Likewise `tools/fitness/tenancy/` and `tools/fitness/profiles/` (ADR-0002). Added: `tools/fitness/modules/` (T-0045) |
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

```
 binary          role package             links, beyond kernel packages (rule 7 lists what each must not)
 cmd/server  --> compose/server     -->   internal/modules/* (generated list), webui, apihost, store,
                                          internal/connector/* (embedded transport, sealed credentials)
 cmd/connector > compose/connector  -->   internal/connector/* (remote run loop, local credentials)
 cmd/edge    --> compose/edge       -->   no store, no keys, no connector, no modules
 cmd/agent   --> compose/agent      -->   internal/agentmodules/* (generated list), platform/agent
     Every role package may import compose/profile and compose/config, and no other role package.

 internal/modules/*     internal/agentmodules/*     internal/connector/*
          \                      |                   /  (connector: directory primitives + model only)
           v                     v                  v
          internal/directory/*  (primitives, model, inventory, sync, client)
                                 |
                                 v
          internal/platform/*  -->  internal/proto/skenzeriq/*
          (kernel: imports no layer above it, and no activediq proto)
```

These rules become binding through T-0045 (`fitness-modules`). Until that ADR is ratified, code
review applies them.

1. **`platform` imports only** `platform`, `internal/proto/skenzeriq/…`, the standard library and
   registered dependencies. It never imports `directory`, `connector`, `modules`, `compose` or
   `internal/proto/activediq/…` (ADR-0002 U2). `fleet` carries product contracts through an opaque
   tunnel (§7.2), so it never needs one.
2. **`directory` imports only** `platform` and `proto`. It never imports `connector`, `modules`
   or `compose`.
3. **`connector` imports only** the directory primitives and model, `platform` and `proto`.
   Outside `internal/connector/` itself, exactly three packages import it:
   - `internal/compose/server`, for the embedded transport and the sealed-credential source;
   - `internal/compose/connector`, for the remote role and local credentials;
   - `internal/compose/t0connector` [post-v1].

   `tools/fitness` may also import it. `compose/server` hands the embedded transport to
   `directory/client` as a value that implements the generated service interface. Credential
   custody therefore holds by construction.
4. **Modules never import other modules.** They cooperate through kernel registries: an Action
   by ID (§4.2), a dataset, an audit kind or a notify sink. A leaver policy composes
   `objects.user.disable` and `m365.licence.remove` by Action ID; it does not import either module.
5. **Only the generated lists name a module.** There are three lists:
   - `internal/compose/server/modules.gen.go` (server modules);
   - `internal/compose/agent/modules.gen.go` (agent modules);
   - `web/src/app/modules.gen.ts` (web modules).

   `tools/gen/modules` generates them from the directory tree, and CI checks that they are not
   stale. Nobody edits them by hand. No other package imports `internal/modules/*` or
   `internal/agentmodules/*`. Nothing takes a module-typed parameter, a struct of modules or a
   growing constructor (postmortem §6: `NewRouter`, 53 parameters).
6. **One owner per table.** The migration filename names the owning package. sqlc query files and
   SQL constants may reference only their owner's tables. Other packages read through the owner's
   Go API or through a registered report dataset. This generalises ADR-0002 T5's "owning package"
   to every table.
7. **Binary hygiene.** Planes are separated by the link graph, not only by the manifest
   (ADR-0002 rule 2). Each binary links only its own role package, so `go list -deps ./cmd/<role>`
   must contain none of the packages listed for it:

   | Binary | Must not contain | Why |
   | --- | --- | --- |
   | `cmd/server` | `internal/agentmodules` | agent code runs on customer hosts, never in the server |
   | `cmd/connector` | `internal/modules`, `platform/apihost`, `internal/webui`, `platform/store` | a remote connector serves no API and has no database; its credentials are local (§7.3) |
   | `cmd/edge` | `internal/modules`, `internal/connector`, `platform/store`, `platform/keys` | user-access plane, "assumed compromised" (ADR-0002 rule 2): no database, no key material, no directory code |
   | `cmd/agent` | `internal/modules`, `internal/connector`, `platform/apihost`, `platform/store`, `internal/webui` | it runs on a DC (Tier 0): no server code, no credential code |
   | `cmd/t0-connector` [post-v1] | `internal/modules`, `platform/apihost`, `internal/webui`, `platform/store` | control plane, alone on its host |

   Rows for `cmd/radius` and `cmd/fpolicy` are added by the tickets that build them. For these
   rows to hold, the kernel packages that satellite binaries link (`agent`, `fleet/dial`,
   `update`, `telemetry`, `secret`, `proc`, `capability`) import no `store`. Server-only steps are
   injected by `compose/server`: migrations in `update`, enrollment records in `fleet`.
8. **Web mirrors the server.** `web/src/app` and `web/src/ds` never import
   `web/src/modules/*`. Modules register their routes, palette actions and search-result renderers
   through a generated `web/src/app/modules.gen.ts`. `web/src/api` is generated (T-0046).

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

```go
// internal/platform/module
type Module interface {
    ID() ID                        // "objects": stable, also the OpenAPI tag and the web module id
    Requires() []capability.ID
    Register(r *Registrar) error   // the only way to contribute anything; called once at boot
}
// Registrar: typed, append-only, closed after boot; duplicate IDs fail start-up.
//   API(tag, handlers)  Action(a)  Job(kind)  Permission(p)  ScopeEvaluator(e)  AuditKind(k)
//   Dataset(d)  Sink(s)  AuthMethod(m)  ApprovalGate(g)
```

Each module exports `New(platform.Deps, directory.Services) module.Module`. Both are fixed
structs of kernel services and grow per *service*, never per module. The generated list in
`compose/server` calls `New` for each module.

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
When a ticket adds a module, it also writes `architecture/modules/<id>.md`. That page records
purpose, owned tables, API tag, Actions, datasets, audit kinds, the EPs implemented and the
dependencies.

### 5.1 Platform kernel (`internal/platform/`, extractable)

| Package | Owner | Interface (what others call) | EPs |
| --- | --- | --- | --- |
| `tenant` | backend-engineer | `tenant.ID`, which only authn, the job wrapper, registered platform paths and tests may mint (ADR-0002 rule 5) | — |
| `store` (+`exempt`, `sqlcdb` conventions) | backend-engineer | `WithTenantTx(ctx, tenant.ID, fn)`, `WithPlatform(ctx, reason, fn)`, `LikePattern`, per-transaction `statement_timeout`; the raw pool is unexported | — |
| `store/reportsql` | reporting-engineer (security-architect reviews every change, P5 rule 3) | `Compile(ast, dataset, scope) (sql, args)`, the only dynamic SQL | consumes EP-8 |
| `module` | backend-engineer | `Module`, `Registrar` | hosts EP-1 |
| `capability` | backend-engineer (IDs: solution-architect) | `capability.ID` constants and `Set.Enabled(id)`. It is a leaf package with no behaviour. Manifests list IDs (`compose/profile`), modules return them from `Requires()` (§4.1), and role packages filter modules by them | supports EP-1 |
| `apihost` | api-engineer | HTTP server, auth middleware, strict JSON, problem types, rate limits, static UI mount | hosts EP-2 |
| `authn` | backend-engineer; security-architect reviews | sessions, API tokens (ADM-141), SAML/OIDC SP (library `[OPEN]`, ADR-0001), MFA (ADM-142), mTLS principals | hosts EP-10 |
| `authz` | backend-engineer | `Authorize(principal, permission, target) Decision`; roles = sets of permissions; assignments = principal × role × scope | hosts EP-6 |
| `operation` | backend-engineer | `Plan`, `Submit`, `Approve`, `Undo`, operation state; bulk chunking on `jobs` | hosts EP-3, EP-4 |
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

| Package | Owner | Interface | EPs |
| --- | --- | --- | --- |
| `ldapfilter`, `dn`, `attr/*` | directory-engineer | the safe primitives P1–P3 (safe-primitives §3–§5) | — |
| `model` | directory-engineer (semantics: ad-expert, T-0006) | `Connection` (AD forest, Entra tenant), `NamingContext`, `Object{GUID, class, parent GUID, DN-for-display}`, `ObjectRef`, link types | — |
| `inventory` | directory-engineer | current state, link graph, GUID ancestry, per-DC values, AD↔Entra correlation, change history (§12). Read API for modules | implements EP-8 |
| `sync` | directory-engineer | full sync, then DirSync / Graph delta per naming context or tenant, under a lease (ADR-0002 rule 6); the cookie is stored in our database, so the connector stays stateless | EP-5 job |
| `client` | directory-engineer | `Directory` (the generated connector-contract client); binding → transport resolution, from data rather than configuration; capability check before Plan | consumes EP-11 |

### 5.3 Connector root (`internal/connector/`)

| Package | Owner | Interface | EPs |
| --- | --- | --- | --- |
| `service` | directory-engineer | implements `activediq.connector.v1` for both transports (§7.1). `service.New(providers, credentialSources)` is one constructor; the two role packages call it with different parameters | — |
| `provider` | directory-engineer (contract: solution-architect) | the `Provider` interface: `Describe() Capabilities` plus the typed operations `service` dispatches to. A provider declares which contract operations and named secret ops it supports, and `directory/client` checks them before `Plan` | hosts EP-11 |
| `provider/ad` | directory-engineer | AD ops over `ldap`, `kerberos`, `ad/scope`; later SMB (`go-smb2`) and MS-RPC (`go-msrpc`), each with a register row first | implements EP-11 |
| `provider/entra` | directory-engineer | Graph ops, including delta queries ([user: delta](https://learn.microsoft.com/en-us/graph/api/user-delta)). SDK or thin client `[OPEN]` (ADR-0001) | implements EP-11 |
| `ldap` | directory-engineer | DC locator, LDAPS/StartTLS, `SecureConn`, paging, ranged reads, DC affinity | — |
| `kerberos` | directory-engineer | `GSSAPIClient` with adapters `sspi` (GOOS=windows platform adapter) and `krb5` (go-krb5, T-0023) | EP-12 |
| `credential` | directory-engineer; security-architect reviews | the credential types and a `Source` interface. Its types are nameable only here (P3). Two sources: `credential/local` (gMSA through the process identity, keytab file, OS-protected certificate), used by both roles; and `credential/sealed` (Entra certificate and AD password fallback, unsealed with `keys` inside the caller's `WithTenantTx`), used **only** by the embedded connector, wired by `compose/server` | — |
| `psx` | backend-engineer | typed sidecar client over `proc` (safe-primitives §6.1) | — |

### 5.4 Server feature modules (`internal/modules/<id>/`)

| Module | Owner | API tag / Actions / datasets (interface) | EPs (§4) | Epic |
| --- | --- | --- | --- | --- |
| `connections` | directory-engineer | AD forest and Entra tenant onboarding; connector enrollment and binding; connection settings (signing, CBT, DC affinity) | EP-1, 2, 6, 7. Reads provider capabilities through `directory/client` (EP-11) | E2.7, E2.12 |
| `objects` | backend-engineer | create/modify/move/rename/delete/restore for users, groups, computers, contacts and OUs, with class definitions as data; templates, naming formats, rules, duplicate checks, copy; bulk and CSV planning | EP-1, 2, **3** (one Action per class × verb; class definitions are data), 6, 7 | E2.2, E2.3 |
| `helpdesk` | backend-engineer | reset, unlock, random passwords, password options; LAPS/BitLocker reads (named secret ops); the reset console with caller verification (EP-10) | EP-1, 2, **3** (reset, unlock, named secret reads), 6, 7. Uses EP-10 for caller verification | E2.5 |
| `delegation` | backend-engineer | roles, technicians, scopes (OU/group/site/domain, include/exclude, cross-domain); implements the directory scope evaluator (EP-6) | EP-1, 2, **3** (role and scope assignment changes; T-0047), **6** (implements the directory scope evaluator), 7 | E2.5 |
| `lifecycle` | backend-engineer | joiner/mover/leaver policies (HR, CSV, DB), scheduled automation, cleanup policies, expiry reminders; it composes Actions by ID | EP-1, 2, **3** (policies compose other modules' Actions by ID), 5 (policy schedules), 6, 7. Uses EP-9 (reminders) | E2.9 |
| `workflow` | backend-engineer | requests, review, approval, SLAs, assigning rules, manager approvers; implements EP-4 | EP-1, 2, **4** (approval gate), 5 (SLA timers, escalations), 6, 7. Uses EP-9 | E2.8 |
| `reports` | reporting-engineer | canned library (data), builder, schedules, exports, act-on-results (→ EP-3), ME crosswalk | EP-1, 2, 5 (schedules), 6, 7. **Consumes EP-8**; calls EP-3 by Action ID (act on results); uses EP-9 (delivery) | E2.6 |
| `history` | backend-engineer | object timeline (inventory history joined with our audit), undo entry point, baseline snapshot (MIG-18) | EP-1, 2, 6, 7. Consumes EP-8 (inventory history, audit); calls EP-3 through `operation.Undo` | E2.4 |
| `search` | backend-engineer | universal search over inventory with RBAC trimming; palette action catalogue from EP-3; dashboard tiles | EP-1, 2, 6, 7. Reads the EP-3 Action catalogue for the palette | E2.1 |
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
| Module system, import DAG, generated lists, table ownership, `fitness-modules` | **T-0045** (ADR) |
| OpenAPI layout, generators, router, versioning, strict JSON, `x-permission` | **T-0046** (ADR) |
| Action contract, operation state machine, audit-trail guarantees; whether configuration writes (templates, roles, policies, `migration` imports) are Actions | **T-0047** (ADR) |
| Paths in skills and safe-primitives.md | **T-0048** (chore) |
| Agent host and module contract; password-filter IPC | T-0040 (+ T-0024) |
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
| Import DAG, Registrar only, generated lists, table ownership, binary hygiene (§2) | `fitness-modules` | T-0045 → its fitness ticket |
| Public API: routes ⊆ OpenAPI, `x-permission`, generated client | API fitness | T-0046 → its fitness ticket |
| Writes only via `Action.Apply`; audit chain verifies | operation fitness | T-0047 → its fitness ticket |
| Safe primitives: imports, banned APIs, literal shapes, corpus, fuzz, oracles, `psx` manifest | FF-SP1–SP9 | T-0033, T-0034 |

Nothing in this table runs yet. This blueprint moves to `accepted` when a human has read it end to
end. The rules it states become *enforced* only as each row's check goes green in `make ci`.

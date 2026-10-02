---
title: "ADR-0002: Two self-hosted profiles from one codebase, multi-tenant from migration 1, SaaS by composition, standalone from UEM with a shared agent-host contract"
date: 2026-10-02
updated: 2026-10-02
status: proposed
owner: heramb
kind: strategic-fork
ticket: T-0003
decision: D-0002, D-0003
---

# ADR-0002: Two self-hosted profiles from one codebase, multi-tenant from migration 1, SaaS by composition, standalone from UEM with a shared agent-host contract

**Status:** proposed. The CEO set the direction in **D-0002** (self-hosted first, SaaS-ready) and **D-0003** (standalone from UEM, converge later), and both are answered. This ADR turns those answers into rules. The factory-director ratifies it at review of T-0003 by checking that it stays inside those answers. The decisions the factory takes *inside* the answers are listed in "Decisions taken inside the CEO's answers" below. They go to the CEO as one notice, which the CEO can veto. The ADR becomes `accepted` when `fitness-tenancy` and `fitness-profiles` run green in `make ci` on `main` (see "Fitness function").
**Kind:** strategic fork. The direction is the CEO's; the detail is the factory's.
**Deciders:** heramb (D-0002, D-0003); solution-architect (author); factory-director (ratifier). **Ticket:** T-0003. **Parity / scope refs:** ADM-158, ADM-209, ADM-210, ADM-213, RMP-046 (platform hygiene, updates, HA).

> Amendments (ratified ADRs only): none.

## Context

**Business framing.** ManageEngine's customers bought on-premises software. A tool with write access to AD is Tier 0, and regulated buyers keep their control plane in-house (`knowledge/business/strategy/product-strategy.md` §7.1, §13 Q2). The CEO therefore chose to ship **self-hosted first**, as a Windows installer and a Linux/Docker image. This serves Windows-standard and Linux-standard estates alike. FEAS §4.3 names the Windows installer the mid-market default. It also needs no hosting operation from us before revenue. The CEO also required the core to be **SaaS-ready and multi-tenant from the first migration**. A hosted offering, and an MSP channel after it, must then be a packaging and operations project, not a rewrite (D-0002). The switch condition is stated in the strategy: if discovery shows the warm accounts prefer SaaS, we switch (§13 Q2). This ADR keeps that switch cheap. On the platform question, the CEO chose **standalone now**: own codebase, UEM's principles, the house stack, the skenzeriq design system. The endpoint agent is to be shared with UEM through module contracts, with convergence on a common core later (D-0003). That keeps our pilot dates independent of UEM's schedule, which is also pre-implementation.

**CEO answers this ADR implements** (`knowledge/memory/decisions-log.md`, 2026-10-02):
- **D-0002, deployment:** "Self-hosted first, SaaS-ready. Windows installer + Linux/Docker; multi-tenant-ready code." Rejected: SaaS first with an on-prem connector; both at once.
- **D-0003, platform:** "Standalone, converge later. Own codebase on UEM principles + stack + design system; shared agent via module contracts." Rejected: a shared skenzeriq core now; fully independent.

**Constraints already in force.**
- **ADR-0001 (ratified)** fixes Go for the server and agents, cgo-free and cross-compiled, with PostgreSQL as the only stateful service. It left the support matrix, installer topology and tenancy topology to this ADR (`0001-technology-stack.md`, "Out of scope here").
- **UEM's ADR-0001 and ADR-0002**, the principles D-0003 tells us to build on:
  - one codebase composed into profiles;
  - no profile conditionals in domain code;
  - tenancy bypasses declared in a registry;
  - the extension point exists before a tier's first feature;
  - an ADR is accepted only when its CI check runs.

  Sources: `../UEM/knowledge/development/decisions/0001-one-codebase-deployment-profiles.md` and `0002-extension-points-precede-features.md`.
- **The feasibility study.** It sketches five deployment shapes and the multi-tenancy design: `tenant_id` and RLS from migration 1, a tenant derived from mTLS certificates, per-tenant keys (`knowledge/development/architecture/build-feasibility/ad-technical-feasibility.md` §4.3, §4.5). It puts the tenant and RBAC core first in build order (§6.1 #1). It describes the directory connector as "embedded in the server (on-prem) or a standalone process near the DCs (SaaS/MSP)" (§4.1).
- **The roadmap.** M2 exit criterion 8 reads: "on both the Windows and the Docker profile, an update applies automatically, and a deliberately bad update rolls back. Both also work with HA enabled" (`knowledge/business/scoping/roadmap-skeleton.md`). Parity rows ADM-209 and ADM-210 are must-have leapfrogs: "zero-downtime updates with rollback, incl. under HA"; "HA in every tier without same-subnet limits" (`feature-parity-matrix.csv`).
- **Safe primitives P5.** These set the SQL tenant-context rules: `set_config('app.tenant_id', $1, true)` per transaction, RLS plus `FORCE`, and an app role that is neither the owner nor `BYPASSRLS` (`knowledge/development/architecture/safe-primitives.md` §7, FF-SP7).

**PatchIQ evidence** (`../UEM/knowledge/development/legacy/patchiq-postmortem.md`):
- **Tenancy came late and stayed partial.**
  - Multi-tenancy was a separate workstream, not migration 1 (§3).
  - The HTTP tenant came from a raw, client-supplied `X-Tenant-ID` header (§3).
  - `BypassPool()` reached 18 call sites with no record of why (§3).
  - The tenant context was built with `fmt.Sprintf` and leaked across pooled sessions (§11 #1, NC1/NC2).
  - Hub and server had two tenancy models that were never unified (§3).
- **Topology fixed at one shape.** A single hub address was required to boot, and one customer's hostnames appeared in 18 files. The multi-site ADR was "Accepted" with zero code (§7).
- **The offline installer was a separate pipeline**, beside the release flow, and unsigned (§7).

**Why the decision is not obvious.** "SaaS-ready" is cheap to say and expensive to keep. Four things make it hard:
1. **Tenancy is only half of it.** In SaaS, AD credentials must stay at the customer site, so the control plane reaches AD only through a connector that dials out (FEAS §4.2, §4.3). If the self-hosted server calls LDAP in-process with direct function calls, SaaS needs a re-architecture of every directory call site. That is the extraction PatchIQ never paid for (UEM ADR-0002, Context).
2. **A single-tenant install tempts shortcuts.** It invites a hard-coded "default tenant", unscoped queries and "temporary" bypasses. All of them look harmless on-prem and become cross-tenant leaks in SaaS.
3. **Two profiles on two OSes tempt per-OS copies.** That is PatchIQ's per-vertical cloning and its "compiles to no-ops" self-update (postmortem §11 #3, #9).
4. **D-0003 promises a shared agent, but no shared agent exists yet.** UEM's module-system and agent-hosting ADRs (A3, A5) are still queued (`../UEM/knowledge/development/architecture/adr-queue.md`). Our DC agent arrives in M3.

## Decision

We will ship activeDIQ as **one codebase composed into deployment profiles**. v1 ships two self-hosted profiles: **Windows installer** and **Linux / OCI**. The **SaaS** profile is designed, composed and tested in CI from M1, but not shipped. Every profile runs the same multi-tenant code path with `tenant_id` and RLS from migration 1. The server reaches directories only through the **connector contract**, which has an embedded transport and a remote transport. activeDIQ is standalone from UEM, except for the **agent host and module contract**. We build that contract as a skenzeriq-wide artefact, reviewed with UEM's owners.

### At a glance: profiles, tenancy and the UEM boundary

| Profile (id) | Ships | Packaging and processes | Datastore | Identity to AD; where directory credentials live | Where tenancy lives | Updates | Relationship with UEM |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Windows installer** (`windows`) | **v1 GA** (M2 exit) | <ul><li>One signed MSI.</li><li>One Windows service runs the `server` role with the `connector` role embedded.</li><li>Optional extra hosts: remote connectors, SSPR edge, agents (M3+).</li><li>Not on a DC (rule 9).</li></ul> | <ul><li>Bundled PostgreSQL 18 as its own service.</li><li>Or the customer's PostgreSQL 16 or later (ADR-0001).</li></ul> | <ul><li>The service runs as a **gMSA**, with no stored password.</li><li>Any credential a customer insists on is sealed under the tenant data key.</li><li>Only the `connector` role uses it.</li></ul> | <ul><li>**Exactly one tenant row**, a random UUID created by the installer.</li><li>Same RLS code path as every profile.</li><li>Tenant provisioning is not composed in.</li></ul> | <ul><li>ENH-07 release train.</li><li>Online channel or offline signed bundle.</li><li>Same verifier either way (rule 7).</li></ul> | <ul><li>Runs with no UEM component present.</li><li>Agent host is skenzeriq-wide (rule 10).</li></ul> |
| **Linux / OCI** (`linux-oci`) | **v1 GA** (M2 exit) | <ul><li>One signed multi-arch OCI image (`linux/amd64`, `linux/arm64`), one image per role.</li><li>A Compose file for the default layout.</li><li>Same roles and the same binary as Windows.</li></ul> | <ul><li>The customer's PostgreSQL 16 or later.</li><li>Or the upstream PostgreSQL 18 image, referenced by digest. We do not rebuild it.</li></ul> | <ul><li>**AES keytab** for a dedicated service account, mounted as a secret. gMSA retrieval is `[LAB]` (FEAS §4.3).</li><li>Held only by the `connector` role.</li></ul> | Same as `windows` | Same as `windows` | Same as `windows` |
| **SaaS** (`saas`) | **Not in v1.** Composed and tested in CI from M1. Launch timing is a CEO fork (roadmap E5.6). | <ul><li>Our cloud, one **cell** per data-residency region.</li><li>N stateless `server` nodes per cell; `edge` hosted by us.</li><li>The customer runs `connector` and agents on-site. They dial out over mTLS.</li></ul> | Managed PostgreSQL per cell | <ul><li>**At the customer site only:** the connector's local gMSA or keytab.</li><li>The control plane holds no AD credential.</li><li>Entra app certificates are sealed under the tenant data key.</li></ul> | <ul><li>Many tenants per cell, in a shared schema with RLS.</li><li>The tenant comes from the authenticated principal.</li><li>Tenant placement (cell and database) is data.</li><li>Per-tenant keys in a KMS.</li><li>MSP parent/child tenants are modelled, not enabled.</li></ul> | <ul><li>We run the rings.</li><li>Connectors and agents use the same channel and verifier.</li></ul> | Same as `windows` |
| *Air-gapped* | Not a profile: a **transport** for both self-hosted profiles | Same artefacts; updates arrive as offline signed bundles | Same | Same | Same | Same verifier; a different courier | Same |
| *Private cloud / Kubernetes, virtual appliance, native Linux packages* | Not in v1 | Would package the same OCI image or binary. No code change. | Customer's | Keytab via a secret store | Same | Same | Same |

### Where tenancy lives

The same rows apply to every profile. A self-hosted install simply has one tenant.

| Layer | Rule |
| --- | --- |
| **Data** | <ul><li>Every tenant-scoped table has `tenant_id uuid NOT NULL REFERENCES tenants(id)`.</li><li>It is the leading column of the primary key and of every unique constraint and index.</li><li>RLS is `ENABLE`d and `FORCE`d.</li><li>The policy is `USING` and `WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)`. With no context set, the comparison is NULL, so reads return nothing and writes are rejected: it **fails closed**.</li><li>Views over tenant tables set `security_invoker = true`. Without it, the view owner's RLS context applies, not the caller's ([CREATE VIEW](https://www.postgresql.org/docs/current/sql-createview.html)).</li><li>RLS semantics: [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).</li></ul> |
| **Transaction** | <ul><li>Tenant context is set only by the data-access package's `WithTenant(ctx, tenant.ID, fn)`.</li><li>It is the first statement of each transaction: `set_config('app.tenant_id', $1, true)` (safe primitives P5 rule 2).</li><li>The raw pool is unexported.</li><li>Platform-scope work goes through `WithPlatform(ctx, reason, fn)`, and only from call sites listed in the exemption registry.</li></ul> |
| **Request** | <ul><li>The tenant is derived only from an authenticated principal: a console session, an API token, or a connector/agent mTLS certificate whose SAN names the tenant and component (FEAS §4.5).</li><li>Never from a header, a query parameter or a body field.</li><li>Anonymous end-user flows (SSPR) resolve the tenant from a platform-scope **hostname binding**. That binding is a registered platform path and grants only anonymous-flow capabilities.</li></ul> |
| **Jobs** | <ul><li>Every job's arguments carry `tenant_id`.</li><li>One job wrapper opens `WithTenant` before the job body runs.</li><li>A job with no tenant must be a registered platform job.</li><li>River's own tables are global and registered: they cannot carry our RLS policy.</li></ul> |
| **Connectors and agents** | <ul><li>Each is enrolled to exactly one tenant.</li><li>The server takes the tenant from the certificate, never from the message.</li><li>Enrollment runs before the tenant is known. It is the first registered platform path (UEM ADR-0001; PatchIQ `enroll.go`).</li></ul> |
| **Keys and secrets** | <ul><li>Each tenant has a data key, wrapped by the installation KEK. The KEK comes from the profile's key-provider adapter: DPAPI-NG/TPM on `windows`; TPM2, KMS, Vault or a passphrase keystore on `linux-oci`; KMS on `saas` (FEAS §2.5).</li><li>Deleting a tenant shreds its key.</li></ul> |
| **Blobs** | Storage keys are prefixed by tenant, through ADR-0001 rule 3's storage interface |
| **Our audit trail** | One hash chain per tenant, so a tenant's chain can be exported and verified on its own |
| **Logs, metrics, caches** | <ul><li>Every log line and metric about tenant work carries the tenant ID.</li><li>In-process caches are keyed by tenant.</li></ul> |
| **Hierarchy** | <ul><li>`tenants.parent_tenant_id` exists from migration 1.</li><li>RLS is **always single-tenant**: no policy admits descendants.</li><li>MSP cross-tenant work iterates tenants, one `WithTenant` transaction each, under an explicit MSP grant. Not enabled in v1 (E5.6).</li></ul> |
| **Configuration scope** | <ul><li>**Platform scope** holds installation settings: database connection, KEK source, TLS, listen addresses, nodes, update ring and window, hostname bindings. The installation operator sets them: the customer when self-hosted, skenzeriq operations in SaaS.</li><li>**Tenant scope** holds everything a tenant administrator does. It is set only through the public API.</li><li>Tenant administration never requires host access: no files, registry, shell or database.</li></ul> |

### The boundary with UEM

| Asset | Relationship now | Rule |
| --- | --- | --- |
| Principles, knowledge-base conventions, ADR ladder | **Adopted** | As written in UEM ADR-0001/0002 and `knowledge/README.md` |
| House stack (Go, React/TypeScript, PostgreSQL) | **Adopted** | ADR-0001 |
| skenzeriq design system | **Consumed, never forked** | <ul><li>A pinned, build-time dependency on `../design-system/`.</li><li>Token changes go upstream.</li></ul> |
| **Agent host and module contract** | **Shared by contract** | <ul><li>Protobuf package `skenzeriq.agent.v1` covers the host: enrollment, identity, module lifecycle, update, health, outbox. It carries no AD-specific type.</li><li>activeDIQ modules (`ad-dc`, `fileserver`, `mgmt-helper`) use `activediq.<module>.v1`.</li><li>The host is built in our repository, under the extractable platform root.</li><li>UEM's owners review the contract before it is frozen (before M3). The draft starts from PatchIQ's `agent.Module` (postmortem §10) and UEM ADR-0002.</li><li>Whichever product ships first ships the host. The other plugs modules into it.</li></ul> |
| Repository, Go module, build and release train, installer, database, tenancy store, authn/RBAC, licensing | **Not shared** | <ul><li>activeDIQ installs and runs with **no UEM component, service or repository present**.</li><li>It imports no UEM or PatchIQ Go module and makes no runtime call to a UEM service.</li></ul> |
| Common core: tenancy, authn/RBAC core, our audit trail, job-engine wrapper, agent host, update client, key provider | **Converge later** (D-0003) | <ul><li>Lives under one platform root, provisionally `internal/platform/`; T-0004 fixes the path.</li><li>That root imports no directory-domain or module package, so it can be extracted.</li><li>Convergence is a superseding ADR.</li></ul> |
| Cross-product features (one console, shared inventory) | **Out of scope** | If ever, through each product's public API |

### Rules that make this checkable

1. **Profiles by composition.** A profile is a typed manifest in the composition root (`cmd/<role>/` plus a compose package; T-0004 fixes the paths). It lists:
   - the roles each process runs;
   - the adapter chosen for each declared interface: key provider, secret source, blob store, service-host integration, update courier, Kerberos client path (ADR-0001);
   - the enabled capabilities, named for the capability (`tenant-provisioning`), never for the profile.

   **Prohibited:**
   - profile conditionals in domain code;
   - reading the profile, or the environment variables that select it, outside the composition root;
   - build tags that select a profile (ADR-0001 rule 2 already restricts GOOS tags to platform adapters);
   - per-profile migrations or schema;
   - long-lived branches per profile or per customer.

   A capability present on one self-hosted profile and missing on the other is a defect, unless the manifest declares it and cites a ratified ADR. Adapters may differ; capabilities may not.
2. **Roles.** Each component in ADR-0001 tiers S and A is a role: `server`, `connector`, `edge`, `radius`, `t0-connector`, `fpolicy`, `agent`. A process runs the roles its profile manifest names. The self-hosted default is one `server` process running `server` + `connector`.
3. **One path to a directory.** Server-side code reaches LDAP, Kerberos, SMB, MS-RPC and Graph only through the **connector contract**. That contract is a versioned protobuf service of typed operations, with no free-form query or script verb. It has two transports:
   - **embedded**: in-process, used by default in self-hosted;
   - **remote**: the connector dials out to the server over mTLS gRPC. It is used by SaaS, and on-prem for additional forests, DMZ or branch sites, and redundant connectors (ADM-210).

   Both transports run the same conformance suite. Directory protocol libraries are imported only under the connector root (extends safe-primitives FF-SP1).
4. **Tenancy from migration 1.** Migration `0001` creates `tenants` (`id`, `parent_tenant_id`, name, state, timestamps) and nothing else is created before it. Every later table follows the "Where tenancy lives" rules or is listed as global in the **exemption registry**.
   - The registry starts with: `tenants`, migration bookkeeping, River's tables, platform settings, hostname bindings, release metadata.
   - Each entry carries a reason.
   - The app role is not the owner, not a superuser and has no `BYPASSRLS`. Migrations run under a separate owner role.
   - No `SECURITY DEFINER` function exists unless it is registered.
5. **Tenant identity is minted, not parsed.** The type `tenant.ID` can be constructed only by:
   - the authentication package;
   - the job wrapper;
   - registry-listed platform paths;
   - tests.

   No other package converts a string or UUID into a tenant ID. There is no default-tenant constant. A single-tenant install's tenant is a random UUID created at install time.
6. **Stateless nodes; HA by adding nodes.**
   - All state lives in PostgreSQL or the blob store (ADR-0001 rule 3), sessions included.
   - Singleton work, such as the DirSync reader per naming context and schedulers, holds a lease in PostgreSQL.
   - Nodes need no shared subnet or virtual IP. Connectors and agents carry a list of server endpoints. Browsers reach nodes through the customer's load balancer or DNS.
   - **Data-tier HA is PostgreSQL's own.** The server accepts multi-host connection strings with `target_session_attrs=read-write`, which pgx supports ([pgconn](https://pkg.go.dev/github.com/jackc/pgx/v5/pgconn)), so it follows a customer's failover.
   - Bundled PostgreSQL is a single node with automatic scheduled backups (ADM-158).
   - Whether v1 also offers a bundled standby is left to the E2.12 PRD. The constraint: it may not add a new kind of stateful service.
7. **One release train, one verifier, two couriers.**
   - Every artefact (MSI, OCI images, connector, edge, agents) is built from one commit, signed, and listed in one signed release manifest.
   - The online channel and offline bundle import feed **the same** verification and apply code.
   - No core function requires egress to skenzeriq.
   - Design: the ENH-07 spec. Signing: T-0027.
8. **Supported hosts in v1.** These are support commitments, separate from ADR-0001's build matrix.

   | Component | Supported | Why |
   | --- | --- | --- |
   | Server, `windows` | Windows Server 2019, 2022 and 2025, x64, Desktop Experience or Server Core | <ul><li>WS2016 extended support ends 12 Jan 2027, before v1 GA ([lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2016)).</li><li>WS2019 is supported until 9 Jan 2029 ([lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2019)).</li><li>WS2025 is supported until 14 Nov 2034 ([lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025)).</li><li>Windows Server is x64-only (FEAS §5.3).</li></ul> |
   | Server, `linux-oci` | Docker Engine or Podman on a vendor-supported Linux, `amd64`/`arm64`. Tested on Ubuntu 24.04 LTS and RHEL 9. | <ul><li>A pure-Go static binary (ADR-0001).</li><li>Docker Desktop is a developer tool, not a production target.</li></ul> |
   | Remote connector, SSPR edge | As the server, on either OS | Same binaries |
   | PostgreSQL | Bundled 18, or customer-supplied 16 or later | ADR-0001 |
   | Managed DCs (agentless, M2) | WS2016–WS2025, with signing and CBT enforced | FEAS §6.3, Phase-1 exit |
   | DC and file-server agents (M3+) | WS2016–WS2025, x64 | Go supports Windows 10 / Server 2016 and later ([Go 1.21 notes](https://go.dev/doc/go1.21#windows)) |

9. **The server is management plane, not Tier 0.** The installer refuses to install the `server` role on a domain controller. A DC hosts only the agent and the password filter (FEAS §2.1). Where the directory credentials sit is fixed by rule 3. The controls around them belong to the threat model (T-0007).
10. **UEM boundary.**
    - No UEM or PatchIQ Go module appears in any build graph.
    - The `skenzeriq.agent.v1` protos reference no `activediq.*` type.
    - The platform root imports no directory-domain or module package.
    - Freezing the agent contract requires a recorded UEM-owner review.

### Decisions taken inside the CEO's answers (the notice)

These go beyond the literal text of D-0002 and D-0003. The factory takes them, and the CEO can veto them:

1. The Windows server host must be WS2019 or later; WS2016 is not supported as a host. Linux runs on Docker Engine or Podman, on `amd64` and `arm64`.
2. Air-gapped is a way of delivering updates, not a third product. Both self-hosted profiles work with no internet access to us.
3. v1 ships no Kubernetes/Helm chart, virtual appliance or native Linux packages. Any of them can be added later without code changes.
4. HA covers the application tier: several active servers and redundant connectors. Database HA uses the customer's own PostgreSQL HA. Whether we bundle a database standby is left to the platform PRD.
5. Self-hosted installs have one tenant in v1. Self-hosted multi-tenant and MSP wait for the E5.6 decision.
6. activeDIQ builds the shared agent host, and UEM's owners review its contract.
7. The server cannot be installed on a domain controller.

## Alternatives considered

### Deployment profiles

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **Separate builds or branches per profile** | <ul><li>Each package tuned to its platform with no abstraction cost.</li><li>Teams can release one profile without the other.</li></ul> | <ul><li>Divergence starts at once and compounds.</li><li>Every fix lands N times.</li><li>The strictest profile (air-gapped) gets the least attention (UEM ADR-0001).</li><li>PatchIQ's separate offline pipeline drifted and was never signed (postmortem §7).</li></ul> |
| **Windows-only server** | <ul><li>Closest fit to Windows-centric admin teams (FEAS §4.3 calls it "default for mid-market").</li><li>gMSA and SSPI everywhere, so a single Kerberos path.</li><li>One installer to test.</li></ul> | <ul><li>D-0002 ships Linux/Docker too.</li><li>SaaS needs Linux containers anyway, so the Linux path exists regardless.</li></ul> |
| **Linux/OCI only** (Windows shops run a Linux VM) | <ul><li>One package and one runtime.</li><li>Appliance-style installs are common for security tools.</li></ul> | <ul><li>D-0002.</li><li>Windows-only teams without Linux skills would have to run a Linux host to use a Windows-identity product.</li><li>No native gMSA.</li></ul> |
| **Kubernetes/Helm as a v1 profile** | Enterprise private-cloud buyers; HA by the platform | <ul><li>No pilot evidence of demand.</li><li>The same OCI image serves a later chart with no code change.</li><li>Rule 6 already gives HA without Kubernetes.</li></ul> |
| **Virtual appliance (OVA/VHDX)** | A turnkey install | We would own and patch a guest OS inside a Tier-0 tool. It can be layered on the OCI image later. |

### Tenancy

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **Single-tenant schema now, tenancy at SaaS time** | <ul><li>Simpler queries.</li><li>No RLS overhead.</li><li>The fastest path to the first pilot.</li></ul> | <ul><li>D-0002 rules it out.</li><li>Tenancy retrofits are the most expensive refactor available (UEM ADR-0001), and PatchIQ's was partial (postmortem §3).</li></ul> |
| **Application-layer `WHERE tenant_id = $1` only, no RLS** | <ul><li>Plain SQL, no session settings, easy to reason about in Go.</li><li>No PostgreSQL-specific policy objects.</li></ul> | <ul><li>One missed predicate is a cross-tenant leak.</li><li>RLS makes the database refuse it. PatchIQ's RLS was its strongest salvage item (postmortem §3, §10).</li></ul> |
| **Schema- or database-per-tenant** | <ul><li>Physical isolation: a missed policy cannot leak.</li><li>Per-tenant backup, restore and residency for free.</li><li>No RLS planner cost.</li></ul> | <ul><li>N migration runs and N connection pools.</li><li>MSP fan-out gets heavier.</li><li>It is still available to us: placement is data, so a large or regulated SaaS tenant can live in its own cell or database with the same schema ("pool by default, silo by placement").</li></ul> |
| **Hierarchical RLS** (policy admits descendant tenants) | One query across an MSP's customers | <ul><li>Recursive policies are hard to prove correct and to index.</li><li>MSP is not in v1.</li><li>Iteration under explicit grants is enough.</li></ul> |

### Server-to-directory path

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **Embedded only** (direct calls); split out when SaaS arrives | Less code and no serialization in M2 | <ul><li>This is the extraction that loses to every deadline (UEM ADR-0002).</li><li>On-prem customers also need remote connectors for extra forests, DMZ and branch sites, and for redundancy (ADM-210).</li></ul> |
| **Remote only** (a connector process on every install) | One transport, identical to SaaS | <ul><li>Every mid-market install gains a second component and a certificate to manage, which hurts install time (USP-3).</li><li>The embedded transport gives the same contract in one process.</li></ul> |

### Relationship to UEM (the CEO's D-0003 options)

| Alternative | What it would buy us | Why not (CEO decision) |
| --- | --- | --- |
| **Shared skenzeriq core now** (activeDIQ as the first module on a common platform) | <ul><li>Tenancy, RBAC, audit, jobs and agent built once for both products.</li><li>Cross-sell from day one.</li></ul> | Couples two pre-implementation schedules. D-0003 chose standalone. |
| **Fully independent** (no shared agent or core) | No cross-team coordination at all | <ul><li>Two skenzeriq agents on the same servers.</li><li>Breaks "one agent per endpoint" (product-strategy §7.2 #10).</li><li>D-0003 rejected it.</li></ul> |

### Agent host

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **An activeDIQ-only agent; converge by rewrite later** | Freedom to shape the host around DC needs | Two agents per host until the rewrite. The rewrite then competes with features. |
| **Wait for UEM's platform agent** | One agent from the first day | Ties our M3 to UEM's unscheduled A3/A5. That is the coupling D-0003 avoided. |

### Data-tier HA

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **Bundle a PostgreSQL cluster manager** (e.g. Patroni) | Turnkey database failover | <ul><li>Needs a distributed configuration store (etcd/Consul): more stateful services, which ADR-0001 rule 3 prohibits without an ADR.</li><li>Windows support `[UNVERIFIED]`.</li></ul> |
| **Active-passive nodes behind a virtual IP** (ManageEngine's shape) | Simple failover | The same-subnet limit is exactly what ADM-210 says we leapfrog |

## Consequences

**Positive**
- **SaaS launch becomes a packaging and operations project.** The `saas` composition, remote connectors and multi-tenant isolation run in CI from M1, so the E5.6 decision does not start a rewrite.
- **On-prem gets remote connectors early.** Customers get extra-forest, DMZ, branch and redundant-connector reach (ADM-210) through the same path SaaS uses, which keeps that path exercised.
- **Tenant isolation holds by construction.** The tenant is minted from authentication, set per transaction, fails closed, and every bypass is registered and visible.
- **Both profiles stay at parity.** Adapters differ; capabilities may not differ unless declared.
- **The UEM seam is precise.** One contract is shared now and one root can be extracted later. Nothing else couples the schedules.

**Negative.** This is what the decision costs.
- **Up-front work for a profile we do not sell yet.** We build the remote transport, the `saas` composition, tenant provisioning paths and their CI before any SaaS revenue, and that slows M1–M2. It is the constraint most likely to be argued away under pilot pressure (UEM ADR-0001 says the same).
- **We own a network-facing connector/agent endpoint in every profile.** Agents need it from M3 anyway. The threat model (T-0007) covers it.
- **RLS has costs.**
  - Every transaction pays a `set_config`.
  - Policies add planner work. The ingest benchmark (T-0026) must measure it.
  - River's tables are outside RLS, so job tenancy rests on the job wrapper plus the static check (T5), not on the database.
- **No bundled database HA in v1.** A customer who wants HA needs PostgreSQL HA skills or a managed PostgreSQL, which may cause sales friction with Windows-only shops. The E2.12 PRD decides whether to close this.
- **Asymmetric AD identity.** gMSA on Windows needs no secret. A keytab on Linux needs rotation unless gMSA retrieval proves out `[LAB]`. That is an operational burden the Linux profile's documentation must own.
- **WS2016 hosts cannot run the server.** Those customers stand up a newer VM. WS2016 DCs remain manageable.
- **Two agents may still share a host** if UEM later chooses a host incompatible with `skenzeriq.agent.v1`. The contract review before freeze is the mitigation, and a revisit trigger covers it.
- **CI cost grows.** The MSI is installed on Windows runners. WS2019 needs a lab VM: GitHub retired its hosted `windows-2019` image on 2025-06-30 ([changelog](https://github.blog/changelog/2025-04-15-upcoming-breaking-changes-and-releases-for-github-actions/)). Both connector transports run against the Samba lab.

**Follow-on work.** All filed in `backlog`, with T-0003 as a dependency:
- **T-0036** `chore` · backend-engineer: **implement `fitness-tenancy`** (checks T1–T5 below). It also implements safe-primitives FF-SP7, so there is one implementation, not two.
- **T-0037** `build` · backend-engineer: **tenancy foundation**. Migration 0001, `WithTenant`/`WithPlatform`, the exemption registry, `tenant.ID` minting and first-run bootstrap, built under `fitness-tenancy` (T-0036). The job wrapper lands with the job-engine ticket.
- **T-0038** `chore` · devops-engineer: **implement `fitness-profiles`** (checks P1–P7 and U1–U4 below). It reuses ADR-0001's manifest mechanism (T-0022).
- **T-0039** `spike` · devops-engineer: **installer toolchain and bundled-PostgreSQL redistribution**.
  - WiX v6 requires an Open Source Maintenance Fee from organisations that use it to generate revenue ([OSMF](https://docs.firegiant.com/wix/osmf/)). Its MS-RL terms need checking against the register.
  - Where the Windows PostgreSQL binaries come from.
  - Whether an offline bundle may carry the upstream PostgreSQL image, which contains GPL distribution packages `[UNVERIFIED]`.
  - Output: register rows and a recommendation.
- **T-0040** `spec` · solution-architect: **agent host and module contract (`skenzeriq.agent.v1`)**, drafted in M1 and reviewed with the UEM owners before freeze (roadmap E1.1).
- Architecture map: T-0004 (blueprint v0) fixes the composition-root, platform-root and connector-root paths and draws the per-profile composition. T-0006 (domain model) carries `Tenant`, platform versus tenant scope and the hierarchy. T-0007 (threat model) draws the trust boundaries per profile. T-0031 (M2 plan) carries the E2.12 decisions left open here.
- **Left open on purpose:**
  - the bundled database standby (E2.12 PRD);
  - the ENH-07 update protocol and ring design (its spec);
  - the SaaS cell layout, regions and operating model (E5.6, a CEO fork);
  - the MSP grant model (E5.6);
  - native Linux packages and a Helm chart (added by pilot demand, no code change);
  - Entra-only tenants with no AD connector (the PRD; the model already allows it).

**Revisit when** (a superseding ADR unless noted):
- Discovery shows the warm accounts prefer SaaS. This is D-0002's own switch condition, and it moves `saas` to shipped.
- UEM ratifies an agent-hosting design incompatible with `skenzeriq.agent.v1`.
- The ingest benchmark (T-0026) shows RLS costs more than 15% of sustained event throughput `[EST]` threshold. Partitioning by tenant under the same rules would be an amendment, not a supersession.
- Two qualified deals are lost because there is no bundled database HA.
- The MSP channel is decided (E5.6). The MSP grant model gets its own ADR.
- A pilot requires a new packaging variant. That is an amendment if it packages an existing profile, and a new ADR if it adds a profile.

## Fitness function

There are two jobs. Both are Go programs invoked by `make ci` (T-0014) and run by the dispatcher's pre-merge gate (T-0015) until hosted CI exists. Paths follow T-0004.

**Job `fitness-tenancy`** (`tools/fitness/tenancy/`). It runs against an ephemeral PostgreSQL 16 and 18, with every migration applied.

| # | Check | Fails when |
| --- | --- | --- |
| T1 | **Migration 1** | <ul><li>The first migration does not create `tenants` with `id` and `parent_tenant_id`.</li><li>Any table is created before it.</li></ul> |
| T2 | **Catalog** | For every table, view and function in product schemas, one of these holds and the object is not in the exemption registry:<ul><li>a table lacks `tenant_id uuid NOT NULL` with an FK to `tenants`;</li><li>`tenant_id` is not the leading column of the primary key and of every unique constraint;</li><li>`relrowsecurity` or `relforcerowsecurity` is false;</li><li>there is no policy with both `USING` and `WITH CHECK` on `app.tenant_id`;</li><li>a view over a tenant table lacks `security_invoker`;</li><li>a `SECURITY DEFINER` function exists.</li></ul>Also fails when a registry entry has no reason, or names an object that no longer exists. |
| T3 | **Roles** | The runtime role owns any object, is a superuser, or has `BYPASSRLS`. Or migrations and the runtime use the same role. |
| T4 | **Isolation** | With two tenants seeded, a generated probe per tenant table finds that:<ul><li>tenant A sees B's rows;</li><li>A can write a row with B's `tenant_id`;</li><li>with no context, rows are visible or a write succeeds;</li><li>after commit, the same pooled connection still shows `app.tenant_id` (safe-primitives SQL-13, SQL-14; FF-SP7).</li></ul> |
| T5 | **Static** (`go/analysis`) | <ul><li>pgx pool or connection types are used outside the data-access package.</li><li>A `WithPlatform` call site is missing from the registry, or a registry call site is stale.</li><li>`set_config`/`SET` SQL text appears outside the tenancy package.</li><li>A `tenant.ID` is constructed outside the allowed packages (rule 5).</li><li>A job type is neither tenant-carrying nor a registered platform job.</li><li>A tenant-scope OpenAPI operation declares a `tenant_id` or `X-Tenant-*` parameter, header or body field.</li></ul> |

**Job `fitness-profiles`** (`tools/fitness/profiles/`).

| # | Check | Fails when |
| --- | --- | --- |
| P1 | **Composition boundary** | <ul><li>A package outside the composition root imports the profile or compose package.</li><li>Such a package reads the profile-selecting environment variables (`os.Getenv`/`LookupEnv` outside the config loader).</li><li>An identifier matching the profile-name denylist (`saas`, `selfhosted`, `linuxoci`, `windowsprofile`, `isSaaS`, …) appears outside the composition root.</li><li>A capability flag is named after a profile.</li><li>The two self-hosted manifests differ in capabilities without an entry citing a ratified ADR.</li></ul> |
| P2 | **Every profile composes and boots** | <ul><li>For each manifest, `windows`, `linux-oci` and `saas`, the artefact set fails to build: the MSI on a `windows-2025` runner, the multi-arch OCI images on Linux.</li><li>The boot smoke test fails: install or start, migrations, health, exactly one tenant (self-hosted) or tenant provisioning (`saas`).</li><li>MSI upgrade or uninstall fails on `windows-2022`/`windows-2025`. WS2019 runs nightly in the lab.</li></ul> |
| P3 | **Both connector transports** | <ul><li>The directory-provider conformance suite fails against the Samba lab (T-0012) under either the embedded or the remote transport. The remote run uses a separate connector container dialing out with mTLS.</li><li>A directory protocol library is imported outside the connector root.</li></ul> |
| P4 | **Multi-tenant composition** | In `saas` with two tenants and two remote connectors, tenant A's connector certificate can read or write tenant B's data, or a message-body tenant overrides the certificate's tenant. |
| P5 | **Offline round trip** | A CI release exported as an offline bundle fails to import and apply in a network-isolated container (`--network none`) through the same verifier as the online path. Or a tampered bundle is accepted. |
| P6 | **No mandatory egress** | A self-hosted boot smoke test fails with outbound traffic denied, except to the lab DC and PostgreSQL. It covers boot, sign-in and a directory read. |
| P7 | **No long-lived variant branches** | A branch exists other than `main` and `factory/T-NNNN`. |
| U1 | **UEM independence** | <ul><li>`go list -deps` of any binary contains a module on the UEM/PatchIQ denylist (initially `github.com/herambskanda/patchiq`, plus UEM's module path once it exists). It reuses ADR-0001 F3's denylist mechanism.</li><li>A `go.mod` has a `replace` directive pointing outside the repository.</li></ul> |
| U2 | **Extractable platform root** | A package under the platform root imports a directory-domain or module package. |
| U3 | **Agent contract namespace** | <ul><li>A proto in `skenzeriq.agent.v1` references an `activediq.*` type.</li><li>A breaking change to either namespace lands without a version bump. The protobuf lint and breaking-change tool is chosen and registered by the fitness ticket.</li></ul> |
| U4 | **Contract-freeze gate** | `skenzeriq/agent/v1` is marked frozen while `knowledge/development/architecture/agent-contract-review.md`, recording the UEM owners' review, is absent or not `accepted`. |

**Checks that activate with their subject.** Some checks cannot run before their subject exists:
- P2 needs the MSI and OCI packaging.
- P3 and P4 need the connector.
- P5 needs the updater.
- U3 and U4 need the agent protos.

The job therefore holds an **activation table**: each check lists the path that brings its subject into existence. When that path exists and the check is not implemented and passing, the job **fails**. A subject cannot land without its check.

**Bypasses and how they are closed.**
- **RLS bypassed through a view, a `SECURITY DEFINER` function, a second role or a second DSN.** T2, T3 and T5: one data-access package, one runtime role, catalog checks on views and functions.
- **A tenant taken from the request.** Rule 5 restricts who can mint `tenant.ID`. T5 checks the OpenAPI contract.
- **Profile logic smuggled in as a capability flag.** P1 bans profile-named flags and checks capability symmetry. Code review checks that flags describe capabilities.
- **The remote transport left untested** because on-prem uses embedded. P3 runs both, every merge.
- **Copying UEM or PatchIQ code instead of importing it.** U1 cannot see this. Ported salvage must name its source in the commit and live under the platform root. Code review enforces it, and that part is manual.

**Status path.** The director ratifies this ADR at review of T-0003 and files the notice. It becomes `accepted` when two conditions hold:
- `fitness-tenancy` (T1–T5) and `fitness-profiles` (P1, P7, U1, U2 and the activation table) run green in `make ci` on `main`;
- the activation table holds an entry for every remaining check: P2–P6, U3 and U4.

From then on, a subject such as the MSI, the connector, the updater or the agent protos cannot merge without its check.

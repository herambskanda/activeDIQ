---
title: "ADR-0001: Go for the server and agents, Rust for code loaded into LSASS and LogonUI, PostgreSQL as the only datastore"
date: 2026-10-02
updated: 2026-10-02
status: proposed
owner: heramb
kind: technical
ticket: T-0002
---

# ADR-0001: Go for the server and agents, Rust for code loaded into LSASS and LogonUI, PostgreSQL as the only datastore

**Status:** proposed. Not binding until ratified.
**Kind:** technical. The factory-director ratifies it when reviewing T-0002, then files a `notice` so the CEO can veto.
**Deciders:** solution-architect (author) and factory-director (ratifier). **Ticket:** T-0002. **Parity / scope refs:** none. This decision serves every capability family.

> Amendments (ratified ADRs only): none.

## Context

activeDIQ has three kinds of code, and each kind has different hard constraints:

1. **Server tier.** This is the product's own network-facing processes: the server (API, UI, jobs, reports, IdP/MFA, event pipeline), the directory connector, RADIUS, the SSPR edge, the Tier-0 connector and the FPolicy receiver. It speaks LDAP, Kerberos, SMB, MS-RPC and Microsoft Graph to customer infrastructure (`knowledge/development/architecture/build-feasibility/ad-technical-feasibility.md` §1, §4.1).
2. **Host agents.** These are services on domain controllers, file servers and a management host. They subscribe to the Security log, relay password-filter notifications and run typed ACL operations. A DC agent is Tier 0 (feasibility §2.1).
3. **In-process plug-ins.** These are DLLs that Windows loads *into its own processes*:
   - a password filter in **LSASS** on every writable DC;
   - a credential provider in **LogonUI**, running as SYSTEM.

   A crash in the password filter reboots the DC. Under LSA protection every LSA plug-in must carry a Microsoft signature and follow SDL guidance, and no debugger can attach ([Microsoft Learn: added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)). ManageEngine shipped SYSTEM-level bugs in exactly the credential-provider slot (CVE-2018-5353, CVE-2019-12476, CVE-2026-74849; feasibility §2.2).

**Why the decision is not obvious.** The house stack (Go + React/TypeScript + PostgreSQL) is the default. UEM's ADR queue calls Go "near-determined" for core, relay and agent (`../UEM/knowledge/development/architecture/adr-queue.md:41`). PatchIQ's working code uses Go 1.25, pgx/sqlc, River, gRPC and React/Vite (`../UEM/knowledge/development/legacy/patchiq-postmortem.md` §1, §9). Even so, four facts make "just use the house stack" wrong for parts of this product:

- **Go cannot be loaded into LSASS or LogonUI.** A Go `c-shared` DLL carries its own runtime and threads, and it cannot be unloaded safely. [golang/go#11100](https://github.com/golang/go/issues/11100) has been open since 2015. Managed .NET code in LSASS is not a supported route (feasibility §3.4 `[UNVERIFIED]`).
- **The Go LDAP/Kerberos stack has a gap that matters in 2026.**
  - go-ldap's Kerberos bind negotiates neither SASL signing/sealing nor channel binding off Windows ([go-ldap PR #565](https://github.com/go-ldap/ldap/pull/565)).
  - gokrb5 has been dormant since 2023.
  - WS2025 DCs require signing by default and can enforce channel binding ([LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)).
  - The maintained successor, [go-krb5/krb5](https://github.com/go-krb5/krb5) (Apache-2.0, stewarded with gokrb5's author's blessing), adds channel bindings and RFC 3244 set-password (feasibility §3.1). It is young (v0.1.0, Feb 2026).

  .NET's `System.DirectoryServices.Protocols` gets signing, sealing and channel binding from the OS when it runs on Windows. On Linux it inherits libldap's behaviour instead ([API docs](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols); feasibility §3.1).
- **Structured PowerShell and COM (GPMC) are .NET-native.** Go has no mature PowerShell Remoting Protocol (PSRP) client with `AddCommand`. PatchIQ's Windows agent had to enable cgo for COM, so it cannot be cross-compiled without a C toolchain (`../patchiq/Makefile:230-234`).
- **The datastore shapes what an on-prem customer must operate.** PatchIQ ended up running PostgreSQL *and* Valkey (a Redis fork) *and* a Watermill SQL bus (`../patchiq/go.mod:10-11,41`). The MinIO server suggested for object storage in feasibility §4.3 is AGPL-3.0, and its repository was archived on 2026-04-25 ([minio/minio](https://github.com/minio/minio)).

**PatchIQ lessons that bear on a stack.**
- Every OS got its own copy of the same work, and a Windows-only feature "compiles to no-ops" elsewhere (postmortem §11 #3, #9).
- Security strings built with `fmt.Sprintf` recurred across tiers (§11 #1, #10). Safe primitives are being specified in T-0005 (`knowledge/development/architecture/safe-primitives.md`, in progress). This ADR fixes which languages those primitives must exist in.

**Out of scope here.** This ADR does not decide where the server runs, who hosts it, or which OSes we *support*. Deployment model, tenancy topology and the relationship with UEM's platform agent are CEO forks, recorded in ADR-0002 (T-0003). The stack chosen here keeps every one of those options open: Windows-only or cross-platform, on-prem, SaaS or MSP, standalone agent or platform-agent module. That openness is a deliberate criterion.

## Decision

We will build activeDIQ on the stack below. Each component belongs to exactly one tier, and a tier's language is the only language allowed in its code.

| Tier | Components (feasibility §4.1) | Language and runtime | Load-bearing dependencies adopted by this ADR | Prohibited |
| --- | --- | --- | --- | --- |
| **S: server** | server, directory connector, RADIUS service, SSPR edge, Tier-0 connector, FPolicy receiver | **Go**, pure Go (`CGO_ENABLED=0`), one toolchain version pinned with the `toolchain` directive in every `go.mod`; dev target **go1.27** ([Go releases](https://go.dev/doc/devel/release)) | **PostgreSQL** (bundled: 18; customer-supplied: 16 or later, [versioning](https://www.postgresql.org/support/versioning/)); **pgx v5** and **sqlc** for all database access; **River** for jobs (pending its licence check, below); **go-ldap v3** plus **go-krb5/krb5** for LDAP/Kerberos; **gRPC-Go + protobuf-go** for agent and connector channels | cgo; Go plugins (`-buildmode=plugin`); a second stateful service (cache, broker, search or object-store server) without its own ADR; ORMs and raw-string query builders; a JVM, Python or Node.js runtime in shipped server artefacts |
| **W: web UI** | admin console, SSPR pages | **TypeScript** (strict) + **React**, built at compile time into static assets embedded in the server binary (`go:embed`) | React, TypeScript, Vite (build-time only); Node.js is build-time only | A Node.js process at runtime (no SSR server); a second UI framework |
| **A: host agents** | DC agent (`ad-dc` module), file-server agent, Windows management helper's host process | **Go**: the same toolchain, safe primitives and protobuf contracts as tier S. Windows service via `golang.org/x/sys/windows/svc`. Outbound gRPC over mTLS only. | as tier S (x/sys, gRPC, protobuf) | cgo (Win32 is reached by syscalls through `x/sys/windows`; COM work goes to tier X); listening ports; a separate agent codebase per OS |
| **N: in-process native** | password-filter DLL (LSASS), credential-provider DLL (LogonUI); also any future module loaded into a privileged host process, such as a Linux PAM module | **Rust** (stable, pinned by `rust-toolchain.toml`) with the **windows-rs** crates; C-ABI/COM exports; every export body wrapped so a panic cannot unwind across the FFI boundary. **C++ only by the gate below.** | Rust toolchain; `windows`, `windows-core`, `windows-implement` | Go, .NET or any other managed or GC runtime in-process; network I/O in the LSASS call path (feasibility §1.7); embedded browsers (feasibility §2.6); any crate not in the licence register |
| **X: sidecars** (bounded exception) | Exchange Online cmdlets; GPMC-identical reports and backups | **.NET 10 LTS + PowerShell 7.6 LTS**, self-contained, hosting `System.Management.Automation`. Invoked only with typed requests and called only through `AddCommand`/`AddParameter`. | .NET runtime, PowerShell SDK, built only when a sidecar is declared | `AddScript` on data; business logic in a sidecar (it is a typed adapter only); any sidecar not declared in the stack manifest |
| **L: lab and test tooling** (never shipped) | lab automation, protocol-fixture recorders, attack replay | Go first. **Python** and PowerShell are allowed only under `lab/` and `tools/`. | none adopted here; each library gets a register row when first used | Any of it inside a shipped artefact |

macOS logon components (Platform SSO extension or authorization plug-in) are **outside this ADR**. When they enter scope, a separate ADR decides their language; feasibility §3.4 recommends Swift because Apple's extension APIs are Swift/Objective-C.

### Rules that make this checkable

1. **Language zones.**
   - Product Go code lives anywhere outside the other zones.
   - TypeScript lives only under `web/`.
   - Rust lives only under `native/`.
   - C/C++ lives only under `native/`, and only for a component recorded as a C++ fallback (rule 4).
   - C# and project files live only under `sidecars/<name>/`, for sidecars declared in the manifest.
   - Python, PowerShell and shell scripts live only under `lab/` and `tools/`, plus build scripts the manifest names.
   - No other language is allowed. `factory/`, `.claude/`, `knowledge/` and `garage/` are not product code and are exempt.

   The blueprint (T-0004) may rename these roots. The rule moves with them.
2. **Pure, cross-compilable Go.** Every Go binary builds with `CGO_ENABLED=0` for `linux/amd64`, `linux/arm64`, `windows/amd64`, `windows/arm64` and `darwin/arm64`.
   - The matrix is a **build** matrix that keeps the platform option open. It is not a **support** matrix; ADR-0002 sets that.
   - OS-specific Go (`_windows.go`, `//go:build`) appears only in packages declared as platform adapters in the manifest. Domain code is OS-neutral.
   - An adapter with no implementation for an OS returns a typed "unsupported on this platform" error, never a silent no-op (PatchIQ §11 #9). Code review checks this.
3. **PostgreSQL is the only stateful service of the server tier.** Jobs, events, snapshots metadata and sessions all live in it.
   - Large blobs (snapshots, GPO backups) go through a storage interface with two backends: a filesystem backend (the default) and an S3-API backend pointed at a customer-supplied store.
   - We never redistribute an object-store server.
   - Agents keep local state (outbox, policy cache) in files under their own data directory. The format is set by the agent design spec.
   - A second store needs its own ADR, backed by the ingest benchmark (follow-on below).
4. **Native-tier gate: Rust by default, C++ by measured exception.** Each DLL starts in Rust in a 2-week Phase-0 spike. A component falls back to C++ only if its spike fails one of these criteria. The fallback is recorded as a dated amendment to this ADR plus a manifest exception citing it. Executing the fallback is within this decision, so it is not a reversal.
   - **Password filter.** It loads into LSASS on a WS2025 DC with `AuditLevel=8` and produces no event 3065 (shared sections). Event 3066 is expected until we have the Microsoft signature. It survives 10,000 scripted password changes, including injected panics, without an LSASS fault.
   - **Credential provider.** It enumerates and renders native fields for `CPUS_LOGON`, `CPUS_UNLOCK_WORKSTATION` and `CPUS_CHANGE_PASSWORD` on Windows 11 x64 and ARM64. It also registers and unregisters cleanly with the system provider still available.
5. **Exceptions are declared, never implied.** The stack manifest (fitness function below) lists:
   - platform-adapter packages;
   - sidecars;
   - C++ fallbacks;
   - copied third-party code under `third_party/<name>/`, each with its LICENSE file.

   Every entry must cite a ratified or accepted ADR.
6. **Every direct dependency is in the licence register before it is merged.** Register rows carry the exact package path in backticks, so CI can match them. Shipped artefacts carry no strong-copyleft licence: GPL, AGPL, SSPL, or the Elastic Licence/BUSL family.

### Build targets per tier (support is decided in ADR-0002 and in the PRDs)

| Tier | CI must produce | Constraint behind it |
| --- | --- | --- |
| S, A (Go) | linux/amd64, linux/arm64, windows/amd64, windows/arm64, darwin/arm64 | Developers work on Apple-silicon Macs. Windows Server is x64-only (feasibility §5.3). |
| N: password filter | windows/x64 only | It runs on DCs, which are x64-only. |
| N: credential provider | windows/x64, windows/ARM64 | It runs on endpoints, which include Windows 11 on ARM (feasibility §1.6). |
| W | static assets inside the Go binary | none |
| X | win-x64 (GPMC helper); linux-x64 and win-x64 (EXO sidecar) | ExchangeOnlineManagement v3 runs on PowerShell 7 on Linux (feasibility §1.9). |

## Alternatives considered

### Server and agent language

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **.NET 10 (C#) for server and agents** | <ul><li>The strongest Windows integration available.</li><li>On Windows, `System.DirectoryServices.Protocols` over wldap32 signs, seals and channel-binds with no adapter of ours.</li><li>Negotiate/SSPI works natively with a gMSA.</li><li>PowerShell SDK and GPMC COM run in-process, with no sidecar.</li><li>Kerberos.NET and mature SAML libraries.</li><li>Native AOT gives single-file deploys.</li><li>For a Windows-only product this is less adapter code than Go.</li></ul> | <ul><li>Off Windows, S.DS.P depends on libldap, so the hardening advantage holds only if the server is Windows-only. That is a CEO fork this ADR must not pre-empt.</li><li>It is a second house runtime, so the agent could not become a module of the Go platform agent (UEM's "one agent process", `../UEM/CLAUDE.md:70`).</li><li>The LTS cadence forces a runtime upgrade every 3 years (.NET 8/9 end 2026-11-10; [lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-and-net-core)).</li><li>It still cannot provide the in-process DLLs.</li><li>We keep its strengths where they are decisive, in tier X.</li></ul> |
| **Java / JVM** (ManageEngine's stack) | <ul><li>Mature JNDI LDAP and JGSS.</li><li>A large hiring pool.</li><li>Parity with the incumbent's integration surface.</li></ul> | <ul><li>A heavy runtime on customer hosts.</li><li>Not a house stack.</li><li>No advantage over Go for MS-RPC/SMB.</li><li>A second runtime on DCs.</li></ul> |
| **Rust everywhere** (server, agents and DLLs) | <ul><li>Memory safety and no GC across the whole product.</li><li>One native language for everything on a DC.</li><li>Good Windows auth via [sspi-rs](https://github.com/Devolutions/sspi-rs).</li></ul> | <ul><li>A thinner AD ecosystem: single-maintainer LDAP crate, no MS-RPC breadth comparable to [go-msrpc](https://github.com/oiweiwei/go-msrpc) (MIT, 100+ protocols).</li><li>Slower iteration for the 90% of the product that is CRUD, jobs and reports.</li><li>Not shared with UEM/PatchIQ.</li><li>We take Rust only where memory safety is decisive (tier N).</li></ul> |
| **TypeScript/Node.js server** | <ul><li>One language from UI to server.</li></ul> | <ul><li>Weak Kerberos, MS-RPC and SMB libraries.</li><li>A runtime on customer hosts.</li><li>Not a house stack.</li></ul> |
| **Python** | <ul><li>impacket, ldap3 and pypsrp have unmatched protocol coverage.</li></ul> | <ul><li>Packaging, performance and type safety are wrong for a shipped Tier-0 product.</li><li>Adopted for **lab tooling only** (tier L).</li></ul> |
| **Rust or C++ DC agent** (Go server kept) | <ul><li>Smaller memory footprint and no GC on DCs.</li><li>One native language for everything on a DC.</li></ul> | <ul><li>It duplicates the safe primitives, protobuf contracts and mTLS client in a second language. That is PatchIQ's per-tier cloning.</li><li>It could not join a Go platform agent.</li><li>The agent is outside LSASS, so a Go crash restarts a service, not the DC.</li></ul> |

### In-process DLL language (tier N)

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **C++ by default** | <ul><li>The conventional route.</li><li>Microsoft's samples are C++ ([CredentialProvider sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider)), so there is no FFI layer.</li><li>Reviewers with LSASS/COM experience are easier to find.</li><li>Every existing password-filter vendor took this path.</li></ul> | <ul><li>A memory bug here means a DC reboot or SYSTEM escalation.</li><li>Lifetime and buffer mistakes are exactly the errors AI-written code makes and the Rust compiler rejects.</li><li>C++ stays the **named fallback** under rule 4, with measurable trigger criteria.</li></ul> |
| **Go `c-shared` DLL** | <ul><li>One language for everything.</li></ul> | <ul><li>Blocked: the DLL embeds a second runtime with its own threads inside LSASS/LogonUI and cannot be unloaded ([#11100](https://github.com/golang/go/issues/11100)).</li></ul> |
| **.NET (COM-visible or hosted CLR)** | <ul><li>Productivity, plus shared code with tier X.</li></ul> | <ul><li>A managed runtime inside LSASS is not a supported route `[UNVERIFIED]`.</li><li>Under PPL every module must meet Microsoft signing rules.</li><li>CLR start-up in LogonUI is fragile.</li></ul> |
| **Defer the choice until the spikes report** | <ul><li>No commitment before evidence.</li></ul> | <ul><li>The spikes need a default to start from, and the fitness function needs zones.</li><li>We take the useful part of deferral as the rule-4 gate.</li></ul> |

### Datastore

| Alternative | What it would buy us | Why not (for now) |
| --- | --- | --- |
| **Microsoft SQL Server as a supported backend** (alone or alongside Postgres) | <ul><li>Some Windows estates mandate SQL Server for every application database.</li><li>Their DBAs already back it up and patch it.</li><li>ManageEngine's AD products are reported to support it `[UNVERIFIED]`.</li></ul> | <ul><li>Two SQL dialects means two data layers. That is the clone pattern we reject, and sqlc does not target SQL Server `[UNVERIFIED]`.</li><li>RLS semantics differ, which weakens the tenancy guarantee.</li><li>It needs a customer licence and is weak on the Linux/Docker profile.</li><li>Revisit trigger below.</li></ul> |
| **Embedded SQLite for small installs** | <ul><li>A zero-admin single file, and the simplest small-site install.</li></ul> | <ul><li>No row-level security.</li><li>A single writer.</li><li>A second schema dialect.</li><li>It does not scale to audit volume.</li><li>The Windows profile bundles PostgreSQL instead (feasibility §4.3).</li></ul> |
| **PostgreSQL + a column store or broker now** (ClickHouse/Timescale for events, Redis/NATS for queues) | <ul><li>Headroom for DC-scale audit ingest (≈3,000 events/s per collector, feasibility §1.5).</li><li>Cheaper long-retention queries.</li></ul> | <ul><li>Every extra service is something an on-prem customer installs, backs up and patches, and PatchIQ's Valkey + Watermill shows the creep.</li><li>River gives transactional job enqueue inside Postgres ([River](https://github.com/riverqueue/river)).</li><li>Whether Postgres is enough for events is an empirical question: the ingest benchmark follow-on answers it before Phase 2.</li></ul> |

## Consequences

**Positive**
- One language (Go) covers the server, connector and agents. Safe primitives, protobuf contracts and the policy model exist once on the Go side. The agent can live standalone or as a module of a skenzeriq platform agent, whichever ADR-0002 decides.
- Pure-Go, cgo-free builds cross-compile from a Mac to every target and produce one static binary per role. That serves air-gapped and Docker installs equally. It also removes the C toolchain PatchIQ's Windows agent needed.
- The two highest-blast-radius components (inside LSASS and LogonUI as SYSTEM) are written in a memory-safe language, with a measured fallback.
- An on-prem customer operates exactly one stateful dependency, PostgreSQL, which we bundle.
- Every load-bearing dependency is MIT, Apache-2.0, BSD or PostgreSQL-licensed, except River (MPL-2.0, below).

**Negative.** This is what the decision costs.
- **We own security-critical adapters** (feasibility §3.5):
  - a GSSAPI client with channel binding on go-krb5/krb5, which is v0.1.0, so we budget to fork it;
  - a RADIUS server;
  - a SAML IdP on goxmldsig;
  - the typed PowerShell bridge.

  .NET would have given us the first one for free on Windows.
- **Two Kerberos client paths.**
  - A Windows-hosted server running as a gMSA has no keytab, so it must bind through go-ldap's Windows SSPI client. Linux/Docker hosts use the go-krb5 adapter with an AES keytab.
  - Both sit behind one `GSSAPIClient` interface, and both need CI: the SSPI path needs the Windows runner.
  - go-msrpc brings its own gokrb5 fork ([go-msrpc](https://github.com/oiweiwei/go-msrpc)), which adds a third Kerberos implementation in the binary unless the connector work unifies them.
- **Three compiled toolchains**, four when a sidecar exists: Go, Rust, TypeScript via Node at build time, and .NET. The CI matrix needs Windows and Windows-ARM runners for tier N.
- **Rust in LSASS has no public precedent**, and few reviewers know Rust COM and LSA internals. AI-written code here needs qualified human review (feasibility App. A #12). If the factory cannot source that review, it is a resourcing question for the CEO, and the director raises it.
- **Password-policy evaluation exists twice.** It runs in Rust, in the filter, with no network I/O in LSASS, and in Go, for SSPR previews and server-side checks. This is a deliberate duplication. Its mitigation is one declarative, signed policy document format plus one shared conformance-vector suite that both CI jobs run. Compiling the Rust evaluator to WASM and running it in Go is the alternative to evaluate when the filter is designed.
- **PostgreSQL only.**
  - Customers whose standard is SQL Server must run PostgreSQL for us.
  - If the ingest benchmark fails, adding an event store later means a migration and a new ADR.
  - River is MPL-2.0: unmodified use inside a proprietary binary is compatible, but we must tell recipients where its source is ([MPL-2.0 §3.2](https://www.mozilla.org/en-US/MPL/2.0/)). The register marks it **Check**, and legal must confirm before GA. If that fails, the fallback is our own `SELECT … FOR UPDATE SKIP LOCKED` job table.
- **Go's garbage collector can copy secrets.** Passwords stay `[]byte` with short lifetimes (feasibility §2.5). Plaintext on DCs exists only in Rust.
- **The UI ships with the server.** Assets are embedded, so a UI-only fix still needs a server release.
- **AV/EDR heuristics sometimes flag unsigned Go binaries** `[UNVERIFIED]`. Authenticode signing of every Windows binary is therefore required from the first agent build.

**Follow-on work** (all filed in `backlog` with T-0002 as a dependency):
- **T-0022** `chore` · devops-engineer: implement the `fitness-stack` job (below) inside `make ci`. It depends on T-0014 (scaffolding) and T-0015 (dispatcher pre-merge gate).
- **T-0024** `spike` · windows-engineer: Rust password filter in LSASS (rule-4 gate).
- **T-0025** `spike` · windows-engineer: Rust credential provider in LogonUI (rule-4 gate).
- **T-0023** `spike` · directory-engineer: LDAP SASL/GSSAPI bind with channel binding on go-krb5/krb5. Samba 4.21+ with strong auth first, then WS2025 with signing and CBT set to "Always", and no events 2887/3039/3074 (feasibility §2.4). **This spike is the main risk to the Go server choice.**
- **T-0026** `spike` · backend-engineer: PostgreSQL partitioned event ingest at ≥ 5,000 events/s synthetic (feasibility §6.2), which decides whether rule 3 holds for audit.
- **T-0027** `ops` · devops-engineer: scope Microsoft LSA file-signing (Partner Center) and Authenticode/EV certificate enrolment. These end in CEO actions (money, legal identity). They have the longest lead time in Phase 2, so they start early.
- Architecture map: T-0004 (blueprint v0) links this ADR and fixes the zone roots (`web/`, `native/`, `sidecars/`, `lab/`, `tools/`, `third_party/`).
- T-0005 (safe primitives): primitives exist in Go for tiers S and A. Tier N needs only the secret-handling and message-parsing subset, in Rust.
- Left open on purpose: HTTP router and OpenAPI generator (the API-contract ADR); migration runner and schema conventions (the data-model and tenancy ADRs); `msgraph-sdk-go` versus a thin generated client, go-msrpc, go-smb2, and the winlogbeat `wineventlog` wrappers. Each is adopted by its first ticket, and each needs a register row first.

**Revisit when** (a superseding ADR, except for rule 4, which is an amendment):
- The CBT spike cannot make go-krb5/krb5 bind under "Always" within 4 weeks, including a fork.
- The ingest benchmark misses 3,000 events/s sustained per collector on reference hardware.
- Two or more qualified deals are lost because of a SQL Server mandate, per sales notes.
- ADR-0002 makes the server Windows-only *and* the adapter cost has become dominant.
- UEM's platform agent settles on a language other than Go.
- Go or Rust drop a target we ship on.

## Fitness function

**Job:** `fitness-stack`. It is a Go program at `tools/fitness/stack/` (final path per T-0004), driven by a machine-readable manifest at `tools/fitness/stack/manifest.json`. It is built by T-0022 and invoked by `make ci` (T-0014). Until hosted CI exists, the dispatcher runs `make ci` before every merge (T-0015). It fails the build when any of these checks fails:

| # | Check | Fails when |
| --- | --- | --- |
| F1 | **Language zones** (rule 1) | A tracked source file's language is not allowed in its path zone: `.rs` outside `native/`; `.c/.cpp/.h` outside a declared C++ fallback; `.cs`/`.csproj` outside a declared sidecar; `.py`/`.ps1`/`.sh` outside `lab/`, `tools/` or named build scripts; `.ts/.tsx` outside `web/`; any `.java .kt .rb .php .lua .bat .cmd .vbs .swift` file. A `go.mod`, `package.json`, `Cargo.toml` or `*.csproj` outside its zone. |
| F2 | **Pure, cross-compilable Go** (rule 2) | `CGO_ENABLED=0 go build ./...` fails for any target in the build matrix. Any `import "C"`, `//export`, or `-buildmode=c-shared\|c-archive\|plugin\|shared` appears anywhere in the tree. The `plugin` package is imported. A `_GOOS.go` suffix or `//go:build` constraint appears outside a declared platform-adapter package. `go.mod` files disagree on the `toolchain` directive. `rust-toolchain.toml` is missing when `native/` exists. |
| F3 | **One stateful service** (rule 3) | `go list -deps` of any server or agent binary contains a denylisted package. The denylist covers clients for Redis/Valkey, Kafka, NATS, MongoDB, Elasticsearch/OpenSearch, ClickHouse and SQL Server; cgo or alternative SQL drivers; ORMs (gorm, ent, bun); and `database/sql` drivers other than pgx's. The denylist lives in the manifest. Other ADRs may append to it; the security ADR may ban script interpreters, for example. |
| F4 | **Licence register** (rule 6) | A direct dependency in any product `go.mod`, `web/package.json`, `native/**/Cargo.toml` or sidecar project, or a `third_party/<name>/` directory, has no register row containing its exact package path in backticks, or its row's status is `Rejected`. A licence scanner finds GPL, AGPL, SSPL, Elastic Licence or BUSL in the transitive closure of a shipped artefact. The scanner tools are chosen and registered by the fitness ticket. |
| F5 | **Exceptions cite an ADR** (rule 5) | A manifest exception (platform adapter, sidecar, C++ fallback, extra `go.mod`, `third_party/` entry) names no ADR file, or names one whose status is not `ratified` or `accepted`. |

**Bypasses and how they are closed.**
- **Excluding a path from F1, or adding an exception.** Every exception is an entry in the manifest, and F5 refuses entries without a ratified ADR. That turns "quietly allow C++ here" into an ADR amendment a reviewer sees.
- **cgo hidden behind a build tag.** F2 also scans the source text, so even `//go:build ignore` files fail.
- **Copy-pasting third-party code to avoid a manifest entry.** It must sit in `third_party/<name>/` with its LICENSE file (F4/F5). Code review (`review-checklist`) treats unattributed copied code as a reject. That part stays manual and is named as such.
- **A Go DLL built in another repository.** It is outside this check. It is also outside our release pipeline: signing is human-gated (feasibility §5.7), and the release checklist accepts tier-N binaries only from `native/`.

**Status path.** This ADR becomes `ratified` when the director signs it off at review of T-0002. It becomes `accepted` when `fitness-stack` runs green in `make ci` on `main`, with F1–F5 implemented.

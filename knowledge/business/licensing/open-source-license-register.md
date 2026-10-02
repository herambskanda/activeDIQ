---
title: "Open Source Licence Register — activeDIQ"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# Open Source Licence Register

> **Purpose.** One place that answers: which outside code do we use, how much, under what licence,
> and does it need a conversation before we ship? activeDIQ ships **on-prem**, which is
> *distribution* — the act that triggers copyleft obligations.
>
> **Not legal advice.** Engineering triage to decide what needs a lawyer. Anything embedded gets a
> real legal review before we ship it. Adapted from `../UEM/knowledge/business/licensing/`.
>
> **Rule:** every new dependency gets a row here *before* it is adopted (CLAUDE.md rule 9).

---

## 1. The three ways we can use someone's project

The licence only matters for some of these. Getting this distinction right saves a lot of
unnecessary negotiation.

| Mode | What it means | Licence needed? |
| --- | --- | --- |
| **Inspiration** | We read their code and docs, learn the design, then write our own | **No.** Ideas and architecture are not copyrightable. Only the actual code is. This is always free. |
| **Separate process** | We ship their program unmodified next to ours and talk over an API or network | **Usually no derivative work** ("mere aggregation"). The escape hatch closes if we modify them. |
| **Embedded** | We copy their code, link their library, or build it into our binary | **Yes.** This is where copyleft and proprietary terms bite. |

**Most of what we want is inspiration.** Studying how other tools model delegation or audit
events costs nothing and needs nobody's permission. We only need a conversation when we want the
actual code inside our product.

---

## 2. The question that decides whether negotiation is even possible

**Can they legally grant us a licence?**

- **Yes — single owner or CLA.** If one company owns the code, or every contributor signed a
  Contributor Licence Agreement handing rights to the project, then one party can say yes. These
  are worth approaching.
- **No — diffuse copyright.** If a project has many outside contributors and no CLA, nobody owns
  all of it. The maintainers cannot relicense it even if they want to, because they do not hold
  the rights to other people's contributions. Approaching them is wasted effort.


---

## 3. Register

Status key: **Clear** = no action needed. **Talk** = worth a conversation. **Check** = needs legal
review or more research. **Candidate** = under consideration, not adopted (adoption needs the ADR
that chooses the stack). **Rejected** = considered and not adopted, kept for the trail (the reason
is in the Use column).

**Machine matching.** A row's Project cell carries the exact package path(s) in backticks. The
`fitness-stack` job of [ADR-0001](../../development/decisions/0001-technology-stack.md) (check F4)
fails CI when a direct dependency has no matching row, or when its row is **Rejected**.

| Project | Licence | Use | Mode | Ships to customers? | Status |
| --- | --- | --- | --- | --- | --- |
| Node.js (factory runtime) | MIT | Internal tooling only. Builds the web UI at compile time (ADR-0001); never shipped | Separate process | No | **Clear** |
| Go toolchain, standard library, `golang.org/x/sys` | BSD-3-Clause ([licence](https://go.dev/LICENSE)) | Language of the server, connector and agents (ADR-0001). The standard library is statically linked. Other `golang.org/x/*` modules get their own row when adopted | Embedded | Yes | **Clear** (toolchain and standard library, adopted by T-0014 at go1.27.0); `golang.org/x/sys` stays **Candidate** until imported |
| go-ldap/ldap (`github.com/go-ldap/ldap/v3`) | MIT ([repo](https://github.com/go-ldap/ldap)) | LDAP client of the directory connector (ADR-0001) | Embedded | Yes | **Candidate** |
| go-krb5/krb5 (`github.com/go-krb5/krb5`) | Apache-2.0 ([repo](https://github.com/go-krb5/krb5)) | Kerberos client: GSSAPI bind with channel binding, kpasswd change/set (ADR-0001). At v0.1.0 it is young, so we budget to fork it | Embedded | Yes | **Candidate** |
| jcmturner/gokrb5 (`github.com/jcmturner/gokrb5/v8`) | Apache-2.0 | Not adopted for direct use: dormant since 2023 and superseded by go-krb5/krb5 (ADR-0001). A fork may still arrive transitively through go-msrpc, which the transitive licence scan covers | Embedded | — | **Rejected** (direct use) |
| microsoftgraph/msgraph-sdk-go (`github.com/microsoftgraph/msgraph-sdk-go`) | MIT | Entra ID / M365. The first Graph ticket decides between this SDK and a thin generated client (ADR-0001) | Embedded | Yes | **Candidate** |
| jackc/pgx (`github.com/jackc/pgx/v5`) | MIT ([repo](https://github.com/jackc/pgx)) | The only PostgreSQL driver, pure Go (ADR-0001) | Embedded | Yes | **Candidate** |
| sqlc (`github.com/sqlc-dev/sqlc`) | MIT ([repo](https://github.com/sqlc-dev/sqlc)) | Generates Go code from SQL. The generated code is ours (ADR-0001) | Dev tooling | No | **Candidate** |
| River (`github.com/riverqueue/river`, `github.com/riverqueue/river/riverdriver/riverpgxv5`) | MPL-2.0 ([repo](https://github.com/riverqueue/river)) | Job queue inside PostgreSQL (ADR-0001). MPL-2.0 copyleft applies per file: using it unmodified in a proprietary binary is compatible, but recipients must be told where the MPL-covered source is ([MPL-2.0 §3.2](https://www.mozilla.org/en-US/MPL/2.0/)). Fallback: our own `SKIP LOCKED` job table | Embedded | Yes | **Check**: legal must confirm before GA |
| gRPC-Go (`google.golang.org/grpc`) | Apache-2.0 ([repo](https://github.com/grpc/grpc-go)) | Agent and connector channels over mTLS (ADR-0001) | Embedded | Yes | **Candidate** |
| protobuf-go (`google.golang.org/protobuf`) | BSD-3-Clause ([repo](https://github.com/protocolbuffers/protobuf-go)) | Typed messages on the agent and connector channels (ADR-0001) | Embedded | Yes | **Candidate** |
| React (`react`, `react-dom`) | MIT ([repo](https://github.com/facebook/react)) | Web UI (ADR-0001) | Embedded | Yes | **Clear** (adopted by T-0014 at 19.3.0; the shipped closure is `react`, `react-dom`, `scheduler`, all MIT) |
| TypeScript (`typescript`) | Apache-2.0 ([repo](https://github.com/microsoft/TypeScript)) | Language of the web UI. The compiler does not ship; the compiled output is ours (ADR-0001) | Dev tooling | No | **Clear** (adopted by T-0014, pinned in `web/package.json`) |
| Vite (`vite`) | MIT ([repo](https://github.com/vitejs/vite)) | Web build tool. Its bundles are embedded in the server binary (ADR-0001) | Dev tooling | No | **Clear** (adopted by T-0014, pinned in `web/package.json`). Its CSS toolchain pulls `lightningcss` (MPL-2.0) at build time only; it is not in the shipped bundle |
| PostgreSQL | PostgreSQL Licence ([licence](https://www.postgresql.org/about/licence/)) | The only datastore of the server tier. We bundle major 18; customer-supplied servers must be 16 or later (ADR-0001) | Separate process | Yes (bundled) | **Candidate** |
| Rust toolchain and standard library (`rustc`, `cargo`, `std`) | MIT OR Apache-2.0 ([repo](https://github.com/rust-lang/rust)) | In-process native tier: the password-filter and credential-provider DLLs (ADR-0001). `core`/`std` are statically linked | Embedded | Yes | **Candidate** |
| windows-rs (`windows`, `windows-core`, `windows-implement`) | MIT OR Apache-2.0 ([repo](https://github.com/microsoft/windows-rs)) | Win32/COM bindings and COM authoring for the native tier (ADR-0001) | Embedded | Yes | **Candidate** |
| .NET 10 runtime (`Microsoft.NETCore.App`) | MIT ([repo](https://github.com/dotnet/runtime)) | Sidecar tier only, published self-contained. Built only when a sidecar is declared (ADR-0001) | Separate process | Yes, when a sidecar ships | **Candidate** |
| PowerShell 7.6 SDK (`Microsoft.PowerShell.SDK`) | MIT ([repo](https://github.com/PowerShell/PowerShell)) | Hosted in the sidecar and called only with `AddCommand`/`AddParameter` (ADR-0001). Also used for lab scripts | Embedded (in the sidecar) | Yes, when a sidecar ships | **Candidate** |
| Python (CPython) | PSF-2.0 ([licence](https://docs.python.org/3/license.html)) | Lab and test tooling only, under `lab/` and `tools/` (ADR-0001). Its libraries get rows when adopted | Dev tooling | No | **Clear** for lab use |
| MinIO server (`github.com/minio/minio`) | AGPL-3.0 ([repo](https://github.com/minio/minio)) | Not adopted: we do not redistribute an object-store server (ADR-0001 rule 3). The repository was archived on 2026-04-25 | Separate process | No | **Rejected** |
| Samba 4 (AD DC) | GPL-3.0 | Test lab only (Docker, `lab/`, T-0012): Debian `samba` 4.22 built into a local image that is never pushed or distributed | Separate process | No | **Clear** for testing; **Check** before any shipping use |
| Debian 13 (`debian:trixie-slim`) base image + `ldb-tools`, `ldap-utils` (OpenLDAP, OpenLDAP Public License), `krb5-user` (MIT-style), `winbind` | Mixed (GPL, LGPL, permissive) — per-package Debian copyright files | Base of the lab container only (T-0012). Pinned by digest; image stays local | Separate process | No | **Clear** for testing; never a base for a shipped image |
| libfaketime (`faketime`) | GPL-2.0 ([repo](https://github.com/wolfcw/libfaketime)) | Lab seeding only: sets the clock back so Samba records past `pwdLastSet` values (T-0012). Runs inside the lab container, never in the product | Separate process | No | **Clear** for testing |
| OpenSSL (`openssl` CLI) | Apache-2.0 ([licence](https://www.openssl.org/source/license.html)) | Generates the lab CA and server certificate (T-0012) | Dev tooling | No | **Clear** for lab use |
| Playwright (`@playwright/test`, `playwright`, `playwright-core`) | Apache-2.0 ([licence](https://github.com/microsoft/playwright/blob/main/LICENSE)) | Pinned at 1.63.0 in `tools/playwright/` (T-0011): E2E tests, QA screenshots, demo recording. Downloads Chromium (Chrome for Testing, BSD-3-Clause plus bundled third-party licences) and an ffmpeg build into a per-user cache; browsers are never committed and never shipped | Dev tooling | No | **Clear** for dev use |
| FFmpeg | LGPL-2.1+ (GPL with some options) | Demo/tutorial video editing | Dev tooling | No | **Clear** for internal use |
| gitleaks (`github.com/gitleaks/gitleaks`) | MIT ([licence](https://github.com/gitleaks/gitleaks/blob/master/LICENSE)) | Secret scanner, pinned at 8.30.1 with SHA-256-verified release archives (T-0013): the pre-commit hook and `make secrets-scan`. Downloaded to a per-user cache, never committed | Dev tooling | No | **Clear** |
| Web build and test tooling (`@vitejs/plugin-react`, `vitest`, `eslint`, `@eslint/js`, `typescript-eslint`, `prettier`, `@types/react`, `@types/react-dom`) | MIT (each package's `license` field in `web/package-lock.json`) | Web console build, lint, format and unit tests (T-0014), pinned exactly in `web/package.json` with a lockfile. Transitive closure checked: MIT, Apache-2.0, BSD, ISC, BlueOak-1.0.0 and MPL-2.0 (`lightningcss`, build-time only, never shipped). Types and tools are not in the shipped bundle | Dev tooling | No | **Clear** |
| Licence scanning in `fitness-stack` F4 (`tools/fitness/stack`) | Ours (no third-party code) | T-0022. The Go scan reads the LICENSE files of the modules in each shipped binary's `go list -deps` closure; the web scan reads `license` fields in `web/package-lock.json`; the Rust scan reads `cargo metadata` (`cargo` is part of the Rust toolchain row above). It adds no dependency, needs no network and runs on the standard library only | Dev tooling | No | **Clear** |
| go-licenses (`github.com/google/go-licenses`) | Apache-2.0 ([repo](https://github.com/google/go-licenses)) | Considered for T-0022 and not adopted: the in-repo scan covers the strong-copyleft families ADR-0001 bans without a network install. Revisit when notice generation for release bundles needs it | Dev tooling | No | **Candidate** |
| cargo-deny (`cargo-deny`) | Apache-2.0 ([repo](https://github.com/EmbarkStudios/cargo-deny)) | Considered for T-0022 and not adopted: `cargo metadata` already feeds F4. Revisit with the first Rust crate (T-0024), for advisories and per-crate licence policy | Dev tooling | No | **Candidate** |

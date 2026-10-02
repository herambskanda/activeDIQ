---
name: engineering-standards
description: How activeDIQ code is structured and written — module boundaries, extension points, dependencies and licences, logging, config, migrations, performance budgets, git, DoD, PatchIQ anti-patterns as hard rules. Use before writing product code.
---

# Engineering standards

PatchIQ was abandoned because nobody, human or agent, could hold its shape in their head
(`../UEM/knowledge/development/legacy/patchiq-postmortem.md` §11). Every rule here keeps
activeDIQ **explainable**: a new agent reads the architecture map and one module and can change
it safely. Stack details are **provisional until ADR-0001** (house stack of sister products:
Go backend, React + TypeScript with Vite, Tailwind and TanStack, PostgreSQL). Until ADR-0001 is
ratified, **no product code** — only `garage/` spikes.

Language-level rules: `reference/style.md`. The anti-pattern rules: §9 below.

## 1. Repository shape

The map is fixed by [blueprint v0 §1](../../../knowledge/development/architecture/blueprint.md)
(§1.1 lists the paths it made final). If this summary and the blueprint disagree, the blueprint wins.

```
cmd/<role>/              one main per process (server, connector, edge, agent, …): load config, call internal/compose/<role>, run
internal/compose/        composition root: <role>/ wiring per binary (server, agent hold modules.gen.go), profile/ (manifest data), config/ (the only env reader)
internal/platform/       extractable kernel: tenant, store (WithTenantTx; exempt, reportsql), module, authn, authz, audit, jobs, operation, keys, secret, proc, pslit, fleet, …
internal/directory/      directory domain: safe primitives (ldapfilter, dn, attr/*), model, inventory, sync, client
internal/connector/      connector root: the only importer of LDAP/Graph libraries and the only unsealer of directory credentials (service, provider/{ad,entra}, ldap, kerberos, credential, psx, ad/scope)
internal/modules/<id>/   one directory per server feature module (connections, objects, helpdesk, delegation, lifecycle, workflow, reports, …)
internal/agentmodules/<id>/  agent modules (addc, fileserver) [M3]
internal/proto/          generated Go for proto/ — never hand-edited
proto/                   protobuf sources (skenzeriq/agent/v1, activediq/connector/v1, activediq/<agent-module>/v1)
api/openapi/             public contract — source of truth (api-design)
migrations/              one forward-only SQL sequence, NNNN_<owner>_<what>.sql
web/                     React + TypeScript console: src/app, src/modules/<id>, src/ds, src/api (generated); Playwright suites in web/e2e
native/                  Rust workspace for in-process DLLs: passfilt, credprov, shared [M4]
sidecars/<name>/         .NET + PowerShell typed adapters (pshost, exchange, gpmc)
packaging/               windows/ (MSI) and oci/ (Dockerfiles, Compose)
testdata/safe-primitives/  the primitive corpus, one <unit>.jsonl per unit
tools/                   fitness/<job>/, analyzers/, vettool/, gen/, playwright/
lab/                     AD lab: Samba compose, seed generator, reset scripts (testing-playbook)
third_party/<name>/      copied third-party code with its LICENSE
garage/<name>/           prototypes with OWNER and EXPIRES — never imported by product code
```

TypeScript lives only under `web/` (ADR-0001 rule 1), so Playwright suites are `web/e2e/`.
Windows-native code is split by tier: in-process DLLs in `native/` (tier N), DC and file-server
agent modules in `internal/agentmodules/` (tier A).

`knowledge/development/architecture/` holds the **architecture map**: one page per module
(purpose, owned data, public interface, extension points it implements, dependencies). A ticket
that adds, removes or re-wires a module updates the map in the same change.

## 2. Module boundaries and extension points first

- Modules talk through **interfaces in their public package** or through events — never by
  importing another module's internals or reading its tables. `internal/platform` imports no
  module. Enforced by an import-rule fitness function in CI.
- **The extension point exists before the first feature on its tier, and it is the only on-ramp**
  (PatchIQ's unused `Module` interface: §11 #2; precedent `../UEM/knowledge/development/decisions/0002-extension-points-precede-features.md`).
  Expected seams: directory connector (AD LDAP, Entra Graph), report definition (data, not code),
  workflow action, audit event source, notification channel, module registration. If you need a
  seam that does not exist, stop: file a `spec` ticket for `solution-architect`.
- No constructor or router with a growing parameter list; modules register themselves through
  the registry. A function with more than ~6 dependencies is a design smell to raise in review.
- **Parameterise, don't clone.** Adding Entra next to AD, or a second report like the first, is a
  new implementation of the same interface or new data — never a copied-and-edited package.

## 3. Dependencies

1. Prefer the standard library and what we already use. Each new direct dependency must earn its
   place: name it, the alternative, and why in the ticket note.
2. **Check the licence register** in `knowledge/business/licensing/` first (CLAUDE.md rule 9 — we
   ship on-prem; distribution triggers copyleft). Permissive (MIT, BSD, Apache-2.0, ISC) → add
   a register row in the same ticket. Weak copyleft (MPL-2.0, LGPL, EPL) → `security-architect`
   and `solution-architect` note in the ticket. Strong or network copyleft (GPL, AGPL, SSPL,
   BUSL, "commons clause") in anything we ship → **blocked**; legal is a CEO call
   (`ceo-decisions`). Test-only tooling (Samba lab) is recorded as test-only. No register file
   yet? Create it with your row — do not skip the step.
3. Pin exact versions with lockfiles (`go.sum`, `pnpm-lock.yaml`); CI actions pinned by SHA.
   Vulnerability scanning in CI (`security-baseline` §8). No abandoned packages (no release in
   2 years and open security issues).

## 4. Errors and logging

- Errors carry context and wrap the cause; they are mapped to problem types at the API edge only
  (`api-design` §4). Never swallow an error; never `panic` for control flow; never return a
  partial result that looks complete (the AD paging trap).
- **Structured JSON logs** (`slog` provisional): `ts level msg traceId module` + domain keys
  (`directoryId`, `objectGuid`, `jobId`). Prefer GUIDs over names — names are personal data.
- **Never log secrets**: passwords, `unicodePwd`, tokens, cookies, `Authorization`, bind
  credentials, gMSA/LAPS/BitLocker material, security answers, OTPs, private keys. Enforce at the
  type level: a `Secret` type whose string and JSON forms are `[REDACTED]`. A secret in a log is a
  P0 bug.
- Audit events are not logs: they go through `internal/platform/audit` (`security-baseline` §7).

## 5. Configuration

12-factor: config from environment and one config file; no environment-specific code paths.
**Deployment profiles** (single-node on-prem, HA, possibly MSP/SaaS — set by ADR-0001) are
compositions of the same binaries, not branches. Secrets are references (OS keychain, DPAPI,
Vault), never plaintext values in config. Every setting has a default, validation at startup,
and documentation.

## 6. Migrations

Forward-only, numbered, one concern each, reviewed like code. Expand → migrate → contract for
anything breaking (add column, backfill, switch reads, drop later). No long table locks on large
tables; tested against the 50k-object fixture. **If ADR-0001 includes MSP or SaaS use, every
domain table has the tenant key from migration 1** and row-level security set with parameterised
`set_config($1, true)` — never string-built SQL (§11 #1 NC1, #6).

## 7. Performance budgets

| Budget | Target | Proven by |
| --- | --- | --- |
| UI interaction | < 100 ms perceived (optimistic or skeleton within 100 ms) | Playwright timing on the 50k fixture |
| List endpoint | p95 < 300 ms at 50k objects | benchmark in CI against seeded store |
| Bulk operation | 10k objects per job, progress at least every 2 s, resumable | lab job test |
| DC load | outbound per-DC concurrency cap; paged searches only; no `*` attribute lists | connector tests, review |

A change that regresses a budget is a reject, not a follow-up.

## 8. Git workflow

Branch `factory/T-xxxx` (worktree per ticket); conventional commits ending with the ticket ID —
`feat(directory): add ranged retrieval for member (T-0042)`; small atomic commits, each building
and passing tests. Never commit to `main`, merge, rebase `main` or force-push: the dispatcher
merges after QA. Full rules: `factory-protocol` §7.

## 9. PatchIQ anti-patterns — hard rules

| # | PatchIQ failure (§11) | Rule here | Countermeasure |
| --- | --- | --- | --- |
| 1 | Mental model lost; 12-agent audits to know state | Architecture before code; map updated by every structural change | DoD item; reviewer checks the map diff; weekly comprehension check |
| 2 | Extension interface written, then bypassed | Seam first, only on-ramp | ADR + import-rule fitness function |
| 3 | Copy-and-adapt per variant | Parameterise, don't clone | Review blocker; CI duplication check |
| 4 | One customer's topology and names in shared code | Partner/customer names only in `knowledge/business/partnerships/` | CI grep for partner names |
| 5 | Bespoke parallel pipeline per delivery mode | One signed build; profiles and transports differ, artefacts don't | ADR-0001 fitness function |
| 6 | Tenancy retrofitted | Tenant key from migration 1 if multi-tenant | Migration lint |
| 7 | Secrets committed | `.env*` ignored, gitleaks pre-commit and CI, guard hook | CI fails on findings |
| 8 | Dead trees and tooling dirs in main | Prototypes in `garage/` with expiry; superseded code deleted in the same change | DoD; weekly tech-debt sweep |
| 9 | Capability asymmetry across platforms | Every spec states its platform matrix (AD / Entra / hybrid; Windows-only parts) | Spec review |
| 10 | `Sprintf`-built security strings recurring | Safe primitives only; raw construction banned by type and lint | Lint; fuzz tests; `security-architect` |

Also from PatchIQ: **no fake data in the UI, no dead buttons** (NC7) — QA clicks every control.

## 10. Definition of Done (build, bug)

All ACs demonstrably met · tests written and passing (`testing-playbook`) · code review passed ·
QA passed with evidence · docs and the architecture map updated if anything user-visible or
structural changed · OpenAPI updated with any API change · licence register updated for new deps
· superseded code deleted · merged to `main` by the dispatcher · two-line summary on the ticket.

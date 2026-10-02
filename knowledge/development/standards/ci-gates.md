---
title: "Standard: CI gates and `make ci`"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: devops-engineer
ticket: T-0014
---

# Standard: CI gates and `make ci`

**Rule.** `make ci` is the one command that must pass before anything merges (the dispatcher runs it
pre-merge once T-0015 lands). A gate is not a gate until a deliberate violation makes it fail:
`make ci-proof` (part of `make ci`) keeps every gate honest by running it against a violation and
against clean input.

## What `make ci` runs

| Gate | Command | Fails when | Proof in `tools/ci/proof.sh` |
| --- | --- | --- | --- |
| Go format | `tools/ci/gofmt-check.sh` | any Go file is not gofmt-clean | unformatted file |
| Go vet | `go vet ./...` | vet finds a defect | bad `Sprintf` verb |
| Module hygiene | `go mod tidy -diff`, `go mod verify` | `go.mod`/`go.sum` untidy or a module differs from its hash | untidy `go.mod` |
| Web types | `tsc --noEmit` (strict, `noUncheckedIndexedAccess`) | a type error | type error |
| Web lint | `eslint` (typescript-eslint strict + bans on `any`, `eval`, `console`, `innerHTML`, `dangerouslySetInnerHTML`) | any rule fires | one file, four violations |
| Web format | `prettier --check` | any source is unformatted | unformatted file |
| Go tests | `go test -count=1 ./...` | a test fails | failing test |
| Web tests | `vitest run` | a test fails | failing test |
| Fitness: `fitness-modules` | `go run ./tools/fitness/modules` | an import breaks blueprint §2 rules 1–5, 7, 8 | CLI on a tree where `platform` imports `directory`; every rule also has a failing fixture in `tools/fitness/modules/check_test.go` |
| Fitness: `fitness-stack` | `go run ./tools/fitness/stack` (manifest: `tools/fitness/stack/manifest.json`) | ADR-0001 F1 language zones, F2 cgo/plug-in/build-tag bans and the `CGO_ENABLED=0` cross-build of linux/amd64, linux/arm64, windows/amd64, windows/arm64, darwin/arm64, F3 denylisted stateful dependency in a shipped binary, F4 register row missing or Rejected and strong-copyleft licences in a shipped closure, F5 exception without a ratified or accepted ADR | the real CLI on throw-away trees, one violation per rule (`tools/ci/proof.sh`); every rule also has a fixture in `tools/fitness/stack/check_test.go` |
| Fitness: `fitness-profiles` | `go run ./tools/fitness/profiles` (manifest: `tools/fitness/profiles/manifest.json`; UEM denylist: `uem-denylist.json`) | ADR-0002 P1 domain code imports `internal/compose`, reads a profile-selecting environment variable, names a profile (`isSaaS`, `selfHosted`, `linuxOCI`, …) or a capability after one; the two self-hosted manifests differ in a capability without an exception citing a ratified ADR; a manifest composes `t0-connector` or `edge` beside another role, puts `t0-connector` in the `saas` cell, or gives the cell an AD provider; P7 a branch other than `main` and `factory/T-NNNN`; U1 a go.mod/go.work/import naming a UEM or PatchIQ module, a `replace` or `use` outside the repository, or the stack manifest not extending the UEM denylist; U2 a package under `internal/platform` importing a directory-domain, connector, module or composition package; the activation table: a subject path exists (installer, connector, updater, agent protos) and its check is not implemented or does not pass, or a row for P2-P6, U3 or U4 is missing | the real CLI on throw-away trees, one violation per rule, plus the clean tree and the printed pending table (`tools/ci/proof.sh`); every rule also has a fixture in `tools/fitness/profiles/check_test.go` |
| Fitness: `fitness-safeprim` | `go run ./tools/fitness/safeprim` (plus the `web/eslint/safe-primitives.js` rules inside Web lint) | safe-primitives FF-SP1 an import outside its home (LDAP, SQL driver, process, PowerShell SDK, CSV, XLSX, PDF, mail, tier L); FF-SP2 a banned symbol, TLS-verification bypass, pprof, crash-mode `GOTRACEBACK`, or a finding of the `dnstring`, `sqlconst`, `secretjson` and `tmplconst` analyzers; FF-SP3 a filter-, DN-, PowerShell-, SQL-, HTML- or header-shaped literal built by concatenation, `+=`, formatting (the whole `fmt` family, a const or variable template, any literal with a printf verb), `strings`/`bytes` joins and replacers, in Go and in `web/` (template, `+`, `+=`, `.concat`, `.join`, `{name}`/`%s` slots) | the real CLI on throw-away trees, FF-SP1 ×3, FF-SP2 ×5, FF-SP3 ×5 (Sprintf, const template, `+=`, `Errorf`, quote doubling) and a product package named `target`, `bin` or `obj` still scanned, with clean primitives and tests passing, plus the web rules on `web/proof/safe-primitives-violation.ts` and one proof per spelling on `web/proof/safe-primitives-spellings.ts` (`tools/ci/proof.sh`); every rule also has a fixture in `tools/fitness/safeprim/scan/scan_test.go`, `tools/analyzers/*/testdata` and `web/eslint/safe-primitives.test.js` |
| Fitness: `fitness-corpus` | `go run ./tools/fitness/corpus` (manifest and ratchet: `testdata/safe-primitives/implementations.json`, `records.lock.json`) | safe-primitives FF-SP4 a unit with fewer than 10 `hostile` records, a record that vanished without a superseding one, an implementation that skips a record, runs another corpus copy or is not declared; FF-SP5 an implemented unit without a corpus-seeded fuzz target; FF-SP8 an argv that differs from the manifest's constant argv | the real CLI on throw-away trees: 9 hostile records, a removed record, a skipping implementation, Go code in a primitive's home nobody declares, no fuzz target, a nightly run shorter than 10 minutes, a differing argv (`tools/ci/proof.sh`); every rule also has a fixture in `tools/fitness/corpus/check_test.go`, and `e2e_test.go` runs a real Go implementation end to end |
| Fitness: `fitness-oracles` | `go run ./tools/fitness/oracles pslit\|ldapfilter` (needs Docker or `pwsh`) | safe-primitives FF-SP6 a `pslit` output that PowerShell's own parser does not read as exactly one single-quoted string with the same value; a P1 filter that go-ldap does not compile or round-trip to a single assertion | the real CLI against an ASCII-only escaper's PSQ-06 and an unescaped injection (`tools/ci/proof.sh`), plus the oracle's own tests |
| Generated code freshness: `gen-check` | `go run ./tools/gen/proto -check` | `internal/proto` is stale, hand-edited or holds an orphaned `*.pb.go` against a fresh generation from `proto/` | the real CLI on a throw-away tree: hand-edited, orphaned and missing file each refused (`tools/ci/proof.sh`) |
| Web build | `vite build` | the build fails | — (a build failure is its own signal) |
| Secret scan | `make secrets-scan` | gitleaks finds a secret in history or the working tree | `make secrets-test` (T-0013) |
| Lab generator tests | `make lab-test-unit` | the seed generator's tests fail (no Docker needed) | — |

## What is deliberately not here yet

Each of these has an owner; none is faked.

| Gate | Owner |
| --- | --- |
| SBOM generation; NuGet transitive licence scan (fails closed once a sidecar is declared) | later `ops` tickets |
| Safe-primitives FF-SP5 nightly fuzz log and the FF-SP6 Windows (PowerShell 5.1, SID, GUID) and Samba lab rows: the targets exist (`fitness-nightly`, `fitness-oracles-windows`) but no scheduler or Windows runner exists | follow-up tickets from T-0034 (runbook `safe-primitives-fitness.md`) |
| Safe-primitives FF-SP9 to FF-SP11 | the `psx` build, the P7 build tickets |
| Activation-table checks P2 to P6, U3 and U4 (installer build and boot, connector transports, multi-tenant composition, offline round trip, no egress, agent contract): each is implemented by the ticket that lands its subject, and `fitness-profiles` fails until it is | the packaging, connector, updater and agent-proto tickets (T-0039, T-0040, M2) |
| `modules.gen.go` / `modules.gen.ts` staleness, which needs `tools/gen/modules` | the module-system ADR (T-0045) |
| Dependency vulnerability scan, duplication check, signing, release | later `ops` tickets; signing is a CEO matter (T-0027) |
| Dispatcher runs `make ci` before merge | T-0015 |

## Rules for adding a gate

1. Add it to `tools/ci/ci.mk` under `ci`. Never `-` prefix a recipe line, never `|| true`, never
   `continue-on-error`.
2. Add its failing and passing case to `tools/ci/proof.sh`, using `must_fail_with` so it fails for the
   expected reason, not because a tool is missing.
3. Add any new tool to the licence register first (CLAUDE.md rule 9) and pin its version.

## Toolchain pins

| Tool | Pin | Where |
| --- | --- | --- |
| Go | `go 1.27.0` in `go.mod` (the toolchain directive equals the go line, which `go mod tidy` collapses to one line); `GOTOOLCHAIN=auto` downloads it | `go.mod` |
| Node packages | exact versions, lockfile, `npm ci` | `web/package.json`, `web/package-lock.json`, `web/.npmrc` |
| gitleaks | 8.30.1, SHA-256 verified | `tools/secrets/` |

Go module path: `github.com/skenzeriq/activediq`. No remote is configured yet, so it is a name, not
a fetch location; change it once, in `go.mod`, before the first external consumer if the hosting
decision differs.

## `fitness-stack` in one page (T-0022)

Rules and rationale: ADR-0001 (`accepted`; its fitness function is this job). Every message reads
`<file>: F<n> (ADR-0001 rule <r>): <what, and where the change belongs>`.

| Check | Rule | What it reads | Notes |
| --- | --- | --- | --- |
| F1 | 1 | tracked and untracked-unignored files | An allowlist per zone (`languageZones` in the manifest). Extensionless scripts are classified by shebang. `.js/.mjs/.cjs` count as JavaScript and live only under `web/`. A `native/` crate must be a manifest-declared tier-N Windows component, which keeps PAM and macOS logon code out until their ADR exists |
| F2 | 2 | `go/parser` (imports and comments, never string contents), `go/build/constraint`, a text scan of every non-prose file, `go build` per target | Files under `//go:build ignore` are still scanned. `unix` counts as a GOOS. Toolchain tags (`go1.N`, plus the manifest `toolchainTags`: `race`, `msan`, `asan`, `purego`) pass anywhere; test tags (`lab`, `windowslab`) pass only in `_test.go` |
| F3 | 3 | `go list -deps` per binary per target | Binaries come from the manifest; an undeclared `package main` under `cmd/` fails. The denylist is extensible: another job's manifest (U1 in fitness-profiles) lists a file in `denylistExtends` |
| F4 | 6 | `go mod edit -json`, `package.json`, `Cargo.toml`, `*.csproj`, `third_party/`, LICENSE files of linked Go modules, `package-lock.json` (production entries), `cargo metadata` | The register match uses the **Project cell** only, exact path in backticks. Transitive scan: GPL, AGPL, SSPL, Elastic, BUSL; LGPL and MPL pass. A text is flagged only when the licence title opens it. An SPDX `OR` with a permissive alternative passes |
| F5 | 5 | the manifest and the ADR frontmatter `status` | Also fails on a stale entry (path gone) and on an undeclared `third_party/<name>/` |

To declare an exception, add an entry under `exceptions` in the manifest with an `adr` file name from
`knowledge/development/decisions/`. The ADR has to be `ratified` or `accepted` first; amend ADR-0001
(or write the ADR) before the manifest entry, not after.

## `fitness-profiles` in one page (T-0038)

Rules and rationale: ADR-0002 "Fitness function" (`ratified`; it becomes `accepted` when this job and
`fitness-tenancy` are green on `main` and the activation table holds a row for each of P2-P6, U3, U4).
Messages read `<file>:<line>: <check> (ADR-0002 fitness function): <what, and where the change belongs>`.
Runbook: `runbooks/ci-and-build.md`.

| Check | What it reads | Notes |
| --- | --- | --- |
| P1 source | `go/parser` over every Go file outside `tools/`, `lab/`, `testdata` and the skipped roots | The composition root is `cmd/` plus `internal/compose/**`. Domain code (everything else) may not import `internal/compose`, name a profile in an identifier (case- and underscore-insensitive tokens in `identifierDenylist`) or compare to the literals `saas`/`linux-oci`. Environment reads (`os`/`syscall` `Getenv`, `LookupEnv`, `Environ`, ...) outside `compose/config` and `cmd/` fail when the variable name matches `profileEnvRegexp`, is not a constant (a constant prefix counts), or the function is passed as a value |
| P1 manifests | the composite literals in `internal/compose/profile`, evaluated without compiling | `windows`, `linux-oci` and `saas` must exist. Self-hosted capability sets must be equal unless the manifest's `Exceptions` entry names the capability (`What`) and cites a ratified or accepted ADR (`ADR`: file name, `ADR-0002` or `0002`) |
| P7 | `git for-each-ref` on `refs/heads` and `refs/remotes` | `main` and `factory/T-NNNN` only. The job fails (exit 2) outside a git checkout rather than skipping |
| U1 | every `go.mod` and `go.work`, and every import | The denylist is `uem-denylist.json`, the same file fitness-stack F3 reads through its `denylistExtends`, so the closure of every shipped binary is checked too. A `replace` or `use` pointing outside the repository fails unless `replaceExceptions` has an entry (`path`: `<go.mod>:<module>`) that cites a ratified ADR |
| U2 | imports of every file under `internal/platform` (tests included) | `platformForbidden` lists the packages the extractable root may not import |
| Activation | the filesystem | A path ending in `/` matches directories only, so `internal/connector/*/` is activated by the first connector package and not by today's `doc.go`. `command` is the check's argv, run from the repository root; empty means not implemented |

To implement an activation check: write it (a `tools/fitness/<job>/` Go program or a `make` target),
register its `command` in the row, and the job runs it as soon as the row's path exists. Do not delete
or loosen a row to get green: the job requires a row for each of P2-P6, U3 and U4.

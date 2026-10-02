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
| Generated code freshness: `gen-check` | `go run ./tools/gen/proto -check` | `internal/proto` is stale, hand-edited or holds an orphaned `*.pb.go` against a fresh generation from `proto/` | the real CLI on a throw-away tree: hand-edited, orphaned and missing file each refused (`tools/ci/proof.sh`) |
| Web build | `vite build` | the build fails | — (a build failure is its own signal) |
| Secret scan | `make secrets-scan` | gitleaks finds a secret in history or the working tree | `make secrets-test` (T-0013) |
| Lab generator tests | `make lab-test-unit` | the seed generator's tests fail (no Docker needed) | — |

## What is deliberately not here yet

Each of these has an owner; none is faked.

| Gate | Owner |
| --- | --- |
| SBOM generation; NuGet transitive licence scan (fails closed once a sidecar is declared) | later `ops` tickets |
| Hand-built security strings (`dnstring`, `sqlconst`, `secretjson` analyzers), safe-primitives corpus | T-0033, T-0034 |
| Tenancy and profile fitness | T-0036, T-0038 |
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

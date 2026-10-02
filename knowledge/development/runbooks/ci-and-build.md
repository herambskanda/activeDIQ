---
title: "Runbook: CI, build and the repository scaffold"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: devops-engineer
ticket: T-0014
---

# Runbook: CI, build and the repository scaffold

Standard: `knowledge/development/standards/ci-gates.md`. Layout: blueprint §1.

## Prerequisites

`go` (any 1.21+; it downloads the pinned 1.27.0 toolchain on first use, so the machine needs
network access once), `node` ≥ 22 with `npm`, `python3`, `make`, `bash`. Everything else is installed
by the targets: web packages by `npm ci`, gitleaks by `make secrets-install`.

## Everyday commands

| Task | Command |
| --- | --- |
| The full gate (what the merge needs) | `make ci` (about 25 s warm) |
| Just lint / tests / fitness / build | `make lint`, `make test`, `make fitness`, `make build` |
| Format everything in place | `make fmt` |
| Prove the gates still fail on violations | `make ci-proof` |
| List all targets | `make help` |

## Fresh clone

```bash
git clone <repo> && cd activediq
make ci        # installs web dependencies from the lockfile, then runs every gate
```

If `make ci` fails on a fresh clone, that is a bug in the scaffold; file an `ops` ticket.

## When a gate fails

- **`gofmt`**: run `make fmt`.
- **`go mod tidy -diff`**: run `go mod tidy` and commit `go.mod`/`go.sum`.
- **`fitness-stack`** (F1–F5, ADR-0001): the message names the file, the check and the ADR rule.
  `make fitness-stack` re-runs it alone; `go run ./tools/fitness/stack -checks F1,F5 -skip-build`
  runs a subset without the cross-build. The fix is in the code, not the manifest, unless a real
  exception is needed: that takes a ratified ADR first, then a manifest entry
  (`standards/ci-gates.md`, "fitness-stack in one page").
  - F1 on a new file: move it into its zone, or rewrite it in the zone's language.
  - F2 `build tag`: custom tags are for tests (`lab`, `windowslab`, in `_test.go` only). OS-specific
    Go goes in a declared platform-adapter package.
  - F3: remove the import. A second stateful service needs its own ADR.
  - F4 `no licence-register row`: add the row to the register first (CLAUDE.md rule 9), exact
    package path in backticks in the Project cell. A transitive copyleft hit means picking another
    library, or an ADR plus a `licenceExceptions` entry.
  - F5: set the ADR's status through the `adr` skill first.
- **`fitness-modules`**: the message names the file, line and blueprint rule. Fix the import. Do not
  edit the rule to pass; a rule changes only by amending the blueprint/ADR.
- **`fitness-safeprim`** (FF-SP1 to FF-SP3, safe-primitives §8): each finding reads
  `file:line: FF-SPn [rule] message`. `make fitness-safeprim` re-runs it alone;
  `go run ./tools/fitness/safeprim -checks FF-SP1,FF-SP3 -no-analyzers` runs a subset without the
  type-aware passes. The same passes run as `go vet -vettool=$(go build -o /tmp/safeprim-vet ./tools/vettool && echo /tmp/safeprim-vet) ./...`.
  The web half is `eslint` (rule names `no-hand-built-security-string`, `no-quote-doubling`,
  `no-dn-string-ops`, `no-export-media-types`, `no-unsafe-dom-sinks`, `safe-url-attributes`).
  - The fix is to call the primitive (filter builder, DN builder, `proc`, `psx`, data-access
    package), not to move the string or silence the rule. Test files and tier L (`tools/`, `lab/`)
    are exempt from FF-SP2 and FF-SP3 literal rules only; FF-SP1 still applies to tests.
  - Where each primitive lives is one table: `tools/analyzers/policy/policy.go`. A new home (for
    example when T-0004 fixes the export package roots) is a change to that table plus a case in
    `tools/fitness/safeprim/scan/scan_test.go`. Rule lists are in `scan/rules.go`.
  - Limits: the syntactic scan ignores build tags on purpose; the type-aware passes see only the
    host OS files (run them with `GOOS=windows` once `_windows.go` files exist, follow-up ticket);
    C# and Rust are scanned as text until their toolchains land. `sidecars/BannedSymbols.txt` and
    `tools/fitness/safeprim/configs/native-clippy.toml` are dormant configs for the first sidecar
    and the first crate.
- **`npm ci` fails with a lockfile error**: `web/package.json` and the lockfile disagree; run
  `npm --prefix web install` once and commit both.
- **Go toolchain download fails**: check network/proxy (`go env GOPROXY`).
- **`secrets-scan`**: see `secret-scanning.md`.

## Adding code

- A new Go package goes where blueprint §1 says. Run `make fitness` early; it checks the import
  rules before a reviewer has to.
- A new dependency needs a row in `knowledge/business/licensing/open-source-license-register.md`
  first, with its exact package path in backticks.
- Go dependencies: `go get <path>@<exact version>` then `go mod tidy`. Web: `npm --prefix web i -E`.

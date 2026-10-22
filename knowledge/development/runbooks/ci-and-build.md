---
title: "Runbook: CI, build and the repository scaffold"
date: 2026-10-02
updated: 2026-10-21
status: draft
owner: devops-engineer
ticket: T-0014
---

# Runbook: CI, build and the repository scaffold

Standard: `knowledge/development/standards/ci-gates.md`. Layout: blueprint §1.

## Prerequisites

`go` (any 1.21+; it downloads the pinned 1.27.3 toolchain on first use, so the machine needs
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
- **`gen-api-check`** (stale or missing generated file): run `make gen-api` and commit the result; never edit a `*.gen.*` file.
  **`lint-api`**: vacuum findings on the bundled contract. Both: `runbooks/api-contract-workflow.md`.
- **`vuln-scan`** (T-0010; `go run ./tools/vulnscan`, govulncheck pinned in `tools/vulntools`): each line names an OSV
  id, the vulnerable symbol your code reaches, the module and the fixed version.
  - *Called vulnerability*: upgrade the module (`go get <module>@<fixed>`, `go mod tidy`) or, for a standard-library
    id, the Go toolchain. If it cannot be fixed yet, add an entry to `tools/ci/vuln-allow.json`:
    `{"osv": "GO-…", "reason": "…", "ticket": "T-NNNN", "expires": "YYYY-MM-DD"}`, with a ticket that owns the fix.
    An entry covers its OSV id in every module that carries it. Imported-but-not-called findings are not gated.
  - *Allow entry expired* or *matches no finding*: fix the finding and delete the entry, or renew it with a new reason and
    date. A renewal is visible in review.
  - *Database could not be read* (`cause: the vulnerability database …`): the scan is not skipped. Check the network or
    proxy, or point `GOVULNDB` at a mirror: `GOVULNDB=https://mirror.example/vulndb make vuln-scan` or
    `GOVULNDB=file:///srv/vulndb make vuln-scan` (a copy of the database in the
    [Go vulndb layout](https://go.dev/security/vuln/database#api)). Air-gapped CI keeps such a mirror up to date.
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
- **`fitness-api`** (A1 layout, A13 policy hygiene, ADR-0004): `make fitness-api` re-runs it alone;
  `-checks A1` runs one. It prints a line per check A1-A14, `active` or `inactive (<missing input>)`,
  and exits 0 while checks are inactive: **a green run is not "the contract is fully checked"**, read
  the table. ADR-0004 stays `ratified` until no line says inactive.
  - A1: the message names the file, line and the rule 1 clause. Move the file to a rule 1 place
    (`openapi.yaml`, `shared/`, `modules/<id>.yaml`, `platform/<pkg>.yaml`), or create the module or
    kernel package it belongs to; give an operation its file's one tag; rename the duplicate; move a
    shape two tags need to `shared/`. A stale bundle is `make gen-api` (that gate is `gen-api-check`).
  - A13: every `policy.yaml` entry needs `reason` and `ref` (an `AN-n` row or a `TM-` section) and
    must name something that exists (`operation`, `method`+`path`, `permission`, `schema`). Delete the
    stale entry or fix the name. An entry with `host` fails until the apihost hostname-binding table
    exists (A4's input): do not work around it, raise it on the A4 ticket. An `AN-n` must be a row of the
    threat model's anonymous allow-list, and every `anonymous` entry cites one (`TM-` tokens are
    shape-checked only; resolving them is a follow-up). A repeated mapping key anywhere in a file under
    `api/openapi` fails (A13 for `policy.yaml`, A1 for the rest): merge the two blocks. Entry fields: `api/openapi/policy.yaml` header.
  - `[ADR-0004 self-test]`: the check read fewer operations or entries than a plain text count or
    the committed bundle shows. Fix the reader (`tools/fitness/api/tree.go`), never the assertion.
  - An inactive line ending `[INPUT NOW PRESENT: ... overdue]` means a subject landed (operations,
    `apihost.Build`) and its check has not; it does not fail the job but the ADR cannot be accepted.
    Implement the check, with a failing fixture, and remove its `needs` text in `inactive.go`.
- **`fitness-profiles`** (P1, P7, U1, U2 and the activation table, ADR-0002): `make fitness-profiles`
  re-runs it alone and prints the activation table first. `-checks P1,U2` runs a subset.
  - P1 domain code: take the compose import, environment read or profile-named identifier out of
    domain code; pass a value in from the composition root instead, or name the *capability*
    (`directory.ad`), never the profile. Profile logic belongs in `internal/compose/**`.
  - P1 capability asymmetry: both self-hosted manifests get the capability, or the solution-architect
    adds an ADR-cited `Exceptions` entry to the manifest first.
  - P7: delete the branch (`git branch -D <name>`, and the remote copy); only `main` and
    `factory/T-NNNN` exist.
  - U1: remove the module. Ported UEM or PatchIQ code is copied with its source named in the commit
    and placed under `internal/platform/`; it is never imported or `replace`d.
  - U2: the platform root imports nothing from the directory domain, connector, modules or compose.
  - Activation (`activation table P2: ... not implemented`): a subject has landed (an installer
    directory, the first connector package, the updater, the agent protos) and its check does not
    exist yet. Implement the check and register its `command` in
    `tools/fitness/profiles/manifest.json`; never delete the row. A new subject path is a change to
    the row's `paths` and is reviewed like a rule change.
  - Lab runs the table cannot do yet (P2 on a `windows-2025` runner, P3 against the Samba lab, P6
    with egress denied) are the registered commands' job; the lab and runner must be documented
    in a runbook by the ticket that registers them.
- **`fitness-modules`**: the message names the file, line and blueprint rule. Fix the import. Do not
  edit the rule to pass; a rule changes only by amending the blueprint/ADR.
- **`fitness-operation`** (O9 of ADR-0005, the kernel import DAG): `make fitness-operation` prints every
  package of the `dag` block as `existing` or `pending`, then the violations as
  `file:line: O9 [rule 13] <importer> imports <imported>; …` with what the importer may import.
  - The source is the `dag` block in ADR-0005 rule 13, read on every run. To change a direction,
    amend the ADR (the `adr` skill) and the check follows; never edit the tool to pass.
  - A violation is fixed by moving the type or the call down to the package the block allows
    (usually `authority` or `operation/step`), not by adding the edge. `(anything operation may
    import)` means the row of `operation` itself.
  - `pending` packages are not checked until they exist; a `self-test` finding means the
    `internal/platform/<name>` mapping found none of the listed packages while the tree has them
    elsewhere. O1–O8 are added by the tickets that land the code they inspect.
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
  - What is skipped: `.git`, `testdata` at any depth; `node_modules` beside a `package.json` is skipped except for `.go` files of our module (Go builds them; a nested `go.mod` makes a dir a separate module, skipped); `knowledge`, `factory`, `garage`,
    `vendor`, `third_party` at the repo root; `bin`/`obj` only beside a `.csproj`, `target` only beside
    `Cargo.toml`, `dist` only beside `package.json`. Never skip by a bare directory name: a package
    called `target` is product code.
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

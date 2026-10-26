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
- **`fitness-api`** (A1, A3, A5, A7 static, A8, A10, A11, A12, A13, ADR-0004): `make fitness-api` re-runs it alone;
  `-checks A1` runs one. It prints a line per check A1-A14: `active`, `active ...; inactive part: <what is
  missing>` (a check whose runtime half has no input yet), or `inactive (<missing input>)`. It exits 0 while
  anything is inactive: **a green run is not "the contract is fully checked"**, read the table. ADR-0004
  stays `ratified` until no line says inactive and no active line has an inactive part.
  A2 is not re-run here: `tools/gen/api` rejects the dialect (`make gen-api-check`) and vacuum lints it
  (`make lint-api`), both in `make ci`; its line stays inactive until the ADR's owner decides that
  delegation satisfies A2.
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
  - A3 (document half): every operation has exactly one `x-permission` (a permission ID, `authenticated`
    or `anonymous`). `anonymous` needs `x-activediq-anonymous: AN-n` (an operation row of the allow-list)
    and a `policy.yaml` `anonymous` entry citing that AN-n; `authenticated` needs a `policy.yaml`
    `authenticated` entry; a policy row may not name an operation that declares a real permission. The
    runtime half (a permission nobody declares in the EP-6 catalogue) is the printed inactive part.
  - A5 (static half): `web/src/api/` holds the generated files, `client.ts`, its test and the README
    only; `schema.gen.d.ts` has an entry per operation and every `x-activediq-enum: open` schema widened
    with `| (string & {})` (run `make gen-api`); a `*.test.ts` there assigns an unknown string to a
    generated open enum so `tsc` (lint-web) fails if the widening is lost; `web/eslint.config.js` keeps
    the rule 12 bans. The real ESLint run on `web/proof/api-client-violation.ts` is in `make ci-proof`.
  - A7 (static half): no `encoding/json` import in `internal/**` or `cmd/**` (tests and tools may), no
    `AllowInvalidUTF8`, `AllowDuplicateNames` or `MatchCaseInsensitiveNames`, no `GOEXPERIMENT` value
    containing `nojsonv2` in a Makefile, script, Dockerfile, env or CI file. Existing v1 importers are
    listed in `tools/fitness/api/json-v1-baseline.txt` (migration: T-0064). The list only shrinks: a new
    importer fails, a listed file that no longer imports v1 fails until its line is deleted, and a line
    absent from `main:tools/fitness/api/json-v1-baseline.txt` fails (growth is caught against main; an
    unresolvable `main` in a git checkout is an error, a shallow clone needs `git fetch origin main`).
  - A8 (linter half): nothing reachable from a response, response headers included (a header name
    matching the secret list, or a header schema with a secret marker, fails; through `$ref`, `items`, `oneOf`,
    `additionalProperties`) may carry `x-activediq-secret`, `writeOnly`, `format: password` or a
    property matching the rule 9 name list (exact or camelCase suffix: `adminPassword` yes,
    `passwordLastSet` no), unless the operation is in `policy.secretResponses`; no credential-named
    query parameter (snake and kebab spellings count), no `apiKey` scheme `in: query`; a
    `secretResponses` operation is class `reveal` with a `secret.*` or token-creation permission.
  - A10: every operation is `x-activediq-stability: preview|stable`; `deprecated: true` needs
    `x-activediq-sunset` (a release, `1.4.0`) and the reverse. Against `main` (and the latest `v*` tag
    once one exists) the stable operations of the committed bundle are diffed with the pinned oasdiff
    (`tools/apitools`, `go tool oasdiff`); a breaking change, a stable to preview demotion or an early
    removal fails: ship a new operation and deprecate the old one. `main` must resolve (in a shallow
    clone: `git fetch origin main --tags`); outside a git checkout the diff is skipped.
  - A11: every 4xx/5xx/`default` response is `application/problem+json` with
    `shared/problems.yaml#/components/schemas/Problem`, and any example `type` is one of the catalogue's
    (the example types of `shared/problems.yaml` `components.responses`); no `http.Error` or
    `WriteHeader` in `internal/**` outside `apihost` (tests exempt). Prefer `$ref` to a catalogue response.
  - A12: `x-activediq-limits` holds `class` (read, write, bulk, auth, reveal, secret, anonymous) and
    `maxBodyBytes` only; anonymous operations use `anonymous` or `auth`; a non-JSON or binary body needs
    `maxBodyBytes`; above 16 MiB needs a `policy.largeBodies` entry; an operation taking `SecretInput`
    is class `secret`, declares `maxBodyBytes` of at most 65536 and has a JSON body.
    An operation with no request body takes none at all: the generator emits `MaxBody: 0` and apihost answers
    `413 /problems/payload-too-large` to any `Content-Length > 0` or `Transfer-Encoding` before authentication (TM §7.6 AN-1).
  - `[ADR-0004 self-test]`: the check read fewer operations or entries than a plain text count or
    the committed bundle shows. Fix the reader (`tools/fitness/api/tree.go`), never the assertion.
  - An inactive line ending `[INPUT NOW PRESENT: ... overdue]` means a subject landed (operations,
    `apihost.Build`) and its check has not; it does not fail the job but the ADR cannot be accepted.
    Implement the check, with a failing fixture (`check_test.go`, `check_static_test.go`) and a `tools/ci/proof.sh` case, and remove its `needs` text in `inactive.go`.
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
- **`fitness-objectid`** (T-0180): fails on any conversion `authz.ObjectID(x)` (any spelling: alias,
  rename, dot-import) outside package `authz` and its tests, as `file:line:col`. Fix: build the value
  with `authz.ObjectIDFromOctets` (raw objectGUID bytes) or `authz.ParseObjectID` (text); `guid.GUID`
  is also `[16]byte` but its byte order differs. Type errors in other packages are printed as
  warnings (the build gate owns them). Proof: `go test ./tools/fitness/objectid` (positive and negative fixtures).
- **`fitness-disclosure`** (T-0258): checks `SECURITY.md` and `.well-known/security.txt`
  (RFC 9116). It fails **30 days before `Expires`** on purpose: that failure is the renewal job.
  Renew by setting `Expires` to a date 9–12 months ahead (RFC 3339, UTC), and change `Contact` only
  together with the channel named in `SECURITY.md` (the check requires both to match). Do not move
  the date without reading `SECURITY.md` for anything stale. Owner: security-architect.
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
    elsewhere. O1 (step escape) also runs `tools/analyzers/stepescape` type-aware: the module must build first. To exempt a deliberate smuggle in a test, put `//fitness:allow-step-escape <reason>` on or above the line (test files only). O2 (write surface) and the SQL half of O4 (state column) run on every invocation; violations read `file:line: O2 [rule 2] …` / `O4 [rule 3] …`. O3, O5–O7 and O8 print `pending <id> … (owner T-…)` until their code lands (T-0391, T-0392, T-0393); the owner replaces the pending entry in `pendingChecks` (tools/fitness/operation/main.go) with the check. A pending line is not a pass.
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
  - What is skipped: `.git` at any depth; `testdata` only under `tools/` (the analyzer fixtures are
    deliberate violations; Go can import a `testdata` package elsewhere, so it is scanned there).
    `node_modules` beside a `package.json` is skipped except every `.go` file and `go.mod` under it
    (Go builds them, and a `replace` can compile a nested module; no structural skip). At the repo
    root: `knowledge`, `factory`, `garage`, `.claude`, `vendor`, `dist`, `third_party`, unless a
    package that product code imports lives in one (T-0082). `bin`/`obj` only beside a `.csproj`,
    `target` only beside `Cargo.toml`, `dist` only beside `package.json`; even then their `.go`
    files are scanned. Never skip by a bare directory name: a package called `target` is product
    code.
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

## Test Postgres containers: labels, `rm -f -v`, reaping (T-0377)

`storetest` and `tools/fitness/pgharness` start throw-away Postgres containers through
`internal/testlab/harnessdocker`. The postgres image declares an anonymous data volume (~74 MB), so:

- containers carry `activediq.harness=1` and `activediq.harness.pid=<owner pid>`;
- they are removed with `docker rm -f -v` (never without `-v`);
- every start first reaps harness containers whose owner pid is dead (a killed test run). Containers
  of live sibling test processes are left alone.

Proofs: `internal/testlab/harnessdocker` (remove + reap, fails if `-v` is dropped) and
`storetest.TestStopRemovesContainerAndAnonymousVolume`. Manual sweep of old leaks:
`docker ps -aq --filter label=activediq.harness=1 | xargs -r docker rm -f -v`.

## API TLS directory permissions (T-0104, TM-TB16-T3)

Go's 0600/0700 modes do nothing on Windows, so packaging sets the access control itself. Files in `packaging/`:

- **Windows** `windows/Set-ApiTlsDirAcl.ps1 -Path <ACTIVEDIQ_API_TLS_DIR> -ServiceIdentity 'DOMAIN\svc$'`: the MSI custom action (and the upgrade path) runs it after the gMSA exists. Inheritance off, owner Administrators, FullControl for Administrators and the service identity only; existing files lose explicit entries. Idempotent. Refuses a broad group, a non-directory and a reparse point.
- **Windows lab test** `windows/Test-ApiTlsDirAcl.ps1 -Path … -ServiceIdentity … -ProbeCredential (Get-Credential)`: run as Administrator on the lab member (`windows-lab.md`). It asserts the ACL and, with a non-administrator local user's credential, that listing the directory is denied (exit 5). Use a throwaway local user created for the run; never commit its password. Save the output under `windows-lab-runs/`.
- **linux-oci** `linux-oci/prepare-tls-dir.sh <host-dir> [10001 [10001]]` (root) then merge `linux-oci/compose.tls.yaml`: directory owned by the numeric non-root service uid:gid, mode 0700, the container runs as that user. The server itself also refuses a directory it does not own or that is group/other-writable.

`make fitness-packaging` checks the files statically and runs the prepare script for real; `make ci-proof` shows it failing on a violation.

---
title: "Runbook: CI, build and the repository scaffold"
date: 2026-10-02
updated: 2026-10-28
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
- **`gen-modules-check`** (T-0997; the table ownership map): a new migration table needs a `-- write-class: <table> config|system` line
  directly above its `CREATE TABLE` (`config`: a principal changes it, so writes are Actions that take a `step.Step`; `system`: bookkeeping its
  owner writes, the closed list in ADR-0005 rule 10; a partition takes its parent's class). The owner key is the migration's file-name
  segment. Then run `make gen-modules` and commit `owners.gen.tsv`; never edit it. A `DROP TABLE` or rename needs `tools/gen/modules`
  extended first (the generator refuses it rather than guess).
- **`gen-api-check`** (stale or missing generated file): run `make gen-api` and commit the result; never edit a `*.gen.*` file.
  **`lint-api`**: vacuum findings on the bundled contract. Both: `runbooks/api-contract-workflow.md`.
- **`fuzz-saml`** (T-0490; `tools/ci/fuzz-target.sh`): `FuzzSAMLComplete` found a forged or replayed login. Go writes the crasher to
  `internal/platform/authn/sso/saml/testdata/fuzz/FuzzSAMLComplete/`; reproduce with `go test ./internal/platform/authn/sso/saml -run FuzzSAMLComplete`,
  fix the verifier (never the oracle), and commit the crasher file as a regression seed. Runs 60s; `make fuzz-saml SAML_FUZZ_TIME=5s` for a quick local run.
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
- **`fitness-profiles`** (P1, P4 telemetry, P7, U1, U2 and the activation table, ADR-0002): `make fitness-profiles`
  re-runs it alone and prints the activation table first. `-checks P1,U2` runs a subset.
  - P1 domain code: take the compose import, environment read or profile-named identifier out of
    domain code; pass a value in from the composition root instead, or name the *capability*
    (`directory.ad`), never the profile. Profile logic belongs in `internal/compose/**`.
  - P1 capability asymmetry: both self-hosted manifests get the capability, or the solution-architect
    adds an ADR-cited `Exceptions` entry to the manifest first.
  - P4 telemetry (T-0135, TM-TB17-T8): a log line in a function that has a tenant in scope (a `tenant.ID`
    parameter, variable or receiver field) must pass `"tenant_id"` or log through `With("tenant_id", ...)`;
    a Prometheus-style metric constructor must list the label `tenant_id` in a `[]string` literal; a map in a
    struct field or package variable named `*cache*` (or in a `*Cache` type) is keyed by `tenant.ID` or a struct
    with a `tenant.ID` field. Fix the code. A platform-scope or one-tenant-per-instance case is a
    `p4.exempt` entry in the manifest (`path` = `file`, `file#Func` or `file#Name`, a ratified ADR, a reason);
    a stale entry fails. The check is syntactic: it cannot see a log line whose tenant is only in a context.
  - P7: delete the branch (`git branch -D <name>`, and the remote copy); only `main` and
    `factory/T-NNNN` exist.
  - U1: remove the module. Ported UEM or PatchIQ code is copied with its source named in the commit
    and placed under `internal/platform/`; it is never imported or `replace`d.
  - U2: the platform root imports nothing from the directory domain, connector, modules or compose.
  - Activation (`activation table P2-oci: ... not implemented`): a subject has landed (an installer
    directory, the first connector package, the updater, the agent protos) and its check does not
    exist yet. Implement the check and register its `command` in
    `tools/fitness/profiles/manifest.json`; never delete the row. A new subject path is a change to
    the row's `paths` and is reviewed like a rule change.
  - Deferral (`activation table P2-oci: deferral ...`, ADR-0002 erratum E-3): a row may carry
    `"deferral": {"ticket", "expires", "adr"}`, which prints `ACTIVE, DEFERRED (T-NNNN until
    YYYY-MM-DD)` instead of failing. It is valid only while the row has no `command`, the ticket is
    `T-` and four or more digits, the expiry (UTC date) is today or later, and the "Activation
    deferrals" table of the named ADR (in `decisionsDir`, ratified or accepted) lists the same
    check, ticket and expiry. Editing the date in the manifest extends nothing: extend by an
    amendment line and a new table row in the ADR. When the check lands, add its `command` **and
    remove the deferral** in the same change, or the job calls the deferral stale.
  - Lab runs the table cannot do yet (P2-msi on a `windows-2025` runner, P3 against the Samba lab, P6
    with egress denied) are the registered commands' job; the lab and runner must be documented
    in a runbook by the ticket that registers them.
- **`fitness-modules`**: the message names the file, line and blueprint rule. Fix the import. Do not
  edit the rule to pass; a rule changes only by amending the blueprint/ADR.
- **`fitness-objectid`** (T-0180): fails on any conversion `authz.ObjectID(x)` (any spelling: alias,
  rename, dot-import) outside package `authz` and its tests, as `file:line:col`. Fix: build the value
  with `authz.ObjectIDFromOctets` (raw objectGUID bytes) or `authz.ParseObjectID` (text); `guid.GUID`
  is also `[16]byte` but its byte order differs. Type errors in other packages are printed as
  warnings (the build gate owns them). Proof: `go test ./tools/fitness/objectid` (positive and negative fixtures).
- **`fitness-sso`** (T-0211, console-sso.md §13): FIT-SSO-1 and FIT-SSO-2. Output lines name the file and
  line (`internal/platform/x/y.go:3: imports github.com/russellhaering/goxmldsig; only
  internal/platform/authn/sso/saml may`), the go.mod line, or the check number (`saml: SAML-7 is cited by
  no corpus record`). Fixes: move the parsing into `sso/saml` or `sso/oidc` (never widen the fence, which
  changes only by amending the spec); raise the module in `go.mod`; add a corpus record that cites the
  number (records are `sso/testdata/corpus/{saml,oidc}/<id>.json`, spec §10.1) and make sure `TestCorpus`
  in that package runs it as a subtest named `<id>`. The check numbers are read from the spec's tables, so
  adding a check to §4 or §5 turns this red until a record cites it. A deleted record, or one whose subtest
  is missing or skipped, fails the same way for OIDC (T-0911) as for SAML. Proof: `go test ./tools/fitness/sso` and the `fitness-sso` cases of `make ci-proof`.
- **`fitness-grantbootstrap`** (T-0808): fails on any identifier or string mention of `GrantBootstrap`
  outside `internal/compose/server/localaccount.go`, the method declaration in
  `internal/platform/rbac/grants.go` and `_test.go` files, as `file:line:col`. `GrantBootstrap`
  skips the grantor's own-authority check, so only the first-account CLI may call it (and the method
  itself accepts only `rbac.BootstrapPrincipal`). Fix: use `rbac.Grants.Grant`, which requires the
  actor to hold what it grants. Proof: `go test ./tools/fitness/grantbootstrap` (a new reference fails).
- **`fitness-update`** (T-0139): TM-F-UPDATE, see `tm-f-update.md`.
- **`fitness-disclosure`** (T-0258): checks `SECURITY.md` and `.well-known/security.txt`
  (RFC 9116). It fails **30 days before `Expires`** on purpose: that failure is the renewal job.
  Renew by setting `Expires` to a date 9–12 months ahead (RFC 3339, UTC), and change `Contact` only
  together with the channel named in `SECURITY.md` (the check requires both to match). Do not move
  the date without reading `SECURITY.md` for anything stale. Owner: security-architect.
  It also checks advisories (T-0260): the message names `security/advisories/<CVE-ID>/advisory.md` or
  `record.json` and what differs. Fix the advisory or the record so that both say the same thing; never
  change the score to make the files agree without the second scorer
  (`security-disclosure.md` §3.2). If the gate says `target_met` is wrong, the advisory must admit the miss.
- **`fitness-keys`** (FF-KEY-1..6 of `keys-custody-design.md` §7; T-0525): `make fitness-keys` (needs Docker for FF-KEY-1 and the bound database tests). A violation prints `file:line CHECK [rule]: …`. FF-KEY-2/3/5 are source scans (`-static-only` runs just those; `internal/compose/server` is the only place that may name the KEK settings, and `internal/platform/keys` the only owner of `tenant_keys`). Parts whose code has not landed are printed `pending` on every run (not a pass): the boot checks and `keys provision --missing` (FF-KEY-4/5), `installation_kek` privileges, the problem-body/audit non-leak and transition property test (FF-KEY-6). The ticket that lands each removes its `pending` line and adds the test to `bindings.go`; when `Rotate`, `ShredTenant` or `OpenMaintenance` land, add their allowed caller packages to `callersAllow` in `static5.go` in the same change.
- **`fitness-fleet-ca-scope`** (ADR-0008 fitness items 1-6, TM-TB6-T15..T18; T-0738): `make fitness-fleet-ca-scope` (no Docker). A violation prints `file:line FCS-n [rule]: …`. Code that has not landed (the server CA, `SignServerLeaf`, `dial.PinnedRoots`, the `fleet_server_ca` migration) is printed as `pending`, which is not a pass: **ADR-0008 stays `proposed`/`ratified` until nothing is pending.** Each build ticket of the ADR lands its tests and then flips `Landed: true` on its row in `tools/fitness/fleetca/bindings.go` using the test names listed there (a test that exists while its row is not landed fails, and a landed test that is missing, failed or skipped fails). The static rules switch on by themselves when their code appears; a `fleet_server_ca` migration without `SignServerLeaf` fails. The rules' own failing fixtures are `go test ./tools/fitness/fleetca`; the real CLI is proven failing and passing in `make ci-proof`. When the last pending line disappears, ask solution-architect to move ADR-0008 to `accepted`.
- **`fitness-audit`** (A1–A9 of ADR-0005, TM-F-AUDIT; T-0133): `make fitness-audit` (needs Docker).
  - **A1** runs the real migrations in PostgreSQL 16 and 18 containers and prints
    `A1 <rule> [<table>]: …` for a runtime-role privilege (UPDATE/DELETE/TRUNCATE on the audit tables,
    UPDATE on the personal and secret side tables, anything beyond SELECT/INSERT/UPDATE on
    `audit_head`), a missing or disabled genesis trigger, a trigger that accepts a head other than
    `seq 0` with the tenant's `hash_0` or keeps a caller-supplied `at`, and a runtime role that owns
    `audit_head`, is a superuser or can `SET session_replication_role`. Fix the migration or the role
    bootstrap, never the check.
  - **A2, A3, A5, A6, A9** run the tests listed in `tools/fitness/audit/bindings.go` and fail with
    `test-failed`, `test-skipped` (no Docker is a failure, not a pass) or `test-missing` (renamed or
    deleted: update the binding in the same change, with the reviewer's eyes on it).
  - **A4, A7, A8** and the alerting half of A6 are printed `pending` with the owning ticket (T-0638,
    T-0639, T-0640) on every run. Whoever lands the guarded code lands the check and deletes the line.
  - Proof: `tools/fitness/audit` tests (one mutation per A1 rule) and `tools/ci/proof.sh`.
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
    elsewhere. O1 (step escape) also runs `tools/analyzers/stepescape` type-aware: the module must build first. To exempt a deliberate smuggle in a test, put `//fitness:allow-step-escape <reason>` on or above the line (test files only). O2 (write surface) also runs `tools/analyzers/connwrite` type-aware in the same load as stepescape (a violation reads `file:line: O2 [rule 2] …` like the syntactic ones; to hold a read-only view of the client, declare a narrow interface without Plan/Apply, never an alias of `ConnectorClient`; the exemptions apply to the top-level `internal/proto` and `internal/directory/client` only, judged by the path below the module root, so a nested `cmd/<x>/internal/…` directory of the same name is checked like any other package). O2 (write surface) and the SQL half of O4 (state column) run on every invocation; violations read `file:line: O2 [rule 2] …` / `O4 [rule 3] …`. O3 and O5–O7 print `pending <id> … (owner T-…)` until their code lands (T-0391, T-0392); the owner replaces the pending entry in `pendingChecks` (tools/fitness/operation/main.go) with the check. A pending line is not a pass.
  - **O8 (pipeline behaviour, T-0393)** reads `internal/platform/operation/o8_manifest_test.go` (it parses the Go source; the list is never copied into the tool), then runs every test the manifest names with `go test -json -count=1` and fails, as `<dir> <Test>: O8 [pipeline behaviour] …`, when a named test is missing (renamed or deleted), fails, is skipped, or has a skipped subtest. **No Docker is a failure, not a skip**: the Postgres tests need the Docker daemon, exactly as `fitness-audit` does. A clause the manifest lists as a `Gap` prints `pending O8 <id>: T-nnnn …` (today the non-ancestry scope roots on T-0824, undo of a failed item T-0830, the Provenance implementation T-0831); when the ticket lands, the manifest owner moves the clause to `Tests`. Tests in `lab`-tagged files must exist but are listed `not run` unless you pass `-o8-lab` (`make lab-up` first, then `go run ./tools/fitness/operation -o8-lab`); a failing run of the lab arm fails the check. Proof: `go test ./tools/fitness/operation` (o8_test.go runs a real `go test` in a throw-away module: failing, skipped, subtest-skipped, renamed, deleted, unbuildable and gap-without-ticket each fail; the clean tree passes).
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

- **Windows** `windows/Set-ApiTlsDirAcl.ps1 -Path <ACTIVEDIQ_API_TLS_DIR> -ServiceIdentity 'DOMAIN\svc$'`: the MSI custom action (and the upgrade path) runs it after the gMSA exists. Inheritance off, owner Administrators, FullControl for Administrators and the service identity only; existing files get owner Administrators and lose explicit entries. Idempotent. Never recurses (flat layout). Refuses: a broad group, a non-directory, a reparse point, a subdirectory/junction/symlink/hard-linked file inside, a pre-existing directory not owned by Administrators/SYSTEM/the service, and a parent that grants write to anyone but Administrators/SYSTEM/TrustedInstaller/CREATOR OWNER (create a protected parent first).
- **Windows lab test** `windows/Test-ApiTlsDirAcl.ps1 -Path … -ServiceIdentity … -ProbeCredential (Get-Credential)`: run as Administrator on the lab member (`windows-lab.md`). It asserts the ACL and, with a non-administrator local user's credential, that listing the directory and reading a file inside are denied (exit 5); the path reaches the probe via `ADIQ_PROBE_PATH`, never string-built. T-0409 adds the lab cases: directory pre-created by a non-admin is refused; a junction child is refused and its target ACL unchanged; an Administrators-owned directory granting Users Modify is refused; a parent pre-created by a non-admin with an Administrators-only DACL is refused (ancestor owner walk); a parent that is a junction created by a non-admin pointing at an Administrators-owned directory is refused and the target's ACL unchanged. Installs must use a real path: any ancestor that is a reparse point (junction, symlink, mounted-folder volume root) is refused. Use a throwaway local user created for the run; never commit its password. Save the output under `windows-lab-runs/`.
- **linux-oci** `linux-oci/prepare-tls-dir.sh <host-dir> [10001 [10001]]` (root) then merge `linux-oci/compose.tls.yaml`: directory owned by the numeric non-root service uid:gid, mode 0700, the container runs as that user. Root never chowns/chmods by path inside the directory (the container can swap paths for symlinks): the script refuses non-regular entries, hard-linked files and files owned by another uid (exit 2), and tightens modes as the service uid via `setpriv`. The server itself also refuses a directory it does not own or that is group/other-writable.

`make fitness-packaging` checks the files statically and runs the prepare script for real, parses every `packaging/**/*.ps1` with PowerShell's own parser (needs pwsh or Docker); `make ci-proof` shows it failing on a violation.

## Release tooling (T-0261)

`workflows-check` guards `.github/workflows/`; the security.txt renewal job, the per-release SBOM and the
signed publication are in `release-and-security-txt.md`. The renewal PR is the job `fitness-disclosure`
above refers to, opened 60+ days before that gate fails.

## TM-F-HOST proof (`make fitness-host`, T-0136)

What it enforces: a booted install is judged on eight named cases (threat-model §15, TM-F-HOST):
`HOST-DC-REFUSED`, `HOST-SERVICE-NOT-PRIVILEGED`, `HOST-FILE-PERMISSIONS`, `HOST-NO-DEFAULT-CREDENTIAL`,
`HOST-NO-PLAINTEXT-LISTENER`, `HOST-SETUP-SECRET-SINGLE-USE`, `HOST-NO-DUMPS`, `HOST-REMOTE-DSN-FULL-TLS`.

- **linux-oci (needs Docker):** `go run ./tools/fitness/host oci` builds `cmd/server` (static) into
  `packaging/linux-oci/Dockerfile.server` (`FROM scratch`, uid 10001, TLS dir 0700), boots it against PostgreSQL 16
  and observes the live process: kernel uid, `/proc/<pid>/limits`, the TLS directory's tar headers, a plaintext
  request and well-known logins against the TLS listener, and five remote-DSN boots (`disable`, `allow`, `prefer`,
  `require`, `verify-ca` without a root) that must each be refused before any dial.
- **windows (lab):** on a lab host run `packaging/windows/Get-HostObservation.ps1 -ServiceName … -InstallDir …
  -ConfigPaths … -InstallerResult refused|installed > obs.json`, then `go run ./tools/fitness/host evaluate obs.json`.
  Run it on dc1 with the MSI once it exists (T-0635) to prove the DC refusal. The script has not yet been run on a
  Windows host (no MSI to observe); first run must be logged in `windows-lab-runs/`.
- **Results:** `ok`, `FAIL` (build fails), `INACTIVE` (the collector could not observe it: the subject does not exist
  yet), `GAP` (fails today, tolerated until the named ticket lands). `tools/fitness/host/known-gaps.json` is a
  ratchet: a gap that passes fails the build until its entry is deleted. Never add a gap without a ticket.
- **Proof it fails:** `hostcheck_test.go` has one violating fixture per case (and asserts no other case trips);
  `make ci-proof` runs `host evaluate` on a compliant observation and on eight mutated ones.
- **Setup secret (T-0636):** on linux-oci `HOST-SETUP-SECRET-SINGLE-USE` is active: the harness reads the
  secret file's tar header (mode/owner), POSTs it twice to `/api/v1/setup/claim` over verified TLS with a valid
  `owner{displayName,email}` block (the route validates the owner before the secret, so a body without one gets a
  400 that proves nothing, T-1161; `claim_test.go` judges the body with the server's own validator) (first 204,
  second must be 401; an unexpected status prints the server log), and boots a second server with `ACTIVEDIQ_SETUP_TTL=2s` to present an expired secret
  (must be 401). The harness also provisions the KEK (`kek init` into a volume) because the server has no
  default custody model; without it no boot gets past start-up. Windows stays INACTIVE for this case until the
  MSI exists (T-0635) and the lab collector grows the same probe.
- **Open gaps:** `HOST-NO-DUMPS` on linux-oci (T-0634); `HOST-DC-REFUSED` (T-0635) and the Windows half of
  `HOST-SETUP-SECRET-SINGLE-USE` are INACTIVE until their product subject exists. The positive verify-full DSN control needs a TLS
  PostgreSQL and is covered by `store.CheckTransport`'s own tests.

## `fitness-agent-host` (T-0554: ADR-0006 A1/A4, ADR-0007 P1-P8, contract R1-R5, F1)

`make fitness-agent-host` (part of `make fitness` and `make ci`). Run a subset: `go run ./tools/fitness/agenthost -checks A1,P`. It prints one line per check; `inactive (<missing input>)` means the subject does not exist yet and the check did not run (exit 0). **ADR-0006 and ADR-0007 become `accepted` only when no line is inactive** and the lab items in ADR-0006 "Verification owed" are confirmed.

| Check | Inactive until | Who lands it |
| --- | --- | --- |
| R1, R2, R5 | `proto/skenzeriq/agent/v1/*.proto` and `proto/activediq/addc/v1/*.proto` exist | T-0600 (the proto) |
| A1 | any WiX source under `packaging/`, or a file there that names the agent (path contains `agent`, or body mentions `activediq-agent`/`activeDIQAgent`) | the agent MSI ticket (windows-engineer) |
| R3, R4, A4, P1-P8, F1 | always active | — |

**What the installer author must write for A1 (allow by exception).** A1 judges **every WiX source under `packaging/`** (`.wxs .wxi .wixproj .xml`), whether or not it names the agent, plus every other file whose path or body names the agent (`activediq-agent`/`activeDIQAgent`). In a WiX source: (1) exactly one `ServiceInstall` naming the agent service with `Account="NT SERVICE\activeDIQAgent"` and no `Password`; every `ServiceSid` on it or on a `ServiceConfig` for it must be `restricted` (an `unrestricted` anywhere fails, whatever order) and the privileges must be exactly `SeChangeNotifyPrivilege`; (2) every `ServiceInstall`, `ServiceConfig` and `ServiceControl` names its service as a **literal**: a name containing `$(var.`, `[Property]` or `!(bind.` fails, because the service cannot then be judged; (3) **no `CustomAction` or `Binary` at all** unless its `Id` is in `tools/fitness/agenthost/installer-allow.txt` (empty today): nothing may compute the account, SID type or privileges at install time, however it spells `sc.exe`; (4) no `RegistryKey`/`RegistryValue`/`RemoveRegistryKey`/`RemoveRegistryValue` under HKLM/HKMU whose key (joined through nested `RegistryKey` elements) starts with `SYSTEM\`, or is built from a property or variable; HKCU/HKCR/HKU and `HKLM\SOFTWARE\...` are fine. The channel ACE (ADR-0006 rule 2) therefore needs its own reviewed element or custom action, listed in `installer-allow.txt` after a security-architect review. In every judged file: any `LocalSystem`, `LocalService`, `NetworkService`, `NT AUTHORITY\SYSTEM` or SID S-1-5-18/19/20 text fails, comments included (write "never the system account"), and any reference to `CurrentControlSet\Services` / `ControlSet001\Services` (any backslash count) fails. In files that name the agent: a **script-type file** (`.ps1 .psm1 .cmd .bat .vbs .js .wsf .sh .py ...`) fails unless its repo-relative path is in `installer-allow.txt`; and an `sc.exe config|create`, `Set-Service`, `New-Service` line with `obj=`/`-Credential`, or any line with `StartName`, `Win32_Service` Change/Create, `ChangeServiceConfig` or `CreateService`, must name the pin on that line (the message layer; the allowlist is what makes the check complete). UTF-16 files (BOM or NUL pattern) are decoded; a WiX or agent-path file that is not text, or over 4 MiB, fails closed unless it has a binary extension (`.ico .png .dll .exe .cab .msi ...`). If WiX spells something differently, extend `judgeInstallerXML` and its fixture together; do not loosen the pin. **Round-4 additions (parsed structure).** The agent pin is driven by the *parsed, entity-decoded* XML, not raw text: an element that decodes to the agent name (`activeDIQ&#65;gent`) gets the full pin wherever it sits, `&#...;` references in WiX fail, and `LocalSystem` text is also searched in decoded attribute values. A `ServiceInstall` with no `Account` fails everywhere (implicit LocalSystem); every non-agent `ServiceInstall` must use `NT SERVICE\<its own Name>` or be listed by `Id`; a Component holding the agent service, and any file naming the agent, may hold exactly one `ServiceInstall`. Any `Permission`, `PermissionEx` or `util:PermissionEx` fails unless its parent element `Id` is in `installer-allow.txt` (the service DACL and data-directory DACL are reviewed items). Templates and transforms (`.in .tmpl .xsl .xslt .j2 ...`) under `packaging/` fail unless listed, and any non-WiX, non-script, non-binary file naming the agent fails unless listed. **Round-5 additions.** (a) Any `<!DOCTYPE`, `<!ENTITY` or named entity other than `amp lt gt quot apos` in a WiX file fails (a DTD entity can build a name the check never sees decoded). (b) Scope is the whole repo, not only `packaging/`: every `.wxs .wxi .wxl .wixproj` (and `Name.wxs.in`-style templates) anywhere is MSI source; only `.git`, `node_modules`, `testdata` and `tools/fitness` are skipped. (c) **Every** `ServiceInstall` (not only the agent's) must carry `ServiceSid="restricted"` and RequiredPrivileges exactly `SeChangeNotifyPrivilege`, from the element, its children, or a `ServiceConfig` naming it in the same file, unless its `Id` is in `installer-allow.txt` (the agent's own service is never exempt); an unmatched `ServiceConfig` may not set any other SID type or privileges.

A core MSI with no agent in it is still judged by rules 2-4 and the LocalSystem/registry text rules, so its own custom actions and system-account services need an `installer-allow.txt` line or a different packaging path: raise it in the MSI ticket.

**R3 and A4 are allowlists.** R3: an agent module (`internal/agentmodules/**`) may import only the standard-library packages in `r3AllowedStd` plus our `<module>/internal/agentmodules/...`, exactly `<module>/internal/platform/agentpolicy` and exactly `<module>/internal/agenthost/hostapi` (module path read from `go.mod`; a look-alike path under another module or a longer name fails); `syscall`, `unsafe`, `import "C"`, `io/ioutil`, `golang.org/x/sys/*`, `plugin`, `os/exec` and every dot or blank import fail by name, and `filepath.WalkDir/Walk/Glob/EvalSymlinks` fail (reads go through the host's dependency struct); package `os` is allowed only as `os.Getenv`, `os.LookupEnv`, `os.Err*` and `os.Is*` (everything else, including `OpenRoot`, `CopyFS`, `FindProcess`, `*os.File`, fails: methods on values cannot be told apart by name); the file-mutating call denylist is a second layer; and any non-`.go` file in a module directory (`.s`, `.syso`, `.c`, `.h`, ...; `testdata/` excepted) fails because it links code the scan cannot see. To give modules another package, add it to `r3AllowedStd`/`r3OwnPrefix`/`r3OwnExact` with a security-architect review. R4: every own-module package in `go list -deps ./cmd/agent` (windows and linux), not a fixed directory list, is scanned; any selector named `Listen*`, `Serve*`, `ListenConfig`, `NewServer`, or `Bind` on `syscall`/`windows`/`unix` fails whatever it is called on. A4: the agent closure may hold only the non-stdlib packages in `tools/fitness/agenthost/closure-allow.txt` (today our own `cmd/agent`, `internal/compose/agent`, `internal/compose/config`); anything else fails, and the named LDAP/SMB/RPC/Kerberos/SSPI bans stay as messages and win over the allowlist. Adding a line to `closure-allow.txt` needs a security-architect review. The tool also fails when ADR-0006/0007 front-matter says `status: accepted` while any check is inactive.

**A1 walker fails closed (T-0677).** A1 does not guess what MSBuild evaluates (`%XX` escapes, properties, globs, `Directory.Build.props`/imports), and it does not trust file names: WiX compiles any file and `<?include?>` takes any name. It scans every WiX-named file (`.wxs/.wxi/.wxl/.wixproj` and their templates) **and, by content, every other text file in the repo (except `.git`; **no extension, binary ones included, exempts a file**, a real binary has NULs and is not text; UTF-16 and UTF-32 are decoded) that is an XML document rooted at `Wix`, `Include` or `WixLocalization`**, wherever it sits; Go/shell files holding a snippet in a string are not XML documents and pass. Consequence: test fixtures must never be WiX on disk (keep them as Go strings written to `t.TempDir()`); WiX under `tools/fitness` fails A1. Prebuilt WiX intermediates (`.wixlib/.wixipl/.wixobj`, or any zip holding `wix-ir.json`) anywhere are violations: we build from source only. A path the walk cannot read (e.g. a mode-000 directory) is a violation. A symbolic link anywhere (except `.git`) is a violation if it is WiX-named, dangling or looping, leaves the repo root, resolves to a directory, or targets a WiX file (by name or content); plain in-repo file links (`node_modules/.bin/*`) pass. Proofs: `TestA1Installer` and `tools/ci/proof.sh` (one fixture per bypass; the unreadable-directory case is skipped as root). **Residual risk:** a Compile Include of an absolute path or one leaving the repo root cannot be checked statically; and so is WiX generated at build time (MSBuild `Exec`/`UsingTask` inline tasks, `WixExtension`/`PackageReference`); that is judged on the built artefact by **`make fitness-built-msi`** (T-0697, below), not by A1's source scan.

**Built-MSI check, `make fitness-built-msi` (T-0697).** After the build, `go run ./tools/fitness/builtmsi -glob 'dist/*.msi'` dumps each MSI with `msidump -t` (msitools) and judges the tables Windows Installer executes: every `ServiceInstall` row must have `StartName` = `NT SERVICE\<its own Name>` (the agent: `NT SERVICE\activeDIQAgent`, exactly one row, no `Password`; empty `StartName` is LocalSystem and fails), every installed service needs an `MsiServiceConfig` row `ConfigType 3` with `Argument 3` (restricted SID) and `ConfigType 4` with exactly `SeChangeNotifyPrivilege`, and any other row for those config types that differs fails; a `ServiceConfig` (util) table with rows fails; every `CustomAction` row must be in both `tools/fitness/agenthost/installer-allow.txt` and `tools/fitness/builtmsi/pinned-actions.txt` with the same Type/Source/Target (the Type numbers there are derived from the flags; verify them against the first real WiX build, and a mismatch is a review item, never a loosening); any `Binary` row fails; every `MsiLockPermissionsEx`/`LockPermissions` row fails (no DACL is reviewed; `installer-allow.txt` lists CustomAction Ids and never vouches for a permission, because MSI keys are per table; a future reviewed DACL needs its own pin keyed by Table+LockObject with the exact SDDL); the `ConfigType 3`/`4` rows count only when `Event` includes install (bit 1), their `Component_` is the one that installs the service, and that component has no `Condition`; any `MsiEmbeddedChainer`/`MsiEmbeddedUI` row fails, `MsiServiceConfigFailureActions` may only restart (0/1, no reboot, no `Command`), and `ServiceControl` may name only the agent service; `Registry`/`RemoveRegistry` rows under HKLM\SYSTEM (or built from a property) fail. Each message names the table and row key. With no MSI the check prints `inactive` (never a pass); the release job runs it on `dist/*.msi` and the ticket that makes the pipeline build the MSI must add `-require` there (`make fitness-built-msi` takes `BUILT_MSI=<glob>`). **Prerequisite:** `apt-get install msitools` (LGPL-2.1+, CI tooling only, never shipped; `wixl` from the same family is needed only by `make ci-proof` and the `TestRealMSI` test, which build real throw-away MSIs). Proof: `tools/ci/proof.sh` builds MSIs whose `.wxs` is generated into `obj/` at build time (as an MSBuild inline task would) and requires the clean one to pass and LocalSystem, an unrestricted SID, an extra privilege, an unreviewed custom action, a service-keyed DACL row, uninstall-only settings and a missing required MSI to fail.

**If it fails.** The line names the rule and the file. A4: the import path is in the message; the agent has no directory or network-identity client, so remove the import, never the ban. P/F1: the test name is printed; fix the verifier or the bound, never the test. A missing test means a rename: P1-P8 are found by the prefixes `TestP1`…`TestP8`, `TestF1`, `FuzzF1`. A `FuzzF1` crasher is written to `internal/platform/agentpolicy/testdata/fuzz/`: commit it as a regression seed. `make fitness-agent-host AGENT_POLICY_FUZZ_TIME=2s` for a quick local run.

**Not covered here (lab or other tickets).** The contract §3 bound "event_ids in the compiled-in catalogue" and the local-ceiling clamp are not enforced by `agentpolicy.Validate` (they need the module catalogue and the host's local config) and so are not in F1: owning ticket T-0555 (agent host and addc module). ADR-0006 A2/A3 (token privilege refusal, channel ACE read, write-denied outside the data directory) run in the Windows lab; F2/F3 (hostile in-bounds policy has no side effect beyond verdicts, applying a policy writes the local entry) need the agent host and rule engine; S1 is T-0556's ingest test.

## The pre-merge gate (T-0941)

**What it is.** The dispatcher builds `main` + `factory/T-NNNN` in a scratch worktree
(`<worktree_root>/.premerge/`) and runs `dispatcher.pre_merge.argv` (default `make -k ci`) there before
it merges. Settings: `factory/config.json` `dispatcher.pre_merge` (`enabled`, `argv`,
`timeout_minutes`, `baseline_reuse_roots`). Logs and the baseline cache: `factory/state/premerge/`.

**The baseline is reused, not re-run per `main` commit (T-1378).** When the merge result is red, the gate
needs `make -k ci` findings of `main`. It takes them from a cached run (`baseline-*.json`) on the same
tree, or on a tree that differs only in files under `knowledge/`, `.claude/`, `factory/`, `garage/` that
no gate file (tracked, outside those directories, not `*.md`) mentions as a path (`readSurface` in
`factory/lib/premerge.mjs`, computed from the tree each time). So memory, report and digest commits cost
nothing, while a commit to the ADRs, the licence register, the architecture map or the runbooks the
fitness tools name does re-run it. The gate summary (event, `factory premerge` output) states which:
`baseline: reused the cached run …` or `baseline: ran a fresh baseline …`. A passing gate stores its
merge-result run as the baseline of the tree it will become, so the second half of a split train runs no
baseline. If a fresh baseline times out, the nearest cached run stands in: the train can pass if all its
findings are in it, otherwise the gate stops with a message naming the findings. Never raise
`timeout_minutes` as the fix for that; find what is loading the host (`uptime`) first.
Rules and the comparison: `standards/ci-gates.md` "The pre-merge gate". It needs what `make ci` needs
(Docker for the container jobs, Node, network once for toolchains).

**See what it would do:** `factory/bin/factory premerge T-NNNN` (exit 0 pass, 1 refused or conflict).
`factory/bin/factory premerge T-NNNN -- make fitness-profiles` runs one job instead.

**A ticket was reopened by the gate.** The note lists the new findings. Fix them in code; merge `main`
into the branch first, because the findings are judged against current `main`. Never edit the
check, add `continue-on-error` or delete a baseline file to get through.

**Reopened with "Renumber to NNNN" (T-1067).** Another branch landed the same migration number
first. Merge `main` into the branch, run the `git mv` the note gives, fix references to the old
number (tests, comments, docs), run `go test ./migrations/ -run TestMigrationNumbersAreUniqueAndContiguous`,
advance again. Settings: `dispatcher.pre_merge.numbering` (`dir`, `argv`, `timeout_seconds`); remove the key
to turn the check off (do not, without the director).

**Everything is refused for the same unrelated reason.** `main` is green and a job is red in the
merge result with no change of ours (an expired token, a tool missing on the dispatcher host): the
refusal names `FAILED <target>`. Fix the environment; the gate fails closed on purpose. To stop the
gate temporarily set `dispatcher.pre_merge.enabled` to `false`, say why in an event, and re-enable it
as soon as the cause is fixed; the director owns that call.

**A red job that is not ratcheted.** Findings are recognised by shape (the table in
`standards/ci-gates.md`, Pre-merge gate). If a job prints violations in another shape, new ones in
it pass while it is red on `main`. Print one self-contained line per violation, add a sample of it
to `JOBS` in `factory/test/premerge.test.mjs` (the test fails for a `make fitness` job without one)
and, for a new shape, extend `findingKey` in `factory/lib/premerge.mjs`. Check a log by hand:
`node -e "import('./factory/lib/premerge.mjs').then(m=>console.log(m.extractFindings(require('fs').readFileSync('job.log','utf8'))))"`
prints the findings it counts; fewer than the job's own violation count means a shape is missed.

**Merges fail with "the main checkout is mid-merge".** A previous merge left `MERGE_HEAD` in the main
checkout (a failed `merge --abort`, for example "Unable to write index"). `mergeTicket` now reports
that as an error and retries, instead of calling it the next ticket's conflict and reopening it
(T-0941 was reopened twice that way). Finish or abort that merge by hand (`git -C <root> merge --abort`
once its index is writable); every pending merge then proceeds on the next pass.

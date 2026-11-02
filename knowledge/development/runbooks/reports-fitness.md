---
title: fitness-reports — enforcing ADR-0010 and the reports contract (RP1–RP11)
date: 2026-10-30
updated: 2026-11-01
ticket: T-0873
status: draft
owner: devops-engineer
---

# fitness-reports: how the job works and how a build ticket plugs into it

Enforces [ADR-0010](../decisions/0010-report-results-stored-as-rows-in-postgres.md) and
[reports.md §9](../architecture/modules/reports.md). Run it with `make fitness-reports` (part of
`make fitness`, so of `make ci`). RP1 runs inside `make fitness-safeprim`.

| Check | Where it runs | What fails |
| --- | --- | --- |
| RP1 | `tools/analyzers/sqlconst` (FF-SP2) | outside `internal/platform/store/reportsql`: a conversion to `reportsql.CompiledSQL`, the address of a `CompiledSQL` (an unmarshal target), a `reportsql.Query` literal; anywhere: `report.SQL` called with a non-constant. Tests and tier L are not judged. |
| RP2 | `tools/fitness/reports`, type-checked | `ReadScope.Terms`/`.Token` outside `authz` and `store/reportsql`; `authz.NewReadScope` outside `rbac`, `authz`, `authz/authztest`; non-test code importing `authz/authztest` |
| RP3 | same | a package under `internal/modules/reports/**` other than `…/reports/run` referencing `Compile`, `CompileCount` or `Exec` of `reportsql` (call, method value or method expression), or an interface there declaring one of them over reportsql types |
| RP7 | same, `library/LOCK` | see below |
| RP4–RP6, RP8–RP11 | same, `go test -json` | the bound test is absent, failed, skipped (a skipped subtest counts), or declared while its binding is not `Landed` |

## Pending is not a pass

Until a part's code exists the job prints it as `pending` on every run. Each check that ran and
found nothing is printed as `pass` (with the bound test and package for RP4–RP11), so the CI log is
the evidence an ADR cites. A check with a pending part or a violation is never listed as `pass`.
ADR-0010 is bound to RP3, RP4 and RP5 only (its § Fitness function). It reached `accepted` on 2026-11-01 (row
B14, T-0968), when it was ratified and those three printed `pass`; a later failure of any of them is a broken accepted ADR, not a pending one. The other RP checks enforce the
reports contract (§9), not the ADR. Each rule turns active by itself when its code appears:
`authz.ReadScope` (T-0880) activates RP2, `store/reportsql` (B2) activates RP3, `library/` (B5)
activates RP7.

## Landing a bound test (build tickets B2–B11)

In `tools/fitness/reports/bindings.go` set `Landed: true` and, if the test lives elsewhere than the
default guess, `Pkg` to its package. That edit is reviewed with the test. The job fails when the
test is later renamed, deleted, fails, or skips (no Docker, no lab: the test must be runnable in CI;
a test that cannot run here proves nothing).

RP11 is run once per dataset. Every `report.Dataset` literal in non-test code must set `ID` to a string
constant; the test must have a subtest named exactly that ID (`t.Run(string(d.ID), …)`) for each one.
A new dataset without a subtest fails the job and names the dataset.

## `library/LOCK` (RP7)

`internal/modules/reports/library/LOCK` is `sha256sum` format: `<64 hex>  <path relative to library/>`,
`#` comments allowed. Every `*.json` under `library/` must be listed and keep its hash. To ship a new
definition version, add the file and `sha256sum <file>` to LOCK in the same change; never edit a
shipped file (FR-03) — ship a new version. `make fitness-reports` also compares LOCK with the base
ref (`REPORTS_LOCK_BASE`, default `main`, else `origin/main`): an entry present there must be present
and equal here, so a definition and its LOCK line cannot be edited together. A base ref that does not
resolve is an error (exit 2), not a skip. `.gitattributes` marks `library/**` as `-text` so line-ending
conversion cannot change a hash.

## Known limits (deliberate, reviewed)

- The typed rules load the host platform's build (`go/packages`, non-test files). Code under a
  build tag for another OS is not judged; the reports packages are not platform-constrained.
- RP2/RP3 judge references, not data flow: a `ReadScope` handed through an `any` and
  reflected is outside them. Reflection is already banned by review.
- RP1 does not catch generic instantiation or `unsafe` casts to `CompiledSQL`; `unsafe` is banned in
  product code by FF-SP2 already.

## Failing runs (evidence for T-0873)

`tools/ci/proof.sh` builds a throw-away tree per rule and requires the real CLI to reject it, and to
accept the clean tree. The same shapes are unit tests: `go test ./tools/fitness/reports
./tools/fitness/internal/boundtest ./tools/analyzers/sqlconst`.

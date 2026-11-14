---
title: Universal search latency benchmark
status: draft
owner: test-engineer
updated: 2026-11-02
---

# Universal search latency benchmark (T-1102, ADR-0011 rule 14, fitness SE6)

Proves that universal search answers in under 200 ms at the 95th percentile, per query class, over 50,000
inventory objects on PostgreSQL 16 and 18, for an unscoped and a scoped caller, through the HTTP handler in
process.

## Run it

```
make search-latency          # the nightly job; needs Docker; both versions, one locked run
make search-latency-pg16     # one version per invocation (fits a 90 min worker session)
```

A passing version takes about 25 minutes on a loaded host, 5.5 of them for the seed.

Output tables land in `factory/demos/evidence/T-1102/search-latency-pg16.txt` and `-pg18.txt`
(`SEARCH_LATENCY_OUT` overrides the directory). Under the hood:
`ACTIVEDIQ_SEARCH_LARGE_OBJECTS=50000 go test ./internal/modules/search/latency -run TestSearchLatency50k`.
The switch follows the `ACTIVEDIQ_*_LARGE` convention of the reports scale tests; the benchmark accepts
exactly `50000`.

`make fitness-nightly` includes `search-latency`. A miss fails the job with a line such as
`search latency budget missed: pg18 caller=scoped class=fuzzy1 p95=231.4ms (budget 200ms)`. No scheduler runs
the nightly target yet (see `standards/ci-gates.md`); until one does, run it by hand before an M2a demo.

`make ci` runs `TestSearchHarnessSmoke`: the same harness on a 1,200-object seed with W=240, every answer
checked against the oracle, no time budget. It keeps the seed, the oracle and the HTTP path from rotting.

**Early stop on a decided miss.** With nearest-rank percentiles, the p95 of 1,000 queries is over budget as soon
as 51 of them are (`overToMiss`, proven in `TestOverToMissDecidesTheP95`). The timed loop stops a class at that
point and prints the row with its real `n` and `stopped: …`. A missing class therefore costs about 51 slow queries
instead of 1,000, and the job fails naming it. Before this, a run in which every query was slow (about 0.5 s
each) hit the 90-minute `go test` timeout without naming any class (T-1102, runs of 2026-11-02). A passing class
always runs all 1,000 queries.

**A timeout is a sample, not a crash.** When a query runs into the service's 2 s timeout (ADR-0011 rule 13), the
handler answers `503 /problems/search-unavailable`. The harness counts that as a sample over budget and notes it on
the row. In the oracle comparison it is a disagreement. Any other non-200 still stops the run. Before this, one
timed-out fuzzy query on pg18 aborted the run and lost its table.

**A miss is attributed by the plan, not by the clock.** The plan-probe lines (`removed by filter`, the fuzzy scan
node) do not depend on host load. If the fuzzy CTE reads the tenant's whole fuzzy-kind key set, the miss is real
on any host (T-1180), not contention.

## What is measured

| Item | Value |
| --- | --- |
| Seed | `NewSeed(50000)`: 30,000 users, 8,000 groups, 10,000 computers, 2,000 contacts; two connections (60/40); 376 OUs per connection, six levels; ~5 % repeated display names; 10 % of users and computers disabled. Pure function of fixed constants, SHA-256 pinned in `TestSeedIsDeterministic`. Written through `inventory.Populator`; row counts asserted before any timing. |
| Machine | Go side `GOMAXPROCS=4`; database container `docker update --cpus=4 --memory=8g`. The host is larger and shared, so the numbers are a conservative-in-CPU, not-quite-isolated measure; the run records host CPUs and `shared_buffers`. |
| Path | `POST /api/v1/directory/search` through the real apihost router, directory handler, `search.Service`, `inventory.Searcher` and PostgreSQL. Authentication, authorization, rate limiting and the read-scope producer are stubs: `rbac.ReadScopes.For` is not in the timed path (its composition is covered by T-1096's `TestSearchTakesItsScopeFromTheComposedProducer`). |
| Runs | 200 warm-up queries, then 1,000 per class and caller: `exact` (sam, UPN, host, mail), `prefix`, `fuzzy1` (one transposed or dropped letter), `nomatch`, `oneletter`, `ceiling` (a one- or two-letter prefix whose matched key rows are just under W, calibrated from the seed). |
| Callers | `admin`: both naming contexts whole. `scoped`: one OU subtree of connection 0 minus a large excluded sub-OU. |
| Oracle | `Seed.Visible` (own implementation of both scopes) plus sorted per-kind key slices for exact and prefix, and a PostgreSQL sequential scan with indexes off for the fuzzy class. Every timed answer is checked for hidden objects; a sample per class is compared for refine state, counts and hit sets. |
| Plan probes | `EXPLAIN (ANALYZE)` of the handler's statement: one-letter key rows read are at most W+1 and identical for both callers (the hidden set is not scanned); no sequential scans; fuzzy rows read and `Rows Removed by Index Recheck` recorded. |
| W sweep | the ceiling-sized class re-measured at W = 5,000 to 10,000 in steps of 1,000, then 20,000 and 40,000. The default W (`inventory.DefaultSearchCeiling`) is set from this sweep: the largest W whose ceiling-class p95 is under 200 ms for both callers on pg16 and pg18 (7,000, T-1303). |

## Rules for changing it

- A change to the seed changes `seedDigest50k`; say so in the commit, because the numbers are no longer comparable.
- A p95 miss is a bug ticket against the search module, never a loosened budget here.
- T-0972 (report scale calibration) should lift `summarize`, `ms` and the table layout into a shared package when
  it starts; its 100,000-user report lab is a different dataset and is not duplicated here.

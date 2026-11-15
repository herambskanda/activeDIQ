# T-1102 evidence: universal search latency at 50,000 objects (2026-11-02)

The budget is missed on PostgreSQL 16 and 18 for both callers, in every class of three or more characters.
The cause is T-1180. T-1102 is blocked on T-1180 and T-1303.

| File | What |
| --- | --- |
| `search-latency-pg16.txt` | `make search-latency-pg16`, PostgreSQL 16.14, full run (22.6 min) |
| `search-latency-pg18.txt` | `make search-latency-pg18`, PostgreSQL 18.6, full run (23.6 min) |
| `root-cause-plan-pg16.txt` | principal-engineer probe: HTTP medians per class, and `EXPLAIN (ANALYZE, BUFFERS)` of the handler's statement with and without the fuzzy CTE |

## p95 (ms), admin / scoped

| Class | pg16 | pg18 | Verdict |
| --- | --- | --- | --- |
| exact | 701 / 705 | 795 / 757 | over, proven by the plan |
| prefix | 1031 / 497 | 624 / 591 | over, proven by the plan |
| fuzzy1 | 706 / 684 | 808 / 730 | over, proven by the plan |
| nomatch | 486 / 544 | 487 / 473 | over, proven by the plan |
| oneletter | 180 / 149 | 143 / 122 | within budget |
| ceiling (W=10,000) | 240 / 180 | 196 / 147 | pg16 admin over, under load → T-1303 |

The over-budget rows stopped after about 51 queries: with a nearest-rank p95 over 1,000 queries, 51 queries over
200 ms decide the miss (`overToMiss`, runbook `knowledge/development/runbooks/search-latency.md`). The oracle found no
disagreement and no hidden object on either version.

## Why the misses are not host load

Both tables mark the misses `INCONCLUSIVE` because the 1-min load average exceeded the host's 12 CPUs at the start of
the timed runs (20.0 on pg16, 22.5 on pg18). The plan probes in the same files rule out load, because their row
counts do not depend on it. For every one-typo probe, the fuzzy CTE is a `Seq Scan` on `inventory_search_keys`
with 415,563 rows removed by filter. That is the tenant's whole fuzzy-kind key set: under FORCE RLS, pg_trgm's `<%`
is not leakproof, so it is never used as an index condition (T-1180). Without the fuzzy CTE, the same statement runs
in 0.9–1.2 ms (`root-cause-plan-pg16.txt`). Every query of three or more characters runs the fuzzy CTE.

The pg16 table was recorded with commit 1b20007f6 and the pg18 table with 5233fbcf0. Since then the harness labels such a miss `PROVEN BY PLAN` instead
of `INCONCLUSIVE`.

## T-1303: work ceiling W (2026-11-14)

`search-latency-pg16.txt` and `search-latency-pg18.txt` are now the W=7,000 runs (load 4.3 / 5.1 at start, host 24 CPUs).
Ceiling class p95, admin / scoped: pg16 172.3 / 145.9 ms, pg18 148.5 / 126.7 ms. pg16 admin is the binding case:
W=8,000 is 196.7 ms in this sweep but 216.4 ms in the earlier quiet run, so W=7,000 is the largest value that held in
every sweep. The `T-1303-*` files are the earlier sweeps. exact, prefix, fuzzy1 and nomatch classes stay over budget:
that is T-1180, not a ceiling effect.

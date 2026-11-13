# T-1335 AC6 — the fuzzy probe over 50,000 objects (PostgreSQL 16 and 18)

Raw transcripts: `probe-pg16.txt`, `probe-pg18.txt`. Reproduce:

    ACTIVEDIQ_SEARCH_PROBE=1 ACTIVEDIQ_SEARCH_PROBE_OUT=$PWD/factory/demos/evidence/T-1335 \
      go test -count=1 -timeout 30m ./internal/directory/inventory -run Test_search_probe_50k -v

**What this is and is not.** The AC names `probe_pg_test.go` on `factory/T-1102`; that file was never committed
(the T-1102 branch holds the latency benchmark, `internal/modules/search/latency`, and the plan transcript
`root-cause-plan-pg16.txt`, whose `probe_pg_test.go:49` is only a log prefix). This probe re-creates it:
`Test_search_probe_50k` in `internal/directory/inventory/search_trigrams_probe_test.go` seeds one tenant with
50,001 user objects (a name key and a sam key each: 100,009 key rows, 1,591,632 postings, 4,627 distinct
trigrams), VACUUM (ANALYZE), then runs the compiled handler statement (`reportsql.CompileSearch`, groupLimit 50,
threshold 0.3) as the runtime role under FORCE RLS inside the 30 s tenant transaction, `EXPLAIN (ANALYZE,
BUFFERS)`, 2 warm-up and 9 timed runs per row. It is NOT the T-1102 seed (different names, no scoped caller, no
HTTP, no 4-CPU/8 GB container limit, not the T-1102 digest), so the numbers are comparable in kind, not in value
(T-1102 measured 312–470 ms for the same classes before this change on its own seed, PG16).

## Execution time of the statement (median / max of 9 runs, ms)

| class | text | PG16 W=10000 | PG18 W=10000 | PG18 W=100 |
| --- | --- | --- | --- | --- |
| exact | a full name | 22.4 / 35.4 | **114.3 / 158.9** | 42.5 / 59.0 |
| prefix | first 7 characters | 14.3 / 24.9 | 96.9 / 125.9 | 29.2 / 38.2 |
| fuzzy1 | name with one letter deleted | 21.2 / 43.2 | 110.7 / 122.3 | 45.0 / 71.7 |
| nomatch | `zx0946z` | 1.4 / 2.5 | 0.4 / 0.6 | 0.4 / 0.8 |
| worst32 | 32 runes of the 8 most frequent whole trigrams | 45.0 / 58.3 (62,173 posting rows) | 139.1 / 172.8 (62,173) | 77.5 / 86.6 |

(PG16 at W=100 matches W=10000 within noise: see the raw file.)

* **PostgreSQL 16: every class is far inside 130 ms**, the worst case included (58 ms max; the 30 s statement
  timeout is not close).
* **PostgreSQL 18 at the default ceiling misses 130 ms for exact (max 159 ms; median 114 ms)**; prefix and fuzzy1 are within
  a few ms of it. Cause, from the plan shape in the raw file: at W=10000 the planner hash-joins the three
  LIMIT W+1 CTEs onto a **Seq Scan of directory_objects (50,004 rows)**. That is the hits join, not the fuzzy class
  (the postings are read through the pkey in all cases), and at W=100 the same queries take 29–45 ms with an index
  probe per candidate. It is already filed as **T-1345** (found in this ticket as T-1344; the evidence is noted
  there). Not fixed here, per the AC.
* On PG18 the posting read for the exact query is a Bitmap Heap Scan (11,215 heap blocks for 29,870 postings); the
  worst case on PG16 is an Index Only Scan (730 blocks for 62,173). The bitmap form is most of PG18's 42 ms at W=100.
  Within budget; noted for the sizing guide.

## Size for the sizing guide (50,001 objects, 100,009 keys)

| relation | total | heap | primary key |
| --- | --- | --- | --- |
| `inventory_search_trigrams` | 208 MB | 91 MB | 117 MB |
| `inventory_search_keys` (before this change it also held the GIN) | 34 MB | | |

About 15.9 postings per key, 32 per object: roughly 4.2 KB of postings table and index per object, so a
500,000-object tenant needs about 2 GB (linear extrapolation, not measured).

## AC5 at the declared scale (PostgreSQL 16)

`ac5-50k-pg16.txt`: tenant A holds 50,000 objects; tenant B loaded empty, equal to A and 10x A (500,000 objects),
VACUUM (ANALYZE) after each load. Posting rows examined by A's four proof queries: 29,322 in all three loads
(keys 30, directory_objects 6); with B 10x the posting index has one more level, covered by the documented
tolerance (one block per probed trigram per extra level). Run with `ACTIVEDIQ_SEARCH_LARGE_OBJECTS=50000`, 1,582 s.
PostgreSQL 18 ran at the CI scale only (N=2,000, B up to 20,000): `Test_search_fuzzy_reads_only_the_tenants_own_postings` green on pg16 and pg18.

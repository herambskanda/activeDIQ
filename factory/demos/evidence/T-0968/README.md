# T-0968 evidence: ADR-0010 fitness checks RP3–RP5 (2026-11-01)

Tree: main `10d8b9fa8` merged into `factory/T-0968` (adds only the per-check `pass` lines to `fitness-reports` and this ADR status change).

- `fitness-reports.txt`: `make fitness-reports`. RP3, RP4 and RP5 print `pass`; only RP10 (row B11, not an ADR-0010 check) is pending.
- `rp4-go-test.txt`, `rp5-go-test.txt`: `go test -count=1 -v` of the two bound tests. Both pass on PostgreSQL 16 and 18 with no skips. RP4 now carries the subtests T-1144 added for the clauses that were missing on 2026-10-31: `export_of_an_expired_run_makes_a_new_run`, `a_succeeded_run_needs_expires_at` (the `report_runs` CHECK) and `every_state_edge_at_the_trigger`.

Result: ADR-0010 is `accepted` (accepted_on 2026-11-01). The 2026-10-31 run on main `d34d56e2c` kept it `proposed`, pending T-1145 (ratification on record) and T-1144 (RP4 coverage). Both are done.

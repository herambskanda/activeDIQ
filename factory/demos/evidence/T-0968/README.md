# T-0968 evidence: ADR-0010 fitness checks RP3–RP5 on main d34d56e2c (2026-10-31)

- `fitness-reports.txt`: `make fitness-reports` with the new `pass` lines. RP3, RP4 and RP5 print `pass`; only RP10 (row B11, not an ADR-0010 check) is pending.
- `rp4-go-test.txt`, `rp5-go-test.txt`: `go test -count=1 -v` of the two bound tests. Both pass on PostgreSQL 16 and 18 with no skips.

ADR-0010 stays `proposed`. Its ratification was never recorded (T-1145), and RP4's bound test misses three of the ADR's RP4 clauses (T-1144).

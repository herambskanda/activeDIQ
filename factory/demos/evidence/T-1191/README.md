# T-1191 QA evidence (build 803f9bd26)
- go-test-sync-race.txt — go test -race ./internal/directory/sync -run 'TestFullCycle|TestCompleteScan' -v, pg16+pg18, EXIT=0 (my run)
- ac6-heap-scaling.txt — my scratch probe: heap growth at 100k/400k/1M objects (DB-free)
- exact-multiple-probe.txt — my scratch probe: 500/1000/1500-object domains on real Postgres (empty last batch carries pass)

## Re-QA, build 4b7308efc (after security F3 fix: client.Reader read-only port)
- go-test-sync-race-4b7308e.txt — same TestFullCycle|TestCompleteScan -race run on pg16+pg18, EXIT=0, 12 top-level tests PASS, 0 SKIP
- go-test-client-fitness-4b7308e.txt — internal/directory/client (TestReaderIsReadOnly), tools/fitness/operation, tools/fitness/ports: ok

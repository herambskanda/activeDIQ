# T-1032 QA — build 27bead370
AC1 PASS. My own runs: go test -count=1 -v ./internal/platform/notify/syslog -> ok (33.9s), the 6 formerly failing tests PASS (go-test-syslog.txt).
Related: apihost/..., modules/reports/..., modules/directory/... ok (go-test-related.txt); compose/server ok 106s (go-test-compose.txt) — builds apihost with the REAL catalogue against the real contract, so "every x-permission is in the catalogue" holds for production.
Contract reports.yaml x-permissions {reports.export, reports.run, reports.schedule, reports.schedule.manage_all} all present in compose/server/catalogue.go moduleOperationPermissions.
No UI/controls changed (test-only diff); n/a. Not verified: pg16/pg18 matrix beyond what the local test run exercises.

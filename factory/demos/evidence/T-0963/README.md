# T-0963 QA evidence (build 3db71c82e)
- reports-export-tests-v.txt, platform-export-run-tests-v.txt — go test -v, pg16+pg18, no skips except opt-in large timing
- large-export-300k.txt — 300k-row export: csv 139k rows/s peak heap 3 MB; xlsx 120k rows/s peak heap 5 MB
- independent/ — real CSV+XLSX downloaded from the export service, digest recomputed in Python (recompute.py) = run digest = About digest; HTTP 410/404/503 scratch tests (run in a git-archive copy, not in the tree)
- fitness-reports.txt, broader-tests.txt, build-vet-gofmt.txt

## Post-merge re-verification (build ff573ab4e, main merged, migration 0067)
- post-merge/build-vet-gofmt.txt — build, vet, gofmt clean
- post-merge/reports-export-tests-v.txt — reports/... and platform/export/... go test -v: all ok, 249 PASS lines, pg16+pg18, only opt-in large timing tests skipped
- post-merge/broader.txt — compose (incl. server), store, apihost, tools/gen, fitness/reports, fitness/modules, migrations ok; fitness-reports ok
- post-merge/http-scratch.txt — my HTTP scratch tests (git-archive copy): creator 200, non-creator 404 + download_denied/creator, expired 410 problem+json + download_denied/expired, no blob dir 503 with 0 export rows

# Re-QA T-0147 at 96d4a64 (third main merge) — qa-verifier
- No conflict markers in tree; working tree clean.
- AC1: `make gen-api` regenerates, tree stays clean (requa-96d4a64-ac1.log); `go run ./tools/gen/api -check` exit 0 on clean, exit 1 "schema.gen.d.ts: stale" after tamper (restored). ci-proof stale/missing proofs ok (make-ci-96d4a64.log:323-325).
- AC2/AC3: go test ./tools/gen/api/... ./internal/platform/apihost/... pass (requa-96d4a64-tests.log); ci-proof duplicate-component proof ok (log:326).
- AC4: fitness-stack F2 builds ok incl. tools/apitools across 5 platforms; fitness-stack passes in make ci.
- make -k ci (make-ci-96d4a64.log): only fitness-safeprim (15 FF-SP2/SP1 in internal/platform/store), fitness-corpus (FF-SP4 sql undeclared) and ci-proof "fitness-safeprim on repo itself" fail — all in internal/platform/store, not touched by this branch; pre-existing on main, tracked as T-0199 (P1). Everything contract-related passes; lint-api vacuum 97/100, 0 errors.
- No UI screens changed.

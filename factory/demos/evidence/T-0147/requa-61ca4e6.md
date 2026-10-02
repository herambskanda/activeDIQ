# T-0147 re-QA at 61ca4e6 (post main-merge)
- make ci: passed (incl. ci-proof: stale/missing/duplicate-component, rule-12 ESLint, FF-SP3). log: /tmp/qa147/make-ci.log
- go test tools/gen/api + apihost: ok
- make gen-api idempotent: tree clean after run
- gen-api-check on hand-edited schema.gen.d.ts: "stale", exit 1; restored
- fitness-stack green

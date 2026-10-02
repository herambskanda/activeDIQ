# T-0147 QA evidence — build 80bdeca
- AC1: make gen-api idempotent (clean tree). go run ./tools/gen/api -check rejected: hand-edited schema.gen.d.ts, models.gen.go, openapi.gen.json ("stale (run make gen-api)", exit 1) and a deleted problems.gen.go ("missing"). Clean tree passes. make ci wires gen-api-check + lint-api (tools/ci/ci.mk:7).
- AC2: fixture handlers.gen.go has Handlers + Bind(h) apihost.TagHandlers; TestGeneratedModelsImportOnlyWhatRule4Allows, TestBindRouteRows, TestFixtureGolden pass. Imports: stdlib, apitypes, shared, bound primitive packages (secret/filter).
- AC3: TestBundleRefusesACollision / ACrossModuleRef / ASharedRefIntoAModule pass; ci-proof 'one component declared in two files' ok.
- AC4: manifest.json extraGoModules tools/apitools cites ADR-0004; denylist has oapi-codegen, daveshanley, oasdiff, kin-openapi, pb33f; go list -deps ./cmd/... links none; fitness-stack ok (F1-F5).
- make ci: passed (make-ci.log). make lint-api: 0 errors, 7 warnings, 97/100.

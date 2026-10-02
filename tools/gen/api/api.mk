# API contract pipeline (T-0147, ADR-0004). Runbook: knowledge/development/runbooks/api-contract-workflow.md
# `make gen-api` rewrites every generated file from api/openapi/; `make gen-api-check` (part of `make ci`) fails
# when any generated file is stale or missing; `make lint-api` lints the bundled contract with vacuum.

.PHONY: gen-api gen-api-check lint-api

gen-api: web-install ## Regenerate the bundle, Go types/handlers/route rows and the TypeScript API types from api/openapi/
	go run ./tools/gen/api

gen-api-check: web-install ## Fail if any file generated from api/openapi/ is stale or missing (run `make gen-api`)
	go run ./tools/gen/api -check

lint-api: ## Lint the bundled OpenAPI document with the house vacuum ruleset (api/openapi/.vacuum.yaml)
	cd tools/apitools && go tool vacuum lint -r ../../api/openapi/.vacuum.yaml ../../internal/platform/apihost/spec/openapi.gen.json

# activeDIQ — root Makefile. Targets are added by the ticket that owns them
# (lab-*: T-0012; secrets-*: T-0013; ci/lint/test/fitness/build: T-0014; the dispatcher gate: T-0015;
# fitness-stack: T-0022; gen-api/lint-api: T-0147; fitness-tenancy: T-0036; fitness-domain-keys: T-0050).
.DEFAULT_GOAL := help
.PHONY: help
help:
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

include lab/lab.mk
include tools/ci/ci.mk
include tools/gen/api/api.mk
include tools/secrets/secrets.mk

# Playwright tooling (T-0011). Runbook: knowledge/development/runbooks/playwright-tooling.md
.PHONY: playwright-install playwright-test
playwright-install: ## Install the pinned Playwright and its Chromium (not committed)
	npm ci --prefix tools/playwright
	npm --prefix tools/playwright run install-browsers

playwright-test: ## Self-test of the screenshot/record scripts (needs `make playwright-install` once)
	npm ci --prefix tools/playwright
	npm --prefix tools/playwright test

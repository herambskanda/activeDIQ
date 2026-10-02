# CI entry point (T-0014). `make ci` is the one command that must pass before a merge.
# Standard: knowledge/development/standards/ci-gates.md · Runbook: knowledge/development/runbooks/ci-and-build.md
# Every gate below has a failing run proving it catches a violation: `make ci-proof` (part of `make ci`).

.PHONY: ci lint lint-go lint-web fmt test test-go test-web fitness fitness-stack fitness-tenancy fitness-proto fitness-safeprim build build-web web-install ci-proof

ci: lint test fitness build secrets-scan lab-test-unit ci-proof ## Everything a merge needs: lint, tests, fitness functions (incl. the ADR-0001 build matrix), web build, secret scan, gate proofs
	@echo "make ci: passed"

web-install: ## Install the pinned web dependencies from the lockfile (npm ci)
	npm ci --prefix web

lint: lint-go lint-web ## gofmt, go vet, go.mod tidiness; eslint, prettier, tsc

lint-go:
	tools/ci/gofmt-check.sh cmd internal tools
	go vet ./...
	go mod tidy -diff
	go mod verify

lint-web: web-install
	npm --prefix web run --silent typecheck
	npm --prefix web run --silent lint
	npm --prefix web run --silent format:check

fmt: ## Format Go and web sources in place
	gofmt -w cmd internal tools
	npm --prefix web run --silent format

test: test-go test-web ## Go and web unit tests

test-go:
	go test -count=1 ./...

test-web: web-install
	npm --prefix web run --silent test

fitness: fitness-stack fitness-tenancy fitness-proto fitness-safeprim ## Architecture fitness functions: fitness-modules (blueprint §2 import rules), fitness-stack (ADR-0001 F1-F5), fitness-tenancy (ADR-0002 T1-T5), fitness-proto (connector contract compiles and keeps its rules) and fitness-safeprim (safe-primitives FF-SP1-3)
	go run ./tools/fitness/modules

fitness-stack: ## ADR-0001: language zones, cgo-free cross-build, one stateful service, licence register, exceptions cite an ADR
	go run ./tools/fitness/stack -v

fitness-tenancy: ## ADR-0002 T1-T5 (and safe-primitives FF-SP7): migration 1, catalog, roles, isolation probes, static rules, against PostgreSQL 16 and 18 containers (needs Docker)
	go run ./tools/fitness/tenancy

fitness-proto: ## T-0064: every proto/ file compiles (pure Go, no protoc) and the connector contract keeps its structural rules P1-P7
	go run ./tools/fitness/proto proto

fitness-safeprim: ## T-0033: safe-primitives FF-SP1 import boundaries, FF-SP2 banned APIs and analyzers (dnstring, sqlconst, secretjson, tmplconst), FF-SP3 literal shapes; the web/ half of FF-SP3 runs in lint-web
	go run ./tools/fitness/safeprim

build: build-web ## Build the web assets; the CGO_ENABLED=0 Go cross-build of the ADR-0001 matrix runs in fitness-stack (F2)

build-web: web-install
	npm --prefix web run --silent build

ci-proof: web-install ## Prove each gate fails on a deliberate violation and passes on clean input
	tools/ci/proof.sh

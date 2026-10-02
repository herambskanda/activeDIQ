# CI entry point (T-0014). `make ci` is the one command that must pass before a merge.
# Standard: knowledge/development/standards/ci-gates.md · Runbook: knowledge/development/runbooks/ci-and-build.md
# Every gate below has a failing run proving it catches a violation: `make ci-proof` (part of `make ci`).

GO_TARGETS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/arm64

.PHONY: ci lint lint-go lint-web fmt test test-go test-web fitness build build-web web-install ci-proof

ci: lint test fitness build secrets-scan lab-test-unit ci-proof ## Everything a merge needs: lint, tests, fitness functions, build matrix, secret scan, gate proofs
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

fitness: ## Architecture fitness functions (fitness-modules: blueprint §2 import rules)
	go run ./tools/fitness/modules

build: build-web ## Cross-compile every binary with CGO_ENABLED=0 for the ADR-0001 build matrix, and build the web assets
	@set -e; for t in $(GO_TARGETS); do \
	  echo "go build $$t"; \
	  CGO_ENABLED=0 GOOS=$${t%/*} GOARCH=$${t#*/} go build -trimpath ./... ; \
	done

build-web: web-install
	npm --prefix web run --silent build

ci-proof: web-install ## Prove each gate fails on a deliberate violation and passes on clean input
	tools/ci/proof.sh

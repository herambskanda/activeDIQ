# CI entry point (T-0014). `make ci` is the one command that must pass before a merge.
# Standard: knowledge/development/standards/ci-gates.md · Runbook: knowledge/development/runbooks/ci-and-build.md
# Every gate below has a failing run proving it catches a violation: `make ci-proof` (part of `make ci`).

.PHONY: ci gen-proto gen-check lint lint-go lint-web fmt test test-go test-web fitness fitness-stack fitness-tenancy fitness-proto fitness-safeprim fitness-corpus fitness-oracles fitness-oracles-windows fitness-oracles-lab fitness-fuzz-nightly fitness-nightly build build-web web-install ci-proof

ci: lint gen-check test fitness build secrets-scan lab-test-unit ci-proof ## Everything a merge needs: lint, generated-code freshness, tests, fitness functions (incl. the ADR-0001 build matrix), web build, secret scan, gate proofs
	@echo "make ci: passed"

gen-proto: ## T-0157: regenerate the connector contract's Go code (internal/proto) from proto/ with the pinned pure-Go toolchain (no protoc, no buf)
	go run ./tools/gen/proto

gen-check: ## T-0157: fail if the generated Go code under internal/proto is stale, hand-edited or orphaned (regenerates in memory and compares)
	go run ./tools/gen/proto -check

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

fitness: fitness-stack fitness-tenancy fitness-proto fitness-safeprim fitness-corpus fitness-oracles ## Architecture fitness functions: fitness-modules (blueprint §2 import rules), fitness-stack (ADR-0001 F1-F5), fitness-tenancy (ADR-0002 T1-T5), fitness-proto (connector contract compiles and keeps its rules) fitness-safeprim (safe-primitives FF-SP1-3), fitness-corpus (FF-SP4, FF-SP5 declarations, FF-SP8) and fitness-oracles (FF-SP6 on Linux)
	go run ./tools/fitness/modules

fitness-stack: ## ADR-0001: language zones, cgo-free cross-build, one stateful service, licence register, exceptions cite an ADR
	go run ./tools/fitness/stack -v

fitness-tenancy: ## ADR-0002 T1-T5 (and safe-primitives FF-SP7): migration 1, catalog, roles, isolation probes, static rules, against PostgreSQL 16 and 18 containers (needs Docker)
	go run ./tools/fitness/tenancy

fitness-proto: ## T-0064: every proto/ file compiles (pure Go, no protoc) and the connector contract keeps its structural rules P1-P7
	go run ./tools/fitness/proto proto

fitness-safeprim: ## T-0033: safe-primitives FF-SP1 import boundaries, FF-SP2 banned APIs and analyzers (dnstring, sqlconst, secretjson, tmplconst), FF-SP3 literal shapes; the web/ half of FF-SP3 runs in lint-web
	go run ./tools/fitness/safeprim

SAFEPRIM_REPORTS ?= .safeprim-reports

fitness-corpus: ## T-0034: safe-primitives FF-SP4 corpus gate (every unit >= 10 hostile records, no skipped or vanished record, every implementation declared and run), FF-SP5 fuzz targets declared and seeded, FF-SP8 constant argv; keeps the run reports in $(SAFEPRIM_REPORTS)
	go run ./tools/fitness/corpus -report-dir $(SAFEPRIM_REPORTS)

fitness-oracles: fitness-corpus ## T-0034: safe-primitives FF-SP6 on Linux: pslit output through PowerShell's own parser (pwsh, or the pinned container; needs Docker), P1 filters through go-ldap's parser. Checks an implementation's actual outputs once one has reported, the corpus's expected values before
	go run ./tools/fitness/oracles pslit -source auto -reports $(SAFEPRIM_REPORTS) -if-present
	go run ./tools/fitness/oracles ldapfilter -source auto -reports $(SAFEPRIM_REPORTS) -if-present

fitness-oracles-windows: ## T-0034: FF-SP6 on the Windows runner/lab (nightly): Windows PowerShell 5.1 parses pslit output; SID and GUID text/bytes through the Win32/.NET APIs. Run from a Windows host with Go and PowerShell 5.1; fails if the oracle cannot run
	go run ./tools/fitness/corpus -report-dir $(SAFEPRIM_REPORTS)
	go run ./tools/fitness/oracles pslit -engine powershell -source auto -reports $(SAFEPRIM_REPORTS) -if-present
	go run ./tools/fitness/oracles winids -unit attr.sid -engine powershell -source auto -reports $(SAFEPRIM_REPORTS) -if-present -verify-as windows -out $(SAFEPRIM_REPORTS)/windows-sid.json
	go run ./tools/fitness/oracles winids -unit attr.guid -engine powershell -source auto -reports $(SAFEPRIM_REPORTS) -if-present -verify-as windows -out $(SAFEPRIM_REPORTS)/windows-guid.json

fitness-oracles-lab: lab-up ## T-0034: FF-SP6 Samba lab row for P1 (nightly): the DC must accept every rendered filter; passing records get "verified": samba in the corpus (commit the change)
	go run ./tools/fitness/corpus -report-dir $(SAFEPRIM_REPORTS)
	go run ./tools/fitness/oracles lab -source auto -reports $(SAFEPRIM_REPORTS) -if-present -verify-as samba -out $(SAFEPRIM_REPORTS)/samba.json
	@test ! -f $(SAFEPRIM_REPORTS)/samba.json || go run ./tools/fitness/corpus -set-verified $(SAFEPRIM_REPORTS)/samba.json

fitness-fuzz-nightly: ## T-0034: FF-SP5 nightly: every declared fuzz target for 10 minutes (go test -fuzz); 4 at a time; log in $(SAFEPRIM_REPORTS)/fuzz.log. A crasher is written under testdata/fuzz/ of its package: commit it
	@mkdir -p $(SAFEPRIM_REPORTS)
	go run ./tools/fitness/corpus -fuzz -nightly -parallel 4 -log $(SAFEPRIM_REPORTS)/fuzz.log

fitness-nightly: fitness-fuzz-nightly fitness-oracles-lab ## T-0034: the nightly job: FF-SP5 long fuzz, FF-SP6 Samba lab; the Windows rows are fitness-oracles-windows on the Windows lab (runbook safe-primitives-fitness.md)

build: build-web ## Build the web assets; the CGO_ENABLED=0 Go cross-build of the ADR-0001 matrix runs in fitness-stack (F2)

build-web: web-install
	npm --prefix web run --silent build

ci-proof: web-install ## Prove each gate fails on a deliberate violation and passes on clean input
	tools/ci/proof.sh

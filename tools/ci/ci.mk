# CI entry point (T-0014). `make ci` is the one command that must pass before a merge.
# Standard: knowledge/development/standards/ci-gates.md · Runbook: knowledge/development/runbooks/ci-and-build.md
# Every gate below has a failing run proving it catches a violation: `make ci-proof` (part of `make ci`).

.PHONY: fitness-sso fitness-reports fitness-fleet-ca-scope fitness-objectid fitness-grantbootstrap ci gen-proto gen-check lint lint-go lint-web fmt test test-go test-web fitness fitness-stack fitness-tenancy fitness-domain-keys fitness-profiles fitness-proto fitness-safeprim fitness-corpus fitness-oracles fitness-api fitness-oracles-windows fitness-oracles-lab fitness-fuzz-nightly fitness-nightly fuzz-saml build build-web web-install ci-proof fitness-operation fitness-audit fitness-disclosure fitness-packaging fitness-host fitness-agent-host fitness-built-msi fitness-update fitness-update-offline fitness-keys fitness-fleet-ca-scope workflows-check

ci: lint gen-check gen-api-check lint-api test fitness workflows-check build secrets-scan vuln-scan fuzz-saml lab-test-unit lab-test-windows-unit ci-proof ## Everything a merge needs: lint, generated-code freshness (connector proto and the API contract), API lint, tests, fitness functions (incl. the ADR-0001 build matrix), web build, secret scan, dependency vulnerability scan, gate proofs
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

test-go: web-install ## Go tests; package parallelism bounded (-p 3) because PG-backed packages each start an embedded PostgreSQL and starve under full parallelism (T-0550)
	go test -count=1 -p 3 -timeout 30m ./...

test-web: web-install
	npm --prefix web run --silent test

fitness: fitness-sso fitness-stack fitness-tenancy fitness-domain-keys fitness-profiles fitness-proto fitness-safeprim fitness-corpus fitness-oracles fitness-api fitness-operation fitness-audit fitness-objectid fitness-grantbootstrap fitness-disclosure fitness-packaging fitness-host fitness-agent-host fitness-built-msi fitness-update fitness-update-offline fitness-keys fitness-fleet-ca-scope fitness-reports ## Architecture fitness-sso (T-0211, console-sso.md section 13: FIT-SSO-1 SAML libraries imported only under authn/sso/saml, go-oidc and go-jose only under authn/sso/oidc, no encoding/xml under platform/authn outside sso/saml, go.mod floors goxmldsig v1.6.0 and gosaml2 v0.12.0; FIT-SSO-2 every OIDC-n/SAML-n check cited by a corpus record, a record of every class per protocol, every record a passing TestCorpus subtest, for the OIDC and the SAML corpus), fitness-reports (T-0873, ADR-0010 and reports contract §9: RP2 ReadScope.Terms/.Token and NewReadScope have one renderer and one producer, RP3 only reports/run calls reportsql.Compile/CompileCount/Exec, RP7 library/LOCK hashes and append-only history, and the bound tests RP4-RP6 and RP8-RP11 run here, a missing or skipped one fails, RP11 once per report.Dataset; RP1 is the sqlconst amendment inside fitness-safeprim; parts whose code has not landed are listed pending), fitness-grantbootstrap (T-0808: GrantBootstrap referenced only by the first-account CLI), fitness-fleet-ca-scope (T-0738, ADR-0008 items 1-6: only SignServerLeaf uses the server CA key and it takes no key/CSR, the server CA is never in the client pool, dial roots are pinned certificates only, fleet_server_ca has no tenant_id, the presented chain is [leaf, server CA]; parts whose code has not landed are listed pending), fitness-keys (T-0525 keys-custody-design FF-KEY-1..6: tenant_keys schema guards, single owner of keys calls, KEK config only in the composition root, bound behaviour tests; parts whose code has not landed are listed pending; needs Docker), fitness-built-msi (T-0697, ADR-0006 A1 on the built MSI: opens dist/*.msi with msidump and judges ServiceInstall, MsiServiceConfig, CustomAction, Binary, MsiLockPermissionsEx, Registry; inactive until a build produces one), fitness-update (T-0139 TM-F-UPDATE: bad updates refused through the online courier and the offline bundle; the offline one again under docker --network none), fitness-agent-host (T-0554, ADR-0006 A1/A4 and ADR-0007 P1-P8, TM-F-AGENTCMD CI half: agent proto lints R1/R2/R5, module capability scans R3/R4, installer identity, agent import closure, P1-P8 and the F1 policy fuzz), fitness-host (T-0136 TM-F-HOST: boots the real server in a container and judges identity, file modes, TLS-only listener, default credentials, dumps and remote-DSN TLS; needs Docker), fitness functions: fitness-packaging (T-0104 API TLS directory ACL/mode in packaging/), fitness-disclosure (T-0258 SECURITY.md and RFC 9116 security.txt intake, Expires renewal; T-0260 advisory and CVE record carry one CVE ID and one CVSS on the fix day), fitness-modules (blueprint §2 import rules), fitness-stack (ADR-0001 F1-F5), fitness-tenancy (ADR-0002 T1-T5), fitness-domain-keys (domain-model X3-X5), fitness-profiles (ADR-0002 P1, P4 logs/metrics/caches, P7, U1, U2 and the activation table), fitness-proto (connector contract compiles and keeps its rules) fitness-safeprim (safe-primitives FF-SP1-3), fitness-corpus (FF-SP4, FF-SP5 declarations, FF-SP8) fitness-oracles (FF-SP6 on Linux) and fitness-api (ADR-0004 A1, A3, A4, A5, A6, A7, A8, A10, A11, A12, A13, A14; prints every inactive check and inactive part)
	go run ./tools/fitness/modules

fitness-keys: ## T-0525, keys-custody-design §7: FF-KEY-1 schema (tenant_keys RLS/index/trigger/grants, installation_kek grants once it exists) on PostgreSQL 16 and 18 containers (needs Docker), FF-KEY-2 single owner of tenant_keys and DEK/wrap calls, FF-KEY-3 KEK config only in compose/server, FF-KEY-5 insert sites and Rotate/ShredTenant/OpenMaintenance callers, and the bound tests of FF-KEY-1/3/4/5/6 (missing, failed or skipped fails); lists every part still pending
	go run ./tools/fitness/keycustody

fitness-fleet-ca-scope: ## T-0738, ADR-0008 fitness function: FCS-1..6 static rules on the tree and migrations, plus the bound tests of each landed part (a missing, failed or skipped bound test fails); lists every part whose code has not landed as pending, which is not a pass
	go run ./tools/fitness/fleetca

REPORTS_LOCK_BASE ?= $(shell git rev-parse --verify -q main >/dev/null && echo main || echo origin/main)

fitness-reports: ## T-0873, ADR-0010 / reports contract §9: RP2 (ReadScope.Terms/.Token only in authz and reportsql, NewReadScope only in rbac and authz), RP3 (only reports/run calls reportsql.Compile/CompileCount/Exec), RP7 (library/LOCK SHA-256s, append-only against $(REPORTS_LOCK_BASE)), and the bound tests RP4-RP6, RP8-RP11 (a missing, failed or skipped one fails; RP11 needs one subtest per report.Dataset); lists every part whose code has not landed as pending, which is not a pass
	go run ./tools/fitness/reports -lock-base $(REPORTS_LOCK_BASE)

fitness-sso: ## T-0211, console-sso.md §13: FIT-SSO-1 import fence and go.mod floors for the SAML and JOSE libraries; FIT-SSO-2 corpus coverage of the §4/§5 checks and one passing TestCorpus subtest per record (for both protocols)
	go run ./tools/fitness/sso

fitness-grantbootstrap: ## T-0808: rbac.Grants.GrantBootstrap (privilege-check bypass for the install-time CLI) is referenced only by internal/compose/server/localaccount.go, its definition and tests
	go run ./tools/fitness/grantbootstrap

fitness-objectid: ## T-0180: no conversion to authz.ObjectID outside internal/platform/authz (type-checked, tests included); use ObjectIDFromOctets or ParseObjectID
	go run ./tools/fitness/objectid

fitness-stack: ## ADR-0001: language zones, cgo-free cross-build, one stateful service, licence register, exceptions cite an ADR
	go run ./tools/fitness/stack -v

fitness-tenancy: ## ADR-0002 T1-T5 (and safe-primitives FF-SP7): migration 1, catalog, roles, isolation probes, static rules, against PostgreSQL 16 and 18 containers (needs Docker)
	go run ./tools/fitness/tenancy

fitness-domain-keys: ## T-0050: domain-model X3 (no directory table keyed or joined on a DN, SID, name), X4 (no column for a SecretAttrs attribute outside the declared sealed columns), X5 (append-only tables: no UPDATE, DELETE only by the retention role, no state column; DM-25.I6 property test present), and every table declared through tablekind.Declare; against PostgreSQL 16 and 18 containers (needs Docker)
	go run ./tools/fitness/domainkeys

fitness-profiles: ## T-0038, T-0135, ADR-0002: P1 composition boundary, P4 tenant ID on every log line, metric and cache key (TM-TB17-T8), P7 branch policy, U1 UEM independence, U2 extractable platform root, and the activation table (P2-P6, U3, U4 become mandatory the moment their subject lands)
	go run ./tools/fitness/profiles

fitness-proto: ## T-0064, T-0144: every proto/ file compiles (pure Go, no protoc) and the connector contract keeps its structural rules P1-P8, fleet F1-F11 and the agent contracts (skenzeriq.agent.v1, activediq.addc.v1, activediq.fileserver.v1) AG1-AG8 (closed RPC list, denied verbs, unary, no free-form fields, policy data only; TM-F-AGENTCMD contract half)
	go run ./tools/fitness/proto proto

fitness-safeprim: ## T-0033: safe-primitives FF-SP1 import boundaries, FF-SP2 banned APIs and analyzers (dnstring, sqlconst, secretjson, tmplconst, constdisp), FF-SP3 literal shapes; the web/ half of FF-SP3 runs in lint-web
	go run ./tools/fitness/safeprim

SAFEPRIM_REPORTS ?= .safeprim-reports

fitness-corpus: ## T-0034: safe-primitives FF-SP4 corpus gate (every unit >= 10 hostile records, no skipped or vanished record, every implementation declared and run), FF-SP5 fuzz targets declared and seeded, FF-SP8 constant argv; keeps the run reports in $(SAFEPRIM_REPORTS)
	go run ./tools/fitness/corpus -report-dir $(SAFEPRIM_REPORTS)

fitness-oracles: fitness-corpus ## T-0034: safe-primitives FF-SP6 on Linux: pslit output through PowerShell's own parser (pwsh, or the pinned container; needs Docker), P1 filters through go-ldap's parser. Checks an implementation's actual outputs once one has reported, the corpus's expected values before
	go run ./tools/fitness/oracles pslit -source auto -reports $(SAFEPRIM_REPORTS) -if-present
	go run ./tools/fitness/oracles ldapfilter -source auto -reports $(SAFEPRIM_REPORTS) -if-present

fitness-api: web-install ## T-0011, T-0017, T-0018, ADR-0004: A1 layout, A3 permission (document half), A4 route set and HTTP probe per profile (apihost.Build), A5 generated client (static), A6 generated server (source), A7 strict JSON (static, type closure, corpus, ajv cross-check from the pinned web deps), A8 secret linter, A10 versioning (oasdiff against main), A11 problems, A12 limits, A13 policy hygiene (host bindings from the apihost table) and A14 responses conform (apitest harness), with a self-test that fails when a check finds nothing where the tree has something. Prints one line per check A1-A14 (active, or inactive (<missing input>)); exits 0 with inactive checks, and the ADR is not accepted while any is
	go run ./tools/fitness/api

fitness-operation: ## T-0013: ADR-0005 O9, the kernel import DAG of rule 13: parses the dag block of the ADR itself and fails on any import among the listed platform packages it does not allow; lists each package as existing or pending plus O1 step escape (syntactic and the type-aware stepescape analyzer), O2, the O4 SQL half and O8 (T-0393: runs the tests named in internal/platform/operation/o8_manifest_test.go and fails when one is missing, failed or skipped; needs Docker; -o8-lab adds the Samba arm) (O3, O5-O7 land with the code they inspect)
	go run ./tools/fitness/operation

fitness-audit: ## T-0133, ADR-0005 A1-A9 and TM-F-AUDIT: A1 catalogue of the audit tables and audit_head's genesis trigger against PostgreSQL 16 and 18 containers (needs Docker); A2, A3, A5, A6, A9 run the bound audit-chain, verifier and retention tests and fail when one is missing, failed or skipped; A4, A7, A8 are listed as pending, not as passes
	go run ./tools/fitness/audit

fitness-packaging: ## T-0104, TM-TB16-T3: the Windows ACL script (Administrators + service identity only, inheritance off), the linux-oci prepare script (run for real: non-root uid, mode 0700, refuses uid 0 and symlinks) and the Compose fragment (numeric non-root user, bind mount); the Windows lab test is packaging/windows/Test-ApiTlsDirAcl.ps1
	go run ./tools/fitness/packaging

fitness-host: ## T-0136, TM-F-HOST: build cmd/server into packaging/linux-oci/Dockerfile.server, boot it against PostgreSQL 16 and judge the named cases (needs Docker); the Windows half is packaging/windows/Get-HostObservation.ps1 judged by `go run ./tools/fitness/host evaluate`. Known gaps are listed in tools/fitness/host/known-gaps.json
	go run ./tools/fitness/host oci

BUILT_MSI ?= dist/*.msi

fitness-built-msi: ## T-0697: ADR-0006 A1 on the built artefact: every MSI matching $(BUILT_MSI) is dumped with msidump (msitools) and its service account (NT SERVICE\\activeDIQAgent), restricted SID, pinned privileges, custom actions, binaries, DACLs and HKLM\\SYSTEM writes are judged; prints inactive when none exists. The release job passes -require once the packaging ticket builds the MSI
	go run ./tools/fitness/builtmsi -glob '$(BUILT_MSI)'

AGENT_POLICY_FUZZ_TIME ?= 20s

fitness-agent-host: ## T-0554: ADR-0006 A1 (installer source: NT SERVICE\\activeDIQAgent, restricted SID, pinned privileges, no LocalSystem), A4 (agent closure has no LDAP/SMB/RPC/Kerberos/SSPI client), ADR-0007 P1-P8 tests must exist and pass, contract R1-R5 (proto lints, module capability and listener scans) and F1 (out-of-bounds policy rejected, then FuzzF1 for $(AGENT_POLICY_FUZZ_TIME)); prints inactive for a check whose subject does not exist yet
	go run ./tools/fitness/agenthost
	tools/ci/fuzz-target.sh internal/platform/agentpolicy FuzzF1DecodeOnlyAcceptsInBounds $(AGENT_POLICY_FUZZ_TIME)

fitness-update: ## T-0139 TM-F-UPDATE (threat model s10, ENH-07 AC-1..AC-8): tampered artefact, tampered manifest, overlong artefact, revoked key, rollback (incl. after a database restore), freeze, clock rewind, under-threshold root rotation, server-signed artefact and withdrawn release are each refused with their reason through both couriers, nothing lands outside quarantine, a good release and an old-threshold-signed root rotation are accepted
	go run ./tools/fitness/update

fitness-update-offline: ## T-0139: the same matrix through the offline bundle courier inside a container with --network none (needs Docker)
	tools/fitness/update/offline.sh

fitness-disclosure: ## T-0258: SECURITY.md and .well-known/security.txt (RFC 9116): Contact named in SECURITY.md, one RFC 3339 Expires under a year ahead, fails 30 days before it so the file is renewed, Policy points at SECURITY.md; T-0260: advisory template present, every security/advisories/<CVE-ID>/ advisory.md and record.json agree on CVE ID and one CVSS v3.1 vector/score, published on the fix day, target_met honest
	go run ./tools/fitness/disclosure

workflows-check: ## T-0261: .github/workflows has no continue-on-error, every action is pinned to a commit SHA, release.yml verifies its signatures; the release tools' tests run in `make test`, their failing cases in `make ci-proof`
	tools/ci/workflows-check.sh

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

SAML_FUZZ_TIME ?= 60s

fuzz-saml: ## T-0490: FuzzSAMLComplete for 60s (go test -fuzz): any forged Verified tuple or replayed assertion fails the build; a crasher lands in internal/platform/authn/sso/saml/testdata/fuzz/ (commit it)
	tools/ci/fuzz-target.sh internal/platform/authn/sso/saml FuzzSAMLComplete $(SAML_FUZZ_TIME)

build: build-web ## Build the web assets; the CGO_ENABLED=0 Go cross-build of the ADR-0001 matrix runs in fitness-stack (F2)

build-web: web-install
	npm --prefix web run --silent build

.PHONY: vuln-scan
vuln-scan: ## T-0010: govulncheck (pinned in tools/vulntools) over ./...; fails on a called vulnerability not in tools/ci/vuln-allow.json, on an expired or stale allow entry, and when the vulnerability database cannot be read (override: GOVULNDB=<mirror>)
	go run ./tools/vulnscan

ci-proof: web-install ## Prove each gate fails on a deliberate violation and passes on clean input
	tools/ci/proof.sh

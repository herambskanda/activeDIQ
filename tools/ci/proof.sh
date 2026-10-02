#!/usr/bin/env bash
# Proof that the CI gates fail when they should (factory rule: a check without a failing run is not
# a check). Each case builds a deliberate violation and requires the real gate to exit non-zero,
# and requires the same gate to pass on the clean counterpart. Run by `make ci-proof` (part of
# `make ci`). Needs the web dependencies (`make web-install`).
set -uo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0

# must_fail <name> <command...>: the gate has to reject the violation.
must_fail() {
  local name=$1; shift
  if "$@" >"$tmp/out" 2>&1; then
    echo "PROOF FAILED: $name — the gate accepted a violation"; sed 's/^/    /' "$tmp/out"; fails=$((fails + 1))
  else
    echo "ok: $name is rejected"
  fi
}
# must_fail_with <name> <pattern> <command...>: as must_fail, and the output must match pattern, so a
# gate that fails for the wrong reason (a broken config, a missing tool) is not counted as a proof.
must_fail_with() {
  local name=$1 pattern=$2; shift 2
  if "$@" >"$tmp/out" 2>&1; then
    echo "PROOF FAILED: $name — the gate accepted a violation"; sed 's/^/    /' "$tmp/out"; fails=$((fails + 1))
  elif ! grep -qE "$pattern" "$tmp/out"; then
    echo "PROOF FAILED: $name — failed, but not for the expected reason ($pattern)"; sed 's/^/    /' "$tmp/out"; fails=$((fails + 1))
  else
    echo "ok: $name is rejected"
  fi
}
# must_pass <name> <command...>: the gate has to accept clean input.
must_pass() {
  local name=$1; shift
  if "$@" >"$tmp/out" 2>&1; then
    echo "ok: $name accepts clean input"
  else
    echo "PROOF FAILED: $name — the gate rejected clean input"; sed 's/^/    /' "$tmp/out"; fails=$((fails + 1))
  fi
}

# in_web <command...>: run a web tool from web/ using its pinned local install.
in_web() { (cd "$root/web" && npx --no-install "$@"); }

# --- gofmt ------------------------------------------------------------------------------------
mkdir -p "$tmp/fmt"
printf 'package x\nfunc   F( ) {  }\n' >"$tmp/fmt/bad.go"
must_fail_with "gofmt-check on an unformatted file" "not formatted" tools/ci/gofmt-check.sh "$tmp/fmt"
printf 'package x\n\nfunc F() {}\n' >"$tmp/fmt/bad.go"
must_pass "gofmt-check" tools/ci/gofmt-check.sh "$tmp/fmt"

# --- go vet -----------------------------------------------------------------------------------
mkdir -p "$tmp/vet"
printf 'module vet.test\n\ngo 1.27.0\n' >"$tmp/vet/go.mod"
printf 'package x\n\nimport "fmt"\n\nfunc F() string { return fmt.Sprintf("%%d", "not a number") }\n' >"$tmp/vet/x.go"
must_fail_with "go vet on a bad format verb" "Sprintf format %d" bash -c "cd '$tmp/vet' && go vet ./..."
printf 'package x\n\nimport "fmt"\n\nfunc F() string { return fmt.Sprintf("%%d", 1) }\n' >"$tmp/vet/x.go"
must_pass "go vet" bash -c "cd '$tmp/vet' && go vet ./..."

# --- go test ----------------------------------------------------------------------------------
mkdir -p "$tmp/gotest"
printf 'module gotest.test\n\ngo 1.27.0\n' >"$tmp/gotest/go.mod"
printf 'package x\n\nimport "testing"\n\nfunc TestFails(t *testing.T) { t.Fatal("deliberate") }\n' >"$tmp/gotest/x_test.go"
must_fail_with "go test on a failing test" "deliberate" bash -c "cd '$tmp/gotest' && go test ./..."
printf 'package x\n\nimport "testing"\n\nfunc TestPasses(t *testing.T) {}\n' >"$tmp/gotest/x_test.go"
must_pass "go test" bash -c "cd '$tmp/gotest' && go test ./..."

# --- fitness-modules (the CLI, end to end) ----------------------------------------------------
fit="$tmp/fit"
mkdir -p "$fit/internal/platform/kernel" "$fit/internal/directory"
printf 'module fit.test\n\ngo 1.27.0\n' >"$fit/go.mod"
printf 'package directory\n' >"$fit/internal/directory/d.go"
printf 'package kernel\n\nimport _ "fit.test/internal/directory"\n' >"$fit/internal/platform/kernel/k.go"
must_fail_with "fitness-modules on a platform package importing the directory domain" "kernel imports nothing above it" go run ./tools/fitness/modules -root "$fit"
printf 'package kernel\n' >"$fit/internal/platform/kernel/k.go"
must_pass "fitness-modules" go run ./tools/fitness/modules -root "$fit"

# --- fitness-proto (the connector contract), the real CLI on throw-away trees ------------------
pr="$tmp/proto"
mkdir -p "$pr"
printf 'syntax = "proto3";\npackage t.v1;\nenum Operation { OPERATION_UNSPECIFIED = 0; OPERATION_GET = 1; OPERATION_APPLY = 100; OPERATION_READ_SECRET = 101; OPERATION_VERIFY_USER = 102; }\nmessage GetRequest { string dn = 1; }\nmessage GetResponse {}\nservice S { rpc Get(GetRequest) returns (GetResponse); }\n' >"$pr/t.proto"
must_fail_with "fitness-proto on a request carrying a DN string" "\\[P2\\]" go run ./tools/fitness/proto "$pr"
printf 'syntax = "proto3";\npackage t.v1;\nmessage {\n' >"$pr/t.proto"
must_fail_with "fitness-proto on a file that does not compile" "\\[P1\\]" go run ./tools/fitness/proto "$pr"
printf 'syntax = "proto3";\npackage t.v1;\nenum Operation { OPERATION_UNSPECIFIED = 0; OPERATION_GET = 1; OPERATION_APPLY = 100; OPERATION_READ_SECRET = 101; OPERATION_VERIFY_USER = 102; }\nmessage Guid { bytes value = 1; }\nmessage GetRequest { Guid guid = 1; }\nmessage GetResponse {}\nservice S { rpc Get(GetRequest) returns (GetResponse); }\n' >"$pr/t.proto"
must_pass "fitness-proto" go run ./tools/fitness/proto "$pr"

# --- fitness-stack (ADR-0001 F1-F5), the real CLI on throw-away trees --------------------------
# One violation per rule, each rejected with the rule's own message; the same tree passes when clean.
# The banned build flag is assembled from parts so this file does not trip F2's text scan.
stackbin="$tmp/stack"
go build -o "$stackbin" ./tools/fitness/stack
fs="$tmp/fs"
fresh_stack_tree() {
  rm -rf "$fs"
  mkdir -p "$fs/cmd/server" "$fs/knowledge/development/decisions" "$fs/knowledge/business/licensing" "$fs/garage/redis" "$fs/garage/gpl"
  printf 'module fs.test\n\ngo 1.27.0\n' >"$fs/go.mod"
  printf 'package main\n\nfunc main() {}\n' >"$fs/cmd/server/main.go"
  printf -- '---\nstatus: ratified\n---\n' >"$fs/knowledge/development/decisions/0001-stack.md"
  printf -- '---\nstatus: proposed\n---\n' >"$fs/knowledge/development/decisions/0009-draft.md"
  printf '| Project | Licence | Use | Mode | Ships | Status |\n| --- | --- | --- | --- | --- | --- |\n| Fine (`example.com/fine`) | MIT | t | Embedded | Yes | **Clear** |\n| Gpl (`example.com/gpl`) | GPL | t | Embedded | Yes | **Clear** |\n| Redis (`github.com/redis/go-redis/v9`) | BSD | t | Embedded | Yes | **Clear** |\n' >"$fs/knowledge/business/licensing/register.md"
  printf 'module github.com/redis/go-redis/v9\n\ngo 1.27.0\n' >"$fs/garage/redis/go.mod"
  printf 'package redis\n' >"$fs/garage/redis/r.go"
  printf 'module example.com/gpl\n\ngo 1.27.0\n' >"$fs/garage/gpl/go.mod"
  printf 'package gpl\n' >"$fs/garage/gpl/g.go"
  printf '                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n' >"$fs/garage/gpl/LICENSE"
  cat >"$fs/manifest.json" <<'JSON'
{
  "decisionsDir": "knowledge/development/decisions",
  "licenceRegister": "knowledge/business/licensing/register.md",
  "exemptZones": ["knowledge", "garage"],
  "buildMatrix": ["linux/amd64"],
  "testTags": ["lab"],
  "toolchainTags": ["race"],
  "languageZones": {
    "go": {"anywhere": true, "deny": ["web", "native"]},
    "rust": {"allow": ["native"]},
    "python": {"allow": ["lab", "tools"]},
    "typescript": {"allow": ["web"]},
    "javascript": {"allow": ["web"]}
  },
  "bannedLanguages": ["java"],
  "binaries": [{"name": "server", "tier": "S", "package": "./cmd/server"}],
  "denylist": [{"prefix": "github.com/redis/go-redis", "reason": "Redis client: a second stateful service"}],
  "exceptions": {"platformAdapters": []}
}
JSON
}
stack() { "$stackbin" -root "$fs" -manifest manifest.json "$@"; }

fresh_stack_tree
must_pass "fitness-stack (all of F1-F5, with the cross-build)" stack

fresh_stack_tree; mkdir -p "$fs/svc"; : >"$fs/svc/lib.rs"
must_fail_with "F1 on a .rs file outside native/" 'svc/lib.rs: F1 \(ADR-0001 rule 1\)' stack -checks F1
fresh_stack_tree; mkdir -p "$fs/svc"; : >"$fs/svc/gen.py"
must_fail_with "F1 on a .py file outside lab/ and tools/" 'svc/gen.py: F1 \(ADR-0001 rule 1\)' stack -checks F1
fresh_stack_tree; mkdir -p "$fs/svc"; : >"$fs/svc/app.mjs"
must_fail_with "F1 on a .mjs file outside web/" 'svc/app.mjs: F1 \(ADR-0001 rule 1\)' stack -checks F1

fresh_stack_tree; mkdir -p "$fs/internal/x"
printf '//go:build ignore\n\npackage x\n\nimport "C"\n' >"$fs/internal/x/x.go"
must_fail_with "F2 on import \"C\" under //go:build ignore" 'internal/x/x.go: F2 \(ADR-0001 rule 2\)' stack -checks F2 -skip-build
fresh_stack_tree; mkdir -p "$fs/tools"
printf 'go build %s ./cmd/server\n' "-build""mode=c-shared" >"$fs/tools/dll.sh"
must_fail_with "F2 on a c-shared build flag in a script" 'tools/dll.sh:1: F2 \(ADR-0001 rule 2\)' stack -checks F2 -skip-build
fresh_stack_tree; mkdir -p "$fs/internal/x"
printf 'package x\n' >"$fs/internal/x/x_windows.go"
must_fail_with "F2 on a GOOS-suffixed file outside a platform adapter" 'x_windows.go: F2 \(ADR-0001 rule 2\)' stack -checks F2 -skip-build
fresh_stack_tree; mkdir -p "$fs/internal/c"
printf 'package c\n\n// int one(void) { return 1; }\nimport "C"\n\nfunc One() int { return int(C.one()) }\n' >"$fs/internal/c/c.go"
printf 'package main\n\nimport _ "fs.test/internal/c"\n\nfunc main() {}\n' >"$fs/cmd/server/main.go"
must_fail_with "F2 on a package that needs cgo (CGO_ENABLED=0 build)" 'CGO_ENABLED=0 go build \./\.\.\. fails for linux/amd64' stack -checks F2

fresh_stack_tree
printf 'module fs.test\n\ngo 1.27.0\n\nrequire github.com/redis/go-redis/v9 v9.0.0\n\nreplace github.com/redis/go-redis/v9 => ./garage/redis\n' >"$fs/go.mod"
printf 'package main\n\nimport _ "github.com/redis/go-redis/v9"\n\nfunc main() {}\n' >"$fs/cmd/server/main.go"
must_fail_with "F3 on a server linking a denylisted Redis client" 'cmd/server: F3 \(ADR-0001 rule 3\): binary "server" .* links github.com/redis/go-redis/v9' stack -checks F3

fresh_stack_tree
printf 'module fs.test\n\ngo 1.27.0\n\nrequire example.com/unregistered v1.0.0\n\nreplace example.com/unregistered => ./garage/redis\n' >"$fs/go.mod"
must_fail_with "F4 on a direct dependency with no register row" 'go.mod: F4 \(ADR-0001 rule 6\): direct dependency example.com/unregistered' stack -checks F4
fresh_stack_tree
printf 'module fs.test\n\ngo 1.27.0\n\nrequire example.com/gpl v1.0.0\n\nreplace example.com/gpl => ./garage/gpl\n' >"$fs/go.mod"
printf 'package main\n\nimport _ "example.com/gpl"\n\nfunc main() {}\n' >"$fs/cmd/server/main.go"
must_fail_with "F4 on a GPL module in a shipped binary" 'F4 \(ADR-0001 rule 6\): shipped binary links example.com/gpl .* GPL' stack -checks F4

fresh_stack_tree; mkdir -p "$fs/internal/winsvc"
printf 'package winsvc\n' >"$fs/internal/winsvc/s.go"
sed -i.bak 's#"platformAdapters": \[\]#"platformAdapters": [{"path": "internal/winsvc", "adr": "0009-draft.md"}]#' "$fs/manifest.json"
must_fail_with "F5 on an exception that cites a proposed ADR" 'manifest.json: F5 \(ADR-0001 rule 5\).*status is "proposed"' stack -checks F5
sed -i.bak 's#0009-draft.md#0001-stack.md#' "$fs/manifest.json"
must_pass "F5 once the exception cites a ratified ADR" stack -checks F5

# --- fitness-tenancy (ADR-0002 T1-T5), the real CLI on throw-away trees ---------------------------
# The per-rule proofs are the tool's own tests (go test ./tools/fitness/tenancy/...); this is the
# end-to-end run: the CLI exits non-zero naming the table and the rule, and zero on the clean tree.
tenbin="$tmp/tenancy"
go build -o "$tenbin" ./tools/fitness/tenancy
tn="$tmp/tn"; mkdir -p "$tn/migrations" "$tn/internal/modules/m"
printf 'module tn.test\n\ngo 1.27.0\n' >"$tn/go.mod"
cp tools/fitness/tenancy/testdata/base/0001_tenant_tenants.sql "$tn/migrations/"
printf '{"globalTables": [{"table": "public.tenants", "reason": "the tenant directory", "owner": "internal/platform/tenant"}]}\n' >"$tn/registry.json"
mkdir -p "$tn/internal/platform/tenant"; printf 'package tenant\n' >"$tn/internal/platform/tenant/t.go"
tenancy() { "$tenbin" -root "$tn" -registry registry.json -pg 18 "$@"; }
cp tools/fitness/tenancy/testdata/bad/missing_force.sql "$tn/migrations/0002_app_items.sql"
must_fail_with "fitness-tenancy on a tenant table without FORCE ROW LEVEL SECURITY" 'T2 public.items \[rls-force\]' tenancy
cp tools/fitness/tenancy/testdata/good/0002_app_items.sql "$tn/migrations/0002_app_items.sql"
must_pass "fitness-tenancy" tenancy
printf 'package m\n\nconst q = "SELECT set_config(%s, %s, false)"\n' "'app.tenant_id'" "'x'" >"$tn/internal/modules/m/m.go"
must_fail_with "fitness-tenancy on set_config text outside the tenancy package" 'T5 internal/modules/m/m.go:3 \[set-config-text\]' tenancy -checks T5

# --- go mod tidy ------------------------------------------------------------------------------
mkdir -p "$tmp/tidy"
printf 'module tidy.test\n\ngo 1.27.0\n\nrequire example.invalid/unused v1.0.0\n' >"$tmp/tidy/go.mod"
printf 'package x\n' >"$tmp/tidy/x.go"
must_fail_with "go mod tidy -diff on an untidy go.mod" "example.invalid/unused" bash -c "cd '$tmp/tidy' && GOFLAGS=-mod=mod GOPROXY=off go mod tidy -diff"

# --- web: eslint, prettier, tsc ---------------------------------------------------------------
# One fixture holds four violations; every one of them has to be reported.
for rule in no-explicit-any no-eval no-console no-restricted-syntax; do
  must_fail_with "eslint rule $rule" "$rule" in_web eslint --no-ignore proof/lint-violation.ts
done
must_fail_with "prettier --check on unformatted source" "Code style issues" in_web prettier --check --ignore-path /dev/null proof/format-violation.ts
must_fail_with "tsc on a type error" "TS2322" in_web tsc --noEmit --ignoreConfig --strict --skipLibCheck proof/type-violation.ts
must_fail_with "vitest on a failing test" "expected 1 to be 2" in_web vitest run --config vitest.proof.config.ts
must_pass "eslint on the real sources" npm --prefix web run --silent lint

# --- api contract: generated files are current, bundle collisions, rule 12 (T-0147, ADR-0004) -
# `-skip-ts` leaves the TypeScript types to the web gate; `-check` regenerates in memory and diffs.
genapi="$tmp/genapi"; go build -o "$genapi" ./tools/gen/api
ar="$tmp/apirepo"; mkdir -p "$ar/internal/platform"
cp -R api "$ar/api"; cp -R internal/platform/apihost "$ar/internal/platform/apihost"
must_pass "gen-api -check on the committed tree" "$genapi" -skip-ts -check -repo "$ar"
printf '\n' >>"$ar/internal/platform/apihost/spec/openapi.gen.json"
must_fail_with "gen-api -check on a hand-edited generated file" 'stale' "$genapi" -skip-ts -check -repo "$ar"
cp internal/platform/apihost/spec/openapi.gen.json "$ar/internal/platform/apihost/spec/openapi.gen.json"
rm "$ar/internal/platform/apihost/spec/openapi.gen.json"
must_fail_with "gen-api -check on a missing generated file" 'missing' "$genapi" -skip-ts -check -repo "$ar"
cp internal/platform/apihost/spec/openapi.gen.json "$ar/internal/platform/apihost/spec/openapi.gen.json"
cp "$ar/api/openapi/shared/guid.yaml" "$ar/api/openapi/shared/guid_again.yaml"
must_fail_with "gen-api on one component declared in two files" 'component .*GUID.* is declared in both' "$genapi" -skip-ts -repo "$ar"
rm "$ar/api/openapi/shared/guid_again.yaml"

# Rule 12: no HTTP client, fetch, XMLHttpRequest or /api string outside web/src/api. One fixture, every selector.
for rule in no-restricted-globals no-restricted-imports no-restricted-syntax; do
  must_fail_with "eslint rule $rule on a hand-written API call" "$rule" in_web eslint --no-ignore proof/api-client-violation.ts
done

if [ "$fails" -ne 0 ]; then echo "ci-proof: $fails proof(s) failed" >&2; exit 1; fi
echo "ci-proof: every gate rejects its violation and accepts clean input"

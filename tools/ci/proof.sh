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

# --- gen-check (T-0157): generated connector code must match a fresh generation ------------------
# Generate into a throw-away tree, then stale / orphan / delete a file and require the real
# `-check` mode to refuse each; the untouched tree passes.
gp="$tmp/genproto"
go run ./tools/gen/proto -out "$gp" || fails=$((fails + 1))
must_pass "gen-check on a fresh generation" go run ./tools/gen/proto -out "$gp" -check
echo "// hand edit" >>"$gp/activediq/connector/v1/common.pb.go"
must_fail_with "gen-check on a hand-edited generated file" "stale" go run ./tools/gen/proto -out "$gp" -check
go run ./tools/gen/proto -out "$gp" || fails=$((fails + 1))
touch "$gp/activediq/connector/v1/removed.pb.go"
must_fail_with "gen-check on an orphaned generated file" "orphaned" go run ./tools/gen/proto -out "$gp" -check
rm "$gp/activediq/connector/v1/removed.pb.go" "$gp/activediq/connector/v1/read.pb.go"
must_fail_with "gen-check on a missing generated file" "missing" go run ./tools/gen/proto -out "$gp" -check

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

# --- fitness-safeprim (safe-primitives FF-SP1 to FF-SP3), the real CLI on throw-away trees --------
# One violation per case, each rejected with the check's own id and the file; the same shapes pass
# in their primitive's home. The per-rule proofs are the tool's own tests (go test ./tools/...).
spbin="$tmp/safeprim"
go build -o "$spbin" ./tools/fitness/safeprim
sp="$tmp/sp"
fresh_sp_tree() { rm -rf "$sp"; mkdir -p "$sp"; printf 'module sp.test\n\ngo 1.27.0\n' >"$sp/go.mod"; }
sp_put() { mkdir -p "$sp/$(dirname "$1")"; cat >"$sp/$1"; }
safeprim() { "$spbin" -root "$sp" "$@"; }

fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import _ "github.com/go-ldap/ldap/v3"
GO
must_fail_with "FF-SP1 on go-ldap imported outside the connector" 'internal/modules/users/u.go:3: FF-SP1 \[ldap-library\]' safeprim -no-analyzers
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import _ "github.com/jackc/pgx/v5/pgxpool"
GO
must_fail_with "FF-SP1 on the SQL driver imported outside store" 'internal/modules/users/u.go:3: FF-SP1 \[sql-driver\]' safeprim -no-analyzers
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import "os/exec"

var _ = exec.Command
GO
must_fail_with "FF-SP1 on os/exec imported outside proc" 'internal/modules/users/u.go:3: FF-SP1 \[process-api\]' safeprim -no-analyzers
fresh_sp_tree
sp_put internal/connector/ldap/c.go <<'GO'
package ldap

import _ "github.com/go-ldap/ldap/v3"
GO
sp_put internal/platform/store/s.go <<'GO'
package store

import _ "github.com/jackc/pgx/v5/pgxpool"
GO
sp_put internal/platform/proc/p.go <<'GO'
package proc

import "os/exec"

var _ = exec.Command
GO
must_pass "fitness-safeprim FF-SP1 with every import in its home" safeprim -no-analyzers

fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

const q = "SELECT set_config('app.tenant_id', $1, " + "false)"
const r = "SELECT set_config('app.tenant_id', $1, false)"
GO
must_fail_with "FF-SP2 on set_config with is_local = false" 'internal/modules/users/u.go:4: FF-SP2 \[set-config-session-scope\]' safeprim -no-analyzers
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import "os/exec"

func f() { exec.Command("x") }
GO
must_fail_with "FF-SP2 on exec.Command outside proc" 'FF-SP2 \[process-start\]' safeprim -no-analyzers
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import "crypto/tls"

var c = tls.Config{InsecureSkipVerify: true}
GO
must_fail_with "FF-SP2 on InsecureSkipVerify" 'FF-SP2 \[tls-skip-verify\]' safeprim -no-analyzers
fresh_sp_tree
sp_put internal/directory/dn/dn.go <<'GO'
package dn

type DNString string
GO
sp_put internal/modules/users/u.go <<'GO'
package users

import (
	"strings"

	"sp.test/internal/directory/dn"
)

func f(d dn.DNString, ou string) bool { return strings.HasSuffix(string(d), ou) }
GO
must_fail_with "FF-SP2 analyzer dnstring on a DNString conversion outside dn" 'internal/modules/users/u.go:9: FF-SP2 \[dnstring\]' safeprim -checks FF-SP2
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import "html/template"

func f(src string) { template.New("a").Parse(src) }
GO
must_fail_with "FF-SP2 analyzer tmplconst on a non-constant template" 'internal/modules/users/u.go:5: FF-SP2 \[tmplconst\]' safeprim -checks FF-SP2

fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import "fmt"

func f(x string) string { return fmt.Sprintf("(&(objectClass=user)(cn=%s))", x) }
GO
must_fail_with "FF-SP3 on a Sprintf-built LDAP filter" 'internal/modules/users/u.go:5: FF-SP3 \[ldap-filter-shape\]' safeprim -no-analyzers
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import "strings"

func f(s string) string { return strings.ReplaceAll(s, "'", "''") }
GO
must_fail_with "FF-SP3 on PowerShell quote doubling (the PatchIQ escapePSPath shape)" 'internal/modules/users/u.go:5: FF-SP3 \[quote-doubling\]' safeprim -no-analyzers
# Ordinary spellings of the same violation, and a feature package named like a build-output directory.
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import "fmt"

const tpl = "(&(objectClass=user)(cn=%s))"

func f(x string) string { return fmt.Sprintf(tpl, x) }
GO
must_fail_with "FF-SP3 on a filter template held in a const" 'internal/modules/users/u.go:5: FF-SP3 \[ldap-filter-shape\]' safeprim -no-analyzers
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

func f(x string) string {
	s := "(&(objectClass=user)(cn="
	s += x
	return s + "))"
}
GO
must_fail_with "FF-SP3 on a filter built with +=" 'internal/modules/users/u.go:4: FF-SP3 \[ldap-filter-shape\]' safeprim -no-analyzers
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import "fmt"

func f(x string) error { return fmt.Errorf("(&(objectClass=user)(cn=%s))", x) }
GO
must_fail_with "FF-SP3 on a filter built with fmt.Errorf" 'internal/modules/users/u.go:5: FF-SP3 \[ldap-filter-shape\]' safeprim -no-analyzers
for d in target bin obj; do
  fresh_sp_tree; sp_put "internal/modules/$d/m.go" <<'GO'
package m

import "fmt"

func f(x string) string { return fmt.Sprintf("(&(objectClass=user)(cn=%s))", x) }
GO
  must_fail_with "FF-SP3 in a product package named $d (no skip by directory name)" "internal/modules/$d/m.go:5: FF-SP3" safeprim -no-analyzers
done
fresh_sp_tree
sp_put internal/directory/ldapfilter/f.go <<'GO'
package ldapfilter

import "fmt"

func Eq(attr, v string) string { return fmt.Sprintf("(%s=%s)", attr, v) }
func And(a, b string) string   { return "(&(" + a + ")(" + b + "))" }
GO
sp_put internal/platform/pslit/p.go <<'GO'
package pslit

import "strings"

func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
GO
sp_put internal/modules/users/u_test.go <<'GO'
package users

import "fmt"

func hostile(x string) string { return fmt.Sprintf("(&(objectClass=user)(cn=%s))", x) }
GO
sp_put internal/platform/store/s.go <<'GO'
package store

import "fmt"

func q(t string) string { return fmt.Sprintf("SELECT 1 FROM %s WHERE a = $1", t) }
GO
must_pass "fitness-safeprim FF-SP2/3 on primitives and test files (no false positive)" safeprim
must_pass "fitness-safeprim on the repository itself" "$spbin" -root "$root"

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
# FF-SP3 for web/: one fixture, every safe-primitives rule has to report (the rules' own tests are web/eslint/*.test.js).
for rule in no-hand-built-security-string no-quote-doubling no-dn-string-ops no-export-media-types no-unsafe-dom-sinks; do
  must_fail_with "FF-SP3 web rule $rule" "FF-SP3: .*safe-primitives/$rule" in_web eslint --no-ignore proof/safe-primitives-violation.ts
done
# Every ordinary spelling of the violation, one per line of the fixture (+=, concat, join, template, replace).
for ln in 4 5 7 8 9 10; do
  must_fail_with "FF-SP3 web spelling on fixture line $ln" "(^|[[:space:]])$ln:[0-9]+[[:space:]]+error[[:space:]]+FF-SP3" in_web eslint --no-ignore proof/safe-primitives-spellings.ts
done
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

# --- fitness-corpus (safe-primitives FF-SP4, FF-SP5, FF-SP8) and fitness-oracles (FF-SP6) -------
# The real CLIs on throw-away trees. The corpus gate's own tests (go test ./tools/fitness/corpus) cover
# every rule and a real Go implementation end to end; these are the command-line proofs.
cpbin="$tmp/corpus"; orbin="$tmp/oracles"
go build -o "$cpbin" ./tools/fitness/corpus
go build -o "$orbin" ./tools/fitness/oracles
cpt="$tmp/cp"
# fresh_cp <unit> <hostile-count>: a repository with one corpus unit of that many hostile records and a lock.
fresh_cp() {
  rm -rf "$cpt"; mkdir -p "$cpt/testdata/safe-primitives"
  printf 'module cp.test\n\ngo 1.27.0\n' >"$cpt/go.mod"
  local i; : >"$cpt/testdata/safe-primitives/$1.jsonl"
  for i in $(seq -w 1 "$2"); do
    printf '{"id":"X-%s","primitive":"%s","call":"C","args":{"value":{"utf8":"v%s"}},"expect":{"render":"r%s"},"hostile":true,"source":"proof","verified":"doc"}\n' "$i" "$1" "$i" "$i" >>"$cpt/testdata/safe-primitives/$1.jsonl"
  done
  "$cpbin" -root "$cpt" -update-lock >/dev/null
}
# A non-Go implementation: impl.sh <unit> [skip-id] writes the run report the Go kit would write.
write_impl() {
  cat >"$cpt/impl.sh" <<'SH'
#!/bin/sh
unit=$1; skip=$2
f=testdata/safe-primitives/$unit.jsonl
sha=$(shasum -a 256 "$f" | cut -d' ' -f1)
{
  printf '{"impl":"sh-impl","unit":"%s","corpus_sha256":"%s","ran":[' "$unit" "$sha"
  sep=""
  for id in $(sed -E 's/.*"id":"([^"]+)".*/\1/' "$f"); do
    [ "$id" = "$skip" ] && continue
    printf '%s{"id":"%s","ok":true,"actual":{"render":"x"}}' "$sep" "$id"; sep=","
  done
  printf '],"skipped":['
  [ -n "$skip" ] && printf '{"id":"%s","why":"not routed"}' "$skip"
  printf ']}\n'
} >"$SAFEPRIM_REPORT_DIR/corpus-sh-impl-$unit.json"
SH
  # write_impl <unit> <skip-id> [extra fields of the implementation] [extra top-level fields]
  printf '{"implementations":[{"name":"sh-impl","language":"sh","tier":"S","units":["%s"],"command":["sh","impl.sh","%s","%s"]%s}]%s}\n' "$1" "$1" "$2" "${3:-}" "${4:-}" >"$cpt/testdata/safe-primitives/implementations.json"
}
corpus() { "$cpbin" -root "$cpt" "$@"; }

fresh_cp dn 9
must_fail_with "FF-SP4 on a unit with 9 hostile records" 'dn.jsonl: FF-SP4 \[min-hostile\]: unit dn has 9 records with "hostile": true, needs 10' corpus -checks FF-SP4 -no-run
fresh_cp dn 10
must_pass "FF-SP4 on a unit with 10 hostile records" corpus -checks FF-SP4 -no-run
sed -i.bak '/"id":"X-01"/d' "$cpt/testdata/safe-primitives/dn.jsonl"; rm -f "$cpt/testdata/safe-primitives/dn.jsonl.bak"
must_fail_with "FF-SP4 on a record that disappeared without a superseding one" 'FF-SP4 \[record-removed\]: record X-01 disappeared without a superseding record' corpus -checks FF-SP4 -no-run

fresh_cp dn 10; write_impl dn X-03 ""
must_fail_with "FF-SP4 on an implementation that skips a record of its unit" 'FF-SP4 \[skipped-record\]: implementation sh-impl skips record X-03 of unit dn' corpus -checks FF-SP4
fresh_cp dn 10; write_impl dn "" ""
must_pass "FF-SP4 on an implementation that runs every record" corpus -checks FF-SP4

fresh_cp proc 10; mkdir -p "$cpt/internal/platform/proc"; printf 'package proc\n' >"$cpt/internal/platform/proc/proc.go"
must_fail_with "FF-SP4 on Go code in a primitive's home that no implementation declares" 'FF-SP4 \[undeclared-implementation\].*declares proc' corpus -checks FF-SP4 -no-run

fresh_cp dn 10; write_impl dn "" ""
must_fail_with "FF-SP5 on an implemented unit with no fuzz target" 'FF-SP5 \[no-fuzz-target\]: unit dn of implementation sh-impl has no corpus-seeded fuzz target' corpus -checks FF-SP5 -no-run
write_impl dn "" "" ',"fuzz":[{"implementation":"sh-impl","unit":"dn","target":"fuzz-dn","properties":["roundtrip","noUnescapedSpecial"],"command":["true"]}]'
must_pass "FF-SP5 on an implemented unit with a declared fuzz target" corpus -checks FF-SP5 -no-run
must_fail_with "FF-SP5 refuses a nightly fuzz run shorter than 10 minutes" 'at least 10m0s per target' corpus -fuzz -nightly -fuzztime 1m

# FF-SP8: the constant-argv test of a proc implementation reports a request-dependent argv.
fresh_cp proc 10
cat >"$cpt/argv.sh" <<'SH'
#!/bin/sh
printf '{"impl":"sh-impl","requests":500,"mismatches":%s}\n' "$1" >"$SAFEPRIM_REPORT_DIR/argv-sh-impl-argv.json"
SH
write_impl proc "" ',"argvCommand":["sh","argv.sh","[\"request 7 (seed 1): argv has 3 elements, the manifest has 2\"]"]'
must_fail_with "FF-SP8 on an argv that differs from the manifest's constant argv" 'FF-SP8 \[argv-differs\].*for 1 of 500 random requests' corpus -checks FF-SP4,FF-SP8
write_impl proc "" ',"argvCommand":["sh","argv.sh","[]"]'
must_pass "FF-SP8 on an argv equal to the manifest's constant argv" corpus -checks FF-SP4,FF-SP8

# FF-SP6: the real PowerShell parser (pwsh, or the pinned container) and go-ldap's parser.
orc="$tmp/orc"; rm -rf "$orc"; mkdir -p "$orc/testdata/safe-primitives"
cp testdata/safe-primitives/pslit.jsonl "$orc/testdata/safe-primitives/"
must_pass "FF-SP6 pslit oracle on the real pslit corpus (PowerShell Parser::ParseInput)" "$orbin" pslit -root "$orc"
sed -i.bak "s/a’’; Start-Process calc; ’’'/a’; Start-Process calc; ’'/" "$orc/testdata/safe-primitives/pslit.jsonl"; rm -f "$orc/testdata/safe-primitives/pslit.jsonl.bak"
must_fail_with "FF-SP6 pslit oracle on an ASCII-only escaper's PSQ-06" 'pslit: FF-SP6 \[pslit\] PSQ-06: output' "$orbin" pslit -root "$orc"
printf '%s\n' '{"id":"LF-01","primitive":"ldapfilter","call":"Eq","args":{"attr":"cn","value":{"utf8":"*)(uid=*"}},"expect":{"render":"(cn=\\2a\\29\\28uid=\\2a)"},"hostile":true,"verified":"doc"}' >"$orc/testdata/safe-primitives/ldapfilter.jsonl"
must_pass "FF-SP6 ldapfilter oracle on an escaped injection" "$orbin" ldapfilter -root "$orc"
printf '%s\n' '{"id":"LF-01","primitive":"ldapfilter","call":"Eq","args":{"attr":"cn","value":{"utf8":"*)(uid=*"}},"expect":{"render":"(cn=*)(uid=*)"},"hostile":true,"verified":"doc"}' >"$orc/testdata/safe-primitives/ldapfilter.jsonl"
must_fail_with "FF-SP6 ldapfilter oracle on an unescaped injection" 'LF-01: .*go-ldap rejects the rendered filter' "$orbin" ldapfilter -root "$orc"

# --- fitness-profiles (ADR-0002 P1, P7, U1, U2, activation table), the real CLI on throw-away trees
pf="$tmp/pf"
fresh_pf_tree() {
  rm -rf "$pf"; mkdir -p "$pf/internal/platform/capability" "$pf/internal/platform/tenant" "$pf/internal/directory/dn" \
    "$pf/internal/compose/profile" "$pf/internal/compose/config" "$pf/tools/fitness/profiles" "$pf/tools/fitness/stack" \
    "$pf/knowledge/development/decisions"
  printf 'module pf.test\n\ngo 1.27.0\n' >"$pf/go.mod"
  printf -- '---\nstatus: ratified\n---\n' >"$pf/knowledge/development/decisions/0002-deployment-model.md"
  cp tools/fitness/profiles/manifest.json tools/fitness/profiles/uem-denylist.json "$pf/tools/fitness/profiles/"
  printf '{"denylistExtends": ["tools/fitness/profiles/uem-denylist.json"]}\n' >"$pf/tools/fitness/stack/manifest.json"
  printf 'package capability\n\ntype ID string\n\nconst (\n\tDirectoryAD ID = "directory.ad"\n\tDirectoryEntra ID = "directory.entra"\n)\n' >"$pf/internal/platform/capability/c.go"
  printf 'package tenant\n' >"$pf/internal/platform/tenant/t.go"
  printf 'package dn\n' >"$pf/internal/directory/dn/d.go"
  printf 'package config\n' >"$pf/internal/compose/config/c.go"
  cat >"$pf/internal/compose/profile/p.go" <<'GO'
package profile

import "pf.test/internal/platform/capability"

type Process struct {
	Binary    string
	Roles     []string
	Providers []string
}
type Manifest struct {
	Name         string
	Processes    []Process
	Capabilities []capability.ID
}

func Windows() Manifest {
	return Manifest{Name: "windows", Processes: []Process{{Binary: "server", Roles: []string{"server", "connector"}, Providers: []string{"ad", "entra"}}}, Capabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra}}
}
func LinuxOCI() Manifest {
	return Manifest{Name: "linux-oci", Processes: []Process{{Binary: "server", Roles: []string{"server", "connector"}, Providers: []string{"ad", "entra"}}}, Capabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra}}
}
func SaaS() Manifest {
	return Manifest{Name: "saas", Processes: []Process{{Binary: "server", Roles: []string{"server", "connector"}, Providers: []string{"entra"}}}, Capabilities: []capability.ID{capability.DirectoryEntra}}
}
GO
  git -C "$pf" init -q -b main && git -C "$pf" -c user.name=proof -c user.email=proof@example.test commit -q --allow-empty -m proof
}
profiles() { go run ./tools/fitness/profiles -root "$pf" "$@"; }
fresh_pf_tree
must_pass "fitness-profiles on a clean composition" profiles
fresh_pf_tree; printf 'package dn\n\nimport _ "pf.test/internal/compose/profile"\n' >"$pf/internal/directory/dn/d.go"
must_fail_with "fitness-profiles P1 on domain code importing the compose package" 'internal/directory/dn/d.go:3: P1 .*imports internal/compose/profile' profiles -checks P1
fresh_pf_tree; printf 'package dn\n\nimport "os"\n\nvar v = os.Getenv("ACTIVEDIQ_PROFILE")\n' >"$pf/internal/directory/dn/d.go"
must_fail_with "fitness-profiles P1 on domain code reading the profile variable" 'internal/directory/dn/d.go:5: P1 .*profile-selecting environment variable' profiles -checks P1
fresh_pf_tree; printf 'package dn\n\nvar isSaaS = true\n' >"$pf/internal/directory/dn/d.go"
must_fail_with "fitness-profiles P1 on an identifier named isSaaS" 'internal/directory/dn/d.go:3: P1 .*"isSaaS" names a deployment profile' profiles -checks P1
fresh_pf_tree; python3 - "$pf/internal/compose/profile/p.go" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("capability.DirectoryAD, capability.DirectoryEntra}}", "capability.DirectoryEntra}}", 1)  # windows loses directory.ad
open(p, "w").write(s)
PY
must_fail_with "fitness-profiles P1 on self-hosted manifests that differ in a capability" 'P1 .*differ in capability "directory.ad"' profiles -checks P1
fresh_pf_tree; python3 - "$pf/internal/compose/profile/p.go" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('Providers: []string{"entra"}}}', 'Providers: []string{"ad", "entra"}}}', 1)  # the saas cell gets an AD provider
open(p, "w").write(s)
PY
must_fail_with "fitness-profiles P1 on an AD provider in the saas cell" 'P1 .*carries the "ad" directory provider' profiles -checks P1
fresh_pf_tree; git -C "$pf" branch release/customer-a
must_fail_with "fitness-profiles P7 on a variant branch" 'P7 .*branch "release/customer-a" is not main or factory/T-NNNN' profiles -checks P7
git -C "$pf" branch -D release/customer-a >/dev/null; git -C "$pf" branch factory/T-0038
must_pass "fitness-profiles P7 on main and factory/T-NNNN" profiles -checks P7
fresh_pf_tree; printf 'module pf.test\n\ngo 1.27.0\n\nrequire github.com/herambskanda/patchiq v0.0.0\n' >"$pf/go.mod"
must_fail_with "fitness-profiles U1 on a PatchIQ module in go.mod" 'go.mod:5: U1 .*requires github.com/herambskanda/patchiq' profiles -checks U1
fresh_pf_tree; printf 'module pf.test\n\ngo 1.27.0\n\nreplace github.com/jackc/pgx/v5 => ../pgx\n' >"$pf/go.mod"
must_fail_with "fitness-profiles U1 on a replace outside the repository" 'go.mod:5: U1 .*points outside the repository' profiles -checks U1
fresh_pf_tree; printf '{"denylistExtends": []}\n' >"$pf/tools/fitness/stack/manifest.json"
must_fail_with "fitness-profiles U1 on a stack manifest that does not extend the UEM denylist" 'U1 .*denylistExtends' profiles -checks U1
fresh_pf_tree; printf 'package tenant\n\nimport _ "pf.test/internal/directory/dn"\n' >"$pf/internal/platform/tenant/t.go"
must_fail_with "fitness-profiles U2 on a platform package importing the directory domain" 'internal/platform/tenant/t.go:3: U2 ' profiles -checks U2
fresh_pf_tree; mkdir -p "$pf/packaging/windows"; : >"$pf/packaging/windows/product.wxs"
must_fail_with "fitness-profiles activation: an installer without its P2 check" 'ACT .*packaging/windows exists, which activates P2.*not implemented' profiles -checks ACT
fresh_pf_tree; mkdir -p "$pf/internal/connector/ldap"
must_fail_with "fitness-profiles activation: a connector without its P3 check" 'ACT .*internal/connector/ldap exists, which activates P3.*not implemented' profiles -checks ACT
fresh_pf_tree
must_pass "fitness-profiles prints the pending table" bash -c "go run ./tools/fitness/profiles -root '$pf' -checks ACT | grep -q 'P2 .*pending'"

if [ "$fails" -ne 0 ]; then echo "ci-proof: $fails proof(s) failed" >&2; exit 1; fi
echo "ci-proof: every gate rejects its violation and accepts clean input"

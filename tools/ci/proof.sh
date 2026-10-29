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

# --- fitness-api (ADR-0004 A1, A3, A5, A7 static, A8, A10, A11, A12, A13, self-test, inactive reporting), the real CLI
# The per-rule proofs are the tool's own tests (go test ./tools/fitness/api); this is the command line.
fa="$tmp/fa"
fresh_fa_tree() {
  rm -rf "$fa"; mkdir -p "$fa/internal/modules/users" "$fa/internal/modules/orders" "$fa/internal/platform/apihost/spec" "$fa/api/openapi/modules" "$fa/api/openapi/shared"
  printf 'package users\n' >"$fa/internal/modules/users/doc.go"
  printf 'package orders\n' >"$fa/internal/modules/orders/doc.go"
  printf 'openapi: 3.1.0\ninfo: {title: t, version: 0.0.0}\nservers: [{url: /api/v1}]\ntags:\n  - name: users\n  - name: orders\n' >"$fa/api/openapi/openapi.yaml"
  printf 'components:\n  schemas:\n    Cursor:\n      type: string\n' >"$fa/api/openapi/shared/paging.yaml"
  printf 'paths:\n  /users:\n    get:\n      operationId: listUsers\n      tags: [users]\n      x-permission: authenticated\n      x-activediq-stability: stable\ncomponents:\n  schemas:\n    User:\n      type: string\n' >"$fa/api/openapi/modules/users.yaml"
  printf 'paths:\n  /orders:\n    get:\n      operationId: listOrders\n      tags: [orders]\n      x-permission: orders.read\n      x-activediq-stability: stable\ncomponents:\n  schemas:\n    Order:\n      type: string\n' >"$fa/api/openapi/modules/orders.yaml"
  printf 'components:\n  schemas:\n    Problem:\n      type: object\n  responses:\n    Validation:\n      description: invalid\n      content:\n        application/problem+json:\n          schema:\n            $ref: shared/problems.yaml#/components/schemas/Problem\n          example: {type: /problems/validation, title: invalid, status: 400}\n' >"$fa/api/openapi/shared/problems.yaml"
  mkdir -p "$fa/web/src/api" "$fa/web/proof"
  printf 'export interface operations {\n    listUsers: {\n    };\n    listOrders: {\n    };\n}\n' >"$fa/web/src/api/schema.gen.d.ts"
  printf 'export {};\n' >"$fa/web/src/api/client.ts"
  printf 'const g = ["fetch", "XMLHttpRequest", "EventSource"]; // axios, src/api exempt\nconst lit = "Literal[value=/^\\\\/api(\\\\/|$)/]";\n' >"$fa/web/eslint.config.js"
  printf 'export const a = fetch("/x");\n' >"$fa/web/proof/api-client-violation.ts"
  printf 'anonymous: []\nauthenticated:\n  - operation: listUsers\n    ref: TM-D16\n    reason: Any signed-in principal lists users.\nnonApiRoutes: []\nsecretResponses: []\nstepUp: []\nlargeBodies: []\n' >"$fa/api/openapi/policy.yaml"
  printf '{"paths": {"/users": {"get": {}}, "/orders": {"get": {}}}}\n' >"$fa/internal/platform/apihost/spec/openapi.gen.json"
  mkdir -p "$fa/knowledge/development/architecture"
  printf '| AN-1 | Health | Console/API | None |\n' >"$fa/knowledge/development/architecture/threat-model.md"
}
fitapi() { go run ./tools/fitness/api -root "$fa" "$@"; }
fresh_fa_tree
must_pass "fitness-api on a clean contract tree" fitapi
must_pass "fitness-api prints A1, A3, A5, A7, A8, A10, A11, A12 and A13 as active and A2, A4, A6, A9, A14 as inactive (<missing input>)" bash -c "go run ./tools/fitness/api -root '$fa' | awk '/^fitness-api A(1|3|5|7|8|10|11|12|13) /{a++; if (\$0 !~ / active/) bad=1} /^fitness-api A(2|4|6|9|14) /{n++; if (\$0 !~ /inactive \(.+\)/) bad=1} END{exit (bad || n != 5 || a != 9)}'"
must_pass "fitness-api on the repository itself lists all fourteen checks" bash -c "go run ./tools/fitness/api | grep -c '^fitness-api A' | grep -qx 14"
fresh_fa_tree; mkdir -p "$fa/api/openapi/extra"; printf 'a: b\n' >"$fa/api/openapi/extra/stray.yaml"
must_fail_with "fitness-api A1 on a file outside the rule 1 places" 'api/openapi/extra/stray.yaml: \[ADR-0004 A1\] outside the rule 1 places' fitapi
fresh_fa_tree; printf 'components:\n  schemas:\n    Ghost:\n      type: string\n' >"$fa/api/openapi/modules/ghost.yaml"
must_fail_with "fitness-api A1 on a module file with an unknown module id" 'api/openapi/modules/ghost.yaml: \[ADR-0004 A1\] module "ghost" is not in the module list' fitapi
fresh_fa_tree; sed -i 's/tags: \[users\]/tags: [users, orders]/' "$fa/api/openapi/modules/users.yaml"
must_fail_with "fitness-api A1 on an operation with two tags" 'api/openapi/modules/users.yaml:3: \[ADR-0004 A1\] GET /users \(listUsers\) has 2 tags' fitapi
fresh_fa_tree; sed -i 's/listOrders/listUsers/' "$fa/api/openapi/modules/orders.yaml"
must_fail_with "fitness-api A1 on a duplicate operationId" '\[ADR-0004 A1\] duplicate operationId "listUsers"' fitapi
fresh_fa_tree; printf 'paths:\n  /users:\n    get:\n      operationId: listUsers\n      tags: [users]\ncomponents:\n  schemas:\n    User:\n      $ref: modules/orders.yaml#/components/schemas/Order\n' >"$fa/api/openapi/modules/users.yaml"
must_fail_with "fitness-api A1 on a cross-module \$ref" 'api/openapi/modules/users.yaml:9: \[ADR-0004 A1\] .*cross-module reference' fitapi
fresh_fa_tree; sed -i 's/operation: listUsers/operation: listGhosts/' "$fa/api/openapi/policy.yaml"
must_fail_with "fitness-api A13 on a policy entry naming a missing operation" '\[ADR-0004 A13\] authenticated listGhosts: stale: operation "listGhosts" is not in the contract' fitapi
fresh_fa_tree; sed -i '/reason:/d' "$fa/api/openapi/policy.yaml"
must_fail_with "fitness-api A13 on a policy entry with no reason" '\[ADR-0004 A13\] authenticated listUsers: no reason' fitapi
fresh_fa_tree; sed -i '/ref:/d' "$fa/api/openapi/policy.yaml"
must_fail_with "fitness-api A13 on a policy entry with no AN/TM reference" '\[ADR-0004 A13\] authenticated listUsers: no AN/TM reference' fitapi
fresh_fa_tree; printf 'anonymous: [{operation: deleteAllUsers}]\n' >>"$fa/api/openapi/policy.yaml"
must_fail_with "fitness-api A13 on a duplicate policy section hiding an entry" '\[ADR-0004 A13\] duplicate mapping key "anonymous"' fitapi
fresh_fa_tree; sed -i 's/^anonymous: \[\]/anonymous:\n  - method: GET\n    path: \/healthz\n    ref: AN-99\n    reason: probe/' "$fa/api/openapi/policy.yaml"
must_fail_with "fitness-api A13 on an anonymous entry citing a missing AN row" 'AN-99 is not a row of the threat model' fitapi
fresh_fa_tree; rm "$fa/api/openapi/modules/users.yaml" "$fa/api/openapi/modules/orders.yaml"; printf 'openapi: 3.1.0\ninfo: {title: t, version: 0.0.0}\nservers: [{url: /api/v1}]\ntags: []\n' >"$fa/api/openapi/openapi.yaml"; printf 'anonymous: []\nauthenticated: []\nnonApiRoutes: []\nsecretResponses: []\nstepUp: []\nlargeBodies: []\n' >"$fa/api/openapi/policy.yaml"
must_fail_with "fitness-api self-test when the bundle has operations but the check found no operation" '\[ADR-0004 self-test\] .*holds 2 operation\(s\) but A1 found 0' fitapi

# One real-CLI case per check that went active with T-0017 (the fixtures are in check_static_test.go).
fresh_fa_tree; sed -i '/x-permission/d' "$fa/api/openapi/modules/orders.yaml"
must_fail_with "fitness-api A3 on an operation with no x-permission" '\[ADR-0004 A3\] GET /orders \(listOrders\) has no x-permission' fitapi
fresh_fa_tree; printf 'export {};\n' >"$fa/web/src/api/fetcher.ts"
must_fail_with "fitness-api A5 on a hand-written file in web/src/api" 'web/src/api/fetcher.ts: \[ADR-0004 A5\] only the generated files' fitapi
fresh_fa_tree; sed -i 's/"XMLHttpRequest", //' "$fa/web/eslint.config.js"
must_fail_with "fitness-api A5 on an ESLint config that stopped banning XMLHttpRequest" '\[ADR-0004 A5\] rule 12 no longer bans XMLHttpRequest' fitapi
fresh_fa_tree; mkdir -p "$fa/internal/modules/users"; printf 'package users\n\nimport "encoding/json"\n\nvar _ = json.Marshal\n' >"$fa/internal/modules/users/j.go"
must_fail_with "fitness-api A7 on an encoding/json v1 import in internal" 'internal/modules/users/j.go:3: \[ADR-0004 A7\] imports encoding/json \(v1\)' fitapi
fresh_fa_tree; printf 'build:\n\tGOEXPERIMENT=no%sjsonv2 go build ./...\n' "" >"$fa/Makefile"
must_fail_with "fitness-api A7 on GOEXPERIMENT containing the v1 decoder switch" 'Makefile:2: \[ADR-0004 A7\] GOEXPERIMENT contains' fitapi
fresh_fa_tree; printf 'paths:\n  /users:\n    get:\n      operationId: listUsers\n      tags: [users]\n      x-permission: authenticated\n      x-activediq-stability: stable\n      responses:\n        "200":\n          description: ok\n          content:\n            application/json:\n              schema:\n                type: object\n                properties:\n                  adminPassword: {type: string}\n' >"$fa/api/openapi/modules/users.yaml"
must_fail_with "fitness-api A8 on a secret-named property in a response" '\[ADR-0004 A8\] GET /users \(listUsers\) response 200 reaches property "adminPassword"' fitapi
fresh_fa_tree; sed -i '/x-activediq-stability/d' "$fa/api/openapi/modules/orders.yaml"
must_fail_with "fitness-api A10 on an operation with no stability" '\[ADR-0004 A10\] GET /orders \(listOrders\) has x-activediq-stability' fitapi
fresh_fa_tree; printf 'package users\n\nimport "net/http"\n\nfunc H(w http.ResponseWriter) { http.Error(w, "x", 400) }\n' >"$fa/internal/modules/users/h.go"
must_fail_with "fitness-api A11 on http.Error outside apihost" 'internal/modules/users/h.go:5: \[ADR-0004 A11\] http.Error in internal' fitapi
fresh_fa_tree; sed -i 's/x-permission: orders.read/x-permission: orders.read\n      x-activediq-limits: {class: turbo}/' "$fa/api/openapi/modules/orders.yaml"
must_fail_with "fitness-api A12 on an unknown rate class" '\[ADR-0004 A12\] GET /orders \(listOrders\) declares unknown rate class "turbo"' fitapi

fresh_fa_tree; printf 'paths:\n  /users:\n    get:\n      operationId: listUsers\n      tags: [users]\n      x-permission: authenticated\n      x-activediq-stability: stable\n      responses:\n        "200":\n          description: ok\n          headers:\n            X-Session-Token:\n              schema: {type: string}\n' >"$fa/api/openapi/modules/users.yaml"
must_fail_with "fitness-api A8 on a secret-named response header" '\[ADR-0004 A8\] GET /users \(listUsers\) response 200 has header "X-Session-Token"' fitapi
fresh_fa_tree; sed -i 's/^anonymous: \[\]/anonymous:\n  - operation: listUsers\n    ref: AN-10\n    reason: probe/; s/x-permission: authenticated/x-permission: anonymous\n      x-activediq-anonymous: AN-1/' "$fa/api/openapi/modules/users.yaml" "$fa/api/openapi/policy.yaml"
must_fail_with "fitness-api A3 on a policy row citing AN-10 for an AN-1 operation" 'cites "AN-10" but the operation declares AN-1' fitapi

# A10 against main, in a throw-away git repository, with the pinned oasdiff of tools/apitools.
fresh_fa_tree
ln -s "$root/tools/apitools" "$fa/tools-apitools-link" && mkdir -p "$fa/tools" && mv "$fa/tools-apitools-link" "$fa/tools/apitools"
b='{"openapi":"3.1.0","info":{"title":"t","version":"1.0.0"},"paths":{"/users":{"get":{"operationId":"listUsers","x-activediq-stability":"stable","responses":{"200":{"description":"ok"}}}},"/orders":{"get":{"operationId":"listOrders","x-activediq-stability":"stable","responses":{"200":{"description":"ok"}}}}}}'
printf '%s\n' "$b" >"$fa/internal/platform/apihost/spec/openapi.gen.json"
git -C "$fa" init -q -b main && git -C "$fa" add -A && git -C "$fa" -c user.name=proof -c user.email=proof@example.invalid commit -q -m base
must_pass "fitness-api A10 on a bundle identical to main" fitapi
b2='{"openapi":"3.1.0","info":{"title":"t","version":"1.0.0"},"paths":{"/users":{"get":{"operationId":"listUsers","x-activediq-stability":"stable","parameters":[{"name":"q","in":"query","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},"/orders":{"get":{"operationId":"listOrders","x-activediq-stability":"stable","responses":{"200":{"description":"ok"}}}}}}'
printf '%s\n' "$b2" >"$fa/internal/platform/apihost/spec/openapi.gen.json"
must_fail_with "fitness-api A10 on a required parameter added to a stable operation (oasdiff against main)" '\[ADR-0004 A10\] breaking change against main on a stable operation' fitapi
# A7: the v1 baseline may not grow against main (same throw-away repository, a baseline now committed on main).
mkdir -p "$fa/tools/fitness/api"; printf '# baseline\n' >"$fa/tools/fitness/api/json-v1-baseline.txt"
git -C "$fa" add -A && git -C "$fa" -c user.name=proof -c user.email=proof@example.invalid commit -q -m baseline
printf '%s\n' "$b" >"$fa/internal/platform/apihost/spec/openapi.gen.json"
printf 'package users\n\nimport "encoding/json"\n\nvar _ = json.Marshal\n' >"$fa/internal/modules/users/j.go"; printf 'internal/modules/users/j.go\n' >>"$fa/tools/fitness/api/json-v1-baseline.txt"
must_fail_with "fitness-api A7 on a v1 importer added to the baseline (not on main)" 'internal/modules/users/j.go is in the baseline but not in the baseline on main' fitapi
rm -rf "$fa/.git"

# --- fitness-operation (ADR-0005 O9, the kernel import DAG), the real CLI on throw-away trees ----
# The throw-away tree carries a copy of the real ADR, so the proof reads the same dag block as CI.
# The per-case proofs are the tool's own tests (go test ./tools/fitness/operation).
opbin="$tmp/fitness-operation"; go build -o "$opbin" ./tools/fitness/operation
opt="$tmp/op"; adr=knowledge/development/decisions/0005-operation-pipeline-and-audit-trail.md
mkdir -p "$opt/internal/platform/tenant" "$opt/internal/platform/store" "$opt/internal/platform/audit" "$opt/internal/platform/authz/actions" "$opt/internal/platform/audit/chain" "$opt/$(dirname "$adr")"
printf 'module op.test\n\ngo 1.27.0\n' >"$opt/go.mod"
cp "$adr" "$opt/$adr"
op_put() { printf 'package p\n\nimport _ "op.test/internal/platform/%s"\n' "$2" >"$opt/internal/platform/$1/p.go"; }
printf 'package p\n' >"$opt/internal/platform/tenant/p.go"; printf 'package p\n' >"$opt/internal/platform/audit/p.go"; printf 'package p\n' >"$opt/internal/platform/audit/chain/p.go"
op_put store audit
must_fail_with "fitness-operation O9 on store importing audit" 'internal/platform/store/p.go:3: O9 \[rule 13\] store imports audit' "$opbin" -root "$opt"
op_put store tenant; op_put tenant store
must_fail_with "fitness-operation O9 on tenant importing store" 'internal/platform/tenant/p.go:3: O9 \[rule 13\] tenant imports store' "$opbin" -root "$opt"
printf 'package p\n' >"$opt/internal/platform/tenant/p.go"; op_put authz/actions audit/chain
must_fail_with "fitness-operation O9 on authz/actions importing a package operation does not import" 'authz/actions imports audit/chain' "$opbin" -root "$opt"
op_put authz/actions audit
must_pass "fitness-operation O9 (store -> tenant, authz/actions -> audit)" "$opbin" -root "$opt"
sed -i.bak 's/^store  *-> tenant$/store -> (none)/' "$opt/$adr"; rm -f "$opt/$adr.bak"
must_fail_with "fitness-operation O9 follows an edit of the ADR block (store -> (none))" 'store imports tenant' "$opbin" -root "$opt"
mkdir -p "$opt/internal/modules/a" "$opt/internal/platform/operation/step"
printf 'package step\n\ntype Step struct{ s *int }\ntype Clearance struct{ s *int }\ntype Minter struct{ s *int }\n\nfunc (Step) Valid() error { return nil }\nfunc TakeMinter() (*Minter, error) { return nil, nil }\n' >"$opt/internal/platform/operation/step/step.go"
printf 'package a\n\nimport "op.test/internal/platform/operation/step"\n\nvar kept step.Step\n' >"$opt/internal/modules/a/a.go"
must_fail_with "fitness-operation O1 on a step.Step held in a global" 'internal/modules/a/a.go:5: O1 \[rule 2\] a step.Step is held in a package-level variable' "$opbin" -root "$opt"
printf 'package a\n\nimport "op.test/internal/platform/operation/step"\n\nvar _, _ = step.TakeMinter()\n' >"$opt/internal/modules/a/a.go"
must_fail_with "fitness-operation O1 on step.TakeMinter outside platform/operation" 'step.TakeMinter is referenced outside internal/platform/operation' "$opbin" -root "$opt"
printf 'package a\n\nimport "op.test/internal/platform/operation/step"\n\nfunc f() { var m step.Minter; _ = m }\n' >"$opt/internal/modules/a/a.go"
must_fail_with "fitness-operation O1 on var m step.Minter outside platform/operation" 'step.Minter is referenced outside internal/platform/operation' "$opbin" -root "$opt"
printf 'package a\n\nimport "op.test/internal/platform/operation/step"\n\nfunc f() { _ = new(step.Minter) }\n' >"$opt/internal/modules/a/a.go"
must_fail_with "fitness-operation O1 on new(step.Minter) outside platform/operation" 'step.Minter is referenced outside internal/platform/operation' "$opbin" -root "$opt"
# O1 type-aware half (tools/analyzers/stepescape): closure capture and a Step passed to a non-step function.
cp "$adr" "$opt/$adr"; printf 'package p\n' >"$opt/internal/platform/store/p.go"
printf 'package a\n\nimport "op.test/internal/platform/operation/step"\n\nfunc f(s step.Step) {\n\tgo func() { _ = s.Valid() }()\n}\n' >"$opt/internal/modules/a/a.go"
must_fail_with "fitness-operation O1 on a step.Step captured by a closure" 'internal/modules/a/a.go:6: O1 \[rule 2\] a step.Step \(s\) is captured by a closure' "$opbin" -root "$opt"
printf 'package a\n\nimport (\n\t"fmt"\n\n\t"op.test/internal/platform/operation/step"\n)\n\nfunc f(s step.Step) {\n\tfmt.Println(s)\n}\n' >"$opt/internal/modules/a/a.go"
must_fail_with "fitness-operation O1 on a step.Step passed to a function with no step.Step parameter" 'internal/modules/a/a.go:10: O1 \[rule 2\] a step.Step is passed to a function with no step.Step parameter' "$opbin" -root "$opt"
printf 'package a\n\nimport "op.test/internal/platform/operation/step"\n\nfunc f(s step.Step) { g(s) }\n\nfunc g(s step.Step) { _ = s.Valid() }\n' >"$opt/internal/modules/a/a.go"
must_pass "fitness-operation O1 on a step.Step passed to a helper that takes one" "$opbin" -root "$opt"
# O2 (write surface) and O4 (state column SQL), both syntactic.
printf 'package a\n\nimport _ "github.com/go-ldap/ldap/v3"\n' >"$opt/internal/modules/a/a.go"
must_fail_with "fitness-operation O2 on an LDAP library imported outside the connector root" 'internal/modules/a/a.go:3: O2 \[rule 2\] directory protocol library' "$opbin" -root "$opt"
printf 'package a\n\nconst q = `UPDATE public.operations SET state = $1 WHERE id = $2`\n' >"$opt/internal/modules/a/a.go"
must_fail_with "fitness-operation O4 on SQL updating a state column outside the transition functions" 'internal/modules/a/a.go:3: O4 \[rule 3\] SQL updates a state column' "$opbin" -root "$opt"
mkdir -p "$opt/internal/directory/client"
printf 'package client\n\ntype C struct{}\n\nfunc (c *C) Send() { c.sendApply() }\nfunc (c *C) sendApply() {}\n' >"$opt/internal/directory/client/c.go"
rm -f "$opt/internal/modules/a/a.go"
must_fail_with "fitness-operation O2 on an exported client method issuing a write RPC without a step.Step" 'O2 \[rule 2\] exported Send issues a connector-contract write RPC but has no step.Step parameter' "$opbin" -root "$opt"
rm -rf "$opt/internal/directory"
rm -rf "$opt/internal/modules"
must_pass "fitness-operation O9 on the repository itself" "$opbin" -root "$root"

# --- fitness-proto (the connector contract), the real CLI on throw-away trees ------------------
pr="$tmp/proto"
mkdir -p "$pr"
printf 'syntax = "proto3";\npackage t.v1;\nenum Operation { OPERATION_UNSPECIFIED = 0; OPERATION_GET = 1; OPERATION_APPLY = 100; OPERATION_READ_SECRET = 101; OPERATION_VERIFY_USER = 102; }\nmessage GetRequest { string dn = 1; }\nmessage GetResponse {}\nservice S { rpc Get(GetRequest) returns (GetResponse); }\n' >"$pr/t.proto"
must_fail_with "fitness-proto on a request carrying a DN string" "\\[P2\\]" go run ./tools/fitness/proto -optional-fleet "$pr"
printf 'syntax = "proto3";\npackage t.v1;\nmessage {\n' >"$pr/t.proto"
must_fail_with "fitness-proto on a file that does not compile" "\\[P1\\]" go run ./tools/fitness/proto -optional-fleet "$pr"
printf 'syntax = "proto3";\npackage t.v1;\nenum Operation { OPERATION_UNSPECIFIED = 0; OPERATION_GET = 1; OPERATION_APPLY = 100; OPERATION_READ_SECRET = 101; OPERATION_VERIFY_USER = 102; }\nmessage Guid { bytes value = 1; }\nmessage GetRequest { Guid guid = 1; }\nmessage GetResponse {}\nservice S { rpc Get(GetRequest) returns (GetResponse); }\n' >"$pr/t.proto"
must_fail_with "fitness-proto on a tree without the fleet package" "\\[F11\\]" go run ./tools/fitness/proto "$pr"
must_pass "fitness-proto" go run ./tools/fitness/proto -optional-fleet "$pr"
# TM-F-AGENTCMD (T-0144), contract half: a denied verb, an RPC off the golden list and a free-form
# policy string are each refused by the real CLI; the clean addc contract passes.
ac='syntax = "proto3";\npackage activediq.addc.v1;\nmessage Empty {}\nmessage CollectionState { uint64 last_event_record_id = 1; }\n'
printf "${ac}service Addc { rpc GetCollectionState(Empty) returns (CollectionState); }\n" >"$pr/t.proto"
must_pass "fitness-proto on the clean addc contract" go run ./tools/fitness/proto -optional-fleet "$pr"
printf "${ac}service Addc { rpc GetCollectionState(Empty) returns (CollectionState); rpc RunScript(Empty) returns (Empty); }\n" >"$pr/t.proto"
must_fail_with "fitness-proto on an addc contract carrying an exec verb" "\\[AG2\\]" go run ./tools/fitness/proto -optional-fleet "$pr"
printf "${ac}service Addc { rpc GetCollectionState(Empty) returns (CollectionState); rpc Ping(Empty) returns (Empty); }\n" >"$pr/t.proto"
must_fail_with "fitness-proto on an addc RPC off the golden list" "\\[AG1\\]" go run ./tools/fitness/proto -optional-fleet "$pr"
printf 'syntax = "proto3";\npackage activediq.fileserver.v1;\nmessage R { string root_id = 1; string path = 2; }\nmessage O {}\nservice Fileserver { rpc ReadAcl(R) returns (O); }\n' >"$pr/t.proto"
must_fail_with "fitness-proto on a fileserver request carrying an absolute path" "\\[AG4\\]" go run ./tools/fitness/proto -optional-fleet "$pr"

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

# --- fitness-domain-keys (domain-model X3, X4, X5), the real CLI on throw-away trees ---------------
# The per-rule proofs are the tool's own tests (go test ./tools/fitness/domainkeys/...); this is the
# end-to-end run: the CLI exits non-zero naming the table, the object and the rule, and zero on the
# clean tree. The tree has the real tenants migration, one directory table, one append-only table.
dkbin="$tmp/domainkeys"
go build -o "$dkbin" ./tools/fitness/domainkeys
dk="$tmp/dk"; mkdir -p "$dk/migrations" "$dk/internal/x"
printf 'module dk.test\n\ngo 1.27.0\n' >"$dk/go.mod"
cp tools/fitness/tenancy/testdata/base/0001_tenant_tenants.sql "$dk/migrations/"
printf '{"globalTables": [{"table": "public.tenants", "reason": "the tenant directory", "owner": "internal/platform/tenant"}]}\n' >"$dk/registry.json"
printf '### DM-01 Tenant · P · owner `platform/tenant`\n### DM-16 DirectoryObject · D · owner `directory/inventory`\n### DM-80 AuditEvent · T · append-only · owner `platform/audit`\n' >"$dk/model.md"
dk_decls() {
  printf 'package x\n\nimport "dk.test/internal/platform/tablekind"\n\n'
  printf 'var _ = tablekind.Declare(tablekind.Table{Name: "public.tenants", Entity: "DM-01", Kind: tablekind.Platform})\n'
  printf 'var _ = tablekind.Declare(tablekind.Table{Name: "public.directory_object", Entity: "DM-16", Kind: tablekind.Directory})\n'
  printf 'var _ = tablekind.Declare(tablekind.Table{Name: "public.audit_event", Entity: "DM-80", Kind: tablekind.Tenant, AppendOnly: true%s})\n' "$1"
}
dk_sql() {
  printf 'CREATE TABLE directory_object (tenant_id uuid NOT NULL, connection_id uuid NOT NULL, object_guid uuid NOT NULL, dn text NOT NULL, PRIMARY KEY (tenant_id, connection_id, object_guid));\n%s\n' "$1"
  printf 'CREATE TABLE audit_event (tenant_id uuid NOT NULL, seq bigint NOT NULL, kind text NOT NULL%s, PRIMARY KEY (tenant_id, seq));\n%s\n' "$2" "$3"
}
domainkeys() { "$dkbin" -root "$dk" -registry registry.json -domain-model model.md -pg 18 "$@"; }
dk_decls "" >"$dk/internal/x/tables.go"
dk_sql "CREATE UNIQUE INDEX uq_dn ON directory_object (tenant_id, dn);" "" "REVOKE UPDATE, DELETE ON audit_event FROM activediq_app;" >"$dk/migrations/0002_app_items.sql"
must_fail_with "fitness-domain-keys on a unique index on a directory table's dn" 'X3 public.directory_object \(unique index uq_dn\) \[key-identity-column\]' domainkeys
dk_sql "" "" "" >"$dk/migrations/0002_app_items.sql"
must_fail_with "fitness-domain-keys on an append-only table the runtime role can UPDATE" 'X5 public.audit_event \[runtime-update\]' domainkeys
dk_sql "" ", unicode_pwd bytea" "REVOKE UPDATE, DELETE ON audit_event FROM activediq_app;" >"$dk/migrations/0002_app_items.sql"
must_fail_with "fitness-domain-keys on a column named for a SecretAttrs attribute" 'X4 public.audit_event.unicode_pwd \[secret-attr-column\].*LF-38' domainkeys
dk_sql "" "" "REVOKE UPDATE, DELETE ON audit_event FROM activediq_app;" >"$dk/migrations/0002_app_items.sql"
must_pass "fitness-domain-keys" domainkeys

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
fresh_sp_tree; sp_put internal/modules/users/u.go <<'GO'
package users

import "github.com/skenzeriq/activediq/internal/connector/ad"

var _ = ad.MintSecretReadGrant
GO
must_fail_with "FF-SP2 on ad.MintSecretReadGrant outside the authorisation layer" 'internal/modules/users/u.go:5: FF-SP2 \[secret-grant-mint\]' safeprim -no-analyzers
must_fail_with "FF-SP1 on the AD connector imported by a feature module" 'internal/modules/users/u.go:3: FF-SP1 \[ad-connector-import\]' safeprim -no-analyzers
fresh_sp_tree; sp_put internal/platform/authz/g.go <<'GO'
package authz

import "github.com/skenzeriq/activediq/internal/connector/ad"

var _ = ad.MintSecretReadGrant
GO
must_pass "fitness-safeprim: authz may mint a SecretReadGrant" safeprim -no-analyzers
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
fresh_sp_tree
sp_put internal/directory/dn/dn.go <<'GO'
package dn

type DNString string
type DN struct{ s string }

func (d DN) String() string { return d.s }
GO
sp_put internal/connector/ad/c.go <<'GO'
package ad

import "sp.test/internal/directory/dn"

func f(d dn.DN) string { return d.String() }
GO
must_fail_with "FF-SP2 analyzer dnstring on dn.DN.String in the connector (not ForRequest)" 'internal/connector/ad/c.go:5: FF-SP2 \[dnstring\].*ForRequest' safeprim -checks FF-SP2
fresh_sp_tree
sp_put internal/directory/dn/dn.go <<'GO'
package dn

type DNString string
type DN struct{ s string }

func (d DN) String() string { return d.s }
GO
sp_put internal/connector/ad/c.go <<'GO'
package ad

import (
	"fmt"

	"sp.test/internal/directory/dn"
)

func f(d dn.DN) string { return fmt.Sprint(d) }
GO
must_fail_with "FF-SP2 analyzer dnstring on a dn.DN reaching DN.String via fmt in the connector" 'internal/connector/ad/c.go:9: FF-SP2 \[dnstring\].*interface' safeprim -checks FF-SP2
fresh_sp_tree
sp_put internal/directory/dn/dn.go <<'GO'
package dn

type DNString string
type DN struct{ s string }

func (d DN) String() string { return d.s }
GO
sp_put internal/connector/ad/c.go <<'GO'
package ad

import (
	"fmt"

	"sp.test/internal/directory/dn"
)

type entry struct {
	dn.DN
	n int
}

func f(e entry) string { return fmt.Sprint(e) }
GO
must_fail_with "FF-SP2 analyzer dnstring on an embedded dn.DN reaching DN.String via fmt in the connector" 'internal/connector/ad/c.go:14: FF-SP2 \[dnstring\].*interface' safeprim -checks FF-SP2
fresh_sp_tree
sp_put internal/directory/dn/dn.go <<'GO'
package dn

type DNString string
GO
sp_put internal/connector/ad/c.go <<'GO'
package ad

import "sp.test/internal/directory/dn"

func f(d dn.DNString) string { return string(d) }
GO
must_fail_with "FF-SP2 analyzer dnstring on a DNString conversion in the connector" 'internal/connector/ad/c.go:5: FF-SP2 \[dnstring\].*DNString' safeprim -checks FF-SP2
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
# generated per-tag server packages (internal/platform/<tag>/api, internal/modules/<tag>/api) are checked too
for d in internal/platform/*/api internal/modules/*/api; do [ -d "$d" ] || continue; mkdir -p "$ar/$(dirname "$d")"; cp -R "$d" "$ar/$d"; done
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

# --- fitness-profiles (ADR-0002 P1, P4 telemetry, P7, U1, U2, activation table), the real CLI on throw-away trees
pf="$tmp/pf"
fresh_pf_tree() {
  rm -rf "$pf"; mkdir -p "$pf/internal/platform/capability" "$pf/internal/platform/tenant" "$pf/internal/directory/dn" \
    "$pf/internal/compose/profile" "$pf/internal/compose/config" "$pf/tools/fitness/profiles" "$pf/tools/fitness/stack" \
    "$pf/knowledge/development/decisions"
  printf 'module pf.test\n\ngo 1.27.0\n' >"$pf/go.mod"
  printf -- '---\nstatus: ratified\n---\n' >"$pf/knowledge/development/decisions/0002-deployment-model.md"
  cp tools/fitness/profiles/uem-denylist.json "$pf/tools/fitness/profiles/"
  # The real manifest, minus its p4.exempt entries (they name files this throw-away tree does not have).
  python3 - tools/fitness/profiles/manifest.json "$pf/tools/fitness/profiles/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["p4"]["exempt"] = []
json.dump(m, open(sys.argv[2], "w"), indent=2)
PY
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
P4HDR='package svc\n\nimport (\n\t"log/slog"\n\n\t"pf.test/internal/platform/tenant"\n)\n\nvar _ = slog.Info\n\n'
fresh_pf_tree; printf 'package tenant\n\ntype ID struct{ b [16]byte }\n' >"$pf/internal/platform/tenant/t.go"; mkdir -p "$pf/internal/modules/svc"
printf "$P4HDR"'func Work(t tenant.ID) { slog.Info("synced") }\n' >"$pf/internal/modules/svc/s.go"
must_fail_with "fitness-profiles P4 on a log line without the tenant ID" 'internal/modules/svc/s.go:11: P4 .*does not carry "tenant_id"' profiles -checks P4
printf "$P4HDR"'func Work(t tenant.ID) { slog.Info("synced", "tenant_id", "x") }\n' >"$pf/internal/modules/svc/s.go"
must_pass "fitness-profiles P4 on a log line with the tenant ID" profiles -checks P4
printf 'package svc\n\nimport "github.com/prometheus/client_golang/prometheus"\n\nvar m = prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"result"})\n' >"$pf/internal/modules/svc/s.go"
must_fail_with "fitness-profiles P4 on a metric without the tenant label" 'internal/modules/svc/s.go:5: P4 .*does not list the label "tenant_id"' profiles -checks P4
printf 'package svc\n\nimport "github.com/prometheus/client_golang/prometheus"\n\nvar m = prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"tenant_id", "result"})\n' >"$pf/internal/modules/svc/s.go"
must_pass "fitness-profiles P4 on a metric with the tenant label" profiles -checks P4
printf 'package svc\n\ntype S struct{ cache map[string]int }\n' >"$pf/internal/modules/svc/s.go"
must_fail_with "fitness-profiles P4 on a cache not keyed by tenant" 'internal/modules/svc/s.go:3: P4 .*cache S.cache is not keyed by tenant' profiles -checks P4
printf 'package svc\n\nimport "pf.test/internal/platform/tenant"\n\ntype S struct{ cache map[tenant.ID]int }\n' >"$pf/internal/modules/svc/s.go"
must_pass "fitness-profiles P4 on a cache keyed by tenant" profiles -checks P4
fresh_pf_tree; mkdir -p "$pf/packaging/windows"; : >"$pf/packaging/windows/product.wxs"
must_fail_with "fitness-profiles activation: an installer without its P2 check" 'ACT .*packaging/windows exists, which activates P2.*not implemented' profiles -checks ACT
fresh_pf_tree; mkdir -p "$pf/internal/connector/ldap"
must_fail_with "fitness-profiles activation: a connector without its P3 check" 'ACT .*internal/connector/ldap exists, which activates P3.*not implemented' profiles -checks ACT
fresh_pf_tree
must_pass "fitness-profiles prints the pending table" bash -c "go run ./tools/fitness/profiles -root '$pf' -checks ACT | grep -q 'P2 .*pending'"

# --- vuln-scan (T-0010) -----------------------------------------------------------------------
# A throw-away module that calls golang.org/x/text/language.ParseAcceptLanguage at v0.3.7
# (GO-2022-1059, fixed in v0.3.8). Needs the vulnerability database and the module proxy, as the gate does.
vt="$tmp/vuln"; mkdir -p "$vt/clean"
printf 'module vt.test\n\ngo 1.27.0\n\nrequire golang.org/x/text v0.3.7\n' >"$vt/go.mod"
printf 'package vt\n\nimport "golang.org/x/text/language"\n\nfunc F(s string) { _, _, _ = language.ParseAcceptLanguage(s) }\n' >"$vt/x.go"
printf 'module clean.test\n\ngo 1.27.0\n' >"$vt/clean/go.mod"
printf 'package clean\n\nfunc F() int { return 1 }\n' >"$vt/clean/x.go"
printf '{"entries":[]}\n' >"$vt/none.json"
printf '{"entries":[{"osv":"GO-2022-1059","reason":"proof: waiting for upstream","ticket":"T-0010","expires":"2026-12-01"}]}\n' >"$vt/allow.json"
printf '{"entries":[{"osv":"GO-2022-1059","reason":"proof: waiting for upstream","ticket":"T-0010","expires":"2026-12-01"},{"osv":"GO-2099-0001","reason":"proof: fixed long ago","ticket":"T-0010","expires":"2026-12-01"}]}\n' >"$vt/stale.json"
(cd "$vt" && GOFLAGS=-mod=mod go mod tidy >/dev/null 2>&1) || echo "PROOF SETUP: go mod tidy failed for the vuln-scan fixture (module proxy unreachable?)"
vulnscan() { go run ./tools/vulnscan "$@"; }
must_fail_with "vuln-scan on a called vulnerability" 'GO-2022-1059: called through golang.org/x/text/language\.ParseAcceptLanguage.*fixed in v0\.3\.8' vulnscan -root "$vt" -allow "$vt/none.json"
must_pass "vuln-scan on the same vulnerability with an unexpired allow entry" vulnscan -root "$vt" -allow "$vt/allow.json" -today 2026-11-01
must_fail_with "vuln-scan on an allow entry past its expiry" 'GO-2022-1059: allow entry expired on 2026-12-01 \(ticket T-0010\)' vulnscan -root "$vt" -allow "$vt/allow.json" -today 2026-12-02
must_fail_with "vuln-scan on an allow entry that matches no finding" 'GO-2099-0001: allow entry .* matches no finding' vulnscan -root "$vt" -allow "$vt/stale.json" -today 2026-11-01
printf '{"entries":[{"osv":"GO-2022-1059","reason":"","ticket":"T-0010","expires":"2026-12-01"}]}\n' >"$vt/noreason.json"
must_fail_with "vuln-scan on an allow entry without a reason" 'reason is required' vulnscan -root "$vt" -allow "$vt/noreason.json"
must_pass "vuln-scan on a module with no dependencies" vulnscan -root "$vt/clean" -allow "$vt/none.json"
must_fail_with "vuln-scan when the vulnerability database is unreachable (never a silent skip)" 'cause: the vulnerability database .*point GOVULNDB at a mirror' env GOVULNDB="file://$vt/no-such-db" go run ./tools/vulnscan -root "$vt/clean" -allow "$vt/none.json"

# --- fitness-disclosure (T-0258) ----------------------------------------------------------------
dc="$tmp/disclosure"; mkdir -p "$dc/.well-known"
cp "$root/SECURITY.md" "$dc/SECURITY.md"
sed -E 's/^Expires: .*/Expires: 2020-01-01T00:00:00Z/' "$root/.well-known/security.txt" >"$dc/.well-known/security.txt"
must_fail_with "fitness-disclosure on an expired security.txt" 'Expires .* has passed' go run ./tools/fitness/disclosure "$dc"
cp "$root/.well-known/security.txt" "$dc/.well-known/security.txt"
must_pass "fitness-disclosure" go run ./tools/fitness/disclosure "$dc"

# --- fitness-packaging (T-0104) -----------------------------------------------------------------
pk="$tmp/packaging"; mkdir -p "$pk"; cp -r "$root/packaging" "$pk/packaging"
sed -i 's/SetAccessRuleProtection(\$true, \$false)/SetAccessRuleProtection($false, $false)/' "$pk/packaging/windows/Set-ApiTlsDirAcl.ps1"
must_fail_with "fitness-packaging on an ACL script that leaves inheritance on" 'inheritance must be disabled' go run ./tools/fitness/packaging "$pk"
cp "$root/packaging/windows/Set-ApiTlsDirAcl.ps1" "$pk/packaging/windows/"
sed -i 's/chmod 0700/chmod 0755/' "$pk/packaging/linux-oci/prepare-tls-dir.sh"
must_fail_with "fitness-packaging on a prepare script that loosens the mode" 'mode 0700' go run ./tools/fitness/packaging "$pk"
cp "$root/packaging/linux-oci/prepare-tls-dir.sh" "$pk/packaging/linux-oci/"
must_pass "fitness-packaging" go run ./tools/fitness/packaging "$pk"

# --- fitness-host (T-0136, TM-F-HOST) -----------------------------------------------------------
ht="$tmp/host"; mkdir -p "$ht"; hf="$root/tools/fitness/host/testdata/clean-windows.json"
must_pass "fitness-host on a compliant Windows observation" go run ./tools/fitness/host evaluate -repo "$root" "$hf"
host_case() { # <label> <expected case> <sed expression>
  sed -e "$3" "$hf" >"$ht/o.json"
  must_fail_with "fitness-host: $1" "FAIL   $2" go run ./tools/fitness/host evaluate -repo "$root" "$ht/o.json"
}
host_case "installer accepts a domain controller" HOST-DC-REFUSED 's/"refused": true/"refused": false/'
host_case "service runs as LocalSystem" HOST-SERVICE-NOT-PRIVILEGED 's/CORP\\\\activediq\$/LocalSystem/'
host_case "config readable by others" HOST-FILE-PERMISSIONS '0,/"tls-dir", "readable_by_others": false/s//"tls-dir", "readable_by_others": true/'
host_case "default credential works" HOST-NO-DEFAULT-CREDENTIAL 's/"default_credentials": \[\]/"default_credentials": ["admin"]/'
host_case "plaintext listener" HOST-NO-PLAINTEXT-LISTENER 's/"plaintext_responds": false/"plaintext_responds": true/'
host_case "setup secret reusable" HOST-SETUP-SECRET-SINGLE-USE 's/"accepted_again": false/"accepted_again": true/'
host_case "WER LocalDumps configured" HOST-NO-DUMPS 's/"wer_local_dumps": false/"wer_local_dumps": true/'
host_case "remote DSN without TLS accepted" HOST-REMOTE-DSN-FULL-TLS 's/"mode": "disable", "remote": true, "accepted": false/"mode": "disable", "remote": true, "accepted": true/'

# --- release tooling and workflows (T-0261) -----------------------------------------------------
rt="$tmp/release"; mkdir -p "$rt"
printf 'Contact: https://example.test/r\nExpires: 2020-01-01T00:00:00Z\n' >"$rt/security.txt"
must_pass "renewsecuritytxt reports a stale file as due" bash -c "go run ./tools/release/renewsecuritytxt -file '$rt/security.txt' | grep -qx renew"
go run ./tools/release/renewsecuritytxt -file "$rt/security.txt" -write >/dev/null
must_pass "renewsecuritytxt rewrote Expires away from the stale date" bash -c "! grep -q 2020-01-01 '$rt/security.txt'"
must_pass "renewsecuritytxt reports the renewed file as current" bash -c "go run ./tools/release/renewsecuritytxt -file '$rt/security.txt' | grep -qx current"
printf 'Contact: x\n' >"$rt/none.txt"
must_fail_with "renewsecuritytxt on a file without Expires" 'want exactly 1' go run ./tools/release/renewsecuritytxt -file "$rt/none.txt"
must_fail_with "sbom without SOURCE_DATE_EPOCH (not reproducible)" 'SOURCE_DATE_EPOCH must be set' env -u SOURCE_DATE_EPOCH go run ./tools/release/sbom -version v0 -o "$rt/s.json"
must_pass "sbom of this repository" env SOURCE_DATE_EPOCH=1790000000 go run ./tools/release/sbom -version v0.0.0-proof -o "$rt/s.json"
seeds=$(go run ./tools/release/sign keygen); seed=$(echo "$seeds" | awk '$1=="seed"{print $2}'); pubkey=$(echo "$seeds" | awk '$1=="public"{print $2}')
echo "$pubkey" >"$rt/k.pub"
must_fail_with "sign without a key (never an unsigned release)" 'RELEASE_SIGNING_KEY' env -u RELEASE_SIGNING_KEY go run ./tools/release/sign sign -sig "$rt/s.sig" "$rt/s.json"
must_pass "sign" env RELEASE_SIGNING_KEY="$seed" go run ./tools/release/sign sign -sig "$rt/s.sig" "$rt/s.json"
must_pass "verify of the signed SBOM" go run ./tools/release/sign verify -pub "$rt/k.pub" -sig "$rt/s.sig" "$rt/s.json"
echo tampered >>"$rt/s.json"
must_fail_with "verify of a tampered SBOM" 'does not match' go run ./tools/release/sign verify -pub "$rt/k.pub" -sig "$rt/s.sig" "$rt/s.json"
wf="$tmp/wf"; mkdir -p "$wf"; cp "$root"/.github/workflows/*.yml "$wf/"
must_pass "workflows-check" tools/ci/workflows-check.sh "$wf"
sed -i '0,/steps:/s//continue-on-error: true\n    steps:/' "$wf/release.yml"
must_fail_with "workflows-check on continue-on-error" 'continue-on-error' tools/ci/workflows-check.sh "$wf"
cp "$root/.github/workflows/release.yml" "$wf/"; sed -i -E 's/(uses: actions\/checkout)@[0-9a-f]{40}/\1@v4/' "$wf/release.yml"
must_fail_with "workflows-check on an unpinned action" 'not pinned' tools/ci/workflows-check.sh "$wf"
cp "$root/.github/workflows/release.yml" "$wf/"; sed -i 's/sign verify/sign noop/' "$wf/release.yml"
must_fail_with "workflows-check on a release that does not verify" 'without verifying' tools/ci/workflows-check.sh "$wf"

# --- fitness-agent-host (T-0554) ----------------------------------------------------------------
# The Go-test half (P1-P8, F1) is judged from `go test -json`; judgeTests' cases fail on a failed,
# skipped or deleted test (tools/fitness/agenthost/check_test.go). The CLI cases below use -skip-tests.
ah="$tmp/agenthost"; mkdir -p "$ah/proto/skenzeriq/agent/v1" "$ah/proto/activediq/addc/v1" "$ah/proto/activediq/fleet/v1"
cp "$root/proto/activediq/fleet/v1/fleet.proto" "$ah/proto/activediq/fleet/v1/"
cat >"$ah/proto/skenzeriq/agent/v1/agent.proto" <<'PROTO'
syntax = "proto3";
package skenzeriq.agent.v1;
message Empty {}
message SignedPolicy { bytes payload = 1; bytes signature = 2; }
message SignedKeyset { bytes payload = 1; bytes signature = 2; }
message StageRequest { bytes tuf_metadata = 1; bytes artefact_digest = 2; }
message AckRequest { uint64 through_agent_seq = 1; }
message Status { uint64 policy_seq = 1; }
service Host {
  rpc GetStatus(Empty) returns (Status);
  rpc ApplyPolicy(SignedPolicy) returns (Status);
  rpc ApplyKeyset(SignedKeyset) returns (Status);
  rpc StageUpdate(StageRequest) returns (Status);
  rpc AckEvents(AckRequest) returns (Status);
}
PROTO
cat >"$ah/proto/activediq/addc/v1/addc.proto" <<'PROTO'
syntax = "proto3";
package activediq.addc.v1;
message Empty {}
message CollectionState { uint64 last_event_record_id = 1; }
message PasswordPolicy { uint32 min_length = 1; repeated string banned_terms = 2; }
message AddcPolicy { PasswordPolicy password = 1; bool collection_enabled = 2; }
service Addc { rpc GetCollectionState(Empty) returns (CollectionState); }
PROTO
mkdir -p "$ah/packaging/windows" "$ah/cmd/agent" "$ah/internal/agentmodules/addc" "$ah/internal/directory/client"
cat >"$ah/packaging/windows/agent.wxs" <<'WXS'
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Package Name="agent">
<ServiceInstall Name="activediq-agent" Account="NT SERVICE\activeDIQAgent" Start="auto">
<ServiceConfig ServiceSid="restricted" RequiredPrivileges="SeChangeNotifyPrivilege" /></ServiceInstall></Package></Wix>
WXS
printf 'module fx.test\n\ngo 1.22\n' >"$ah/go.mod"
printf 'package client\n' >"$ah/internal/directory/client/c.go"
printf 'package main\n\nfunc main() {}\n' >"$ah/cmd/agent/main.go"
printf 'package addc\n' >"$ah/internal/agentmodules/addc/a.go"
printf 'fx.test/cmd/agent\n' >"$tmp/agenthost-allow.txt"
agenthost() { go run ./tools/fitness/agenthost -skip-tests -closure-allow "$tmp/agenthost-allow.txt" -root "$@"; }
must_pass "fitness-agent-host on a clean agent tree" agenthost "$ah"
cp "$ah/proto/skenzeriq/agent/v1/agent.proto" "$tmp/agent.proto.clean"
sed -i 's/service Host {/service Host { rpc RunCommand(Empty) returns (Status);/' "$ah/proto/skenzeriq/agent/v1/agent.proto"
must_fail_with "fitness-agent-host on a denied verb (exec) in the agent proto (R1)" '\[AG2\].*contains .run.' agenthost "$ah"
cp "$tmp/agent.proto.clean" "$ah/proto/skenzeriq/agent/v1/agent.proto"
cp "$ah/proto/activediq/addc/v1/addc.proto" "$tmp/addc.proto.clean"
sed -i 's/bool collection_enabled = 2;/bool collection_enabled = 2; string log_path = 3;/' "$ah/proto/activediq/addc/v1/addc.proto"
must_fail_with "fitness-agent-host on a path field in the policy (R2)" '\[AG4\]' agenthost "$ah"
sed -i 's/string log_path = 3;/uint32 password_hash = 3;/' "$ah/proto/activediq/addc/v1/addc.proto"
must_fail_with "fitness-agent-host on a password field in the addc surface (R5)" 'AG6' agenthost "$ah"
cp "$tmp/addc.proto.clean" "$ah/proto/activediq/addc/v1/addc.proto"
cp "$ah/packaging/windows/agent.wxs" "$tmp/agent.wxs.clean"
sed -i 's/NT SERVICE\\activeDIQAgent/LocalSystem/' "$ah/packaging/windows/agent.wxs"
must_fail_with "fitness-agent-host on LocalSystem in the MSI source (A1)" 'LocalSystem' agenthost "$ah"
cp "$tmp/agent.wxs.clean" "$ah/packaging/windows/agent.wxs"
sed -i 's/SeChangeNotifyPrivilege/SeChangeNotifyPrivilege SeBackupPrivilege/' "$ah/packaging/windows/agent.wxs"
must_fail_with "fitness-agent-host on an extra privilege in the MSI source (A1)" 'RequiredPrivileges of .*are' agenthost "$ah"
cp "$tmp/agent.wxs.clean" "$ah/packaging/windows/agent.wxs"
# T-0664: the WiX SDK compiles **/*.wxs, so testdata/ and node_modules/ under packaging/ are scanned.
# Fourth review: no reachability heuristic; WiX files in testdata/ or node_modules/ anywhere are scanned.
lsys='<Wix><Package><ServiceInstall Name="skzHelper" Account="LocalSystem"/></Package></Wix>'
for d in packaging/windows/testdata packaging/windows/node_modules testdata "src[/testdata" src/testdata; do
  mkdir -p "$ah/$d"
  printf '%s\n' "$lsys" >"$ah/$d/x.wxs"
  [ "$d" = "src/testdata" ] && printf '<Project/>\n' >"$ah/$d/Evil.wixproj"
  [ "$d" = "src[/testdata" ] && printf '<Project/>\n' >"$ah/src[/Evil.wixproj"
  [ "$d" = "testdata" ] && printf '<Project><ItemGroup><Compile Include="..\\..\\testdata\\x.wxs"/></ItemGroup></Project>\n' >"$ah/packaging/windows/A.wixproj"
  must_fail_with "fitness-agent-host on a LocalSystem service in $d (A1)" 'LocalSystem' agenthost "$ah"
  rm -rf "$ah/$d" "$ah/src[" "$ah/src" "$ah/packaging/windows/A.wixproj"
done
printf 'package main\n\nimport _ "fx.test/internal/directory/client"\n\nfunc main() {}\n' >"$ah/cmd/agent/main.go"
must_fail_with "fitness-agent-host on a directory client in the agent binary (A4)" 'internal/directory/client' agenthost "$ah"
printf 'package main\n\nfunc main() {}\n' >"$ah/cmd/agent/main.go"
printf 'package addc\n\nimport "os/exec"\n\nvar _ = exec.Command\n' >"$ah/internal/agentmodules/addc/a.go"
must_fail_with "fitness-agent-host on os/exec in an agent module (R3)" 'imports os/exec' agenthost "$ah"
printf 'package addc\n' >"$ah/internal/agentmodules/addc/a.go"
printf 'package main\n\nimport "net"\n\nfunc main() { _, _ = net.Listen("tcp", ":1") }\n' >"$ah/cmd/agent/main.go"
must_fail_with "fitness-agent-host on a listener in the agent (R4)" 'calls net.Listen' agenthost "$ah"
printf 'package main\n\nfunc main() {}\n' >"$ah/cmd/agent/main.go"
# Bypasses the security review found in the first version of R3/R4/A1/A4: each must fail now.
printf 'package addc\n\nimport "golang.org/x/sys/windows"\n\nvar _ = windows.CreateProcess\n' >"$ah/internal/agentmodules/addc/a.go"
must_fail_with "fitness-agent-host on windows.CreateProcess in an agent module (R3 allowlist)" 'x/sys/windows' agenthost "$ah"
printf 'package addc\n\nimport . "os"\n\nfunc f() { _ = WriteFile("x", nil, 0) }\n' >"$ah/internal/agentmodules/addc/a.go"
must_fail_with "fitness-agent-host on a dot-import in an agent module (R3)" 'dot-imports' agenthost "$ah"
printf 'package addc\n' >"$ah/internal/agentmodules/addc/a.go"
printf 'package main\n\nimport "net"\n\nfunc main() { var lc net.ListenConfig; _ = lc }\n' >"$ah/cmd/agent/main.go"
must_fail_with "fitness-agent-host on net.ListenConfig in the agent (R4)" 'ListenConfig' agenthost "$ah"
mkdir -p "$ah/internal/other"; printf 'package other\n' >"$ah/internal/other/o.go"
printf 'package main\n\nimport _ "fx.test/internal/other"\n\nfunc main() {}\n' >"$ah/cmd/agent/main.go"
must_fail_with "fitness-agent-host on a package outside the closure allowlist (A4)" 'not on the allowlist' agenthost "$ah"
printf 'package main\n\nfunc main() {}\n' >"$ah/cmd/agent/main.go"
sed -i 's|<ServiceConfig ServiceSid="restricted"|<ServiceConfig ServiceSid="unrestricted" /><ServiceConfig ServiceSid="restricted"|' "$ah/packaging/windows/agent.wxs"
must_fail_with "fitness-agent-host on an unrestricted ServiceSid followed by a restricted one (A1)" 'service SID type of .* is .unrestricted' agenthost "$ah"
cp "$tmp/agent.wxs.clean" "$ah/packaging/windows/agent.wxs"
printf 'sc.exe config activeDIQAgent obj= LocalSystem\n' >"$ah/packaging/windows/Install-Agent.ps1"
must_fail_with "fitness-agent-host on LocalSystem in an install script (A1)" 'Install-Agent.ps1 names' agenthost "$ah"
rm "$ah/packaging/windows/Install-Agent.ps1"
# Second security review: os.OpenRoot, assembly, service registry key, WMI, UTF-16 script.
printf 'package addc\n\nimport "os"\n\nvar _ = os.OpenRoot\n' >"$ah/internal/agentmodules/addc/a.go"
must_fail_with "fitness-agent-host on os.OpenRoot in an agent module (R3 os allowlist)" 'uses os.OpenRoot' agenthost "$ah"
printf 'package addc\n' >"$ah/internal/agentmodules/addc/a.go"
printf 'TEXT sys(SB),0,$0\n\tSYSCALL\n' >"$ah/internal/agentmodules/addc/a_linux_amd64.s"
must_fail_with "fitness-agent-host on an assembly file in an agent module (R3)" 'only .go files' agenthost "$ah"
rm "$ah/internal/agentmodules/addc/a_linux_amd64.s"
printf '<Wix><RegistryValue Key="SYSTEM\\CurrentControlSet\\Services\\activeDIQAgent" Name="ObjectName" Value=".\\svc-admin" /></Wix>\n' >"$ah/packaging/windows/agent-reg.wxs"
must_fail_with "fitness-agent-host on a service registry key in the MSI source (A1)" 'Services registry key' agenthost "$ah"
rm "$ah/packaging/windows/agent-reg.wxs"
printf 'Invoke-CimMethod -Query "SELECT * FROM Win32_Service WHERE Name=%sactiveDIQAgent%s" -MethodName Change -Arguments @{StartName=%s.\\svc-admin%s}\n' "'" "'" "'" "'" >"$ah/packaging/windows/Install-Agent.ps1"
must_fail_with "fitness-agent-host on a WMI service account change (A1)" 'other than' agenthost "$ah"
printf 'sc.exe config activeDIQAgent obj= LocalSystem\n' | iconv -f UTF-8 -t UTF-16 >"$ah/packaging/windows/Install-Agent.ps1"
must_fail_with "fitness-agent-host on LocalSystem in a UTF-16 install script (A1)" 'Install-Agent.ps1 names' agenthost "$ah"
rm "$ah/packaging/windows/Install-Agent.ps1"
# Third security review: an allow-by-exception installer. Unselected WiX files, custom actions, scripts, HKLM\SYSTEM.
mkdir -p "$ah/packaging/windows/core"
printf '<?define P="activeDIQ"?><Wix><Package><ServiceConfig ServiceName="$(var.P)Agent" ServiceSid="unrestricted"/></Package></Wix>\n' >"$ah/packaging/windows/core/Product.wxs"
must_fail_with "fitness-agent-host on a variable service name in a WiX file that never names the agent (A1)" 'through a variable' agenthost "$ah"
printf '<Wix><Package><CustomAction Id="CA_Acct" ExeCommand=%s"[SystemFolder]sc.exe" config activeDIQAgent obj= [ACCT]%s/></Package></Wix>\n' "'" "'" >"$ah/packaging/windows/core/Product.wxs"
must_fail_with "fitness-agent-host on a quoted sc.exe custom action (A1 deny-by-default)" 'runs code at install time' agenthost "$ah"
printf '<Wix><Package><RegistryValue Root="HKLM" Key="SYSTEM\\CurrentControlSet\\[K]" Name="ObjectName" Value="x"/></Package></Wix>\n' >"$ah/packaging/windows/core/Product.wxs"
must_fail_with "fitness-agent-host on a property-split HKLM\\SYSTEM registry key (A1)" 'HKLM key' agenthost "$ah"
rm "$ah/packaging/windows/core/Product.wxs"
printf 'sc.exe config activeDIQAgent obj= "NT SERVICE\\activeDIQAgent"\n' >"$ah/packaging/windows/Install-Agent.ps1"
must_fail_with "fitness-agent-host on an unreviewed script in the agent packaging (A1)" 'is a script in the agent packaging' agenthost "$ah"
rm "$ah/packaging/windows/Install-Agent.ps1"
printf 'package addc\n\nimport _x "fx.test/internal/agenthost/apix/exec"\n\nvar _ = _x.Y\n' >"$ah/internal/agentmodules/addc/a.go"
must_fail_with "fitness-agent-host on a look-alike own package path in an agent module (R3 exact match)" 'allowlist' agenthost "$ah"
printf 'package addc\n\nimport "path/filepath"\n\nvar _ = filepath.WalkDir\n' >"$ah/internal/agentmodules/addc/a.go"
must_fail_with "fitness-agent-host on filepath.WalkDir in an agent module (R3)" 'filepath.WalkDir' agenthost "$ah"
# Fourth security review: parsed, entity-decoded structure; services, ACLs and file types denied by default.
printf '<Wix><Package><ServiceInstall Name="activeDIQ&#65;gent" Account="NT SERVICE\\activeDIQ&#65;gent"><ServiceConfig ServiceName="activeDIQ&#65;gent" ServiceSid="unrestricted" RequiredPrivileges="SeDebugPrivilege"/></ServiceInstall></Package></Wix>\n' >"$ah/packaging/windows/core/Product.wxs"
must_fail_with "fitness-agent-host on an entity-encoded agent service name with an unrestricted SID (A1)" 'character reference' agenthost "$ah"
printf '<Wix><Package><ServiceInstall Name="skzHelper" Type="ownProcess" Start="auto"/></Package></Wix>\n' >"$ah/packaging/windows/core/Product.wxs"
must_fail_with "fitness-agent-host on a ServiceInstall with no Account, i.e. implicit LocalSystem (A1)" 'no Account' agenthost "$ah"
printf '<Wix><Package><Component Id="C"><ServiceInstall Name="activediq-agent" Account="NT SERVICE\\activeDIQAgent"/><ServiceInstall Name="x" Account="NT SERVICE\\x"/></Component></Package></Wix>\n' >"$ah/packaging/windows/core/Product.wxs"
must_fail_with "fitness-agent-host on a second service in the agent Component (A1)" 'exactly one' agenthost "$ah"
printf '<Wix><Package><ServiceInstall Name="Other" Account="NT SERVICE\\Other"><PermissionEx Sddl="D:(A;;GA;;;WD)"/></ServiceInstall></Package></Wix>\n' >"$ah/packaging/windows/core/Product.wxs"
must_fail_with "fitness-agent-host on a PermissionEx ACL (A1 deny-by-default)" 'grants an ACL' agenthost "$ah"
# Fifth security review: DTD entities, WiX outside packaging/, every service pinned.
printf '<!DOCTYPE Wix [<!ENTITY g "Agent">]><Wix><Package><ServiceInstall Name="activeDIQ&g;" Account="NT SERVICE\\activeDIQ&g;"><ServiceConfig ServiceName="activeDIQ&g;" ServiceSid="unrestricted" RequiredPrivileges="SeDebugPrivilege"/></ServiceInstall></Package></Wix>\n' >"$ah/packaging/windows/core/Product.wxs"
must_fail_with "fitness-agent-host on a DOCTYPE/ENTITY-built agent service name (A1)" 'DOCTYPE or ENTITY' agenthost "$ah"
printf '<Wix><Package><Component><ServiceInstall Name="skzHelper" Account="NT SERVICE\\skzHelper"><ServiceConfig ServiceSid="unrestricted" RequiredPrivileges="SeDebugPrivilege,SeBackupPrivilege"/></ServiceInstall></Component></Package></Wix>\n' >"$ah/packaging/windows/core/Product.wxs"
must_fail_with "fitness-agent-host on a second service with an unrestricted SID and extra privileges (A1)" 'service SID type of' agenthost "$ah"
rm "$ah/packaging/windows/core/Product.wxs"
mkdir -p "$ah/installer"
printf '<Wix><Package><ServiceInstall Name="activeDIQAgent" Account="LocalSystem"/></Package></Wix>\n' >"$ah/installer/agent.wxs"
must_fail_with "fitness-agent-host on LocalSystem in WiX outside packaging/ (A1)" 'LocalSystem' agenthost "$ah"
rm -rf "$ah/installer"
printf '<Wix><Package><ServiceInstall Name="x" Account="NT SERVICE\\x" ServiceSid="restricted" RequiredPrivileges="SeChangeNotifyPrivilege"/></Package></Wix>\n' >"$ah/packaging/windows/core/Product.wxs"
rm "$ah/packaging/windows/core/Product.wxs"
mkdir -p "$ah/packaging/windows/agent"
printf '<ServiceInstall Name="activeDIQAgent" Account="NT SERVICE\\activeDIQAgent"><ServiceConfig ServiceSid="unrestricted"/></ServiceInstall>\n' >"$ah/packaging/windows/agent/Product.wxs.in"
must_fail_with "fitness-agent-host on an unparsed WiX template in the agent packaging (A1)" 'template or transform' agenthost "$ah"
rm -rf "$ah/packaging/windows/agent"
printf 'package addc\n' >"$ah/internal/agentmodules/addc/a.go"
must_pass "fitness-agent-host after the violations are removed" agenthost "$ah"
must_pass "fitness-agent-host is wired into make fitness" bash -c "make -n fitness | grep -q 'tools/fitness/agenthost'"

# --- fitness-audit (ADR-0005 A1-A9, TM-F-AUDIT), the real CLI ------------------------------------
# The per-rule proofs of A1 are the tool's own tests (go test ./tools/fitness/audit/...). Here: A1 on a
# real migration sequence with one extra migration that lets the runtime role DELETE audit rows (needs
# Docker), and the test bindings of A2-A9 on a throw-away module whose bound tests fail, are skipped or
# are missing.
aubin="$tmp/fitness-audit"
go build -o "$aubin" ./tools/fitness/audit
au="$tmp/au"
mkdir -p "$au/migrations" "$au/internal/platform/audit"
cp migrations/*.sql "$au/migrations/"
printf 'module au.test\n\ngo 1.27.0\n' >"$au/go.mod"
printf 'GRANT DELETE ON public.audit_event TO activediq_app;\n' >"$au/migrations/9999_audit_proof.sql"
must_fail_with "fitness-audit A1 when the runtime role can DELETE audit events" 'A1 audit_event \[runtime-privilege\]: .*holds DELETE' "$aubin" -root "$au" -pg 18 -checks A1
rm "$au/migrations/9999_audit_proof.sql"
printf 'GRANT TRUNCATE ON public.audit_checkpoint TO activediq_app;\n' >"$au/migrations/9999_audit_proof.sql"
must_fail_with "fitness-audit A1 when the runtime role can TRUNCATE the checkpoints" 'A1 audit_checkpoint \[runtime-privilege\]: .*holds TRUNCATE' "$aubin" -root "$au" -pg 18 -checks A1
rm "$au/migrations/9999_audit_proof.sql"
must_pass "fitness-audit A1" "$aubin" -root "$au" -pg 18 -checks A1
a2tests="TestRolledBackAppendLeavesNothingAndTheChainStaysGapless TestA2NonReadCommittedAppendIsRefusedAndChainStaysGapless TestFailsClosedWhenMiswired TestHeadGuards"
write_a2() { # $1 = body of TestHeadGuards
  { printf 'package audit_test\n\nimport "testing"\n\n'
    for n in $a2tests; do [ "$n" = TestHeadGuards ] || printf 'func %s(t *testing.T) {}\n' "$n"; done
    printf 'func TestHeadGuards(t *testing.T) { %s }\n' "$1"; } >"$au/internal/platform/audit/a_test.go"
}
write_a2 't.Fatal("an edited event verified")'
must_fail_with "fitness-audit A2 when a bound test fails" 'A2 \./internal/platform/audit TestHeadGuards \[test-failed\]' "$aubin" -root "$au" -checks A2
write_a2 't.Skip("no docker")'
must_fail_with "fitness-audit A2 when a bound test is skipped" 'A2 \./internal/platform/audit TestHeadGuards \[test-skipped\]' "$aubin" -root "$au" -checks A2
write_a2 ''
sed -i 's/TestHeadGuards/TestHeadGuardsRenamed/' "$au/internal/platform/audit/a_test.go"
must_fail_with "fitness-audit A2 when a bound test is renamed away" 'A2 \./internal/platform/audit TestHeadGuards \[test-missing\]' "$aubin" -root "$au" -checks A2
write_a2 ''
must_pass "fitness-audit A2" "$aubin" -root "$au" -checks A2

# --- fitness-update (T-0139) -------------------------------------------------------------------
upd="$tmp/update-bin"
go build -o "$upd" ./tools/fitness/update
must_pass "fitness-update (both couriers)" "$upd"
must_fail_with "fitness-update against a verifier that accepts bad updates" 'accepted a bad update; want refusal "tamper"' "$upd" -sabotage accept-all
must_fail_with "fitness-update against a verifier that refuses for the wrong reason" 'refused with "tamper", want "rollback"' "$upd" -sabotage mislabel
must_fail_with "fitness-update against a verifier that extracts before it decides" 'extraction before verification' "$upd" -sabotage leak
must_pass "make fitness-update-offline is wired into make ci" bash -c "make -n ci | grep -q 'tools/fitness/update/offline.sh'"

# --- fuzz-target / fuzz-saml (T-0490) -----------------------------------------------------------
fz="$tmp/fuzz"
mkdir -p "$fz"
printf 'module fuzz.test\n\ngo 1.27.0\n' >"$fz/go.mod"
printf 'package x\n\nimport "testing"\n\nfunc FuzzT(f *testing.F) {\n\tf.Add([]byte("a"))\n\tf.Fuzz(func(t *testing.T, b []byte) {\n\t\tif len(b) > 0 && b[0] != 0 {\n\t\t\tt.Fatal("oracle violated")\n\t\t}\n\t})\n}\n' >"$fz/x_test.go"
must_fail_with "fuzz-target on a target whose oracle is violated" "oracle violated" tools/ci/fuzz-target.sh "$fz" FuzzT 5s
must_fail_with "fuzz-target on a target that does not exist (a silent no-op)" "did not fuzz" tools/ci/fuzz-target.sh "$fz" FuzzMissing 5s
rm -rf "$fz/testdata"
printf 'package x\n\nimport "testing"\n\nfunc FuzzT(f *testing.F) {\n\tf.Add([]byte("a"))\n\tf.Fuzz(func(t *testing.T, b []byte) {})\n}\n' >"$fz/x_test.go"
must_pass "fuzz-target" tools/ci/fuzz-target.sh "$fz" FuzzT 3s
must_pass "make fuzz-saml is wired into make ci" bash -c "make -n ci | grep -q 'fuzz-target.sh internal/platform/authn/sso/saml FuzzSAMLComplete 60s'"

if [ "$fails" -ne 0 ]; then echo "ci-proof: $fails proof(s) failed" >&2; exit 1; fi
echo "ci-proof: every gate rejects its violation and accepts clean input"

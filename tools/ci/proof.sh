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

if [ "$fails" -ne 0 ]; then echo "ci-proof: $fails proof(s) failed" >&2; exit 1; fi
echo "ci-proof: every gate rejects its violation and accepts clean input"

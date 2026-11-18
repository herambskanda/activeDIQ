#!/usr/bin/env bash
# T-2313: proof that every check in `make prescreen` goes red on a deliberate violation and is green on the
# clean tree (the prescreen run itself). Each case mutates the work tree, runs the real target, requires a
# non-zero exit (and, where given, a matching message, so a broken tool does not count), then restores the
# tree. Needs a clean work tree (commit first) and Docker-free tooling; takes 10-15 minutes. Run it on
# demand and after changing prescreen: `make prescreen-proof`. It is not part of `make ci`.
# fitness-merge-order is red on main today (M5, T-1101); its own failing/passing history fixtures are
# the node tests of the checker, run here.
set -uo pipefail
cd "$(dirname "$0")/../.."
if [ -n "$(git status --porcelain)" ]; then echo "prescreen-proof: the work tree must be clean (it restores with git checkout/clean)" >&2; exit 2; fi
fails=0
out=$(mktemp)
trap 'git checkout -q -- . ; git clean -fdq; rm -f "$out"' EXIT
restore() { git checkout -q -- . ; git clean -fdq; }

# case <name> <pattern> <make target or command...>   (mutation is applied by the caller beforehand)
expect_red() {
  local name=$1 pattern=$2; shift 2
  if "$@" >"$out" 2>&1; then
    echo "PROOF FAILED: $name: the check accepted the violation"; fails=$((fails + 1))
  elif ! grep -qE "$pattern" "$out"; then
    echo "PROOF FAILED: $name: red, but not for the expected reason ($pattern)"; sed 's/^/    /' "$out" | tail -15; fails=$((fails + 1))
  else
    echo "ok: $name is red on its violation"
  fi
  restore
}
put() { mkdir -p "$(dirname "$1")"; cat >"$1"; }

put internal/zzproof/x.go <<'G'
package zzproof
func  F( ) {}
G
expect_red "lint-go (unformatted Go file)" "not formatted" make -s lint-go

f=$(ls internal/proto/*/*.go | head -1); echo "// stale" >>"$f"
expect_red "gen-check (hand-edited generated proto code)" "." make -s gen-check

echo "zz_proof	config" >>internal/platform/store/owners/owners.gen.tsv
expect_red "gen-modules-check (hand-edited owners map)" "." make -s gen-modules-check

echo " " >>internal/platform/apihost/spec/openapi.gen.json
expect_red "gen-api-check (hand-edited bundled contract)" "." make -s gen-api-check

sed -i '0,/"operationId": *"[^"]*"/{s/"operationId": *"[^"]*",\?//}' internal/platform/apihost/spec/openapi.gen.json
expect_red "lint-api (an operation without operationId)" "operationId|error|fail" make -s lint-api

put internal/zzproof/u.go <<'G'
package zzproof
import "unsafe"
var _ unsafe.Pointer
G
expect_red "fitness-safeprim (FF-SP2 unsafe import)" "unsafe" make -s fitness-safeprim

put internal/zzproof/s.go <<'G'
package zzproof
import _ "github.com/russellhaering/gosaml2"
G
expect_red "fitness-sso (FIT-SSO-1 SAML library outside sso/saml)" "FIT-SSO-1|gosaml2" make -s fitness-sso

printf 'x\n' >testdata/safe-primitives/csv.jsonl
expect_red "fitness-corpus (FF-SP4 corpus gutted)" "FF-SP4|csv|corpus" make -s fitness-corpus

put proto/zzproof/bad.proto <<'G'
syntax = "proto3";
package zzproof
message M {
G
expect_red "fitness-proto (P1 file that does not compile)" "P1" make -s fitness-proto

put internal/zzproof/o.go <<'G'
package zzproof
import "github.com/skenzeriq/activediq/internal/platform/authz"
func F(b [16]byte) authz.ObjectID { return authz.ObjectID(b) }
G
expect_red "fitness-objectid (conversion outside authz)" "ObjectID" make -s fitness-objectid

put internal/zzproof/g.go <<'G'
package zzproof
type grants struct{}
func (grants) GrantBootstrap() {}
func F(g grants) { g.GrantBootstrap() }
G
expect_red "fitness-grantbootstrap (call outside the first-account CLI)" "GrantBootstrap" make -s fitness-grantbootstrap

sed -i 's/^Expires: .*/Expires: 2020-01-01T00:00:00Z/' .well-known/security.txt
expect_red "fitness-disclosure (security.txt expired)" "Expires|expire" make -s fitness-disclosure

put migrations/0999_zzproof.sql <<'G'
ALTER TABLE public.fleet_server_ca ADD COLUMN tenant_id uuid;
G
expect_red "fitness-fleet-ca-scope (FCS-5 tenant_id on fleet_server_ca)" "FCS-5" make -s fitness-fleet-ca-scope

# fitness-merge-order: the checker's own fixtures (a violating history fails, a clean one passes)
if node --test factory/test/fitness-merge-order.test.mjs >"$out" 2>&1; then echo "ok: fitness-merge-order checker tests (violating history fails, clean passes) pass"; else echo "PROOF FAILED: fitness-merge-order node tests"; tail -15 "$out"; fails=$((fails + 1)); fi

sed -i '0,/^jobs:/s//jobs:/' .github/workflows/release.yml; printf '    continue-on-error: true\n' >>.github/workflows/release.yml
expect_red "workflows-check (continue-on-error)" "continue-on-error" make -s workflows-check

put zzproof-secret.txt <<G
aws_access_key_id = $(printf '%s%s' 'AKIA' 'QYLPMN5HHHFPZAM2')
G
expect_red "secrets-scan (fake AWS key in the work tree)" "leak|secret" make -s secrets-scan

put tools/ci/vuln-allow.json <<'G'
{"entries":[{"osv":"GO-2000-0001","reason":"proof","ticket":"T-2313","expires":"2020-01-01"}]}
G
expect_red "vuln-scan (expired allow entry)" "expire|stale" make -s vuln-scan

# prescreen-gotests: three bound Go tests
put internal/zzproof/t.go <<'G'
package zzproof
import _ "github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
G
expect_red "TestOnlyPermittedFilesImportTenantref (unlisted importer)" "tenantref" make -s prescreen-gotests

put internal/zzproof/w.go <<'G'
package zzproof
import _ "github.com/skenzeriq/activediq/internal/connector/write/ops"
G
expect_red "TestOpsPackageImportedOnlyByGuard (importer outside write)" "imports the operation bodies" make -s prescreen-gotests

cp migrations/0001_tenant_tenants.sql migrations/0001_zzproof_dup.sql
expect_red "TestMigrationNumbersAreUniqueAndContiguous (duplicate number)" "unique|contiguous|0001" make -s prescreen-gotests

echo "prescreen-proof: $fails failed"
[ "$fails" -eq 0 ]

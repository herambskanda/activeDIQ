#!/bin/bash
# T-0308: the `dsdb:schema update allowed` override lives only in lab/seed/schema-seed.sh.
# Fails if it appears anywhere else in the repo (product code, other scripts). Self-test: --selftest
# plants a violation in a temp tree and proves the check fails.
set -uo pipefail
cd "$(dirname "$0")/../.."
check() { # $1 = root
  git -C "$1" grep -nIi 'schema update allowed' -- . ':!lab/seed/schema-seed.sh' ':!lab/tests/test_schema_seed.sh' \
    ':!knowledge' ':!factory/state' ':!.claude' 2>/dev/null
}
if [ "${1:-}" = --selftest ]; then
  t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
  git -C "$t" init -q; mkdir -p "$t/internal"; echo '// dsdb:schema update allowed = true' > "$t/internal/x.go"
  git -C "$t" add -A
  if check "$t" >/dev/null; then echo "PASS selftest: violation detected"; exit 0; else echo "FAIL selftest: violation NOT detected"; exit 1; fi
fi
if check . ; then echo "FAIL: override found outside lab/seed/schema-seed.sh"; exit 1; fi
grep -q 'searchFlags: 512' lab/seed/schema-seed.sh || { echo "FAIL: seed does not set searchFlags 512"; exit 1; }
echo "PASS: override confined to lab/seed/schema-seed.sh"

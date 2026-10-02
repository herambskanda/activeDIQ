#!/bin/bash
# Live verification of the AD lab (T-0012): proves AC1-AC3 mechanically.
#   1. LDAPS answers from the host, with the lab CA verified (no skip-verify).
#   2. The loaded seed matches the manifest the generator wrote (counts, states, edge cases, ranges).
#   3. The lab behaves like a hardened DC (no plain simple bind) and the service account is delegated
#      only on OU=Managed.
#   4. `make lab-reset` returns the directory to the exact seeded state after we dirty it.
# Each check prints PASS/FAIL; any FAIL makes the script exit non-zero. Run: make lab-test-live
set -uo pipefail
cd "$(dirname "$0")/../.."
. lab/.lab.env
COMPOSE="docker compose -f lab/docker-compose.yml"
PORT="${LAB_LDAPS_PORT:-636}"
RESET_CMD="${RESET_CMD:-make lab-reset}"   # overridden only to prove the reset check can fail (RESET_CMD=true)
fails=0; passes=0
pass() { passes=$((passes + 1)); printf 'PASS  %s\n' "$*"; }
fail() { fails=$((fails + 1)); printf 'FAIL  %s\n' "$*"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }

in_dc() { $COMPOSE exec -T -e LAB_SVC_PASSWORD="$LAB_SVC_PASSWORD" -e LAB_USER_PASSWORD="$LAB_USER_PASSWORD" dc bash -s; }

# ---- 1. host -> LDAPS with certificate verification ---------------------------------------------
check "host reaches LDAPS :$PORT and the cert verifies against lab/.lab-ca.pem (host name localhost)" \
  bash -c "echo | openssl s_client -connect localhost:$PORT -CAfile lab/.lab-ca.pem -verify_return_error -verify_hostname localhost"
check "cert does NOT verify without the lab CA (so tests cannot pass by skipping verification)" \
  bash -c "! (echo | openssl s_client -connect localhost:$PORT -CAfile /dev/null -verify_return_error 2>&1 | grep -q 'Verification: OK')"

# ---- 2/3. seed + hardening, run inside the DC container (same tooling on macOS and Linux CI) ----
# Output lines: "<check> <got> <want>"
OUT=$(in_dc < lab/tests/inner-checks.sh)

DIGEST_BEFORE=""
while read -r name got want; do
  [ -z "${name:-}" ] && continue
  if [ "$name" = digest ]; then DIGEST_BEFORE="$got"; pass "state digest of OU=Managed recorded ($got)"
  elif [ -z "$got" ]; then fail "$name: empty result (check did not run)"
  elif [ "$got" = "$want" ]; then pass "$name ($got)"
  else fail "$name: got $got, want $want"; fi
done <<< "$OUT"
[ -n "$DIGEST_BEFORE" ] || fail "no digest produced (container checks did not run)"

# ---- 4. reset round trip ------------------------------------------------------------------------
digest() { in_dc < lab/tests/inner-digest.sh; }
echo "--- dirtying the directory (create, delete, modify), then make lab-reset ---"
in_dc >/dev/null 2>&1 < lab/tests/inner-dirty.sh
DIRTY_DIGEST=$(digest)
if [ "$DIRTY_DIGEST" != "$DIGEST_BEFORE" ] && [ -n "$DIRTY_DIGEST" ]; then pass "the probe changed the directory (digest $DIRTY_DIGEST) — the reset proof is not vacuous"
else fail "probe changes were not visible (digest $DIRTY_DIGEST)"; fi
t0=$(date +%s)
if $RESET_CMD >/dev/null 2>&1; then pass "$RESET_CMD succeeded in $(( $(date +%s) - t0 ))s"; else fail "$RESET_CMD failed"; fi
AFTER=$(digest)
if [ "$AFTER" = "$DIGEST_BEFORE" ]; then pass "state digest after reset equals the seeded digest ($AFTER)"
else fail "state digest after reset is $AFTER, seeded was $DIGEST_BEFORE"; fi

echo
echo "lab verification: $passes passed, $fails failed"
[ "$fails" -eq 0 ]

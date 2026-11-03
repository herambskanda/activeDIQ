#!/usr/bin/env bash
# The live user-search proof against the Windows lab DC (T-0765, M1 demo criterion 2).
#
#   lab/windows/bin/with-dc1-lock lab/e2e/live-user-search.sh EVIDENCE_DIR
#
# Boots a REAL lab-built server (boot-lab-server.sh) with WIN_LAB_* pointing at dc1 (signing + channel binding, the non-Domain-Admin
# service account), mints a console session through the product's sign-in API, types a seeded user's name into the real console
# (web/e2e/live-user-search.spec.ts), then records what dc1 logged during the run and the service account's group membership.
# EVIDENCE_DIR receives: boot.log, server.log (secrets-free tail), playwright.log, live-results.png, dc1-events.txt, dc1-svc-groups.txt,
# summary.txt. Exit 0 only if the user was listed AND the DC shows no 2887/3039/3074 AND the service account has no admin group.
# Needs: WIN_LAB_ENV (the lab env file, absolute path), WIN_LAB_CA (the DC CA PEM, absolute path), docker, go, node, python3 + pywinrm.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ev="${1:-}"; [ -n "$ev" ] || { echo "usage: $0 EVIDENCE_DIR" >&2; exit 2; }
: "${WIN_LAB_ENV:?set WIN_LAB_ENV to the absolute path of the lab env file}"
: "${WIN_LAB_CA:?set WIN_LAB_CA to the absolute path of the DC CA PEM}"
[ -n "${DIQ_DC1_LOCK_HELD:-}" ] || { echo "live-user-search: run under lab/windows/bin/with-dc1-lock (dc1 is shared)" >&2; exit 2; }
USER_SAM="${ADIQ_E2E_USER_SAM:-lab-user-01}"; USER_NAME="${ADIQ_E2E_USER_NAME:-lab-user-01}"
mkdir -p "$ev"; ev="$(cd "$ev" && pwd)"
dir="$(mktemp -d)"; chmod 700 "$dir"
status=0
cleanup() { "$root/lab/e2e/boot-lab-server.sh" down "$dir" >/dev/null 2>&1 || true; rm -rf "$dir"; }
trap cleanup EXIT

# The lab env file is KEY=VALUE; export only what the server and the checks need (the passwords never reach a log).
set -a; . "$WIN_LAB_ENV"; set +a
export WIN_LAB_DC_ADDR WIN_LAB_SVC_PASSWORD WIN_LAB_CA WIN_LAB_TLS_NAME="${WIN_LAB_TLS_NAME:-dc1.win.activediq.test}"

dc1() { "$root/lab/windows/bin/dc1-evidence" "$@"; }
since="$(dc1 now)"; echo "dc1 clock at start: $since" | tee "$ev/summary.txt"
"$root/lab/windows/bin/dc1-policy" check 2>&1 | tee "$ev/dc1-policy.txt"

# 1. Boot. The server activates its win connection at start-up (verification V5/V7/V8/V9) before it listens.
"$root/lab/e2e/boot-lab-server.sh" up "$dir" > "$ev/boot.log" 2>&1 || { status=1; tail -n 20 "$ev/boot.log" >&2; echo "FAIL: the lab server did not boot" | tee -a "$ev/summary.txt"; }
if [ "$status" = 0 ]; then
  . "$dir/env"
  # 2. Mint a session through the real sign-in API.
  python3 "$root/lab/e2e/mint_session.py" "$dir/server" "$ADIQ_BASE_URL" "$ADIQ_E2E_CA" "e2e-$(openssl rand -hex 3)" "$dir/session" 2>&1 | tee -a "$ev/summary.txt" || status=1
  # 3. The E2E in the real console (only with a session).
  [ "$status" != 0 ] || ( cd "$root/web" && ADIQ_E2E_SESSION="$(cat "$dir/session")" ADIQ_E2E_USER_NAME="$USER_NAME" ADIQ_E2E_USER_SAM="$USER_SAM" \
      ADIQ_E2E_EVIDENCE_DIR="$ev" npx playwright test live-user-search ) 2>&1 | tee "$ev/playwright.log" || status=1
  grep -E "server:|activat|lab bootstrap|listening" "$dir/server.log" | grep -viE "password|secret|token" | tail -n 30 > "$ev/server.log" || true
fi

# 4. What dc1 saw, from dc1's own clock.
{ echo "window: $since .. $(dc1 now)"; dc1 events "$since"; } 2>&1 | tee "$ev/dc1-events.txt" || status=1
dc1 svc 2>&1 | tee "$ev/dc1-svc-groups.txt" || status=1

if [ "$status" = 0 ]; then echo "RESULT: PASS (user listed; no 2887/3039/3074; service account not an admin)" | tee -a "$ev/summary.txt"
else echo "RESULT: FAIL (see the logs above)" | tee -a "$ev/summary.txt"; fi
exit "$status"

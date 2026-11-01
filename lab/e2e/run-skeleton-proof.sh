#!/usr/bin/env bash
# Walking-skeleton proof (T-0671): boot the REAL lab-built server on a lab, sign in through the console, type a
# name, and assert the real user is found. One lab per run.
#
#   lab/e2e/run-skeleton-proof.sh windows   VM 119 (dc1, WS2025, LDAP signing + channel binding enforced)
#   lab/e2e/run-skeleton-proof.sh samba     the Samba lab of this worktree (make lab-up)
#
# windows needs, from the MAIN checkout (gitignored, absolute): WIN_LAB_ENV, WIN_LAB_CA; WIN_LAB_DC_ADDR,
# WIN_LAB_TLS_NAME default to 192.168.1.9 / dc1.win.activediq.test. The run holds with-dc1-lock for its whole
# length (runbook windows-lab.md section 10) and also writes the read-only dc1 proof.
# Evidence lands in factory/demos/evidence/T-0671/ (override: ADIQ_E2E_EVIDENCE_DIR). The server log is saved only
# after a scan proves none of the lab passwords is in it.
set -euo pipefail
mode="${1:-}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
die() { echo "run-skeleton-proof: $*" >&2; exit 1; }

case "$mode" in
windows)
  : "${WIN_LAB_ENV:?set WIN_LAB_ENV to the main checkout lab/windows/.win-lab.env}"
  : "${WIN_LAB_CA:?set WIN_LAB_CA to the main checkout lab/windows/.win-lab-ca.pem}"
  # Re-run under the dc1 lock (re-entrant: the marker is set once we hold it).
  if [ -z "${DIQ_DC1_LOCK_HELD:-}" ]; then
    exec "$root/lab/windows/bin/with-dc1-lock" -- "$0" "$@"
  fi
  export WIN_LAB_DC_ADDR="${WIN_LAB_DC_ADDR:-192.168.1.9}" WIN_LAB_TLS_NAME="${WIN_LAB_TLS_NAME:-dc1.win.activediq.test}"
  svcpw="$(sed -n 's/^WIN_LAB_SVC_PASSWORD=//p' "$WIN_LAB_ENV" | head -1 | tr -d '"')"
  adminpw="$(sed -n 's/^WIN_LAB_ADMIN_PASSWORD=//p' "$WIN_LAB_ENV" | head -1 | tr -d '"')"
  [ -n "$svcpw" ] || die "WIN_LAB_SVC_PASSWORD missing from $WIN_LAB_ENV"
  export WIN_LAB_SVC_PASSWORD="$svcpw"
  ;;
samba)
  [ -f "$root/lab/.lab.env" ] || die "no lab/.lab.env: run make lab-up"
  # shellcheck disable=SC1091
  set -a; . "$root/lab/.lab.env"; set +a
  export LAB_CA="$root/lab/.lab-ca.pem"
  svcpw="$LAB_SVC_PASSWORD"; adminpw="$LAB_ADMIN_PASSWORD"
  # The Samba seed has no lab-user-01 (the Windows lab's name); create it, idempotently, in the managed OU.
  if ! docker exec "$LAB_CONTAINER" samba-tool user show lab-user-01 >/dev/null 2>&1; then
    docker exec "$LAB_CONTAINER" samba-tool user create lab-user-01 --random-password --userou=OU=Managed >/dev/null
  fi
  ;;
*) die "usage: $0 windows|samba" ;;
esac

export ADIQ_E2E_LAB="$mode" ADIQ_E2E_USER_SAM="${ADIQ_E2E_USER_SAM:-lab-user-01}"
export ADIQ_E2E_EVIDENCE_DIR="${ADIQ_E2E_EVIDENCE_DIR:-$root/factory/demos/evidence/T-0671}"
mkdir -p "$ADIQ_E2E_EVIDENCE_DIR"

dir="$(mktemp -d)"
trap '"$root/lab/e2e/boot-lab-server.sh" down "$dir" >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT
"$root/lab/e2e/boot-lab-server.sh" up "$dir" >/dev/null
# shellcheck disable=SC1091
. "$dir/env"

rc=0
(cd "$root/web" && npx playwright test walking-skeleton --retries=0 --reporter=list) || rc=$?

# Evidence: the server log, only if no lab secret is in it.
for s in "$svcpw" "$adminpw"; do
  if [ -n "$s" ] && grep -qF -- "$s" "$dir/server.log"; then die "a lab password is in the server log: not saving it"; fi
done
grep -v '^$' "$dir/server.log" > "$ADIQ_E2E_EVIDENCE_DIR/$mode-server.log"
if [ "$mode" = windows ]; then
  python3 "$root/lab/windows/bin/skeleton-proof-evidence" > "$ADIQ_E2E_EVIDENCE_DIR/windows-dc1-proof.txt" || rc=1
fi
echo "evidence: $ADIQ_E2E_EVIDENCE_DIR" >&2
exit "$rc"

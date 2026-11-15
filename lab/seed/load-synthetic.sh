#!/bin/sh
# T-2195: load N synthetic user candidates into a LAB Postgres (lab/seed/synth-candidates.sql). Lab/CI only.
#   ACTIVEDIQ_LAB_DSN=postgres://owner@host/db  lab/seed/load-synthetic.sh <tenant-uuid> <connection-uuid> <nc-uuid> [n=500000] [seed=a]
# The DSN carries the table-owner login (never committed; pass it from the environment or .pgpass).
# Prints the rows inserted and the wall time. Refuses a DSN that is not obviously a lab one unless LAB_SYNTH_ALLOW_HOST=1.
set -eu
here=$(dirname "$0")
[ $# -ge 3 ] || { echo "usage: $0 <tenant-uuid> <connection-uuid> <nc-uuid> [n] [seed]" >&2; exit 2; }
: "${ACTIVEDIQ_LAB_DSN:?set ACTIVEDIQ_LAB_DSN to the lab database owner DSN}"
n=${4:-500000}; seed=${5:-a}
case "$n" in ''|*[!0-9]*) echo "n must be a number" >&2; exit 2;; esac
for u in "$1" "$2" "$3"; do
  printf '%s' "$u" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || { echo "not a lower-case uuid: $u" >&2; exit 2; }
done
case "$ACTIVEDIQ_LAB_DSN" in
  *localhost*|*127.0.0.1*|*@lab*|*@postgres*|*@db*) ;;
  *) [ "${LAB_SYNTH_ALLOW_HOST:-}" = 1 ] || { echo "refusing: DSN host does not look like a lab database (LAB_SYNTH_ALLOW_HOST=1 to override)" >&2; exit 2; };;
esac
t0=$(date +%s)
psql "$ACTIVEDIQ_LAB_DSN" -v ON_ERROR_STOP=1 -q -f "$here/synth-candidates.sql"
rows=$(psql "$ACTIVEDIQ_LAB_DSN" -v ON_ERROR_STOP=1 -At -c "SELECT lab_synth.load_users('$1','$2','$3',$n,'$seed')")
echo "synthetic users inserted: $rows (requested $n, seed $seed) in $(( $(date +%s) - t0 ))s"

#!/bin/sh
# T-2195: the loader must refuse injection-shaped args and non-lab hosts BEFORE touching psql (a fake psql proves it is never reached).
set -u
here=$(cd "$(dirname "$0")" && pwd); bin=$(mktemp -d); trap 'rm -rf "$bin"' EXIT
printf '#!/bin/sh\necho PSQL-REACHED >&2; exit 99\n' >"$bin/psql"; chmod +x "$bin/psql"
U=11111111-1111-1111-1111-111111111111; fail=0
refuses() { out=$(PATH="$bin:$PATH" ACTIVEDIQ_LAB_DSN="$1" sh "$here/load-synthetic.sh" $U $U $U 5 "$2" 2>&1); rc=$?
  if [ $rc -ne 2 ] || echo "$out" | grep -q PSQL-REACHED; then echo "FAIL: not refused: dsn=$1 seed=$2"; fail=1; fi; }
refuses postgres://o@localhost/db "a'); DROP TABLE x; --"
refuses postgres://o@localhost/db 'UPPER'
refuses postgres://o@evil-localhost.example/db a
refuses postgres://o@prod-db.example.com/db a
out=$(PATH="$bin:$PATH" ACTIVEDIQ_LAB_DSN=postgres://o@localhost:5432/db sh "$here/load-synthetic.sh" $U $U $U 5 a 2>&1)
echo "$out" | grep -q PSQL-REACHED || { echo "FAIL: valid lab DSN/seed did not reach psql"; fail=1; }
[ $fail -eq 0 ] && echo "load-synthetic guards: ok"; exit $fail

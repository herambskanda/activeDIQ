#!/bin/sh
# Control experiment: the same three binds against a DC whose CBT enforcement is relaxed
# (ldap server require strong auth = allow_sasl_without_tls_channel_bindings). Shows the 'none' rejection in
# run-spike.sh is caused by the missing channel binding and by nothing else. Swaps the lab container for a
# one-off, then restores the strict one. Env as in run-spike.sh.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
C=${LAB_CONTAINER:-activediq-lab-t0023-dc-1}
PROJ=${C%-dc-1}
ENVF=$here/../../lab/.lab.env
CA=${SPIKE_CA:-$here/../../lab/.lab-ca.pem}
KT=${SPIKE_KEYTAB:-$here/.lab/spike.keytab}
out=${1:-logs/samba-control-relaxed.log}
restore() { docker stop t0023-ctl >/dev/null 2>&1 || true; docker start "$C" >/dev/null; }
trap restore EXIT
docker stop "$C" >/dev/null
docker run -d --rm --name t0023-ctl --hostname dc1.lab.activediq.test --cap-add SYS_ADMIN --env-file "$ENVF" -e LAB_TIER=small \
  -v "${PROJ}_lab-state:/var/lib/samba" -v "${PROJ}_lab-snapshots:/snapshots" \
  -p 127.0.0.1:1636:636 -p 127.0.0.1:1389:389 -p 127.0.0.1:1088:88/tcp -p 127.0.0.1:1088:88/udp \
  --entrypoint sh activediq-lab-dc:local -c \
  'sed "s/require strong auth = yes/require strong auth = allow_sasl_without_tls_channel_bindings/" /usr/local/bin/lab-entrypoint > /tmp/ep && exec sh /tmp/ep serve' >/dev/null
sleep 20
{
  echo "# T-0023 control run $(date -u +%FT%TZ): CBT enforcement relaxed"
  echo "# smb.conf: $(docker exec t0023-ctl grep -h 'strong auth' /etc/samba/smb.conf | tr -d '\t')"
  go build -o .lab/cbtbind ./cmd/cbtbind
  for cbt in none wrong server-end-point; do
    .lab/cbtbind -mode ldaps -addr 127.0.0.1:1636 -ca "$CA" -keytab "$KT" -cbt "$cbt" || true
  done
} 2>&1 | tee "$out"

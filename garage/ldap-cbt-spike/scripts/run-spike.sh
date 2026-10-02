#!/bin/sh
# Runs the whole spike against the T-0012 lab and writes the evidence log to logs/. See README.md.
# Needs: lab up (own project/ports as in README), scripts/setup-lab-account.sh already run.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
export SPIKE_CA=${SPIKE_CA:-$here/../../lab/.lab-ca.pem}
export SPIKE_KEYTAB=${SPIKE_KEYTAB:-$here/.lab/spike.keytab}
C=${LAB_CONTAINER:-activediq-lab-t0023-dc-1}
out=${1:-logs/samba-strong-auth.log}
{
  echo "# T-0023 spike run $(date -u +%FT%TZ)"
  echo "# samba: $(docker exec "$C" samba --version)"
  echo "# smb.conf: $(docker exec "$C" grep -h 'strong auth' /etc/samba/smb.conf | tr -d '\t')"
  echo "# go: $(go version)"
  echo "# go-krb5/krb5: $(go list -m github.com/go-krb5/krb5 | cut -d' ' -f2)  go-ldap: $(go list -m github.com/go-ldap/ldap/v3 | cut -d' ' -f2)"
  echo "# keytab etypes (client side): $(go run ./cmd/aeskeytab "$SPIKE_KEYTAB" /dev/null | head -1)"
  echo
  go test -count=1 -v ./... 2>&1
  echo
  echo "# raw CLI runs"
  go build -o .lab/cbtbind ./cmd/cbtbind
  for m in "ldaps 1636" "starttls 1389"; do
    mode=${m% *}; port=${m#* }
    for cbt in server-end-point none wrong; do
      .lab/cbtbind -mode "$mode" -addr "127.0.0.1:$port" -ca "$SPIKE_CA" -keytab "$SPIKE_KEYTAB" -cbt "$cbt" || true
    done
  done
} 2>&1 | tee "$out"

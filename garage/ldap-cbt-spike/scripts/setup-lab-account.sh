#!/bin/sh
# Creates the spike's bind account in the T-0012 Samba lab and writes an AES-only keytab to .lab/spike.keytab.
# Idempotent. The account password is random, lives only inside the lab container, and is never printed.
# Env: LAB_CONTAINER (default activediq-lab-t0023-dc-1). Lab state is restored by `make lab-reset`.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
C=${LAB_CONTAINER:-activediq-lab-t0023-dc-1}
REALM=LAB.ACTIVEDIQ.TEST
mkdir -p "$here/.lab"
docker exec "$C" sh -eu -c '
  P="$(head -c 24 /dev/urandom | base64 | tr -d "=+/")Aa1!"
  samba-tool user delete svc-cbt-spike >/dev/null 2>&1 || true
  samba-tool user create svc-cbt-spike "$P" --description="T-0023 spike (AES-only keytab)" >/dev/null 2>&1
  # 0x18 = AES128 + AES256 only (feasibility §2.4)
  ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<LDIF
dn: CN=svc-cbt-spike,CN=Users,DC=lab,DC=activediq,DC=test
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
LDIF
  samba-tool user setpassword svc-cbt-spike --newpassword="$P" >/dev/null 2>&1
  rm -f /tmp/spike-full.keytab
  samba-tool domain exportkeytab /tmp/spike-full.keytab --principal=svc-cbt-spike@'"$REALM"' >/dev/null 2>&1
'
docker cp "$C:/tmp/spike-full.keytab" "$here/.lab/spike-full.keytab"
docker exec "$C" rm -f /tmp/spike-full.keytab
(cd "$here" && go run ./cmd/aeskeytab .lab/spike-full.keytab .lab/spike.keytab)
rm -f "$here/.lab/spike-full.keytab"
chmod 600 "$here/.lab/spike.keytab"

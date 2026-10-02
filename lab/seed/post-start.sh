#!/bin/bash
# Seed steps that can only happen through the protocol, with Samba running (T-0012):
#   - delegate the service account on OU=Managed (never Domain Admins)
#   - lock out the accounts listed in the manifest by real failed binds past the threshold
set -Eeuo pipefail
MANIFEST="$1"
BASEDN="DC=lab,DC=activediq,DC=test"
export LDAPTLS_CACERT=/var/lib/samba/lab-tls/ca.pem
LDAPS=ldaps://dc1.lab.activediq.test:636

svc_sid=$(samba-tool user show svc-activediq --attributes=objectSid 2>/dev/null | sed -n 's/^objectSid: //p')
[ -n "$svc_sid" ] || { echo "[lab] service account SID not found" >&2; exit 1; }

# Delegation on OU=Managed, inherited down: create/delete/list/read/write on all child objects and
# reset password (User-Force-Change-Password) on user objects. No rights on anything else.
# Static SDDL constants — never built from input.
samba-tool dsacl set --objectdn="OU=Managed,$BASEDN" \
  --sddl="(A;CI;CCDCLCLORPWPDTRC;;;$svc_sid)(OA;CI;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;$svc_sid)" >/dev/null
echo "[lab] delegated OU=Managed to svc-activediq"

# Lockouts: 6 wrong passwords against a threshold of 5.
python3 - "$MANIFEST" <<'PY' | while read -r sam; do
import json, sys
for s in json.load(open(sys.argv[1]))["locked_samaccountnames"]:
    print(s)
PY
  for _ in 1 2 3 4 5 6; do
    ldapwhoami -H "$LDAPS" -x -D "$sam@lab.activediq.test" -w "wrong-password-for-lockout-seed" >/dev/null 2>&1 || true
  done
done
n=$(ldapsearch -H "$LDAPS" -x -D "svc-activediq@lab.activediq.test" -w "$LAB_SVC_PASSWORD" -b "OU=Managed,$BASEDN" \
  "(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))" dn 2>/dev/null | grep -c '^dn:' || true)
echo "[lab] locked-out accounts: $n"

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

# T-1070: primary-group oracle. primaryGroupID can only point at a group the user is a member of, so add the
# membership and switch the primary group. The directory itself drops the now-redundant explicit `member`
# value (AD and Samba both), so the user is a member ONLY through primaryGroupID (the case inventory.groups
# must not call empty). Neither AD nor Samba lets the `member` value be added back (samldb: "already set via
# primaryGroupID"), so a primary-group member is never also an explicit one.
python3 - "$MANIFEST" <<'PY' | while IFS='|' read -r gdn udn; do
import json, sys
for p in json.load(open(sys.argv[1])).get("oracle", {}).get("primary", []):
    print(f'{p["group"]}|{p["user"]}')
PY
  rid=$(ldapsearch -H "$LDAPS" -x -D "svc-activediq@lab.activediq.test" -w "$LAB_SVC_PASSWORD" -LLL -b "$gdn" -s base objectSid 2>/dev/null \
    | python3 -c "import sys,base64; l=[x for x in sys.stdin.read().split('\n') if x.startswith('objectSid::')]; b=base64.b64decode(l[0].split(':: ')[1]); print(int.from_bytes(b[-4:],'little'))")
  ldapmodify -H "$LDAPS" -x -D "svc-activediq@lab.activediq.test" -w "$LAB_SVC_PASSWORD" >/dev/null <<LDIF || { echo "[lab] primary group step failed for $udn" >&2; exit 1; }
dn: $gdn
changetype: modify
add: member
member: $udn

dn: $udn
changetype: modify
replace: primaryGroupID
primaryGroupID: $rid
LDIF
done
echo "[lab] primary-group oracle applied"

#!/bin/bash
# Runs INSIDE the lab container (fed to `bash -s` by verify.sh). See verify.sh.
export LDAPTLS_CACERT=/var/lib/samba/lab-tls/ca.pem
H=ldaps://dc1.lab.activediq.test:636
B="OU=Managed,DC=lab,DC=activediq,DC=test"
S="svc-activediq@lab.activediq.test"
L() { ldapsearch -H "$H" -x -D "$S" -w "$LAB_SVC_PASSWORD" -LLL -o ldif-wrap=no "$@"; }
n() { grep -c '^dn:' || true; }
M=/var/lib/samba/lab-manifest.json
j() { python3 -c "import json,sys; d=json.load(open('$M')); print(eval(sys.argv[1]))" "$1"; }
USERS='(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))'

# Baseline digest of everything visible under OU=Managed (non-operational attributes), taken BEFORE any
# check below binds as a seeded user (binds change lastLogon/logonCount/badPwdCount — and the reset undoes them).
echo "digest $(L -b $B -s sub '(objectClass=*)' '*' | grep -v '^$' | sort | sha256sum | cut -c1-16) -"
echo "users $(L -b $B "$USERS" dn | n) $(j 'd["counts"]["users"]')"
echo "computers $(L -b $B '(objectClass=computer)' dn | n) $(j 'd["counts"]["computers"]')"
echo "groups $(L -b $B '(objectClass=group)' dn | n) $(j 'd["counts"]["groups"]')"
echo "ous_under_managed $(L -b $B '(objectClass=organizationalUnit)' dn | n) $(( $(j 'd["counts"]["ous"]') - 1 ))"
for st in disabled never_expires must_change; do
  case $st in
    disabled) f='(userAccountControl:1.2.840.113556.1.4.803:=2)';;
    never_expires) f='(userAccountControl:1.2.840.113556.1.4.803:=65536)';;
    must_change) f='(pwdLastSet=0)';;
  esac
  want=$(j "d['counts']['user_states']['$st']")
  # edge-case users and the service account are outside these counts only if they do not match the filter
  echo "state_$st $(L -b $B "(&$USERS$f)" dn | n) $want"
done
echo "locked_users $(L -b $B "(&$USERS(lockoutTime>=1))" dn | n) $(j 'len(d["locked_samaccountnames"])')"
BIG=$(j 'd["counts"]["big_group_members"]')
# Explicit ranged retrieval (what a correct connector does) pages 0-1499, then 1500-*.
echo "big_group_page1_label $(L -b $B '(cn=GG-Big)' 'member;range=0-1499' | sed -n 's/^member;range=\([0-9]*-[0-9*]*\):.*/\1/p' | sort -u) $(j '"0-1499" if d["counts"]["big_group_members"] > 1500 else "0-*"')"
echo "big_group_page1_values $(L -b $B '(cn=GG-Big)' 'member;range=0-1499' | grep -c '^member;range=') $(( BIG > 1500 ? 1500 : BIG ))"
echo "big_group_page2_values $(L -b $B '(cn=GG-Big)' 'member;range=1500-2999' | grep -c '^member;range=') $(( BIG > 1500 ? BIG - 1500 : 0 ))"
# KNOWN SAMBA GAP (pinned so a Samba upgrade that changes it is noticed): a plain `member` read returns every
# value unranged. Windows ranges a >1500-value attribute on its own (MaxValRange) [UNVERIFIED value], so a
# connector that forgets to page passes on Samba and fails on Windows. See runbook "What the lab cannot test".
echo "samba_gap_plain_member_unranged $(L -b $B '(cn=GG-Big)' member | grep -c '^member:') $BIG"
echo "edge_users_found $(for sam in $(j '" ".join(e["sam"] for e in d["edge_users"])'); do L -b $B "(sAMAccountName=$sam)" dn; done | n) $(j 'len(d["edge_users"])')"
echo "cn_64_chars $(L -b $B "(cn=$(printf 'A%.0s' $(seq 64)))" dn | n) 1"
echo "non_bmp_user $(L -b $B '(sAMAccountName=eemoji)' displayName | grep -c '^displayName::') 1"
echo "cycle_a_has_b $(L -b $B '(cn=GG-Cycle-A)' member | grep -c 'GG-Cycle-B') 1"
echo "cycle_c_has_a $(L -b $B '(cn=GG-Cycle-C)' member | grep -c 'GG-Cycle-A') 1"
echo "empty_group $(L -b $B '(cn=GG-Empty)' member | grep -c '^member') 0"
echo "all_staff_direct_members $(L -b $B '(cn=GG-All-Staff)' member | grep -c '^member:') $(j 'd["counts"]["departments"]')"
echo "all_staff_transitive_users $(L -b $B "(&$USERS(memberOf:1.2.840.113556.1.4.1941:=CN=GG-All-Staff,OU=OrgGroups,$B))" dn | n) $(j 'd["counts"]["generated_users"]')"
# password ages as seeded (relative to the seed reference day), see manifest samples
for st in pwd_expiring pwd_expired stale; do
  sam=$(j "d['samples']['$st'][0]['sam']"); age=$(j "d['samples']['$st'][0]['pwd_age_days']")
  got=$(L -b $B "(sAMAccountName=$sam)" pwdLastSet | sed -n 's/^pwdLastSet: //p')
  echo "pwd_age_days_$st $(python3 - "$got" "$(j 'd["now"]')" <<'PY'
import math, sys
print(math.ceil((int(sys.argv[2]) - (int(sys.argv[1]) / 1e7 - 11644473600)) / 86400))
PY
) $age"
done
# a seeded user can bind with the lab password over LDAPS; a wrong password is rejected; a locked user is rejected
u=$(j 'd["samples"]["normal"][0]["sam"]')
ldapwhoami -H "$H" -x -D "$u@lab.activediq.test" -w "$LAB_USER_PASSWORD" >/dev/null 2>&1 && echo "seeded_user_bind 1 1" || echo "seeded_user_bind 0 1"
ldapwhoami -H "$H" -x -D "$u@lab.activediq.test" -w "not-the-password" >/dev/null 2>&1 && echo "wrong_password_rejected 0 1" || echo "wrong_password_rejected 1 1"
lk=$(j 'd["locked_samaccountnames"][0]')
ldapwhoami -H "$H" -x -D "$lk@lab.activediq.test" -w "$LAB_USER_PASSWORD" >/dev/null 2>&1 && echo "locked_user_rejected 0 1" || echo "locked_user_rejected 1 1"
# hardened-DC behaviour: simple bind over plain LDAP is refused
ldapwhoami -H ldap://127.0.0.1:389 -x -D "$S" -w "$LAB_SVC_PASSWORD" >/dev/null 2>&1 && echo "plain_ldap_simple_bind_refused 0 1" || echo "plain_ldap_simple_bind_refused 1 1"
# delegation: the service account can create and delete under OU=Managed and cannot create elsewhere
printf 'dn: CN=verify-probe,OU=Empty-01,%s\nobjectClass: group\nsAMAccountName: verify-probe\n' "$B" > /tmp/probe.ldif
ldapadd -H "$H" -x -D "$S" -w "$LAB_SVC_PASSWORD" -f /tmp/probe.ldif >/dev/null 2>&1 && echo "svc_can_create_in_managed 1 1" || echo "svc_can_create_in_managed 0 1"
ldapdelete -H "$H" -x -D "$S" -w "$LAB_SVC_PASSWORD" "CN=verify-probe,OU=Empty-01,$B" >/dev/null 2>&1 && echo "svc_can_delete_in_managed 1 1" || echo "svc_can_delete_in_managed 0 1"
printf 'dn: CN=verify-probe,CN=Users,DC=lab,DC=activediq,DC=test\nobjectClass: group\nsAMAccountName: verify-probe\n' > /tmp/probe2.ldif
ldapadd -H "$H" -x -D "$S" -w "$LAB_SVC_PASSWORD" -f /tmp/probe2.ldif >/dev/null 2>&1 && echo "svc_denied_outside_managed 0 1" || echo "svc_denied_outside_managed 1 1"

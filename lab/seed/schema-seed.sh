#!/bin/bash
# Lab-only schema seed (T-0308): one custom attributeSchema flagged searchFlags = 0x200 (512) ONLY, the
# CC-SCH-02 custom case. Samba refuses schema adds over LDAP, so this loads offline into a STOPPED
# sam.ldb with ldbadd. The `dsdb:schema update allowed` override exists here and nowhere else — it is a
# test-fixture switch for a throwaway lab database and must never appear in product code (a CI grep
# enforces that: lab/tests/test_schema_seed.sh).
# Idempotent: re-running when the attribute exists is a no-op. Static constants only — nothing is
# built from input.
set -Eeuo pipefail
SAM="${1:?usage: schema-seed.sh <path to sam.ldb>}"
BASEDN="DC=lab,DC=activediq,DC=test"
SCHEMA="CN=Schema,CN=Configuration,$BASEDN"
NAME="activediqLabConfidential"
DN="CN=$NAME,$SCHEMA"

if ldbsearch -H "$SAM" -b "$DN" -s base "(objectClass=attributeSchema)" dn 2>/dev/null | grep -q '^dn: '; then
  echo "[lab] schema seed: $NAME already present"
  exit 0
fi

ldif=$(mktemp)
trap 'rm -f "$ldif"' EXIT
cat > "$ldif" <<LDIF
dn: $DN
objectClass: top
objectClass: attributeSchema
cn: $NAME
lDAPDisplayName: $NAME
attributeID: 1.2.840.113556.1.8000.2554.99999.4.1
attributeSyntax: 2.5.5.12
oMSyntax: 64
isSingleValued: TRUE
searchFlags: 512
showInAdvancedViewOnly: TRUE
adminDisplayName: $NAME
adminDescription: activeDIQ lab fixture - searchFlags 0x200 (RODC filtered attribute set) only
objectCategory: CN=Attribute-Schema,$SCHEMA
LDIF
ldbadd -H "$SAM" --relax --option="dsdb:schema update allowed=true" "$ldif" >/dev/null
echo "[lab] schema seed: added $NAME (searchFlags 0x200)"

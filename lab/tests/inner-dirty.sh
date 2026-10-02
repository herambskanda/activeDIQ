#!/bin/bash
# Runs INSIDE the lab container (fed to `bash -s` by verify.sh). See verify.sh.
export LDAPTLS_CACERT=/var/lib/samba/lab-tls/ca.pem
H=ldaps://dc1.lab.activediq.test:636; B="OU=Managed,DC=lab,DC=activediq,DC=test"; S="svc-activediq@lab.activediq.test"
printf 'dn: CN=reset-probe,OU=Empty-02,%s\nobjectClass: group\nsAMAccountName: reset-probe\n' "$B" | ldapadd -H "$H" -x -D "$S" -w "$LAB_SVC_PASSWORD"
ldapdelete -H "$H" -x -D "$S" -w "$LAB_SVC_PASSWORD" "CN=GG-Empty,OU=OrgGroups,$B"
printf 'dn: CN=GG-Cycle-A,OU=OrgGroups,%s\nchangetype: modify\ndelete: member\n' "$B" | ldapmodify -H "$H" -x -D "$S" -w "$LAB_SVC_PASSWORD"
printf 'dn: CN=Smith\\, John,OU=EdgeCases,%s\nchangetype: modify\nreplace: description\ndescription: dirtied\n' "$B" | ldapmodify -H "$H" -x -D "$S" -w "$LAB_SVC_PASSWORD"

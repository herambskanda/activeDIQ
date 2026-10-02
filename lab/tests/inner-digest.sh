#!/bin/bash
# Runs INSIDE the lab container (fed to `bash -s` by verify.sh). See verify.sh.
export LDAPTLS_CACERT=/var/lib/samba/lab-tls/ca.pem
ldapsearch -H ldaps://dc1.lab.activediq.test:636 -x -D svc-activediq@lab.activediq.test -w "$LAB_SVC_PASSWORD" -LLL -o ldif-wrap=no -b OU=Managed,DC=lab,DC=activediq,DC=test -s sub '(objectClass=*)' '*' | grep -v '^$' | sort | sha256sum | cut -c1-16

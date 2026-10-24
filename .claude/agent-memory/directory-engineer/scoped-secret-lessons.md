---
name: scoped-secret-lessons
description: ScopedSearch/ReadSecret/SecretAttrs lab facts — Samba schema writes refused, no referral class, userPassword readable by svc
metadata:
  type: reference
---

- Samba refuses attributeSchema adds over LDAP ("updates are not allowed"): a custom 0x200-only attribute needs a seed (ldbadd) addition (T-0308). attributeID OID arcs must have no leading zeros.
- Samba has no `referral` objectClass: LF-32 needs a fault-injecting proxy (T-0309).
- Lab schema has 22 attributes with searchFlags 0x80/0x200/0x1000; svc-activediq can read `userPassword`; `unicodePwd` never returns (SECRET_NOT_SET).
- `Schema.With` rebuilds from the stored list; secrets are loaded in `Open` (loadSecretAttrs), static names always marked even if absent from the forest.
- `make lab-up` takes ~5 min from cold; run it in the background at the start of a lab ticket.

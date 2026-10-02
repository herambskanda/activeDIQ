---
name: gssapi-cbt-lessons
description: Craft lessons from the T-0023 GSSAPI/channel-binding spike (go-krb5, Samba lab, AES keytab)
metadata:
  type: reference
---

- go-krb5/krb5 v0.1.0 has NO channel binding or SASL layers (ADR-0001 was wrong); `main` (since 2026-08) has both. Always
  compile-probe a library claim before building on it. Spike: `garage/ldap-cbt-spike`, findings in build-feasibility/.
- AD allows SASL on TLS but no SASL sign/seal on top: pick layer "none" (0x01) in the RFC 4752 second round.
- Samba 4.22 default `ldap server require strong auth = yes` already enforces CBT; relaxed mode is
  `allow_sasl_without_tls_channel_bindings`. Wrong binding is rejected in both modes (80090346).
- Samba `exportkeytab` includes RC4: filter to etype 17/18 for an honest AES-only test.
- go-ldap's `gssapi` package bundles gokrb5 v8 with the SSPI client: importing it on Windows links gokrb5.
- Lab gotcha: lab may be running from a deleted worktree (no `.lab.env`); use own compose project + shifted ports.
- zsh does not word-split `set -- $var`; use explicit args in test scripts.

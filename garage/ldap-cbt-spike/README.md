# ldap-cbt-spike

- **OWNER:** directory-engineer
- **TICKET:** T-0023 (ADR-0001 risk spike)
- **EXPIRES:** 2026-12-31. After that, delete it. T-0080 re-implements the adapter in `internal/connector/kerberos`;
  T-0133 reuses these tests against WS2025 and must land first, or this expiry moves.
- **QUESTION:** can a pure-Go client (go-ldap + go-krb5/krb5) do a SASL/GSSAPI bind with a `tls-server-end-point`
  channel binding, using an AES-only keytab, over LDAPS and StartTLS, against a DC that requires it?
- **ANSWER:** yes on Samba 4.22 (`ldap server require strong auth = yes`). Findings:
  `knowledge/development/architecture/build-feasibility/t-0023-ldap-gssapi-cbt-spike.md`. Windows is the open gate (T-0133).

Nothing here is imported by product code. Own Go module (`go.mod`), so its dependencies do not enter the root module.

## What is in it

| Path | What |
| --- | --- |
| `krb5gssapi/` | `Client`, an `ldap.GSSAPIClient` on go-krb5/krb5 with RFC 5929 channel binding; unit tests |
| `cmd/cbtbind/` | CLI + integration tests: LDAPS/StartTLS × binding `server-end-point` / `none` / `wrong` |
| `cmd/aeskeytab/` | strips non-AES entries from a keytab |
| `scripts/` | `setup-lab-account.sh`, `run-spike.sh`, `control-relaxed.sh`, `probe-v010.sh` |
| `logs/` | evidence: `samba-strong-auth.log`, `samba-control-relaxed.log`, `probe-krb5-v0.1.0.log` |
| `cmd/sspiprobe/` | `GOOS=windows` compile check of go-ldap's SSPI client (cannot run here) |

## Reproduce

The lab of T-0012 normally owns ports 636/389/88. To avoid a clash, the spike used its own compose project on shifted ports:

```sh
export COMPOSE_PROJECT_NAME=activediq-lab-t0023 LAB_TIER=small LAB_LDAPS_PORT=1636 LAB_LDAP_PORT=1389 \
       LAB_KRB_PORT=1088 LAB_GC_LDAPS_PORT=13269 LAB_KPASSWD_PORT=1464
make lab-up                                    # from the repo root
sh garage/ldap-cbt-spike/scripts/setup-lab-account.sh   # svc-cbt-spike + AES-only keytab (.lab/, gitignored)
sh garage/ldap-cbt-spike/scripts/run-spike.sh           # unit + integration tests + raw runs -> logs/
sh garage/ldap-cbt-spike/scripts/control-relaxed.sh     # same binds with CBT enforcement relaxed
sh garage/ldap-cbt-spike/scripts/probe-v010.sh          # released v0.1.0 cannot build the adapter
```

Certificate verification is on in every run (the lab CA, server name `dc1.lab.activediq.test`). The KDC and DC are
reached at 127.0.0.1; the SPN `ldap/dc1.lab.activediq.test` comes from the server name, not from DNS.

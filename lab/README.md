# lab/ — the AD lab (T-0012)

A Samba 4 AD DC in Docker with LDAPS and a seeded synthetic organisation (≈5,000 users, 14 department
OUs, nested/circular/huge groups, computers, disabled/stale/locked/expired accounts, edge-case names).
**Test infrastructure only** — Samba is GPL-3.0 and is never shipped.

```bash
make lab-up      # build + provision + seed + start; prints connection details
make lab-test    # generator unit tests + live checks + reset round trip
make lab-reset   # exact seeded state again (seconds)
make lab-down | lab-destroy | lab-rebuild | lab-status | lab-logs | lab-shell
```

Entra lab (a Microsoft 365 Developer sandbox, dev-only): `make entra-lab-bootstrap` (CEO, device-code
sign-in, once per sandbox) then `make entra-lab-verify`. Scripts `bin/entra-lab-*`, permission set
`entra/permissions.txt`, handover files `.entra-lab.env` / `.entra-lab.pem` (0600, gitignored).

Full runbook (accounts, ports, what is seeded, **what Samba cannot test**, troubleshooting):
`knowledge/development/runbooks/ad-lab.md`.

| Path | What |
| --- | --- |
| `docker-compose.yml`, `lab.mk` | the stack and the `make lab-*` targets (root `Makefile` includes `lab.mk`) |
| `samba/` | image recipe (`Dockerfile`) and `entrypoint.sh` (init / serve / restore / healthcheck) |
| `seed/generate.py` | deterministic seed generator (LDIF + manifest); `seed/post-start.sh` does protocol-level steps; `seed/schema-seed.sh` adds the 0x200-only custom schema attribute (lab-only override) |
| `tests/` | `test_generate.py` (unit, no Docker), `verify.sh` (live, with `inner-*.sh` run in the container) |
| `bin/` | `lab-env` (random credentials), `lab-info` |

Generated and gitignored: `.lab.env` (credentials), `.lab-ca.pem` (trust anchor). Credentials are random per
lab and never committed. Fixtures live only here; product code never imports them.

## Fault proxy (T-0309)

Samba cannot create referral objects, so LF-32 / CC-SRCH-10 is proven by injection:
`internal/connector/ad/ldapfault_test.go` is a test-only LDAPS proxy that relays every message and plants a
SearchResultReference in scoped searches. `referral_fault_test.go` runs it over an in-process stand-in
(no lab needed); `ldapfault_lab_test.go` (tag `lab`, `make lab-test-connector`) runs it in front of the
Samba lab. The real-Windows-DC case is `TestReferralWindowsRealDCPending`: it shows as SKIP/PENDING in
`go test -v` output until the Windows lab can host a referral.

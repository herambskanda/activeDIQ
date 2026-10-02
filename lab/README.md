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

Full runbook (accounts, ports, what is seeded, **what Samba cannot test**, troubleshooting):
`knowledge/development/runbooks/ad-lab.md`.

| Path | What |
| --- | --- |
| `docker-compose.yml`, `lab.mk` | the stack and the `make lab-*` targets (root `Makefile` includes `lab.mk`) |
| `samba/` | image recipe (`Dockerfile`) and `entrypoint.sh` (init / serve / restore / healthcheck) |
| `seed/generate.py` | deterministic seed generator (LDIF + manifest); `seed/post-start.sh` does protocol-level steps |
| `tests/` | `test_generate.py` (unit, no Docker), `verify.sh` (live, with `inner-*.sh` run in the container) |
| `bin/` | `lab-env` (random credentials), `lab-info` |

Generated and gitignored: `.lab.env` (credentials), `.lab-ca.pem` (trust anchor). Credentials are random per
lab and never committed. Fixtures live only here; product code never imports them.

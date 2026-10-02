---
title: "Runbook: the AD lab (Samba 4 AD DC in Docker)"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: devops-engineer
ticket: T-0012
---

# Runbook: the AD lab (Samba 4 AD DC in Docker)

One command gives you a real Active Directory-compatible domain controller with LDAPS and a seeded
organisation of about 5,000 users. It is the base for every directory test and demo. Samba is
**GPL-3.0 and test-only**: the image stays on your machine or CI runner and is never pushed,
bundled or shipped (licence register: `knowledge/business/licensing/open-source-license-register.md`).

Companion references: `.claude/skills/testing-playbook/reference/ad-lab.md` (tiers, Windows and Entra
labs), `knowledge/development/architecture/build-feasibility/ad-technical-feasibility.md` §5.2
(Samba fidelity). Code: `lab/` (README there is the 30-second version).

## 1. Quick start

Needs Docker with Compose v2 (Docker Desktop, OrbStack or Linux Docker), `openssl` and `make` on the
host. Nothing else.

```bash
make lab-up        # first run: build image, provision, seed, snapshot, start (111 s measured, no image cache); later runs: seconds
make lab-test      # unit tests of the seed generator + live checks + a reset round trip
make lab-reset     # back to the exact seeded state (~7 s)
make lab-down      # stop (state kept)      make lab-destroy   # delete everything incl. credentials
make lab-rebuild   # destroy, then provision and seed from scratch
make lab-status    # health + connection details       make lab-shell    # shell in the DC container
```

`make lab-up` ends by printing the connection details. Credentials are random per lab, written to
`lab/.lab.env` (gitignored, mode 0600), and never printed. The DC's CA certificate is exported to
`lab/.lab-ca.pem`.

| Thing | Value |
| --- | --- |
| Domain / NetBIOS | `lab.activediq.test` (RFC 2606 reserved) / `LAB` |
| Base DN, product's OU | `DC=lab,DC=activediq,DC=test`, `OU=Managed,DC=lab,DC=activediq,DC=test` |
| LDAPS | `ldaps://localhost:636` (cert SANs `dc1.lab.activediq.test`, `lab.activediq.test`, `localhost`, `127.0.0.1`, `::1`) |
| Other ports (loopback only) | 3269 GC over TLS, 389 LDAP (StartTLS only — simple bind refused), 88 Kerberos, 464 kpasswd |
| Product service account | `svc-activediq@lab.activediq.test`, password `LAB_SVC_PASSWORD`. Delegated on `OU=Managed` only (never Domain Admins) |
| Seeded users | `<sAMAccountName>@lab.activediq.test`, password `LAB_USER_PASSWORD` (same for all, per lab) |
| Seeding/admin identity | `Administrator`, password `LAB_ADMIN_PASSWORD` — used for provisioning only, not by product code |

Override a port that clashes with something on your machine: `LAB_LDAPS_PORT=1636 make lab-up`
(also `LAB_GC_LDAPS_PORT`, `LAB_LDAP_PORT`, `LAB_KRB_PORT`, `LAB_KPASSWD_PORT`).

**Always connect over LDAPS with `lab/.lab-ca.pem` trusted. Never skip certificate verification,
not even in tests** — the habit leaks into product code.

```bash
LDAPTLS_CACERT=lab/.lab-ca.pem ldapsearch -H ldaps://localhost:636 -x \
  -D svc-activediq@lab.activediq.test -w "$LAB_SVC_PASSWORD" \
  -b OU=Managed,DC=lab,DC=activediq,DC=test -s one dn      # after: . lab/.lab.env
```

## 2. What is seeded (tier `standard`, seed `20261002`)

Everything is synthetic: names come from fixed lists, mail is `@example.com`, and the company is
invented. Same seed + same reference day gives byte-identical LDIF
(`lab/tests/test_generate.py`). The generator is `lab/seed/generate.py`; `manifest.json`, written
beside the LDIF and kept in the lab at `/var/lib/samba/lab-manifest.json`, lists the expected
counts that `make lab-test-live` asserts against the live directory.

| Content | Detail |
| --- | --- |
| OUs | `OU=Managed` → 14 departments (Engineering … Research), each with `Users` (and `Users/Contractors`), `Computers`, `Groups`; plus `Servers`, `OrgGroups`, `EdgeCases`, 12 empty OUs, `Ops, Field` (comma) and `Sales #Q4+Plan` (`#`, `+`). `OU=ServiceAccounts` sits outside `Managed` |
| Users | 5,000 generated + 17 edge-case users + the service account |
| User states | 3 % disabled, 8 % stale (no logon 180–900 days), 2 % account expired, 1 % expiring within 30 days, 2 % password never expires, 0.5 % must change, 2 % password expired (> 90 days), 2 % password expiring (80–89 days), 2 % never logged on, **25 locked out** (real failed binds past the threshold), the rest normal. Each department's first user is its manager |
| Computers | 1,500 workstations (≈ 3 % disabled, ≈ 10 % stale) + 40 servers |
| Groups | ≈ 150: per department `GG-<Dept>-All`, `-Managers`, project groups, a domain-local share group (global→domain-local nesting) and a distribution group; `GG-All-Staff` and `GG-Leadership` (nested); a 6-deep nesting chain; **circular** `GG-Cycle-A→B→C→A`; `GG-Empty`; **`GG-Big` with 3,000 members** (ranged retrieval); groups with specials and Unicode in the CN |
| Edge-case users (`OU=EdgeCases`) | comma, leading `#`, `+`, double quotes, backslash, `<>;=`, `()*`, accents NFC and NFD, CJK, non-BMP (emoji, math letters), 64-character CN, 20-character sAMAccountName, dot/hyphen, leading and trailing space in the CN |
| Password policy | complexity on, max age **90 days**, lockout after **5** bad passwords (until an admin unlocks) |

Ages ("stale", "expiring") are relative to the day the lab was **built** (`manifest.json` → `now`).
A snapshot ages like a real directory: after about a month the "expiring" users have expired. Run
`make lab-rebuild` to refresh, or write your own timestamps in tests. Set `LAB_SEED_NOW=<unix>` for a
pinned, reproducible build.

`LAB_TIER=small make lab-up` builds the 300-user tier for faster CI loops (`lab-destroy` first when switching tier; the tier is part of the seed version). The `scale`
tier (50k users) and a second DC (`2dc`) are not built yet — see §7.

## 3. How it works

- **Image** (`lab/samba/Dockerfile`): Debian 13 pinned by digest; Debian's `samba` 4.22.x plus
  `ldb-tools`, `ldap-utils`, `faketime`. Runs on linux/arm64 (Apple silicon) and linux/amd64.
- **State** lives in two named Docker volumes, not a macOS bind mount, because Samba needs
  xattr/ACL support on sysvol: `activediq-lab_lab-state` (the live `/var/lib/samba`) and
  `activediq-lab_lab-snapshots` (`state.tar`).
- **Init** (`entrypoint.sh init`, only when the volume is empty or the seed version changed):
  provision → generate our own CA and server cert with SANs → load the seed **offline** into the
  stopped `sam.ldb` with `ldbadd`/`ldbmodify` (about a minute for 5,000 users; far faster than
  per-user `samba-tool`) → start Samba → delegate `OU=Managed` and lock out the listed accounts through the
  protocol → stop → tar the state as the snapshot.
- **Reset** (`make lab-reset`): stop the DC, wipe the state, untar the snapshot, start. The
  directory is bit-for-bit what it was at the end of init (same GUIDs, SIDs, USNs, timestamps).
  A fresh `lab-rebuild` yields identical *content* but new GUIDs/SIDs/timestamps — never hard-code
  those in tests.
- **Seed version** = hash of the generator, post-start script, entrypoint and Dockerfile + tier + the
  credentials file's id. Changing any of them makes the next `make lab-up` rebuild the state;
  a stale snapshot is never reused.
- **Why faketime:** Samba accepts `pwdLastSet` only as 0 or -1 over LDAP/ldb, so password ages are
  produced by adding each user while the clock reads the password-set day (`loadplan.txt`, one
  `ldbadd` per age bucket). `lastLogon`, `lastLogonTimestamp`, `accountExpires` are written
  directly. As a side effect `whenCreated` of a seeded user or computer is its password-set day; the service account and edge-case users carry the real build time.
- **Lab audit log:** Samba's JSON auth/dsdb audit lines go to the container log
  (`make lab-logs`). It is not a Windows event log (§5).

## 4. Using the lab in tests

- Integration tests connect with the lab CA and the **service account**, not Administrator, so
  permission errors appear as they will at customers.
- A test that writes creates its own OU under `OU=Managed` (`OU=t-<test>-<rand>`) and deletes it;
  run `make lab-reset` between suites. Never rely on GUIDs, SIDs, USNs or `whenCreated`.
- Tests may not edit the seed to make a test pass: change `generate.py` (this changes the seed
  version) and add a unit test.
- Tests needing Windows are tagged (`windowslab`) so CI on Samba skips them loudly (§5).

## 5. What the lab cannot test — and what needs a Windows lab

Samba's fidelity table is in feasibility §5.2. Below, **Measured** means we observed it in this lab
(`make lab-test-live` pins it); the rest comes from the cited docs and is `[UNVERIFIED]` until
proven in a Windows lab.

| Not covered by the Samba lab | Why it matters | Needs a Windows lab for |
| --- | --- | --- |
| **Windows Security/System event logs** and audit policy (4720, 4738, 4740, 4625, 5136, 4662…) — Samba writes JSON audit logs instead ([ports/audit](https://wiki.samba.org/index.php/Samba_AD_DC_Port_Usage)) | Event collectors and ADAudit-class reports | event pipeline and audit tickets; T-0026 (ingest benchmark) can use recorded EVTX fixtures instead |
| **ADWS (port 9389) and the `ActiveDirectory` PowerShell module** — absent from Samba's port list ([source](https://wiki.samba.org/index.php/Samba_AD_DC_Port_Usage)) | The sidecar tier (ADR-0001) and anything calling AD cmdlets | the PowerShell/sidecar tickets |
| **Password filter in LSASS, credential provider in LogonUI**, LSA protection, Authenticode/LSA signing | Native tier | T-0024, T-0025, T-0027 |
| **GPO client-side processing**, `gpresult`-style reporting; SYSVOL is not replicated between Samba DCs `[UNVERIFIED]` | GPO reporting | GPO tickets |
| **WS2025 hardening defaults** (confidential-attribute encryption, SAMR blocking, RC4 TGT refusal, LDAP signing/CBT "Always" enforcement as Windows implements it) | Connector hardening interop | T-0023 (LDAP GSSAPI bind with channel binding): Samba ≥ 4.21 supports channel bindings, so develop against Samba, then prove on WS2025 |
| **Windows diagnostic strings and error codes**, exact referral/`busy` behaviour under load | User-facing error mapping | per-feature, in the platform matrix |
| **Name comparison rules** — AD ignores case, width, kana and accents (MS-ADTS sort keys); Samba may not. A uniqueness test can **false-pass** on Samba (José vs Jose) — see `knowledge/memory/lessons.md` | Uniqueness checks in the safe primitives and create/rename flows | any uniqueness or rename test |
| **Unranged multi-valued reads (Measured):** a plain read of `member` on `GG-Big` returns all 3,000 values on Samba; Windows ranges a large attribute by itself (MaxValRange, default value `[UNVERIFIED]`). Explicit `member;range=0-1499` / `1500-*` paging works on Samba | A connector that forgets to page **passes on Samba and fails on Windows**. Test paging with explicit ranges, and review that code never reads multi-valued attributes unranged | the group-membership connector ticket |
| Recycle Bin undelete parity, multi-domain forests and trusts, functional levels above 2008 R2 (opt-in), Windows LAPS, AD FS, AD CS | Lifecycle, cross-forest and CA features | respective tickets |
| Domain Controller **replication** — the lab has one DC, so `uSNChanged`/DirSync tests see one USN space and no per-DC attributes | Sync correctness across DCs | the `2dc` tier (§7), then Windows |
| **Scale** — 5k users is not 50k+ | Performance budgets | `scale` tier (§7) |

The Windows lab and the Entra test tenant cost money and need accounts, so they are **CEO matters**
(ADR/decision first). Until they exist, Windows-only tests are written, tagged, and recorded as
**unverified** in the ticket — never claimed as passing.

## 6. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Docker daemon is not running` | Start Docker Desktop / OrbStack (`orbctl start`) |
| `port is already allocated` on 636/88/389 | Another service owns it: set `LAB_LDAPS_PORT`, `LAB_KRB_PORT`… (§1) |
| `make lab-up` seems to re-seed every time | `lab/.lab.env` or the lab files changed (new seed version) — expected once |
| LDAPS handshake fails with certificate errors | Use `lab/.lab-ca.pem` and connect as `localhost`, `127.0.0.1` or `dc1.lab.activediq.test` (add `127.0.0.1 dc1.lab.activediq.test` to `/etc/hosts` for the last) |
| `Strong(er) authentication required` on port 389 | Intended: simple bind over plain LDAP is refused like on a hardened DC. Use LDAPS or StartTLS |
| Container unhealthy | `make lab-logs`; if the state is damaged `make lab-reset`; as a last resort `make lab-rebuild` |
| Kerberos from the host | Samba's DNS is not exposed. Add the DC name to `/etc/hosts` and point `krb5.conf` `kdc = 127.0.0.1` (port `LAB_KRB_PORT`) |

CI: the same commands work on a Linux runner with Docker; wiring `make lab-test` into the pipeline
belongs to the CI ticket (T-0015).

## 7. Known limits and follow-ups

- Samba is the Debian 13 package (4.22.x). The feasibility doc names 4.25 as latest stable; newer
  Samba (e.g. 4.24's AES-only enctype default) needs a build from source or a newer base — a
  follow-up if a test needs it.
- Tiers `scale` (50k users, 5,000 groups, 500 OUs) and `2dc` (second DC) from the testing playbook
  are follow-up tickets; the generator already takes a tier table and per-tier counts.
- Snapshots live in a Docker volume. CI caching of snapshots by seed version (playbook §4) is part
  of the CI integration ticket.
- Lab ages drift with real time (§2); `make lab-rebuild` refreshes.

---
name: testing-playbook
description: How activeDIQ is tested and how a worker proves a change — test pyramid, Samba AD lab in Docker, Windows and Entra labs, Playwright evidence, deterministic fixtures, flaky-test policy. Use for tests, fixtures, lab tooling or ticket evidence.
---

# Testing playbook

A test that passes against a mock of AD proves nothing about AD. activeDIQ is tested against a
real directory server from the first connector ticket, and every claim in a ticket note is
backed by a command and its output. Tooling and paths are **provisional until ADR-0001**.
Owner of the lab and shared fixtures: `test-engineer` (lab infrastructure with `devops-engineer`).

Lab procedures (start, seed, reset, Windows and Entra labs): `reference/ad-lab.md`.

## 1. The pyramid

| Layer | Scope | Runs against | Speed | When |
| --- | --- | --- | --- | --- |
| **Unit** | Pure logic: codecs, filter/DN builders, RBAC evaluation, filter compiler, job state machine | Nothing external; injected clock | whole suite < 1 min | every commit |
| **Integration** | Connector ↔ directory; store ↔ PostgreSQL; handlers ↔ store + lab | Samba AD lab (`small` tier), real PostgreSQL | < 10 min | every commit |
| **Contract** | Responses vs the bundled `api/openapi/` contract (ADR-0004); breaking-change diff; generated clients compile; PowerShell module vs API | Running server + lab | < 5 min | every commit touching API |
| **E2E** | A few critical admin journeys through the real UI | Full stack + lab, Playwright | < 15 min | every commit touching UI; nightly full |
| **Performance** | Budgets from `engineering-standards` §7 | `scale` tier (50k users) | nightly | before milestone demo |
| **Windows-only** | Event logs, GPO, password filter, credential provider, real error strings | Windows lab (CEO-approved) | manual or scheduled | per feature, per release |

Rules:
- **Mock at our own interfaces, never at the wire.** Module tests may fake the `Directory`
  interface; connector tests always hit Samba. PostgreSQL is never mocked.
- **Fuzz every parser, encoder and builder** — the safe primitives above all
  (`ad-engineering` §1): hostile input in, valid escaped output or a typed error out.
- **Bug tickets start with a failing test** that reproduces the bug at the lowest layer that can.
- Tests that need Windows are tagged (`//go:build windowslab`, `@windows-lab`) so CI on Samba
  skips them loudly — the skip appears in the report, not silently.
- No `sleep` waits — wait on a condition with a timeout. No dependence on order, wall-clock now,
  locale or time zone: inject them.

## 2. The AD lab — Samba 4 AD DC in Docker (CI and local)

Samba speaks LDAP, LDAPS, Kerberos and the AD schema well enough for connector, sync, write and
most reporting tests. Quick reference (full detail and commands: `reference/ad-lab.md`):

```bash
make lab-up TIER=small        # provision or restore snapshot; prints LDAPS port, CA path, base DN
make lab-reset                # restore the tier snapshot (seconds) — between suites
make lab-seed TIER=scale      # build the 50k-object snapshot (slow; cached by seed version)
make lab-down
```

- Domain `lab.activediq.test` (RFC 2606 reserved). Credentials are generated at `lab-up` into a
  gitignored file — never committed, never printed in ticket notes.
- Connect over **LDAPS with the lab CA trusted** — never skip certificate verification, even in
  tests (the habit leaks into product code).
- Tests that write create their own OU (`OU=t-<test>-<rand>`) and delete it; full reset between
  suites. Tiers: `small` (~500 objects incl. edge cases), `scale` (50k users, 5k groups, 500 OUs,
  a 3,000-member group), `2dc` (second DC for per-DC attributes and USN tests).

**Samba does not emulate** (verify these in the Windows lab and say so in the platform matrix):
Security/System event logs, audit policy, GPO client-side processing, ADWS and the
ActiveDirectory PowerShell module, password filters, credential providers, Windows LAPS, AD FS,
Windows diagnostic strings, and some replication-metadata, Recycle Bin and channel-binding
behaviour `[UNVERIFIED]`. `ad-engineering/reference/gotchas.md` #51–52.

## 3. Windows lab and Entra test tenant — need CEO approval

Windows Server DCs (event logs, GPO, DC agent, password filter, credential provider) and an Entra
test tenant require accounts and possibly spend: **money and accounts are CEO decisions**
(`ceo-decisions`, kind `directional`; or a CEO action item for account creation). Until approved,
Windows-only and live-Graph tests are written, tagged, and recorded as **unverified** in the
ticket — never claimed as passing. Graph unit tests use recorded, sanitised HTTP fixtures.
Never test against a customer, partner or production tenant.

## 4. Fixtures — deterministic, synthetic, never product data

- Generated from a **fixed seed**: same seed → byte-identical output. The seed version is part of
  the snapshot name, so a fixture change invalidates caches deliberately.
- Synthetic people only (fixed name lists), `@example.com` mail, no real names, no customer or
  partner data, no realistic-looking secrets.
- Edge cases are first-class fixtures: commas, `#`, `+`, quotes, leading/trailing spaces, non-BMP
  Unicode, 64-char CNs, 20-char `sAMAccountName`s, disabled, expired, locked, must-change,
  never-expires, nested and cyclic groups, empty OUs, huge groups.
- Fixtures live only in `testdata/`, `lab/seed/`, `web/e2e/fixtures/` and Storybook stories. The
  **demo seed** (`lab/seed/demo`) feeds the running product for demos through the real API and
  directory — it is never imported by product code. A fixture under `web/src` or `internal/` is a
  review blocker (no fake data in the UI).

## 5. E2E with Playwright — evidence for QA

- Suites in `web/e2e/` (TypeScript lives only under `web/`, ADR-0001 rule 1), run against the full stack on the lab. Locate by role and label, not CSS.
- Screenshots at each AC state: `factory/demos/evidence/<ticket>/<ac#>-<state>.png`
  (e.g. `ac2-empty.png`, `ac3-error-dc-unreachable.png`). Projects for light and dark mode and
  for 1280 and 1920 widths. Trace on failure.
- Every number asserted in an E2E test is asserted against the API or the lab, not a literal
  copied from the screen.

## 6. Flaky tests

A test that fails and then passes with no code change is flaky. **Same day:** file a P1 `bug`
(owner `test-engineer`, or the test's author), tag the test `quarantine` with the ticket ID.
Quarantined tests still run and report, but do not gate. **Five working days** maximum: fix it or
delete it with replacement coverage. No retry-until-green in CI; Playwright `retries: 1` only,
and every retry is reported as a flake.

## 7. Proving a change works — the ticket note

Before `advance`, the owner runs the relevant layers and writes evidence mapped to each AC:

```
Evidence (T-0042)
AC1 ranged retrieval: $ go test ./internal/connector/ldap -run TestMemberRange -count=1
    ok   github.com/skenzeriq/activediq/internal/connector/ldap  2.31s
AC2 3,000-member group (Samba small tier): $ make lab-up TIER=small && go test -tags=lab ./internal/connector/ldap -run TestHugeGroup
    --- PASS: TestHugeGroup (1.84s)   members=3000
AC3 UI empty state: factory/demos/evidence/T-0042/ac3-empty.png
Not verified: Windows-only diagnostic text (needs Windows lab — D-00xx pending)
```

Commands must be copy-pasteable from a clean checkout. Output is an excerpt, not a dump.
"Tests pass" without a command is not evidence. Anything not verified is listed as such.

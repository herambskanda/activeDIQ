---
title: "Spec: E2.11 ManageEngine (ADMP) migration kit — importers as proposals, hostile-file limits, lifecycle change-volume limit"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: heramb
author: product-manager
ticket: T-0151, T-0633
epic: E-001
milestone: M2
parity: [ADM-010, ADM-011, ADM-012, ADM-015, ADM-017, ADM-019, ADM-020, ADM-097, ADM-101, ADM-104, ADM-105, ADM-106, ADM-125, ADM-139, ADM-040, ADM-041, ADM-042, ADM-043, ADM-044, ADM-045]
scope: locked
sources_last_checked: 2026-10-28
---

# Spec: E2.11 ManageEngine importer (ENH-02, ADMP part)

> An AD admin hands us their ManageEngine configuration and gets back a **reviewable set of
> proposals** and a fidelity report that says, row by row, what carried over exactly, what changed,
> what needs a human and what is not supported. Nothing an importer reads can run, escalate anyone,
> or go live without a named person applying it.

Closes TM-F-MIGRATE's spec dependency, binds TM-D21 and TM-TB18-T1…T12, and answers the open item
of TM-TB9-T4 / TM-Q6 (per-run change-volume limits for HR-driven lifecycle, §8). Input to the E-017
build tickets and, for §8, to the E2.9 lifecycle build tickets. Reviewed by `solution-architect`.
**Tag every build ticket from this spec `security-sensitive`.** Threat model:
[threat-model.md §5.18](../../development/architecture/threat-model.md); playbook requirements:
[manageengine-migration-playbook.md §8](../../business/service/manageengine-migration-playbook.md).

Scope anchor: ENH-02 (ADMP part) is in v1 per D-0004 in
[v1-scope-options.md](../../business/scoping/v1-scope-options.md); the ADAP and ADSSP adapters are
M3 and M4 and each is an RT-18 trigger (threat model §14), so they get their own spec.
Playbook IDs covered: MIG-01, 02, 03, 04, 05, 06, 10, 14, 16 (the set the scope doc names for M2).

## 1. Problem and user

- **AD admin / migration lead (customer or partner engineer).** Job: move a configured ADMP
  estate (templates, naming formats, roles, workflows, automations, custom reports, schedules)
  to activeDIQ without re-keying it by hand and without a risky big-bang. Once per customer,
  but it decides whether the purchase happens: sunk configuration is the named switching barrier
  (matrix ADM-012 note "Sunk-config barrier"; AD360 §8.2 in
  [manageengine-ad360-suite-and-commercials.md](../../business/market-research/manageengine-ad360-suite-and-commercials.md)).
- **Security reviewer / auditor.** Job: be sure the import cannot widen anyone's access. ADMP's
  own history is the reason: CVE-2022-28810 (custom script, KEV) and CVE-2025-10020 (Custom
  Script command injection) are script-bearing content; CVE-2024-24409 is the privilege class
  (ME-SEC §4.1 in
  [manageengine-ad-customer-voice-and-security.md](../../business/market-research/manageengine-ad-customer-voice-and-security.md)).
- **What it costs today.** ADMP has no template export and its REST API v2 has no template or
  workflow-approval endpoints; its backup is a proprietary `.ezip` and is not a migration source
  (matrix ADM-158 note; playbook §4.1). So the customer rebuilds from screenshots. Role-to-person
  mapping is hard because technicians share logins (playbook R8, CV §5.3).

## 2. Parity baseline

There are no ManageEngine features to match here; the baseline is the **ManageEngine objects we
must be able to receive**, from the matrix (no new IDs invented):

| Object | Matrix IDs | Input route | Playbook ID |
| --- | --- | --- | --- |
| Bulk CSV in ADMP format (LDAP headers, DN `memberOf`/manager, `templateName`) | ADM-010, ADM-011 | File | MIG-04 |
| Creation / modification templates, mover rules | ADM-012, ADM-015 | Read-only DB; else guided rebuild | MIG-02 |
| Naming macros, custom functions | ADM-017, ADM-019 | Read-only DB (macros); functions never executable | MIG-02 |
| Duplicate-prevention rules | ADM-020 | Read-only DB | MIG-02 |
| Technicians, roles, OU/group scope | ADM-125–133, ADM-139 | Technician-inventory report export; DB | MIG-02, MIG-16 |
| Workflows, approvals | ADM-116–123 | Read-only DB | MIG-02 |
| Scheduled automations and policies | ADM-104–106 | DB / API v2 listing | MIG-02, MIG-14 |
| Custom reports | ADM-097 | DB | MIG-05 |
| Scheduled reports, recipients | ADM-101 | DB / screenshots | MIG-06 |
| Discovery | ADM-135 | AD read | MIG-01 |
| Parallel run | ADM-104–115 | Dry-run vs ADMP results | MIG-10 |

Report exports are CSV, PDF, XLSX, HTML or CSVDE (ADM-100); whether every format is available for
the technician report (ADM-139) is `[UNVERIFIED]` in the playbook, so the importer accepts CSV and
XLSX and HTML where present and never requires one format. Whether API v2 returns full automation
definitions is `[UNVERIFIED]` (playbook §4.1); the importer treats the API as a listing source
only until the lab proves more. Gaps that need a lab install are tracked in §11.

## 3. Enhancements (all v1; each tied to a sourced pain)

1. **Fidelity report** (MIG-03): every inventory row appears once as `exact`, `changed` (with
   diff), `manual` or `not supported`; exportable CSV/PDF for customer sign-off. Pain: undocumented
   import limits and sunk configuration (ADM-012 note; CV §5.2).
2. **Proposals, not live** (TM-D21): the safety property ADMP lacks. Pain: ME-SEC §4.1 CVEs above.
3. **Unmodified ADMP CSV works** with a row-level dry-run preview (MIG-04, matrix ADM-011:
   "Auto-map columns, group names instead of DNs, row-by-row preview").
4. **One writer per job** (MIG-14): ownership lock that makes double execution (a leaver deleted
   twice) impossible. Playbook risk R2.

Not enhancements, not v1: ADMP REST shim (MIG-17, proposal only), cockpit (MIG-15, P1 after
checkpoint 2c), baseline snapshot (MIG-18, owned by the snapshot spec).

## 4. Experience target (to be confirmed with `product-designer`)

| Task | ManageEngine / manual today | Target |
| --- | --- | --- |
| Get the first fidelity report from a lab-sized estate (≤ 200 config items) | Not possible: no export; rebuild by screenshot | Upload or connect → report in ≤ 4 clicks, ≤ 5 min `[EST]` |
| Review and apply one proposal | n/a | Diff visible without leaving the screen; apply in ≤ 2 clicks plus step-up |
| Apply 50 proposals of one kind | n/a | Select-all with per-row exclusions, one step-up, one audit Action per proposal |
| Move one job's ownership | Disable in ME, enable in new tool, by memory | One action, both sides shown, ≤ 3 clicks |

The admin never writes an LDAP filter, a DN or a column mapping by hand: filters are shown as
typed conditions, group names resolve to DNs, and column mapping is suggested and remembered.

## 5. Platform matrix

| Dimension | Decision |
| --- | --- |
| Source product | ADMP builds recorded per adapter; first target is lab build 8043 (playbook MIG-02). Any other build → adapter refuses with "build not supported", never best-effort parses |
| Source routes | File upload (v1, first); read-only DB read (v1, in this spec); API v2 listing (v1, inventory only) |
| ADMP DB engines | PostgreSQL (bundled) and MS SQL Server. Windows auth to SQL Server is Kerberos only (TM-D10). Other engines: not supported, stated in UI |
| Target directory | On-prem AD (functional levels as set in the forest-connection spec), Entra ID, hybrid. Proposals that name an AD-only object are reported `not supported` for an Entra-only tenant, never silently dropped |
| Discovery scanner | On-prem AD via the connector; Entra: users and groups counts only (blank cells below are decisions: no Entra delegation-ACL equivalent exists, report "not applicable") |
| Windows Server versions | No DC-side component. Server runs on the supported host OS set of ADR-0002. A Samba AD lab covers file and proposal tests; Windows lab covers discovery against native ACLs |
| Delivery | Self-hosted and SaaS-ready: uploads go to the per-job store, DB reads go through the egress client; the SaaS case keeps the same limits |

## 6. Functional behaviour

### 6.1 Intake
An admin with permission `migration.import` creates a **migration project**, picks a source route
and gets a job. Each job records actor, source kind, source SHA-256, ADMP build and starts in
`quarantined`. Parsing happens only after the size gate (§7). Jobs have quotas: ≤ 3 concurrent per
tenant, ≤ 1 per user.

### 6.2 Classification and proposals
Each parsed item becomes exactly one fidelity row (MIG-03) and, unless `not supported` or `manual`,
one **proposal** (a stored, inert description of intended configuration plus the grants it
carries). A proposal has no effect on authorisation, jobs, schedules or notifications until applied.

### 6.3 Applying a proposal
Applying is an Action (T-0131) with a Plan. It requires: (a) the applier holds, over the proposal's
whole scope, **every** privilege of **every** grant the proposal carries (DM-36.I1 test) — the
importer's own service identity is never the applier; (b) step-up (threat model §7.4). Otherwise
Plan refuses and names the missing privilege.

### 6.4 What is never imported
`tenant-owner`; any permission that administers RBAC, delegation scopes or connections; any scope
or target resolving to a `tier0` object (reported `not supported`); script bodies; raw SQL; any
credential, key, token or technician password; open requests (drained in ADMP per playbook §4.1).

### 6.5 Scripts, filters, macros
- Script-bearing content: escaped text in the fidelity report, class `manual`. activeDIQ has no
  custom-script feature.
- Custom-report LDAP filters: parsed into the typed filter AST or classed `not supported`.
- Naming macros: parsed into a typed rule; unknown macro → `not supported`.

### 6.6 Schedules and notifications
Imported scheduled reports and notifications land **disabled**, with recipients shown. Recipients
outside the tenant's allowed domains are flagged and cannot be enabled without an explicit
override recorded in the audit event (TM-TB18-T9).

### 6.7 Technician mapping (MIG-16)
A technician login used by more than one person (detected by the inventory, or marked by the admin)
yields **no role proposal** until each use is mapped to a named person or group. Technicians are
created by invitation or SSO, never with imported passwords.

### 6.8 Ownership lock (MIG-14) and parallel run (MIG-10)
Every imported automation, schedule and notification has an owner field: `manageengine` or
`activediq`. Imported items start `manageengine`. A job owned by ManageEngine **cannot run** in
activeDIQ (refuses, with the reason). Switching is an Action with step-up, audited with actor and
time, and reversible. Comparator runs are **Plan-only**: no Apply path exists, and their output is
labelled advisory, with the source of each row shown.

### 6.9 Discovery scanner (MIG-01)
Needs its own permission `migration.discover`, uses only read rights (R1, threat model §6.3), writes
nothing, and its output is inventory under normal RBAC trimming. Exports use the standard encoders
and are audited (TM-TB18-T10).

## 7. Hostile-file limits (binding; TM-TB18-T1, T12)

Defaults below are **configuration ceilings, not floors**: an operator may lower them; raising
needs a change of the build constant. `[EST]` values are to be confirmed against the lab corpus.

| Limit | Value | On breach |
| --- | --- | --- |
| Upload size, report/CSV/XLSX/HTML | 256 MiB | Reject at the size gate before any read |
| Upload size, database dump | 4 GiB, streamed, never stored in the blob store | Reject |
| Decompressed size per archive | 1 GiB total and ≤ 100:1 ratio per entry | Abort job |
| Archive entries | ≤ 10,000; names with `..`, absolute paths, drive letters or links rejected | Abort job, name the entry |
| Rows per sheet / CSV | 1,000,000 | Abort job at the row |
| Cell / field length | 32,767 characters (the Excel cell maximum) | Abort job at the cell |
| XML/HTML nesting depth | 64 | Abort job |
| Per-job memory | 512 MiB | Abort job |
| Per-job wall time | 30 min | Abort job |

Only Go `encoding/xml` parses XML in importers (no external entities). Every importer format has a
fuzz target (FF-SP5). Imported strings are data and re-encoded on every output (T-0150). An aborted
job leaves no proposals and a failure row stating the limit hit; partial results are never applied.

## 8. Lifecycle change-volume limit (TM-TB9-T4, TM-Q6; E2.9)

An HR source (database or CSV drop; ADM-040, ADM-041) is a TM-X12 peer: a bad feed must not be
able to disable the company. Every lifecycle policy run (joiner, mover, leaver; ADM-042–045) goes
through a Plan and these per-run limits, evaluated **before** any change applies:

| Limit | Default | Behaviour on exceed |
| --- | --- | --- |
| Changes per run, all kinds | max(25, 5% of the policy's in-scope accounts) | Whole run held for approval; none applied |
| Disables + deletes per run | max(5, 1% of in-scope accounts) | Whole run held for approval |
| Deletes per run | 0 unattended: a delete always needs an approval step | Held |
| Same account changed by the same policy within 24 h | 1 | The second change is held |

A held run shows the Plan, what tripped the limit, and offers approve-all, approve-subset or
reject. A run within limits proceeds unattended ("a believable HR change still flows",
TM-TB9-T4 residual). Operators may tighten the limits, or loosen them up to 3× the defaults, with
step-up; each change is audited. The limit is enforced in the operation pipeline (ADR-0005 O8, T-0393), not in
the lifecycle module, so that no policy can bypass it. The same limit class applies to an
**imported** automation once its ownership flips to activeDIQ.

## 9. Security and audit

- **Directory privileges.** Importers need none (no directory access). Discovery needs R1 reads.
  Applying a proposal needs what the proposal grants (§6.3).
- **Database credential** (TM-TB18-T4, T5): read-only login or token; read-only transactions; no
  write statement in adapter code. Adapters select from an **allow-list** of tables and columns per
  build; a CI-checked **deny list** covers every credential, key and password table or column.
  The credential is sealed, write-only, never returned, deleted when the project closes. The dump
  upload is deleted at job end.
- **Outbound** only through the egress client (loopback, link-local, metadata and private ranges
  refused unless the operator allow-lists them); ADMP servers are registered explicitly; Kerberos
  only, no NTLM (TM-TB18-T6).
- **Audit.** Every run records actor, source kind, SHA-256, ADMP build and counts per class
  (TM-TB18-T11). Every applied proposal, every ownership switch and every limit override is its
  own audited Action. Audit detail never contains a script body, secret or file content.
- **`security-architect` must review:** the allow/deny lists, the applier-holds-every-privilege
  check, the limits table, and the ownership lock.

## 10. Acceptance criteria — TM-TB18 rows

Proof owner is the team that writes the proof; `qa-verifier` re-runs it against the running
product for evidence. Fixture names are placeholders for the corpus the proof owner builds.

| ID | TM row | Given / When / Then | Proof owner |
| --- | --- | --- | --- |
| AC-01 | TB18-T1 | **Given** a CSV, XLSX and HTML export each carrying an external-entity declaration, **when** imported, **then** no file or URL is read, the job aborts or the entity is inert, and a canary file's content never appears in any proposal or log. | `backend-engineer`; fuzz corpus `test-engineer` (TM-F-MIGRATE) |
| AC-02 | TB18-T1 | **Given** an XLSX/ZIP with entries named `../x`, `/etc/x`, `C:\x` and a symlink entry, **when** imported, **then** the job aborts naming the entry and no file is created outside the per-job directory. | `backend-engineer` |
| AC-03 | TB18-T1, T12 | **Given** a 1 MiB archive that expands past 1 GiB (or > 100:1), **when** imported, **then** the job aborts within the memory cap and the server's other requests stay within normal latency. | `test-engineer` |
| AC-04 | TB18-T1 | **Given** files with one row over 1,000,000, one cell of 32,768 characters, and nesting depth 65, **when** imported, **then** each aborts at the stated limit, no proposal exists, and the failure row names the limit. | `backend-engineer` |
| AC-05 | TB18-T1 | **Given** each importer format, **when** CI runs, **then** a fuzz target exists and runs for a stated minimum time with zero crashes (FF-SP5). | `devops-engineer` |
| AC-06 | TB18-T1 | **Given** a cell containing `=cmd|' /C calc'!A0`, `<script>` and a 5,000-character string, **when** it appears in the UI, the fidelity-report CSV and PDF, **then** it is escaped/encoded and inert in each. | `qa-verifier` |
| AC-07 | TB18-T2 | **Given** a completed import, **when** the admin reads configuration, **then** no role, delegation, approver, schedule or automation from the import is active, and the tenant behaves identically to before the import. | `qa-verifier` |
| AC-08 | TB18-T2 | **Given** a proposal whose grant needs a privilege the applying admin lacks (over any part of its scope), **when** they apply it, **then** Plan refuses, names the privilege, and nothing changes. A complete-privilege admin without step-up is also refused. | `backend-engineer` |
| AC-09 | TB18-T2 | **Given** an export containing `tenant-owner`, an RBAC-administering permission, a connections-administering permission and a scope that is a `tier0` object, **when** classified, **then** each is `not supported` (reason shown), none appears as a proposal. | `backend-engineer`, `ad-expert` on the tier0 set |
| AC-10 | TB18-T2 | **Given** a technician login used by several people, **when** roles are imported, **then** no role proposal exists for that login until each use is mapped (MIG-16). | `qa-verifier` |
| AC-11 | TB18-T3 | **Given** a custom script, a script-backed automation and a custom naming function, **when** imported, **then** each is escaped text classed `manual`; no code path executes it; the CI check finds no script-execution route reachable from importer output. | `backend-engineer`; `security-architect` |
| AC-12 | TB18-T3 | **Given** custom-report filters — one valid, one with unbalanced parentheses, one raw SQL — **when** imported, **then** the first becomes a typed filter, the other two are `not supported`, and no string-built filter or SQL reaches a directory or database (FF-SP1, SP5). | `directory-engineer` |
| AC-13 | TB18-T3 | **Given** a naming macro with an unknown token, **when** imported, **then** the item is `not supported` and named, never approximated. | `backend-engineer` |
| AC-14 | TB18-T4 | **Given** the lab ADMP database containing credential and password tables, **when** an adapter runs, **then** the query log shows only allow-listed tables and columns; a planted deny-listed table in the adapter fails CI. | `devops-engineer` (CI), `directory-engineer` |
| AC-15 | TB18-T4 | **Given** a database dump upload, **when** the job ends (success, failure or abort), **then** the upload no longer exists on disk or in the blob store, and technicians arrive only as invitations. | `qa-verifier` |
| AC-16 | TB18-T5 | **Given** a saved DB/API credential, **when** any API response, log, audit entry or export is searched for it, **then** it is absent (canary, TM-F-SECRETOUT); and a statement other than read-only select cannot be issued by the adapter. | `backend-engineer`, `test-engineer` |
| AC-17 | TB18-T5 | **Given** a closed migration project, **when** opened, **then** the stored credential is gone. | `qa-verifier` |
| AC-18 | TB18-T6 | **Given** an ADMP server URL that resolves to loopback, link-local, metadata or private ranges without allow-list, or redirects to one, **when** registered or used, **then** it is refused; and no NTLM is attempted (TM-F-EGRESS, TM-F-NTLM). | `backend-engineer` |
| AC-19 | TB18-T7 | **Given** an imported automation owned by `manageengine`, **when** a run is triggered by schedule or API, **then** activeDIQ refuses and the audit shows why. **And given** a comparator run, **then** it has no Apply path and writes nothing to the directory. | `backend-engineer`; operation fitness O7 (T-0392) |
| AC-20 | TB18-T7 | **Given** an ownership switch, **when** an admin without step-up attempts it, **then** it is refused; with step-up it is recorded with actor and time and can be reversed. | `qa-verifier` |
| AC-21 | TB18-T8 | **Given** a seeded divergence between activeDIQ and ADMP results, **when** the comparator runs, **then** every divergence is listed; each row names its source; and no automatic write follows from any comparator output. | `test-engineer` |
| AC-22 | TB18-T9 | **Given** an imported scheduled report with an external recipient domain, **when** imported, **then** it is disabled, recipients are shown, the external one is flagged, and enabling needs an audited override. | `qa-verifier` |
| AC-23 | TB18-T10 | **Given** a user without `migration.discover`, **when** they request discovery or its output, **then** denied; with it, results respect RBAC trimming and an export is audited. | `qa-verifier` |
| AC-24 | TB18-T11 | **Given** any import run, apply, switch or override, **when** the audit trail is read, **then** each appears with actor, source SHA-256, ADMP build and per-class counts, and no content of the file. | `qa-verifier` |
| AC-25 | TB18-T12 | **Given** a 100,000-object directory discovery and a 1M-row export, **when** run, **then** both complete inside the §7 caps, with the scan under 30 minutes for 10k objects (MIG-01 `[EST]`) and no unbounded memory growth. | `test-engineer` |
| AC-26 | TB9-T4 | **Given** a Plan from an HR feed exceeding any §8 limit, **when** it runs, **then** none of its changes apply, it is held with the tripped limit named, and approve-subset applies only the chosen rows. | `backend-engineer`; operation fitness |
| AC-27 | TB9-T4 | **Given** a run within every §8 limit, **when** it runs, **then** it applies unattended; and a delete in it is held for approval regardless of count. | `qa-verifier` |
| AC-28 | TB9-T4 | **Given** an admin loosens the limit beyond 3× default or without step-up, **when** saved, **then** refused; a permitted change is audited. | `backend-engineer` |

Cases applied to the feature as a whole: **empty** (a file with headers only → job completes with
zero rows and says so); **error** (unreadable file, unsupported ADMP build, unreachable DB → named
reason, no partial state); **partial failure** (some items parse, one fails → the fidelity report
lists the failure; successes remain proposals; nothing is applied automatically); **large** (100k
objects; groups with > 1,500 members are read through ranged retrieval and members are not truncated).

## 11. Out of scope and open questions

**Out of scope.** ADAP and ADSSP adapters (M3/M4); ADMP REST shim (MIG-17); migration cockpit UI
(MIG-15); baseline snapshot (MIG-18); enrollment migration (MIG-09); audit-history bridge (MIG-07);
executing or translating scripts; importing open requests; cross-forest migration (ADM-185…187).

**Open questions (none directional).**
1. ADMP build 8043 schema, DB table allow-list and EULA review — needs a lab install
   (TM-Q28; playbook MIG-02). Ticket to follow with `directory-engineer` and `market-analyst`.
2. Do ADMP report exports include the technician report in all formats (ADM-139)? Research ticket
   for `market-analyst`.
3. Numbers in §7 and §8 are defaults; the lab corpus may revise them; the structure is fixed.
4. Dump-versus-live DB mode (TM-Q28): both are specified; the first build ticket may ship the dump
   route first.

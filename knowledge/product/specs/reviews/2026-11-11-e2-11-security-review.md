---
title: "Security review (C-02): E2.11 ManageEngine (ADMP) migration importer, file and DB-dump routes"
date: 2026-11-11
status: draft
owner: security-architect
reviews:
  - knowledge/product/specs/e2-11-migration-importer.md (draft 2026-10-28, first review)
ticket: off-board plan key C-02 (m2c-plan); attach the board ID at merge
---

# Security review: E2.11 migration importer (C-02)

**Verdict: reject.** 3 blockers, 7 majors, 6 minors, 3 nits.

The spine of the spec is right. Imports land as proposals (TM-D21). The applier must hold every
imported privilege (DM-36.I1). Scripts are classed `manual`, custom-report filters go to the
typed AST, schedules land disabled, and §7 has a real limits table. The rejects are about what
the spec leaves open at the points a hostile ADMP source or an insider with `migration.import`
would aim for:

- **who receives** imported authority, as opposed to who grants it;
- **how a database dump is read**;
- **secrets on the file route**, where ADMP's own reports carry LAPS passwords and BitLocker keys.

The author (C-03) fixes the numbered items. I re-review only those.

**Scope of this review.** I reviewed the director's 2c cut: intake, file route, DB-dump route,
§6.1–§6.7, §7, §9, the 2c ACs, and the ownership-lock **enforcement** of §6.8. That enforcement
must ship in 2c, because 2c imports schedules (see M5). Discovery (§6.9), the comparator, the
ownership **switch** and §8 lifecycle limits are 2d. I read them only for consistency, and they
get no graded findings here.

**How I reviewed it.** This is a document review: there is no code to run and no lab. I read the
spec in full and checked it against:

- threat model §5.18 (TM-TB18-T1…T12, TM-D21), §6.9a (`guarded-v1`), RT-13 and TM-F-MIGRATE;
- ADR-0005 rules 7 (Plan and Apply re-check), 8 (gate, separation of duties), 9 (transient
  secrets) and 10 (configuration writes);
- domain model DM-33.I3, DM-34.I2, DM-36.I1/I2, DM-50, DM-51, DM-60, DM-64/65/66;
- safe-primitives §3 (P1 `ParseAdminFilter`), §3.7 (`SecretAttrs`), §4 (P2) and §12.3 (CSV reader);
- E2.6 §11 and AC-B28/B29/B43;
- the E2.7 review's A-B2 and carry-over row 2.

For each focus question I built the attack and recorded whether a written rule stops it. ADMP
behaviour comes from our research files, cited by path. External library behaviour was checked
on 2026-11-11 against the pages cited inline.

---

## 1. TM-TB18 coverage (C-02 Definition of Done)

| Row | Spec coverage | Holds? | Finding |
| --- | --- | --- | --- |
| T1 hostile file | §7 table, AC-01–06 | Partly. The limits are not enforceable as written, the dump and HTML parsers are unspecified, and declared sizes are trusted | B2, M1, M2 |
| T2 escalation via imported grants | §6.3, §6.4, §6.7, AC-08–10 | Grantor side only. The grantee is chosen by the file. Workflows and approvers fall outside the grant test. Tier0 is checked only at classification | B1, M3, M4, M7 |
| T3 script-bearing content | §6.5, AC-11–13 | Yes, apart from the E2.6 §11.2 citation and the parser caller | m1 |
| T4 ADMP credentials read or imported | §6.4, §9, AC-14/15 | DB route only. The file route has no secret control, and the deny list's completeness is asserted, not established | B3, B2 |
| T5 DB/API credential leak | §9, AC-16/17 | Live route only. It is not exercised by the 2c dump route | m6 |
| T6 SSRF/NTLM | §9, AC-18 | Yes, for the live route (2d) | m6 |
| T7 imported automations run for real | §6.8, AC-19/20 | The lock exists, but where it is enforced and which triggers it covers are open | M5 |
| T8 false parity | §6.8, AC-21 | 2d | — |
| T9 attacker-chosen recipient | §6.6, AC-22 | Yes for recipients. Schedule **owner** binding is open | B1 |
| T10 discovery as a recon map | §6.9, AC-23 | 2d. The same threat applies to the **fidelity report** in 2c | M4 |
| T11 traceability | §9, AC-24 | Yes, with one contradictory sentence | m4 |
| T12 DoS | §7, §6.1 quotas, AC-03/25 | Not enforceable in the shared process | M1 |

---

## 2. Blockers

**B1 [blocker] · §6.3 (lines 129–133), §6.7 (151–154), §6.6, AC-08/AC-10; TM-TB18-T2; DM-36.I1, DM-30.I5.
The file chooses who receives imported authority.**

- **Problem.** §6.3 checks the **grantor**: the applier must hold every privilege of every grant.
  Nothing constrains the **grantee**. A role proposal's subject is a technician login, an AD
  group, an e-mail or a display name taken from the export. The same holds for:
  - a workflow's approvers;
  - an automation's or schedule's owner (`owner_account_id`, DM-60; delivery runs with the
    owner's scope, TM-TB15-T2).

  §6.7 binds subjects to people only for **shared** logins. For any other login, the subject is
  whatever the file says. "Technicians are created by invitation" leaves open where the
  invitation goes, and today the only address on hand is the file's.
- **Exploit sketch.**
  - A compromised ADMP (TM-X13) or an insider holding `migration.import` adds technician
    `helpdesk-ops`, with e-mail `ops@attacker.example`, a Help Desk role and a domain-wide user
    scope.
  - A tenant-owner applies the batch. DM-36.I1 passes, because the tenant-owner holds everything.
  - The invitation goes to the attacker, who accepts it and can then reset every non-tier0
    password.

  A variant names an AD group by display name, and the name resolves to a look-alike group the
  attacker controls.
- **Fix.**
  1. Every grantee, owner, approver and assignee in a proposal is a **binding the applier makes**.
     The applier picks from directory-resolved identities: an account bound through DM-30.I5
     anchors, or a security group by `objectGUID` that satisfies DM-36.I2. The file only
     **suggests** a binding. A suggestion is resolved by exact anchor or GUID, never by UPN,
     e-mail, `sAMAccountName` or display name alone. Until bound, the proposal is `manual`.
  2. Invitations go only to the address held on the **bound directory object**, or are replaced
     by SSO admission (DM-30). An e-mail address from the file is never a destination.
  3. The Plan diff of a grant-bearing proposal shows each grantee as canonical DN plus GUID,
     next to the file's original string, escaped (M7).
  4. An applied automation's or schedule's `owner_account_id` is the applier, never an ADMP name.
  5. §6.3 states that the DM-36.I1 test runs at Plan **and again at Apply** (ADR-0005 rule 7).
     It also states that the grant's `granted_by` is the applier.
- **Tests.**
  - `role_proposal_unbound_subject_is_manual`
  - `invitation_never_uses_file_email` (canary address absent from outbound mail)
  - `group_subject_resolved_by_guid_not_name` (two groups with the same display name, so the
    binding is ambiguous and the proposal is `manual`)
  - `applied_schedule_owner_is_applier`
  - Extend AC-10 to non-shared logins.

**B2 [blocker] · §5 "Source routes", §7 row "database dump" (176), §9 (213–217), §11 Q1/Q4,
AC-14/15; TM-TB18-T1, T4. How a database dump is read is unspecified.**

- **Problem.** The DB-dump route is in 2c scope, and it carries the riskiest parser in the
  feature. The spec says "4 GiB, streamed" and "only allow-listed tables are extracted", but it
  never says:
  - which dump formats are accepted: PostgreSQL plain SQL, `pg_dump -Fc`, or a SQL Server `.bak`;
  - how the dump is read.

  The tempting implementation is to restore the dump into a scratch database and `SELECT` the
  allow-list. That **executes** attacker-supplied DDL and SQL: functions, triggers, `COPY …
  PROGRAM` under a privileged restore role, and `CREATE EXTENSION`. A plain-text dump is a SQL
  script. Replaying it is running the customer's hostile file, and it is "raw SQL", which §6.4
  forbids. A streamed upload also has to land somewhere, and nothing says it is encrypted while
  spooled. Finally, the allow-list does not exist yet: §11 Q1 says it needs the lab.
- **Exploit sketch.** A compromised ADMP produces a plain dump containing
  `COPY t FROM PROGRAM '…'`, or a function with a `SECURITY DEFINER` body. The migration admin
  uploads it. A restore-based adapter runs it with the scratch database's rights, on or next to
  the activeDIQ server.
- **Fix.**
  1. State that a dump is **parsed, never restored, replayed or attached** by any database engine.
     No statement in it is executed.
  2. Name the accepted formats. For 2c I recommend PostgreSQL only, in one named format
     (`pg_dump` custom or plain), read by our own streaming parser that understands only the TOC
     or `COPY` data blocks of allow-listed tables. A SQL Server `.bak` is `not supported` in 2c.
     SQL Server waits for the live read-only route, which is 2d.
  3. Bytes of non-allow-listed tables are discarded as they stream. They are never buffered,
     logged or echoed in a parse error.
  4. If the stream must spool, it spools to a per-job file encrypted under a job key that is
     destroyed at job end (crypto-shred), not just deleted.
  5. §7's decompression limits apply to compressed dump entries too.
  6. The DB-dump route is **not Ready for build** until the column-level allow-list for build 8043
     exists and is signed off (see M6 for who owns it).
- **Tests.**
  - `dump_with_copy_program_is_inert` (a canary command never runs; no DB connection is opened
    by the job)
  - `dump_denied_table_bytes_not_retained`
  - `dump_spool_unreadable_after_job`
  - A fuzz target for the dump parser (FF-SP5).

**B3 [blocker] · §6.4 (135–138), §5 "Delivery" (114), §6.5 (141), §9, AC-15; TM-TB18-T4;
security-baseline §3. The file route has no secret control.**

- **Problem.** The secret controls (allow-list, deny list, deletion at job end) exist only for the
  DB route. The file route is the first route, and it ingests ADMP report exports. ADMP reports
  carry secrets:
  - LAPS passwords with history (ADM-060 in
    `knowledge/business/market-research/manageengine-admanager-plus.md`);
  - BitLocker recovery keys (ADM-087, same file).

  Three things make this worse:
  - Uploads "go to the per-job store" with no retention rule. AC-15 deletes only dumps.
  - Script bodies, which routinely embed credentials `[UNVERIFIED]`, are kept as escaped text and
    exported in the fidelity report for "customer sign-off". That report leaves the building.
  - The spec does not say that `.ezip` backups and `customer-config.xml` are refused. Per ADM-158
    in the same research file, they hold the backup password material.
- **Exploit sketch.** An admin exports ADMP's "computers" report with the LAPS column included and
  uploads it. Every local administrator password in the estate now sits in our blob store,
  readable by any `migration.import` holder. It is not sealed, not audited per read, and it
  survives the job, against baseline §3 ("retrieved on demand, never cached").
- **Fix.**
  1. Classify columns and headers at parse time against `SecretAttrs` (safe-primitives §3.7),
     plus a reviewed list of ADMP display labels ("LAPS Password", "Recovery Password",
     "Password" and so on). On a match, **abort before anything persists**, naming the column, not
     the value, and tell the admin to re-export without it.
  2. Run a value-level secret-shape scan (high-entropy tokens, BitLocker 48-digit recovery
     format) on every persisted string. A hit sets the row to `not supported` with the value
     withheld.
  3. Delete every upload, of every route, at job end. Only extracted, non-secret proposal data
     survives.
  4. Script bodies are shown only in the console to `migration.import` holders. Fidelity exports
     carry the item name, SHA-256 and length, never the body.
  5. Refuse `.ezip`, ADMP configuration files and any file ADMP marks encrypted, by magic bytes
     and name.
- **Tests.**
  - `laps_column_export_aborts_before_persist` (canary password absent from the blob store, DB,
    logs and audit)
  - `bitlocker_key_shape_withheld`
  - `upload_deleted_at_job_end_all_routes` (extends AC-15)
  - `fidelity_export_has_no_script_body`
  - `ezip_refused`

---

## 3. Majors

**M1 [major] · §7 (170–187), AC-03, AC-25; TM-TB18-T1, T12, RT-13. Parsers run in the Tier-0
process, and the memory and time caps cannot be enforced as written.**

- **Problem.** A "per-job memory 512 MiB" limit cannot be enforced inside a shared Go server
  process. Go has no per-goroutine memory limit; `GOMEMLIMIT` applies to the whole process. AC-03
  ("other requests stay within normal latency") therefore depends on accounting that nothing
  specifies.

  The parsers also share the address space that holds the directory connections and the seal
  keys. `encoding/xml` documents no depth or token-size limit (https://pkg.go.dev/encoding/xml).
  It has had stack-exhaustion bugs on deep nesting (GO-2022-0521, CVE-2022-28131:
  https://pkg.go.dev/vuln/GO-2022-0521).
- **Fix.**
  - Importer parsing runs in a **separate OS process**, along the lines of the safe-primitives
    tier-X sidecar pattern. That process has:
    - no credentials, no database role and no network;
    - OS-enforced memory and CPU limits (a Job Object on Windows, a cgroup on Linux);
    - a hard kill at wall time.
  - It returns typed results only.
  - The §7 caps are counted on **bytes actually produced**: our own depth counter and a bounded
    token reader around the decoder, never the library's defaults.
  - Process placement is C-27's to design; the spec states the requirement.
- **Test.** `bomb_kills_parser_not_server`. During AC-03, the server stays responsive and holds
  no parser memory.

**M2 [major] · §7 (177–187), AC-01/02/06. Format-specific gaps in the limits table.**

- **ZIP and XLSX.**
  - Count decompressed bytes and ratio on actual output, never the central directory's declared
    sizes, which the attacker controls. That also defeats overlapping-entry bombs
    `[UNVERIFIED: technique per Fifield, https://www.bamsoftware.com/hacks/zipbomb/ — page refused
    automated fetch]`.
  - Refuse nested archives.
  - Refuse duplicate entry names (a central-directory versus local-header differential).
  - Refuse backslashes, NUL, drive or UNC prefixes, NTFS stream syntax and reserved device names.
  - **Never extract to the filesystem.** Read entries in memory, which removes the
    path-traversal class rather than filtering it.
  - XLSX: read cached values only. Never evaluate formulas. Never resolve `TargetMode="External"`
    relationships, `externalLinks/` entries or DDE. Refuse macro-enabled content types
    (`vbaProject.bin`).
  - Add a **total-cells** cap. 1M rows times 16,384 columns is not bounded by the row cap.
- **HTML.**
  - Name the parser. `encoding/xml` cannot parse real HTML.
  - If it is `golang.org/x/net/html`, pin it at v0.33.0 or later: earlier versions parse crafted
    input in non-linear time (GO-2024-3333, CVE-2024-45338: https://pkg.go.dev/vuln/GO-2024-3333).
  - Check it against `knowledge/business/licensing/`.
  - Apply the nesting-depth cap to it.
  - It never fetches `src`, `href` or `<base>`.
- **Encodings.**
  - Detect from the BOM or the declared encoding: UTF-8, UTF-16LE (common in Windows exports)
    and Windows-1252.
  - Reject invalid sequences rather than substituting U+FFFD.
  - Reject NUL and C0 controls except TAB, CR and LF.
- **Tests.**
  - `zip_declared_size_lies_aborts`
  - `zip_duplicate_entry_refused`
  - `xlsx_external_link_not_fetched`
  - `xlsm_refused`
  - `html_quadratic_input_within_cap`
  - `utf16_bom_csv_parses`
  - `invalid_utf8_aborts`

**M3 [major] · §6.3, §6.4, §2 row "Workflows, approvals"; DM-64, DM-66, DM-34.I2, DM-33.I3.
Imported workflows can weaken controls that the grant test does not see.**

- **Problem.** A WorkflowDefinition grants no privilege, so §6.3 passes it whoever applies it.
  Workflow administration is not `control_plane` (DM-33.I3 lists roles, assignments, scopes and
  connections), so §6.4 does not exclude it either. Yet applying one can:
  - **un-gate** Actions that a stricter published definition currently holds, through an
    overlapping `applies_to`, empty stages, `auto_execute`, or quorum `any` over a broad role;
  - make someone an approver (B1).

  Separately, an ADMP **requester** role imported as `request`-mode privileges (DM-34.I2) without
  its workflow has no defined behaviour: neither ADR-0005 nor DM-34 says what happens when no
  WorkflowDefinition matches (follow-up F2).
- **Fix.**
  - Imported definitions land `draft` with `auto_execute` off. They never replace or shadow a
    published definition.
  - The proposal's Plan shows the **effective-gating diff**: every Action ID whose gate changes,
    and in which direction.
  - Any loosening needs `tenant-owner`.
  - Assignees bind per B1.
  - A role proposal with `request`-mode privileges depends on its workflow proposal and cannot be
    applied first.
- **Tests.**
  - `imported_workflow_cannot_ungate_existing_action`
  - `request_mode_role_blocked_without_workflow`

**M4 [major] · §4 row "Apply 50 proposals" (98), §6.3; ADR-0005 rule 8. Separation of duties
and review integrity for grant-bearing proposals.**

- **Problem.** The uploader chooses the file's content, and its provenance is unverifiable: the
  SHA-256 proves what was uploaded, not that ADMP produced it. "Select-all, one step-up" turns
  review into a rubber stamp for exactly the proposals that move authority. In addition, the
  fidelity report and the proposal list are a map of who holds power in the estate (the
  TM-TB18-T10 class), and nothing restricts who may read or export them.
- **Fix.**
  - Grant-bearing proposals (role assignments, delegation scopes, workflow definitions,
    automation-policy RoleAssignments) are **excluded from select-all**. Each is applied with its
    diff open.
  - Their applier must not be the job's uploader, unless the applier is `tenant-owner`. That case
    is recorded in the audit event.
  - Label the job "source asserted by the uploader, not verified".
  - Reading proposals and fidelity reports needs `migration.import`, or a new `migration.read`.
    Exports are audited and go through the TB15 encoders.
- **Tests.**
  - `grant_proposal_not_bulk_selectable`
  - `uploader_cannot_apply_grant_proposal`
  - `fidelity_report_denied_without_permission`

**M5 [major] · §6.8 (156–161), AC-19/20; DM-60 `execution_owner`; ADR-0005 rule 7; E2.6 AC-B29.
The ownership lock: where it is enforced and what it covers.**

- **Problem.** "A job owned by ManageEngine cannot run" does not say **who refuses**. If the
  lifecycle or reports module refuses, then any path that module does not route the check
  through bypasses the lock: "run now", an `operation_event` or `directory_state` trigger, a
  delivery retry, **clone** (does the clone default to `activediq`?), **restore** of an earlier
  version (does `owner` sit inside the versioned content?), or a re-import applied twice.

  The switch is "reversible", but nothing re-checks the owner between Plan and Apply. The plan
  also moves the switch to 2d. 2c still applies imported schedules (E2.6 AC-B29), so the lock's
  **refusal** must ship in 2c, or C-03's cut will take it out together with the switch.
- **Fix.**
  - The kernel enforces the lock at Plan **and** Apply, the way §8 places its limits in the
    pipeline (ADR-0005 O8). An Operation whose origin is an automation policy or schedule with
    `execution_owner ≠ activediq` is refused.
  - The owner field sits **outside** versioned content. Restore cannot change it, and clone
    inherits it.
  - Applying a proposal is idempotent per (project, source item key).
  - Use DM-60's vocabulary, `execution_owner`: `activediq` | `external` (+ source product), not a
    second `owner` that collides with `owner_account_id`. E2.6 §11.3 says "owner `manageengine`"
    and should change to match.
  - C-03 keeps the refusal half of AC-19 in 2c.
- **Tests.**
  - `locked_policy_refused_all_triggers` (schedule, API, run-now, `operation_event`, retry)
  - `clone_inherits_lock`
  - `restore_cannot_unlock`
  - `switch_back_between_plan_and_apply_refuses`

**M6 [major] · §2 rows "templates", "naming", "duplicate-prevention"; §6.4; DM-50; threat model
§6.9a `guarded-v1`; carry-over row 2. Imported templates can carry takeover attributes.**

- **Problem.** An imported creation template can set defaults or rules for attributes that
  decide sign-in or sync identity. The worst is `ms-DS-ConsistencyGuid`. A constant value in a
  template is never legitimate. A per-object value stamped from a template is the anchor-collision
  takeover from E2.7 A-B2: Entra Connect uses it as the sourceAnchor that matches on-premises
  objects to existing Entra objects ("hard match"), and the value is fixed once the object is
  imported into the connector space
  (https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-design-concepts).

  `ms-DS-ConsistencyGuid` is not yet in `guarded-v1` (carry-over row 2). Even when it is, DM-50.I3
  checks only the **technician's** privileges at use, and a `tenant-owner` passes.

  Templates can also hold a default password (`[UNVERIFIED]` for ADMP creation templates;
  ADM-152 shows ADMP sets default passwords on restore).

  Separately, the DB allow-list's companion deny list "covers every credential, key and password
  table or column" (§9). That is a claim about a schema we have not seen.
- **Fix.**
  - In template defaults, rules and post-steps, these are always `not supported` (named, never
    approximated), independent of carry-over row 2:
    - any attribute in `SecretAttrs` (safe-primitives §3.7);
    - any attribute in `guarded-v1`, including its `denied` class;
    - `ms-DS-ConsistencyGuid`, `adminCount` and `nTSecurityDescriptor`.
  - Template passwords are never imported. The template references a DM-52 policy that the
    applier picks.
  - Rules that add tier0 groups, or groups that are RBAC subjects (TM-D18), are flagged
    `changed`, with a reason shown.
  - The deny list's completeness is established from the lab schema, and the allow-list is the
    control. Every column of the 8043 schema is classified, and an unclassified column fails CI.
  - Allow-list changes need `security-architect` approval through CODEOWNERS.
- **Tests.**
  - `template_consistencyguid_not_supported`
  - `template_guarded_attr_not_supported`
  - `template_default_password_dropped`
  - `allowlist_unclassified_column_fails_ci`

**M7 [major] · §4 (101), §6.4 tier0 clause, §6.2; DM-35.I5; ADR-0005 rule 7; safe-primitives
P1/P2. Name and DN resolution, and the tier0 re-check.**

- **Problem.** "Group names resolve to DNs", and OU, group and container references in templates
  and scopes all start as hostile strings. The spec does not require:
  - that lookups are built with `ldapfilter.Eq` and the P2 parser;
  - that an ambiguous name stops the import rather than taking the first match;
  - that the tier0 test is re-run when the proposal is **applied**.

  As written, the tier0 test runs at classification, possibly weeks before apply. The tier0 set
  and OU contents can change in between.

  In the review UI, bidi overrides (U+202E), zero-width characters and homoglyphs in role, OU and
  group names let a file present one name and bind another.
- **Fix.**
  - Every lookup goes through P1 and P2. A match binds by GUID. Zero matches or more than one
    gives `manual`.
  - The tier0 check is part of the apply Action's Plan **and** Apply re-check (rule 7 facts). The
    classification result is advisory.
  - The UI shows the file string with control, bidi and zero-width code points made visible, next
    to the resolved canonical DN and GUID.
- **Tests.**
  - `lookup_name_with_filter_metachars_is_literal` (`x)(cn=*`)
  - `ambiguous_name_is_manual`
  - `tier0_added_after_import_refused_at_apply`
  - `bidi_name_rendered_visible`

---

## 4. Minors

1. **[minor] §6.5, AC-12; E2.6 §11.2 (FB-10).**
   - AC-12 should cite E2.6 §11.2 as the target grammar. That list adds `manual` for unregistered
     attributes, plus secret-attribute → `not supported`.
   - State that `ParseAdminFilter` runs with a **fixed least-privilege importer caller**, so a
     secret attribute is `ForbiddenAttribute` whoever uploaded.
   - State that the original ADMP text is display-only, and name the single RP-B1 allow-listed
     intake operation. Its input is the file, not a string member.
2. **[minor] §7 "Abort job, name the entry", AC-02/04.** Failure rows give the location (entry,
   sheet, row, column) and the limit. They never echo a value. Entry names are attacker text, so
   they go through the encoders, like `ValidationError` in safe-primitives.
3. **[minor] §2 row 1 versus §6.4.** ADMP bulk CSV (MIG-04) legitimately carries initial
   passwords, which contradicts "any credential … never imported". The plan moves MIG-04 to E2.3.
   Drop the row here, or say that its password column follows ADR-0005 rule 9 (transient
   secrets).
4. **[minor] §9 "Audit detail never contains … file content" versus "every applied proposal is
   its own audited Action".** The applied Action's diff necessarily holds imported values. Reword:
   raw file bytes, script bodies and secrets never appear; the configuration diff is audited as
   for any Store Action.
5. **[minor] §6.2, AC-07.**
   - Add a fitness function: only `migration` reads the proposal store, and applying goes only
     through the target module's Action IDs.
   - The importer's service identity holds no Action permission.
   - Proposals, fidelity rows and per-job blobs carry the tenant key under the tenancy rules (the
     PatchIQ §11 tenant-context lesson).
6. **[minor] 2c cut for C-03.** AC-16–18 (the sealed credential and egress) and the §9 "Outbound"
   bullet belong to the live and API routes, which come later. AC-21, AC-23 and AC-25's discovery
   half are 2d. Keep the refusal half of AC-19 (M5) and AC-22 in 2c.

## 5. Nits

1. AC-01: a CSV cannot carry an entity declaration. Test XLSX parts and HTML instead.
2. §7: a 100:1 per-entry ratio may abort legitimate, highly repetitive XLSX `sharedStrings.xml`.
   Confirm it against the lab corpus (§11 Q3 already allows that).
3. AC-05: state the minimum fuzz time per target (for example, 10 minutes per target nightly).

## 6. Follow-ups for the server board (not in this spec)

| # | File as | Title | Owner | Priority |
| --- | --- | --- | --- | --- |
| F1 | chore, `security-sensitive` | Threat model §5.18: add TB18 rows for grantee nomination (B1), dump replay (B2), file-route secrets (B3), imported gating weakening (M3) and lock-bypass triggers (M5); extend TM-F-MIGRATE | security-architect | P1 |
| F2 | decision-prep / ADR amendment | Define what a `request`-mode privilege does when no WorkflowDefinition matches (DM-34.I2 versus ADR-0005 rule 8 `permission-only`): hold for kernel single approval, never allow | solution-architect | P2 |

Carry-over row 2 (`ms-DS-ConsistencyGuid` into `guarded-v1`) still stands. M6 does not depend on
it.

## 7. Re-review

I re-review B1–B3 and M1–M7 against the C-03 revision. Minors and nits are the author's call,
but m6 decides what C-03's cut keeps.

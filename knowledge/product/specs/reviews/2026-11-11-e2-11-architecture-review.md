---
title: "Architecture review: E2.11 ManageEngine (ADMP) migration importer"
date: 2026-11-11
status: draft
owner: solution-architect
reviews: [knowledge/product/specs/e2-11-migration-importer.md]
plan_key: C-01
---

# Architecture review: E2.11 ADMP migration importer (plan key C-01, off-board)

This is the spec-stage review by `solution-architect`. It was done off-board on branch `m2c-plan`
under the CEO decision of 2026-11-11 at the top of `knowledge/memory/decisions-log.md`. No ticket
exists, so no `factory` command was run, and the spec was not edited. The author revises in **C-03**,
and this file is that work order. The security review (C-02) covers TM-TB18-T1…T12, the
allow/deny lists, the §6.3 applier check and the lock. Where this review touches those topics, it
covers only module fit and pipeline use.

**Checked against:**
- ADR-0003: rules 4–6, the rule 9 table (`migration` row) and dataset ownership.
- ADR-0004: rule 14, `apihost.Upload`, `maxBodyBytes`/`largeBodies` and A12/A15.
- ADR-0005: rules 1, 8 and 10, including the T-0892 undo amendment and the T-1221 class test; also O3, O7 and O8.
- ADR-0010 (ratified; C-16 will supersede it) and ADR-0011 rev 3.
- `e2-6-report-builder.md` §5 and §11 (FR-B18, AC-B28/B29), and `e2-7-hybrid-provisioning.md` FR-09, FR-33 and FR-41.
- `domain/domain-model.md`: DM-33, DM-36.I1/I4, DM-50, DM-60 and DM-73.
- `architecture/blueprint.md`: §4 (EP table, "migration sources are one importer shape"), the §5.4 `migration` row, `egress`, `proc` and `export`.
- `architecture/modules/reports.md` (export and notify rows as built) and `threat-model.md` §5.18 / TM-D21.
- The migration playbook §4.1 and §8, and `roadmap-skeleton.md` 2c/2d and exit criterion 6.
- `m2c-plan.md` §1 and rows C-27…C-105.

**Grades:**
- **Blocker:** C-27 (module design) cannot be done correctly until this is fixed.
- **Major:** a build ticket would be wrong, missing or would clone a seam.
- **Minor:** fix before that row is groomed.
- **Nit:** wording.

## Verdict

| Spec | Verdict | Blockers | Majors | Minors | Nits |
| --- | --- | --- | --- | --- | --- |
| E2.11 `e2-11-migration-importer.md` (draft, 2026-10-28) | **reject** | 2 | 9 | 10 | 3 |

The safety posture is right and agrees with TM-D21: proposals not live, scripts as text, never
import administrative grants, hostile-file limits, and the applier holds the privileges. What the
spec does not say is *how* a proposal becomes configuration. It names "an Action (T-0131)" and stops
there, so C-27/C-97 would most likely build a migration-private apply path with its own privilege
check. That would be PatchIQ anti-pattern #5, a bespoke parallel pipeline. The blueprint already
answers the question: `migration` writes what it imports **through the owning modules' Actions by
ID** (§5.4 `migration` row, ADR-0005 rule 10). The second blocker is the DB-dump route. It is in the
2c scope but is specified only as a size limit.

Nothing here needs the CEO. Every fix is a technical call or the author's.

---

## Ruling on the 2c scope cut

**Confirmed, with two amendments and three consequences.**

The director's cut is right on the merits. Exit criterion 6 is "every item is classified in the
fidelity report" (MIG-02/03 acceptance). That needs intake, classification, the fidelity report and
proposals. It does not need discovery, a comparator or an ownership switch.

- **MIG-01 discovery → 2d (confirmed).** It needs connector reads at R1, its own permission, and
  scale proofs (AC-23, AC-25 discovery half). None of these is on the demo path, and none of them is
  needed to classify an import.
- **MIG-10 comparator → 2d (confirmed).** The comparator diffs dry runs of imported *automations*.
  Their target, `lifecycle` (E2.9), only exists at 2d, and DM-60's `shadow` state is the natural
  host for it. Built at 2c, it would have nothing to compare.
- **MIG-14 ownership switch → 2d (confirmed), but the *lock* is 2c (amendment 1).** 2c applies
  imported report schedules (MIG-06 is in the 2c slice; E2.6 §11.3 and AC-B29 require them disabled
  "owner `manageengine`" and refusing to run), and AC-07 requires that nothing imported is active.
  So the `execution_owner` field and the single refuse-to-run guard are 2c work. Only the switch
  Action (AC-20) and the comparator ACs (AC-19 second half, AC-21) are 2d. See M-2.
- **§8 lifecycle change-volume limits → out of E2.11 entirely, not "2d inside E2.11" (amendment 2).**
  §8 is a rule for every lifecycle run. It overlaps DM-60.I3 `max_objects` and the O8 case "an
  automation run over `max_objects` is held". It belongs to the E2.9 spec, and the pipeline half
  belongs to an ADR-0005 amendment. See M-1. Plan row C-03 should read "move §8 to E2.9", not
  "carve §8 to 2d".
- **Consequence 1: workflow and automation items are classify-only at 2c.** Their target modules
  (E2.8 `workflow`, E2.9 `lifecycle`) are 2d. They get fidelity rows and stored proposals. Apply is
  offered only once the target Action is in `operation.Catalogue()`, so there is no dead button. See M-3.
- **Consequence 2: live-DB and API v2 routes stay deferred (confirmed), and so do their ACs.**
  AC-16, AC-17 and AC-18 are about a *saved credential* and a *registered ADMP server*, and neither
  exists on the dump route. The live route also needs a non-HTTP egress seam (m-1). The 2c ACs are
  AC-01–15 (AC-14 restated for the dump), AC-19 first half (report schedules), AC-22, AC-24 and the
  1M-row export half of AC-25.
- **Consequence 3: MIG-04 (ADMP-format bulk CSV) is E2.3, as the plan says.** E2.11 §2's row,
  enhancement 3 and frontmatter `ADM-010/011` should point to E2.3's CSV planner. They should not
  define a second CSV intake (m-9).

The 2c DB-dump route stays in scope **only once B-2 is fixed**. It may be narrowed to PostgreSQL
(ADMP's bundled engine, playbook §4.1) or replaced by an allow-listed extract. C-02 rules on that.

---

## Blockers

**B-1 · §6.2–6.3, §4 (lines 124–133, 98): the apply path is undefined, and the natural reading
builds a second pipeline.**

§6.3 says "Applying is an Action (T-0131) with a Plan" that checks DM-36.I1 itself. Three readings
are possible: a `migration.proposal.apply` Action that writes target tables directly, a migration
Action with its own privilege check, or the owners' Actions. Only the last is allowed:
- Blueprint §5.4 says "writes what it imports through the owning modules' Actions by ID (EP-3
  caller)".
- ADR-0005 rule 10 says every configuration write by a principal is the owner's `Store` Action.
- ADR-0003 rule 6 forbids writing another owner's tables.

Plan row C-97 ("Apply Action with applier-holds-every-privilege") already reads it the wrong way.

**Fix (state in a new §6.3):**
1. A proposal is migration-owned inert data. It holds the target Action ID, the target's
   parameters in the target's own schema and version, the fidelity row ID and the source item
   reference.
2. Applying it is an **Operation planned for the applier** that runs the owners' Actions:
   - `reports` definition create (E2.6 §11.3);
   - `reports.schedule.*` (landing disabled);
   - `delegation` scope create, `authz` role and assignment create (technicians);
   - E2.3 template and naming-format Actions;
   - later, `workflow` and `lifecycle`.

   The privilege rule is **the owners' own invariants**: DM-36.I1 for roles and assignments,
   DM-60.I2 for automation, DM-73.I2 for external delivery. Migration re-implements no privilege
   check. It only *pre-computes* the missing privileges for display, by calling the target's Plan.
3. `plan_hash` covers the proposal version. A proposal edited after review re-plans. A target that
   changed since import (name collision, deleted scope) fails Plan with the target's reason. Apply
   runs the target's validate-only first (generalising E2.6 §11.4).
4. **Undo** is the target family's `<owner>.<noun>.restore` (ADR-0005 T-0892 amendment). The HTTP
   surface is a preview twin and the undo pair (ADR-0004 rule 14). One apply that spans families
   (a technician = scope + role + assignment) uses the operation-level routes of **C-07**.
5. Atomicity: a composite proposal is **one Operation**, so it lands all or nothing. A scope must
   never land without its role.

Plan impact: C-27 must depend on C-07, and C-97 becomes "proposal store and apply via owners'
Actions".

**B-2 · §5 row 2, §7 row 2, §9 bullet 2, OQ 4 (lines 109–110, 176, 213–217, 281): the DB-dump
route is in the 2c scope but is not specified.**

The spec gives a 4 GiB cap and "streamed, never stored in the blob store", and nothing else. C-94
cannot be built from that:
- **Format is undefined.** The engines listed are PostgreSQL and MS SQL. A pg_dump plain/COPY file,
  a pg_dump custom archive and a SQL Server `.bak` are three different parsers. A `.bak` has no
  pure-Go reader on the licence register.
- **Restore is not forbidden.** The obvious implementation is "restore into a scratch database and
  `SELECT` the allow-list". That **executes** the dump (functions, `DO` blocks, triggers), which
  breaks TM-D21 ("never imports an executable artefact") and the rule that nothing an importer
  reads may run.
- **The deny list cannot hold at the boundary.** A full dump *carries* ADMP's stored AD credentials
  and technician password tables (TM-TB18-T4, Horizon3 finding). "Only allow-listed tables are
  extracted" happens *after* those bytes are on our host. That needs an explicit rule: deny-listed
  table bytes are skipped as a stream, never buffered or written to disk.
- **Single-pass consequence.** "Streamed, never stored" means the upload is parsed while it is
  received. A failed job cannot be retried without a new upload, and in HA the job is pinned to the
  receiving node. Neither is stated.

**Fix:**
- For 2c, accept **PostgreSQL plain-format pg_dump only**, parsed by a Go streaming parser of
  `COPY … FROM stdin` blocks, with an RT-13 fuzz target. The parser **never restores** the dump into
  any engine and never interprets SQL beyond the COPY grammar. Any other statement is skipped as
  data. Deny-listed tables are skipped without buffering. MS SQL is "not supported, stated in UI"
  until the live route.
- Alternatively (C-02 to rule): an **allow-list extract bundle**. We publish a read-only `SELECT`
  script per build that the customer's DBA runs, producing CSVs of the allow-listed columns only.
  Import then uses the file route, and credential tables never leave ADMP.

Either way, AC-14 is restated for the dump ("extracted tables ⊆ allow-list; a planted deny-listed
table's bytes appear nowhere on disk, in the store or in a log"), and OQ 4 is closed.

## Majors

**M-1 · §8 and AC-26–28 (lines 189–207, 259–261): lifecycle limits are not importer scope, and
they duplicate an existing invariant.**

DM-60.I3 already holds a run that plans more than `max_objects`, and ADR-0005 O8 already tests it.
§8 adds four new dimensions:
- a percentage default;
- disables plus deletes;
- zero unattended deletes;
- the same account changed twice in 24 h.

It also adds its own approve-subset UX and claims enforcement "in the operation pipeline (ADR-0005
O8, T-0393)" without an ADR change.

**Fix:** remove §8, AC-26–28, ADM-040–045 from frontmatter, and the title clause. File them as E2.9
input. The kernel half becomes an ADR-0005 amendment that generalises `max_objects` into a limit
set evaluated at Plan, with its O8 cases. Keep one sentence in E2.11: "an imported automation,
once owned by activeDIQ, is subject to E2.9's limits".

**M-2 · §6.8 (lines 156–161), AC-19/20: the lock and switch are fused, the vocabulary disagrees
with the domain model, and the enforcement point is unnamed.**

- **Vocabulary.** DM-60 and DM-73 already define `execution_owner` = `activediq | external`. The
  spec, and E2.6 §11.3 and AC-B29, say `manageengine`. `external` plus a provenance field
  (`source_product: admp`, build) survives ADAP and ADSSP (playbook P7, parameterise).
- **Where it is enforced.** The guard must have **one** enforcement point that every scheduled or
  triggered run passes. Candidates are the `platform/jobs` fire path or an operation-gate verdict,
  not each module's own check. §8 makes exactly this argument for its own limits.
- **Write class.** A write that sets `execution_owner = activediq` is a widening decision, so the
  owner's table is `config` (ADR-0005 rule 10 class test, T-1221).

**Fix:**
- Split §6.8 into "6.8a lock (2c)" and "6.8b switch (2d)".
- Adopt the DM vocabulary.
- Name the single guard, which C-27 places.
- Raise an erratum to E2.6 §11.3 and AC-B29 for the value name.

**M-3 · §2, §6.2: there is no proposal-target seam, and some targets do not exist at 2c.**

Each proposal kind targets a module:
- reports: E2.6, 2c;
- schedules: 2a;
- templates and naming: E2.3, 2b;
- roles and scopes: E2.5, 2b;
- workflows: E2.8, 2d;
- automations: E2.9, 2d.

E2.6 §11.1/§11.4 has already invented the right contract for one kind: a versioned target schema, a
validate-only call with class reasons, and an attribute map. Without generalising it, each kind
gets its own ad-hoc mapping inside `migration`, which is clone-per-variant. And workflow and
automation proposals would have no Action to apply through at 2c.

**Fix:**
- State that each target owner exposes the same three things for its proposal kind: schema and
  version, validate-only, and the Action ID. `migration` holds only the source-side parsers.
- Apply is offered when the Action is in `operation.Catalogue()`. Otherwise the row says
  "available when <module> ships", with no dead control.
- C-27 records this as the importer extension point and its fitness (a proposal kind without a
  registered target schema fails `Boot`).

**M-4 · §3.1, §6.5, AC-12 (lines 80–82, 141–145, 245): fidelity classes are not defined once, and
the acceptance number is missing.**

E2.6 §11.2 now defines the four classes precisely for reports:
- `manual` includes an unregistered attribute, with a one-click sync-set fix;
- scripts are `manual`;
- secret attributes and raw SQL are `not supported`.

E2.6 §11.4 also says "the `exact` plus `changed` share on lab ADMP 8043 is **E2.11's acceptance
number**". E2.11 states no such number, and it has no general class definitions for non-report
kinds.

**Fix:**
- Add a §6.2 class table: general definitions, with E2.6 §11.2 cited as the report instance (FB-10;
  AC-12 cites it, and its filter target is `ReportAst` via the P1 parser, not "the typed filter
  AST").
- Add the 2c acceptance: 100 % of inventory rows classified exactly once, and an `exact + changed`
  share `[LAB]` target set from C-30.
- Add a re-classify transition, so a `manual` row whose blocker the admin fixed (sync-set add,
  technician mapped) is re-evaluated without a re-upload.

The classes must agree with E2.6 word for word.

**M-5 · §7 (lines 168–187), AC-03: the limits table cannot be enforced as written, and it has
gaps.**

- **The memory cap needs a mechanism.** "Per-job memory 512 MiB → abort" has no mechanism in a
  shared Go process: `GOMEMLIMIT` is per process, and a goroutine cannot be capped. Either memory is
  bounded *by construction*, with every reader a counting `io.LimitReader`, fixed buffers and
  per-row caps, or parsing runs in a child process under OS limits (`platform/proc` plus a Job
  Object on Windows or rlimit/cgroup on Linux). The second option also contains a parser crash.
- **Two caps are missing:**
  - **Columns per row / bytes per row.** 16,384 columns × 32,767 characters passes every listed
    cap at ~1 GiB per row.
  - **Items or proposals per job.** 1,000,000 rows can become 1,000,000 fidelity rows and
    proposals in PostgreSQL.

**Fix:** add both caps. Restate the memory row as an outcome ("a hostile file cannot raise server
RSS above X or p95 latency of other requests above Y", proven by AC-03). C-27 chooses
by-construction or child process, and the choice is recorded in the module page. A new process role
would be an ADR-0002 amendment.

**M-6 · §6.1–6.7: there is no data model and no write classes.**

The domain model has no migration entities. The spec introduces migration project, job, proposal,
fidelity row and technician mapping without owners, states, keys or retention. After T-1221, every
table needs a write class (ADR-0005 rule 10, O3 fails a table without one).

**Fix:** list the entities with owner `modules/migration`, the job states (`quarantined → parsing →
classified | aborted`; proposal `pending → applied | rejected | superseded`), and the classes
proposed for C-27 to confirm:
- Proposals and fidelity rows are inert: they cannot widen until a target Action applies them.
- **Technician mapping is a widening input.** It chooses who receives grants. Either it is
  `config`, or it is carried *inside* the proposal and shown in the Plan the applier signs. I
  recommend the latter.

State retention for these rows. Fidelity rows and recipient lists carry personal data.

File the DM entries as a C-27 sub-deliverable.

**M-7 · §4 (line 101), §6.7, §10 "large": directory references are by name/DN, and the resolution
path is unnamed.**

"Group names resolve to DNs" contradicts the data-model rule: objects are keyed by `objectGUID`,
because DNs change on move or rename. ADR-0011 retired the live LDAP search (T-1127), and fuzzy or
trigram matching must never decide a grant target.

**Fix:** proposals store `(connection_id, objectGUID)` for every directory reference. A name or DN
from ADMP resolves **exactly** through the `inventory` batch resolver (E2.6 FB-6b
`inventory.ResolveIdentifiers`; DNs through the `dn` package). Zero or several matches → `manual`,
naming the candidates. A resolved `tier0` object → `not supported` (TM-TB18-T2). Add FB-6b as a
dependency of C-95.

**M-8 · There is no API section (ADR-0004).**

C-100 defines the OpenAPI, but the spec must give it the operation list and the limits ADR-0004
checks:
- the upload operations with `maxBodyBytes`. 256 MiB and 4 GiB both exceed 16 MiB, so each needs a
  `largeBodies` entry with a reason (A12). The §7 "size gate" *is* `apihost.Upload`'s cap.
- the **one intake operation** that E2.6 §5 says RP-B1 allow-lists (name it);
- the async job pattern (`202`, poll the job);
- the apply surface per B-1 (preview twin, `ActiveDIQ-Operation-Id`, operation-level routes, A15);
- the EP-6 permissions: `migration.import` and `migration.apply`, if migration has its own apply
  Action at all after B-1. State their `kind` and whether any is `control_plane` (the DM-33
  backstop).

**M-9 · §3.1, §6.9: the fidelity export would be a bespoke exporter.**

C-99 ("fidelity report view and CSV/PDF export", reporting-engineer) reads as a migration-private
export. `platform/export` already builds CSV, XLSX, PDF and HTML (T-0963, T-0964) with the About
block and digest. ADR-0003 lets a module register a dataset over its own tables.

**Fix:** state that the fidelity report is a report. `migration` registers an EP-8 dataset over its
fidelity rows, and the export is a normal run (ADR-0010 rows, digest, `platform/export` encoders,
T-0150 escaping, which is what AC-06 tests). It is not a second encoder path.

## Minors

1. **§5 Delivery, §9 Outbound (lines 114, 218–220).** "DB reads go through the egress client":
   `platform/egress` is the HTTP client only (blueprint §1, T-0160). A PostgreSQL or TDS connection
   needs a vetted-dial seam that does not exist. Move to the deferred live route, with a note that
   it needs one. SQL Server Kerberos would reuse `connector/ad/gssapi`, not a new stack.
2. **§10 "large" (lines 266–267) and AC-25.** "Groups with > 1,500 members are read through ranged
   retrieval" is discovery. Importers read no directory (§9). Move it to 2d with MIG-01, and split
   AC-25.
3. **§6.3 (line 132).** "The importer's own service identity is never the applier": there must be
   **no** importer identity. The import job runs with no principal of its own (audit initiator =
   the creating account). Its proposal writes are migration's own rows, and it holds no grants.
4. **§4 row 3 (line 98).** "One audit Action per proposal": an Action is a type, and an Operation is
   an instance. Say "one Operation per proposal". State that one step-up covers N applies only
   within the TM-D16 freshness window, and that a mid-batch Plan refusal does not stop the others.
5. **§6.6 (lines 147–149), AC-22.** Use what is built: "allowed domains" = `notify/settings`
   allowed recipient domains (T-0950). The "override" is DM-73.I2's external-delivery permission
   plus step-up on `reports.schedule.*`, not a new override concept.
6. **E2.7 cross-check (templates).** Imported ADMP creation templates that carry O365 settings map
   to DM-50 `provider = hybrid` templates. Through the target's validate-only (M-3):
   - a `ms-DS-ConsistencyGuid` write is `not supported` (E2.7 FR-09);
   - a cloud group not on the writable list is `manual` (FR-41; the import never adds to that
     list);
   - no imported template grants a cloud permission (DM-50.I3).
7. **§7 / XML (line 185).** HTML exports are not XML, so `encoding/xml` cannot parse them. Name
   `golang.org/x/net/html`: the module is on the register (BSD-3, T-0950), so add the package use
   to its row. The XLSX reader is our own over `archive/zip` + `encoding/xml`. No XLSX library is on
   the register.
8. **AC-01 (line 234).** "The job aborts or the entity is inert" is not deterministic. Pick one:
   abort on any `DOCTYPE`.
9. **§2 row 1, §3.3, frontmatter parity (lines 11, 60, 83–84).** MIG-04 and ADM-010/011 are E2.3's
   (m2c-plan §1). Point to E2.3 and keep the parity list to what 2c E2.11 delivers (the plan says
   "no matrix IDs").
10. **Audit provenance, AC-24.** An applied proposal is the owner's Operation, so its event must
    carry `origin = migration proposal <id>, job <id>` for TM-TB18-T11 to hold. List the
    `migration.*` audit kinds (EP-7).

## Nits

1. Title and §0 still name the lifecycle limit. Retitle after M-1.
2. Frontmatter `scope: locked` and `sources_last_checked: 2026-10-28` while the scope is being cut:
   update both in C-03.
3. OQ 1 is now plan row C-29 (lab ADMP 8043, schema, allow-list, EULA). Cite it. The ADMP trial
   action is A-0024 in decisions-log 2026-11-02 and A-0036 in m2c-plan. The director should
   reconcile the two at filing.

---

## Stale against what landed since 2026-10-28

| Landed | Date / ref | Where E2.11 is stale | Finding |
| --- | --- | --- | --- |
| ADR-0005 rule 10 class test, O3 allow-list | 2026-11-01, T-1221, D-0019 | No write classes. The owner switch is widening | M-2, M-6 |
| ADR-0005 config undo and ADR-0004 rule 14 (preview twin, undo pair) | 2026-10-30, T-0892 | Apply has no preview or undo | B-1, M-8 |
| C-07 operation-level routes (planned) | m2c-plan | Multi-family apply needs it | B-1 |
| ADR-0010 ratified; ADR-0012 to supersede (C-16); `platform/export` CSV/XLSX/PDF/HTML built | 2026-11-01; T-0963/T-0964 | Bespoke fidelity export | M-9 |
| ADR-0011 rev 3; live LDAP search retired (T-1127); FB-6b resolver | 2026-10-31 / 11-02 | Name → DN resolution | M-7 |
| E2.6 §11 (classes, step-up apply, validate-only, `ReportAst`, acceptance number) | 2026-11-11 | §6.5, AC-12, no acceptance number | M-3, M-4 |
| `notify/settings` allowed recipient domains | T-0950 | §6.6 invents its own | m-5 |
| `egress` built as HTTP-only | T-0160 | DB reads "through egress" | m-1 |
| EP-11 provider extraction (facets) | 2026-10-30, T-0993 | §5 "AD-only object" for Entra-only tenants should read as a provider capability, not a kind | (fold into m-6 wording) |
| DM-60 / DM-73 `execution_owner` | domain model | `manageengine` vocabulary | M-2 |

## Plan impact (for the director at filing; no change made to `m2c-plan.md`)

- **C-03** grows from S to **M**. It must fix B-1, B-2 and M-1…M-9, not only the three items in its
  row. Its AC should read: "E2.11 states its 2c scope per the C-01 ruling; §8 moved to E2.9; AC-12
  cites E2.6 §11.2; B-1/B-2 closed".
- **C-27** depends on C-07. Its AC adds the proposal-target seam (M-3), the lock guard (M-2),
  entities and classes (M-6), and the isolation choice (M-5).
- **C-28** adds a check: a proposal kind without a registered target schema fails `Boot`.
- **C-94** waits on the B-2 and C-02 ruling (pg_dump COPY parser or extract bundle).
- **C-95** depends on FB-6b.
- **C-97** is reworded per B-1.
- **C-99** becomes "register the fidelity dataset; export through `platform/export`".
- E2.6 needs an erratum for the `execution_owner` value (M-2).
- E2.9's spec inherits §8 (M-1). Its ADR-0005 amendment is a 2d ticket.

## Re-review checklist (C-03 → re-review)

1. A §6.3 apply contract naming owners' Actions, one Operation per composite proposal, undo and
   C-07 routes (B-1).
2. The dump route: format, no restore, deny-list streaming skip, single-pass, PostgreSQL-only or
   extract bundle (B-2).
3. §8 gone (M-1). §6.8 split; DM vocabulary; one guard (M-2).
4. The proposal-target contract and catalogue-gated apply (M-3). The class table, acceptance number
   and re-classify (M-4).
5. Limits: column/row-byte and item caps; memory as an outcome (M-5).
6. Entities and classes (M-6). GUID-keyed references through FB-6b (M-7). An API section (M-8). The
   fidelity dataset (M-9).
7. The 2c AC list as in the ruling above, with deferred ACs marked 2d or "live route".

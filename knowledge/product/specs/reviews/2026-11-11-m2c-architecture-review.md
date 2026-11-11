---
title: "Architecture review: M2c specs E2.7 hybrid provisioning and E2.6 report builder"
date: 2026-11-11
status: draft
owner: solution-architect
reviews: [knowledge/product/specs/e2-7-hybrid-provisioning.md, knowledge/product/specs/e2-6-report-builder.md]
---

# Architecture review: E2.7 hybrid provisioning and E2.6 report builder (M2c, off-board)

Spec-stage review by `solution-architect`, off-board on branch `m2c-plan` (CEO decision 2026-11-10,
decisions-log). No ticket exists, so no `factory` command was run. The authors fix the specs; this file is
the work order.

**Checked against:** ADR-0003, ADR-0004 (rule 14), ADR-0005 (rules 1–3, 7–11), ADR-0010 (**accepted**
2026-11-01), ADR-0011 rev 3 (ratified), `domain/domain-model.md` (DM-10, 20, 21, 24, 34, 35, 40–42, 50,
70–72, 80), `architecture/connector-contract.md` v1.2 (§6.6, §8.1, §8.9), `blueprint.md` (parity → module
table, T-0326 ingester), `architecture/modules/reports.md` (§3.2, §3.4, §5, §6.1–6.6), and
`e2-11-migration-importer.md` (draft, 2026-10-28).

**Grades:** blocker = the spec cannot be groomed correctly until fixed · major = a ticket would be
wrong or missing · minor = fix before grooming that row · nit = wording.

## Verdicts

| Spec | Verdict | Blockers | Majors | Minors | Nits |
| --- | --- | --- | --- | --- | --- |
| E2.7 `e2-7-hybrid-provisioning.md` | **reject** | 1 | 7 | 8 | 3 |
| E2.6 `e2-6-report-builder.md` | **reject** | 1 | 7 | 11 | 4 |
| Cross-spec (E2.6 ↔ E2.7 ↔ E2.11), counted separately; both specs must fix X-1 and X-2 | n/a | 0 | 2 (X-1, X-2) | 1 (X-3) | 0 |

Both drafts are close. Neither needs a redesign. Each rejection comes down to one requirement that
contradicts a ratified or accepted ADR without saying so, plus follow-up lists that would give the
project-manager an incomplete or misrouted ticket set. No ADR change needs the CEO: every amendment
below is technical, so the director ratifies it.

---

## E2.7 hybrid provisioning

### Blocker

**H-B1 · FR-10 + FR-21 (lines 214, 233) with AC-12 and AC-15 (lines 310, 313) cannot both hold under ADR-0005 rule 3, and §8/OQ-F1 do not list the gap.**
ADR-0005 makes the *item* the unit of blocking and of phase. "Items in phase n+1 start only after phase
n is terminal" (rule 1, `StepPlan`). A `blocked` item does not stop other items: the result is "at best
`partially_succeeded`" (rule 3). Inside one item, "a step failed … later steps `not_run`" and the item is `failed`.
- If the AD half and the cloud half are **two items** (which is what §8's "AD steps phase 1, cloud steps
  phase 2" implies), FR-10/AC-12 fail. A cloud item blocked for `usage_location_missing` still lets the AD item
  run, but AC-12 requires "no AD write occurs".
- If they are **one item**, AC-15 fails. The licence is verified and the group add is refused, so the item is
  `failed` and the operation is `failed` (no item succeeded) while the AD user exists. FR-21 requires
  `partially_succeeded` with a per-step list.

**Fix:** add to OQ-F1 and §8 an ADR-0005 amendment for a **coupled item group** (one request = N items
planned all-or-nothing at Plan: any blocked item blocks the group; at Apply each item keeps its own
outcome). Restate FR-10 as "Plan MUST block every item of the request" instead of "Plan MUST NOT start any AD
write", because Plan never writes.

### Major

**H-M1 · FR-18, FR-21, AC-14, AC-21 (lines 230, 233, 314, 319): resume and the new outcomes contradict rule 3's closed sets. OQ-F1 covers only an "AD done, Entra pending" outcome.**
- FR-21 adds the terminal results `ad_done_cloud_expired` and `ad_done_cloud_cancelled`. Rule 3 closes the operation result set (`succeeded | partially_succeeded | failed | no_change | cancelled`), and so does `operation.completed` (rule 11).
- FR-18 and AC-21 call the same state `expired_waiting` and make it resumable.
- AC-14 resumes a step that `failed` with `replication_pending`.
- "Nothing leaves a terminal state except `→ undone`" (rule 3). Rule 3 also says "the technician then retries as a new operation".

**Fix:** use one name per state. Either map the outcomes onto the existing set (`partially_succeeded` or `cancelled` with counts, plus a `cloud_reason`) or list them as amendment items. Define **Resume** as a new Operation (origin `console`, linked by `request_id`) planned against live state, not as a transition out of a terminal state. Add both points to OQ-F1.

**H-M2 · FR-33 (line 255) "checked at Plan" has no defined meaning for a target that does not exist yet. That is a rule 7 gap, not only a hashing gap.**
At Plan there is no Entra object and no correlation. So `include_correlated` through a `matched` correlation
(DM-35.I6) cannot be evaluated, and neither can an `administrative_unit` or `group_members` root. ADR-0005
defines "to be created" only as an AD planned parent GUID plus RDN (rule 1). **Fix:** OQ-F1 must also cover
*what authority the Plan check proves for a deferred Entra target*. Recommendation: at Plan, require the
permission over the tenant's `entra_tenant` root, or over the planned AD parent with `include_correlated`.
At Apply, re-check against the resolved object (FR-16). For the deferred-target hash (§8 row 2), bind the
placeholder to `(entra_connection_id, anchor_attr, anchor_value)` so the hash stays stable *and* binds the
identity FR-14 records.

**H-M3 · I360-003 is "In" (line 89), yet no FR delivers Entra inventory sync. Correlation can only change through sync.**
Blueprint maps I360-003 and ADM-169 to `sync` (Graph delta, `provider/entra`). DM-20.I5 says "the stored
state changes only through sync (kind D)", and the T-0326 ingester judges the gate "only from stored
inventory". FR-15 and FR-19 ("targeted lookup and re-evaluate") read as if the hybrid flow evaluated the
correlation itself. FR-30 shows Entra objects in "every … search row". ADR-0011 rule 9 says Entra objects are
"admitted by no 2a scope kind" until T-1131. **Fix:** (a) add FRs, or a named dependency, for Graph delta
sync of users, groups and SKUs into inventory (connector §6.6), with the targeted re-sync that DM-20.I5
already names. "Check now" requests a targeted re-sync and then *reads* the correlation. (b) List T-1131
and the DM-35 Entra root evaluators (m2-plan E-011) as dependencies of FR-30, FR-32 and FR-33.

**H-M4 · §9 (line 277): `m365.group.member.add/remove` and `m365.user.usage_location.set` clone AD Actions per provider.**
Blueprint's parity table puts ADM-164/M365-007 in **`objects` on the Entra provider** and only ADM-161
(licences) in `m365`. EP-11 (decisions-log 2026-10-30) keeps one `(ProviderKind, WriteKind)` table with
handlers that "branch on facets, never on kind". **Fix:** group membership uses the `objects.group.member.*`
family parameterised by provider. Usage location is an `objects.user.update` key on the Entra plane, unless
the spec argues otherwise in one line. FR-33's permission names follow the same families.

**H-M5 · FR-25 (line 242) guards only group steps. The licence and usage-location writes are guarded too, and get no FR or AC.**
Connector contract §8.9 (TM-D25 rule 7): `ASSIGN_LICENSE` is refused when the dynamic-group closure holds
`assignedPlans`, `mail` or `proxyAddresses`. An Entra `UPDATE` is checked by key, and `user.usageLocation`
is a common dynamic-membership rule property, so setting it can pull the new user into a dynamic group.
**Fix:** extend FR-25 to "every cloud step passes the §8.9 property guard with its `PropertyWrite`". Add
AC-17 cases for a licence step and a `usageLocation` step under a closure.

**H-M6 · FR-17 (line 229) has no AC for its security branch, and "re-approval" is undefined when the original gate was `permission-only`.**
AC-06 covers only the equal-diff path. Nothing proves that a changed SKU, group, scope or availability *holds*.
If the first submit passed the kernel default gate, there is no approver to ask again. **Fix:** add an AC
for "re-plan differs → cloud half held, zero Graph writes, new diff shown". Define the hold: kernel hold
reason `replan_changed`, routed through rule 8 like any hold, with the initiator able to re-submit when no
workflow matches. Also missing an AC: FR-02 (several tenants), FR-05 (application-only), FR-06 (90-day max
age, 14-day warning, token discarded), FR-07 (write gate closes and re-opens), FR-26 (group-based licence
verify), FR-31 (licence and group actions on existing users, ≤ 50) and FR-35 (closed error set). The ACs
name no FRs, unlike E2.6. Add the FR column so the trace can be checked.

**H-M7 · No ADR-0004 follow-up although §9 (line 279) adds operation-level routes.**
ADR-0004 rule 14 defines one undo pair *per Action family* ("404 when … its Action is outside the family").
It says: "Directory Actions … The operation status and approval routes are a later amendment." A hybrid
request spans `objects.user.*`, `m365.licence.*` and `objects.group.member.*`, and needs status,
check-now, cancel-cloud-steps and resume. **Fix:** add an ADR-0004 rule 14 amendment to §14 for
multi-family operations: the status route, cancel, resume as a new operation (H-M1), and undo of a
multi-family operation.

### Minor

1. **FR-12 / AC-19 (lines 216, 317):** undoing the AD create of a synced user deletes the Entra object
   through sync, which releases the licence and starts the 30-day soft-delete. That is an effect on
   another system that the undo preview must class `Lossy` and name (rule 1). AC-19 only adds "a note".
2. **FR-14 (line 226):** DM-20.I1 allows any `anchor_attr`, including string anchors such as employeeID.
   A tenant with a non-default sourceAnchor would wait 24 h and expire. Add `source_anchor_attr` to
   the DM-21 follow-up, or detect it at hybrid-link confirmation.
3. **FR-08 (line 207):** the Cloud Sync default of 2 min contradicts the spec's own §1, which cites the
   FAQ's 10–20 min. With "late" at 3× the interval, that raises false alarms after 6 min. Default to
   20 min `[PROPOSED]`.
4. **FR-35 (line 257):** the "closed set" leaves out `ambiguous_anchor`, `expired_waiting`,
   `read_back_mismatch`/`verify_failed` and `outcome_unknown` (minor 5). Either list every code
   used in FR-11 to FR-29 or state the mapping.
5. **§8 row `outcome_unknown` (line 270):** right to flag. Add it to OQ-F1 explicitly. Rule 3 says
   `outcome_unknown` is reachable "only [by] a password step", and its corollary "a `failed` step never
   changed its target" breaks for a Graph timeout after send. Naming it in §8 without an OQ-F1 line leaves
   it unowned.
6. **FR-11 (line 215):** "fails `insufficient_licences` if it changed" should read "if no unit is
   available at Apply". A drop from 5 to 4 must not fail the step.
7. **E4 / AC-02 (lines 112, 300):** DM-24 says an EV3 `fail` "is overridable by a DM-25
   acknowledgement". State whether an Entra directory role or deny-list permission can be acknowledged.
   If it can, E4's claim "refuses activation" needs "unless acknowledged". If it cannot, record that as a
   DM-24 follow-up.
8. **FR-34 (line 256):** the `hybrid.*` audit kinds need EP-7 registration by their owner (ADR-0005 rule 1,
   `Boot` refuses unregistered kinds). Add them to §14.

### Nit

1. §5 line 148: "T-1005-style cell work in ADR-0002". T-1005 is the EP-11 provider migration. Cite the
   saas-cell ticket or drop the reference.
2. Flow B step 3 (line 179) merges the step-up and the kernel hold for irreversible changes, which rule 8
   keeps apart.
3. §5 matrix row "FR-13…21 continuation and wait": FR-13 belongs to §7.2.

### Follow-ups the spec claims: real, complete, correctly scoped?

| Claimed follow-up | Real? | Complete? | Scope note |
| --- | --- | --- | --- |
| ADR-0005 wait/gate step (OQ-F1) | Yes. Rule 3 has no `running → planning` edge and no wait | No. Add H-B1 (coupled items), H-M1 (resume, outcomes), H-M2 (rule 7 at Plan), minor 5 (`outcome_unknown` for Graph) | ADR-0005 amendment (ratified ADR, so an amendment is allowed). Technical, so the director ratifies |
| Deferred-target hashing | Yes. Rule 9 hashes "every item's target" | Add the binding recommendation (H-M2) | Same amendment |
| Resume / outcome states | Only partly claimed ("AD done, Entra pending") | No (H-M1) | Same amendment |
| `plan_valid_until` vs sync interval | Yes. 1 h for directory Actions (rule 9) | Also say whether the 72 h secret TTL matters. It does not, because the password is used in phase 1. State it | Same amendment |
| Connector `WriteKind` arms | Yes (§8.1 "no kind in v1.1") | Frame them as Entra rows of the EP-11 `(ProviderKind, WriteKind)` table with a `PropertyWrite` per kind (§8.9), and put group membership under `objects` (H-M4). Retryable not-visible error: yes, `OBJECT_NOT_FOUND` is "never" retried today (§7) | connector-contract revision, director review |
| Domain-model entities | Yes (DM-16, 21, 24, 33, 40, 50; LicenceSku) | Add DM-21 `source_anchor_attr`, DM-41/42 coupled group (H-B1), DM-80 kinds | `ad-expert` + `backend-engineer` |
| **Missing** | | ADR-0004 rule 14 amendment (H-M7); Entra inventory sync dependency (H-M3); T-1131 / E-011 Entra root evaluators (H-M3) | |

---

## E2.6 report builder

### Blocker

**R-B1 · §9 (lines 290–291), §6 rows 4 and 6 (lines 201, 203), FR-B08 (line 551), AC-B15/B16: a preview's "exact count" from `CompileCount` contradicts accepted ADR-0010 rule 3. FB-3b does not list it.**
ADR-0010 rule 3 says "The total is `report_runs.row_count` and is never a `COUNT(*)`". reports.md §5 says
`CompileCount` is used "only for the … message after the cap trips" and that "totals shown to users are
never `COUNT(*)`". A separate count statement also runs on a different snapshot from the stored rows, so
the count can disagree with the page. That breaks the spec's own rule in §9(f). §6 row 4's per-condition
"narrows to 1,204 users" multiplies the problem, and no FR, AC or budget covers it.

**Fix:** compute the match count **in the run's one cursor statement** (`count(*) OVER ()` beside the
`LIMIT cap+1`), store it as a typed run field, and list that field in the new ADR (R-M1). Drop the
per-condition live counts, or specify them as preview runs with their own cap and budget. Keep "1,000+"
only for the statement-timeout case.

### Major

**R-M1 · FB-3b (line 501) "ADR-0010 amendment (revision)" is not possible. ADR-0010 is `accepted` (2026-11-01, fitness RP3–RP5 green) and therefore immutable.**
Under the ADR ladder, an accepted ADR changes only through a superseding ADR, or an erratum that "changes no
rule". Preview-class retention (rule 5: "7 days at 2a"), a second total, and the run record of an unsaved
definition are rule changes. **Fix:** FB-3b becomes **a new ADR that supersedes or extends ADR-0010**. It
climbs the ladder with its own fitness additions, and RP3–RP5 must stay green. Scope it to:
- run class `preview` (1 h, superseded-expiry, its own job cap);
- the in-statement match count (R-B1);
- group and total rows (`row_key` as the hash of the key values, a row-kind discriminator for the total row,
  digest and export coverage of the total row);
- totals **in the same statement** (GROUPING SETS/ROLLUP). Drop the "repeatable-read snapshot" alternative:
  rule 2 says "no isolation above default" and rule 6 bans held snapshots, while one statement already
  satisfies rule 2;
- a run of an unsaved AST. `report_runs` records `definition_id`, `definition_version` and
  `definition_sha256` (reports.md §3.6, §6.2), and a preview has none of them. Store the AST hash and the
  typed AST instead.

**R-M2 · FB-3a (line 500) under-scopes the reports.md change. The custom definition does not fit the §3.4 types.**
`report.Definition` is "shipped as JSON under `library/`". Its `Category` enum has no `Custom`, it requires
`Presets ≥ 1`, its `DefinitionID` is `"usr-01"`-shaped, and `Resolve(def, preset, p, ds)` takes the shipped
type. **Fix:** FB-3a also covers:
- a stored `CustomDefinition` in the `report_definitions` table, with owner, origin, `ast_version`, versions
  and shares;
- how `Resolve` takes it;
- the `Custom` category;
- the ID namespace;
- §3.2's grouping nodes, `ActionSubject` and the per-field read permission, as already listed.

**R-M3 · §16 (lines 489–491) and AC-B35 (line 783): a rolled-up `reports.preview` event "per account and dataset per 10 minutes" contradicts ADR-0005 rule 11 and DM-80, yet §17 says "ADR-0005: no amendment".**
Rule 11 and DM-80.I1 chain events "at commit" with the state they record. A window aggregate needs an
uncommitted buffer, which is lost on a crash, and it is emitted after the fact. A preview already writes a
`report_runs` row in a transaction (§9), so a per-preview event costs nothing extra in architecture.
**Fix:** one event per preview run (a light kind; the filters hash and row count, no values). AC-B35 becomes
"12 events". Or keep the rollup and list an ADR-0005 rule 11 amendment for `security-architect` (FB-5).

**R-M4 · §7 (line 225) against §21 (line 794) and DM-80.I4: `audit.events` is in scope and out of scope at once, and its "no personal value" column set lists two personal values.**
- §21 puts "custom reports over audit events → M3". §7, FR-B26 and AC-B31 put `audit.events` in 2c.
  The intent is probably DC events, so say so.
- "Actor (display)" and "target … display name" are `PersonalRef`s (DM-80.I1/I4: the display snapshot "is
  personal data and is erasable"). Resolving them into `report_run_rows` copies erasable values out of the
  side store for the retention period (ADR-0005 rule 12).

**Fix:** reconcile §21. Either drop the two display columns, or make FB-5 rule on erasure of stored rows
(expire runs that hold an erased subject) before FR-B26 is built.

**R-M5 · Line 508, "ADR-0011 needs no amendment for pickers", is not shown, and is probably false.**
ADR-0011 rule 10 fixes the search producer to `rbac.ReadScopes.For(…, directory.read)`, and rule 9 says
"every kind in the 2a set is read under `directory.read`". The run is trimmed under `reports.run`. A runner
whose `directory.read` scope is wider than their `reports.run` scope would see managers, groups and OUs in a
picker that the report itself hides. That is the LF-36 leak §9(e) claims to close. **Fix:** state which
scope the picker uses. If it is `reports.run`, which matches §9(e), add a small ADR-0011 amendment that
lets `inventory.Search` take a caller-named permission for a picker, with an SE3-style test. FB-6 can carry
it.

**R-M6 · §11.2 (lines 365–371): the `exact` example meets the spec's own definition of `changed`, and the script class disagrees with E2.11.**
- The example maps `userAccountControl:1.2.840.113556.1.4.803:=2` to "enabled". §11.2 itself classes "a
  bit test to the registered enabled/locked column" as `changed`. `objectCategory=person` also matches
  contacts, so mapping it to dataset Users narrows the result.
- §11.2, §11.4 and AC-B28 class scripts as `not supported`. E2.11 §6.5 and its AC-11 class script-bearing
  content as **`manual`**.

E2.11's acceptance number counts `exact` + `changed` (§11.7), so ambiguous class boundaries make it
untestable. **Fix:** use a true `exact` example (`(department=Finance)` on Users), class the given one
`changed`, and align the script class with E2.11. E2.11 owns classification, so change E2.6 (see X-3).

**R-M7 · §8 (lines 239–240), FR-B09 (line 552) and §11.3 (lines 372–376): the definition's lifecycle has three conflicting stories.**
- §8 and FR-B09: "nothing is stored before Save", with drafts held in the browser.
- §9: previews store rows and a run record.
- §11.3: an applied import is a server-side definition that becomes "version 1 only when the admin opens
  and saves it". That is an unversioned, server-side state the version model does not have.
- DM-71: `draft → published → archived`, with no `delete`, while §8 has
  `delete | restore | reassign`.

**Fix:** pick one model and record it in FB-3d. Recommendation: a server-side `draft` (DM-71), unshared and
unschedulable, which an import also lands in, and from which Save publishes version n. Say that previews
store run rows, not definitions. Name the import's version state explicitly, and say whether the applier
can run it before review. Also align with E2.11 §6.3: apply needs step-up.

### Minor

1. **FR ↔ AC gaps:** FR-B07 (≤ 64 columns, ≤ 4 sort keys, column order = export and digest order) and
   FR-B24 (OpenAPI first, one `x-permission`, generated client only) have **no AC**. FR-B23 is proven only
   for preview and `group_members` (AC-B15, AC-B34). The grouped preview, the full run and the picker budgets
   in §14 are untested.
2. **AC-B19 (line 687)** is traced to FR-B22 (audit) but tests caps and timeouts. Trace it to FR-B21 and
   add the §9 preview cap to an FR. **AC-B08** should also trace FR-B06.
3. **AC-B09 (lines 627–631):** the Given ("sorted by manager", "grouped by OU path") is never used in the
   When. **AC-B09 and AC-B17** use `lastLogon`, a per-DC field that §7 (line 228) and §21 (line 800) exclude
   from the builder. Use the replicated logon column.
4. **AC-B06 (line 610):** the hostile corpus has LDAP metacharacters but no LIKE metacharacters (`%`, `_`,
   `\`), which are what `LikePattern` (P5 rule 4) must neutralise. Add them.
5. **Inconsistent `FB-3`:** "FB-3" appears unlettered at lines 136, 160, 173, 292, 329 and 395, while §17
   splits it into FB-3a–d. FB-1, 2, 5, 7, 8 and 9 appear only in prose and §22. Give §17 one table of
   every FB-n, so the project-manager can map them to ticket IDs.
6. **Caps tables disagree:** §5 step 2 lists what `Resolve` refuses. It leaves out the sort-key cap (4,
   FR-B07), Top N (≤ 1,000) and the 10,000-group cap. The §9 table leaves out sort keys and Top N. Use one
   list.
7. **Preview statement timeout:** §9 inherits "the P5 SQL-22 timeout", which is 15 min for the run job
   (reports.md §5). With 2 preview slots per tenant, two heavy previews block the builder for 15 min (abuse
   case 5). Set a preview timeout `[PROPOSED]`, for example 10 s, and name it in AC-B16.
8. **§5 grouping (lines 160–167):** a guid-with-label group key (for example manager) must take its label
   from the masked related column (reports.md §3.3), or an out-of-scope manager's name leaks as a group
   label. Say so, and add the case to RP-B3. Time buckets "in the runner's time zone": state the zone for
   schedule runs and record it in the query hash.
9. **FR-B17 / AC-B26:** the accepted identifier kinds are unspecified until FB-6 decides, so AC-B26 cannot
   be tested as written. Name the default set (GUID, DN) and the FB-6 extension.
10. **§17 last row (line 506):** a write class is declared on the migration's `-- write-class` line
    (ADR-0005 rule 10), not "in the O3 writers list". That list holds only `system` writers. `report_shares`
    is a widening decision, so `config` is right.
11. **§11.5 (line 380):** leaves out E2.11 §6.8's ownership lock. Imported schedules start
    owner=`manageengine` and "cannot run" until a step-up switch. AC-B29 should assert it. §11.4 cites
    E2.11 §6.4 for "ADMP's attached tasks", which that section does not list.

### Nit

1. Frontmatter lacks `reviewer: solution-architect` and `security-sensitive: true`. §16 tags build
   tickets security-sensitive.
2. Lines 24–25 anchor 2c on "m2-plan row E2.6", but m2-plan line 37 shows E2.6 at checkpoint 2a.
   Reconcile with the roadmap skeleton.
3. §18 (lines 521–532) has no row for FR-B19–B25 and FR-B27. At minimum add FR-B25 (Entra gating), which
   is a platform row.
4. FR-B26 matrix cell "tenant-independent" should read "Entra-tenant-independent": in this repo, "tenant"
   means the activeDIQ tenant.

### Follow-ups the spec claims: real, complete, correctly scoped?

| Claimed follow-up | Real? | Complete? | Scope note |
| --- | --- | --- | --- |
| ADR-0010 preview class, group `row_key`, totals snapshot (FB-3b) | Yes | No. Add the in-statement count (R-B1), the total-row kind, and the run of an unsaved AST. Drop the RR-snapshot option | **New superseding/extending ADR**, not an amendment (R-M1) |
| modules/reports §3.2 grouping nodes (FB-3a) | Yes ("the 2c builder adds grouping with an amendment to this page") | No (R-M2: stored custom definition, `Resolve`, category, IDs) | Architecture page, `solution-architect` + `reporting-engineer` |
| DM-71 / DM-34 (FB-3d) | Yes. DM-71 lacks `cloned` and `ast_version`. DM-34's allowlist is write-only in today's text | Add the lifecycle reconciliation (R-M7) | `ad-expert` + `backend-engineer` |
| RP-B1–B3 (FB-3c) | Yes | RP-B3 must cover group labels (minor 8) | `security-architect` |
| FB-4 scope renderer for Entra and `group_members` roots | Yes (reports-2a §8.1, ADR-0011 T-1131) | Shared with E2.7 (X-2) | delegation, E-011 |
| FB-6 batch resolver | Yes | Carry the picker-permission point (R-M5) | ADR-0011 amendment (ratified, so allowed) |
| "ADR-0005: no amendment" | **No** while the preview rollup stands (R-M3) | | |
| "ADR-0011: no amendment for pickers" | **Unproven** (R-M5) | | |

---

## Cross-spec: E2.6 ↔ E2.7 ↔ E2.11

**X-1 (major, both specs) · Neither spec specifies the Entra datasets.**
- E2.6 §7 (line 226), FR-B25 and Q6 wait for "datasets that **E2.7 registers**": users, groups, devices,
  licences, memberships and correlation columns.
- E2.7 registers no dataset and never uses the word. It mentions only a LicenceSku D-table (§9) and has no
  devices. Its §12 (line 329) sends M365 reports to "E2.6/M5".
- Each spec points at the other, so nobody owns the datasets.
- DM-70 says datasets are declared by `directory/inventory` and `platform/audit`, not by a feature.

**Fix:** E2.7 adds a short section, "Entra inventory exposed to reports and search": which DM-16 Entra
kinds sync at 2c (from H-M3), the registered datasets and columns (the matched-correlation columns of
E2.6 line 227, `assignedLicenses`, `usageLocation`, the SOA badge as a column), and the scope root kinds
they need. Devices are out unless E2.7 syncs them. E2.6 then cites that section by number, and its Q6
closes.

**X-2 (major, both specs) · Neither spec lists the shared scope dependency.**
- E2.6 FB-4 names it: the reports renderer for `entra_tenant`, `administrative_unit` and `group_members`.
- ADR-0011 rule 9 / T-1131 needs the same root kinds for search.
- E2.7 FR-30, FR-32, FR-33 and AC-10/AC-22 need the DM-35 evaluator for them, but E2.7 does not list it.

**Fix:** one shared follow-up (m2-plan E-011 "DM-35 Entra roots and `include_correlated`"), cited by both
specs. E2.7's ACs that use those scopes depend on it.

**X-3 (minor) · E2.6 §11 and E2.11 disagree in four places.**
1. Scripts: E2.6 says `not supported`; E2.11 §6.5 says `manual`.
2. Apply: E2.11 §6.3 requires step-up for apply; E2.6 §11.3 requires only `reports.build`.
3. The ownership lock (E2.11 §6.8) is missing from E2.6 §11.5.
4. E2.6 refines E2.11 §6.5 ("typed AST or `not supported`") with `changed` and `manual` for filters. That
   is compatible, but E2.11 AC-12 should cite E2.6 §11.2 as the target grammar.

E2.11 is the owner (E2.6 line 357: "Nothing here redefines it"), so E2.6 changes. E2.11 gets a one-line
cross-reference.

---

## Must change before these specs are groomed into tickets

**E2.7:**
1. H-B1: coupled items.
2. H-M1: resume and outcome names.
3. H-M2: rule 7 for deferred targets, and the hash binding.
4. H-M3: Entra sync and scope dependencies.
5. H-M4: group membership under `objects`.
6. H-M5: §8.9 guard on licence and `usageLocation` writes.
7. H-M6: the FR-17 AC and hold definition; the FR column on the ACs and the missing ACs.
8. H-M7: ADR-0004 follow-up.
9. X-1 and X-2.

**E2.6:**
1. R-B1: in-statement count.
2. R-M1: a new ADR instead of an ADR-0010 amendment.
3. R-M2: FB-3a scope.
4. R-M3: preview audit.
5. R-M4: `audit.events` scope and personal values.
6. R-M5: picker scope.
7. R-M6: fidelity classes.
8. R-M7: definition lifecycle.
9. X-1 citation, X-3 alignment, and minor 1 (FR-B07 and FR-B24 ACs).

**CEO:** nothing in either spec needs a CEO decision. OQ-C1 (E2.7, sync-server helper) and Q11 (E2.6,
conditional cut order) are already framed as directional and are filed only on need. The new ADR that
replaces the ADR-0010 change and the ADR-0004/0005/0011 amendments are technical, so factory-director
ratifies them.

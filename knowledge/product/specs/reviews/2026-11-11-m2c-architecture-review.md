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

---

## Round 2 — 2026-11-11

Round-2 drafts at `abec6994`: E2.7 revision 2 (599 lines) and E2.6 revision 2 (943 lines). Every round-1
finding was checked **in the spec text**, not in the response tables (E2.7 §15, E2.6 §24). A parallel
security round 2 is running, so this round stays on architecture. No `factory` command was run.
Checked again against ADR-0003 (ratified), ADR-0004 (ratified, rule 14 and A15), ADR-0005 (ratified;
rules 1–3, 6, 8–11, 13, and the T-0892 rule 10 amendment), ADR-0010 (**accepted**), ADR-0011 (ratified), the
blueprint parity → module table (lines 1839–1861), and DM-71.

### Verdicts, round 2

| Spec | Verdict | Blockers | Majors | Minors | Nits |
| --- | --- | --- | --- | --- | --- |
| E2.7 | **reject** (small delta) | 0 | 3 (H2-M1…M3) | 7 | 1 |
| E2.6 | **reject** (small delta) | 0 | 2 (R2-M1, R2-M2) | 6 | 1 |

Both specs moved a long way. Every round-1 blocker and major is fixed in the text, and so is every cross-spec
item. What is left are new findings, most of them caused by the round-2 additions themselves. None needs a
redesign. I estimate the E2.7 delta at about 30 lines and the E2.6 delta at about 15. Round 3 will be a
**delta review of the IDs below only**.

### Round-1 findings: verified in the text

| ID | Status | Evidence in the text (round-2 line numbers) |
| --- | --- | --- |
| H-B1 | **Closed** | FR-09 (241) declares a coupled item group. FR-10 (242) blocks every item at Plan, giving `plan_failed`, a state that exists in ADR-0005 rule 3. FR-11 and AC-15 move a later shortage to `partially_succeeded` + `cloud_step_failed`. §14.1 item 1 |
| H-M1 | **Closed for terminal states, re-opened for holds** → H2-M2 | FR-21's table (283–293) uses only closed results plus `cloud_reason`, and Resume is a new Operation (FR-18). The part about a *held* request that is still `running` is new: H2-M2 |
| H-M2 | **Closed** | FR-33 (319) covers Plan-time authority. The two-stage binding (plan hash + activation digest, FR-17, §14.1 item 5) is coherent, because `objectGUID` does not exist at Plan. Security confirms the binding |
| H-M3 | **Closed** | FR-36…38 (§7.6) and the targeted re-sync (FR-37). "Check now" reads after a re-sync (FR-19). T-1131 / E-011 is listed in §14.6 |
| H-M4 | **Closed** | FR-23, FR-33 and §9 (368) are the Entra arm of `objects`. The `m365.group.member.*` and `usage_location.set` Actions are explicitly superseded. This matches blueprint 1859 |
| H-M5 | **Closed** | FR-25 (306) and AC-28 |
| H-M6 | **Closed** | AC-23 covers the FR-17 hold. Every AC has an FR column. Every FR-01…FR-40 has at least one AC (checked one by one) |
| H-M7 | **Closed**; fitness missing → H2-M3 | §14.2 |
| H-m1…m8 | **Closed** | FR-12/AC-34; FR-08 and FR-10(i) (binary anchors only, a clean Dec); FR-08 at 20 min; FR-35 table; §14.1 item 8 (but see H2-m1); FR-11; FR-03 + §14.3; FR-34 + §14.1 item 9 |
| H-n1, n2 | **Closed** | §5; Flow B step 3 |
| H-n3 | **Open** | §5 row 168 still reads "FR-13…21, 40 continuation and wait", but FR-13 sits in §7.2 |
| R-B1 | **Closed** | §5 "Match count" (179–181), §9 (313–316), FR-B08, and AC-B15 (statement log: one cursor statement). But one per-condition count survives in §15: R2-M2 |
| R-M1 | **Closed in direction; the type is still ambiguous** → R2-M1 | FB-3b (526) is a new ADR, and ADR-0010 is not edited |
| R-M2 | **Closed** | FB-3a (525) |
| R-M3 | **Closed** | §16: one `reports.preview.run` per preview, chained at commit; AC-B35 expects 12 events |
| R-M4 | **Closed** | §7 (236) has restricted columns and no display names; §21 puts DC events in M3 |
| R-M5 | **Closed** | FB-6a is an ADR-0011 amendment (ADR-0011 is ratified, so that is the right type). §9 L5/L6 and the §16 interim residual are acceptable, because `Resolve` re-authorises every value |
| R-M6 | **Closed** | §11.2 (390–400), AC-B28 |
| R-M7 | **Closed** (a different model from the one I recommended, and coherent) | §8 (251–261): editing state lives in the browser, Save publishes, a server `draft` exists only for imports, and nothing is hard-deleted. FR-B09, AC-B44. See R2-m1 for a naming collision |
| R-m1…m11, R-n1…n4 | **Closed** | Spot-checked each: AC-B36/B37/B42; AC-B09 Given and replicated logon; AC-B06 `% _ \`; one FB table; one limits table (§9); 10 s preview timeout; masked group label and zone in the hash; GUID/DN default; FB-12; §11.5 lock; frontmatter |
| X-1 | **Closed** | E2.7 §7.6 registers three datasets owned by `directory/inventory` (DM-70). E2.6 §7 (237), FR-B25 and FB-11 cite it and define none |
| X-2 | **Closed** | E2.7 §14.6 and E2.6 FB-4 name the same dependency (E-011 / T-1131) |
| X-3 | **Closed** | E2.6 §11.2–11.5; FB-10 |

### Director rulings: coherent and buildable?

1. **ADR-0010 accepted → E2.6 storage in a new ADR (FB-3b).** This is the right direction, but the ADR must be **superseding**. "Extending" is not a valid type here (R2-M1).
2. **E2.7 owns Entra delta sync and the Entra datasets.** This is coherent. Producer (`sync`/`provider/entra`) → `inventory` Populator/Ingester (T-0326) → datasets declared by `directory/inventory` matches blueprint 1860–1861 and DM-20.I5. E2.6 AC-B30 and E2.7 AC-43 are two sides of one gate. Make the gate a Boot rule (H2-m3) so that both can be tested.
3. **Group membership through `objects` on the Entra provider.** This is coherent with blueprint 1859 and EP-11. One RBAC consequence of the default licence path is left unstated (H2-m6).
4. **Group-based licensing as the default.** This is buildable. FR-26 verifies through `licenseAssignmentStates`, AC-12 proves that no profile-write or direct-licence call is made, and the wizard states the preconditions (§2). It also improves least privilege (E4).

### E2.7: round-2 findings

**H2-M1 (major) · §9 (365–372), §14.1 item 2 (475–479) and FR-34 (320): no module owns the continuation, and the kernel cannot evaluate the gate's condition.**
- The spec adds a `gate` step whose condition is "the Entra object exists and is `matched`". It also adds a HybridRequest/continuation entity and `hybrid.*` audit kinds, but never says which module owns any of them.
- `platform/operation` imports no module or directory package (ADR-0005 rule 13 `dag`, O9; ADR-0003), so the kernel cannot evaluate an Entra correlation. Left unowned, the condition gets hard-coded into the kernel or bolted onto `objects` ad hoc. That is PatchIQ §11 #2.
- Audit kinds are `<owner>.<…>`, and no module is named `hybrid`.
- Blueprint 1839 assigns ADM-027 to **`objects`** ("one flow for AD + Entra"), with the `m365` licence Action beside it.

**Fix:**
- The gate condition is declared by the Action's owner on the EP-3 Action descriptor. For example, `Descriptor.Gates`: a named condition with an evaluator the module supplies through `Registrar.Action`. The kernel holds only the generic gate state machine and the sweeper deadline. This needs no new EP. A separate `Registrar` method would instead be an ADR-0003 amendment, so the descriptor field is preferred.
- `objects` owns the HybridRequest record and the evaluator. The evaluator reads correlation only through `inventory`'s read API.
- The kinds become `objects.hybrid.*`.
- §14.7 gains an architecture-map ticket: blueprint §5 rows for `objects` (Entra arm, continuation) and `sync` (Graph delta producer), plus an `architecture/modules/m365.md` page. Today `m365` has only a blueprint row (988) and no page.

**H2-M2 (major) · FR-17 (257), FR-18 (278), FR-21 table row "waiting or held" (293), §14.1 items 2 and 4, AC-23: Resume of a *held* request starts a second live Operation and leaves the first undefined.**
- A `hold` "resolves only by Resume". Yet a held Operation stays `running` with its gate `waiting`, and Resume is a *new* Operation. Nothing ends the original, so two Operations could write the same cloud steps for one `request_id`.
- Approval carry-over across Operations (FR-18: "same hash, ADR-0005 rule 8") is undefined. The new Operation plans against live state with a resolved target, so its plan hash cannot equal the original's.
- §14.1 item 2 says cloud steps "are planned against live state" when the gate passes. That is a Plan inside `running`, which rule 1 does not have.

**Fix:**
1. **Pass the gate by binding, not by planning.** Gate pass *binds* the resolved target into the steps planned at Plan and computes the live diff read-only. If it differs, the step-level wait reason becomes `replan_changed`. This is not a rule 8 kernel hold, which comes before approval; say so.
2. **Resume supersedes the original in one transaction.** Resuming a waiting or held request ends the original's cloud item in the same transaction (`cancelled`, `cloud_reason = cloud_superseded`, added to the closed set in FR-21 and §14.1 item 3, with a `superseded_by` link). A unique key on `request_id` over live continuations allows at most one per request.
3. **Define carry-over.** Approvals carry over only if the new Operation's FR-17 bound elements, recomputed, equal those in the original activation digest, and only inside `approval_valid_until`. This is an explicit rule 8 addition in §14.1 item 4.
4. **Test it.** AC-23 asserts that the original ends `partially_succeeded` / `cloud_superseded` and that no Graph write happens twice.

**H2-M3 (major) · §14.1 and §14.2 name no fitness additions, so grooming would produce amendments with no CI behind them.**
§14.1 adds a step kind, a state and edges: `planned → waiting`, `waiting → verified | not_run`, item `planned → cancelled`, gate-driven `running → cancelled`, and a wider `partially_succeeded`. ADR-0005's O4 compares `transitions.go` with the ADR's `transitions` block, so O4 fails until the block changes. O8 has no case for coupled blocking, gate expiry, Resume supersede or carry-over refusal. Rule 6's `operation.sweep` re-drives every `running` operation it thinks stalled (ADR-0005 line 262), and a 24-hour `waiting` gate is exactly what that rule would re-drive. §14.2 changes rule 14 routes, which A15 checks.

**Fix:**
- §14.1 states that waiting gates hold no step claim and are excluded from stalled detection: the sweeper drives the deadline and a scheduled poll drives the re-check.
- §14.1 lists the fitness ticket: O4 `transitions` block and its property test, O8 cases, owner `backend-engineer`, depends on the amendment.
- §14.2 lists the A15 extension, owner `api-engineer`.

**Minor**
1. **H2-m1 · FR-22 (303), FR-23, §14.1 item 8, AC-33: drop the Entra `outcome_unknown`.** Round-1 minor 5 pointed the wrong way, and this corrects it. "Resolved by Check now or Resume" contradicts rule 3: `failed` is terminal, and Check now is a read. Rule 6 already covers this case: "a step whose state cannot be read stays `applying` for the reconciler". Graph writes are read-then-write idempotent (FR-22, FR-23), so the reconciler can re-read and either finish or re-apply. Delete item 8 and the `outcome_unknown` row of FR-35. AC-33 then asserts that the step stays `applying` until the target is readable. This also keeps rule 3's undo corollary true without amending it.
2. **H2-m2 · FR-35 table (323–327).** `pim_read_failed` is missing from the Plan row, although FR-10(f) and AC-14 use it at Plan. `cloud_expired` is a `cloud_reason`, not a step outcome. Give the cloud reasons a row of their own: `cloud_step_failed`, `cloud_expired`, `cloud_cancelled`, `cloud_denied`, and `cloud_superseded` from H2-M2.
3. **H2-m3 · FR-38 (338), AC-43: "MUST NOT be registered until the scope renderer supports the root kinds".** As written this is a merge-order instruction that no test can hold. Make it a Boot rule: the dataset registry refuses a dataset whose declared root kinds the scope renderer does not render. AC-43 then tests the refusal, and E2.6 AC-B30's first state is the same Boot outcome.
4. **H2-m4 · FR-40 (297), AC-35.** Only Cancel's permission is tested. Add cases for the Resume and Undo permissions and for the Check-now rate limit (one per 30 s).
5. **H2-m5 · FR-30 (316).** "Every … search row" has no AC, because AC-37 covers the user page. Add a search-row case that depends on T-1131.
6. **H2-m6 · FR-33 (319) with FR-26: the default licence path is a group-membership Action.** As written, a technician with membership rights over a licensed group assigns a paid licence without `m365.licence.assign`. State the rule. Recommendation: a step targeting a group that carries a licence (FR-38 column "carries a licence") also requires `m365.licence.assign` over the target at Plan and Apply. Security-architect confirms.
7. **H2-m7 · FR-04 (230): "SKU reads via `LicenseAssignment.Read.All` or `Organization.Read.All`".** The consent list is closed (AC-04), so name one.

**Nit**
1. H-n3, still open (above).

### E2.7: follow-up list corrections (§14.1–14.7)

| List | Type as written | Correct? | Change |
| --- | --- | --- | --- |
| §14.1 ADR-0005 | amendment | Yes: ADR-0005 is `ratified`, and nothing in the list reverses a rule | Add the gate-condition seam (H2-M1), Resume supersede and carry-over (H2-M2), and the sweeper exclusion plus the fitness ticket (H2-M3). Delete item 8 (H2-m1). solution-architect writes it as **one** dated amendment. The spec should keep a five-line pointer and not a second copy of the text (see Length) |
| §14.2 ADR-0004 rule 14 | amendment | Yes: ADR-0004 is `ratified` | Add the A15 fitness ticket |
| §14.3 domain model | DM changes | Yes | Add `cloud_superseded` to the `cloud_reason` set. Add the owner of the HybridRequest entity (`objects`, H2-M1) |
| §14.4 connector contract | contract revision | Yes | none |
| §14.5 threat model, `guarded-v1` P1 bug | TM change + `bug` | Yes (security's call) | none |
| §14.6 cross-spec | dependency | Yes | none |
| §14.7 tickets | tickets | **Incomplete** | Add the architecture-map ticket (H2-M1) and the fitness tickets (H2-M3) |
| Accepted ADR amended? | n/a | **None.** ADR-0002, 0004, 0005 and 0011 are not accepted | none |

### E2.6: round-2 findings

**R2-M1 (major) · FB-3b (526): "New ADR extending or superseding ADR-0010" must be *superseding*. "Extending" is not a valid type here.**
ADR-0010 is `accepted`. The new ADR changes what three of its rules require:
- **Rule 3 ("the total is `report_runs.row_count`").** A preview's match count exceeds its 1,000 stored rows, so a second user-visible total is introduced.
- **Rule 5 (7-day retention, later 1–30 days).** A 1-hour preview class falls outside it.
- **The run identity (DM-72, reports.md §6.2).** A run would exist with no definition ID.

An "extending" ADR would leave ADR-0010 `accepted`, with text that contradicts a binding successor. That is two documents that disagree, which is the drift the ladder exists to stop, and the ladder has no partial supersede.

**Fix:**
- FB-3b reads "**new ADR superseding ADR-0010**". It restates the unchanged rules, carries RP3–RP5 forward unchanged, and adds its own checks. Proposal: RP6, no `CompileCount` or second count statement on any run path (a `reportsql` call-site check plus the AC-B15 statement-log test); RP7, preview-class supersede and expiry.
- ADR-0010 becomes `superseded` when the new ADR is ratified. List the fitness ticket.
- State whether `CompileCount` is deleted for library runs as well. §15's "1.4 million rows" over-cap message now comes from the window count, so yes. That makes it a reports.md §5 change under FB-3a, with the superseded code deleted in the same change.

**R2-M2 (major) · §15 "Unsynced attribute" (474) and AC-B04 (630): "a filter on it says 'n users not yet read'" is a per-condition count that survived R-B1.**
The number counts in-scope users that the condition *excludes*, so it cannot come from the result statement. It can only come from one of two places:
- a separate `COUNT`, which contradicts §5 "Match count" and FB-3b; or
- the sync-set backfill's progress counter, which is tenant-wide and would leak a count outside the runner's scope (FR-B30, AC-B40).

**Fix:** show no number: "<Field> has not been read for every user yet (sync started 09:12). Users not yet read do not match." AC-B04 asserts this text and that no count is shown. The header count of "Not synced yet" cells among *stored* rows may stay, because it is computed from stored rows.

On the dropped counts the director asked about:
- **Source-picker row counts.** Dropping them is consistent with the experience target. Step 2 shows the scoped match count one interaction later. T21–T23 count interactions, not numbers, and E-B1 promises "rows plus match count" per preview, which is kept.
- **Per-condition live counts.** Also consistent. The header count refreshes on every debounced edit (§6 step 4), which gives the same signal one edit at a time.
- **The "N checked" count.** It appears nowhere in revision 2, and the selection contract binds `all_matching` to the stored `row_count` (§10.2), so no separate count is needed.
- **Result.** No dead or fake element remains apart from R2-M2 and the wording in R2-m5.

**Minor**
1. **R2-m1 · §8 (256–261): `reports.definition.restore` collides with ADR-0005 rule 10 (T-0892 amendment).** That rule makes "`<owner>.<noun>.restore`" the family's **undo inverse**, refused as `superseded` when the row has moved on. The spec uses `restore` for un-archive, and undo of an update "publishes a new version equal to the previous". Define one `reports.definition.restore` as "restore a recorded state (version and lifecycle state)". It is both the undo inverse and the un-archive control. FB-3d adds the DM-71 edge `archived → published`, which DM-71 lacks today. It has `draft → published → archived` only.
2. **R2-m2 · FB-5 (530): "register the `reports.preview.run` kind" under the `platform/audit` owner.** EP-7 kinds are registered by their owner, and `reports.*` belongs to `modules/reports`. Move the kind into FB-3a or the reports build ticket. FB-5 keeps the `audit.events` dataset and the erasure ruling.
3. **R2-m3 · FB-6b (532): owner and type.** `inventory.ResolveIdentifiers` is an `inventory` read API (blueprint 930, owner `directory-engineer`). Type it as a blueprint `inventory` row plus a build ticket for `directory-engineer`, with a design note by solution-architect. If it is meant as a search-producer variant, it rides on FB-6a's ADR-0011 amendment instead.
4. **R2-m4 · FB-12 (538)** is a constraint on the definition-store build ticket, not a follow-up. Fold it into that ticket's AC so that grooming does not create an empty ticket.
5. **R2-m5 · §15 "Preview truncated" (472).** "At least 1,000 users match" contradicts FR-B08: the count is exact, and "1,000+" appears only after the rows-only fallback. Write "4,312 users match; the preview shows the first 1,000. The saved report stores up to 1,000,000." Keep "1,000+" for the fallback state only.
6. **R2-m6 · §9 (313–316) and §5 (163).**
   - The rows-only fallback is a **new** preview run (ADR-0010 rule 2: never resume into the same run) and counts against the per-account rate. Say so.
   - Say that the *n* in "k of n groups shown" comes from the same grouped statement (a window over the groups before Top N and the minimum group size), so it is not a second count either.

**Nit**
1. §1 (43): "owns Entra sync and datasets, §7" should read "§7.6".

### E2.6: follow-up list corrections (§17 FB-1…FB-12)

| FB | Type as written | Correct? | Change |
| --- | --- | --- | --- |
| FB-1, FB-2, FB-7, FB-8, FB-9 | research, lab, design, spec, later | Yes | none |
| FB-3a | reports.md amendment (architecture page) | Yes | Add `CompileCount` removal (R2-M1), the `reports.preview.run` kind (R2-m2), and the single `restore` Action (R2-m1) |
| FB-3b | "new ADR extending or superseding" | **No** | **Superseding ADR**, plus its fitness ticket (RP6/RP7), RP3–RP5 carried (R2-M1) |
| FB-3c | security review + fitness RP-B1…B3 | Yes | none |
| FB-3d | domain model | Yes | Add the DM-71 edge `archived → published` (R2-m1) |
| FB-4 | shared dependency (E-011 / T-1131) | Yes, and it matches E2.7 §14.6 | none |
| FB-5 | `platform/audit` dataset + erasure ruling + kind | Partly | Remove the kind (R2-m2) |
| FB-6a | ADR-0011 amendment | Yes: ADR-0011 is `ratified` | none |
| FB-6b | owner solution-architect | **No** | `directory-engineer` build plus a blueprint `inventory` row (R2-m3) |
| FB-10, FB-11 | cross-reference; done in E2.7 | Yes | none |
| FB-12 | follow-up | **No** | A build-ticket AC (R2-m4) |
| Accepted ADR amended? | | ADR-0010 stays untouched, as ruled. FB-3b must supersede it, not extend it | |

### Traceability

- **E2.7.** All 40 FRs map to ACs (46 ACs, each with a tier and named evidence). The numbers agree across sections: 20/30 min, 3×, 24 h, 90/14 days, 30-day certificate warning, 50/51, four writes, 2-minute window, 30 s. Gaps are H2-m4 and H2-m5 only.
- **E2.6.** The trace table (839–850) covers FR-B01…B30. Every AC names its evidence. The preview caps (1 / 2 / 30 per minute / 10 s), the limits table, Top N, 10,000 groups and AC-B35's 12 events agree everywhere. The only number that disagrees with its FR is §15's "At least 1,000" (R2-m5).

### Length: are these still usable working documents?

**E2.7 (599 lines): usable, but trim it to about 450 and split out one slice.**
1. Move §15 (the review-response table, 43 lines) into this review file, and leave a one-line pointer in the changelog. Response tables belong to the review record, not the contract.
2. Replace §14.1's 37-line amendment text with a five-line pointer once solution-architect drafts the ADR-0005 amendment. Two copies of one amendment will drift.
3. Split §7.6 (FR-36…38, the dataset table, AC-42, AC-43; about 70 lines) into `e2-7a-entra-inventory-sync.md`. It is its own build slice (§14.7 already says so), it is E2.6's dependency, and FB-11 can then point at a stable document instead of a section number.

**E2.6 (943 lines): too long to work from. Target ≤ 750 now and ≤ 650 once FB-3a and FB-3b land.**
1. Move §24 (35 lines) into this file, as for E2.7.
2. Once FB-3a and FB-3b exist, replace the architecture they will own with links: §5 "How it compiles" and "Match count", §5 rules 1–3, and §9 L1–L8 (about 60 lines). Keep FR-B28 and FR-B30, which are the product contract.
3. Merge §12 into §3's "Differs" column (−10).
4. Cut §16's abuse-case list to one line per case pointing at its ACs (−10).
5. Cut §11 to the target classes and FR-B18; the intake rules are E2.11's (−15).
6. Do not split the ACs: they are the test plan.

### Must change before grooming (round 3, delta only)

**E2.7:** H2-M1 (owner and gate seam), H2-M2 (Resume of a held request), H2-M3 (fitness lines and sweeper exclusion), H2-m1…m7, H-n3, and the §14 follow-up rows above.

**E2.6:** R2-M1 (FB-3b supersedes ADR-0010, with its fitness ticket), R2-M2 (no "n users not yet read"), R2-m1…m6, and the §17 rows above.

**CEO:** nothing new. OQ-C1 and Q11 stay dormant. All ADR work above is technical, so factory-director ratifies it.

---
title: "Security review (second reviewer): E2.7 hybrid provisioning and E2.6 report builder, checkpoint 2c drafts"
date: 2026-11-11
status: draft
owner: security-architect
reviews:
  - knowledge/product/specs/e2-7-hybrid-provisioning.md (draft 2026-11-11)
  - knowledge/product/specs/e2-6-report-builder.md (draft 2026-11-11)
ticket: off-board (m2c-plan); attach board IDs at merge
---

# Security review: E2.7 hybrid provisioning and E2.6 report builder (2c drafts)

**Verdicts.** E2.7: **reject** (2 blockers, 4 majors). E2.6: **reject** (2 blockers, 2 majors).
Both specs are close. The architecture is right: anchor-only lookup, no cloud create, typed AST,
scope in the `WHERE`. The rejects are about what the specs leave undefined at the exact points an
attacker would aim for. The authors fix; I re-review only the numbered items below.

**How this was reviewed.** This is a document review, so there is no code to run and no lab. I read
both specs in full and checked them against: threat model §6.4 (E1–E5, TM-D25), §6.6 (TM-D5 allow
and deny lists), §6.8 (TM-D17), §6.9a (TM-D28 `guarded-v1`); domain model DM-10.I7, DM-20.I1–I7,
DM-21.I2, DM-35.I5–I7, DM-41/42, DM-50.I3, DM-71/72/73; ADR-0005 rules 7, 8 and 9; ADR-0010 rule 2;
`modules/reports.md` (scope renderer, `MaskAnchor`, DN disclosure rule, RP11); safe-primitives
§3.7 and LF-36/38/39. For each question I tried to build the attack and recorded whether a written
rule stops it. Microsoft behaviour was checked against learn.microsoft.com on 2026-11-11 (pages
cited inline). Anything else is tagged `[UNVERIFIED]`.

---

## Part A: E2.7 hybrid provisioning

### A.1 Ruling on OQ-F2 (unattended cloud half, FR-17)

**Ruling: yes, the cloud half may run without a second human approval, but only under a bound,
time-boxed approval as defined below. The original approval plus a live re-check at Apply is
*not* enough as the spec words it.** It falls short for three reasons:

1. **The approver's authority over the cloud target was never checked.** ADR-0005 rule 8 requires
   "one approval by an account holding `operation.approve` over the scope of **every** item". The
   Entra object did not exist when approval was given. An approver whose scope is one AD OU without
   `include_correlated` (DM-35.I6) could therefore approve licence and group writes on an Entra
   object they hold no authority over. FR-33 re-checks only the initiator (ADR-0005 rule 7, "whose
   authority": initiator chain). Nothing re-checks the approver.
2. **"Equal to the approved diff apart from the now-resolved target identity" is not a hash rule.**
   ADR-0005 rule 8 keeps approvals only when the plan hash is unchanged, and rule 9 hashes every
   item's target. Unless the hash contains a binding descriptor that the resolved object must
   *satisfy*, "apart from the target" means "any target".
3. **Resume extends the approval with no end date.** FR-18 lets **Resume** re-plan after
   `expired_waiting`, and FR-17 then auto-runs on an equal diff. So a 24-hour approval becomes
   open-ended.

**What the approval must bind.** All of the following go into the plan hash as the deferred-target
descriptor, which also resolves OQ-F1's hashing question:

| Bound element | Value | Changes → |
| --- | --- | --- |
| Tenant | Entra connection ID **and** its `directory_identity` (tenant ID, DM-10.I1) | refuse |
| Identity | `ad_ref` = the `objectGUID` **returned by our own create** (not re-read later); `anchor_attr` + `anchor_value` derived from it; `match = anchor` | refuse (never re-approve onto another identity) |
| Usage location | the ISO 3166 value | re-approval |
| Licences | the exact `skuId` set, each with its exact `disabledPlans` set; **add-only** (`removeLicenses` empty for a create) | re-approval |
| Groups | the exact group object IDs, each with the classification it had at approval (cloud-mastered, not dynamic, not role-assignable, not `tier0`, not in a designated closure) | re-approval if a group is added or reclassified; refuse if it became `tier0` |
| Actors | initiator chain, approval IDs, approvers | re-validated at Apply (below) |
| Expiry | `approval_valid_until` = AD-half `verified` + 24 h. Fixed: **Check now**, `late` and polling never extend it | after expiry, **Resume needs a new approval** (and step-up if any step is Irreversible) |

**What must be re-checked live at Apply,** immediately before each cloud write:

- the correlation gate (DM-20.I4 (a)–(g)), including (f) from the attestation and (g) from
  `cloud_seen_at`;
- the A.2 binding rules;
- the `tier0` guard on the user and on every group (A.3);
- the **initiator** chain (FR-33); and
- **each approver**: the account is active, it still holds `operation.approve` over the *resolved*
  Entra object (`entra_tenant`, AU, Entra `group_members`, or an AD scope with `include_correlated`
  through the `matched` correlation), and the separation-of-duties checks still pass.

A narrowing (a step that is now `already_applied`) never needs re-approval. A widening, or any
change in the table above, holds the steps. A scope or permission loss **denies** them; it does
not ask for re-approval (see A.6 #6). The continuation must never fall through to FR-32's
`candidate` path: a hybrid request whose correlation is not `matched` holds, whatever scope the
initiator has.

### A.2 Ruling on takeover: can we be made to license or group an object we did not create?

| Vector | Stopped by | Verdict |
| --- | --- | --- |
| **Soft match** (pre-staged cloud user with the new user's UPN or SMTP address) | FR-15 looks up by anchor only, never by UPN; DM-20.I4(f) needs `blockSoftMatchEnabled` attested; AC-08 | **Stopped.** With soft-match blocking on, Entra Connect may instead quarantine the duplicate UPN on the synced object `[UNVERIFIED — lab]`. The anchor lookup still finds the right object (see A.6 #9). |
| **Hard match** (pre-staged cloud user with `onPremisesImmutableId` = base64 of the new `objectGUID`; any domain user can read the GUID once the AD half commits, TM §6.8) | (f) attested blocks the takeover at the sync client. But the spec does **not** define what happens when the anchor lookup finds exactly one object that is cloud-only | **Gap → blocker A-B2.** |
| **Flag flip in the wait window** (an E4 admin turns hard-match blocking off, stages, lets sync take over, turns it back on) | (g) catches it only if we *observed* the object cloud-only. Without `AuditLog.Read.All` the attestation stays `attested` for up to 90 days (DM-10.I7(c),(d)) | **Residual TM-R11 / E4 is accepted.** The spec makes it worse by omitting the monitor (A-M3) and by not recording what the FR-15 poll sees (A-B2). |
| **Anchor collision** (another AD object's `ms-DS-ConsistencyGuid` set to the victim's anchor, or the new user's `ms-DS-ConsistencyGuid` set to the victim's anchor before FR-14 records it) | DM-20.I4(e) (`ambiguous_anchor`) and (c) (SID corroboration) cover it, but only if the live lookup finds every holder. FR-16 does not bind the correlation's `ad_ref` to our object, and `ms-DS-ConsistencyGuid` is **not** in `guarded-v1` (TM §6.9a), so a template field or any AD writer can stamp it | **Gap → blocker A-B2.** |
| **Renamed UPN during the wait** | Lookup by anchor and writes by object `id` (FR-15, FR-22, FR-23) | **Stopped.** UPN is presentation only (A.6 #9). |
| **Entra-scoped admin licensing a `candidate` object** (FR-31/FR-32) | By design an `entra_tenant` grant is direct Entra authority over a cloud object; it is not a takeover | **Accepted**, provided the hybrid continuation can never use this path (A.1). |

### A.3 Ruling on the Graph permission set (FR-04)

- **Deny list.** None of FR-04's application permissions is on the TM §6.6 deny list.
  `Synchronization.ReadWrite.All` is correctly left out (FR-19). The one delegated scope,
  `OnPremDirectorySynchronization.Read.All` without `offline_access`, matches TM-D17 rule 2.
- **`User.ReadUpdate.All` covers `usageLocation`: confirmed by the page's structure, not by an
  explicit sentence.** Microsoft's update-user page lists `User.ReadUpdate.All` as the least
  privileged application permission for `PATCH /users/{id}`. It then names the exceptions that need
  other permissions: `otherMails`, `passwordProfile`, `businessPhones`/`mobilePhone`,
  `accountEnabled`, `identities`, `employeeLeaveDateTime` and `customSecurityAttributes`.
  `usageLocation` is not an exception, and its row names no permission
  ([update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0)). The
  permissions reference describes `User.ReadUpdate.All` (application ID
  `5639c449-cfd9-4088-bc48-3e16da108bf8`) only as "Allows the app to read and update users, without
  a signed-in user"
  ([permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)).
  Status: **resolved on the documentation, confirm in lab G3** (cheap). OQ-F4's usage-location half
  is no longer a security unknown. Its breadth is, and that is finding A-M2.
- **Missing from the "closed" set:** `AuditLog.Read.All`, which TM §6.6 marks recommended whenever
  a HybridLink exists, and `Policy.Read.ConditionalAccess` (optional, TM-D25 rule 9). See A-M3.

### A.4 Blockers

**A-B1 [blocker] · §7.3 FR-17, §8 "Approve" row, §10 "Unattended continuation", §13 OQ-F2.**
- **Problem.** Approval binding and approver re-check are undefined, and Resume re-arms an expired
  approval.
- **Exploit sketch.** A technician with `entra_tenant` scope gets an AD-only approver, whose scope
  never covered Entra, to approve a hybrid create. The cloud half licenses the user and adds it to
  cloud groups under an approval that authorised nothing on the cloud side. Or a request expires,
  someone presses Resume weeks later, and the old approval runs it.
- **Fix.** Write A.1 into FR-17 and FR-18: the binding descriptor in `plan_hash`, the fixed
  `approval_valid_until`, Resume after expiry as a new approval, the approver re-check at Apply,
  and no fall-through to FR-32. Route the hashing to the ADR-0005 amendment (OQ-F1).
- **Tests.**
  - `approval_binds_deferred_target`: the hash changes if the anchor, tenant, SKU set,
    disabled-plan set or group set changes.
  - `approver_scope_rechecked_on_cloud_target`: an approver without Entra reach → steps held
    `approver_scope_denied`.
  - `approver_disabled_while_waiting`: the steps are denied.
  - `resume_after_expiry_requires_new_approval`.
  - `candidate_never_falls_through_to_entra_scope_path`.

**A-B2 [blocker] · §7.3 FR-14, FR-15, FR-16; §10 "central abuse case"; DM-20.I4(e)(g), DM-20.I5, DM-16.I9.**
- **Problem.** The identity binding has three holes.
  1. FR-15 defines zero matches and more than one, but not **one match on an object that is
     cloud-only or cloud-managed** (`onPremisesSyncEnabled` not `true`, or `isCloudManaged`). That is
     exactly the shape of a hard-match staging attempt.
  2. FR-16 requires "correlation `matched`" but never says *which* correlation. It must be the one
     whose `ad_ref` is our created `objectGUID` and whose `entra_ref` is the found object.
  3. FR-14 derives the anchor from `ms-DS-ConsistencyGuid` "else `objectGUID`" read at AD-half
     verify. `ms-DS-ConsistencyGuid` is not a guarded attribute, so a hybrid template field, another
     Action or any AD writer with rights on the OU can stamp a victim's anchor on the new user
     before FR-14 records it.
- **Exploit sketch.**
  - (a) An Entra admin with a role that can write `onPremisesImmutableId` (TM §6.8) pre-creates a
    cloud user carrying the new user's anchor during the 30-minute wait. Our poll sees it, does
    nothing, and the request waits and expires with a "late" banner that lists benign causes. If (f)
    later lapses, the takeover completes, and (g) does not fire because nothing recorded
    `cloud_seen_at`.
  - (b) A template writes `ms-DS-ConsistencyGuid` = base64 of the CFO's GUID. FR-14 records the
    CFO's anchor. FR-15 finds the CFO's synced cloud object, which is `matched` to the CFO's AD
    object. The anchor equals the recorded one, so FR-16 passes on its wording, and only a
    successful live (e) lookup across every linked forest stands between us and licensing or
    grouping the CFO's account.
- **Fix.**
  - (i) FR-15: a single anchor match that is cloud-only or cloud-managed MUST set `cloud_seen_at`
    through the targeted re-sync (DM-20.I5), hold `anchor_on_cloud_object` (new reason), and raise
    a `high` security alert to `tenant-owner`. It must never just keep waiting. Every FR-15 poll
    that reads (a) or (b) feeds DM-16.I9.
  - (ii) FR-16 adds two bindings: `correlation.ad_ref` = the recorded `objectGUID` and
    `correlation.entra_ref` = the found object `id`.
  - (iii) FR-14: the anchor is `objectGUID` as returned by our create. If `ms-DS-ConsistencyGuid`
    is present at verify with a value other than that `objectGUID`, hold `anchor_tampered` and
    alert. A `provider = hybrid` template, and every AD step of the request, MUST NOT write
    `ms-DS-ConsistencyGuid` (Plan refuses).
  - (iv) The I1a lookup at Apply fails closed (`unknown` counts as `ambiguous_anchor`) when any AD
    connection with a HybridLink to the tenant cannot be read.
- **Tests.**
  - `prestaged_cloud_object_with_anchor_holds_and_alerts` (fake Graph): asserts `cloud_seen_at`
    is set and no write is made.
  - `consistency_guid_stamped_holds`.
  - `correlation_adref_must_equal_created_guid`.
  - `anchor_lookup_unknown_forest_fails_closed`.
  - Extend TM-F-HYBRID with the wait-window cases.
- **Follow-up outside this diff (server board, P1, `security-sensitive`, owner
  `directory-engineer`):** add `ms-DS-ConsistencyGuid` to `guarded-v1` under `map_credential`
  (TM §6.9a). It decides which cloud identity an AD object becomes, which is the AD-side mirror of
  `entra:onPremisesImmutableId`, already listed there.

### A.5 Majors

**A-M1 [major] · §7.4 FR-25, §7.3 FR-16, §10 "Tier 0".**
- **Problem.** FR-25 blocks "a role-assignable group or a privileged-role holder". The Entra
  `tier0` set is wider: E1–E5, and the TM-D25 reach closure, which includes customer-designated
  (Conditional-Access-excluded) groups and groups that are PIM-eligible members of a role-assignable
  group. Also, FR-16's Apply re-check does not name the `tier0` guard, and the new AD user can
  become `tier0` during the wait, for example if someone adds it to a protected group (C16/E5
  propagation, DM-20.I7).
- **Exploit sketch.** A cloud group that is an *eligible* member of a role-assignable group holding
  Global Administrator passes the narrow wording. Adding the new user to it lets that user activate
  the role.
- **Fix.**
  - FR-25 cites "any `tier0` group per TM §6.4 E1–E5 and TM-D25 rules 1–7".
  - FR-16 re-runs the `tier0` guard on the user and every group immediately before each write.
  - The PIM reads are required, with TM-D25 rule 4's fail mode: a failed read holds every cloud
    step.
  - Verify runs ADR-0005 rule 7's `tier0_after_write` for Entra steps.
- **Tests.** `group_in_pim_closure_refused`, `designated_group_refused`,
  `user_became_tier0_while_waiting_refused`, `pim_read_failure_holds_cloud_half`.

**A-M2 [major] · §7.1 FR-04 (usage location family), FR-10.**
- **Problem.** `User.ReadUpdate.All` is tenant-wide profile write on every non-admin user. The same
  page gives no property-specific permission for `onPremisesImmutableId` or `userPrincipalName`,
  both "sensitive actions"
  ([users](https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0),
  [user resource](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)).
  TM §6.6 records that app-only callers can change sensitive properties of users with no admin role.
  So this grant probably lets our app write an anchor or a UPN on any ordinary cloud user
  `[UNVERIFIED — lab G3 extended]`. We request all of that to set one property.
- **Exploit sketch.** A compromised activeDIQ server stamps an AD admin's anchor onto a cloud-only
  user (hard-match staging) or renames a cloud user's UPN (soft-match staging). The tenant flags
  are the only barrier left.
- **Fix.**
  - Make **usage location** its own opt-in family, off by default, with EV5 text naming the
    breadth.
  - Offer the group-based licence path (FR-26) as the default where the tenant location is right:
    "For group-based licensing, any users without a specific location inherit the location of the
    tenant"
    ([M365 group licences](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-group-licenses?view=o365-worldwide)).
  - Evaluate setting it on the AD side (`msExchUsageLocation` through sync) `[UNVERIFIED — lab]`.
  - The `m365.user.usage_location.set` Action may emit only the constant `usageLocation` key
    (TM-D28 B2/B4/B8 cover it once the Action exists).
  - Add a TM §6.6 row and a residual for the breadth.
- **Tests.** `usage_location_action_emits_only_usageLocation` (B3/B4 fitness);
  `ev5_warns_user_readupdate_breadth`; lab G3 extended to `onPremisesImmutableId` and
  `userPrincipalName` on a non-admin cloud user.

**A-M3 [major] · §7.1 FR-04 ("closed" set), FR-06, FR-18 late causes.**
- **Problem.** `AuditLog.Read.All` is left out, although TM §6.6 and TM-D17 rule 3 recommend it
  whenever a HybridLink exists. It is the only demotion trigger for the attestation (DM-10.I7(d)).
  Without it, a flag flip during the wait is invisible for up to 90 days. A "closed" set would also
  make EV5 flag it as excess.
- **Fix.**
  - Add `AuditLog.Read.All` as **recommended** whenever a HybridLink is declared. Health shows
    "change monitoring off" while it is absent.
  - Add `Policy.Read.ConditionalAccess` as optional (TM-D25 rule 9).
  - List "change monitoring off" among the `late` causes.
- **Test.** `hybrid_link_without_auditlog_shows_monitoring_off`; `ev5_does_not_flag_auditlog_with_hybrid_link`.

**A-M4 [major] · §7.1 FR-01, §10 "Credentials"; security-baseline §3 (rotation).**
- **Problem.** There is no rotation flow for the Entra certificate and no expiry surfacing. EV3/EV5
  "extra key credential" logic will flag our own second certificate during a rotation (TM §6.6:
  "flags any extra key").
- **Fix.**
  - Specify rotation: generate a new key sealed under the tenant key; the customer adds the public
    certificate; Verify records the pending thumbprint as ours (by the SHA-1 of `key`, TM lab G7);
    cut over; the customer removes the old certificate; Verify confirms there is one key.
  - Health shows the certificate's age and expiry and warns 30 days before expiry `[PROPOSED]`.
  - The private key is deleted when the old thumbprint is gone.
- **Test.** `certificate_rotation_no_downtime`; `pending_thumbprint_not_flagged_extra`; `expiry_warning`.

### A.6 Minors and nits

1. **[minor] FR-11 vs FR-17.** An availability drop at Apply "fails `insufficient_licences`"
   (FR-11) in one place and "holds for re-approval" (FR-17) in another. Pick FR-11 for availability
   and FR-17 for SKU, group or target changes.
2. **[minor] Flow A step 7 vs DM-21.I2.** A *declared* link is created `confirmed` by a holder of
   the privilege over both sides. Only a *discovered* link is `proposed`. Fix the wording.
3. **[minor] FR-34 audit content.** Each cloud-step event must carry the evidence the SOC persona
   asks for (§1): the AD `objectGUID`, the Entra object `id`, the anchor, the correlation ID, its
   state and `eligibility_class`, the attestation ID and age, the approval IDs and `plan_hash`, and
   that the executor was the continuation acting for the initiator chain.
4. **[minor] FR-34 wording.** "The initial password is never persisted outside the AD write"
   contradicts ADR-0005 rule 9: the password is stored sealed in `operation_secret` while the
   request waits for approval (72-hour TTL). Say "never stored except sealed in `operation_secret`
   per ADR-0005 rule 9, deleted when the AD step records".
5. **[minor] Cancel, Undo, Resume and Check now permissions.** Name the permission and scope check
   for each. Resume and Cancel are audited Actions; Check now is a rate-limited read.
6. **[minor] FR-17's list "SKU, group, scope or availability".** "Scope" must deny (FR-33,
   ADR-0005 rule 7), never re-approve.
7. **[minor] AC coverage.** Add ACs for A-B1, A-B2 and A-M1 as listed in their test lines.
   AC-08 should also assert that `cloud_seen_at` was set.
8. **[nit]** FR-15: cite the `$filter` support for `onPremisesImmutableId` ("Supports `$filter`
   (`eq`, …)", [user resource](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)).
9. **[nit] Renamed or quarantined UPN.** Show the Entra UPN observed at Apply in the status and the
   audit when it differs from the planned UPN. No re-approval is needed, because identity is the
   anchor.

---

## Part B: E2.6 report builder

### B.1 Ruling on grouping leaks

| Surface | Leak? | Why |
| --- | --- | --- |
| Counts, totals, Top N, minimum (`HAVING`), chart buckets over the row's **own** columns | No, given §5 step 3 | Scope precedes grouping in the same statement (FR-B13, LF-39). |
| Group keys, `count distinct`, `min`/`max`/`sum`/`avg` over a **masked or related-object** column (guid-with-label of a manager or group, OU path, `policy_source`, `Via`, member counts with `UnknownWhen`) | **Yes → B-B1** | The rows are in scope, but masking is projection-level (`MaskAnchor`, `modules/reports.md`). Grouping on the raw GUID with a masked label yields one "(outside your scope)" bucket per hidden object. |
| Sort order | No, if §9(c) holds | `sort_keys` "come from the same visible values". B-B1 applies the same rule to group keys and aggregates. |
| "Too many groups" (10,000) refusal, "1,000+" flag, error class | One-bit oracle **if** computed before scope | They must be computed post-scope. That is part of the B-M1 invariant. |
| Shared report run by a lower-scoped recipient | **Yes → B-B2** | Condition values (`GUIDV`) and their labels were picked under the owner's scope. |
| Preview runs | No | A preview is an ordinary run (§9), and DM-72.I5 keeps it readable only by its runner. |
| Schedules | Inherited 2a design | They run under the owner's scope with external confirmation (DM-73.I1, TM-D30). B.4 #4 adds a fail-closed rule. |
| Exports | No | They serialise stored rows only (DM-72.I2). |
| Timing (count timeout depends on total table size) | Residual, low | It reveals tenant data volume only, not objects. Accepted. |

**Is RP-B3 as proposed sufficient? No.** An oracle "over `AuthorizeRead`-admitted objects"
checks *which rows* exist. It does not check *what values derived from hidden objects* reach the
output, which is B-B1's class. It also does not cover condition values in shared definitions,
which is B-B2's class. B-M1 states the replacement.

### B.2 Ruling on free text and act-on-results

- **Free-text filter, SQL or LDAP path: none found in the UI or the API.** FR-B02, FR-B05 and RP-B1
  hold. Text values are bound (`TextV`, `LikePattern`). Names, descriptions and labels are encoded
  (FR-B27). There are two carve-outs that must be stated precisely (B.4 #1):
  - The E2.11 intake is the one place where filter text enters, as an uploaded file parsed by P1.
  - The importer's "Add `<attribute>` to the sync set" suggestion carries an attribute name taken
    from a hostile file.
- **Act-on-results cannot widen *authority*.** ADR-0005 rule 7 re-authorises every target at Plan
  and at Apply, and the `tier0` guard applies. But the spec does not define the API selection
  contract. So the *binding* between "the rows the admin saw" and the Operation's targets, which
  the `report_results` origin and the audit linkage rely on, is not guaranteed (B-M2).

### B.3 Blockers and majors

**B-B1 [blocker] · §5 "Grouping and totals", §9 (a)(b)(c), FR-B06, FR-B13.**
- **Problem.** Group keys and aggregates over masked or related-object columns are computed on raw
  values.
- **Exploit sketch.** A technician scoped to OU=Sales groups "Users" by `manager` (guid-with-label)
  with `count`. Each hidden manager in HR becomes a separate "(manager outside your scope)" bucket.
  The number of buckets, and each bucket's size, reveal how many out-of-scope managers there are
  and how many Sales staff each manages. `count distinct manager` gives the same number directly.
  `max()` over a related object's time column leaks a hidden object's value. `sum` over a member
  count read as Unknown either leaks the hidden size or shows a wrong number.
- **Fix.**
  - Group keys, aggregate inputs and `sort_keys` are computed over the **post-mask cell
    expression**. Every masked value collapses into one bucket per column.
  - Each column carries registry flags `groupable` and `aggregatable` (FB-3a). A column built on a
    `MaskAnchor` or a `Via` is groupable only on its masked rendering.
  - An aggregate over any Unknown cell is Unknown, or the run is refused. It is never computed from
    the raw value.
  - Group keys over an OU path follow the DN disclosure rule: only the row's own `dn` may name
    ancestors.
  - FB-3c's review must cover this explicitly.
- **Tests.** `group_by_masked_column_single_bucket`, `count_distinct_masked_related`,
  `aggregate_over_unknown_is_unknown`, plus the B-M1 property test.

**B-B2 [blocker] · §8 "Sharing", "What a recipient may and may not see", §9(e), FR-B11, FR-B12; also `reports.manage_all` metadata and the FR-B14 schedule diff.**
- **Problem.** A shared definition carries `GUIDV` values and parameter defaults picked under the
  owner's scope. The spec re-checks *fields* for the runner but not *values*.
- **Exploit sketch.**
  - The admin shares "Reports of manager = CFO (HR)". The Sales technician opening it sees the
    label "CFO, Jane Doe" in the condition editor.
  - Running it reveals which in-scope users report to a hidden object: a relationship oracle on
    out-of-scope data, which is exactly what LF-36 refuses in the admin-filter path
    (`ReferencedObjectNotReadable`).
  - A `reports.manage_all` holder reads the same labels from metadata.
- **Fix.**
  - The AST stores GUIDs only, never labels.
  - Labels are resolved at display under the **viewer's** scope, and an unreadable object shows
    "(object outside your scope)".
  - At every `Resolve` (run, preview, schedule fire, drill-down, comparator) each `GUIDV` and
    parameter default is re-authorised for the runner through `AuthorizeRead`. An unreadable one
    refuses the run with `value_not_permitted` and the condition *path*, naming no object.
  - Text values the owner typed are the owner's disclosure. State this as a residual in §16.
- **Tests.** `shared_guid_value_unreadable_refused`, `shared_definition_label_masked`,
  `manage_all_metadata_labels_masked`, `schedule_fire_guid_value_rechecked`.

**B-M1 [major] · §17 FB-3c (RP-B3), AC-B08, AC-B09.**
- **Problem.** RP-B3 as stated is an equality-to-oracle test over admitted objects. It misses
  derived-value leaks and condition values.
- **Fix: replace it with a non-interference property test.**
  - The generator draws random `ReportAst`s from the full grammar: every registered column,
    conditions, ≤ 3 group keys, aggregates, minimum, Top N, sort, parameters and `GUIDV`s.
  - It runs them over worlds W and W′ that differ **only** in:
    - out-of-scope objects (added, removed or mutated);
    - attributes of out-of-scope objects; and
    - in-scope objects' links to out-of-scope objects, with link existence held constant.
  - Assert that the runner's output is identical between W and W′: cells, group keys, counts,
    ordinal, `row_count`, digest, the "1,000+" flag, the "too many groups" refusal and the error
    class. Keep the existing oracle equality as a second assertion.
  - Run it for an own run, a shared run by a lower-scoped recipient, a preview, a drill-down and a
    schedule fire.
  - Extend RP-B2 so that preview, drill-down, validate-only and the E2.11 comparator also go
    through `Resolve`.
  - The group-cardinality check runs post-scope.
- **Test.** `rp_b3_noninterference` (property-based, seeded, in CI on PostgreSQL), with its
  deliberately failing fixtures (a raw-GUID group key, a pre-scope cardinality check) so the
  checker cannot rot into a no-op.

**B-M2 [major] · §10 items 2–4, FR-B16.**
- **Problem.** The act-on-results selection contract is undefined.
- **Exploit sketch.** A client posts arbitrary GUIDs labelled `report_results`, or acts on a run
  made by someone else or under a scope it no longer holds. Rule 7 stops the authority breach.
  But the Operation then claims a provenance ("the rows you saw as of `as_of`") that is false, and
  `max_batch` or the audit linkage can be gamed.
- **Fix.**
  - The API selection is `{run_id, row_keys[] | all_matching}`. It never accepts GUIDs.
  - The server resolves targets from `report_run_rows` through the dataset's `ActionSubject`.
  - The run must be the actor's own and pass DM-72.I5's fingerprint check, or the call answers
    409 "Your access changed since this run".
  - `all_matching` is bound to the stored `row_count`.
  - A grouped row's "Show rows" is a **new** run by the actor.
  - The Operation records `run_id` and the run digest.
- **Tests.** `act_selection_rejects_raw_guids`, `act_on_foreign_run_refused`,
  `act_after_scope_change_409`, `drilldown_is_new_run_by_actor`.

### B.4 Minors and nits

1. **[minor] §5, §11, FR-B02, FR-B03, FR-B05.** Make RP-B1 allow-list exactly one operation that
   accepts filter text: the E2.11 file intake, parsed by P1 and never executed as LDAP. The
   sync-set Action's input is an attribute chosen from the live schema (by `attributeSchema`
   reference, validated server-side), not free text. This resolves the literal clash with FR-B02.
   The importer's suggestion passes the same validation and the schema-driven `SecretAttrs` set
   (safe-primitives §3.7, LF-38: `searchFlags` 0x80/0x200/0x1000), with the Action's preview. Cite
   §3.7 in §16 rather than a name list.
2. **[minor] FR-B17.** Use an exact resolver only. Never fall back to `CompileSearch` or trigram
   matching, because a fuzzy match turns a list into a probe. DN values are parsed by the `dn`
   package and compared canonically.
3. **[minor] §16 audit (answers Q5/FB-5).**
   - `audit.events` is readable only with the audit-read permission.
   - Events with no directory target (sign-in, RBAC, settings) need **tenant-wide** audit-read.
   - Target-bearing events are visible to a scoped audit reader only when every target is in their
     read scope.
   - Actor display names stay `PersonalRef` (X11).
   - The "filters hash" and "query hash" are HMACs under a per-tenant salt (as `digest_salt`,
     DM-24.I5), because low-entropy filter values are otherwise brute-forceable by audit readers.
   - The preview event lists the field and operator IDs used, never values.
   - The proposed aggregation (one event per account and dataset per 10 minutes) is **accepted**,
     because previews are scope-trimmed.
4. **[minor] §8 sharing, FR-B14.**
   - Saving as an *Edit*-level sharee validates every field against the **editor's** permissions.
   - A schedule fire re-applies FR-B12 under the owner's current permissions and fails closed: the
     delivery fails with a reason and conditions are never dropped.
5. **[minor] §9 caps.** The per-tenant preview cap of 2 lets one account starve everyone's
   previews. Add a per-account cap of 1, so a newer preview supersedes the running one.
6. **[nit] §5.** Say whether the grand total under Top N is the total of all in-scope rows or of
   the top N.

---

## Summary for the authors

| Spec | Verdict | Blockers | Majors | Minors | Nits |
| --- | --- | --- | --- | --- | --- |
| E2.7 | **reject** | A-B1 approval binding; A-B2 identity binding | A-M1 tier0 at Apply; A-M2 `User.ReadUpdate.All` breadth; A-M3 `AuditLog.Read.All`; A-M4 certificate rotation | 7 | 2 |
| E2.6 | **reject** | B-B1 masked group keys and aggregates; B-B2 shared GUID values | B-M1 RP-B3 → non-interference; B-M2 act-on-results contract | 5 | 1 |

Follow-up for the server board (outside both diffs): add `ms-DS-ConsistencyGuid` to `guarded-v1`
`map_credential` (P1 `bug`, `security-sensitive`, owner `directory-engineer`, TM §6.9a and B1
fitness).

## Sources

- Microsoft Learn (read 2026-11-11):
  - [update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0): permission table, the property exceptions list, the `usageLocation` row
  - [permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference): `User.ReadUpdate.All`, `User-Mail.ReadWrite.All`, `User-Phone.ReadWrite.All` entries
  - [working with users](https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0): sensitive actions
  - [user resource](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0): `onPremisesImmutableId`, `onPremisesSyncEnabled`, `onPremisesSecurityIdentifier` and `usageLocation` rows
  - [M365 group licences](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-group-licenses?view=o365-worldwide): tenant-location inheritance
- Not read; tagged in the text: Entra Connect duplicate-attribute (UPN quarantine) behaviour
  `[UNVERIFIED]`; `msExchUsageLocation` flowing to `usageLocation` `[UNVERIFIED]`; app-only writes
  of `onPremisesImmutableId` and UPN with `User.ReadUpdate.All` `[UNVERIFIED — lab G3]`.
- Repository ground truth: as listed under "How this was reviewed".

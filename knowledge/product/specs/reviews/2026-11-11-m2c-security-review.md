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

---

## Round 2 — 2026-11-11

**Verdicts.** E2.7 (revision 2): **reject**. Every round-1 blocker and major is closed in the spec
text, but there are 2 new majors (A2-M1, A2-M2), 0 blockers and 7 minors. E2.6 (revision 2):
**advance**, with 3 minors and 1 nit to land before the build tickets are cut.

**How this was reviewed.** I verified each round-1 item against the FR, AC and §14 text itself. I
used the §15 and §24 response tables only as an index. I re-read: TM §6.4 (E1–E5, TM-D25 rule 1),
§6.6 (allow and deny lists, the "Gaps" paragraph), connector contract F1/F2 and CC-WRITE-14
(touched set), and the `inventory` notes in `blueprint.md` (`cloud_seen_at` trigger, `AnchorMatches`).
Microsoft pages were read on 2026-11-11 and are cited inline. This is still a document review, so
nothing was run. Each "attack attempted" below is a walk-through against the written rules.

### R2-A. E2.7 hybrid provisioning

#### R2-A.1 Round-1 items, verified in the text

| ID | Verdict | Evidence in the spec (not the response table) |
| --- | --- | --- |
| A-B1 | **Closed, on the conditions in R2-A.2** | FR-17 table (tenant and identity refuse; usage location, licences and groups hold; actors deny; fixed expiry); FR-18 (wait ends at `approval_valid_until`; Resume after it always needs a new approval); FR-16(5) and FR-33 (approver re-check at Apply on the resolved object, SoD, account active); FR-33 Plan rule (`entra_tenant` root or planned parent with `include_correlated`, initiator **and** approver); FR-16 no fall-through to FR-32; AC-22…AC-26 carry every round-1 test name. Attack walk-through: an AD-only approver approves → FR-33 blocks at Plan (`scope_denied`), and if their scope is removed later, FR-16(5) denies. Resume three weeks later → FR-18 requires a new approval. |
| A-B2 | **Closed** | (i) FR-15: a single cloud-only or cloud-managed match sets `cloud_seen_at`, holds `anchor_on_cloud_object` and raises a `high` alert; every poll feeds DM-16.I9; AC-18. (ii) FR-16(1): `ad_ref` = the recorded `objectGUID`, `entra_ref` = the found `id`, and the anchor re-read live; AC-20. (iii) FR-14: anchor = the created `objectGUID`; a foreign `ms-DS-ConsistencyGuid` holds `anchor_tampered` with an alert; FR-09: Plan refuses any write of `ms-DS-ConsistencyGuid`/`onPremisesImmutableId`; AC-19. (iv) FR-15: the I1a lookup fails closed; AC-21. Attack walk-through: a stamp on the new user *after* AD verify still fails, because the lookup uses base64 of our `objectGUID` and FR-16(1) compares the cloud object's anchor live. A second AD object stamped with our anchor → (e) `ambiguous_anchor` (live under FR-16). The `guarded-v1` follow-up is in §14.5. |
| A-M1 | **Closed** | FR-25 cites "any `tier0` group per TM §6.4 E1–E5 and TM-D25 rules 1–7", PIM-eligible nesting and designated groups included; FR-16(2) re-runs the guard on the user and every group before each write; `pim_read_failed` holds; `tier0_after_write` at Verify; FR-10(f) at Plan; AC-27. |
| A-M2 | **Closed for `User.ReadUpdate.All`** (the breadth moved, see A2-M2) | FR-04: Usage location is its own opt-in family, off by default, with EV5 breadth text; Flow A step 2; AC-04; the Action is single-key (§9, FR-33, AC-45); TM row and lab G3 extended (§14.5, OQ-F4). |
| A-M3 | **Closed** | FR-04 (recommended with a HybridLink; `Policy.Read.ConditionalAccess` optional; EV5 does not flag it), FR-06 ("change monitoring off"), FR-18 (late cause), AC-11. |
| A-M4 | **Closed** (minor A2-m6 tightens it) | FR-39 and FR-03 (a pending certificate is not an extra key); AC-10. |
| A.6 #1–#9 | **Spot-checked, all present** | FR-11/FR-17 split; Flow A step 7; FR-34 evidence fields and password wording; FR-40; FR-17 "scope denies"; AC-18…AC-27; FR-15 `$filter` cite; FR-16 observed UPN. |

#### R2-A.2 Ruling on the two-stage binding (plan hash plus activation digest)

**Ruling: the two-stage binding is equivalent in strength to the round-1 ruling, on six conditions.**
The round-1 requirement was that the approver's signature commits to the identity the cloud steps
act on. `objectGUID` cannot be in the plan hash, but it does not need to be. It is enough that:

- the plan hash commits to a *deterministic rule* for producing the identity;
- the only free input to that rule is a fact our own create step records once; and
- that fact is fixed in the hash chain before any cloud step can claim a token.

The conditions are:

| # | Condition | Why it matters |
| --- | --- | --- |
| D1 | **The plan hash commits to the derivation, not just to "a reference".** It names the operation, item and step whose result supplies `objectGUID`; the anchor rule (`anchor_attr`, base64 of `objectGUID`); the tenant connection and `directory_identity`; and the approval TTL constant (24 h) | Then nothing in the digest is chosen after approval. Every digest input is either in the plan hash or is the create step's recorded result |
| D2 | **One writer, one moment.** The continuation writes the digest exactly once, in the same transaction that records the AD item `succeeded` (step verified). `objectGUID` comes from the create step's own result record (see A2-m5), never from a later read or from inventory | A second write (a verify retry, a re-plan, Resume) would slide `approval_valid_until` or re-point the identity |
| D3 | **Write-once in storage.** The HybridRequest columns `objectGUID`, anchor, `approval_valid_until` and `activation_digest` have no UPDATE path for the runtime role (a guard trigger, as on `authn_accounts`). Resume is a new Operation that **copies** these values from the original record. It never recomputes them | This answers "can it be rewritten": no |
| D4 | **In the audit chain at birth.** `hybrid.awaiting_sync.started` is written in the D2 transaction and carries `plan_hash`, `objectGUID`, anchor, tenant ID, `approval_valid_until` and the digest. It is chained at commit (DM-80.I1) | Tampering with the row is then detectable against the chain, and an auditor can recompute the digest from one event |
| D5 | **Recompute, don't trust.** Before each cloud write the executor recomputes SHA-256(plan hash ‖ `objectGUID` ‖ anchor ‖ tenant ID ‖ `approval_valid_until`) from the D3 values and compares it with the token's bound digest. The inputs use a fixed-width canonical encoding, never string concatenation | A token bound to a digest the executor does not re-derive is a label, not a binding |
| D6 | **Absolute cap.** `approval_valid_until` ≤ approval time + `plan_valid_until` (1 h) + AD verify window + 24 h, asserted at D2 | It bounds the window even if AD verify is delayed |

FR-14, FR-17 and §14.1 item 5 state D2 in part and D5 in part ("tokens bind to it"). D1, D3, D4 and
D6 are absent. This, together with the Resume carry-over below, is **A2-M1**.

#### R2-A.3 New majors

**A2-M1 [major] · FR-14, FR-17 (paragraph after the table), FR-18 (Resume), FR-20, §14.1 items 4–5.
The activation-digest lifecycle and Resume carry-over are unspecified.**
- **Problem.** (a) Conditions D1, D3, D4 and D6 above are missing, so the text allows a recompute of
  `approval_valid_until` on Resume or on a verify retry. (b) FR-18 lets Resume "before
  `approval_valid_until` with an identical activation digest" keep the original approvals from
  **any** terminal state, `cloud_cancelled` included. (c) It does not say whether a held request
  under a security reason (`anchor_on_cloud_object`, `anchor_tampered`, `ambiguous_anchor`) may
  continue on the original approval once the condition clears.
- **Exploit sketch.**
  - A SOC analyst or the approver presses **Cancel cloud steps** after an `anchor_on_cloud_object`
    alert or on spotting a wrong group. The initiator presses **Resume** 10 minutes later. The digest
    is identical, so the cancelled approval licenses and groups the user with no new human sign-off.
  - Separately: if Resume recomputes "AD verify + 24 h" from the new Operation's clock, every
    Resume extends the window. That is the open-ended approval A-B1 closed.
- **Fix.**
  - Write D1–D6 into FR-17 and §14.1 item 5.
  - Approvals carry over only from `cloud_step_failed` (a retry of the same diff), and only within
    the window.
  - `cloud_cancelled` and `cloud_denied` **consume** the approvals: Resume then needs a new
    approval.
  - The security holds (`anchor_on_cloud_object`, `anchor_tampered`, `ambiguous_anchor`) are
    **sticky**. They never auto-clear on a later poll. They resolve only through Cancel, or through
    Resume with a fresh approval after a `tenant-owner` acknowledges the alert.
  - The transient holds (`tenant_takeover_open`, `pim_read_failed`, `reconfirm_required`,
    `not_matched`, `throttled`) auto-clear.
  - List both classes in FR-35.
- **Tests.**
  - `resume_after_cancel_requires_new_approval`
  - `resume_copies_window_never_recomputes`
  - `activation_digest_write_once` (an UPDATE is refused for the runtime role)
  - `awaiting_sync_event_carries_digest_inputs` (the digest recomputes from the event alone)
  - `security_hold_does_not_autoclear`
  - `digest_mismatch_refuses_token`

**A2-M2 [major] · §3 E4, FR-04 "Group membership (on by default)", Flow A step 2, §10 "Privileges",
AC-04. The new default grant `GroupMember.ReadWrite.All` is tenant-wide group-membership write, and
the spec presents it as the least-privilege path with no breadth text.**
- **What the permission actually reaches** (Microsoft Learn, read 2026-11-11):
  - The application permission "Allows the app to list groups, read basic properties, read and
    update the membership of the groups this app has access to without a signed-in user. Group
    properties and owners cannot be updated and groups cannot be deleted"
    ([permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference),
    `GroupMember.ReadWrite.All`, application ID `dbaae8cf-10b5-4b86-a4a1-f871c94c6695`).
    "Membership" covers add **and** remove.
  - **Role-assignable groups: no.** "To add members to a role-assignable group, the app must also
    be assigned the *RoleManagement.ReadWrite.Directory* permission". The API answers `403` when
    "you're attempting to add a member to a role-assignable group and you don't have the required
    permissions" ([add members](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0)).
    `RoleManagement.ReadWrite.Directory` is on the TM §6.6 deny list and EV3 refuses it without
    acknowledgement, so **Microsoft enforces this boundary for us**. Good.
  - **Groups in a restricted management AU: no.** "Applications can't modify objects in restricted
    management administrative units by default … If you assign Microsoft Graph application
    permissions to the application, those permissions won't apply"
    ([RMAU](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management)).
    The same page notes that RMAUs hold only security groups, not Microsoft 365 groups, and need
    Entra ID P1 for each AU administrator.
  - **AD-synced groups: no** (FR-24; group SOA page).
  - **Everything else: yes, add and remove, for any user.** That includes:
    - **groups holding Azure RBAC roles.** "You can assign a role to any of these security
      principals" (user, group, service principal, managed identity), and assignments are
      transitive through nested groups
      ([Azure RBAC](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview)).
      A group that holds Owner on a management group is therefore one membership write away from
      subscription takeover. **Graph cannot see Azure role assignments, and TM §6.4 E1–E5 has no
      Azure RBAC basis.**
    - **groups that Conditional Access excludes** (MFA bypass). These are `tier0` only if the
      customer designated them, and the proposal read `Policy.Read.ConditionalAccess` is optional
      in FR-04.
    - **groups that are a PIM-for-Groups eligible member of a role-assignable group.** These are in
      our TM-D25 closure, so our guard refuses them. Whether Graph refuses a membership write on
      them is `[UNVERIFIED — lab G11]`, and I assume it does not.
    - **app-access and Intune-RBAC groups.**
    - **Microsoft 365 groups**, whose membership grants their Teams, SharePoint and mailbox data.
- **Exploit sketch.**
  - A stolen Entra certificate (the TM §6.6 residual) or a compromised activeDIQ server adds an
    attacker-held ordinary user to an Azure-Owner group or a CA-exclusion group. Neither Microsoft
    nor our guard stops it on the default configuration.
  - Through a PIM-nested group, the only thing between the attacker and Global Administrator is
    our own server-side guard, which the attacker in this scenario controls.
  - The removal direction is a weakening too: taking a user out of a CA *include* group (for
    example "MFA required") drops their protection.
- **Fix.**
  1. Group-membership breadth text in Flow A step 2 and EV5 (FR-04), parallel to the
     `User.ReadUpdate.All` text: "can add or remove any user in any cloud security or Microsoft 365
     group that is not role-assignable, not in a restricted management AU and not synced from AD,
     including groups that grant Azure roles, app access or Conditional Access exclusions".
  2. Reword §3 E4. The claim "no profile-write permission on the default path" is true. "Least
     privilege" must not imply narrow membership reach.
  3. **Onboarding guidance (Microsoft-enforced boundary):** put CA-excluded groups, groups holding
     privileged Azure roles, groups nested as PIM-eligible members of role-assignable groups, and
     break-glass accounts into an RMAU. Health shows whether designated groups sit in one
     `[PROPOSED]`.
  4. **`Policy.Read.ConditionalAccess` becomes required whenever the Group-membership family is
     on.** CA-excluded groups are then proposed for designation (TM-D25 rule 9), and CA-*include*
     groups are flagged so that a removal from them previews as a security weakening.
  5. **Per-connection writable-group allow-list** (default empty apart from the licensed groups the
     admin picks at onboarding). Changing it is a step-up `tenant-owner` Action that shows each
     group's classification. Plan refuses any other group with `group_not_writable(not_allow_listed)`.
     This bounds a malicious technician or template. Items 3 and 4 bound a compromised server.
  6. TM follow-ups: a §6.6 residual row for `GroupMember.ReadWrite.All` reach, and a §6.4
     designation category "groups holding privileged Azure RBAC roles", entered by hand because
     Graph cannot see Azure role assignments.
- **Tests.**
  - `ev5_warns_groupmember_breadth`
  - `group_not_on_allowlist_refused`
  - `ca_policy_read_required_with_group_family`
  - `removal_from_ca_include_group_flagged`
  - lab G11 extended: a membership write on a non-role-assignable group that is a PIM-eligible
    member of a role-assignable group, app-only, records whether Graph refuses it

#### R2-A.4 New attack surface: FR-36…FR-40, minors and nit

- **FR-36 (delta sync).** Sound: the property list is fixed at the first request; `cloud_seen_at` is
  set by sync and protected by the inventory trigger (`blueprint.md`, T-0431); nothing in it is
  written to Entra. Minor A2-m7 covers token and host binding.
- **FR-37 (targeted re-sync).** Sound: lookup is by `id` or by anchor through P8 `Eq`/`Str`.
  Minors A2-m3 (rate) and A2-m8 (TOCTOU).
- **FR-38 (datasets).** Sound: `onPremisesImmutableId`, mail and proxy addresses are not columns;
  related-object flags are used. Minor A2-m1.
- **FR-39 (rotation).** Minor A2-m6.
- **FR-40 (request controls).** Minor A2-m3.

1. **A2-m1 [minor] · FR-38, `inventory.entra_users` and `.entra_groups`.** Correlation state,
   `candidate_reason` (for example `sid_mismatch`, `ambiguous_anchor`) and the AD-derived part of the
   SOA badge are facts about **AD** objects. A runner scoped only to `entra_tenant` learns from them
   that out-of-scope AD objects exist and carry an anchor. Flag these columns related-object and
   mask them for a runner without read on the AD side. Synced/cloud stays visible, because it is an
   Entra fact (`onPremisesSyncEnabled`). Test: `entra_only_runner_sees_no_ad_derived_reason`
   (E2.6 FR-B30 covers it once the column is flagged).
2. **A2-m2 [minor] · FR-12, FR-31.** Removing a user from a **licensed** group, including the undo
   of the add, removes a licence. Class it **Lossy**, as direct licence removal is. Test:
   `licensed_group_removal_is_lossy`.
3. **A2-m3 [minor] · FR-37, FR-40.** Check now is limited only per request, and anyone who can read
   requests may press it. One account across many requests can spend the tenant's Graph throttling
   budget, which writes share (FR-27). Add per-account and per-tenant caps, and give the write path
   priority over re-sync. Test: `check_now_tenant_cap`.
4. **A2-m4 [minor] · FR-35.** Covered by A2-M1: the two hold classes (sticky security holds,
   transient holds) must be named in the error table.
5. **A2-m5 [minor] · FR-14, FR-17 "the `objectGUID` returned by our own create".** An LDAP add
   returns no attributes (`AddResponse ::= [APPLICATION 9] LDAPResult`,
   [RFC 4511 §4.7](https://www.rfc-editor.org/rfc/rfc4511#section-4.7)). Define the value as the
   create step's read on the same pinned DC immediately after the add, by DN, checked by
   `uSNCreated` above the pre-add `highestCommittedUSN`, and recorded in the step result. Test:
   `create_records_guid_from_pinned_readback`.
6. **A2-m6 [minor] · FR-39.**
   - Rotation is a step-up, audited Action.
   - A pending thumbprint lives at most 14 days `[PROPOSED]`, then EV5 flags it again.
   - A key the server did not generate is still flagged during a rotation.
   - Test: `pending_thumbprint_expires`, `unknown_key_flagged_during_rotation`.
7. **A2-m7 [minor] · FR-36, §9.** `@odata.deltaLink` and `@odata.nextLink` are stored per
   connection and followed only after the P8 host pin. Each access token's `tid` is checked against
   `directory_identity` on acquisition, not only at EV2. A delta page from another tenant is
   refused. Test: `delta_link_foreign_host_refused`, `token_tid_mismatch_refused`.
8. **A2-m8 [minor] · FR-16 vs FR-37.** FR-16 says "re-read live immediately before each write",
   while FR-37 makes the targeted re-sync plus the *stored* result the only read. Say that the
   FR-16 read is a targeted re-sync inside the same step claim, and that the write uses the object
   `id` from that read.
9. **[nit] §14.4.** State the Entra membership touched set: the group **and** the member, as
   CC-WRITE-14 does for AD. A `tier0` user is then never added to or removed from any group through
   Graph.

### R2-B. E2.6 report builder

#### R2-B.1 Round-1 items, verified in the text

| ID | Verdict | Evidence in the spec |
| --- | --- | --- |
| B-B1 | **Closed** | §5 rules 1–3 (post-scope, post-mask; one masked bucket per column; labels from the masked column; OU key from the row's own `dn`; Unknown propagation; refusals post-scope); the Fields paragraph adds `groupable`/`aggregatable`; FR-B28; L1–L3; AC-B38 (4 buckets, `count distinct` 4 not 7, max Unknown, OU own container). Attack walk-through (group Sales by manager): the 4 hidden HR managers collapse into one bucket whose count equals what the row cells already show. |
| B-B2 | **Closed** | FR-B29 (GUIDs without labels; re-authorisation at every `Resolve`; `value_not_permitted` with the path only; viewer-scope labels; `manage_all` metadata without values), §8 recipient rules, L6 (run, preview, drill-down, schedule fire, comparator, validate-only), §16 residual for owner-typed text, AC-B39. |
| B-M1 | **Closed** (minor B2-m1) | FR-B30, AC-B40 (the worlds I specified, the five run kinds plus export, the oracle kept, the two failing fixtures), FB-3c with RP-B2 widened, §5 rule 3. |
| B-M2 | **Closed** | §10 item 2 and FR-B16 (`{run_id, row_keys[] or all_matching}`, GUIDs → 400, derivation through `ActionSubject`, own, `succeeded`, unexpired run, 410/409, `all_matching` bound to `row_count`, masked identity rows skipped), drill-down as a new run, run ID and digest recorded; AC-B41. |
| B-m1, B-m2, B-m4, B-m5, B-n1 | **Spot-checked, present** | §5 carve-outs and AC-B43; FR-B17 and FB-6b; §8 Edit-level and schedule fire with AC-B10 and AC-B45; §9 per-account cap with AC-B19; §5 grand total. |
| B-m3 | **Present except the roll-up** | Ruled below. |

#### R2-B.2 Ruling on B-m3 (one `reports.preview.run` event per preview run)

**Acceptable, and better than what I accepted in round 1.** I accepted the roll-up only to save
volume. It was not a security requirement. A roll-up also needs either a mutable aggregate row or
a deferred write, and both conflict with "written in the same transaction" and the append-only,
chained store (security-baseline §7). One event per run, chained at commit, is the stronger
control. The §9 rate limit of 30 per minute per account bounds chain volume. AC-B35 proves 12
events and a verifying chain.

Two conditions are folded into B2-m3:
- every preview that started is recorded, whatever its end; and
- refused previews are recorded as denials without flooding the chain.

#### R2-B.3 New surface: FR-B28…FR-B30, and minors

FR-B28 and FR-B29 are correct as written. FR-B30 is the right property, with one contradiction
(B2-m1).

1. **B2-m1 [minor] · FR-B30 vs §16 "Residuals accepted".** FR-B30 requires the "timing class" to be
   identical across worlds. §16 accepts that a timeout reveals tenant data volume. The "1,000+"
   flag (rows-only fallback after a count timeout) and "too heavy" both depend on how many hidden
   rows exist. As written, the property is either flaky or quietly weakened in the test.
   - State the property **modulo resource limits**: the property test runs with the statement
     timeout disabled.
   - Timeout-driven outcomes are the §16 residual.
   - Every other error class must be identical.
2. **B2-m2 [minor] · §9 L5, FR-B29.** L5 answers "not found" for an unreadable GUID, while FR-B29
   answers `value_not_permitted`. Use **one** code in every path, own or shared, for nonexistent
   and unreadable alike. Otherwise a runner can craft definitions through the API and tell hidden
   objects from deleted ones. The AC-B40 generator must draw `GUIDV`s from out-of-scope objects
   that W′ removes.
3. **B2-m3 [minor] · §16 preview audit.**
   - Write the event in the transaction that makes the preview terminal: `succeeded`, superseded,
     cancelled, failed or "too heavy". It carries the outcome and row count.
   - A preview that read data and was then superseded must still appear.
   - Record rate-limit and cap refusals as one `reports.preview.refused` per account per minute,
     with a count. Nothing was read, so aggregating them is acceptable.
   - Test: `superseded_preview_audited`, `preview_refusals_aggregated`.
4. **[nit] FR-B29.** Once FB-6a ships, editor labels resolve under the `reports.run` scope, the
   same scope `Resolve` uses. Until then they resolve under `directory.read` (residual already in
   §16).

### Round 2 summary

| Spec | Verdict | Open blockers | Open majors | Minors | Nits |
| --- | --- | --- | --- | --- | --- |
| E2.7 | **reject** | none | A2-M1 activation-digest lifecycle and Resume carry-over; A2-M2 `GroupMember.ReadWrite.All` reach on the default path | 7 (A2-m1–m3, m5–m8; m4 folds into A2-M1) | 1 |
| E2.6 | **advance** | none | none | 3 (B2-m1–m3) | 1 |

Re-review of E2.7 covers A2-M1 and A2-M2 only.

**Follow-ups for the server board (outside both diffs; owner `security-architect` unless noted):**
- TM §6.6: residual row for `GroupMember.ReadWrite.All` reach (A2-M2 item 6).
- TM §6.4: designation category for groups holding privileged Azure RBAC roles.
- Lab G11 extended: is a membership write refused on a PIM-eligible nested group? (`directory-engineer`.)
- Still open from round 1: the P1 `guarded-v1` addition of `ms-DS-ConsistencyGuid`.

### Round 2 sources

- [Add members (Graph v1.0)](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0): the permissions table, the role-assignable sentence and the `403` cases (read in full 2026-11-11).
- [Permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference): the `GroupMember.ReadWrite.All` and `GroupMember.Read.All` entries (read 2026-11-11).
- [Restricted management administrative units](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management): blocked operations, programmability, supported object types, licence (read in full 2026-11-11).
- [Azure RBAC overview](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview): security principals include groups; group assignments are transitive (read in full 2026-11-11).
- [RFC 4511 §4.7](https://www.rfc-editor.org/rfc/rfc4511#section-4.7): `AddResponse` is a bare `LDAPResult` (from the standard; not re-read today).
- Not verified and tagged in the text: whether Graph refuses a membership write on a non-role-assignable group that is a PIM-eligible member of a role-assignable group `[UNVERIFIED — lab G11]`.

### E2.7 round 1→2 responses

Moved here from the E2.7 spec ("§15 Review response", revision 2) in round 3, per the architecture review's length finding. It answers **both** round-1 reviews (architecture `H-*`, `X-*`; security `A-*`, `A.6`). Spec locations are as of revision 2: §7.6 now lives in [e2-7a-entra-inventory-sync.md](../e2-7a-entra-inventory-sync.md), and §14.1 item 8 was dropped in round 3 (H2-m1). The round 2→3 responses are in the spec's own `### Round 3` section.

Both reviews are dated 2026-11-11. "Taken" = changed as asked. Findings that concern only E2.6 (R-\*, B-\*)
and X-3 are not part of this diff.

| Finding | Disposition | Where |
| --- | --- | --- |
| H-B1 coupled items, FR-10 vs FR-21 | Taken, with Plan-time checks for everything knowable before the AD write; a later refusal gives `partially_succeeded` + `cloud_reason` and offers AD undo | FR-09, FR-10, FR-21, §14.1 items 1–3 |
| H-M1 outcome names, Resume | Taken. One name per state; display labels derived; Resume is a new Operation | FR-18, FR-21, AC-25, §14.1 items 3–4 |
| H-M2 Plan-time authority, hash binding | Taken. Binding is two-stage because `objectGUID` does not exist at Plan (reference in the plan hash, values in the activation digest). Security to confirm | FR-17, FR-33, §14.1 items 5–6 |
| H-M3 Entra sync, T-1131/E-011 | Taken. Sync is in this spec | FR-36, FR-37, §14.6 |
| H-M4 group membership under `objects`, usage location | Taken: Entra arm of `objects` group-membership Actions; usage location is an Entra arm of `objects.user.update` limited to one key | FR-23, FR-33, §9 |
| H-M5 §8.9 guard on licence and `usageLocation` | Taken | FR-25, AC-28 |
| H-M6 FR-17 AC, `replan_changed`, FR column, missing ACs | Taken. FR column added; ACs added for FR-02, 05, 06, 07, 17, 26, 31, 35 | §11, AC-05…AC-08, AC-23, AC-38, AC-41, AC-46 |
| H-M7 ADR-0004 follow-up | Taken | §14.2 |
| H-m1 undo of AD create is Lossy | Taken | FR-12, AC-34 |
| H-m2 non-default anchor | Taken in part: 2c supports binary anchors only; a string anchor blocks at Plan; `source_anchor_attr` on the link | FR-08, FR-10(i), AC-09 |
| H-m3 Cloud Sync default | Taken: 20 min `[PROPOSED]` | FR-08 |
| H-m4 closed error set | Taken: table by phase | FR-35, AC-41 |
| H-m5 `outcome_unknown` for Graph | Taken | FR-22, FR-23, §14.1 item 8, AC-33 |
| H-m6 availability wording | Taken | FR-11, AC-15 |
| H-m7 EV3 acknowledgement | Taken as the stricter option: not acknowledgeable for Entra in 2c. This departs from DM-24's text, so it is a domain-model follow-up | FR-03, §14.3, AC-02 |
| H-m8 `hybrid.*` EP-7 registration | Taken | FR-34, §14.1 item 9 |
| H nits 1–3 (T-1005 reference, step-up vs kernel hold, FR-13 row) | Taken | §5 matrix, Flow B step 3 |
| X-1 Entra datasets | Taken: E2.7 owns and registers users, groups, licence assignments | FR-38, §7.6, AC-43 |
| X-2 shared scope dependency | Taken, listed here; the E2.6 side is an E2.6 edit | §14.6, §5 |
| X-3 E2.6 vs E2.11 | Not this spec | none |
| A-B1 / OQ-F2 approval binding | Taken as ruled, OQ-F2 closed, with the two-stage hash noted above | FR-14, FR-16…FR-18, FR-33, AC-22…AC-26 |
| A-B2 identity binding | Taken: single cloud-only match holds and alerts, `ad_ref` binding, `anchor_tampered`, Plan refuses the write, fail-closed lookup | FR-09, FR-14…FR-16, AC-18…AC-21 |
| A-M1 tier0 at Apply | Taken | FR-16, FR-25, AC-27 |
| A-M2 `User.ReadUpdate.All` breadth | Taken: opt-in family, default licence path via licensed group, single-key Action, TM row as follow-up. `msExchUsageLocation` kept as an optional lab question, not relied on | FR-04, FR-26, §2, §14.5, OQ-F9 |
| A-M3 `AuditLog.Read.All` | Taken: recommended with a link, "monitoring off" health and late cause | FR-04, FR-06, FR-18, AC-11 |
| A-M4 certificate rotation | Taken | FR-39, AC-10 |
| A.6 #1 availability vs re-approval | Taken | FR-11, FR-17 |
| A.6 #2 declared link is `confirmed` | Taken | Flow A step 7, AC-09 |
| A.6 #3 audit content | Taken | FR-34, AC-39 |
| A.6 #4 password wording | Taken | FR-34 |
| A.6 #5 permissions of Cancel, Undo, Resume, Check now | Taken | FR-40, AC-35 |
| A.6 #6 scope denies, never re-approves | Taken | FR-17, FR-33 |
| A.6 #7 ACs for A-B1, A-B2, A-M1 | Taken | AC-18…AC-27 |
| A.6 #8 `$filter` cite | Taken | FR-15 |
| A.6 #9 observed UPN | Taken | FR-16, AC-37 |
| A.1–A.3 rulings; `guarded-v1` follow-up | Applied; follow-up listed | §10, §14.5 |

## Round 3 — 2026-11-11

**Verdict. E2.7 (revision 3) and e2-7a (revision 1): advance.** A2-M1 and A2-M2 are closed in the
spec text. Every round-2 minor and the nit are present. The split lost nothing security-relevant. I
confirm H2-m6 on four conditions. Round 3 raises 0 blockers, 0 majors, 3 minors (A3-m1…m3) and
2 nits. Land them before the build tickets are cut. Scope was narrow: the round-2 open items only.
This was a document review, so nothing was run. Each attack below is a walk-through against the
written rules. I read the FR, AC and §14 text, and used the spec's `### Round 3` list only as an
index.

### R3.1 Round-2 items, verified in the text

| ID | Verdict | Evidence (E2.7 unless marked) |
| --- | --- | --- |
| A2-M1 (a) D1–D6 | **Closed** | FR-17 "Activation digest rules" states D1–D6 as ruled. FR-14 sets one transaction for `approval_valid_until` and the digest. §14.1 item 5 points to them. AC-47 holds a test per rule: `create_records_guid_from_pinned_readback` (D2 input), `activation_digest_write_once` (D3), `awaiting_sync_event_carries_digest_inputs` (D4), `digest_mismatch_refuses_token` (D5), `window_cap_asserted` (D6). D1 is in the AC-47 text but has no named test (nit 1). |
| A2-M1 (b) Resume | **Closed** (A3-m1 tightens it) | FR-18 Resume rule. A live original ends `cloud_superseded` with `superseded_by` in the same transaction, and a unique key on `request_id` allows one live continuation (AC-49, `one_live_continuation_per_request`, `no_double_cloud_write`). Approval carries over only after `cloud_step_failed`, before `approval_valid_until`, with equal bound elements. Cancel, `cloud_denied`, `cloud_expired` and security holds consume it (AC-48, `resume_after_cancel_requires_new_approval`). FR-20 Cancel → `cloud_cancelled`. Attack walk-through, the round-2 exploit: SOC presses Cancel, the initiator presses Resume 10 min later → the terminal reason is `cloud_cancelled`, so a new approval is required. Refused. |
| A2-M1 (c) holds | **Closed** | FR-35 has a sticky row (`anchor_on_cloud_object`, `anchor_tampered`, `ambiguous_anchor`) and a transient row. FR-18: sticky holds end only through Cancel, or through Resume with a new approval after `tenant-owner` acknowledges the alert. AC-48 `security_hold_does_not_autoclear`, `transient_hold_autoclears`. AC-41 renders sticky or transient. |
| A2-M2 | **Closed** | FR-41 (a)–(d): breadth text, which equals Flow A step 2. A deny-by-default writable-group allow-list: a step-up `tenant-owner` Action that shows each group's classification, `group_not_writable(not_allow_listed)`, audited as `connection.writable_groups.changed` (FR-34). `Policy.Read.ConditionalAccess` is required with the family (FR-04; a missing permission disables the family, AC-51). CA-excluded groups are proposed for `tier0`. A CA-include removal previews as a security weakening. RMAU guidance with its limits. Sources inline (permissions reference, add members, RMAU, Azure RBAC). E4 is reworded ("reduced-privilege", breadth stated). §10 Privileges. TM residual and lab G11 are in §14.5 and OQ-F4. AC-50, AC-51. Attack walk-through: a compromised template names an Azure-Owner group → not on the list → Plan refuses. A compromised server stays the residual that FR-41(d) and the TM row cover. |
| A2-m1 | **Closed** | e2-7a FR-38 "AD-derived columns" and the dataset footnote (correlation state, `candidate_reason`, `ad_object` related-object and masked; synced/cloud visible). AC-57 `entra_only_runner_sees_no_ad_derived_reason`. |
| A2-m2 | **Closed** | FR-12, FR-31 (licensed-group removal and undo of the add are Lossy). AC-52 `licensed_group_removal_is_lossy`. |
| A2-m3 | **Closed** (A3-m2 clarifies it) | FR-40 caps per request, per account and per tenant. e2-7a FR-37 budget (6 per account and 30 per tenant per minute `[PROPOSED]`, writes ahead of re-syncs). AC-56. |
| A2-m4 | **Closed** | Folded into A2-M1 (FR-35 classes). |
| A2-m5 | **Closed** | FR-14 pinned-DC read-back by DN, `uSNCreated` above the pre-add `highestCommittedUSN`, value recorded in the step result, RFC 4511 §4.7 cited. AC-47. |
| A2-m6 | **Closed** | FR-39 step-up audited Action, 14-day pending thumbprint, unknown key still flagged. AC-10 `pending_thumbprint_expires`, `unknown_key_flagged_during_rotation`. |
| A2-m7 | **Closed** | e2-7a FR-36 "Link and token binding": links stored per connection, followed after the P8 host pin, `tid` checked on every acquisition, foreign page refused. AC-55. |
| A2-m8 | **Closed** | FR-16: the pre-write read is a targeted re-sync inside the same step claim, and the write uses its `id`. AC-20 `write_uses_id_from_presync_read`. |
| A2 nit | **Closed** | §14.4: the membership touched set is the group **and** the member. |

### R3.2 Ruling: a terminal original keeps its own `cloud_reason`

**Confirmed. This opens nothing, and it is the safer choice.** The carry-over test in FR-18 keys
off the original's terminal reason: only `cloud_step_failed` carries over. If a terminal original
were re-marked `cloud_superseded`, the `cloud_cancelled`, `cloud_denied` or `cloud_expired` signal
that consumes the approval would be overwritten. Re-marking would also mutate a terminal row in an
append-only audit design. Walk-throughs:
- **Resume on a terminal original while a later continuation is live.** The `request_id` unique key
  refuses it (fail closed, AC-49).
- **Chained carry-over.** A fails (`cloud_step_failed`), B is resumed from it and also fails, then C
  is resumed. Every hop copies A's `approval_valid_until` (D3), so the window never grows.
- **Superseding a live original.** A waiting or held original is never `cloud_step_failed`, so
  superseding it always needs a new approval.

The terminal original has no `superseded_by` link, so traceability rests on `request_id` and
`objects.hybrid.resumed`. Nit 2 makes that event carry what an auditor needs.

### R3.3 The split (E2.7 → e2-7a)

**Nothing lost.**
- **Deny list:** stays in E2.7 FR-04. e2-7a adds no permission and reads with the Read family (e2-7a
  intro, §4).
- **`onPremisesImmutableId`:** still synced (FR-36; correlation needs it) and not exposed (dataset
  footnote, §4 "never a column", AC-43).
- **Scope gating:** the FR-38 Boot rule refuses a dataset whose root kinds the renderer cannot
  render (AC-43 `dataset_registry_refuses_unrendered_root`). A dataset is readable only under its
  scope. Each dataset declares its scope roots.
- **Takeover signal:** sync sets `cloud_seen_at`, protected by the inventory trigger (e2-7a §4).
- **Safe primitives:** P8 only, with `nextLink` followed after the host pin.
- **References:** E2.6 now cites e2-7a FR-38 (E2.6 lines 39, 76, 378).

### R3.4 Ruling on H2-m6 (FR-33: a licence-carrying group step also needs `m365.licence.assign`)

**Confirmed, on four conditions** (A3-m3). The rule is right: membership rights alone must never
spend a paid licence or grant the services it carries. The FR-41 allow-list already limits this to
groups a `tenant-owner` listed. The conditions close the gaps the one-line rule leaves:
1. **Whose scope.** `m365.licence.assign` (`.remove` for a removal or an undo) is evaluated over the
   **member user**, the licensee, exactly as on the direct path. This is in addition to the
   membership permission over the group.
2. **Live and fail-closed.** "Carries a licence" is read live from the group's `assignedLicenses`
   at Plan and at Apply, not only from inventory: group delta returning `assignedLicenses` is
   `[UNVERIFIED — lab]` (e2-7a FR-36). If the value cannot be read, the group is treated as
   licence-carrying.
3. **Bound at approval.** Add "carries licence SKU set S" to the FR-17 Groups classification. A group
   that gains or changes a licence during the wait then holds `replan_changed`. Otherwise an
   approver who approved a plain group add would have a paid licence spent under their approval by
   an initiator who happens to hold `.assign`.
4. **The AD arm.** FR-24 routes AD-synced groups to an AD step. Licensing groups are often
   AD-synced, so where the Entra twin (matched by SID) carries a licence, the same permission and
   the "assigns licence via sync" preview apply. The general case, AD group-membership Actions on
   synced licensed groups outside a hybrid request (E2.2), is a server-board follow-up for the
   `objects` owner. It is not part of this diff.

Test: AC-52 `licensed_group_add_needs_licence_permission`, extended with
`licence_gained_during_wait_holds`, `licence_flag_unreadable_fails_closed` and
`synced_licensed_group_needs_licence_permission`.

### R3.5 Minors and nits (land before the build tickets are cut)

1. **A3-m1 [minor] · FR-18, FR-17 D3, AC-48 "the new Operation copies `approval_valid_until` and
   the digest values" after Cancel, denial, expiry or a security hold.**
   - **Problem.** Those cases need a new approval. With an expired window copied over, the resumed
     Operation is dead on arrival. With the original digest copied over, D5 (which hashes the new
     plan hash) never matches. This fails closed, but an implementer will "fix" it by adding an
     UPDATE path, and that is how D3 erodes.
   - **Fix.** `objectGUID` and the anchor are **always** copied, never re-read.
     `approval_valid_until` and the digest are copied **only on carry-over**. After a new approval,
     the new continuation row writes its own window and digest once, by the D2–D6 rules relative to
     the new approval (the D1 supplying step is still the original's create step), with its own
     `objects.hybrid.awaiting_sync.started`. That is a new write-once row, never an UPDATE.
   - **Test.** `resume_with_new_approval_writes_fresh_row_copies_identity`.
2. **A3-m2 [minor] · e2-7a FR-37 budget vs E2.7 FR-15/FR-16.**
   - **Problem.** The FR-15 lookup and the FR-16 pre-write read are targeted re-syncs. If they count
     against the 30-per-minute tenant cap, five readers pressing Check now can starve every
     continuation until it expires.
   - **Fix.** State that the account and tenant caps apply to human-initiated re-syncs only. The
     continuation's own reads belong to the write path's budget and priority.
   - **Test.** `continuation_reads_not_starved_by_check_now`.
3. **A3-m3 [minor] · FR-33, FR-17 Groups row, FR-24.** The H2-m6 conditions 1–4 above.
4. **[nit] AC-47.** Name a D1 test (`plan_hash_commits_to_derivation`).
5. **[nit] FR-34.** `objects.hybrid.resumed` carries the source Operation ID, the source's
   `cloud_reason`, and whether the approval carried over or which new approval IDs replaced it.

### Round 3 summary

| Spec | Verdict | Open blockers | Open majors | Minors | Nits |
| --- | --- | --- | --- | --- | --- |
| E2.7 rev 3 + e2-7a rev 1 | **advance** | none | none | 3 (A3-m1…m3) | 2 |

**Follow-ups for the server board (unchanged from round 2, plus one):** TM §6.6
`GroupMember.ReadWrite.All` residual. TM §6.4 Azure-RBAC designation category. Lab G11 extended.
P1 `guarded-v1` for `ms-DS-ConsistencyGuid`. **New:** AD group-membership Actions on AD-synced
groups whose Entra twin carries a licence need the `m365.licence.assign` rule once an Entra
connection exists (owner `backend-engineer`, `objects`; R3.4 condition 4).

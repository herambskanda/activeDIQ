---
title: "Security review: policy-row scope (domain-head rule) and the ReadReplicationStatus right (T-1124)"
date: 2026-11-13
updated: 2026-11-13
status: review
owner: heramb
author: security-architect
ticket: T-1884
binding_sources: modules/reports.md §3.3a (e), §4.2; connector-contract.md §5.5, §5.6, §5.7; threat-model.md §6.3 R14, TM-D31; modules/rbac.md (read scopes, root kinds DM-35); specs/reports-2-second-slice.md §7.1 rules 3 and 6, §7.3
sources_last_checked: 2026-11-13
---

# Policy-row scope and the ReadReplicationStatus right

Reviewed: decision 13 ("policy rows exist only for a runner who can read the domain head") and
`ReadReplicationStatus` (connector-contract §5.6), both from the T-1124 amendment. Read-only review of
the design text and of `factory/T-1723` (the built RPC); no product code changed.

**Two premises in the ticket are corrected here, so nobody builds on them.**

- **TM-D30 is not a threat model for policy data.** TM-D30 is the conditional step-up for report
  schedules with external recipients ([reports-schedules-security-review.md](reports-schedules-security-review.md) §2).
  It has nothing on PSOs. The data-class analysis for policy rows is therefore §1 below. The only
  TM-D30 interaction is delivery (an exported policy row leaves like any other row, §1.5).
- **`ReadPerDC` has no distinct permission.** Connector-contract §5.5 bounds it by a closed attribute
  enum and per-DC caps, and names no separate right. The "own permission" precedent for per-DC reads is
  TM-D31/R14, which is a *directory* right on the connection account, not a new RBAC concept. See §2.

## 1. Policy-row scope

### 1.1 Verdict

**"The domain head is in the runner's read scope" is the right and sufficient boundary for the *domain*
row, and necessary but NOT sufficient for PSO rows.** Finding PR-F1 (medium) below is the gap.

### 1.2 What the rule does well (verified against the RBAC text)

- Only a `naming_context` root contains the domain head. `ou_subtree` and `ou_one_level` roots are OU
  GUIDs (rbac.md, DM-35): an OU-scoped runner has no head in scope and gets the scope notice. The
  `tenant` root "contributes nothing to directory datasets", so it does not reach the head by accident.
- A token layer is AND-ed with the grants, so an API token narrowed to an OU cannot see policy rows
  even when its owner can. `Via` (correlation-derived) grants contribute nothing. A scope kind without
  an evaluator drops the grant. The object view fails closed on an unknown root kind.
- The domain row (the eight attributes on the head) is readable by every authenticated principal in AD,
  so showing it to a head-in-scope runner discloses nothing new.

### 1.3 The gap: the head being in scope does not mean every PSO's targets are in scope

A `naming_context` assignment can carry **OU-subtree excludes** (rbac.md: excludes beat includes). Such
a runner has the head in scope and a hole in their scope on purpose, for example the Executives or the
Service Accounts OU. Today's design shows them every PSO row: name, precedence and every value, and
only "Applies to" is filtered to in-scope targets.

- **Exploit sketch.** A delegated reporting role has a naming-context scope that excludes
  `OU=Executives`. A PSO named `Executives-Strict` (precedence 1, lockout threshold 3, minimum length
  20, applies to a group in the excluded OU) appears in SYS-01 with "Applies to: 0 in your scope". The
  runner has learned that the excluded population exists, which group-like name it has and how its
  password and lockout policy differ from the domain's. That is exactly the knowledge an exclude is
  meant to withhold, and the weaker-than-domain deltas point at the easiest accounts to spray.
- **AD baseline for comparison.** Spec §7.1 rule 3 records that PSOs are readable by Domain Admins only
  by default. activeDIQ relays that data to anyone who passes RBAC, so RBAC is the *only* gate for it.
  That is acceptable only if RBAC is exact; the head rule alone is not exact.

### 1.4 Required rules (PR-1 to PR-5)

| # | Rule |
| --- | --- |
| PR-1 | **Domain row:** shown iff the NC's domain head is in the runner's read scope (decision 13 stands). |
| PR-2 | **PSO row:** shown iff the head is in scope **and** the PSO object itself is in scope **and** (it has at least one direct target in scope **or** it has no direct targets at all). A PSO whose direct targets are all out of scope is not a row: not its name, precedence, values or count. |
| PR-3 | **Notice for hidden PSOs, without a number.** When PR-2 hides one or more PSOs, the report shows a fixed notice "Fine-grained policies that apply only to objects outside your scope are not shown." It carries no count, no name and no precedence. It never reads "no policies" (spec §7.1 rule 3 wording rule still binds). It is carried in every export, like the head notice. |
| PR-4 | **Deltas** ("stricter / weaker") are computed only for rows PR-2 allows, and use the *domain* row as the comparison. Precedence is shown as stored; a gap in precedence numbers does leak that a hidden PSO may exist, so precedence is shown as a **rank among the visible rows** and the stored value is not exported. `[PROPOSED]` — product-manager may prefer the stored value; the stored value is acceptable if PR-3's notice is always shown whenever the runner has any exclude. |
| PR-5 | **Tier-0 targets are not special-cased.** DM-35.I5 says Tier-0 does not narrow reads, and a runner who can read the head can already read the Tier-0 principals a PSO names. A PSO applied to Domain Admins is shown to such a runner. Accepted residual, recorded as TM-R-PR1: the runner learns the password strength required of privileged accounts. Mitigation is the permission being held only by roles that already hold a naming-context read scope; no Tier-2 built-in role does (`ValidateRoles`). |

### 1.5 Delivery and freshness

Policy rows are ordinary report rows after the scope filter, so schedule delivery to external
recipients is already held by TM-D30 SX-1 and the run re-computes the scope at each run (the run records
the read-scope fingerprint). No new control is needed. A scope change between runs changes the next run's
rows, not an old result's.

### 1.6 Tests that must exist (extends RP15)

1. Naming-context root with an OU exclude: a PSO whose only target group is in the excluded OU is absent,
   PR-3's notice is present, and no response field (row, header, count, export, audit detail) contains
   its name, precedence or values. Run as a table over API, export CSV/XLSX and the stored result.
2. Same PSO with one target in scope: present, "Applies to" lists only the in-scope target.
3. PSO with no targets: present for a head-in-scope runner.
4. OU-subtree and OU-one-level runner, and a token narrowed to an OU: notice only, nothing else.
5. Two domains, head readable for one: no name or count of the other domain anywhere.
6. Mutation: change the PR-2 predicate to "head in scope only" and test 1 must fail.

## 2. The `ReadReplicationStatus` right

### 2.1 Verdict

**It is not covered by the general directory-read scope; it needs its own two gates, both already
half-decided, and one of them is still `[UNVERIFIED]`.** Nothing new is invented here; this review
confirms TM-D31/R14 and closes the RBAC half.

| Layer | Gate | Status |
| --- | --- | --- |
| Directory (connection account) | Control access right **Monitor Active Directory Replication** (DS-Replication-Monitor-Topology) on each partition head the report covers; optional, off by default, typed ACE through the security-descriptor builder, never Get-Changes/Get-Changes-All, never an Administrators or Domain Admins membership (TM-D31 rules 2 and 3, R14) | Decided. Location of `msDS-Repl*` and sufficiency of the right are **`[UNVERIFIED]`**: T-1510 was inconclusive on a one-DC lab and T-1742 is the positive control. TM-D31 rule 3 stays armed: if the lab needs more than Monitor-Topology, SYS-03 ships fallback-only and the question returns to security-architect. |
| activeDIQ RBAC (runner) | A permission distinct from `reports.run`, `[PROPOSED]` name **`reports.replication.read`**, held at a scope that includes the **head of each partition reported** (the same head rule as §1) | Named here for T-1512 (TM-D31 rule 5 left the name open). Not in any Tier-2 built-in role. Not step-up: it reads topology, not secrets. |

### 2.2 Reasoning against the precedent

- **Why not just "directory read".** The right is not in the read-everything set the connection account
  already holds. `msDS-Repl*` discloses which DC replicates from which, partner DNS names and the DC's own
  error text: reconnaissance, no secret and no directory content (TM-D31 rule 2). Reconnaissance value is
  why it is optional on the directory side. The same reasoning requires a distinct RBAC permission, so a
  role that may run inventory reports does not see DC topology by default.
- **Why Monitor-Topology and nothing wider** is TM-D31's reading of
  [MS-ADTS 3.1.1.3.2.28](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b4a0b2bf-95f9-40b4-9301-834ccadea40c);
  it stays `[UNVERIFIED]` until T-1742. Do not widen on a lab failure; return to this role.
- **Tier-0 angle.** The objects described are domain controllers. Topology reads are not narrowed by
  Tier-0 (DM-35.I5) and a read is not a write, so the permission needs no Tier-0 scope root; it needs the
  partition-head scope so that a runner who cannot see the domain cannot see its DCs' replication.
- **Fail mode when the right is absent is fixed, not a choice:** TM-D31 rule 4 ("Not reported", coverage
  "0 of N", never Healthy).

### 2.3 Finding PR-F2 (medium): the built `PERMISSION_DENIED` outcome must not claim what AD cannot say

T-1510 measured that a no-right read returns an **attribute-less entry, not an error**. So a DC cannot
tell the connector "denied"; absent attribute equals "denied or empty". Connector-contract §5.6 rule 6
says a refusal is `PERMISSION_DENIED` per DC. On `factory/T-1723` (`replstatus/handler.go`, `stateOf`)
`PERMISSION_DENIED` is set only when the read layer reports `Denied`. Required: that flag may be set only
on an explicit LDAP `insufficientAccessRights` result; an attribute-less entry is `NOT_RETURNED`, and the
report may say "No inbound partners reported" only when the onboarding DACL check (TM-D31 rule 2) says
the right is granted. Test: attribute-less entry for each of the four attributes with the right
unverified yields `NOT_RETURNED`, and SYS-03 prints "Not reported", not "healthy" (TM-F-RIGHTS (c), (d)).
Owner: reporting-engineer (T-1512) for the report half, directory-engineer for the flag.

## 3. Does the closed `ReplicationAttribute` enum bound the exposure?

**For which attributes: yes, correctly.** Four values, no `;binary` (not representable in the request),
no `repsFrom`/`repsTo` (static check RX6 on T-1723 forbids the strings in non-test Go), no outbound
neighbours or queue statistics, no LDAP control. I read the T-1723 diff for these: the allow-list test
(`TestReadReplicationStatus_no_repsFrom`) and the wire-name check match the contract.

**What the enum does not bound, and what must also hold:**

| # | Gap | Required |
| --- | --- | --- |
| E1 | **Which entry is read.** The enum names attributes, not the object. | The read is a base-scope read of the answering DC's **rootDSE** only, never a caller-supplied DN; the request carries no DN or host (`partitions` are GUIDs, rule 1). Test: the connector refuses to issue any other base DN for these attributes. |
| E2 | **Which DCs.** | DC list comes from `InventoryHost`/`Describe` (TM-D10), never from the request; 100-DC cap before any read (rule 5). Already in the contract; keep CC-REPL test. |
| E3 | **DC-controlled text.** `last_result_text`, `source_dns_host`, `partition_display_dn` are written by a possibly compromised DC (TM-X3). | Safe decoder only (§5.7), size bounds (8 MiB per DC per call is on T-1723), escape on output (FF-SP4), never in logs. Already specified; the report must not link or resolve `source_dns_host`. |
| E4 | **Who sees the result.** The enum bounds the call, not the viewer. | §2.1 permission and partition-head scope; results not stored (D14); every run, export and audit event as reports-2a §8.6. |
| E5 | **Caller allow-list.** A future module could call the RPC for another purpose. | Same pattern as TM-F-RIGHTS (b): a grep-level and contract test that the only non-test caller of `ReadReplicationStatus` is the reports run path. |

Per-object `msDS-ReplAttributeMetaData` (§5.7, D10) is a different path: an ordinary `Read` of an
in-scope object under that object's scope, no extra right. No change.

## 4. Follow-up tickets (acceptance criterion 4)

The ticket named "T-1518's successor" and T-1878. T-1518 was cancelled for T-1723 (built, done, and
cannot take new scope); **T-1878 is an unrelated sync ticket** (display attributes marked unreadable) and
is not the policy-row owner. The real owners are used instead:

| Finding | Ticket | Owner |
| --- | --- | --- |
| PR-F1, PR-1 to PR-5, tests 1-6 | T-1902: policy-row rows for SYS-01 must apply PR-2/PR-3 (extends RP15) | reporting-engineer (builds `inventory.policies`, T-1114/T-1746) |
| PR-F2, §2.1 permission name, E1-E5 | T-1903 (built RPC), plus a note on T-1512: `PERMISSION_DENIED` only on an explicit refusal, rootDSE-only read, caller allow-list, `reports.replication.read` | directory-engineer (flag, E1, E5), reporting-engineer T-1512 (permission) |
| Spec wording for PR-3/PR-4 | T-1904: reports-2 §7.1 rule 6 gains the hidden-PSO notice and the precedence rule | product-manager |

## 5. Residual risks

- **TM-R-PR1** (PR-5): privileged-account password strength is visible to a naming-context reader. Accepted.
- **TM-R-PR2:** the right and location of `msDS-Repl*` are `[UNVERIFIED]` until T-1742; SYS-03 live read
  stays off by default until then.
- Compliance mapping is not part of this review; the ticket did not ask for one.

---
title: "Spec: Lingering-object detection (DsReplicaVerifyObjects, advisory mode) for the Lingering Objects report"
date: 2026-11-04
updated: 2026-11-04
status: draft
owner: heramb
author: ad-expert
ticket: T-1121
epic: E-002
milestone: M2a
parity: [ADM-092]
scope: proposed
sources_last_checked: 2026-11-04
---

# Lingering-object detection (advisory mode)

**Conclusion.** Detection is possible only through the DRS call `DsReplicaVerifyObjects` with
`ulOptions = 1` (advisory), run **against the DC that may hold the lingering objects**, with a
writable DC of the same partition as the reference. The call returns nothing useful: the findings
are written as **events in the target DC's Directory Service log**, so detection is "make the call,
then read that DC's event log". Neither half is LDAP, so the report needs a Windows-side helper
(§5). The access check for the call is **`DS-Replication-Manage-Topology` on the partition head**,
the same check as the destructive mode, so "read-only" is a property of **our client** (the option
is a constant, deletion unreachable), not of the right. That right is Tier-0, which is why this
spec asks `security-architect` for a ruling (§9) before any build. Deleting stays a 2b Action (§8).
Nothing here is verified on Windows or Samba yet; the lab rows are in §10.

Supersedes the "Out" row for Lingering Objects in
[reports-2-second-slice §2, §7.3, §8](reports-2-second-slice.md) (follow-up F2).

## 1. What a lingering object is (so the report says it right)

An object that was deleted on the other DCs, whose tombstone has been garbage-collected there, but
which still exists as a live object on a DC that did not replicate the deletion within the
tombstone lifetime (typically a DC that was offline or isolated longer than that).
`DsReplicaVerifyObjects` "verifies the existence of objects in an NC replica by comparing against a
replica of the same NC on a reference DC"
([MS-DRSR 4.1.24](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/022f186b-1b1c-434f-899f-c9170f787b56)).
Precisely, per that spec: an object "exists" if it is a live object **or a tombstone**; S' is the
target's objects that were also known to the reference (computed with the up-to-dateness vectors,
so objects recently created on the target are excluded); for each object in S' absent from the
reference, the server expunges it (`ulOptions = 0`) or logs an administrator-visible event
(`ulOptions = 1`). So a finding means exactly: **"present on target, absent (not even a tombstone)
on this reference"**, which is a property of a *pair of DCs*, not of the object alone.

Consequences the report must respect:

- **Pair-scoped.** Every finding names target DC, reference DC and partition. "No lingering
  objects found" is never forest-wide; it is "none found on target T against reference R in
  partition P at time t".
- **Transient false positives.** Garbage collection runs every 12 hours by default per DC, so for up
  to ~12 hours an object past its tombstone lifetime is already gone from one DC and still a
  tombstone on another; the tool reports it and "no action is required"
  ([Lingering Object Liquidator](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/lingering-object-liquidator-tool)).
  A finding is therefore **"candidate"** until a second run at least 12 hours later still finds it
  (`[PROPOSED]`: the UI offers "Re-check now" and shows "seen in N consecutive runs").
- **Reference quality.** The reference must hold a **writable** replica of the partition (an RODC is
  not a valid reference; the LoL tool documents errors 1396 and 8440 for RODC / non-writable
  references). A reference that itself holds lingering objects hides them from this pair, which is
  why Microsoft's tools clean the reference first and the full method is pairwise (n × (n−1)).
- **Partial replicas.** `FullReplicaExists(nc) or PartialGCReplicaExists(nc)` is the target
  precondition in the spec, so a GC's partial replica of another domain's partition can be a target;
  the reference must be a writable DC of that domain.
- **Other lingering things this does not find:** lingering *links* (attribute values), abandoned
  objects not discoverable by the call (LoL docs), and AD LDS (unsupported by the LoL tool; out of
  our scope anyway).

## 2. The call (what the helper does, exactly)

| Item | Value | Source / status |
| --- | --- | --- |
| API | `DsReplicaVerifyObjectsW(hDS, NameContext, pUuidDsaSrc, ulOptions)`; wire method `IDL_DRSReplicaVerifyObjects` (drsuapi) | [ntdsapi](https://learn.microsoft.com/en-us/windows/win32/api/ntdsapi/nf-ntdsapi-dsreplicaverifyobjectsa), [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/022f186b-1b1c-434f-899f-c9170f787b56) |
| `hDS` | `DsBind` to the **target** DC (the DC being checked; "the server running IDL_DRSReplicaVerifyObjects") | MS-DRSR |
| `NameContext` | DN of the partition (domain, Configuration, Schema, application partitions) | MS-DRSR (`pNC`) |
| `pUuidDsaSrc` | `objectGUID` of the **reference DC's `nTDSDSA` object** (under `CN=Sites,CN=Configuration`), *not* the computer object GUID | MS-DRSR: "select one object o from subtree ConfigNC() where o!objectGUID = uuidDsaSrc and nTDSDSA in o!objectClass" |
| `ulOptions` | **`DS_EXIST_ADVISORY_MODE` (1) always.** Value 0 expunges. | MS-DRSR; ntdsapi |
| Errors the spec names | `ERROR_DS_DRA_INVALID_PARAMETER` (bad version, null NC, null or unknown source DSA), `ERROR_DS_DRA_BAD_NC` (target holds no replica), `ERROR_DS_DRA_ACCESS_DENIED` (8453), and any error from fetching the reference's up-to-date vector (reference unreachable) | MS-DRSR; LoL doc for 8453 |
| Output | **None in the return value.** Success (0) means "processed", not "none found". Findings are events on the target DC (§4). | MS-DRSR ("log an administrator-visible event") |
| Duration | Scales with partition size and links; LoL documents n×(n−1) comparisons taking "possibly even days" in large forests; cancelling the client "doesn't actually stop the server-side API" | [LoL](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/lingering-object-liquidator-tool) |
| Same call as | `repadmin /removelingeringobjects <DC> <ref-DSA-GUID> <NC> /advisory_mode`; the LoL tool and `repldiag /advisorymode` | [LoL](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/lingering-object-liquidator-tool), [ReplDiag](https://learn.microsoft.com/en-us/archive/blogs/robertbo/cleaning-lingering-objects-across-the-forest-with-repldiag-exe-part-2-of-4) |

`[UNVERIFIED]`: whether the call blocks until completion on Windows Server 2016 to 2025 or can
return early (the pseudo-code is synchronous; the LoL doc implies a long server-side run). The
helper must treat "returned 0" and "events complete" as separate facts (§4).

## 3. Rights

| Need | Right | Notes |
| --- | --- | --- |
| The call | **`DS-Replication-Manage-Topology`** control access right on the **partition head** of every partition checked, on the target DC's view (`AccessCheckCAR(nc, DS-Replication-Manage-Topology)`, else `ERROR_DS_DRA_ACCESS_DENIED`) | MS-DRSR. Held by default by Domain Admins, Enterprise Admins and Administrators at the relevant heads `[UNVERIFIED]` (the default DACLs are to be read in the lab). The LoL doc says the tool needs Domain Admin per domain (Enterprise Admin forest-wide); it states what the tool needs, not the minimum right. |
| Reading the findings | Remote read of the target DC's **Directory Service** event log | Needs "Remote Event Log Management (RPC)" firewall rule on the DC (LoL doc). Account membership of **Event Log Readers** on the DC suffices for non-Security logs `[UNVERIFIED]` for the Directory Service channel; `[LAB: Windows]`. |
| Finding reference and target DCs, partitions | Default Authenticated Users LDAP read of `CN=Configuration` / `nTDSDSA` / `crossRef` | Already granted to the default connection account. |

Key points for the engineer and for the review:

1. **The right is not read-only.** The same right authorises `ulOptions = 0` (expunge) and
   topology changes (replica add/delete/modify use the same right per MS-DRSR's DRS methods
   `[UNVERIFIED]` for each). This **contradicts reports-2a §9 "no new directory right"** and the
   spirit of read-only reports. A dedicated, delegated group holding only this CAR on the
   partition heads is the least privilege that works, and it must still be treated as Tier-0
   (it can delete directory objects on a DC with a different client).
2. **Not the default connection account.** The detection credential is separate from the
   report-read credential, optional, off by default, and named in Connection. Verifying the right
   without starting a scan is an open lab question (§10 L3): the spec's order of checks is
   parameters, then NC, then access, then reference lookup, so a null source GUID returns
   `INVALID_PARAMETER` **before** the access check and proves nothing; reading the CAR from the
   partition head's DACL is the candidate probe `[UNVERIFIED]`.
3. **Never Domain Admin by default.** A report engine holding a Domain Admin credential is a
   Tier-0 compromise path; the spec asks for the delegated group (§9 Q1).

## 4. Reading the result: events 1938, 1942, 1946

Events are written by the NTDS Replication source in the **Directory Service** log on the target DC
(on AD LDS the instance log). What is documented and what is not:

| Event | Meaning | Status |
| --- | --- | --- |
| 1938 | Marks the **start** of the verification (logged by the DC when the advisory run begins) | Microsoft blog evidence ([ReplDiag part 2](https://learn.microsoft.com/en-us/archive/blogs/robertbo/cleaning-lingering-objects-across-the-forest-with-repldiag-exe-part-2-of-4): "Event ID 1938 and 1942 were logged" in an advisory run). Exact text `[UNVERIFIED]` |
| 1946 | **One event per lingering object found** in advisory mode (the LoL tool "collects lingering object event ID 1946 and displays objects") | [LoL](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/lingering-object-liquidator-tool), [Ask DS example](https://learn.microsoft.com/en-us/archive/blogs/askds/using-repadmin-with-adlds-and-lingering-objects). The fields (object DN or GUID, source DC, partition) are `[UNVERIFIED]` pending a Windows capture |
| 1942 | **Completion** of the run for that partition/source, with a count (also logged with count zero) | Secondary sources only (Microsoft KB 948071 as summarised by the search; Linda Taylor / Liquidator posts). `[UNVERIFIED]`: exact text and whether it carries the count |
| 1945 | An object was **removed** (delete mode). Seeing it means somebody ran the destructive call; the report must surface it as an alert, not as a finding | Ask DS blog above |
| 1937 / 1939 | Start / completion of a **removal** run `[UNVERIFIED]` (1939 documented as "zero removed") | secondary |
| 1988 | Replication **blocked** by strict consistency: the source offered an object the destination does not have (the classic lingering-object symptom) | [KB 870695](https://support.microsoft.com/kb/870695), cited by Ask DS; use as corroboration only |
| 2042 | The DC has not replicated within the tombstone lifetime; replication disabled | Ask DS blog above |

Reading rules (the "false pass" prevention):

- **Bracket the window.** Record `t_start` (before the call) and `t_end` (after). Read events on the
  target with `TimeCreated` in the window, provider NTDS Replication, IDs 1938/1942/1946/1945.
  Event queries use structured XPath/`EvtQuery` with typed parameters, never string-built filters.
- **A run is "Complete" only if** the call returned 0, a 1938 start and a 1942 end are both in the
  window for that partition and the same source, **and** the count of 1946 events equals the count
  stated by 1942 (if 1942 carries one, `[UNVERIFIED]`). Otherwise the pair is **"Incomplete"**,
  never "None found".
- **Log rollover.** The Directory Service log can overwrite events (ReplDiag post: large numbers of
  cleaned objects "will over run the Directory Service logs"). If the earliest event in the log is
  newer than `t_start`, or the log reports the window was overwritten, the pair is "Incomplete:
  event log rolled over". Recommendation to show: raise the log size before scanning (a
  customer action, not ours).
- **Attribution.** Another admin or tool may run the same call on the same target. Match events to
  our run by partition and reference-DC GUID inside the event text `[UNVERIFIED]` and by window;
  events in our window that do not match are shown as "other activity", not mixed in.
- **Cannot read the log** (firewall, right): "Not reported: event log unreadable (reason)". The
  call must **not** have been made if the log is known unreadable (probe first, §6).

## 5. Where it runs (the platform constraint)

Our servers and the standard connector read over LDAP; `linux-oci` has no `ntdsapi`. The spec
fixes the semantics and leaves the topology to `solution-architect`, with this recommendation:

1. **A Windows helper on a member server, not on a DC** (component owner `windows-engineer`;
   transport via the existing fleet tunnel). It calls `ntdsapi!DsReplicaVerifyObjectsW` and reads
   the remote event log; it exposes only "advisory verify (target, reference, partition) → events"
   to the server. Rationale: a crash or a defect in code on a DC can take down a domain
   (CLAUDE role description), and nothing here needs on-DC execution.
2. Implementing the DRS RPC (DsBind with signing and sealing) natively on `linux-oci` is possible
   in principle but is Tier-0 protocol code with no documented safety net; not recommended for v1
   `[PROPOSED]`.
3. **The destructive path is not compiled in.** The helper's only entry point passes the constant
   `DS_EXIST_ADVISORY_MODE`; there is no parameter, no flag, no code path for 0. A CI check
   asserts the call site's literal and a test with a fake `ntdsapi` asserts the argument. This is
   the "what is read-only" answer: the helper cannot delete, whatever rights its account holds.

## 6. Scan model

- **Admin-initiated, never silently scheduled.** A scan is a named job with a confirmation that
  states: partitions, target/reference pairs, estimated load, duration unknown, writes events to
  the DC logs. Scheduling is allowed only after a first manual scan, and off-hours.
- **Pre-flight (no scan until all pass):** target and reference answer; reference is writable for
  the partition (`nTDSDSA` / `msDS-hasMasterNCs`); target holds the partition (`msDS-HasDomainNCs`
  / `hasPartialReplicaNCs`); event log readable on the target; right present (§10 L3). Failing a
  check yields "Not run: reason", row per pair.
- **Pair selection.** Default `[PROPOSED]`: per partition, one chosen writable reference
  (preferring a DC known healthy by SYS-03), every other holder as target, plus the reference
  against a second writable DC. Full pairwise is an opt-in "Thorough" mode with a displayed cost
  (n × (n−1) per partition). The report states which mode produced each row.
- **One concurrent call per target DC**, a hard cap on concurrent targets (default 1, `[PROPOSED]`),
  a timeout per pair that marks the pair "Incomplete: still running on the DC" (the server-side
  work may continue after the client gives up).
- **Not stored beyond the run record.** Results are per-run facts (pair, time, object GUID and DN,
  event IDs), retained per the report retention policy; object DNs can be sensitive (disclosure as
  SYS-03/USR-06).

## 7. What the report shows

Columns: Partition, Target DC, Reference DC, Status, Objects found, Object (DN, objectGUID,
objectClass if the event carries it), First seen, Seen in N runs, Scan started, Scan ended, Events
read (IDs and counts), Detail.

Status vocabulary (closed set; an admin can disprove each in ADUC/repadmin):

| Status | Condition |
| --- | --- |
| **Found (n)** | call returned 0, run Complete (§4), n ≥ 1. Wording: "present on target, absent on reference" and the transient caveat. This is genuine detection; the word "detected" is allowed **only here**. |
| **None found** | Complete and n = 0, with the pair, time and mode in the cell: "on T against R in P at t" |
| **Incomplete** | any rule in §4 failed (rollover, missing 1942, count mismatch, timeout) |
| **Not run** | pre-flight failed (reason) |
| **Not reported** | right missing, log unreadable, platform (Samba) unsupported |

SYS-03's "Lingering-object risk" indicator remains as specified (never "detected") and links to
this report when a scan exists for the DC. The two must not be merged: the indicator is a
tombstone-lifetime heuristic from replication age, the finding is evidence.

Each finding row carries "What it means / what to do" (E-S3 style): read the 1946 detail, confirm
on the reference with `repadmin /showobjmeta` / a GUID search, re-check after 12 hours, and that
removal is a separate Action (§8). Wording is mine; remedy text cites
[Microsoft's lingering-object guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/lingering-object-liquidator-tool).

## 8. What is read-only, and what is not

**Read-only (guaranteed by our client):** no directory data is changed by the call in advisory mode
(MS-DRSR: the only action is "log a message"). We make no LDAP write. We never pass option 0. We
never invoke `removeLingeringObject`
([MS-ADTS 3.1.1.3.3.15](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/5d8570a6-cb92-4e37-ad0d-6d32cd2cdc0d))
or any DRS method other than this one. The helper's account has no write right on any object other
than what `DS-Replication-Manage-Topology` implies (§3.1).

**Not free of side effects (say so in the confirmation text):** the call loads the target and the
reference (reads the partition and fetches an up-to-date vector), and **writes events to the target
DC's log** (volume proportional to findings), which can roll the log. That is a DC-side write to the
event log, not to the directory.

**Out of this spec (2b Action):** deleting. When specified it will be per object via the
`removeLingeringObject` primitive (the LoL tool logs the full attribute set first so a hydrate is
possible), with a preview, a re-verification of absence on the reference immediately before, an
approval, and an audit entry carrying the stored attributes. The bulk `ulOptions = 0` path is
**rejected** for activeDIQ (it expunges every finding on the target with no preview) `[PROPOSED]`.

## 9. Request to `security-architect` (Tier-0 review)

Please review and rule on, before any build ticket is filed:

1. **Credential and right.** Is a dedicated delegated group holding only
   `DS-Replication-Manage-Topology` on the partition heads acceptable, given the right permits
   destructive and topology calls by other clients? Alternatives: require operator-supplied
   Domain Admin credentials per scan, never stored (ephemeral, via the helper). Conflict with
   reports-2a §9 and T-1125 needs an explicit ruling.
2. **Where it runs.** Member-server Windows helper (recommended) vs on-DC agent vs native RPC on the
   server. Trust boundary: the helper holds the Tier-0-adjacent credential.
3. **Read-only enforcement.** Is a constant argument plus a CI literal check and a fake-ntdsapi test
   enough, or is a signed-code or separate-binary assurance needed?
4. **Event-log read.** Remote Event Log Management firewall opening on DCs, and the log
   disclosure (DNs of deleted-elsewhere objects).
5. **Audit.** Every scan, with initiator, target, reference, partition, option = advisory, and
   outcome, in our audit; alert on any 1945 event seen on a DC (somebody else deleting).
6. **Threat-model entries** for the helper and the credential (threat-model §6 rows to add).

Review request: T-1564 (security-architect).

## 10. Platform matrix and lab rows

| Platform | Status |
| --- | --- |
| Windows Server 2016 to 2025 DCs (ADR-0002) | The API is documented for Windows Server 2008 and later ([ntdsapi](https://learn.microsoft.com/en-us/windows/win32/api/ntdsapi/nf-ntdsapi-dsreplicaverifyobjectsa)); 2016 to 2025 behaviour, event text and the right `[UNVERIFIED]`, `[LAB: Windows]` |
| RODC as target | LoL says it removes from RODCs; ReplDiag (2010) says RODCs not yet. Advisory behaviour on an RODC `[UNVERIFIED]`, `[LAB: Windows]` |
| RODC as reference | Not valid (not writable) |
| Entra ID | n/a, no equivalent |
| AD LDS | Out of scope |
| Samba AD (CI lab) | **No support assumed.** Whether Samba implements `DsReplicaVerifyObjects` is `[UNVERIFIED]`, and it has no Windows event log: **a Samba test cannot prove detection, and an unsupported-call error must produce "Not reported", never "None found"** (a stub returning success with no events would otherwise read as a clean pass) |
| `windows` / `linux-oci` server profiles | Same behaviour via the Windows helper over the tunnel; without a helper the report states "Requires the Windows helper" |

`[LAB: Windows]` rows for `devops-engineer` / `test-engineer` (need a Windows forest with a DC that
has a deliberate lingering object: stop a DC past tombstone lifetime with a shortened
`tombstoneLifetime`, delete an object elsewhere, force-garbage-collect, bring it back with strict
replication off):

- **L1** Capture 1938/1942/1946 text, fields and whether 1942 has the count; zero-finding run emits 1942.
- **L2** Does the call block to completion; what happens to events if the client disconnects.
- **L3** Minimum right: a user with only the delegated CAR succeeds in advisory mode; without it gets 8453; also confirm what the same account can do with `ulOptions = 0` and topology calls. An access-denied probe must be proven not to start a scan.
- **L4** Event Log Readers sufficiency for the Directory Service channel remotely.
- **L5** Log rollover behaviour and the incompleteness signals.
- **L6** RODC target; GC partial-replica target.
- **L7** The 12-hour transient window (an object just past TSL).
- **L8** Samba: call result and absence of events.

## 11. Acceptance criteria (for the build spec to inherit)

1. Given a target and reference with a seeded lingering object, When the scan completes, Then the
   report shows "Found (1)" with the object's DN and GUID, pair and time, and an admin can confirm it
   with `repadmin /removelingeringobjects ... /advisory_mode` showing the same 1946 event.
2. Given a clean pair, Then "None found" names the pair, partition and time; no cell says
   "no lingering objects" without the pair.
3. Given the Directory Service log rolled over during the scan, or a 1942 is missing, Then the pair
   is "Incomplete" and not "None found".
4. Given the right is missing, Then the pair is "Not run/Not reported" with the reason and no
   scan started.
5. Given a code path that tries to pass option 0, Then CI fails (literal check) and the helper
   has no way to receive it from the server.
6. Given Samba, Then the report says "Not reported: unsupported on this directory", never "None found".
7. Given a 1945 event on any scanned DC, Then an alert states that a removal was run, by event time.
8. Every scan is recorded in the audit trail with option = advisory.

## 12. Follow-ups (proposed; not filed here)

- Security-architect review and threat-model rows (§9) — filed as a review ticket.
- Solution-architect: helper topology and component contract (after the ruling).
- Windows-engineer: helper build. Directory-engineer: event decoder (typed, bounded) and pre-flight reads.
- Reporting-engineer: report definition and statuses (§7).
- Test-engineer / devops-engineer: `[LAB: Windows]` rows L1 to L8.
- Product-manager: the 2b Action for removal and the update of reports-2-second-slice §8 once this is accepted.

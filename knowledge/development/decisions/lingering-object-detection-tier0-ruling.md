---
title: "TM-D35: Tier-0 ruling for lingering-object detection: credential, Windows helper, read-only enforcement, event-log read, audit"
date: 2026-11-13
updated: 2026-11-13
status: review
owner: heramb
author: security-architect
kind: security
ticket: T-1892
reviews: T-1121 (spec `knowledge/product/specs/lingering-objects-detection.md` §9)
fitness: TM-F-LINGER (L1 to L8 below; `status` moves to `accepted` when L1 to L4 run in CI)
---

# TM-D35: lingering-object detection is allowed, as an optional feature with its own identity, host and binary

**Ruling in one paragraph.** The build may proceed under these constraints. The scan runs from a
dedicated **Windows verify helper** (its own signed binary, on a hardened member server that is not
the activeDIQ server and not a DC), under a **dedicated gMSA** that is **not** the connection
account. That gMSA holds `DS-Replication-Manage-Topology` on the partition heads, **customer-applied,
never written by activeDIQ**, plus a narrow read of the Directory Service log. Ephemeral
Domain-Admin credentials are **rejected**. "Read-only" is a property of our code and is claimed as
exactly that: the right itself can expunge objects and change topology, so a compromise of the
helper host is a Tier-0 loss, and the docs, the UI and the sales material must say so. Every scan
is audited before the call is made; a removal event (1945) on any DC we read raises an alert.
The threat-model rows are in [threat-model.md](../architecture/threat-model.md) §5.20 (TM-TB20),
§6.3 R16 and TM-R29.

Evidence base: spec §2 to §9 (cited there from [MS-DRSR 4.1.24](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/022f186b-1b1c-434f-899f-c9170f787b56)
and the [Lingering Object Liquidator doc](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/lingering-object-liquidator-tool));
threat-model §6.2 (TM-D1: never Domain Admin), §6.3 R14 and TM-D31 (T-1125), TM-D34 (T-1643),
§9.4 (credentials exist only where used), TB6, TB12. Nothing below was run on a Windows forest;
every Windows behaviour is `[UNVERIFIED — LAB: Windows]` and carried as a lab case (L1 to L8).
ManageEngine's record is why we do not take the shortcut: see
[manageengine-ad-customer-voice-and-security.md](../../business/market-research/manageengine-ad-customer-voice-and-security.md)
(customers' security teams review a Tier-0 tool for exactly this kind of standing, over-broad credential).

## Ruling 1: credential and right

**Dedicated delegated gMSA holding only the one right: accepted, with eight conditions.
Ephemeral operator-supplied Domain Admin: rejected.**

Why not ephemeral Domain Admin: it moves a full Tier-0 credential through a browser session, the
management-plane server and the tunnel, typed by a person who is not meant to hold it in our RBAC.
That is TM-D1 (never Domain Admin, TM-O1) broken per scan, it defeats our own per-feature RBAC and
step-up, it trains operators to paste Domain Admin passwords into a web form (the phishing pattern
ME's record shows), and it holds far more than the one right the call needs. The delegated identity
holds the one right and nothing else; its worst case is bounded by `DS-Replication-Manage-Topology`
(expunge and topology calls), which is strictly less than Domain Admin.

Why the delegated right is still not "safe": the same right authorises the destructive option and
topology changes by *any* client holding the identity (spec §3.1; MS-DRSR). Therefore:

1. **Own identity.** A gMSA created for the helper (`PrincipalsAllowedToRetrieveManagedPassword` =
   the helper host's computer account only). It is **never** the connection account, never the
   gMSA of the server or a remote connector. Otherwise a compromise of the connector (TM-D34) would
   inherit topology rights it never needed.
2. **Customer-applied.** activeDIQ never writes the ACE (it holds no `WriteDACL` on heads, TM-D1).
   We publish the documented delegation steps. Verification is a typed read of the head's DACL
   (typed ACE structures, [safe-primitives-security-descriptor.md](../architecture/safe-primitives-security-descriptor.md)),
   GUID resolved from the forest's `rightsGuid` at run time, never hard-coded (same rule as R14).
3. **Scoped.** The ACE is on the head of each partition the customer chooses to scan, and the
   trustee is the dedicated group holding only the helper gMSA. Membership of Administrators,
   Domain Admins or Enterprise Admins to get the right is a reject (as R14).
4. **Optional, off by default.** No other report needs it. The default connection account never
   holds it. Without it the report row is "Not reported: detection right not delegated", never
   "None found".
5. **Own RBAC permission and step-up.** A distinct permission (proposed `reports.lingering_scan.run`,
   held by no default help-desk role) and step-up re-authentication to start a scan (§7.4). Viewing
   findings is a separate permission from running.
6. **The identity and its group are Tier-0 to us.** The helper gMSA, its group, and its host computer
   account join the TM-D34 refusal set (basis C20): no activeDIQ write kind may reset, disable,
   re-key, change membership of, or move them. The group is added to the §6.4 `tier0` set as a C19
   control point.
7. **Use only from the helper host.** Detective control (`[PROPOSED]`, via the audit collector once it
   exists): alert when the gMSA authenticates from any address other than the helper host (it
   should never log on interactively, and gets deny-logon-locally/RDP via GPO in the install guide).
8. **Kerberos only.** The helper's `DsBind` is Kerberos; NTLM is restricted outbound on the helper
   host. A server-supplied target that fails Kerberos is "Not run", never retried over NTLM
   (TM-TB20-T3).

**Conflicts, resolved.**
- *reports-2a §9 "no new directory right"*: stays true for every report **except** SYS-03 (R14,
  optional, T-1125 / A4 in reports-2-second-slice §9) **and now the Lingering Objects scan (R16,
  optional)**. Product-manager folds R16 into the A4 wording of reports-2a §9 (follow-up ticket below).
- *T-1125*: R14 is a topology-**read** right that is not in `tier0`. R16 is **write-capable**, so T-1125's
  pattern (dedicated group, optional, DACL-proven, fallback "Not reported") is reused but tightened:
  separate identity (R14 sits on the connection account; R16 must not), step-up, helper host
  outside the management plane. R14 and R16 are never interchangeable.
- *Spec §3.1 tension ("contradicts reports-2a §9")*: accepted as stated; the contradiction is the
  honest consequence of the API. The customer-facing text says "this scan needs a right that can
  also change replication topology; activeDIQ only ever issues the advisory call".

Residual: TM-R29 (helper host compromise = the identity's full right).

## Ruling 2: where it runs

**A Windows verify helper on a dedicated member server. Chosen.**

| Option | Ruling | Trust-boundary reason |
| --- | --- | --- |
| Member-server helper (`windows-engineer`, own signed binary, fleet-tunnel component kind) | **Chosen** | The Tier-0-adjacent credential exists only on one host that runs nothing else exposed. A crash cannot touch a DC. It follows TM-D8: the credential exists only where it is used and is never pushed over fleet. |
| On-DC agent | **Rejected** | The DC agent runs on every DC under a virtual service account (ADR-0006), i.e. the *computer account* would carry the right: every DC agent compromise becomes a topology/expunge right on the whole partition. It also puts new code in a process whose crash can take down a DC (role charter), against TB12's minimal-surface rule. |
| Native DRS RPC on the server (`linux-oci`) | **Rejected for v1** | The credential would live in the management-plane process that faces browsers and the internet edge (TM-O1 requires that compromise does not yield Tier 0). It also needs our own sealed DRS client, which is Tier-0 protocol code with no safety net (spec §5.2). |

Constraints on the helper:

1. **Host.** Dedicated, hardened, Tier-0-adjacent, in the customer's Tier-0/Tier-1 admin model. It
   may share a host with a remote connector (same tier). It is **never** co-hosted with the
   activeDIQ server, the edge, the self-service portal or any internet-facing component. On the
   single-box `windows` profile the feature therefore reads "Requires a separate helper host" (a
   consequence for solution-architect, not a CEO question).
2. **Own binary, own service, own contract.** Not a module of the DC agent, the connector or the
   server. A new fleet component kind with its own mTLS identity and enrolment (TB6 rules apply);
   enrolment on the host, no secret pushed (TM-D8).
3. **Narrow wire contract.** One call: `AdvisoryVerify(target_dsa_guid, reference_dsa_guid,
   partition_dn)` returning typed result and bounded decoded events. **No options field**, no
   script or query verb, no raw event text. Contract lint in TM-F-FLEET.
4. **The helper re-validates server input.** It enumerates the forest's `nTDSDSA` and `crossRef`
   objects itself and refuses any target, reference or partition that is not in that set (a
   compromised server (X6) cannot point the credential at an attacker host, TM-TB20-T3), refuses an
   RODC reference, and refuses a pair it is not enabled for.
5. **No standing result store.** The helper keeps no findings on disk; its own log carries counts,
   IDs and error codes, never DNs.

## Ruling 3: read-only enforcement

**A constant argument plus a CI literal check plus a fake-`ntdsapi` test is necessary but not
sufficient. Required: all of them, plus a separate signed binary, an artifact-level check, and one
real-DC invariant test. The honest claim is "activeDIQ's helper cannot delete", never "the
account cannot delete".**

Why the three alone are not enough: a source-literal check proves only what the *source* says at one
call site. It misses a computed value, a second import or `GetProcAddress` by name, a different
`ntdsapi` function (`DsReplicaDel`, `DsReplicaAdd`, `DsReplicaModify`, `DsReplicaSync`), a change
in a linked library, and a mutated build. A fake `ntdsapi` proves what a test saw, not what the
shipped binary does. None of them constrains an attacker who obtains the gMSA and calls the API
from anywhere (that is TM-R29 and is not fixable in code).

Required controls (each is a TM-F-LINGER check):

1. **Constant, typed, single call site.** `DS_EXIST_ADVISORY_MODE` is a compile-time constant in one
   wrapper that is the only caller of the symbol. The wire contract carries no option. The wrapper
   cannot be reached by an argument from the server.
2. **Source check (L1).** An analyser (AST-level in the helper's language, not a regexp) fails the
   build if the symbol is called anywhere else, with a non-literal, or with any value other than 1.
3. **Artifact check (L2).** CI inspects the *built, signed* binary's import table and strings: the
   only `ntdsapi` imports are exactly `DsBindW`, `DsUnBindW`, `DsReplicaVerifyObjectsW`
   (and `DsFreeDomainControllerInfo` if needed, added by a ruling amendment, not by the build).
   `DsBindW` binds in the current security context, i.e. the helper's gMSA via Kerberos. `DsBindWithCredW`
   (and any `*WithCred*` or `DsBindWithSpn*` variant) is **not** allowed: it takes explicit credentials,
   which contradicts the no-credential-handling, gMSA/Kerberos-only stance (ruling 1, TM-TB20-T3). No `DsReplica*` other than that one, no
   `DsRemoveDsServer`, no dynamic `LoadLibrary`/`GetProcAddress` by non-literal name. An allowlist
   (exact entries), not a denylist.
4. **Fake-`ntdsapi` test (L3).** Asserts `ulOptions == 1` on every path, plus a **mutation test**: a
   build with the literal changed to 0 must fail L1 and L2 (proves the checks bite).
5. **Real-DC invariant (L4, lab).** Against a lab forest with a seeded lingering object, after a full
   scan the object is still present on the target and no 1945 or removal-start event exists in the
   log window. Also records the option actually sent (a shim in the lab build), covering the case
   where source and artifact checks agree but runtime differs.
6. **Runtime echo.** The helper returns the `ulOptions` it passed; the server records it and treats
   anything but 1 as a critical alert and aborts the scan series (`option_violation`). Belt and braces.
7. **Separate signed binary.** Signed by the release key like every Windows artifact
   ([release-signing-key-custody.md](../architecture/release-signing-key-custody.md)); separation is
   what makes L3's allowlist small enough to be meaningful. Signing is integrity, not behaviour
   assurance; we do not claim otherwise.
8. **No destructive code is ever added to this binary.** The future 2b removal Action (spec §8) is a
   different component, per-object `removeLingeringObject`, different identity, different review. A
   review rejects any diff adding a second `ulOptions` value to the helper.

Customer-facing wording rule: "the activeDIQ verify helper issues the advisory call only", never
"read-only account" or "cannot modify AD".

## Ruling 4: event-log read

1. **Firewall.** Reading the Directory Service log remotely needs the **Remote Event Log Management**
   inbound rules on each scanned DC, which are the NP-In, RPC and RPC-EPMAP rules
   ([SolarWinds ARM for DCs](https://documentation.solarwinds.com/en/Success_Center/ARM/Content/configure-the-windows-firewall-for-ad-logga.htm);
   [Veeam ONE rules](https://helpcenter.veeam.com/docs/one/userguide/firewall_rules.html);
   [Event Manager port mapping](https://hstechdocs.helpsystems.com/manuals/corects/eventmanager/current/gtthelp/content/resources/windows_audit_overview.htm);
   exact names and ports `[UNVERIFIED — LAB: Windows]` on 2016 to 2025). Rules:
   - We never change a DC firewall; the customer enables the rules (GPO), **scoped to the helper
     host's address only**, not "any", with the dynamic-RPC range left to the customer's policy.
   - NP-In (SMB 445 from the helper) is not required if RPC works; the guide enables the minimum
     that passes pre-flight and says so `[UNVERIFIED]`.
   - The pre-flight reads a harmless event query first. If the log is unreadable the scan is
     **not started** (spec §6), because the DC-side work cannot be undone or observed.
2. **Right to read.** Prefer a **per-channel** read grant for the helper gMSA on the Directory Service
   log only (channel access / log `CustomSD` by GPO). Membership of the domain-wide Event Log Readers
   group is the documented fallback only, because it exposes every non-Security log on every DC
   (L5 decides whether the narrow grant works remotely). Never the Security log, never clear or
   write rights (read query only; the helper cannot clear a log).
3. **Query is typed, narrow, bounded.** Provider NTDS Replication, an exact ID allowlist
   {1937, 1938, 1939, 1942, 1945, 1946} plus 1988 and 2042 for corroboration only, a `TimeCreated`
   window, a hard cap on event count and bytes per pair. Built by a structured XPath builder from
   integers and validated timestamps, never string concatenation (safe-primitives; TM-TB20-T6).
4. **Disclosure.** 1946 events name DNs of objects deleted elsewhere (spec §4). Therefore:
   - The helper decodes with a typed, length-bounded parser (DN, GUID, partition, DSA GUID) and
     returns **only decoded fields**, never raw message or XML. Oversize, malformed or unexpected
     fields drop the event and mark the pair "Incomplete: event could not be decoded".
   - Findings are stored as rows (ADR-0010) and treated as directory-derived data under TM-D32's
     amplification rules. Visibility follows the existing report scope: a scoped runner sees only
     findings whose DN parses under their OU scope; a DN that does not parse is hidden from scoped
     runners and shown only to domain-wide scope (fail closed).
   - DNs are **never** in audit entries, logs, metrics, notifications, alerts or SIEM exports unless
     the export itself is a report export under its own permission. Audit holds counts and a
     result reference.
   - Retention is the report retention policy; the helper retains nothing.
5. **Log integrity limits.** Anyone with admin on a DC can clear or forge the log. A cleared or
   rolled log is detected and yields "Incomplete" (spec §4); a forged 1942 with no real run is
   possible only to a DC admin and is outside our model (TM-R29 note). Events in our window that
   do not match our run are "other activity" and are never merged.

## Ruling 5: audit and alert

Every scan is an operation through the ADR-0005 pipeline, with the tamper-evident chain. **The start
record is written and durable before the call is made; if it cannot be written the call is not
made** (fail closed). Each pair writes two records: `lingering_scan.started` and
`lingering_scan.finished`; a pre-flight failure writes `finished` with outcome "Not run".

Required fields (all typed, none free text from the DC):

| Field | Content |
| --- | --- |
| Initiator | acting principal, session, step-up reference, trigger (manual, or the approval of a schedule) |
| Operation | operation ID, scan ID, pair index, mode (default or Thorough) |
| Helper | component ID, certificate serial, helper host name, helper binary version and signature hash |
| Target | DC FQDN and `nTDSDSA` GUID |
| Reference | DC FQDN and `nTDSDSA` GUID, writable flag |
| Partition | NC DN and kind (domain, Configuration, Schema, application) |
| Option | `ulOptions` **as echoed by the helper**, expected `1` (advisory); the server also records its own expected value |
| Time | `t_start`, `t_end`, per-pair timeout |
| Outcome | closed vocabulary (Found(n), None found, Incomplete(reason), Not run(reason), Not reported(reason)), Win32 return code, events read as (ID, count), count of 1946 events (no DNs) |
| Result reference | ID of the stored rows (so an auditor can join without the audit holding DNs) |

Crash handling: a `started` with no `finished` after the timeout is marked "outcome unknown" by a
reconciler and alerts. Audit is exportable like every other record (§11, TB15).

**1945 alert.** Any 1945 (object removed) event decoded on a DC we read (the scan window plus a
bounded look-back, `[PROPOSED]` 30 days, capped by log retention) raises a **high** alert to the
owner alert channel ([an8-owner-alert-channel-ruling.md](an8-owner-alert-channel-ruling.md)), not to the scan initiator,
not dismissible by the scan-runner role, deduplicated by (DC, record ID). The alert states DC, time,
partition and count only, no DNs. If it falls in a window where our helper echoed option 1, it still
fires, labelled "not from this scan, our helper passes the advisory option only" plus the echoed
value, so an auditor can separate our activity from someone else's. We only see DCs and windows we
read; the alert text says "seen on", never "none occurred". 1937 (removal run start) joins the alert
once L6 captures its text.

## Ruling 6: threat-model entries

Added to [threat-model.md](../architecture/threat-model.md) (this change): §5.20 TB20 (rows
TM-TB20-T1 to T14), §6.3 R16, TM-R29 in §16.1, changelog. Proof is TM-F-LINGER.

## Fitness functions (TM-F-LINGER)

| ID | Check | Where |
| --- | --- | --- |
| L1 | Single call site, literal 1, wrapper-only; any other value fails | CI, helper repo analyser |
| L2 | Built-artifact import allowlist and string check | CI on the signed artifact |
| L3 | Fake-`ntdsapi` test plus mutation build (literal 0 must fail L1/L2) | CI |
| L4 | Seeded lingering object survives a full scan; no 1945/1937 in window; shim records option 1 | Windows lab (T-1121 §10 L1/L3 rows) |
| L5 | Narrow per-channel log grant works remotely; unreadable log means no scan started | Windows lab (§10 L4) |
| L6 | Contract lint: no option field, no raw event text; server rejects `option != 1` echo | CI |
| L7 | Scoped runner never sees an out-of-scope or unparseable DN; no DN in audit/log/alert | CI |
| L8 | Audit start-before-call: audit write failure means no call; crash yields "outcome unknown" | CI |

`status` stays `review` until L1 to L3 and L6 to L8 run in CI (L4/L5 are lab-gated, as T-1121 §10).

## Constraints for the build tickets

Build tickets for the Lingering Objects report inherit rulings 1 to 5. Order: (1) solution-architect
helper component contract; (2) windows-engineer helper with L1 to L3 landing in the same change as the
call site; (3) directory-engineer typed event decoder and pre-flight; (4) backend-engineer audit and
alert wiring; (5) reporting-engineer report with the status vocabulary; (6) lab rows. Every one is
tagged `security-sensitive`. No ticket may add a destructive path, a Domain Admin option, or a
credential stored by the server.

## Follow-ups

- product-manager: add R16 to the A4 wording of reports-2a §9 and mark spec §9 answered.
- solution-architect: helper component contract (fleet kind, no option field, forest re-validation).
- test-engineer / devops-engineer: L4 and L5 lab cases; the L1 to L3 CI jobs.
- directory-engineer: a `tier0` change for the helper gMSA, its group and host (basis C20 extension).

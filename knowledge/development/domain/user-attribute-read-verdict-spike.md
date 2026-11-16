---
title: "Per-attribute read verdict for user sync (DACL read-evaluation): feasibility spike"
date: 2026-11-16
updated: 2026-11-16
status: draft
owner: heramb
author: ad-expert
ticket: T-2220
related: [T-2216, T-2219, T-1112, T-1731, T-1741, T-1566]
---

# Per-attribute read verdict for user sync (T-2220)

## Recommendation (conclusion first)

**GO, narrowly, as a generalisation of machinery that is already built.** The connector already proves readability of
`userParameters` by evaluating `sd.Grants` against the object's own DACL with the identity's full token set
(connector-contract §5.9.4). T-1731 (property-set tree) and T-1741 (token set) are `done`. The user-attribute verdict is
the same proof applied to the 11 user-attribute-report attributes. The new work is plumbing and a Windows lab gate, not
a new evaluator. Confidence: **medium**. The spec side is documented. The model-versus-DC agreement on Windows is
**not yet measured for these attributes** `[UNVERIFIED Windows]`.

Two rules keep it honest:

1. **A verdict is only needed when the attribute is absent.** A returned value proves readability, because the DC only
   returns what the caller may read ([MS-ADTS 3.1.1.4.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8271b44d-a755-4872-a762-1ac57152099d)).
2. **Only `not_observed` may mean "proven empty".** A report that says a user *lacks* a photo or logon script must
   filter on a *proven-readable and absent* verdict, never on "absent".

## 1. Why the wire cannot tell (sourced)

- A value the requester may not see "is treated as 'does not exist' in the returned attributes and the LDAP filter":
  the server answers as if the attribute were not on the object. No error, no marker
  ([MS-ADTS 3.1.1.4.3 Access Checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8271b44d-a755-4872-a762-1ac57152099d)).
  The same text applies to confidential attributes
  ([3.1.1.4.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/e6685d31-5d87-42d0-8a5f-e55d337f47cd)).
- The requirement is `RIGHT_DS_READ_PROPERTY` on **OA**, where OA is the attribute *or the property set containing it*,
  granted by the object's `nTSecurityDescriptor` (same page). So one ACE on a property set can hide several attributes.
- The feed is DirSync in object-security mode (§6.2), which returns only "objects and attributes that are otherwise
  accessible to the client" (connector-contract §6.2, citing MS-ADTS DirSync). A lost-access change is not reported as
  a clear `[UNVERIFIED Windows]` (§5.9.5).
- `allowedAttributes(Effective)` are write signals, not read signals ([3.1.1.4.5.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c16a23d1-6847-4b25-9f6b-f09fc29e8627)).
  There is no LDAP read-rights query. A DACL evaluation is the only per-attribute signal.

## 2. The evaluation (what the engineer builds)

Per user object, when one of the 11 attributes is absent from the entry:

1. Read `nTSecurityDescriptor` with the SD-flags control `0x4` (DACL only), plus `objectSid` and `objectClass`.
   The caller needs `READ_CONTROL` on the object. Authenticated Users hold it on a default user `[UNVERIFIED Windows]`.
   If the SD is not returned, the verdict is **unevaluable**, not denied.
2. Build the principal from the **T-1741 `TokenSet`** (objectSid + tokenGroups + implicit logon SIDs + `sIDHistory`),
   with `WithObjectSID(target)` so SELF ACEs apply. `tokenGroups` alone gives a false *No* or, worse, a false *Yes* when a
   deny sits on an implicit SID (connector-contract §5.9.4 "Whose token").
3. Ask `sd.Grants` for `READ_PROPERTY` on each absent attribute with the object-type tree **class → property set →
   attribute**, all three GUIDs from the schema snapshot (`schemaIDGUID`, `attributeSecurityGUID`), never hard-coded
   (T-1731). The rules for the tree are those of the DC's access check ([MS-DTYP 2.5.3.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4f1bbcbb-814a-4c70-a11e-2a5b8779a6f9)).
4. **Confidential attributes** (`searchFlags` bit 0x80, ignored for base-schema attributes) need `READ_PROPERTY` **and**
   `CONTROL_ACCESS` ([3.1.1.4.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/e6685d31-5d87-42d0-8a5f-e55d337f47cd)).
   The 11 are not confidential by default, but `msRTCSIP-UserEnabled` is a non-base-schema attribute and a customer can
   mark it. Read `searchFlags` from the snapshot. If 0x80 is set, ask both rights.
5. Map the answer, fail-closed, to the director's tri-state (T-2219):

| `sd.Grants` result and conditions | Marker | Meaning for a "without" report |
| --- | --- | --- |
| Value in the entry | `observed` | Has the attribute |
| Absent and `Yes`, not `Incomplete`/`Anomalous`, conditions below hold | `not_observed` | **Proven empty**: may be listed as lacking |
| Absent and `No` | `unknown_denied` (reason `denied`) | Never list as lacking |
| Absent and `Unknown`, `Incomplete`, `Anomalous`, no SD, unresolved GUID, or a condition fails | `unknown_denied` (reason `unevaluable`) | Never list as lacking |

   **Naming risk to hand to T-2216/T-2219:** `unknown_denied` covers "denied" *and* "could not prove". For the report
   the two behave the same (excluded from "without"), so one stored value is enough. Keep the reason in a diagnostic
   column or counter, so an admin who sees "unknown" can learn why.

   Conditions for `not_observed` (copied from §5.9.4 and unchanged): the binding identity is the `TokenSet`'s identity;
   the check is in the current verification epoch and clean; the target is in the `TokenSet`'s domain (a target in
   another domain has domain-local groups the set cannot know); `Complete`; the serving DC is writable (an RODC omits
   its filtered attribute set, so absence there is not proof).

6. **Built-in oracle.** When `sd.Grants` says `No` for an attribute that **is** present in the entry, the model is wrong
   (or the SD changed between reads). Count it as `model_divergence`, treat the verdict as `unknown_denied`, and alert
   on any non-zero rate. This gives the product a continuous production check of the evaluator that no lab gives.

## 3. Point-in-time: when a verdict goes stale

A verdict is a fact about one SD, one token and one schema at read time. It is invalidated by:

| Change | Detectable how | Action |
| --- | --- | --- |
| The object's SD changes (including inherited ACE propagation from an OU change) | The SD is a replicated attribute: it bumps `uSNChanged` and DirSync returns it **if requested** `[UNVERIFIED Windows: object-security DirSync returns an SD-only change]` | Re-read the object (SD + 11 attributes) and recompute |
| The sync identity's token changes (group membership, `sIDHistory`) | `TokenSet.Epoch` changes (T-1741) | Mark every verdict of the old epoch `stale`; recompute on next read or by a bounded background pass. Until then the report must not use them as proof |
| Schema change to `attributeSecurityGUID`, `searchFlags` or the class | Schema snapshot version | Same as token change |
| Deny/allow ACE on an OU changes without the child rewrite yet replicated | Replication latency, per DC | Verdict is per serving DC; say so |

Store `verdict_epoch` (token epoch + schema version) with the markers. A report may use only markers whose epoch is
current. Otherwise it falls back to the existing caveat header `user_attribute_absent_or_unread`. This is what keeps
the number from being disproved in ADUC: ADUC reads as *the admin*, who may see more than the sync identity. The
report must say **"as read by the activeDIQ service identity"** next to the column. That wording is a spec change for T-1112.

## 4. Cost

| Item | Estimate | Basis |
| --- | --- | --- |
| Wire, initial sync | One SD (DACL only) per user, typically a few hundred bytes to a few KB. At 200k users, a few hundred MB | `[UNVERIFIED]` estimate, measure on the T-0065 200k fixture |
| Wire, incremental | Only changed users. SD bytes only for changed or newly absent-attribute users | Request the SD only for users with at least one of the 11 attributes absent. Users with all 11 present need none |
| CPU | `sd.Grants` is a linear ACE walk. Microseconds per ask | Fine |
| Storage | One marker per attribute (3-state), plus `verdict_epoch`. **Do not store the SD.** | Keeps `maxBag` and the T-2018 flood in mind: adding bag keys writes `edited` history rows on resync |
| The bulk path | `ScopedSearch` does not return `nTSecurityDescriptor` in bulk (`constructedReadOnly`, §5.9.4). Either allow it for this one use or use per-user `Read` (one base read per user, the same order as T-1019/T-1566) | Design choice for the build ticket. Reuse the T-1566 single base read for both |
| Build size | M. Plumbing, snapshot lookups, markers, epoch, divergence counter, lab gate | Evaluator itself exists |

**Worth it?** Yes, because the alternative is a "without" report that lists every user the identity cannot read, which
is exactly the wrong number an admin disproves in thirty seconds. In most estates the answer will be "all readable", so the
verdict mostly **confirms** the report. It matters in the minority of estates with property-set denies or blocked
inheritance, which is exactly where a trust-destroying number comes from.

**Not worth doing:** a domain-wide "assume readable" preflight. Per-object denies and blocked inheritance exist; a
preflight on the NC root misses them.

## 5. Samba versus Windows verification plan

| Check | Samba | Windows | Pass condition |
| --- | --- | --- | --- |
| Evaluator agrees with the DC's own read (differential): for a non-admin identity and users with (a) default DACL, (b) per-object deny on one attribute, (c) OU-inherited property-set deny, (d) blocked inheritance, (e) deny on an implicit SID (Authenticated Users), (f) `sIDHistory` deny, (g) SELF ACE, (h) a confidential-flagged attribute | **Functional only.** Samba's `acl_read` module also drops unreadable attributes and requires control-access for confidential ones ([acl_read.c](https://sources.debian.org/src/samba/2%3A4.1.17%2Bdfsg-2/source4/dsdb/samdb/ldb_modules/acl_read.c), [Samba bug 13434](https://bugzilla.samba.org/show_bug.cgi?id=13434)), so the logic can be regression-tested | **Required, gating.** DC's answer = LDAP read as that identity | 100% agreement; any `Yes` where the DC omits the value is a failure; `Unknown` is allowed |
| `tokenGroups` plus implicit SIDs equals the DC's token | Not comparable. Samba's token build differs | Required | The implicit-SID deny (e) agrees |
| Default DACL gives Authenticated Users read of the 11 | **False-pass risk**: Samba's default user SD and property-set membership come from its own schema | Required: dump `schemaIDGUID`, `attributeSecurityGUID`, `searchFlags` of the 11 on a Windows DC and record in the note | Catalogue recorded, not assumed |
| Object-security DirSync returns an SD-only change; a lost-access change appears or not | Samba DirSync differs (Samba fixed its own bypass: [CVE-2023-4154](https://www.samba.org/samba/security/CVE-2023-4154.html)). Do not count | Required (already open in §5.9.5) | Result recorded either way. Either answer is usable: if no clear is reported, the SD change re-reads the object |
| `msRTCSIP-UserEnabled` | Not possible: Samba cannot add the Lync schema (T-1111 note) | Required, with the schema extension | Verdict `unevaluable` if the attribute is not in the snapshot |
| RODC serving the read | Not available | Required if RODCs are in scope | `unknown_denied`, never `not_observed` |

**Samba gives a false pass** for any claim about implicit logon SIDs, default SD, property-set membership, DirSync
behaviour or the Lync attribute. A green Samba run is evidence the *code* runs, not that the *model matches Windows*.
The T-1731 AC2 rule stands: Samba does not count as evidence for the agreement.

## 6. Risks

- **A wrong `Yes`** lists an unreadable user as lacking: the failure we are curing. Guards: `Unknown` fails closed, the
  divergence counter, the Windows differential gate.
- **Claims-based and conditional (callback) ACEs** evaluate to `Unknown`: safe, noisy in forests that use them.
- **Sync identity differs from the rights-check identity**: condition 1 forces `unevaluable`.
- **Different DCs, different answers** during replication: say "as read from DC X".
- **Security-sensitive**: the connector reads more of the SD (DACL only, never SACL). security-architect reviews; the SD
  is never stored or logged (DM-24.I3 identifiers-only).

## 7. Proposed build tickets (dependency order)

1. **Windows lab: catalogue and differential** (test-engineer + ad-expert). Dump the 11 attributes' GUIDs and flags;
   run the (a)-(h) differential on Windows. **Gate for 3 and 4.**
2. **Schema snapshot: serve `attributeSecurityGUID`, `schemaIDGUID`, `searchFlags` for the 11** (directory-engineer).
3. **Connector: user attribute verdict** (directory-engineer, security-sensitive): SD + token set + `sd.Grants`,
   `model_divergence` counter, SD requested only when an attribute is absent.
4. **Sync + store: write `not_observed` / `unknown_denied` + `verdict_epoch`; invalidate on epoch change** (directory-engineer).
5. **T-1112 AC2 amendment** (product-manager): "without" presets filter on `not_observed` in the current epoch; column
   label "as read by the activeDIQ service identity".

Tickets 1 to 3 are T-2221, T-2222, T-2223 (backlog; T-2223 depends on T-2221 and T-2222 in practice). 4 and 5 follow the Windows result.

## 8. Verification status

| Claim | Status |
| --- | --- |
| Denied attribute treated as non-existent, no error | Documented (MS-ADTS 3.1.1.4.3). Not re-measured here |
| Property-set GUID is the access target (OA) | Documented |
| Confidential attribute needs RP + CA | Documented |
| Evaluator agrees with the DC for the 11 attributes | `[UNVERIFIED Windows]` (ticket 1) |
| Authenticated Users hold READ_CONTROL on a default user | `[UNVERIFIED Windows]` |
| Object-security DirSync returns an SD-only change | `[UNVERIFIED Windows]` |
| SD size and wire cost | `[UNVERIFIED]` estimate |
| Samba `acl_read` omits unreadable attributes | Documented in source/bug (secondary), not lab-run here |

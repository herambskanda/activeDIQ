---
title: "AD change notifications (LDAP_SERVER_NOTIFICATION_OID) and deleted objects"
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
author: ad-expert
ticket: T-0018
---

# AD change notifications and deleted objects

**Conclusion.** On Windows Server AD, a change-notification search **does** notify when an object in
scope is deleted, and the client does **not** need the Show Deleted control for that. The
ad-engineering skill said the opposite and was wrong; the feasibility doc had the right behaviour
but attributed it to MS-ADTS, which is silent on deletes (the statement is in the Win32 page).
Reading the deleted object afterwards still needs Show Deleted. Samba is expected to behave
differently, so a Samba test cannot confirm this. Both documents are now corrected to this note.

## What the sources say

| # | Claim | Source | Status |
| --- | --- | --- | --- |
| 1 | "If an object within the search scope is deleted, the client receives a change notification and the `isDeleted` attribute of the object is set to TRUE. … the search results report the new distinguished name of the object in the Deleted Objects container … It is not necessary to specify the tombstone control (`LDAP_SERVER_SHOW_DELETED_OID`) to get notifications of object deletions." | [Win32: Change Notifications in AD DS](https://learn.microsoft.com/en-us/windows/win32/ad/change-notifications-in-active-directory-domain-services) | doc only |
| 2 | Base scope: a notification fires when any attribute changes, or the object is deleted or moved. One-level scope: when a child is created, deleted, moved or modified. | same | doc only |
| 3 | Moving or renaming an object **above** the target does not notify, even though the target's DN changed. Monitoring a container's children gives nothing if the container itself is moved or renamed. | same | doc only |
| 4 | The server returns the attributes the client requested on the original search, "not necessarily the attributes that were modified". Notifications fire on a change to any attribute. | [MS-ADTS LDAP_SERVER_NOTIFICATION_OID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f14f3610-ee22-4d07-8a24-1bf1466cba5f); Win32 page | doc only |
| 5 | Only filter allowed: `(objectclass=*)`, else `unwillingToPerform`. Scopes base, one-level and subtree are permitted; Windows Server 2003 and later have no NC-root restriction on subtree. | MS-ADTS (same page) | doc only |
| 6 | Win32 guidance contradicts #5: do not use subtree; it is only supported when the base is an NC root, "its use can severely impact server performance", and subtree on "an arbitrary subtree" cannot be specified. | Win32 page | doc only, **conflict with #5** |
| 7 | Limit: `MaxNotificationPerConn`, **default 5** outstanding notification searches per connection, set through `lDAPAdminLimits`; the 6th gets `adminLimitExceeded` / `ERROR_DS_ADMIN_LIMIT_EXCEEDED`. | [MS-ADTS LDAP Policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99) | doc only |
| 8 | Notifications end on disconnect or abandon. The client must re-register, then re-read current state. Register **first**, then read initial state. `uSNChanged` is used to detect a restored replica (server value lower than the client's). | Win32 page | doc only |
| 9 | Timeliness depends on replication latency; designed for "reasonably prompt notification of infrequent changes"; heavy use hurts the server. Polling is recommended when immediacy is not needed. | [Overview of Change Tracking Techniques](https://learn.microsoft.com/en-us/windows/win32/ad/overview-of-change-tracking-techniques) | doc only |
| 10 | A deleted object keeps few attributes; it is only visible to searches that carry the tombstone / Show Deleted control (`isDeleted=TRUE` filter, objectGUID search works). | [Retrieving Deleted Objects](https://learn.microsoft.com/en-us/windows/win32/ad/retrieving-deleted-objects) | doc only |

Nothing here is verified on a Windows DC. The Win32 page is dated 2018 and carries no Windows
Server version table.

## Semantics for connector design

1. **A notification is a hint, never a record.** It carries no cookie, nothing is replayed after a
   disconnect, and it only reports changes that reached *that* DC. Delete detection is authoritative
   only through DirSync with Show Deleted, or `uSNChanged` polling with Show Deleted (feasibility doc,
   change-tracking rows). Use notifications, if at all, to trigger an early incremental run.
2. **On a delete notification**, key on `objectGUID` (request it), never on the DN: the DN in the
   result is the new `CN=<name>\0ADEL:<guid>,CN=Deleted Objects,…` form. Request `isDeleted` to
   tell a delete from a modify. Do not read the object back without Show Deleted. Treat a returned
   entry whose requested attributes are missing as a tombstone, and fall back to DirSync/USN.
3. **A move out of scope** may not be reported to a one-level or base watcher the way a delete is.
   Docs only say "deleted or moved" for base scope and "moved" for children `[LAB: Windows]` (T1/T3
   below). Never treat the absence of a notification as the absence of a change.
4. **Scope.** Register base or one-level scopes. Subtree is allowed by MS-ADTS but discouraged by
   Win32; if used it must be on an NC root `[LAB: Windows]` (T4).
5. **Budget.** Assume at most 5 registrations per connection (default, tunable by the customer,
   so read `lDAPAdminLimits` / handle `adminLimitExceeded`). One connection per DC per NC at most.
6. Pin one DC per NC for the connection; a notification on DC A says nothing about DC B.

## Samba (the CI lab) does not match Windows here

Read from source, not run `[LAB: Samba]`:

- Samba implements the control in an LDB module that **polls**: each retry re-runs the search with
  `uSNChanged >= (last known USN + 1)`
  ([dsdb_notification.c](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/dsdb_notification.c)).
  Retries are driven by the LDAP server, which also enforces `MaxNotificationPerConn`
  ([ldap_backend.c](https://github.com/samba-team/samba/blob/master/source4/ldap_server/ldap_backend.c)).
- Samba's `show_deleted` module hides objects with `isDeleted` unless the Show Deleted control is
  present ([show_deleted.c](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/show_deleted.c)).
  Because the notification search does not carry that control, **our reading is that Samba will
  not deliver delete notifications**. Unverified until T5 runs.
- Samba's filter check accepts presence filters on `objectClass`, `objectGUID`, `distinguishedName`
  and `name`, not only `(objectClass=*)`. Its source comment says Windows accepts these too, while
  MS-ADTS lists only `(objectclass=*)` `[UNVERIFIED]`.
- Consequence: a notification-based delete test on Samba would **fail where Windows passes** (a
  false failure) and a Samba pass would say nothing about Windows. Delete detection in CI must
  therefore go through DirSync / USN with Show Deleted, which Samba does implement.
  Whether Samba also supports DirSync's full behaviour is a separate matter (see ad-lab runbook §5).

## [LAB] test procedures

Use a throwaway OU `OU=T0018` and a script holding a notification search open with
`(objectClass=*)`, requesting `objectGUID, isDeleted, distinguishedName, uSNChanged`, no other
controls. Record every returned entry with timestamps. Run each on **Samba (lab)** and on
**Windows Server** (T-0051); record the DC build.

| ID | Procedure | Expected on Windows (from docs) | Samba prediction |
| --- | --- | --- | --- |
| T1 | Base-scope watch on user U. Move U to a sibling OU, then back. | notification on each move | `[UNVERIFIED]` |
| T2 | One-level watch on `OU=T0018`. Create U, modify `description`, delete U (Recycle Bin off, then on). | 3 notifications; the delete entry has `isDeleted=TRUE` and a DN under `CN=Deleted Objects`; **no Show Deleted control sent** | no delete notification |
| T3 | One-level watch on `OU=T0018`. Move U out of the OU to a sibling; move another user in. | records whether the move out is reported (docs say "moved") | `[UNVERIFIED]` |
| T4 | Subtree watch (a) on the domain NC root, (b) on `OU=T0018`, (c) on the root with filter `(objectGUID=*)`. | (a) works; (b) per MS-ADTS works, per Win32 should fail; (c) `unwillingToPerform` per MS-ADTS, or accepted (see Samba comment) | (c) accepted |
| T5 | Samba only: repeat T2 with Show Deleted added to the notification search. | n/a | tells us if delete notifications are reachable at all |
| T6 | Open 6 notification searches on one connection. | 6th fails `adminLimitExceeded`; then set `MaxNotificationPerConn` through `lDAPAdminLimits` and retest | 6th fails |
| T7 | Rename and move the parent OU of a watched object. | no notification for the child | `[UNVERIFIED]` |
| T8 | Kill the connection, delete U, reconnect, register, then read. | the delete is missed by notifications and found by DirSync + Show Deleted | same |

T2 and T5 are the load-bearing ones. For each, note the attributes actually present on the delete
notification (are `objectGUID` and `isDeleted` there?).

## Open points

- `[LAB: Windows]` T1–T4, T6, T7: contradictions and gaps between MS-ADTS and the Win32 page.
- `[LAB: Samba]` T2, T5: delete delivery on the lab. If the prediction holds, `lab/` gets a documented
  "Samba does not notify deletes" limit in the ad-lab runbook.
- Not checked: Entra ID has no equivalent; Graph change notifications (webhooks) are a separate
  mechanism and are out of scope here.

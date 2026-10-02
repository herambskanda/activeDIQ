---
name: ad-engineering
description: AD/Entra engineering playbook — LDAP paging, ranged reads, syntaxes, password/unlock/membership writes, change tracking, Graph, connector security, mandatory safe filter/DN builders. Use for any code or spec that talks to a directory.
---

# AD engineering

Our customers' admins know AD better than most vendors. One wrong number — a "locked" user who
is not, an "inactive" user who logged in yesterday — and they stop trusting every screen. This
skill is how directory code is written here. Feasibility research:
`knowledge/development/architecture/build-feasibility/ad-technical-feasibility.md` (draft).
Stack specifics (Go, `go-ldap`, package paths) are **provisional until ADR-0001**.

Supporting files — read the one you need:
- `reference/attributes.md` — key attributes: syntax, replicated or not, GC, how to read and write.
- `reference/uac-flags.md` — `userAccountControl` and the computed flags.
- `reference/gotchas.md` — the traps, numbered. **Read it before any directory ticket.**

Unsure how AD *behaves*? Ask `ad-expert` (consult subagent) before coding a guess.

## 1. Safe primitives — mandatory, no exceptions (CLAUDE.md rule 5)

Never build an LDAP filter, a DN, or an encoded attribute value with string formatting or
concatenation. PatchIQ died partly of `Sprintf`-built security strings
(`../UEM/knowledge/development/legacy/patchiq-postmortem.md` §11 #1, #10). Here the unsafe thing
must be **unrepresentable**: the connector API accepts typed values only.

| Primitive (path: blueprint §1.1) | Does | Rule |
| --- | --- | --- |
| `internal/directory/ldapfilter` | AST builder: `And/Or/Not/Eq/Present/Prefix/BitAnd/BitOr/InChain`; renders with RFC 4515 escaping (`*`→`\2a`, `(`→`\28`, `)`→`\29`, `\`→`\5c`, NUL→`\00`; binary values byte-wise `\xx`). Also a **parser** for admin-supplied LDAP filters (custom reports) → AST, rejected if invalid. | `Search` takes `ldapfilter.Filter`, never `string`. Delegation scope is AND-composed on the AST. |
| `internal/directory/dn` | Parse, build (`dn.Child(parent, "CN", value)`), escape RDN values per RFC 4514 (`, + " \ < > ;`, leading space or `#`, trailing space, NUL), normalise, compare. | Operations take `dn.DN`. Prefer `<GUID=…>` DNs to address existing objects. |
| `internal/directory/attr/{guid,sid,filetime,gentime,flags,unicodepwd}` | Typed codecs: `GUID`, `SID`, `FileTime`, `GeneralizedTime`, `UAC`, `GroupType`, `LargeInt`, `UnicodePwd` (a `Secret` from `internal/platform/secret`: never logged, never serialised). | Raw `[]byte`/`string` attribute access outside the codec package is a review blocker. |

- RFC 4514: https://www.rfc-editor.org/rfc/rfc4514 §2.4 · RFC 4515: https://www.rfc-editor.org/rfc/rfc4515 §3
- Only the connector root `internal/connector/` may import the raw LDAP library — enforced by a
  lint/import rule (fitness function FF-SP1). Scoped search and controls live in
  `internal/connector/ad/scope`, `SecureConn` in `internal/connector/ldap`; `dn` implements
  RFC 4514 itself and does not wrap go-ldap's `ParseDN` (blueprint §7.4). Every builder ships
  with fuzz tests over hostile input (`*)(uid=*`, `\`, NUL, `,CN=x`, leading `#`, 64+ chars,
  non-BMP Unicode).
- Missing a primitive? Stop and file a `security-sensitive` build ticket for it. Never inline one.

## 2. Reading

- **Always paged** — paged results control (RFC 2696, OID `1.2.840.113556.1.4.319`), page size
  1000 (AD `MaxPageSize` default). An unpaged search silently stops at 1000 with
  `sizeLimitExceeded`. The cookie is bound to the connection: never resume a page on another
  connection or DC. https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil
- **Ranged retrieval** for big multi-valued attributes (`member`, `memberOf` on huge users,
  `msDS-*` link lists): beyond `MaxValRange` (1500) AD returns `member;range=0-1499` and **no**
  `member` attribute. Loop `member;range=1500-*` until the range ends in `*`.
  https://learn.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval
- **Ask for exactly the attributes you need.** Never `*` in production code — it misses
  constructed and operational attributes anyway, and costs DC CPU.
- Users are `(sAMAccountType=805306368)` — indexed and excludes computers, which are also
  `objectClass=user`. Matching rules: bit AND `1.2.840.113556.1.4.803`, OR `…804`, transitive
  chain `…1941` (expensive; avoid on large estates).
  https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
- **Identity is `objectGUID`.** DNs change on rename/move; SIDs change on cross-domain migration
  (old SID moves to `sIDHistory`). Store GUID; display DN; never key on DN or name.
- **Syntaxes** (details in `reference/attributes.md`): `objectGUID`/`objectSid` binary;
  FILETIME (100-ns ticks since 1601 UTC, Large Integer, sent as decimal string) vs Generalized
  Time (`whenCreated`); domain policy intervals (`maxPwdAge`, `lockoutDuration`) are **negative**
  FILETIME intervals. Convert to ISO 8601 UTC on the server — a FILETIME exceeds JS's 2^53.
- **Computed truth beats stored flags.** Locked out / password expired come from
  `msDS-User-Account-Control-Computed`; password expiry date from
  `msDS-UserPasswordExpiryTimeComputed` (honours fine-grained policies). Effective groups from
  `tokenGroups` (constructed, **base-scope searches only**, includes the primary group).
- **Last logon** — `lastLogon` is per-DC and not replicated; `lastLogonTimestamp` replicates but
  lags 9–14 days by design. "Inactive users" reports state which they used and the tolerance, or
  query `lastLogon` on every DC and take the max.
  https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp
- **Linked attributes**: `member` (forward) ↔ `memberOf` (back-link, read-only, excludes the
  primary group). `manager` ↔ `directReports`. Write the forward link only.
  https://learn.microsoft.com/en-us/windows/win32/ad/linked-attributes
- **Topology**: DC (389/636) holds one domain, all attributes, writable; GC (3268/3269) holds the
  forest but only the partial attribute set, and is read-only. Forest-wide search → GC, then read
  full attributes from a DC of the object's domain. **Do not chase referrals** automatically
  (credential leakage, latency); resolve the right DC from our topology map.
- **Multi-domain/forest**: one connection pool per domain, DC selection by site via DNS SRV
  (`_ldap._tcp.<site>._sites.dc._msdcs.<domain>`), failover on `unavailable`/`busy`. Cross-forest
  members appear as `CN=ForeignSecurityPrincipals` objects — resolve the SID in the other forest.
  Group nesting can cycle: always recurse with a visited set.

## 3. Writing

- LDAP modify is **atomic per entry**: all changes in one request apply or none do. Use
  `replace` for single-valued; `add`/`delete` specific values for multi-valued.
- **Optimistic concurrency** without ETags: `delete` the old value + `add` the new one in one
  modify. If someone changed it meanwhile, the delete fails with `noSuchAttribute` (16) — a
  compare-and-swap. Use it for edits made from a form the admin loaded earlier.
- **Password set (admin reset)**: `replace unicodePwd` with the password wrapped in double quotes,
  encoded **UTF-16LE**, over an encrypted connection (LDAPS/StartTLS). User change = `delete` old
  quoted value + `add` new one in one modify. Policy failures arrive as `constraintViolation` (19)
  or `unwillingToPerform` (53) with an extended code (`0000052D`) in the diagnostic message —
  map them to a clear "does not meet password policy" error. Admin resets skip password history
  unless you send the policy-hints control `1.2.840.113556.1.4.2239`.
  https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/set-user-password-with-ldifde
- **Must change at next logon**: `pwdLastSet = 0`. Clear it with `pwdLastSet = -1` (only 0 and −1
  are writable). **Unlock**: `lockoutTime = 0`. Target the **PDC emulator** for password and
  lockout writes so they take effect domain-wide at once.
- **Create user**: create disabled (`userAccountControl = 514`) → set password → enable (`512`),
  or include `unicodePwd` in the add over LDAPS. `sAMAccountName` ≤ 20 chars, `cn` ≤ 64.
- **Membership at scale**: add/delete many `member` values per modify (chunks of 500,
  provisional), with the permissive-modify control `1.2.840.113556.1.4.1413` so re-adding an
  existing member or removing an absent one is a no-op (makes retries idempotent). One bad value
  fails the whole chunk: bisect to find it and report per-member results.
- **Replication latency**: read-your-writes only from the DC you wrote to. A job pins one DC per
  domain for its lifetime.
- **Deletes**: objects with children need tree-delete `1.2.840.113556.1.4.805`; "protect from
  accidental deletion" is a deny ACE → `insufficientAccessRights` even for admins — say so.
- Every write is audited by our own audit trail (`security-baseline`), with before/after values
  and secrets redacted.

## 4. Change tracking

| Mechanism | Use for | Watch out |
| --- | --- | --- |
| **DirSync** control `1.2.840.113556.1.4.841` | Incremental sync of a naming context | Needs *Replicating Directory Changes* on the NC head (or the object-security flag, which returns only readable objects). Returns changed attributes only; use incremental-values for `member`. Cookie is per DC. https://learn.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-the-dirsync-control |
| **uSNChanged** polling | Sync with no special rights | USNs are per DC. Store `(DC, invocationId, highestCommittedUSN)`; a new invocationId (DC restore) or DC switch → full resync. https://learn.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-usnchanged |
| **Replication metadata** `msDS-ReplAttributeMetaData` / `msDS-ReplValueMetaData` | When and on which DC an attribute or link value last changed | It tells you *when* and *where*, never *who*. "Who" requires Security event logs (Windows-only, `windows-engineer`). https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-replattributemetadata |
| Change notification `1.2.840.113556.1.4.528` | Near-real-time hints | Filter `(objectclass=*)` only; base or one-level scope (no subtree). Default 5 per connection (`MaxNotificationPerConn`). **Deletes do notify, with no show-deleted needed** (`isDeleted=TRUE`, new DN under Deleted Objects), but reading the object afterwards does need it. Parent move or rename is silent. Not replayed after a disconnect. **Samba likely does not notify deletes** `[LAB]`. Hint only; reconcile with DirSync/USN. https://learn.microsoft.com/en-us/windows/win32/ad/change-notifications-in-active-directory-domain-services · https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f14f3610-ee22-4d07-8a24-1bf1466cba5f · full note: `knowledge/development/domain/ad-change-notifications.md` |

Deleted objects: show-deleted `1.2.840.113556.1.4.417` and read rights on `CN=Deleted Objects`
(needed to *search* for them, not to be notified of a delete).
With Recycle Bin on, deleted objects keep their attributes until `isRecycled`.

## 5. Microsoft Graph (Entra ID)

- **Least privilege**: application permissions with a **certificate** credential, never a client
  secret in config. Read: `User.Read.All`, `Group.Read.All` (+ `AuditLog.Read.All` for
  `signInActivity`, which needs Entra ID P1). Write only what the feature needs
  (`GroupMember.ReadWrite.All` before `Group.ReadWrite.All`); never `Directory.ReadWrite.All`
  without a security-architect sign-off. Check https://learn.microsoft.com/en-us/graph/permissions-reference
  before requesting any permission — it changes.
- **Throttling**: honour `429` + `Retry-After`; exponential backoff with jitter; a per-tenant
  concurrency cap. https://learn.microsoft.com/en-us/graph/throttling. `$batch` takes ≤ 20 requests.
- **Delta queries**: store the `@odata.deltaLink` per resource; follow `@odata.nextLink` to the
  end; on `410 Gone`/resync errors, full sync. Always `$select`.
  https://learn.microsoft.com/en-us/graph/delta-query-overview
- `$count`/`$search`/advanced filters need `ConsistencyLevel: eventual` + `$count=true`.
- Hybrid: synced users are mastered on-prem — write them via AD, not Graph; Graph rejects most
  writes to `onPremisesSyncEnabled` objects. Show the admin where the object is mastered.

## 6. Connector security (details: `security-baseline`)

- Transport: LDAPS (636) or StartTLS; **always verify certificates** (customer CA bundle
  supported; never skip-verify, not even "for the lab" in product code). Plain 389 only with
  Kerberos signing and sealing.
- Auth: **Kerberos (SASL/GSSAPI) preferred**; simple bind only over TLS. **Reject empty
  passwords before binding** — an empty-password simple bind is an *unauthenticated* bind that
  "succeeds" (RFC 4513 §5.1.2).
- Signing and channel binding: DCs increasingly require both (ADV190023:
  https://msrc.microsoft.com/update-guide/vulnerability/ADV190023). Test against a DC that
  enforces them; verify the LDAP library supports channel-binding tokens before ADR-0001 picks it.
- Service account: gMSA where the host is Windows (Linux hosts cannot consume a gMSA natively — an
  ADR-0001 input); least-privilege delegation on specific OUs; **never Domain Admins**. Protected
  accounts (`adminCount=1`) ignore OU delegation — AdminSDHolder resets their ACLs hourly.

## 7. Testing (details: `testing-playbook`)

Integration tests run against **Samba 4 AD DC in Docker**. Samba does **not** emulate: Security
event logs and audit policy, GPO client-side processing, ADWS (so the ActiveDirectory PowerShell
module), password filters and credential providers, Windows LAPS, AD FS, and Windows-specific
error-message text. Its replication metadata, channel binding and Recycle Bin behaviour differ
from Windows `[UNVERIFIED]` — confirm per feature. Anything in that list needs the Windows lab
(CEO-approved access), and the spec's platform matrix must say so.

## 8. Before you advance

- [ ] Every filter/DN/encoded value goes through §1 primitives; no raw LDAP import outside the connector.
- [ ] Paged; ranged where multi-valued; attribute list explicit; GUID used as identity.
- [ ] Read-after-write on the same DC; per-object results for bulk; retries idempotent.
- [ ] Every relevant gotcha in `reference/gotchas.md` checked; Samba gaps named in the ticket note.
- [ ] Integration test against the Samba lab passing, command and output excerpt in the note.

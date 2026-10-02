# AD and Entra gotchas

Each one has cost someone a wrong number or an outage. Format: **trap** — consequence — what to do.
Found a new one? Add it here in your ticket and a line to `knowledge/memory/lessons.md`.

## Reading

1. **`(objectClass=user)` matches computers** — user counts include machines — filter on
   `sAMAccountType=805306368` (indexed).
2. **Unpaged search stops at 1000** with `sizeLimitExceeded` (4) and partial results that look
   complete — always use the paged results control and treat code 4 as an error.
3. **Paging cookie is per connection** — resuming on a pooled or failed-over connection returns
   errors or restarts — hold one connection for a whole paged search.
4. **`member` over 1500 values comes back as `member;range=0-1499`** and the plain `member`
   attribute is absent — a 5,000-member group looks empty — implement ranged retrieval in the
   connector, test it with a 3,000-member lab group.
5. **`memberOf` omits the primary group** — "Domain Users" members look like they are in nothing
   — combine with `primaryGroupID`, or use `tokenGroups` for effective membership.
6. **`tokenGroups` only works in base-scope searches** — subtree searches return nothing for it —
   one base search per user; batch and cache.
7. **`memberOf` from a GC of another domain shows universal groups only** — wrong membership in
   multi-domain forests — read memberships from a DC of each group's domain.
8. **Nested groups can form cycles** — naive recursion never ends — recurse with a visited set and
   a depth cap; report cycles as a finding.
9. **`LDAP_MATCHING_RULE_IN_CHAIN` (…1941) is slow on large estates** — queries hit the DC's
   `MaxQueryDuration` (120 s) and time out — expand membership in our own store instead.
10. **GC returns only the partial attribute set** — attributes silently missing, not errors —
    know which attributes are in the PAS; read the rest from a DC.
11. **Referral chasing sends your bind credentials to whatever host the referral names** — disable
    chasing; route to DCs from our own topology map.
12. **Constructed attributes cannot be used in filters** (`msDS-User-Account-Control-Computed`,
    `tokenGroups`) — the filter matches nothing — filter on stored attributes, compute the rest.
13. **`*` does not return constructed or operational attributes** — computed lockout missing —
    request every attribute by name.
14. **Server-side sort control on large paged results is expensive and capped** — timeouts —
    sort in our store or the client.
15. **Schema-dependent attributes may not exist** (Exchange, LAPS) — `undefinedAttributeType`
    errors or empty columns — read the schema at connect; feature-flag on presence.

## Time and syntax

16. **`lastLogon` is per DC and not replicated** — "never logged on" for active users — take the
    max over all DCs, or use `lastLogonTimestamp` and state the lag.
17. **`lastLogonTimestamp` lags 9–14 days by design** — "inactive for 7 days" reports are wrong —
    never offer thresholds below 14 days on this attribute without a per-DC `lastLogon` sweep.
18. **`whenChanged` and `uSNChanged` are not replicated** — different values per DC — never
    compare them across DCs; sync watermarks are per `(DC, invocationId)`.
19. **`accountExpires` has two "never" values** (`0` and `0x7FFFFFFFFFFFFFFF`) — "expired in 1601"
    or "expires in 30828" — decode through the codec only.
20. **ADUC shows `accountExpires` as "end of" the previous day, in local time** — off-by-one-day
    disputes with admins — display the exact UTC instant and the local date, and say "end of".
21. **Domain policy intervals are negative FILETIME intervals** (`maxPwdAge`, `lockoutDuration`) —
    negative durations or "expired in the past" — use `attr.Interval`.
22. **FILETIME is larger than 2^53** — JavaScript rounds it — convert to ISO 8601 on the server.
23. **`groupType` is a signed 32-bit integer** — security groups appear negative — decode flags,
    never compare raw numbers.
24. **`objectGUID` string form is mixed-endian** — GUIDs that never match Microsoft tools — use the
    codec for both directions; test against a known GUID from the lab.
25. **DNs compare case-insensitively and have several escape forms** (`\,` vs `\2C`) — duplicate
    or missed objects — compare by GUID; if you must compare DNs, parse and normalise.

## Account state

26. **The LOCKOUT and PASSWORD_EXPIRED bits of `userAccountControl` are unreliable** — shows
    unlocked users as locked or vice versa — use `msDS-User-Account-Control-Computed`.
27. **Non-zero `lockoutTime` does not mean locked** — the value persists after the lockout
    duration expires — use the computed bit, or compare against `lockoutDuration`.
28. **`badPwdCount` is per DC** — counts disagree — read it from the PDC emulator.
29. **`adminCount=1` stays after a user leaves privileged groups** — "privileged user" reports
    overcount — derive privilege from current transitive membership; report stale `adminCount`
    separately.
30. **AdminSDHolder rewrites ACLs on protected accounts every 60 minutes** — delegated help-desk
    rights "stop working" on admins — expected; explain it in the UI rather than retrying.

## Writing

31. **Empty-password simple bind succeeds as an unauthenticated bind** (RFC 4513 §5.1.2) — an
    authentication bypass in "verify password" flows — reject empty passwords before any bind.
32. **Verifying a user's current password by binding increments `badPwdCount`** — the self-service
    portal can lock users out (a user-change modify with a wrong old password counts too
    `[UNVERIFIED]`) — rate-limit, count our own failures and stop below the domain lockout
    threshold, never verify the same password twice.
33. **`unicodePwd` must be quoted UTF-16LE over an encrypted connection** — `unwillingToPerform` (53)
    — use the `UnicodePwd` codec; LDAPS/StartTLS only.
34. **Password policy failures surface as 19 or 53 with `0000052D` in the diagnostic text** — a
    generic "operation failed" — map to "does not meet password policy" and list the domain or
    PSO requirements.
35. **Admin resets ignore password history** unless the policy-hints control (…2239) is sent —
    self-service resets allow reused passwords — send it for any end-user-initiated reset.
36. **`pwdLastSet` accepts only `0` and `-1`** — constraint violation — the codec exposes
    `MustChangeAtNextLogon(bool)`, not a timestamp setter.
37. **Re-adding an existing member fails the whole modify** (`attributeOrValueExists`, 20) — a
    bulk add stops at the first duplicate — permissive-modify control, chunked, with bisection.
38. **Replication latency: write on DC1, read on DC2 shows the old value** — "my change didn't
    save" — pin the DC for a job; read your writes from the same DC.
39. **Writes to an RODC or to an object in another domain return a referral** (10) — writes
    appear to fail — route writes to a writable DC of the object's domain.
40. **Protected-from-accidental-deletion objects deny delete and move to everyone** —
    `insufficientAccessRights` (50) for Domain Admins — detect the deny ACE and say so; never
    strip it silently.
41. **Deleting objects with children needs the tree-delete control** — `notAllowedOnNonLeaf` (66)
    on computers with BitLocker or Hyper-V children — use tree delete, after explicit confirmation.
42. **`modifyDN` cannot move objects across domains** — cross-domain moves need ADMT-style
    tooling — out of scope unless a spec says otherwise; block in the UI with a reason.
43. **Setting `userAccountControl` from a stale read undoes concurrent bit changes** — use
    compare-and-swap (`uac-flags.md`).

## Security, transport and topology

44. **Clock skew over 5 minutes breaks Kerberos binds** — "invalid credentials" that are valid —
    surface skew in connector health checks.
45. **TLS-terminating proxies break LDAP channel binding** — binds fail only at customers with
    enforcement on — connect directly to DCs; document it in deployment requirements.
46. **The paged search cookie, DirSync cookie and USN watermarks are DC-specific** — failover
    silently skips or replays changes — store the DC identity with every watermark; full resync
    on mismatch.

## Microsoft Graph

47. **Graph throttles per app and per tenant** — bursts of `429` — honour `Retry-After`, cap
    concurrency per tenant, batch (≤ 20).
48. **Delta tokens expire** — `410 Gone` — fall back to full sync automatically; never surface it
    as a failure to the admin.
49. **`signInActivity` needs `AuditLog.Read.All` and Entra ID P1** — empty last-sign-in columns on
    free tenants — detect licence and say "not available on this tenant", not "never".
50. **Directory-synced users are read-only in Graph** — writes rejected — write on-prem via AD and
    show where the object is mastered.

## Samba lab vs real AD

51. **Samba has no Security event log, no GPO client processing, no ADWS** — features "pass" in CI
    that cannot work there — Windows-only behaviour is verified in the Windows lab and named in
    the platform matrix.
52. **Samba error codes and diagnostic strings differ from Windows** — error mapping tested on
    Samba alone misfires at customers — keep a table of Windows diagnostics captured from the
    Windows lab and test the mapper against both.

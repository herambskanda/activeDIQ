---
title: "Connector contract v1: the read side (Describe, search, read, per-DC read, change feed)"
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
author: directory-engineer
ticket: T-0064
binding_sources: blueprint §7.1-7.2, safe-primitives §3.6-3.7, domain-model DM-13..DM-19, threat-model §6.3 R1/R2 and TM-TB3-*
---

# Connector contract v1: the read side

The source is `proto/activediq/connector/v1/`. This document is its long form: why each shape is as
it is, what every operation promises, how failures look, and which cases a provider must pass
(§9). If the two disagree the proto wins and this file is the bug. `make fitness-proto` compiles
the proto and enforces rules P1 to P7 (§2) on every merge.

**In scope:** `Describe`, `DescribeSchema`, `ScopedSearch`, `Read`, `ReadPerDC`, `ChangeFeed`, the
error and capability model, the provider conformance suite. **Reserved by name only:** `Apply`,
`ReadSecret`, `VerifyUser` (§8). **Out of scope:** write operations, named secret operations, the
fleet stream limits (TM-Q8), inventory tables and sync passes (T-0065), the Entra provider's
Graph mapping.

## 1. What this contract is for

The server (sync ingester, search, reports, Action Plans) and the connector meet here. One
`Connector` service, two transports (blueprint §7.2): in-process for the embedded connector, and
the connector-initiated mTLS stream for remote ones. The same messages cross both, and one
conformance suite runs against both (§9). A compromised server is in the threat model (TM-TB6-T4),
so **the connector never trusts a request**: it re-validates every filter node, attribute name and
limit under its own rules before touching a directory.

## 2. Rules every message obeys

| # | Rule | Why | Enforced by |
| --- | --- | --- | --- |
| 1 | No request carries a DN, a filter or a base as text. Objects are addressed by `Guid`; DNs in filters are the typed `Dn` (a list of RDNs); filters are the typed `Filter` AST. Response DNs are `display_dn`, display only | Safe primitives P1 and P2 (CLAUDE.md rule 5). The unsafe string is unrepresentable | `fitness-proto` P2 |
| 2 | No free-form query, script or command verb. Every operation is a typed RPC | ADR-0002 rule 3 | P2, P5 |
| 3 | No `google.protobuf.Any` in a request | An `Any` is a back door for an untyped payload | P3 |
| 4 | RPCs are unary or server-streaming. Never client or bidirectional streaming | Flow control, cancellation and resource release stay simple | P4 |
| 5 | Every RPC has an `OPERATION_<NAME>` value, so every operation has a capability entry in `Describe` | One place to ask "can this provider do it" | P5 |
| 6 | `Apply`, `ReadSecret` and `VerifyUser` exist as names in `Operation` and have no RPC | Reserved, shape later | P6 |
| 7 | No `string` or `bytes` field is named `password`, `unicode_pwd`, `credential` or `secret` | Secrets use the `Secret` type, never this contract | P7 |
| 8 | The tenant is never a field | ADR-0002: a remote connector's tenant comes from its certificate SAN; the embedded one runs inside the caller's `WithTenantTx` | P2 (`tenant`, `tenant_id`) |
| 9 | GUID bytes are in RFC 4122 network order, the order of the canonical string, never the LDAP wire order | One order on the contract, so no caller can get the mixed-endian mistake (gotcha 24) | CC-DATA-01 |
| 10 | A value the directory does not expose is unset or `UNKNOWN`, never `0` or `FALSE` | Samba omits facts Windows has; a default would turn a gap into an answer | CC-DESC-03 |
| 11 | A result is valid only if its stream ends with the completion event (`SearchCompleted`, `ReadCompleted`, a `PerDcSummary`, a `ChangeBatch` with `cycle_complete`) | A silently partial result is a wrong number (TM-TB3-T9) | CC-SRCH-10, CC-FEED-14 |
| 12 | Evolution is additive: field numbers are never reused, removed fields are `reserved`, new enum values are added at the end, `contract_minor` goes up. A caller treats an unknown `ErrorCode` as `PROVIDER_FAILURE` | Both transports, mixed versions during an update | review |

## 3. Layout

| File | Holds |
| --- | --- |
| `common.proto` | `Guid`, `Sid`, `ConnectionRef`, `DirectoryIdentity`, `DcIdentity`, `Observation`, `DcSelection`, `TimeValue`, `AttributeValue`, `Attribute`, `DirectoryEntry`, `ValueRange` |
| `filter.proto` | `Filter` AST, `FilterValue`, `Dn`, `Rdn` (the P1 and P2 wire forms) |
| `errors.proto` | `ConnectorError`, `ErrorCode`, `RetryAdvice`, `ResyncReason`, per-code details |
| `describe.proto` | `Operation`, `Feature`, `SupportState`, `DescribeRequest/Response`, `DescribeSchema*`, topology and health messages |
| `read.proto` | `ScopedSearch*`, `Read*`, `ReadPerDC*` |
| `changefeed.proto` | `ChangeFeedRequest`, `FeedCookie`, `ChangeBatch`, `ObjectChange` |
| `connector.proto` | the `Connector` service |

Go package `internal/proto/activediq/connector/v1` (`go_package`) is generated and never
hand-edited (blueprint §1). Code generation is a separate ticket (§10).

## 4. Describe and the capability model

`Describe(connection, refresh)` is the DM-13.I2 binding check: a connection binds to a connector
only if `Describe` reports a provider for the connection's kind. It returns:

- **`operations[]`**: one `OperationSupport` per `Operation` value with `SUPPORTED`,
  `UNSUPPORTED`, `UNVERIFIED` or `RESERVED`, and a reason. This is the capability flag of every
  read operation. `directory/client` checks it before it plans, and a call to an operation that is
  not `SUPPORTED` fails with `CAPABILITY_UNSUPPORTED`.
- **`features[]`**: finer flags with their **source** (`DECLARED` by the provider's code,
  `PROBED` from the directory, `ASSUMED` where the directory exposes nothing). `UNVERIFIED` means
  the provider declares it but it depends on a right or a DC behaviour that cannot be checked
  without a side effect. `FEED_DELETIONS` is always `UNVERIFIED` on AD (§6.5).
- **Topology (AD):** `naming_contexts[]` (DM-14), `forest_settings` (Recycle Bin, tombstone and
  deleted-object lifetime, read and never assumed; an absent attribute is unset and the caller
  applies the documented default, DM-10.I6), and `domain_controllers[]` (DM-15).
- **Per DC:** `dsa_guid` and `invocation_id` (read from the NTDS Settings object, found through
  rootDSE `dsServiceName`, because `invocationId` is not a rootDSE attribute), site, RODC, GC, PDC
  emulator (the `fSMORoleOwner` on the domain head, **cross-checked** against that DC's own
  `validFSMOs`, since a DC that has not replicated a role move reports the old owner),
  `highest_committed_usn` sampled with a DC clock reading, clock skew, the features this DC can
  serve, and `reachable` with the error. The list comes from the configuration NC's NTDS Settings
  objects, so DCs that are down or left over from an incomplete metadata cleanup appear with an
  error. Nothing is dropped silently.
- **`limits`**: `max_page_size`, `max_value_range` (the DC's MaxValRange, read from
  `lDAPAdminLimits`), `max_message_bytes` (provisional 1 MiB), the P1 filter limits, per-DC
  concurrency.
- **Health:** an overall state and per-check results (DC locator, TLS, bind, rootDSE, clock skew,
  schema, Graph token). The *delegated-rights check* of onboarding is T-0068's, not this contract's.

`DescribeSchema` streams the schema the server-side filter builder needs for its allowlist
(safe-primitives §3.3 rule 1): per attribute its syntax, value kind, single or multi, constructed,
indexed, in the GC, linked (with link id), `secret`, and the raw `searchFlags` and `systemFlags`.
`secret` is the connector's `SecretAttrs` (§3.7: schema flags `0x80`, `0x200`, `0x1000` plus the
static list minus the reviewed exemptions), so the server refuses early and the connector refuses
again. The fingerprint in `Describe` tells a caller when to re-fetch.

## 5. The read group

### 5.1 `ScopedSearch`

`ScopedSearchRequest{connection, roots[], depth, filter, attributes[], page_size, dc}`.

- **Base is the delegation root's `Guid`** (with the `nc_guid` of the domain that holds it). Scope
  is `SUBTREE` or `ONE_LEVEL` (the AD Explorer tree, ADM-004) and never reaches above the root.
  One search per root; results de-duplicated by object GUID (a set of 16-byte GUIDs, not a buffer
  of objects). A deleted root fails the call with `DELEGATION_ROOT_GONE`, with no fallback to a
  wider root (LF-31); a moved root works because the GUID follows the object.
- **Controls are not the caller's.** There are no control, sort, VLV or port fields. Slots 8 to 15
  are reserved so none can be added casually. The connector attaches only paged results (319),
  domain scope (1339, no continuation references), extended DN (529, response only) and, from
  T-0118, SD flags (801) (safe-primitives §3.6).
- **Filter** is required. The connector composes `And(scope, filter)`, so it only narrows, and
  re-validates the AST: schema allowlist, value kind against syntax, constructed attributes not
  filterable, no substring on DN syntax, no empty assertions, secret attributes refused,
  matching rules limited to 803, 804 and 1941, and the size and depth limits. Violations return
  `FILTER_REJECTED` with the P1 rule id (`rejected_input.rule_id`) and the request path, never the
  value.
- **Attributes** are explicit, one or more. `*` and `+` are `INVALID_ARGUMENT`. A secret
  attribute is `SECRET_ATTRIBUTE` (LF-37). Constructed attributes are readable only by `Read`
  (`tokenGroups` returns nothing in a subtree search, gotcha 6), so a search naming one gets
  `ATTRIBUTE_NOT_ALLOWED`.
- **Paging is the connector's.** It runs the paged control on one pinned connection and DC and
  streams entries in `SearchBatch` messages of at most `max_message_bytes`. gRPC flow control is the
  backpressure; cancelling the stream abandons the LDAP search and releases the DC resources
  (CC-SRCH-14). There is **no resume cursor**: an LDAP paging cookie belongs to its connection and
  DC (gotcha 3). The finest checkpoint is `RootCompleted`, so a caller splits large work into
  roots (for example one per top-level OU) and re-runs only the unfinished roots after a failure.
- **Referrals are never chased.** A continuation reference in any response fails the stream with
  `UNEXPECTED_REFERRAL` (count only, no URLs, LF-32) and no page is returned as complete.
  Connections to the Global Catalog are refused (`GLOBAL_CATALOG_NOT_ALLOWED`, LF-33).
- **No counts.** The contract has no total, estimate or `contentCount`. Per-object authorisation
  and the numbers users see are applied by `directory/client` on what the contract returns, so a
  DC-side count cannot reach a screen (LF-39). `[REVIEW → D1]`
- **Entries** carry the typed `DirectoryEntry`: `object_guid`, display DN, `parent_guid` and
  attributes decoded by the codecs (§5.4). A multi-valued attribute beyond one range returns the
  first range with `complete = false`; **a search never follows ranges** (it would turn one page
  into N reads). Completion is `Read`'s job.

### 5.2 Initial inventory and the reconcile pass

The connector offers one way to read a whole NC: `ScopedSearch` rooted at the NC head by a system
delegation, a few attributes (`objectGUID` only for the reconcile pass), paged and streamed. T-0065
owns when and how often. The contract's part is that this pass must be cheap and streamable at 200,000
objects (CC-SRCH-15) because it is also the only mechanism that notices what the feed cannot (§6.5).

### 5.3 `Read` and ranged attributes

`Read{connection, guid, nc_guid, attributes[], dc, max_values_per_attribute}` is a base read by
GUID. It is a server stream: a `ReadHeader` with the object and every attribute that fit one DC
response, then `ValueChunk` messages for each multi-valued attribute that was ranged
(`member;range=0-1499`, then `1500-*`, until the range ends in `*`), then `ReadCompleted`. A group
with 50,000 members is 34 chunks, never one 4 MiB message.

- The connector asks for ranges explicitly. **Samba returns all values of a >1,500-value attribute
  unranged on a plain read while Windows ranges it** (measured, ad-lab runbook §5), so a connector
  that forgets to range passes the lab and fails at a customer. CC-READ-01 asserts the explicit
  range request and the first range's size.
- Ranges arrive in order; values are as-of-read, not a snapshot. A membership change during the
  read can duplicate or skip a value. Exact membership comes from the feed.
- `max_values_per_attribute` caps what one call returns; a cut attribute is named in
  `ReadCompleted.truncated_attributes`. The connector has its own ceiling when the field is 0.
- Constructed attributes (`tokenGroups`, `msDS-User-Account-Control-Computed`,
  `msDS-UserPasswordExpiryTimeComputed`) are readable here and only here.
- `Read` of a GUID that does not exist, or was deleted, is `OBJECT_NOT_FOUND`. Show-deleted is not
  available on this contract (it belongs to a later named operation). An object the identity cannot
  read can be `INSUFFICIENT_RIGHTS` or `OBJECT_NOT_FOUND` depending on the DC; **callers must not
  show the difference to a user** (LF-36).
- `nTSecurityDescriptor` fails with `CAPABILITY_UNSUPPORTED` until T-0028 and T-0118 add its typed
  shape. Request slots 7 to 15 are reserved for the SD-flags selection.

### 5.4 Typed values

The connector's codecs (P3) decode, so no caller sees raw bytes of a known syntax.

| Source syntax | Contract form | Note |
| --- | --- | --- |
| `objectGUID`, Entra id | `Guid` (16 bytes, RFC 4122 order) | rule 9 |
| `objectSid`, `sIDHistory` | `Sid` (MS-DTYP binary) | text form is the codec's |
| Integer (2.5.5.9) | `int32_value` (signed) | `groupType` stays negative for security groups; `userAccountControl` flags decoded by `attr/flags` |
| Large Integer, not a time | `int64_value` | |
| FILETIME, Generalized Time | `TimeValue` | `ZERO` (0), `MAX` (`0x7FFF…`), a timestamp, or raw ticks past year 9999. `accountExpires` 0 and `MAX` are both "never" to the caller; `pwdLastSet` 0 is "must change" |
| DN syntax | `DnValue{display_dn, guid, sid}` | the GUID and SID come from the extended-DN control and are the identity of the target |
| Unknown syntax | `octets` | |

### 5.5 `ReadPerDC`

Attributes that are not replicated (`lastLogon`, `logonCount`, `badPwdCount`, `badPasswordTime`)
and `lockoutTime` (replicated but authoritative on the PDC emulator) are read from **every DC of the
object's domain** (exact last logon, ADM-084; DM-15.I1). The attribute set is a closed enum, so this
is no back door for arbitrary reads. The call streams one `PerDcResult` per DC (values or a typed
error, with `Observation`), then a `PerDcSummary{dcs_in_scope, dcs_answered, coverage}`.

- **Coverage is explicit.** `COMPLETE` only when every DC in scope answered. With `PARTIAL`, a
  maximum over the answered DCs is a lower bound: a caller must not report "never logged on" or an
  exact time from it. An unreachable or stale DC is a result with an error, never a silent drop.
- RODCs are included with `PER_DC_SCOPE_ALL` and excluded with `WRITABLE`. An RODC holds the logons
  it served and is not a feed source.
- Reads run concurrently under the connector's per-DC and per-domain caps (TM-TB3-T8). `lastLogon`
  is not in the GC partial attribute set, so no GC shortcut exists `[UNVERIFIED]`.

## 6. `ChangeFeed`

### 6.1 Shape

`ChangeFeedRequest{connection, partition, start, attributes[]}`, where `start` is one of:

| Start | Meaning | AD | Entra |
| --- | --- | --- | --- |
| `prime` | Establish a cookie and return **no object data**. The connector drains the first cycle itself | yes | yes (delta without data is a full enumeration the connector discards) |
| `full` | Deliver the whole current state as changes | **no** (`CAPABILITY_UNSUPPORTED`; the initial state is a `ScopedSearch`) | yes |
| `resume{cookie}` | Continue from a cookie. **There is no DC choice**: the cookie names its DC | yes | yes |

Sequence for a new AD partition: **prime, then paged search, then resume.** Changes between the
prime and the search are delivered again by the feed; replays are harmless because apply is an
idempotent upsert by GUID (DM-16.I1). This is the reason for `prime`: it removes the race without
streaming the domain twice.

A call streams `ChangeBatch` messages and ends with the one that has `cycle_complete = true`
(DirSync `MoreResults = 0`, Graph deltaLink reached). Every successful call ends with one, even
with zero changes, so the cookie's `issued_at` advances. A stream that ends without it, or with an
error, was cut off: the caller keeps its last committed cookie (CC-FEED-14).

### 6.2 DirSync is object-security mode only (TM §6.3 R2)

The AD feed sends the DirSync control with `LDAP_DIRSYNC_OBJECT_SECURITY` (0x1) and
`INCREMENTAL_VALUES` (0x80000000) and **nothing else**. The request has no flags field and
slots 7 to 15 are reserved, so replication-rights mode and DirSync EX (`…2090`) cannot be asked for.
Reasons, from the threat model and the spec:

- With the object-security flag the server skips the NC-root Get-Changes check and returns only
  "objects and attributes that are otherwise accessible to the client"
  ([MS-ADTS DirSync](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/2213a7f2-0a36-483c-b2a4-8574d53aa1e3);
  [ProcessDirSyncSearchRequest](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/0e61ce24-eac7-40d1-a014-37854e932b43)).
  The right is not needed since Windows 2003, and Samba's fix for its own bypass confirms the
  split ([CVE-2023-4154](https://www.samba.org/samba/security/CVE-2023-4154.html)).
- Plain Get-Changes through DirSync bypasses object and attribute ACLs and reads confidential
  attributes; Get-Changes-All is DCSync. Neither is held (threat-model §6.3 R2).
- The base must be the NC root; the scope is treated as subtree. A non-root base gets
  `unwillingToPerform`. The control must be critical.
- The connector adds the show-deleted control (`…417`) because DirSync "automatically includes"
  deleted objects on ADSI but not on raw LDAP, and requests `objectClass` and `isDeleted` (not
  `objectCategory`, which tombstones lack; DM-19, T-0018). DirSync and DirSync EX in one request is
  a protocol error.

### 6.3 Cookie, issuing DC and the DM-19 mapping

`FeedCookie{provider_state, provider_kind, format_version, issuer{dsa_guid, invocation_id,
hostname, site}, highest_committed_usn_before, issued_at}`. `provider_state` is the DirSync cookie
bytes (Entra: the delta link) and is **never parsed by callers**. The rest is the connector's own
record, made when the cookie is issued, because the server does not report a restore.

| DM-19 | Contract |
| --- | --- |
| I1 written in the same transaction as the rows it covers | Each `ChangeBatch.cookie_after` is the cookie that, resumed, yields everything after that batch. The caller commits the batch's rows and that cookie together. No acknowledgement RPC exists: replays are harmless |
| I2 one reader per partition (lease) | The caller's lease (DM-06). The connector holds no per-partition state between calls |
| I3 an invalid or expired cookie forces a full resync | `STALE_COOKIE` with a `ResyncReason` (below). The caller sets `resync_required`, re-primes, searches, and diffs forest-wide by GUID, so a deletion missed while the cookie was stale still becomes `deleted` or `purged` |
| I4 a cookie is reused only on the DC that issued it | `resume` has no DC field. The connector pins the issuer and never switches a cookie to another DC. If the issuer cannot be reached the error is `UNREACHABLE_DC` (retry the same DC), **not** `STALE_COOKIE`. A caller that gives up re-primes on another DC; that is a resync by definition |
| I5 children of a moved or renamed parent are not reported | Documented on `ObjectChange.dn`: a DN is a snapshot at emission. The caller re-derives `dn` and `ancestry` from the parent's new position |
| I6 a Graph delta token expires after 7 days; `410 Gone` is a full sync | `STALE_COOKIE` with `DELTA_TOKEN_EXPIRED`. Never surfaced to an admin as an error |

**Client-side checks before the first search** (the server does not report these; a cookie from a
restored DC is silently treated as USN zero,
[MS-DRSR cycle start](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/eb6876c5-6997-4541-8165-3844e46b464d)).
Each failure is a `STALE_COOKIE` raised **before any batch**:

| Check | `ResyncReason` |
| --- | --- |
| DC reached has a different `dsa_guid` than `issuer` | `ISSUER_MISMATCH` |
| NTDS Settings `invocationId` differs from `issuer.invocation_id` | `INVOCATION_ID_CHANGED` |
| `highestCommittedUSN` is lower than `highest_committed_usn_before` | `USN_ROLLBACK` |
| Cookie age (now minus `issued_at`) is at or beyond the smaller of `tombstoneLifetime` and `msDS-deletedObjectLifetime`, less a margin | `COOKIE_TOO_OLD` |
| `format_version` unknown to this build | `COOKIE_FORMAT_UNKNOWN` |

The DC is also asked, and may itself reject the cookie (`0000203D`, `protocolError`; Samba answers
`unsupportedCriticalExtension` for an unparsable one): `SERVER_REJECTED`. Classification is on the
LDAP result code, never on the Windows text. Replays and near-full resyncs after a wrong-DC cookie
are the third outcome in DM-19.I4 and cannot be detected; the pre-checks exist so that is only
reachable by a DNS change that the `dsa_guid` check missed. The margin is provisional (the larger of
one day and 10 % of the lifetime) `[OPEN → T-0065]`.

### 6.4 The batch

`ObjectChange{object_guid, state, dn, parent_guid, attributes[]}` is **final state since the cookie,
as a patch, not a snapshot**. Several changes between polls collapse and an add followed by a remove
can vanish (DM-18.I2). No change carries an old value; the old value is the caller's own previous
observation.

- `state` is `LIVE`, `DELETED` (`isDeleted = TRUE`) or `RECYCLED` (`isRecycled = TRUE`: past the
  deleted-object lifetime, no longer restorable). A physical purge is **never** reported by the feed
  (the object simply vanishes) and is found by the reconcile pass (§6.5).
- `AttributeChange.op` is `SET` (the full current set), `CLEARED`, `VALUES_ADDED` or
  `VALUES_REMOVED`. The last two are the normalised form of the provider's incremental encodings:
  Windows `member;range=1-1` for an added value, Samba also `;range=0-0` for a removed one
  `[UNVERIFIED Windows]`, Graph `members@delta`. **These are not paging cursors**: a dedicated
  decoder maps them, and the ranged-read loop of §5.3 is never applied to feed output (it would
  chase `range=1-*`).
- The connector requests, always, a **mandatory set**: `objectGUID`, `objectClass`, `name`,
  `isDeleted`, `isRecycled`, `lastKnownParent`. `name` is required for the DC to supply
  `parentGUID` `[UNVERIFIED lab]`. The caller's `attributes` are added to it. Zero attribute changes
  on an `ObjectChange` is legal (the object changed only in attributes not requested): callers infer
  nothing from it.
- **No order.** Batches are not parent-first (the ancestors-first flag is not used and Samba does
  not enforce it either). A change may reference a parent not yet seen. Apply is order-independent
  (CC-FEED-16).
- **Secrets never leave the connector.** `SecretAttrs` are stripped from every change, name
  included, before the batch is built. The batch reports only `secret_attributes_dropped`, a count
  for diagnosis (TM-TB3-T6, DM-16.I3, DM-18.I4).
- A removed member whose target was deleted may not appear as `VALUES_REMOVED` on Samba (the entry is
  skipped when the target no longer resolves). Membership removal is derived by the caller from the
  member's `DELETED` and by the reconcile; both are idempotent.

### 6.5 What the feed cannot promise, and what the caller must do

Deletions and visibility are the weakest part of an object-security feed, and Microsoft's documents
are silent on several edges. The ad-expert consult (T-0064, 2026-10-02) found, and this contract
therefore states, the following; every `[UNVERIFIED]` needs a Windows lab case (§9, **W-**cases).

1. **The feed is not authoritative for deletions.** Whether a non-administrator sees tombstones in an
   object-security feed is unspecified: by default only SYSTEM and Administrators can list
   `CN=Deleted Objects` ([KB 892806](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/non-administrators-view-deleted-object-container)),
   and the deleted object's own security descriptor, not the container's, may be the one evaluated
   `[UNVERIFIED Windows]`. `FEED_DELETIONS` is therefore `UNVERIFIED` in `Describe`.
2. **Gaining or losing visibility is silent.** An ACL change that makes an object unreadable gives
   no "lost access" entry and no delete-like entry; the object just stops appearing, or returns
   with fewer attributes. Gaining access is not replayed: the object appears only at its next
   change. An inheritable-ACE change on a parent does not report the children, either way, and a
   move or rename of a parent does not report its children
   ([DirSync polling](https://learn.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-the-dirsync-control)).
3. **Consequence, as a binding rule for T-0065:** deletes are "observed by the feed" **plus**
   "inferred by a periodic reconcile", never feed-only. The reconcile is a paged `ScopedSearch` of
   the NC head returning `objectGUID` only, diffed forest-wide against inventory by GUID (DM-16.I1,
   DM-19.I3). Feed silence never means "unchanged".
4. **Notifications are hints, not the feed** (T-0018): the change-notification control is not used
   here, so nothing in this contract depends on Samba delivering delete notifications, which it
   likely does not.
5. **Samba never sets `MoreResults` and ignores the byte limit**, so batch-boundary behaviour
   cannot be tested on it; Windows enforces a minimum of `0x100000` bytes per response and the
   maximum of one `MaxPageSize` of objects, so small batches cannot be forced there either.
   `cookie_after` at every response boundary is nevertheless defined, and mid-cycle cookies are
   tested on Windows (CC-FEED-21).

### 6.6 Entra

The same shape. `prime` and `full` both start a delta query with no token; `resume` carries the
delta link in `provider_state`. `$select` is the attribute list, `@removed` becomes `DELETED`,
`members@delta` becomes `VALUES_ADDED` and `VALUES_REMOVED`, and honouring `Retry-After` is the
connector's (`THROTTLED` with `retry_after`). An expired token or `410 Gone` is `STALE_COOKIE`
`DELTA_TOKEN_EXPIRED`. The Graph mapping is the Entra provider's spec; its conformance cases need
the Entra test tenant and are listed as **E-**cases `[LAB: Entra]`.

## 7. Errors

Every failure is one `ConnectorError{code, retry, message, dc, provider_result_code, details}`: on the
wire the single detail of a gRPC status, on the embedded transport the same message in a Go error.
Both transports must give the same `code` for the same cause (CC-ERR-01). **Callers classify on
`code`**, never on `message` and never on a directory's diagnostic text. `message` never contains
credentials, filter text, attribute values, cookies or a raw LDAP response (CC-ERR-02).

| Code | Meaning (typical source) | Retry advice | gRPC status | Details |
| --- | --- | --- | --- | --- |
| `UNREACHABLE_DC` | No DC, or the pinned or issuing DC, could be reached or served | same DC after backoff, or other DC (not for a resume) | `UNAVAILABLE` | `unreachable` (each attempt and cause) |
| `UNEXPECTED_REFERRAL` | A referral or continuation reference (LF-32) | never | `FAILED_PRECONDITION` | `referral` (count only) |
| `STALE_COOKIE` | The feed cookie cannot continue (§6.3) | after resync | `FAILED_PRECONDITION` | `stale_cookie` (reason, issuer, observed) |
| `INSUFFICIENT_RIGHTS` | `insufficientAccessRights`, Graph 403 | operator action | `PERMISSION_DENIED` | `insufficient_rights` (operation, object) |
| `OBJECT_NOT_FOUND` | `noSuchObject`, deleted or unreadable object | never | `NOT_FOUND` | none |
| `DELEGATION_ROOT_GONE` | A root GUID resolves to nothing (LF-31) | never | `NOT_FOUND` | `root_gone` |
| `FILTER_REJECTED` | The AST failed P1 validation | never | `INVALID_ARGUMENT` | `rejected_input` (rule id, field) |
| `ATTRIBUTE_NOT_ALLOWED` | Unknown, constructed-in-filter, or `tokenGroups` outside a base read | never | `INVALID_ARGUMENT` | `rejected_input` |
| `SECRET_ATTRIBUTE` | A `SecretAttrs` member in a filter, list or sort (LF-22, 34, 35, 37, 38) | never | `PERMISSION_DENIED` | `rejected_input` |
| `INVALID_ARGUMENT` | Malformed request: no roots, `*` attribute, page size 0, no filter | never | `INVALID_ARGUMENT` | `rejected_input` |
| `CAPABILITY_UNSUPPORTED` | Operation or feature not `SUPPORTED`, or a reserved name | never | `UNIMPLEMENTED` | none |
| `DIRECTORY_IDENTITY_MISMATCH` | The connection points at another directory (DM-10.I1) | operator action | `FAILED_PRECONDITION` | none |
| `TRANSPORT_SECURITY` | TLS, signing or channel binding failed. Never downgraded, never retried with validation off | operator action | `FAILED_PRECONDITION` | none |
| `BIND_FAILED` | The directory refused the connector's credential | operator action | `FAILED_PRECONDITION` | none |
| `GLOBAL_CATALOG_NOT_ALLOWED` | The connection is bound to a GC port (LF-33) | operator action | `FAILED_PRECONDITION` | none |
| `THROTTLED` | DC busy, `adminLimitExceeded`, Graph 429 | same DC after backoff | `RESOURCE_EXHAUSTED` | `throttled` (`retry_after`) |
| `LIMIT_EXCEEDED` | A connector limit (value cap, message size, outstanding ops) | never | `RESOURCE_EXHAUSTED` | `limit` |
| `PROVIDER_FAILURE` | Unmapped directory failure; result code in `provider_result_code` for diagnosis only | never | `INTERNAL` | none |

Cancellation and deadline use the gRPC statuses `CANCELLED` and `DEADLINE_EXCEEDED` with no
`ConnectorError`; the connector releases its DC resources in both cases (CC-TR-03, CC-TR-04).
`UNREACHABLE_DC`, `STALE_COOKIE`, `UNEXPECTED_REFERRAL` and `INSUFFICIENT_RIGHTS` are the four
typed failures of the ticket's acceptance criterion; they are the ones every caller must handle.

## 8. Reserved names and extension

`Operation` holds `APPLY = 100`, `READ_SECRET = 101` and `VERIFY_USER = 102`. `Describe` reports
them `RESERVED` for every provider. The write group, the named secret operations (LAPS, BitLocker;
each with its own capability and audit kind, safe-primitives §3.7) and `VerifyUser` add their RPCs
and messages in later tickets as additive changes. The named operations that safe-primitives §3.6
reserves for escape controls (`GroupMembersExpand`, `ForestWideLookup`, `RecycleBinBrowse`,
`RestoreDeleted`) are not part of this version: each gets an `Operation` value and a security-architect
review when it is specified. `ChangeFeed` **is** the `ChangeTracking` named operation: DirSync's
control exists only inside it.

## 9. Provider conformance suite

**Where it lives:** `internal/connector/conformance` (a Go package, `conformance.Run(t, Target)`),
built by the first connector ticket (T-0081 for the embedded transport). A `Target` is a running
provider plus the transport it is reached over. **Both transports run every case** against the
Samba lab on every merge (blueprint §7.2), unless the column says otherwise. The embedded target
calls `connector/service` in-process; the remote target dials a `cmd/connector` through a
`fleet` tunnel. Cases tagged **S** run in CI on Samba. **W** cases are written and tagged
`windowslab` so CI skips them loudly (ad-lab runbook §5); they are `[UNVERIFIED]` until the Windows
lab runs them (ticket in §10). **E** cases need the Entra test tenant. **2dc** and **scale** need the
lab tiers of T-0049. **FI** cases use a fault-injecting LDAP proxy in front of the lab DC (test-engineer
owns it): the directory behaviour is real, only the injected fault is synthetic.

Seed facts used (ad-lab runbook §2): about 5,000 users, `GG-Big` with 3,000 members, `GG-Cycle-A` to
`GG-Cycle-C`, a 6-deep nesting chain, specials and Unicode in CNs (commas, `+`, `"`, `*`, `(`, `)`),
disabled, expired and locked accounts.

### 9.1 Describe and DescribeSchema

| ID | Case | Expectation | Lab |
| --- | --- | --- | --- |
| CC-DESC-01 | `Describe` on the lab | `provider_kind = AD`, contract `activediq.connector.v1`, directory identity equals the lab forest root GUID and SID; the six operations `SUPPORTED`, `APPLY` `READ_SECRET` `VERIFY_USER` `RESERVED` | S |
| CC-DESC-02 | Topology | domain, configuration and schema NCs with GUIDs and the domain SID; `forest_settings` reflects what is read, with an absent `tombstoneLifetime` left **unset** (no default applied) | S |
| CC-DESC-03 | DC facts | the lab DC has `dsa_guid`, `invocation_id` equal to its NTDS Settings object, site, `is_pdc_emulator = TRUE` after the `validFSMOs` cross-check; every fact Samba does not expose is `UNKNOWN`, never `FALSE` or `0` | S |
| CC-DESC-04 | Wrong directory identity | `DIRECTORY_IDENTITY_MISMATCH`; no read was issued | S |
| CC-DESC-05 | No DC reachable (closed port) | `UNREACHABLE_DC` with an attempt per DC and its cause; for a previously described connection, `Describe` answers from cache with `health = UNAVAILABLE` and the per-DC errors | S |
| CC-DESC-06 | Features | `FEED_DELETIONS` is `UNVERIFIED`, never `SUPPORTED`, on AD; `FEED_FULL_START` is `UNSUPPORTED` on AD; each feature carries its `source` | S |
| CC-DESC-07 | Limits | `max_page_size` equals the DC's `lDAPAdminLimits` value; `max_value_range` equals MaxValRange or the documented default when unreadable | S |
| CC-DESC-08 | DC topology completeness | a DC known from the configuration NC but stopped appears with `reachable = false` and an error; nothing is dropped | 2dc |
| CC-DESC-09 | RODC and `fSMORoleOwner` staleness | `is_rodc` from the nTDSDSA object; a stale role owner is not reported as PDC after the cross-check | W |
| CC-SCH-01 | `DescribeSchema` | streams to `last = true`; `objectGUID` kind `GUID`, `member` linked with a link id, `msDS-User-Account-Control-Computed` constructed, `unicodePwd` secret; fingerprint equals `Describe`'s | S |
| CC-SCH-02 | Schema-driven secrets (LF-38) | every `attributeSchema` with `searchFlags` & (`0x80` or `0x200` or `0x1000`) is `secret = true`, including a seeded custom attribute flagged `0x200` only; each is refused in filter, attribute list and sort with `SECRET_ATTRIBUTE` | S (needs seed addition, §10) |
| CC-SCH-03 | `if_fingerprint_differs_from` equal | a single empty chunk with `last = true` | S |

### 9.2 ScopedSearch

| ID | Case | Expectation | Lab |
| --- | --- | --- | --- |
| CC-SRCH-01 | Paged read of every user under the NC head, `page_size = 100` | every seeded user exactly once; more than one `SearchBatch`; the stream ends with `SearchCompleted`; no `sizeLimitExceeded` | S |
| CC-SRCH-02 | Root-bounded | with an OU root and `SUBTREE`, no entry is outside the OU's subtree; with `ONE_LEVEL`, only direct children; the root itself is returned when it matches | S |
| CC-SRCH-03 | Several roots, one nested in another | each object once; `RootCompleted` for each root | S |
| CC-SRCH-04 | Deleted root (delete an OU, then search it) | `DELEGATION_ROOT_GONE`, no entries, no fallback to a wider root (LF-31) | S |
| CC-SRCH-05 | Moved root | the search still resolves it by GUID and returns its subtree | S |
| CC-SRCH-06 | Hostile values as data: `Eq(cn, "*)(uid=*")`, a literal `*`, backslash, a comma-and-plus DN value, `"Zoë 😀"`, a GUID as `Guid` | each returns exactly the seeded object or nothing, never a widened set (LF-01 to LF-09, LF-16) | S |
| CC-SRCH-07 | Rejected inputs | unknown attribute and constructed attribute in a filter: `ATTRIBUTE_NOT_ALLOWED`; secret in filter, list or key: `SECRET_ATTRIBUTE` (LF-22, 34, 37); `*` as attribute, no filter, no roots, page size 0: `INVALID_ARGUMENT`; empty `And`, a 10,000-deep `Not`, a 20,000-character value: `FILTER_REJECTED` (LF-25, 28, 29) with no crash | S |
| CC-SRCH-08 | Filter widening attempts | `Substring` on a DN-syntax attribute, an `Eq` with an empty value, a bit match on a text attribute: `FILTER_REJECTED` with the rule id (LF-12, 15) | S |
| CC-SRCH-09 | Ranged attribute in a search | `member` of `GG-Big` returns `complete = false`, the first range (1,500 values on Samba with the explicit range request), and the entry is not completed by following ranges | S (Samba returns all 3,000 on a plain read: assert the request, not only the result) |
| CC-SRCH-10 | Referral | an injected continuation reference ends the stream with `UNEXPECTED_REFERRAL`, a count and no URL; no `SearchCompleted`; no page returned as complete (LF-32) | FI |
| CC-SRCH-11 | Global Catalog | a connection bound to port 3268 or 3269: `GLOBAL_CATALOG_NOT_ALLOWED` (LF-33) | S |
| CC-SRCH-12 | Typed decoding | for the seeded accounts: `accountExpires` ZERO, `MAX` and a timestamp; `pwdLastSet` ZERO; `lastLogonTimestamp` and `whenCreated` timestamps; `groupType` negative for security groups; `userAccountControl` flags; `objectGUID` and `objectSid` equal the canonical text from `ldbsearch` (rule 9) | S |
| CC-SRCH-13 | Pinned DC that does not exist | `UNREACHABLE_DC`, no silent switch to another DC | S |
| CC-SRCH-14 | Cancel after the first batch | the connector releases the LDAP search and its pinned connection within 2 s; a second search succeeds; the open-operations gauge returns to 0 | S |
| CC-SRCH-15 | Memory bound | reading 5,000 and 50,000 users with `objectGUID` only, peak heap growth does not depend on the result size (streaming, no buffering) | S, scale |
| CC-SRCH-16 | DC dies mid-stream | `UNREACHABLE_DC`, no `SearchCompleted` | S |
| CC-SRCH-17 | Unreadable root | a root under a deny ACE: `INSUFFICIENT_RIGHTS` or `OBJECT_NOT_FOUND`, and the harness's caller-side mapping treats both the same (LF-36) | S (needs seed addition); W for the exact DC behaviour |
| CC-SRCH-18 | `nTSecurityDescriptor` in the attribute list | `CAPABILITY_UNSUPPORTED` until T-0118 | S |
| CC-SRCH-19 | Failover to a second DC | with the pinned DC stopped and no pin, the search restarts on the other DC from the start of the unfinished root, with no duplicate entries in the final set | 2dc |

### 9.3 Read

| ID | Case | Expectation | Lab |
| --- | --- | --- | --- |
| CC-READ-01 | `member` of `GG-Big` | the header has `complete = false` and the first range (0 to 1,499); chunks follow in order; the last has `terminal`; 3,000 distinct values; the connector issued explicit range requests (assert on the request, not only the result) | S |
| CC-READ-02 | `max_values_per_attribute = 2000` | 2,000 values, `member` in `truncated_attributes` | S |
| CC-READ-03 | Nested and circular groups | `GG-Cycle-A` returns its direct members only; no recursion, no hang | S |
| CC-READ-04 | Constructed attributes | `tokenGroups` and `msDS-User-Account-Control-Computed` read on a base read; the same names in a `ScopedSearch` attribute list: `ATTRIBUTE_NOT_ALLOWED`. The locked seeded account shows the lockout bit from the computed attribute, not from `userAccountControl` | S where Samba computes it; W otherwise |
| CC-READ-05 | Not found | a random GUID and a deleted object's GUID: `OBJECT_NOT_FOUND` (no show-deleted) | S |
| CC-READ-06 | DN specials | an object whose CN has a comma, `+` and Unicode: `display_dn` parses back with P2 to the same RDNs; `object_guid` is stable across a rename | S |
| CC-READ-07 | Secrets and the SD | `unicodePwd`, `msDS-ManagedPassword`, `ms-Mcs-AdmPwd`: `SECRET_ATTRIBUTE`; `nTSecurityDescriptor`: `CAPABILITY_UNSUPPORTED` | S |
| CC-READ-08 | Absence is not emptiness | an attribute the identity cannot read is omitted exactly like an unset one; the harness documents that no caller may infer "not set" from omission for a security decision | S, W for confidential attributes |
| CC-READ-09 | A 50,000-value attribute | streamed in chunks each within `max_message_bytes`; no message above the limit; memory bounded | scale |

### 9.4 ReadPerDC

| ID | Case | Expectation | Lab |
| --- | --- | --- | --- |
| CC-PDC-01 | Single-DC lab | one `PerDcResult` for the lab DC; `PerDcSummary` is `1/1 COMPLETE`; `lastLogon` of a never-logged-on seeded user is `ZERO`, not "never" | S |
| CC-PDC-02 | Typed values | `logonCount`, `badPwdCount` integers; times as `TimeValue` | S |
| CC-PDC-03 | A DC down | `PARTIAL`, the stopped DC listed with an error result, never dropped; the maximum over answered DCs is flagged a lower bound by the harness's reference reader | 2dc |
| CC-PDC-04 | The exact maximum | logons on different DCs: the maximum over a `COMPLETE` result equals the latest | 2dc |
| CC-PDC-05 | Object not yet replicated | the lagging DC answers `OBJECT_NOT_FOUND` as its result, the call still ends in a summary | 2dc |
| CC-PDC-06 | RODC | included with `ALL`, excluded with `WRITABLE`; its `lastLogon` is its own | W |
| CC-PDC-07 | Concurrency cap | with 20 DCs in scope the connector never runs more than `max_concurrent_ops_per_dc` against one DC and the requested `max_concurrency` is lowered | 2dc, scale |

### 9.5 ChangeFeed

| ID | Case | Expectation | Lab |
| --- | --- | --- | --- |
| CC-FEED-01 | `prime` | exactly one batch, `cycle_complete`, zero changes; the cookie's issuer equals the DC from `Describe` (`dsa_guid`, `invocation_id`); `highest_committed_usn_before` and `issued_at` set; no object data on the wire | S |
| CC-FEED-02 | Create, modify, rename, move, delete a user after a prime, then `resume` | the changes arrive with the right `state` (`LIVE`, then `DELETED` for the delete); the delete carries the tombstone DN and the GUID; applying them to a reference inventory gives the directory's state | S |
| CC-FEED-03 | `resume` with nothing changed; the same cookie resumed twice | an empty batch with `cycle_complete` and a newer `issued_at`; the same cookie yields the same changes (replay-safe) | S |
| CC-FEED-04 | One member added to and removed from `GG-Big` | one `VALUES_ADDED` of that single value and later one `VALUES_REMOVED`, never a 3,000-value `SET`; the decoder is not the range loop | S (the Samba `0-0` removal form); W |
| CC-FEED-05 | Password reset after a prime | `pwdLastSet` changes; no `unicodePwd`, `ntPwdHistory`, `lmPwdHistory`, `supplementalCredentials` or `dBCSPwd` appears in any batch under any name; `secret_attributes_dropped` is reported | S |
| CC-FEED-06 | The bind account lacks Get-Changes | the feed works (object-security mode); the harness proves the account holds no replication right | S |
| CC-FEED-07 | Edited `issuer.invocation_id` | `STALE_COOKIE` `INVOCATION_ID_CHANGED` before any batch | S (synthetic cookie edit on a real DC) |
| CC-FEED-08 | `highest_committed_usn_before` raised above the DC's | `STALE_COOKIE` `USN_ROLLBACK` before any batch | S |
| CC-FEED-09 | Edited `issuer.dsa_guid` | `STALE_COOKIE` `ISSUER_MISMATCH` | S |
| CC-FEED-10 | `issued_at` set to the smaller lifetime minus the margin, and just inside it | `COOKIE_TOO_OLD` at and beyond the boundary, a normal batch just inside | S |
| CC-FEED-11 | Corrupted `provider_state` | `STALE_COOKIE` `SERVER_REJECTED` (Samba: unsupported critical extension; Windows: `0000203D`); classified on the result code | S; W for the Windows code |
| CC-FEED-12 | Unknown `format_version` | `STALE_COOKIE` `COOKIE_FORMAT_UNKNOWN` | S |
| CC-FEED-13 | The issuing DC is down | `UNREACHABLE_DC` (retry the same DC), not `STALE_COOKIE`; no silent switch | S |
| CC-FEED-14 | Cut-off stream | kill the stream after a batch: the caller's last committed cookie resumes, and the union of both runs equals an uninterrupted run (property test) | S |
| CC-FEED-15 | Rename a parent OU | its children are **not** in the feed (DM-19.I5); the harness's reference applier re-derives their DNs from the parent | S measured; W |
| CC-FEED-16 | Apply order | shuffling the apply order of the changes in a cycle gives the same final inventory | S |
| CC-FEED-17 | `start = full` on AD | `CAPABILITY_UNSUPPORTED` | S |
| CC-FEED-18 | `attributes = ["*"]` | `INVALID_ARGUMENT`; the mandatory set is present on every change | S |
| CC-FEED-19 | Restore the DC from a backup | `INVOCATION_ID_CHANGED` on the next call | W |
| CC-FEED-20 | A non-administrator identity: does the feed show tombstones? | the observed answer is recorded, and `Describe`'s `FEED_DELETIONS` state is made consistent with it; a missing delete is caught by the reconcile in the harness's reference loop | W |
| CC-FEED-21 | A cycle with `MoreResults` and the byte limit | a mid-cycle `cookie_after` resumes correctly; batch boundaries hold | W |
| CC-FEED-22 | ACL change that hides, then re-exposes, an object; an inheritable-ACE change on a parent | the feed's behaviour is recorded; the reconcile finds the difference (§6.5) | W |
| CC-FEED-23 | DirSync request on the wire | the control is sent critical with flags exactly `0x1 \| 0x80000000`, base is the NC root, show-deleted is attached, and no other control is (captured by the proxy) | FI |
| CC-FEED-24 | Entra delta | `prime` and `full` work; `@removed` gives `DELETED`; `members@delta` gives added and removed; an expired token and `410` give `DELTA_TOKEN_EXPIRED`; a 429 gives `THROTTLED` with `retry_after` | E |

### 9.6 Cross-cutting

| ID | Case | Expectation | Lab |
| --- | --- | --- | --- |
| CC-ERR-01 | The same cause on both transports | the same `ErrorCode`, `retry` and detail type for each of the typed failures of §7 | S |
| CC-ERR-02 | Canary scan | known canaries (a bind password, a filter value, an attribute value, a cookie) never appear in any `message`, log line or span of any failure above | S |
| CC-ERR-03 | Reserved and unsupported operations | `Describe` lists them; no RPC exists for the three reserved names | S |
| CC-TR-01 | Message size | no message of any operation exceeds `max_message_bytes` on either transport | S |
| CC-TR-02 | Tenant | the remote target rejects a call whose certificate names another tenant before any provider code runs; no message has a tenant field (P2) | S (remote only) |
| CC-TR-03 | Cancellation over the tunnel | cancelling a stream on the remote transport releases the connector's DC resources as the embedded one does | S |
| CC-TR-04 | Deadline | a deadline that expires gives `DEADLINE_EXCEEDED`, the DC resources are released, and no partial result is reported as complete | S |
| CC-DATA-01 | Codec round trip | for the GUID, SID and time codecs of §5.4, every value of the P3 corpus round-trips through the contract on both transports, including the `0`, `MAX` and out-of-range FILETIMEs | S |

### 9.7 Samba and Windows coverage

| Behaviour | Samba lab | Needs |
| --- | --- | --- |
| Paging, ranges (explicit), codecs, filters and rejections, referrals (injected), GC refusal, error mapping, DirSync object-security basics, cookie pre-checks, secret stripping, streaming and cancellation | yes (S, FI) | n/a |
| Unranged reads | **false-pass**: Samba returns all values. Cases assert the request | the explicit-range assertions in CC-READ-01 and CC-SRCH-09 |
| `MoreResults` and the byte limit | cannot be exercised (Samba never sets it) | W (CC-FEED-21) |
| Tombstone visibility to a non-admin in an object-security feed; ACL-driven visibility; removal encoding of link values; restore and `invocationId` | Samba's code path differs; a Samba pass proves nothing | W (CC-FEED-04, 19 to 22) |
| Multiple DCs: failover, per-DC maxima, partial coverage, replication lag | no (one DC) | 2dc tier (T-0049), then W |
| RODC behaviour, `fSMORoleOwner` staleness | no | W |
| Windows error text and `0000203D` | no | W |
| Entra delta, throttling, token expiry | no | E (Entra test tenant) |
| 50,000-user and 50,000-member scale | partial | scale tier (T-0049) |

## 10. Decisions for review and follow-ups

Decisions made in this spec, flagged for the reviewers:

- **D1. Authorisation and counts live in `directory/client`.** Safe-primitives §3.3 rule 8 and LF-39 say
  authorisation is checked per returned object and counts follow it. In the remote case the technician
  and RBAC are on the server, so the connector cannot do it. The contract returns root-bounded entries
  and carries no counts; `AuthorisedPage` is built server-side. solution-architect to confirm and align
  safe-primitives §3.1's `scope.ScopedSearch(... ) -> AuthorisedPage` wording.
- **D2. A sixth RPC, `DescribeSchema`**, beyond the blueprint §7.1 sketch. The server-side filter builder
  needs the schema allowlist (§3.3 rule 1) and a 1,700-attribute schema does not fit `Describe`'s message.
- **D3. Prime, search, resume** for the initial sync, and `full` unsupported on AD (§6.1).
- **D4. Deletions are never feed-only** (§6.5): `FEED_DELETIONS` is `UNVERIFIED` and the reconcile pass is
  mandatory. T-0065 owns the schedule.
- **D5. No resume cursor on `ScopedSearch`** (an LDAP paging cookie is per connection and DC); checkpoint
  granularity is the root.
- **D6. GUID byte order and time sentinels** (§2 rule 9, §5.4).
- **D7. Cookie age margin** (§6.3) is provisional `[OPEN → T-0065]`.
- **D8. `ReadPerDC` attributes are a closed enum.**
- **D9. Entra `ScopedSearch` is `UNSUPPORTED` in v1.** Entra reads are `Read` by object id and the feed. The
  Entra provider's spec may add it.

Follow-up tickets created (backlog) with this spec: T-0156 (Windows-lab proof of the W-cases), T-0157
(proto code generation and the `internal/proto` package) and T-0158 (lab seed additions: a custom
attribute flagged `0x200` only, and an OU with a deny ACE for the bind account, for CC-SCH-02 and
CC-SRCH-17).

## Sources

- DirSync: [Polling for changes using the DirSync control](https://learn.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-the-dirsync-control) · [MS-ADTS DirSync](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/2213a7f2-0a36-483c-b2a4-8574d53aa1e3) · [MS-DRSR ProcessDirSyncSearchRequest](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/0e61ce24-eac7-40d1-a014-37854e932b43) · [MS-DRSR cycle start](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/eb6876c5-6997-4541-8165-3844e46b464d) · [MS-ADTS LDAP extended controls](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea)
- Ranges and paging: [Attribute range retrieval](https://learn.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval) · [RFC 2696](https://www.rfc-editor.org/rfc/rfc2696) · [LDAP policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99)
- Directory facts: [MS-ADTS rootDSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db) · [invocationId](https://learn.microsoft.com/en-us/windows/win32/adschema/a-invocationid) · [KB 892806, viewing Deleted Objects](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/non-administrators-view-deleted-object-container)
- Samba: [CVE-2023-4154](https://www.samba.org/samba/security/CVE-2023-4154.html) · [dirsync.c](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/dirsync.c)
- Entra: [delta query](https://learn.microsoft.com/en-us/graph/delta-query-overview) · [throttling](https://learn.microsoft.com/en-us/graph/throttling)
- Internal: `knowledge/development/domain/ad-change-notifications.md` (T-0018), `knowledge/development/runbooks/ad-lab.md` §5, and the ad-expert consult recorded in the T-0064 notes. The Samba statements in the consult (no `MoreResults`, `;range=0-0`, skipped removed links) come from a reading of the source, not a run, and are `[UNVERIFIED lab]` until CC-FEED-04 and CC-FEED-21 run.

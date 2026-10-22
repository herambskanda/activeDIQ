---
title: "Connector contract v1.1: the read side (Describe, search, read, per-DC read, change feed), the write group (Plan, Apply) and VerifyConnection"
date: 2026-10-02
updated: 2026-10-22
status: review
owner: heramb
author: directory-engineer
ticket: T-0064
amended_by: T-0091 (v1.1, author solution-architect)
binding_sources: blueprint §7.1-7.2, safe-primitives §3.6-3.7, domain-model DM-10, DM-13..DM-20, DM-24, DM-25, threat-model §6.2-§6.6 (TM-D1, TM-D2, TM-D4, TM-D5), §6.3 R1/R2 and TM-TB3-*, ADR-0005 rules 2, 4, 5
---

# Connector contract v1.1: the read side, the write group and the rights check

The source is `proto/activediq/connector/v1/`. This document is its long form: why each shape is as
it is, what every operation promises, how failures look, and which cases a provider must pass
(§9). If the two disagree the proto wins and this file is the bug. `make fitness-proto` compiles
the proto and enforces rules P1 to P8 (§2) on every merge.

**In scope:** `Describe`, `DescribeSchema`, `ScopedSearch`, `Read`, `ReadPerDC`, `ChangeFeed`, the
error and capability model, the provider conformance suite. **v1.1 (T-0091) adds** `VerifyConnection`,
`Plan` and `Apply`, the errors `TIER0_REFUSED`, `ACTIVATION_REFUSED_OVERPRIVILEGED` and
`TARGET_CHANGED`, and the fail-closed rule for cross-directory Tier-0 context (§8). **Reserved by
name only:** `ReadSecret`, `VerifyUser` (§8.6). **Out of scope:** concrete write kinds (one spec
ticket each, §8.1), server-side activation logic (T-0100), the classifiers (T-0093, T-0095), named
secret operations, the fleet stream limits (TM-Q8), inventory tables and sync passes (T-0065), the
Entra provider's Graph mapping.

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
| 6 | `ReadSecret` and `VerifyUser` exist as names in `Operation` and have no RPC. `OPERATION_APPLY = 100` keeps its number now that `Apply` has a shape (v1.1) | Reserved, shape later | P6 |
| 7 | No `string` or `bytes` field is named `password`, `unicode_pwd`, `credential` or `secret` | Secrets use the `Secret` type, never this contract | P7 |
| 8 | The tenant is never a field | ADR-0002: a remote connector's tenant comes from its certificate SAN; the embedded one runs inside the caller's `WithTenantTx` | P2 (`tenant`, `tenant_id`) |
| 9 | GUID bytes are in RFC 4122 network order, the order of the canonical string, never the LDAP wire order | One order on the contract, so no caller can get the mixed-endian mistake (gotcha 24) | CC-DATA-01 |
| 10 | A value the directory does not expose is unset or `UNKNOWN`, never `0` or `FALSE` | Samba omits facts Windows has; a default would turn a gap into an answer | CC-DESC-03 |
| 11 | A result is valid only if its stream ends with the completion event (`SearchCompleted`, `ReadCompleted`, a `PerDcSummary`, a `ChangeBatch` with `cycle_complete`) | A silently partial result is a wrong number (TM-TB3-T9) | CC-SRCH-10, CC-FEED-14 |
| 12 | Evolution is additive: field numbers are never reused, removed fields are `reserved`, new enum values are added at the end, `contract_minor` goes up. A caller treats an unknown `ErrorCode` as `PROVIDER_FAILURE` | Both transports, mixed versions during an update | review |
| 13 | Every write-group request (`Plan`, `Apply`) has a top-level, non-repeated `Tier0Context` field, and `Tier0Context` has a repeated `CorrelationStatement` field | No write can be expressed without the per-object context the connector evaluates fail-closed (§8.3 F1) | P8 |

## 3. Layout

| File | Holds |
| --- | --- |
| `common.proto` | `Operation`, `Guid`, `Sid`, `ConnectionRef`, `DirectoryIdentity`, `DcIdentity`, `Observation`, `DcSelection`, `TimeValue`, `AttributeValue`, `Attribute`, `DirectoryEntry`, `ValueRange` |
| `filter.proto` | `Filter` AST, `FilterValue`, `Dn`, `Rdn` (the P1 and P2 wire forms) |
| `errors.proto` | `ConnectorError`, `ErrorCode`, `RetryAdvice`, `ResyncReason`, per-code details |
| `describe.proto` | `Feature`, `SupportState`, `DescribeRequest/Response`, `DescribeSchema*`, topology and health messages |
| `read.proto` | `ScopedSearch*`, `Read*`, `ReadPerDC*` |
| `changefeed.proto` | `ChangeFeedRequest`, `FeedCookie`, `ChangeBatch`, `ObjectChange` |
| `tier0.proto` (v1.1) | `Tier0Basis` (C1-C16, E1-E5, designated), `Tier0Context`, `CorrelationStatement`, `CorrelatedPeer`, `CorrelationEvidence` |
| `write.proto` (v1.1) | `PlanRequest/Response`, `ApplyRequest/Response`, `WriteKind`, `WriteChange`, `WriteTarget`, `TargetPrecondition`, `StepKey`, `ActingPrincipal`, `WriteGateOverride`, `Tier0Evaluation` |
| `verify.proto` (v1.1) | `VerifyConnectionRequest/Response`, `RightsFinding` and its right and source types, `RightsFamily`, `VerificationCheck`, `VerificationVerdict` |
| `connector.proto` | the `Connector` service |

Go package `internal/proto/activediq/connector/v1` (`go_package`) is generated and never
hand-edited (blueprint §1). It is generated by `make gen-proto` (`tools/gen/proto`, T-0157), which
compiles `proto/` with the pure-Go protocompile and runs `protoc-gen-go` and `protoc-gen-go-grpc`,
both pinned as `tool`s in `go.mod`: no protoc, no buf, no non-Go toolchain. Output is
reproducible. `make gen-check`, a step of `make ci`, regenerates in memory and fails on a stale,
hand-edited or orphaned `*.pb.go`. The reserved names `ReadSecret` and `VerifyUser` are
also pinned at compile time by `internal/proto/activediq/connector/v1/reserved_test.go`: the
package stops compiling if either generated interface gains one of those methods or the
`Operation` enum loses one of those values. The same test pins the RPC list (nine in v1.1), the
numbers of `PLAN`, `VERIFY_CONNECTION`, `APPLY`, `READ_SECRET` and `VERIFY_USER`, that a provider
with no write path answers `Plan`, `Apply` and `VerifyConnection` only with `UNIMPLEMENTED`, and that
`WriteKind` has no kind yet.

## 4. Describe and the capability model

`Describe(connection, refresh)` is the DM-13.I2 binding check: a connection binds to a connector
only if `Describe` reports a provider for the connection's kind. It returns:

- **`operations[]`**: one `OperationSupport` per `Operation` value with `SUPPORTED`,
  `UNSUPPORTED`, `UNVERIFIED` or `RESERVED`, and a reason. This is the capability flag of every
  read operation. `directory/client` checks it before it plans, and a call to an operation that is
  not `SUPPORTED` fails with `CAPABILITY_UNSUPPORTED` (for `Plan` and `Apply` the write gate and the Tier-0 refusal answer first, §8.1). From v1.1, `PLAN` and `APPLY` are
  `SUPPORTED` only when the provider's write path is wired for at least one `WriteKind` **and**
  `VERIFY_CONNECTION` is `SUPPORTED` (a write path without its own rights check and tier0 set would
  have nothing to refuse with); otherwise both are `UNSUPPORTED`. `PLAN` and `APPLY` are always
  reported with the same state. `RESERVED` is now only `READ_SECRET` and `VERIFY_USER` (CC-DESC-10).
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
  schema, Graph token). The *delegated-rights check* of onboarding is `VerifyConnection` (§8.4),
  not `Describe`: it is slower, it streams findings that are access-restricted (DM-24.I5), and its
  result is the connector's write gate.

`DescribeSchema` streams the schema the server-side filter builder needs for its allowlist
(safe-primitives §3.3 rule 1): per attribute its syntax, value kind, single or multi, constructed,
indexed, in the GC, linked (with link id), `secret`, and the raw `searchFlags` and `systemFlags`.
`secret` is the connector's `SecretAttrs` (§3.7: schema flags `0x80`, `0x200`, `0x1000` plus the
static list minus the reviewed exemptions), so the server refuses early and the connector refuses
again. The fingerprint in `Describe` tells a caller when to re-fetch.

## 5. The read group

### 5.1 `ScopedSearch`

`ScopedSearchRequest{connection, roots[], depth, filter, attributes[], page_size, dc}`.

- **Page size**: `page_size` 0 (unset) means `Limits.max_page_size`; a value above it is clamped to it. Neither is an error (a page size is a batching hint, and a caller must not learn the DC limit by failing). The connector never relies on the DC's size limit to end a search.

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
streaming the domain twice. The cost is that `prime` drains a full DirSync cycle on the DC, so an AD initial sync costs two DC-side enumerations (the prime's and the search's). T-0065 measures this at 200,000 objects (the CC-SRCH-15 scale) `[OPEN → T-0065]`.

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
- **Secrets never leave the connector.** A `SecretAttrs` member **named in the request** fails the
  call with `SECRET_ATTRIBUTE` before any DirSync or delta call (LF-37, the same rule as
  `ScopedSearch` and `Read`). `SecretAttrs` that arrive unrequested (DirSync returns what the
  object-security mode permits, and a schema flag can change between calls) are stripped from every
  change, name included, before the batch is built. The batch reports only `secret_attributes_dropped`, a count
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
| `INSUFFICIENT_RIGHTS` | `insufficientAccessRights`, Graph 403 | operator action | `PERMISSION_DENIED` | `insufficient_rights` (`Operation`, object) |
| `OBJECT_NOT_FOUND` | `noSuchObject`, deleted or unreadable object | never | `NOT_FOUND` | none |
| `DELEGATION_ROOT_GONE` | A root GUID resolves to nothing (LF-31) | never | `NOT_FOUND` | `root_gone` |
| `FILTER_REJECTED` | The AST failed P1 validation | never | `INVALID_ARGUMENT` | `rejected_input` (rule id, field) |
| `ATTRIBUTE_NOT_ALLOWED` | Unknown, constructed-in-filter, or `tokenGroups` outside a base read | never | `INVALID_ARGUMENT` | `rejected_input` |
| `SECRET_ATTRIBUTE` | A `SecretAttrs` member in a filter or an attribute list (LF-22, 34, 37, 38). Sort keys do not exist on this contract; LF-35 (`ForbiddenSortKey`) belongs to the server-side filter builder | never | `PERMISSION_DENIED` | `rejected_input` |
| `INVALID_ARGUMENT` | Malformed request: no roots, `*` attribute, no filter, an unset connection | never | `INVALID_ARGUMENT` | `rejected_input` |
| `CAPABILITY_UNSUPPORTED` | Operation or feature not `SUPPORTED`, or a reserved name | never | `UNIMPLEMENTED` | none |
| `DIRECTORY_IDENTITY_MISMATCH` | The connection points at another directory (DM-10.I1) | operator action | `FAILED_PRECONDITION` | none |
| `TRANSPORT_SECURITY` | TLS, signing or channel binding failed. Never downgraded, never retried with validation off | operator action | `FAILED_PRECONDITION` | none |
| `BIND_FAILED` | The directory refused the connector's credential | operator action | `FAILED_PRECONDITION` | none |
| `GLOBAL_CATALOG_NOT_ALLOWED` | The connection is bound to a GC port (LF-33) | operator action | `FAILED_PRECONDITION` | none |
| `THROTTLED` | DC busy, `adminLimitExceeded`, Graph 429 | same DC after backoff | `RESOURCE_EXHAUSTED` | `throttled` (`retry_after`) |
| `LIMIT_EXCEEDED` | A connector limit (value cap, message size, outstanding ops) | never | `RESOURCE_EXHAUSTED` | `limit` |
| `PROVIDER_FAILURE` | Unmapped directory failure; result code in `provider_result_code` for diagnosis only | never | `INTERNAL` | none |
| `TIER0_REFUSED` (v1.1) | `Plan` or `Apply`: an object the write touches is `tier0`, or the request's Tier-0 context is missing, stale or contradicted (§8.1, §8.3). Nothing was written | never | `PERMISSION_DENIED` | `tier0_refused` (object, bases, stage) |
| `ACTIVATION_REFUSED_OVERPRIVILEGED` (v1.1) | `Plan` or `Apply`: the connector's own last `VerifyConnection` does not open its write gate (§8.2). Nothing was written | operator action | `FAILED_PRECONDITION` | `activation_refused` (gate state, verification id, unacknowledged count) |
| `TARGET_CHANGED` (v1.1) | `Apply`: the target no longer matches the `TargetPrecondition` from `Plan`. Nothing was written. The pipeline records the step `stale_state` (DM-42.I2) | after re-plan | `ABORTED` | `target_changed` (object) |

Cancellation and deadline use the gRPC statuses `CANCELLED` and `DEADLINE_EXCEEDED` with no
`ConnectorError`; the connector releases its DC resources in both cases (CC-TR-03, CC-TR-04).
`UNREACHABLE_DC`, `STALE_COOKIE`, `UNEXPECTED_REFERRAL` and `INSUFFICIENT_RIGHTS` are the four
typed failures of the ticket's acceptance criterion; they are the ones every caller must handle.
Write-group callers (`directory/client`) must also handle `TIER0_REFUSED`,
`ACTIVATION_REFUSED_OVERPRIVILEGED` and `TARGET_CHANGED`; none of the three is ever retried as is.
`RetryAdvice` gains `AFTER_REPLAN` (v1.1). `Tier0RefusedDetails` carries a `tier0` object GUID:
the server may store it with the step's outcome, but never copies it into an audit event, under the
same rule as DM-24.I5 (it maps the Tier-0 set).

## 8. The write group and the rights check (v1.1)

v1.1 (T-0091) adds three RPCs. `VerifyConnection` is the connector's own rights check (TM §6.5,
§6.6). `Plan` and `Apply` are the write group that the operation pipeline calls (ADR-0005). The
server's pipeline stays the place where authorisation, approvals and audit happen. The connector adds
two guards of its own that hold even when the server is compromised (TM-TB6-T4), and matter most
for remote and SaaS connectors (TB6, TB17):

- **the write gate** (TM-D1 in the connector, §8.2): no `Plan` or `Apply` unless the connector's
  own latest `VerifyConnection` says its identity is not over-privileged, or every over-privilege
  finding is acknowledged;
- **the Tier-0 refusal** (TM-D2 check 2, §8.1, §8.3): no write to a `tier0` object, whatever the
  server asks. Nothing in a request can make an object *less* protected than the connector computes
  on its own.

### 8.1 `Plan` and `Apply`

**Envelope only.** `WriteKind` has no kind in v1.1 and `WriteChange` has no arm. Each concrete kind
(create user, set attribute, add member, move, …) comes with its own spec ticket, which adds the
kind, its `WriteChange` arm, its **touched-set rule** (every object the change writes or whose
protection it changes; for example adding a member touches the group, and a move touches the old
and the new parent), its conformance cases and its `Describe` entry. The connector derives the
touched set from the typed change and never from a list the server sends. `reserved_test.go` fails
when the first kind is added, so the kind arrives with its test changes.

**No credential material.** No field of `Plan` or `Apply` carries a password, key or token (P7 by
name, review by intent). A kind that sets a secret (password reset, ADM-136) needs a sealed-secret
shape and a security-architect review in its own ticket.

**What `Apply` carries for ADR-0005.** The step key `(operation, item, step)` and the fenced
claim's `attempt` (rule 6), the `acting_principal` and the `plan_digest` (rule 2), the DC pin as
`precondition.dc` (rule 5), and the before-state as `TargetPrecondition` (rule 4). The connector
logs the step key, attempt, acting principal, plan digest, outcome and any refusal stage locally for
every `Plan` and `Apply`, including refusals (TM-TB6-T5). It logs identifiers only, never values or
the peer list of the Tier-0 context.

**Order of evaluation.** `Plan` and `Apply` run the same steps. The first failing step ends the
call, and nothing after it runs.

| # | Step | Failure | Directory calls before it |
| --- | --- | --- | --- |
| 1 | Request shape: connection and directory identity, `target.object` set; `Apply` also needs `precondition` and `plan_digest` | `DIRECTORY_IDENTITY_MISMATCH`, `INVALID_ARGUMENT` | none |
| 2 | Write gate (§8.2) | `ACTIVATION_REFUSED_OVERPRIVILEGED` | none |
| 3 | Tier-0 context present; a `CorrelationStatement` for `target` with `correlation` and `computed_at` set, fresh (§8.3 F1, F3) | `TIER0_REFUSED` `CONTEXT_MISSING`, `CONTEXT_STALE` | none |
| 4 | **Target** against the request's designations and tier0 peers (F2) and the connector's own set from its last `VerifyConnection` | `TIER0_REFUSED` `REQUEST_CONTEXT`, `CONNECTOR_SET` | **none** |
| 5 | Kind known and wired; `Apply`: plan digest recomputed from the typed fields with the `operation/step` function, rule id `PlanDigestMismatch` | `INVALID_ARGUMENT`, `CAPABILITY_UNSUPPORTED` | none |
| 6 | The connector derives the touched set from the typed change. Every touched object other than the target needs its own present, fresh statement (F1, F3); then each is checked against the designations, its statement's peers (F2, F5) and the connector's set | `TIER0_REFUSED` `CONTEXT_MISSING`, `CONTEXT_STALE`, `REQUEST_CONTEXT`, `CONNECTOR_SET` | none |
| 7 | Live re-read on the pinned DC (AD) or Graph (Entra) of every touched object and of the facts named **live** in the per-basis table below, plus the correlation evidence for F4. Then classification with the connector's classifier (T-0093, T-0095), using the live facts for the live bases and the connector's set for the rest. A read error or an unknown answer counts as `tier0` | `TIER0_REFUSED` `LIVE_REREAD`, `CONTEXT_CONTRADICTED` | reads only |
| 8 | `Plan`: return `precondition`, `before`, `Tier0Evaluation`. `Apply`: compare with `precondition`; if the after-state is already in place return `ALREADY_APPLIED` with `read_back`; otherwise run the conditional write of ADR-0005 rule 4 and read back | `TARGET_CHANGED` | reads only, then the write |

**Live re-read per basis (step 7).** The connector's set is computed by its last `VerifyConnection`,
which can be up to the maximum verification age old (26 hours, §8.2). Step 7 therefore re-reads,
for each touched object X, the facts below. A basis marked **set** rests on the connector's set and
the request's context only; it is the residual R-T0SET-1 below.

| Basis | Step 7 reads, live | Status |
| --- | --- | --- |
| C1, C4, C13 (identity) | X's `objectSid` (well-known RIDs: C1 groups, 502), `msDS-SecondaryKrbTgtNumber` (RODC `krbtgt`). C13 groups without a well-known RID (DnsAdmins, Exchange groups) by GUID from the set | **live**, C13 by GUID **set** |
| C2 | X's `tokenGroups` (transitive, primary-group edge included) intersected with the C1 SIDs and the designated groups | **live** |
| C3, C6 (container), C7, C8, C10 | X's parent chain by `objectGUID` up to the NC head, compared with AdminSDHolder, the NC heads, `CN=System`'s sensitive children and `CN=Public Key Services` | **live** |
| C5 | X's `userAccountControl` (0x2000, 0x4000000) and `primaryGroupID` (516, 521) | **live** |
| C6 (OU holding a DC) | When X is an OU or container: one subtree search under X for a computer with 0x2000 or 0x4000000 in `userAccountControl`, size limit 1 | **live** |
| C9 | GPO reach over SOMs, enforcement, block inheritance and loopback (DM-23.I5). Too wide to recompute per write | **set**. A write to the *SOM's* `gPLink`/`gPOptions` on the domain head, a C6 OU or a C15 site is live through those bases |
| C11 | The domain head's DACL (SD-flags control, DACL only, through the typed security-descriptor primitive), evaluated against X's `objectSid` and `tokenGroups` for Get-Changes **and** Get-Changes-All, or an access mask that implies both (`GENERIC_ALL`, all extended rights), with the same evaluation as the classifier's C11 (T-0093) | **live** |
| C12 | X's `userAccountControl` (TRUSTED_FOR_DELEGATION, TRUSTED_TO_AUTH_FOR_DELEGATION) and `msDS-AllowedToDelegateTo`, where a value whose host is in the set's DC list or does not resolve counts as a DC service; the `msDS-AllowedToActOnBehalfOfOtherIdentity` of the DCs in the set's DC list | **live**; the DC list is **set** |
| C14 | X's `sAMAccountName` = `AZUREADSSOACC$` | **live** |
| C15 | When X is a site: one subtree search under X for a `server` object with a `serverReference` | **live** |
| C16, E5 | The request's statement (§8.3), whose evidence F4 checks against X as re-read | context |
| E1, E4 (roles) | Role assignments and eligibility schedules with `principalId` = X, directly and through its role-assignable groups | **live** |
| E2 | X's `isAssignableToRole` when X is a group; X's transitive memberships and owned objects filtered to role-assignable groups | **live** |
| E3 | X's owned applications and service principals | **live**; which of those apps hold a role or deny-list permission is **set** |
| E4 (sync clients) | X's `appId` against the registered sync-client list | **live** |
| Designated | The request's `designated` list (§8.3 F2) | context |

**Residual R-T0SET-1 (stale connector set).** An object that became `tier0` since the connector's
last `VerifyConnection` through a **set** basis above (a GPO newly linked so that it reaches a DC; a
C13 group that appeared with an Exchange install; a newly promoted DC that is not yet in the DC list
for C12; an app that gained a role after X became its owner) is not found by step 7. The window is
bounded by the maximum verification age (26 hours), and the server's own `tier0` guard, recomputed
on every sync (TM §6.4), is checked first at Plan. Declared here and routed to T-0108 for the
security-architect's confirmation or a tighter bound. A connector may always re-read more than this
table requires, never less.

**Residual R-T0RACE-1 (step 7 to step 8).** LDAP cannot make a write conditional on membership,
ancestry or a DACL elsewhere. Adding X to Domain Admins changes the group's `member` attribute;
`memberOf` is a back-link, so X's own `uSNChanged` does not move and the conditional modify of
ADR-0005 rule 4 still succeeds. The same holds for a new DCSync ACE on the domain head (C11) and a
move of a DC into an OU (C6). An object that becomes `tier0` between the step-7 read and the write
can therefore be written. This is the same window as ADR-0005 rule 7's residual ("no directory makes
a write conditional on ancestry, membership or correlation"), lasts milliseconds to seconds, and is
detected the same way: Verify reads the facts again after the write, and the next set computation
reports the object as `tier0`. Entra has the same window plus Graph's read consistency `[UNVERIFIED]`.

**What AC 3 of T-0091 promises.** `Apply` on a `tier0` target returns `TIER0_REFUSED` before any
directory write, except within the declared residuals R-T0CTX-1, R-T0SET-1 and R-T0RACE-1. When the
target is already in the connector's set or marked by the request's context, the refusal (step 4)
also comes before any directory call. An object that became `tier0` after the connector's last set
computation through a **live** basis (for example, added to Domain Admins, or granted DCSync rights,
since) is found by the reads of step 7. It is refused after those reads and before any write.

**Why the target check precedes the kind check.** Refusing a known `tier0` target never depends on
the kind or on whether the provider's write support is complete. The guard can therefore be proven
from the first handler (T-0098, TM-F-T0GUARD in T-0066), before any kind exists. A provider with the
handler but no kind still reports `PLAN` and `APPLY` `UNSUPPORTED` (§4). Its calls fail with
`ACTIVATION_REFUSED_OVERPRIVILEGED`, `TIER0_REFUSED` or `INVALID_ARGUMENT`, never with success.
This is the one exception to "a call to an operation that is not `SUPPORTED` fails with
`CAPABILITY_UNSUPPORTED`": both answers refuse, and the refusal that names the reason wins.

**Idempotency without connector state.** The connector keeps no plan or step state. A retried
`Apply` (same step key, next `attempt`) is safe through the precondition. If the first attempt
wrote, the after-state is found and the answer is `ALREADY_APPLIED`. If someone else changed the
target, the answer is `TARGET_CHANGED`, which the pipeline records as `stale_state` (DM-42.I2) and
never overwrites. For Entra, which has no general If-Match, the precondition is the connector's
`state_digest`, read and compared immediately before the write. The window between read and write
is ADR-0005 rule 4's declared residual.

### 8.2 The write gate (TM-D1 inside the connector)

The connector holds, in memory, per connection and credential, the result of its latest completed
`VerifyConnection`: the verdict, each check's outcome, the fingerprints of the blocking findings, its
computed `tier0` set and `completed_at`. The result is not persisted. After a restart the gate is
`NOT_VERIFIED` until the server runs a verification, and the server's write gate (DM-10.I11)
re-runs one automatically. The gate is **open** only when all of these hold. Each failure names its
`WriteGateState`:

| Condition | Otherwise |
| --- | --- |
| A completed run exists for the connection and its current credential | `NOT_VERIFIED` |
| The run is no older than the maximum verification age: provisionally 26 hours, which is the daily scheduled run (DM-24.I7) plus a margin `[OPEN → T-0098]` | `STALE` |
| V8 (AD) or EV4 (Entra) is not `FAIL`. Under-privilege is never overridable (FR-12) | `INSUFFICIENT` |
| The run's verdict is not `FAILED`, and V7 or EV3 is neither `COULD_NOT_VERIFY` nor `NOT_RUN` | `COULD_NOT_VERIFY` |
| V7 or EV3 is `PASS`, or it is `FAIL` and every blocking V7 or EV3 fingerprint is in the request's `WriteGateOverride.acknowledged_fingerprints` | `OVERPRIVILEGED` (with the count of unacknowledged findings) |

This follows DM-10.I9 (b) and I11 for V7 and EV3, and adds conditions DM-10.I11 does not state:
`INSUFFICIENT` (I11 reads the V7 outcome only, so a failed V8 or EV4 does not close it) and `STALE`
(the server keeps the gate on `last_verification_id` and re-verifies on schedule, with no age limit
in I11), and it treats a `FAILED` verdict as closed. Every condition of I11 is also a condition
here, so the connector's gate is never open where the server's is closed; it can be closed where
the server's is open, which is the fail-closed direction. Aligning DM-10.I11's wording
with these two states is routed to T-0107. The server's gate is checked first, at Plan (ADR-0005 rule 7). The connector's gate is the
independent second check. `VerifyConnection` itself is never gated.

**The override comes from the server.** DM-25 is server state, guarded by step-up and audit. A
compromised server could forge an override and make the connector write with an over-privileged
identity. That is a residual (D11), and it is bounded: **an override bypasses TM-D1, never TM-D2.**
The Tier-0 refusal of §8.1 does not read the override, so every `tier0` target is still refused
(CC-WRITE-08).

### 8.3 Tier-0 context from the server, and the fail-closed rule (decision D10)

**The problem.** A connector sees one directory. Two parts of `tier0` need more than that:
- C16 (an AD object correlated with an Entra `tier0` principal) and E5 (the reverse) need both
  directories and the DM-20 correlation, which only the server holds;
- customer designations are server state (TM §6.4).

The connector must still not trust the server blindly.

**Decision.** Every `Plan` and `Apply` carries a request-scoped `Tier0Context` (fitness-proto P8),
built by the server per step from DM-20 and the designations. The connector uses it only under these
rules:

| # | Rule | On violation |
| --- | --- | --- |
| F1 | **Mandatory, per touched object.** The `Tier0Context` is present and holds a `CorrelationStatement` whose `object` is each object of the touched set the connector derives from the typed change, the target included (an object the change creates has no GUID yet; its kind's touched-set rule names the existing objects that stand for it, such as the parent). Each such statement has `correlation` set (`no_hybrid_link` or `peers`) and `computed_at` set; an unset timestamp is never read as the epoch. Absence never means "no correlation". The target's statement is checked at step 3, the others' at step 6. Statements about objects outside the touched set are ignored and counted in the connector's log. Two statements about one object are merged additively; one saying `no_hybrid_link` and another listing `peers` are contradictory | `TIER0_REFUSED` `CONTEXT_MISSING`; the contradiction is `CONTEXT_CONTRADICTED` |
| F2 | **Additive only.** A designated GUID marks that object `tier0` (`CUSTOMER_DESIGNATED`). `designated` covers the whole touched set: every touched object that is designated and every designated group any touched object is a member of. A peer with `peer_tier0` marks the object its statement is about `tier0` (C16 for AD, E5 for Entra) **in every correlation state**: `candidate`, `matched` or `broken`, as TM §6.4 requires ("protection is wider than authority"). No field of the context can remove an object from the connector's own set, and none exists that could | `TIER0_REFUSED` `REQUEST_CONTEXT` |
| F3 | **Fresh.** Each statement's `computed_at` is no older than the maximum statement age (provisionally 15 minutes; Plan and Apply of one step are minutes apart, and a bulk chunk re-fetches) and no more than 5 minutes in the future of the connector's clock. **What freshness defends against:** an *honest but stale* server, for example one whose correlation job lags or that replays a cached context. It is no defence against a lying server, which simply stamps the current time; that case is F6 | `TIER0_REFUSED` `CONTEXT_STALE` |
| F4 | **Bound to its object.** Each listed peer's `evidence` matches the object its statement is about, as re-read in step 7. AD object: `source_anchor` equals its `objectGUID` or `ms-DS-ConsistencyGuid` bytes, or `security_identifier` equals its `objectSid`. Entra object: `source_anchor` equals the base64-decoded `onPremisesImmutableId`, or `security_identifier` equals `onPremisesSecurityIdentifier` (DM-20.I1, I1a, I1b). A statement made for another object cannot be replayed onto this one | `TIER0_REFUSED` `CONTEXT_CONTRADICTED` |
| F5 | **Unknown is `tier0`.** A peer is inconsistent, and counts as `tier0`, when its `state` is `CORRELATION_STATE_UNSPECIFIED`; its `peer_kind` is `PROVIDER_KIND_UNSPECIFIED` or the connection's own kind; its `evidence` oneof is unset; or it has `peer_tier0` with an empty basis, or a basis without `peer_tier0`. Checked at step 4 for the target and step 6 for the others, before F4 | `TIER0_REFUSED` `REQUEST_CONTEXT` |
| F6 | **Omission is the residual.** A server that leaves out a correlated `tier0` peer or a designation, for any touched object, cannot be detected by a single-directory connector. C16 and E5 are *defined* by DM-20 correlations, which only the server computes. That is why marker heuristics are not used (option d below). Detective control: the connector logs the context's `tier0_revision`, the statement count and the peer count with every `Plan` and `Apply`, so the customer's connector-side log shows what it was told. Accepted as residual R-T0CTX-1, pending the security-architect confirmation in follow-up T-0108 | none |

**Options considered.**
- **(a) Request-scoped server context, additive and fail-closed: chosen.** It is the only option
  that needs no new credential and no new trust path. It protects against a server that is
  *wrong or stale*, which F1, F3, F4 and F5 refuse. It does not protect against a server that
  *lies by omission* (F6). Everything C1 to C15 and E1 to E4 cover stays independent of the server.
- **(b) The connector queries the other directory itself: rejected.** An AD connector would need
  Graph credentials, and an Entra connector LDAP credentials. That doubles the blast radius of a
  connector compromise, breaks one credential per connection (DM-11), and gives remote AD connectors
  internet egress to Graph. It also still lacks DM-20: correlation needs both inventories and the
  tenant's takeover-protection state (DM-20.I4 (f)).
- **(c) The peer connector signs its `tier0` set and the server relays it: rejected for v1.1.** In
  every v1 deployment the Entra connector runs embedded in the server, so its signature adds nothing
  against a compromised server. Correlation, the part F6 is about, is server-computed and would stay
  unsigned anyway. To be revisited if Entra connectors ever run remote.
- **(d) Refuse every write to any object with a sync marker unless the server proves it safe:
  rejected.** `ms-DS-ConsistencyGuid` stays set on objects that left sync scope. On an AD-only
  deployment no correlation can exist, so C16 is empty by definition. This option would refuse
  ordinary writes on every hybrid customer's users with no gain over F6.

### 8.4 `VerifyConnection`

`VerifyConnection(connection, run_kind, verification_id, enabled_families, managed_domains,
managed_roots, designated_tier0)` runs the forest-connection spec's V1–V9 (AD) or EV1–EV5 (Entra)
as the connector identity and streams:
- `header` (verification id, `check_list_version`, observed identity);
- `findings` chunks;
- `tier0_set` chunks (the connector's computed C1–C15 or E1–E4 set plus the designations, each with
  its bases, so the server can compare it with its inventory-derived set; a difference is a server
  health finding and never shrinks the connector's set);
- exactly one `completed` (verdict, each check's outcome, counts, `write_gate_openable`).

A stream without `completed` is an interrupted run: the verdict is `FAILED` with `run_interrupted`
(DM-10.I10). The run is **read-only**. It never requests the SACL; step 3 uses the SD-flags control
for DACL, owner and group only, through the typed security-descriptor primitive (T-0028, T-0118).
It is never gated. Its findings hold identifiers only (DM-24.I3). They map the forest's Tier-0
exposure, so the server stores them under FR-16 and never copies one into an audit event (DM-24.I5).

The server's inputs can only shape *what is compared*. A smaller `enabled_families` list yields more
excessive findings. Smaller `managed_roots` hide V9 warnings, which do not block. Smaller
`designated_tier0` is the F6 residual. V7 runs over the connector's computed set whatever the
inputs.

**The ticket's "excessive[] and missing[] with object, right and source"** are the
`RightsFinding`s of kind `EXCESSIVE_RIGHT` and `MISSING_RIGHT`. Each has `object`, `right`
(`RightRef`) and `source` (`RightSource`). They are one list rather than two, because every finding
has the same DM-24 shape and fingerprint. **The "refused flag"** is `verdict = REFUSED`, and
`write_gate_openable` is the gate's view (§8.2).

**Each verification step and the fields that express it** (AC 2):

| Source | Step | `check`, `kind`, `severity` | `object` | `right` | `source` | Other |
| --- | --- | --- | --- | --- | --- | --- |
| TM §6.5 | 1 Group membership: `tokenGroups` ∩ C1, C13 and designated groups | V7, `TIER0_GROUP_MEMBERSHIP`, block | the Tier-0 group | unset | `membership`: hops from the identity to the group, `primary_group_edge`, SID-only hops for foreign security principals | `object_tier0_basis` C1, C13 or `CUSTOMER_DESIGNATED` |
| TM §6.5 | 2 Constructed effective rights on each `tier0` object | V7, `EXCESSIVE_RIGHT`, block | the `tier0` object | `ad`: `WRITE_PROPERTY` + attribute `schemaIDGUID` (`allowedAttributesEffective`); `CREATE_CHILD` + class (`allowedChildClassesEffective`); `WRITE_OWNER`, `WRITE_DAC`, `WRITE_SACL` (`sDRightsEffective`) | `effective_attribute` (which of the three) | `object_tier0_basis` |
| TM §6.5 | 3 DACL evaluation: extended rights, confidential read, validated writes | V7, `EXCESSIVE_RIGHT`, block | the `tier0` object | `ad`: `CONTROL_ACCESS`, `VALIDATED_WRITE` or `READ_PROPERTY` (confidential), with `rightsGuid` or `schemaIDGUID` in `object_type` and the raw `access_mask` | `ace`: `on_object`, `inherited`, `inherited_from`, `trustee` SID, `trustee_group` | `object_tier0_basis` |
| TM §6.5 | 4 Excess in managed OUs | V9, `EXCESSIVE_RIGHT`, warn | the managed OU | `ad`: `GENERIC_ALL`, `GENERIC_WRITE`, `WRITE_DAC`, `WRITE_OWNER`, `DELETE_TREE`, or `WRITE_PROPERTY` on the R3/R7 never-delegate list | `ace` | `family` the mask is measured against |
| TM §6.5 | 5 Delegation configured on the identity | V7, `DELEGATION_CONFIGURED`, block | the identity, or the DC whose RBCD attribute lists it | `delegation`: `UNCONSTRAINED`, `CONSTRAINED`, `PROTOCOL_TRANSITION`, `RESOURCE_BASED` | `identity_attribute`, an `IdentityAttribute` enum: `USER_ACCOUNT_CONTROL`, `MS_DS_ALLOWED_TO_DELEGATE_TO`, `MS_DS_ALLOWED_TO_ACT_ON_BEHALF_OF_OTHER_IDENTITY` | |
| TM-D1 / §6.3 | Missing rights: R1 and R2 on each managed domain NC (V8, block); missing rights of enabled write families (V9, warn) | V8 or V9, `MISSING_RIGHT` | the domain NC head or managed OU | `ad` with the expected right | `expected_by` the family | `family` |
| FR-11 | An answer that could not be computed (unreadable object, unreachable domain or GC, ACL not returned) | V7, `COULD_NOT_VERIFY`, block | the object not decided | unset | unset | the check's outcome is `COULD_NOT_VERIFY`, never `PASS` |
| TM §6.6 | Deny-list application permission | EV3, `ENTRA_DENY_LIST_PERMISSION`, block | the service principal | `entra.app_permission` (`app_role_id`, `value`, `resource_app_id`) | `entra_assignment` (the appRoleAssignment id) | |
| TM §6.6 | Any directory role, active or PIM-eligible, held directly or through a role-assignable group the service principal belongs to (membership read; `[UNVERIFIED — lab G6]` that an SP member receives the role, so the conservative reading refuses) | EV3, `ENTRA_DIRECTORY_ROLE`, block | the service principal | `entra.directory_role` (`role_definition_id`, `ACTIVE` or `ELIGIBLE`, `directory_scope_id`) | `entra_assignment` | |
| TM §6.6 | Permission beyond the enabled rows | EV5, `EXCESSIVE_RIGHT`, warn | the service principal | `entra.app_permission` | `entra_assignment` | |
| TM §6.6 | Permission an enabled row needs and the app lacks | EV4, `MISSING_RIGHT`; block for the read rows the connection needs (tenant, user and group read and delta, admin pre-flight), warn for write rows | the service principal | `entra.app_permission` | `expected_by` the family | `family` |
| TM §6.6 | Extra key credential (not the certificate this connector holds; ours is recognised only by the SHA-1 of the public certificate in `key`, never by the caller-set `customKeyIdentifier`; `[UNVERIFIED — lab G7]` whether every read path returns `key`, and a key without it is extra) on the application **or** its service principal | EV5, `ENTRA_EXTRA_KEY_CREDENTIAL`, warn | the holder's object id | `entra.key_credential` (`key_id`, thumbprint, type, validity, `holder` = `APPLICATION` or `SERVICE_PRINCIPAL`; never key material) | unset | |
| TM §6.6 | Password credential (client secret) on the application **or** its service principal. The connector authenticates with a certificate only, so every one is extra | EV5, `ENTRA_PASSWORD_CREDENTIAL`, warn `[severity to confirm → T-0108]` | the holder's object id | `entra.password_credential` (`key_id`, validity, `holder`; never `secretText`, `hint`, `displayName` or `customKeyIdentifier`) | unset | |
| TM §6.6 | Owner on the application or service principal | EV5, `ENTRA_OWNER`, warn | the application or service principal | `entra.owner` (owner object id) | unset | |

**Mapping to a DM-24 Finding.** `check`, `code`, `severity`, `object` → `object_guid` and
`object_domain_sid` are copied as they are. `qualifier` is derived per kind:
- membership: the first group hop's GUID, or its SID for a foreign security principal;
- AD rights: `right.ad.object_type`, else `source.ace.trustee_group`, else `source.ace.trustee`;
- delegation: empty;
- Entra permission: `app_role_id`;
- role: `role_definition_id`, with `@<group id>` appended when held through a role-assignable group;
- key or password credential: `key_id` (the holder is already `object`);
- owner: the owner id;
- could-not-verify: empty.

The connector computes `fingerprint` with the DM-24.I4 recipe over exactly these values, so the
server stores, and a Tier0Override acknowledges, the value the write gate later compares (§8.2).

### 8.5 Describe and the reserved test

`OPERATION_PLAN = 7` and `OPERATION_VERIFY_CONNECTION = 8` are new. `OPERATION_APPLY = 100` keeps
its number. The `Describe` rules are in §4. `reserved_test.go` (§3) is the compile-time and test-time
pin, and fitness-proto P6 and P8 enforce the rest in CI.

### 8.6 Reserved names and extension

`Operation` holds `READ_SECRET = 101` and `VERIFY_USER = 102`. `Describe` reports them `RESERVED` for
every provider. The named secret operations (LAPS, BitLocker), each with its own capability and audit
kind (safe-primitives §3.7), and `VerifyUser` add their RPCs and messages in later tickets as
additive changes. The named operations that safe-primitives §3.6 reserves for escape controls
(`GroupMembersExpand`, `ForestWideLookup`, `RecycleBinBrowse`, `RestoreDeleted`) are not part of
this version. Each gets an `Operation` value and a security-architect review when it is specified.
`ChangeFeed` **is** the `ChangeTracking` named operation: DirSync's control exists only inside it.

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
| CC-DESC-01 | `Describe` on the lab | `provider_kind = AD`, contract `activediq.connector.v1`, `contract_minor` ≥ 1, directory identity equals the lab forest root GUID and SID; the six read operations `SUPPORTED`; `READ_SECRET` `VERIFY_USER` `RESERVED`; `VERIFY_CONNECTION` `SUPPORTED` once T-0096 lands; `PLAN` and `APPLY` `UNSUPPORTED` until the first `WriteKind` lands | S |
| CC-DESC-02 | Topology | domain, configuration and schema NCs with GUIDs and the domain SID; `forest_settings` reflects what is read, with an absent `tombstoneLifetime` left **unset** (no default applied) | S |
| CC-DESC-03 | DC facts | the lab DC has `dsa_guid`, `invocation_id` equal to its NTDS Settings object, site, `is_pdc_emulator = TRUE` after the `validFSMOs` cross-check; every fact Samba does not expose is `UNKNOWN`, never `FALSE` or `0` | S |
| CC-DESC-04 | Wrong directory identity | `DIRECTORY_IDENTITY_MISMATCH`; no read was issued | S |
| CC-DESC-05 | No DC reachable (closed port) | `UNREACHABLE_DC` with an attempt per DC and its cause; for a previously described connection, `Describe` answers from cache with `health = UNAVAILABLE` and the per-DC errors | S |
| CC-DESC-06 | Features | `FEED_DELETIONS` is `UNVERIFIED`, never `SUPPORTED`, on AD; `FEED_FULL_START` is `UNSUPPORTED` on AD; each feature carries its `source` | S |
| CC-DESC-07 | Limits | `max_page_size` equals the DC's `lDAPAdminLimits` value; `max_value_range` equals MaxValRange or the documented default when unreadable | S |
| CC-DESC-08 | DC topology completeness | a DC known from the configuration NC but stopped appears with `reachable = false` and an error; nothing is dropped | 2dc |
| CC-DESC-09 | RODC and `fSMORoleOwner` staleness | `is_rodc` from the nTDSDSA object; a stale role owner is not reported as PDC after the cross-check | W |
| CC-DESC-10 | Write-group capability consistency (v1.1) | `PLAN` and `APPLY` always share one state; `SUPPORTED` only with `VERIFY_CONNECTION` `SUPPORTED` and at least one `WriteKind` wired; neither is ever `RESERVED`; a provider without the handlers answers `CAPABILITY_UNSUPPORTED` (UNIMPLEMENTED on the wire) and writes nothing | S |
| CC-SCH-01 | `DescribeSchema` | streams to `last = true`; `objectGUID` kind `GUID`, `member` linked with a link id, `msDS-User-Account-Control-Computed` constructed, `unicodePwd` secret; fingerprint equals `Describe`'s | S |
| CC-SCH-02 | Schema-driven secrets (LF-38) | every `attributeSchema` with `searchFlags` & (`0x80` or `0x200` or `0x1000`) is `secret = true`, including a seeded custom attribute flagged `0x200` only; each is refused in a filter and in an attribute list with `SECRET_ATTRIBUTE` | S (needs seed addition, §10) |
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
| CC-SRCH-07 | Rejected inputs | unknown attribute and constructed attribute in a filter: `ATTRIBUTE_NOT_ALLOWED`; secret in a filter or an attribute list: `SECRET_ATTRIBUTE` (LF-22, 34, 37); `*` as attribute, no filter, no roots: `INVALID_ARGUMENT`; empty `And`, a 10,000-deep `Not`, a 20,000-character value: `FILTER_REJECTED` (LF-25, 28, 29) with no crash | S |
| CC-SRCH-08 | Filter widening attempts | `Substring` on a DN-syntax attribute, an `Eq` with an empty value, a bit match on a text attribute: `FILTER_REJECTED` with the rule id (LF-12, 15) | S |
| CC-SRCH-09 | Ranged attribute in a search | `member` of `GG-Big` returns `complete = false`, the first range (1,500 values on Samba with the explicit range request), and the entry is not completed by following ranges | S (Samba returns all 3,000 on a plain read: assert the request, not only the result) |
| CC-SRCH-10 | Referral | an injected continuation reference ends the stream with `UNEXPECTED_REFERRAL`, a count and no URL; no `SearchCompleted`; no page returned as complete (LF-32) | FI |
| CC-SRCH-11 | Global Catalog | a connection bound to port 3268 or 3269: `GLOBAL_CATALOG_NOT_ALLOWED` (LF-33) | S |
| CC-SRCH-12 | Typed decoding | for the seeded accounts: `accountExpires` ZERO, `MAX` and a timestamp; `pwdLastSet` ZERO; `lastLogonTimestamp` and `whenCreated` timestamps; `groupType` negative for security groups; `userAccountControl` flags; `objectGUID` and `objectSid` equal the canonical text from `ldbsearch` (rule 9) | S |
| CC-SRCH-13 | Pinned DC that does not exist | `UNREACHABLE_DC`, no silent switch to another DC | S |
| CC-SRCH-14 | Cancel after the first batch | the connector releases the LDAP search and its pinned connection within 2 s; a second search succeeds; the open-operations gauge returns to 0 | S |
| CC-SRCH-18 | Page-size normalisation | `page_size` 0 pages at `Limits.max_page_size`; `page_size` 1,000,000 is clamped to it; neither returns an error and both return every seeded user exactly once | S |
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
| CC-READ-04 | Constructed attributes | `tokenGroups`, `tokenGroupsGlobalAndUniversal` (granted to the R1 identity through Windows Authorization Access Group, TM §6.3 R1) and `msDS-User-Account-Control-Computed` read on a base read, with the R1 identity and not an administrator; the same names in a `ScopedSearch` attribute list: `ATTRIBUTE_NOT_ALLOWED`. The locked seeded account shows the lockout bit from the computed attribute, not from `userAccountControl` | S where Samba computes it; W otherwise |
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
| CC-FEED-25 | Secret named in a feed request | `unicodePwd`, the seeded `0x200`-only attribute and a LAPS attribute each fail the call with `SECRET_ATTRIBUTE` before any DirSync call (the harness's DC-side operation counter shows none); the same request without them succeeds | S (needs seed addition, §10) |

### 9.6 Cross-cutting

| ID | Case | Expectation | Lab |
| --- | --- | --- | --- |
| CC-ERR-01 | The same cause on both transports | the same `ErrorCode`, `retry` and detail type for each of the typed failures of §7 | S |
| CC-ERR-02 | Canary scan | known canaries (a bind password, a filter value, an attribute value, a cookie) never appear in any `message`, log line or span of any failure above | S |
| CC-ERR-03 | Reserved and unsupported operations | `Describe` lists them; no RPC exists for the two reserved names (`ReadSecret`, `VerifyUser`) | S |
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

### 9.8 VerifyConnection and the write group (v1.1)

`VerifyConnection` cases land with T-0096 (AD) and T-0097 (Entra). Cases marked **K0** run as soon as
the `Plan`/`Apply` handlers exist (T-0098), with no `WriteKind`, because steps 1 to 4 of §8.1 come
before the kind check. Cases marked **K1** need the first concrete kind and are written with it. All
TM-F-RIGHTS and TM-F-T0GUARD proofs (T-0066) are drawn from this table.

| ID | Case | Expectation | Lab |
| --- | --- | --- | --- |
| CC-VER-01 | Correctly delegated identity | `header` first, `completed` last; verdict `PASS`; V7 `PASS`; no block finding; a `MISSING_RIGHT` for each enabled family whose rights were deliberately not granted | S |
| CC-VER-02 | Identity in Domain Admins directly, through a nested group, and through its primary group | `REFUSED`; one `TIER0_GROUP_MEMBERSHIP` per path with `object` = Domain Admins, basis C1, hops in order, `primary_group_edge` on the primary-group path | S |
| CC-VER-03 | Identity in Account Operators | `REFUSED`, `TIER0_GROUP_MEMBERSHIP`, basis C1 | S |
| CC-VER-04 | GenericAll on the Domain Controllers OU | `EXCESSIVE_RIGHT` on the OU, basis C6, `GENERIC_ALL`, `ace` source | S; W for exact ACE semantics |
| CC-VER-05 | Write property `member` on a C1 group | `EXCESSIVE_RIGHT`, `WRITE_PROPERTY` with `member`'s `schemaIDGUID`, source `allowedAttributesEffective` | S |
| CC-VER-06 | Reset-Password inherited onto AdminSDHolder-protected users | `EXCESSIVE_RIGHT`, `CONTROL_ACCESS` with the Reset-Password `rightsGuid`, `ace` source with `inherited` | W (SDProp) |
| CC-VER-07 | Constrained delegation to `ldap/<DC>`; listed in a DC's RBCD attribute | `DELEGATION_CONFIGURED` `CONSTRAINED`; `RESOURCE_BASED` with `object` = the DC | S |
| CC-VER-08 | A `tier0` object the identity cannot read (deny ACE); a second domain unreachable | V7 `COULD_NOT_VERIFY`, verdict `COULD_NOT_VERIFY`, a `COULD_NOT_VERIFY` finding naming the object, `write_gate_openable = false`; never `PASS` (FR-11) | S (seed T-0158), FI |
| CC-VER-09 | WRITE_DAC on a managed, non-`tier0` OU | V9 `EXCESSIVE_RIGHT` warn with `family`; verdict stays `PASS` | S |
| CC-VER-10 | Fingerprints | two runs give identical fingerprints for the same exposures; a different right or group path gives a different one; each equals the DM-24.I4 recipe recomputed by the harness | S |
| CC-VER-11 | Read-only run | the proxy sees no add, modify, delete or modDN during the run; the SD-flags control never asks for the SACL | FI |
| CC-VER-12 | Stream cut before `completed` | the harness's caller records `FAILED` (`run_interrupted`); the connector's gate does not change | S |
| CC-VER-13 | Entra: `Directory.ReadWrite.All` granted; a directory role active and one eligible; a second certificate on the app; a certificate on the service principal; a client secret on the app and one on the service principal; an owner on the app; `User.Read.All` missing; a permission beyond the rows | EV3 block for the permission and both roles; `ENTRA_EXTRA_KEY_CREDENTIAL` EV5 warn with `key_id`, once with `holder` `APPLICATION` and `object` = the application id, once with `SERVICE_PRINCIPAL` and `object` = the service principal id; `ENTRA_PASSWORD_CREDENTIAL` EV5 warn for each secret with `key_id`, validity and the right `holder`, and the fake's `secretText` and `hint` values appear in no message, log line or span; EV5 warn with the owner; EV4 `MISSING_RIGHT` block; EV5 `EXCESSIVE_RIGHT` warn | Graph fake in CI; E |
| CC-VER-14 | `tier0_set` | includes the lab's C1 groups and their transitive members, `krbtgt`, the DC and its OU, AdminSDHolder and the NC heads, each with its bases; `designated_tier0` inputs appear as `CUSTOMER_DESIGNATED` | S |
| CC-WRITE-01 | TM-F-T0GUARD, server guard off: `Plan` and `Apply` on a Domain Admins member, Domain Admins, the DC computer, a GPO linked to the DC OU, AdminSDHolder | `TIER0_REFUSED` stage `CONNECTOR_SET`; the DC-side operation counter shows **no directory call** | S, K0 |
| CC-WRITE-02 | A user added to Domain Admins after the last `VerifyConnection` | `TIER0_REFUSED` stage `LIVE_REREAD`; reads only, no write | S, K1 |
| CC-WRITE-03 | `Tier0Context` absent; no statement for the target (only one for another object); `correlation` unset; `computed_at` unset; `computed_at` 16 minutes old or 6 minutes in the future; two statements for the target, one `no_hybrid_link` and one `peers` | `TIER0_REFUSED` `CONTEXT_MISSING` (absent, no statement, `correlation` unset, `computed_at` unset), `CONTEXT_STALE` (old, future) or `CONTEXT_CONTRADICTED` (the pair); no directory call | S, K0 |
| CC-WRITE-04 | C16: statement lists a peer with `peer_tier0`, once each as `candidate`, `matched` and `broken` | `TIER0_REFUSED` `REQUEST_CONTEXT` with basis C16; no directory call | S, K0 |
| CC-WRITE-05 | A peer whose evidence matches neither the target's anchor nor its SID | `TIER0_REFUSED` `CONTEXT_CONTRADICTED`, no write | S, K1 |
| CC-WRITE-06 | Inconsistent peer, one per case: `UNSPECIFIED` state; `peer_tier0` with no basis; `peer_kind` `UNSPECIFIED`; `peer_kind` equal to the connection's own kind; `evidence` unset with `peer_tier0` false. And a designated target | `TIER0_REFUSED` `REQUEST_CONTEXT` for each, before any directory call; basis `CUSTOMER_DESIGNATED` for the designation | S, K0 |
| CC-WRITE-07 | Write gate: no run since start; run older than the maximum age; V8 fail; V7 `COULD_NOT_VERIFY` with an override; V7 fail with an override missing one fingerprint; V7 fail fully acknowledged | `ACTIVATION_REFUSED_OVERPRIVILEGED` with `NOT_VERIFIED`, `STALE`, `INSUFFICIENT`, `COULD_NOT_VERIFY`, `OVERPRIVILEGED` (count 1); the last passes the gate | S, K0 |
| CC-WRITE-08 | A fully acknowledging override and a `tier0` target | still `TIER0_REFUSED`: an override never opens TM-D2 | S, K0 |
| CC-WRITE-09 | Entra: targets holding a role (E1), a role-assignable group, its member and its owner (E2), the owner of a privileged app (E3), a Directory Synchronization Account (E4), and an object correlated with AD `tier0` through the statement (E5) | `TIER0_REFUSED` before any Graph call (the fake's call log is empty after the gate's reads) | Graph fake, K0; E |
| CC-WRITE-10 | `WRITE_KIND_UNSPECIFIED` on a non-`tier0` target with an open gate | `INVALID_ARGUMENT`; `Describe` still reports `PLAN` and `APPLY` `UNSUPPORTED` | S, K0 |
| CC-WRITE-11 | `Apply` without a precondition; with a wrong `plan_digest`; after the target changed; retried after a successful write | `INVALID_ARGUMENT`; `INVALID_ARGUMENT` `PlanDigestMismatch` with no directory call; `TARGET_CHANGED` with nothing written; `ALREADY_APPLIED` with `read_back` | S, K1 |
| CC-WRITE-12 | Both transports, every refusal above | the same code, stage and gate state (extends CC-ERR-01); the remote connector's local log has the step key, attempt, acting principal and plan digest of each call, refusals included (TM-TB6-T5) | S |
| CC-WRITE-13 | Canary scan of the write group and `VerifyConnection` | no credential, attribute value, key material or peer list appears in any `message`, log line or span (extends CC-ERR-02) | S |
| CC-WRITE-14 | Touched set beyond the target (first kind with a second touched object, for example add-member: the user and the group): (a) the group's statement lists a `candidate` peer with `peer_tier0` (Entra E2 group); (b) the context has a statement for the user only; (c) the group is in `designated`; (d) the group's statement is 16 minutes old | (a) `TIER0_REFUSED` `REQUEST_CONTEXT`, basis C16, `object` = the group; (b) `CONTEXT_MISSING`, `object` = the group; (c) `REQUEST_CONTEXT`, `CUSTOMER_DESIGNATED`; (d) `CONTEXT_STALE`. All before any directory call (step 6) | S, K1 |
| CC-WRITE-15 | A target that became `tier0` through a **live** basis after the last `VerifyConnection`: (a) granted Get-Changes and Get-Changes-All on the domain head (C11); (b) `TRUSTED_FOR_DELEGATION` set (C12); (c) an OU into which a DC computer was moved (C6) | `TIER0_REFUSED` `LIVE_REREAD` with basis C11, C12 or C6; reads only, no write | S, K1 |
| CC-WRITE-16 | Residual R-T0SET-1 made visible: a GPO newly linked to the Domain Controllers OU after the last `VerifyConnection`, then written | the connector does **not** refuse (basis C9 is **set**), and the case asserts that; after the next `VerifyConnection` the same write is `TIER0_REFUSED` `CONNECTOR_SET`, basis C9. The test pins the residual so that narrowing it is a deliberate change | S, K1 (the first kind that can target a GPO) |

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

**v1.1 decisions (T-0091), for the reviewers:**

- **D10. Cross-directory Tier-0 context reaches the connector in the request, additive and
  fail-closed** (§8.3 F1 to F6; options a to d). Omission by a compromised server is residual
  R-T0CTX-1. The security-architect confirms or tightens it in T-0108.
- **D11. The connector's write gate mirrors DM-10.I11 and accepts the server's override** (§8.2).
  A forged override opens TM-D1 only, never TM-D2. Also in T-0108.
- **D12. The gate state is in memory, not persisted.** A restart closes the gate (`NOT_VERIFIED`)
  until the next run, which the server's I11 gate triggers. The alternative, a persisted signed
  verification, would add key management to the connector for a few minutes of availability after
  a restart.
- **D13. The target's Tier-0 refusal precedes the kind and capability checks** (§8.1 steps 4 to 5),
  so the guard is provable before any `WriteKind` exists (K0 cases) and never depends on the kind.
- **D14. `TARGET_CHANGED` is a new code**, beyond the two the ticket named. ADR-0005 rule 4's
  conditional write needs a typed "precondition failed, nothing written" answer, so the pipeline can
  record `stale_state` without classifying on text.
- **D15. `VerifyConnection` streams** (header, findings, Tier-0 set, completed), because findings are
  bounded by the Tier-0 set and the managed OU count, not by one message (DM-24.I7). It also returns
  the connector's own Tier-0 set, so the server can detect a divergence from its inventory-derived set.
- **D16. Provisional limits:** a maximum statement age of 15 minutes and a maximum verification age
  of 26 hours `[OPEN → T-0098, T-0108]`.
- **D17. fitness-proto gains P8** (write-group requests carry a `Tier0Context` holding repeated `CorrelationStatement`s), and P6 no longer
  reserves `Apply` but still requires `OPERATION_APPLY`.

**v1.1 rework (T-0091 review, 2026-10-22):**

- **D18. One `CorrelationStatement` per touched object.** The first draft bound one statement to the
  target, so C16 and E5 for the other objects of the touched set had no field. `Tier0Context.statements`
  is repeated, `designated` covers the whole touched set, and F1 refuses `CONTEXT_MISSING` for any
  touched object without a statement (§8.3; CC-WRITE-14). Field 1 (`correlation`) is reserved.
- **D19. Step 7 re-reads named facts per basis** (§8.1 table). C1–C8, C10–C12, C14, C15, E1, E2 and E4
  are re-read live, so a target granted DCSync rights or delegation since the last run is refused
  (CC-WRITE-15). C9, the C13 groups without a well-known RID, C12's DC list and E3's privileged-app list
  rest on the connector set: residual **R-T0SET-1**, bounded by the maximum verification age, pinned
  by CC-WRITE-16 and routed to T-0108.
- **D20. The step-7-to-write window is declared** as residual **R-T0RACE-1**, the same window as
  ADR-0005 rule 7's: a conditional modify on the target does not see a membership, DACL or ancestry
  change elsewhere.
- **D21. Entra credentials cover both holders and both kinds.** `EntraKeyCredential` and the new
  `EntraPasswordCredential` (key id and validity only) carry an `EntraCredentialHolder`, and a new
  finding kind `ENTRA_PASSWORD_CREDENTIAL` reports client secrets (EV5 warn; severity to confirm in
  T-0108). `RightSource.identity_attribute` is an `IdentityAttribute` enum (field 4 reserved).
- **D22. Unset fields fail closed.** An unset `computed_at` is `CONTEXT_MISSING`; an unset `evidence`
  or an unspecified or same-directory `peer_kind` makes a peer count as `tier0` (F1, F5; CC-WRITE-03,
  -06). F3 states it defends against an honest-but-stale server only.
- The connector's write gate is described as stricter than DM-10.I11 (§8.2), with the DM-10.I11
  alignment routed to T-0107.

v1.1 follow-ups: T-0108 (security-architect: TM §6.2, §6.4 and §16.1 amendments, and confirmation of
D10, D11 and D16), T-0109 (backend-engineer: `directory/client` builds the `Tier0Context` and the
override, and maps the new errors), T-0107 (solution-architect: align blueprint §7.1, DM-24 and DM-25).
The existing build tickets implement the rest: T-0096 (AD `VerifyConnection`), T-0097 (Entra
`VerifyConnection`), T-0098 (`Plan`/`Apply` handlers), T-0093 and T-0095 (classifiers), T-0100
(activation gate), T-0066 (the TM proofs, drawn from §9.8).

## Sources

- DirSync: [Polling for changes using the DirSync control](https://learn.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-the-dirsync-control) · [MS-ADTS DirSync](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/2213a7f2-0a36-483c-b2a4-8574d53aa1e3) · [MS-DRSR ProcessDirSyncSearchRequest](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/0e61ce24-eac7-40d1-a014-37854e932b43) · [MS-DRSR cycle start](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/eb6876c5-6997-4541-8165-3844e46b464d) · [MS-ADTS LDAP extended controls](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea)
- Ranges and paging: [Attribute range retrieval](https://learn.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval) · [RFC 2696](https://www.rfc-editor.org/rfc/rfc2696) · [LDAP policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99)
- Directory facts: [MS-ADTS rootDSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db) · [invocationId](https://learn.microsoft.com/en-us/windows/win32/adschema/a-invocationid) · [KB 892806, viewing Deleted Objects](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/non-administrators-view-deleted-object-container)
- Samba: [CVE-2023-4154](https://www.samba.org/samba/security/CVE-2023-4154.html) · [dirsync.c](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/dirsync.c)
- Entra: [delta query](https://learn.microsoft.com/en-us/graph/delta-query-overview) · [throttling](https://learn.microsoft.com/en-us/graph/throttling)
- v1.1, write group and rights check: [allowedAttributesEffective](https://learn.microsoft.com/en-us/windows/win32/adschema/a-allowedattributeseffective) · [sDRightsEffective](https://learn.microsoft.com/en-us/windows/win32/adschema/a-sdrightseffective) · [Entra Connect source anchor design](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-design-concepts) · [Graph user resource (onPremisesImmutableId, onPremisesSecurityIdentifier, onPremisesSyncEnabled)](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0) · [application addKey](https://learn.microsoft.com/en-us/graph/api/application-addkey?view=graph-rest-1.0) · [passwordCredential resource (hint, secretText, keyId)](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0) · [servicePrincipal resource (keyCredentials, passwordCredentials)](https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0) · [tokenGroups](https://learn.microsoft.com/en-us/windows/win32/adschema/a-tokengroups) · [memberOf is a back-link](https://learn.microsoft.com/en-us/windows/win32/adschema/a-memberof) · [RFC 4511 §4.6 Modify](https://www.rfc-editor.org/rfc/rfc4511#section-4.6). Internal: threat-model §6.2 to §6.6 and §6.8, domain-model DM-10.I8 to I11, DM-20, DM-24, DM-25, ADR-0005 rules 2, 4, 5 and 7, forest-connection spec §7 (V1 to V9, FR-10 to FR-13, FR-35).
- Internal: `knowledge/development/domain/ad-change-notifications.md` (T-0018), `knowledge/development/runbooks/ad-lab.md` §5, and the ad-expert consult recorded in the T-0064 notes. The Samba statements in the consult (no `MoreResults`, `;range=0-0`, skipped removed links) come from a reading of the source, not a run, and are `[UNVERIFIED lab]` until CC-FEED-04 and CC-FEED-21 run.

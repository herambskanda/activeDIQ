---
title: "Safe primitive P8: OData query and key-segment builder for Microsoft Graph"
date: 2026-10-22
updated: 2026-10-22
status: review
owner: heramb
ticket: T-0106
sources_last_checked: 2026-10-22
---

# P8: OData `$filter`, query options and key segments (`odata`)

This is a sibling of [safe-primitives.md](safe-primitives.md), like P6. Rules R1–R9, the corpus
format and the FF-SP gate in that document (§1, §8) apply here unchanged. This document adds one
primitive, one corpus unit (`odata`) and one FF-SP3 rule family (`odata-*`).

**Why now.** T-0094 builds Graph URLs by concatenation. The cases are `"servicePrincipals(appId='"+id+"')"`
and `q.Set("$filter", "principalId eq '"+principalID+"'")`, at `internal/connector/graph/reads.go`
lines 125, 142, 198, 242 and 253 (main at `7cf9dfd`). Each is safe today for one reason only: the value
next to it is checked against a GUID regex (`needGUID`, or `guidRE` on `ClientID` in `client.go:71`).
The next Graph features use free text: UPN, `mail` and `displayName` lookups for bulk create and modify,
account actions and groups (ADM-160, ADM-162, ADM-164;
[v1 scope](../../business/scoping/v1-scope-options.md)). If they copy this pattern, a value such as
`x' or 1 eq 1 or userPrincipalName eq 'y` turns a single-user lookup into a tenant-wide match. Once
that match feeds a block, delete or reset, the action lands on the wrong account. That is PatchIQ's
hand-built-string failure, ported to Graph (`../UEM/knowledge/development/legacy/patchiq-postmortem.md`
§11 #1, #10). FF-SP3 does not catch it today. The filter-shape regex in
`tools/fitness/safeprim/scan/goscan.go:423` knows LDAP attribute names, not OData operators.
`appId='` and `principalId eq '` pass it.

| # | Primitive | Bans | Tiers | Implementer | Corpus unit |
| --- | --- | --- | --- | --- | --- |
| P8 | `odata`: typed property declarations, filter AST (`Eq`, `In`, `And`), query options, key-segment and path renderer, strict subset parser for tests and the fake Graph | `$filter`/`$search`/`$orderby`/`$select`/`$expand` text outside the primitive; key segments glued from strings; quote doubling outside the primitive; `url.Values` or `RawPath`/`RawQuery` assembly of Graph URLs in feature or connector code | S only. Tier A has no Graph access (ADR-0002 rule 3). Tier W builds none (§7) | directory-engineer (primitive and migration); devops-engineer (FF-SP3 rule) | `odata` |

Package: `internal/directory/odata`, beside `ldapfilter`, for the same reason. Feature modules build
filter ASTs and pass them to the connector, and only the connector speaks HTTP to Graph (FF-SP1). The
Graph property declarations live in `internal/directory/odata/graphschema`. Blueprint §1.1 gains this
path in the build ticket (§9).

## 1. What the grammar requires

- **String literals are single-quoted, and an embedded quote is doubled.** "Single quotes within
  string literals are represented as two consecutive single quotes": `People('O''Neil')` is valid and
  `People('O'Neil')` is not
  ([OData 4.01 URL Conventions §2.2](https://docs.oasis-open.org/odata/odata/v4.01/odata-v4.01-part2-url-conventions.html)).
  Microsoft Graph documents the same rule for `$filter`, with the example
  `subject eq 'let''s meet for lunch?'`
  ([Graph query parameters, "Escaping single quotes"](https://learn.microsoft.com/graph/query-parameters)).
- **`%27` is a quote too.** The ABNF lets a quote be written as `'` or as `%27`, and a doubled quote as
  any mix of the two
  ([OData 4.01 ABNF](https://docs.oasis-open.org/odata/odata/v4.01/csprd06/abnf/odata-abnf-construction-rules.txt)).
  A server whose parser accepts `%27` *after* its own percent-decoding turns a literal `%27` in our
  value into a delimiter. That is why §3 rule V3 refuses percent triplets.
- **The server decodes once, after splitting.** It splits the undecoded query at `&` and `=`, then
  percent-decodes "exactly once" (URL Conventions §2.1). So a `&` or `=` that we percent-encode inside
  a value cannot start a new query option. Graph's own page also says "Sometimes, you need to
  double-encode values" without saying when
  ([Graph query parameters, "Encoding query parameters"](https://learn.microsoft.com/graph/query-parameters)).
  We treat a second decode somewhere in Graph as possible `[UNVERIFIED — lab OD-L1]` and design for it
  (V3).
- **System query option names may lack the `$` and are case-insensitive** in 4.01. The same option
  "MUST NOT be specified more than once" (URL Conventions §5.1). So `filter=`, `$FILTER=` and
  `%24filter=` are all `$filter` to a 4.01 service. The FF-SP3 rule matches every spelling (§6).
- **Key-as-segment:** "Forward-slashes in key value segments MUST be percent-encoded" and "single
  quotes within key value segments are treated as part of the key value" (URL Conventions §4.3.6).
  Graph documents the parenthesised form for UPNs that start with `$`, for example
  `/users('$AdeleVance@contoso.com')`, and `#` as `%23` for B2B guest UPNs
  ([Graph user get](https://learn.microsoft.com/graph/api/user-get)).
- **`in` takes a parenthesised, comma-separated list of primitive literals**, for example
  `Name in ('Milk', 'Cheese')` (URL Conventions §5.1.1.1.11).
- **Entra UPNs** allow `A–Z a–z 0–9 ' . - _ ! # ^ ~`, one `@`, at most 113 characters, and at most 64
  before the `@`
  ([Entra account restrictions](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy)).
  The apostrophe is legal, so `O'Neil@…` is a real input. `/` is not. Microsoft's own `$AdeleVance`
  example contradicts that character list, so P8 does not validate UPN syntax (that belongs to a
  codec). It renders any string safely.

Go's `url.PathEscape`, used by today's `endpoint` helper, percent-encodes `'`, `(` and `)`. It leaves
`..` unchanged. So `servicePrincipals(appId='…')` goes on the wire as
`servicePrincipals%28appId=%27…%27%29`, and an unvalidated value of `..` would be a dot-segment
(checked with Go 1.x `net/url` in a scratch probe, 2026-10-22). Whether Graph routes the encoded
parenthesised form is `[UNVERIFIED — lab OD-L3]`. The fake Graph accepts it because it compares
strings. P8 replaces this helper (§4).

## 2. API sketch

Go names illustrate the ratified stack (ADR-0001). All types are sealed: unexported fields, no public
constructor from an unchecked `string` except the validating ones listed.

```go
package odata

// Name is an OData identifier: an entity set, navigation property, property or cast segment.
// Grammar: [A-Za-z_][A-Za-z0-9_]{0,127}, plus dotted casts (microsoft.graph.user) for Cast.
// It is a defined string type so untyped constants convert implicitly. Converting a non-constant
// string to Name outside this package is an FF-SP2 finding (analyzer `odataname`, §6).
type Name string

// Property declarations: only in package graphschema, one var per property, with its Edm type.
type Prop[V Value] struct{ name Name /* unexported */ }
func StringProp(n Name) Prop[String]        // Edm.String
func GUIDStringProp(n Name) Prop[GUIDText]  // Edm.String that carries a GUID (directoryObject id, appId): quoted
func GUIDProp(n Name) Prop[GUID]            // Edm.Guid: unquoted literal
func BoolProp(n Name) Prop[Bool]
func IntProp(n Name) Prop[Int]              // Edm.Int32/Int64; range checked by the declared width
func TimeProp(n Name) Prop[Time]            // Edm.DateTimeOffset, rendered UTC with Z

// Values. String validates (§3). GUID and GUIDText wrap the P3 attr/guid type, so no GUID regex
// lives in the connector any more.
func Str(s string) (String, error)
func GUIDOf(g guid.GUID) GUID
func GUIDTextOf(g guid.GUID) GUIDText
func BoolOf(b bool) Bool
func IntOf(i int64) Int
func TimeOf(t time.Time) (Time, error)

// Filter AST. No Or, Not, lambda (any/all), startswith/contains or $search in this version: each
// is an amendment with its own vectors (§8).
type Filter interface{ sealed() }
func Eq[V Value](p Prop[V], v V) Filter
func In[V Value](p Prop[V], vs ...V) (Filter, error) // 1..MaxIn values
func And(fs ...Filter) (Filter, error)                // 2..MaxAnd operands, depth ≤ MaxDepth

// Query options. $top, $count and $orderby are typed. $expand takes a navigation Name and a $select.
type Query struct{ /* unexported */ }
func (Query) Select(ps ...AnyProp) Query
func (Query) Filter(f Filter) Query
func (Query) Expand(nav Name, sel ...AnyProp) Query
func (Query) Top(n int) Query
func (Query) Count() Query
func (Query) OrderBy(p AnyProp, desc bool) Query

// Path segments.
type Segment struct{ /* unexported */ }
func Seg(n Name) Segment                                  // entity set or navigation: /groups, /members
func Key(id GUID) Segment                                  // key-as-segment: /<lowercase-guid>
func KeyStr(set Name, v String) (Segment, error)           // set('v'): UPN keys on /users
func AltKey[V Value](set Name, p Prop[V], v V) (Segment, error) // set(prop=literal): servicePrincipals(appId='…')
func Cast(n Name) Segment                                  // /microsoft.graph.user

type Request struct{ /* unexported */ }
func Get(segs ...Segment) Request
func (Request) With(q Query) Request
// URL resolves against the pinned Graph base (scheme, host and version path). It sets Path,
// RawPath and RawQuery itself; no caller touches them.
func (Request) URL(base *url.URL) *url.URL
```

**Unique lookups (C1).** A lookup that resolves an identity for a write, an approval, an RBAC decision
or a Tier-0 classification uses `graph.Client.Unique(ctx, Request) (DirectoryObject, error)`.
It returns `NotFound` for zero results and `NotUnique` for more than one; it never returns the first
result. The caller then compares the requested property with the returned object under
`strings.EqualFold`: Graph is the authority on matching, and this catches server-side folding such as
U+2019 matching `'`, `[UNVERIFIED — lab OD-L5]`. From then on the operation uses the returned `id`
(GUID) only, never the UPN, mail or display name. This is domain-model X3 ("a UPN in a CSV is resolved
to the object `id` at Plan and is never stored as a key";
[domain-model.md](../domain/domain-model.md)) and R9 applied to Entra. A filter cannot then widen into a
write even if a future defect slips past the renderer.

## 3. Rendering and validation

| Rule | Behaviour |
| --- | --- |
| **V1 String literal** | `'` + value with every U+0027 replaced by `''` + `'`. No other character is changed. The doubling happens here and nowhere else (R2) |
| **V2 Look-alike quotes are data** | U+2019, U+02BC, U+FF07, U+2032 and the rest are not delimiters in OData. They are left as they are, never doubled and never folded (R4) |
| **V3 Percent triplets refused** | A string value containing `%` followed by two hex digits, in either case, is error `PercentTriplet`. Fail closed: a server that decodes twice (§1) would read `%27` as a quote, and `%2F` as `/` in a key. The refusal is relaxed only if lab OD-L1 and OD-L2 show that Graph decodes exactly once, and that change updates OD-06, OD-07 and OK-07 in the same change. A bare `%` not followed by two hex digits is allowed and is encoded as `%25` |
| **V4 R3 at the boundary** | Invalid UTF-8 is `InvalidUTF8`. NUL, C0 controls, DEL and C1 controls (U+0080–U+009F) are `ControlChar`. Nothing is trimmed or replaced |
| **V5 Bounds (R5, provisional)** | `MaxString = 1024` bytes (`TooLong`); `MaxIn = 15` values (`TooMany`); `In()` with no values is `Empty`; `MaxAnd = 8` operands; `MaxDepth = 4` (`TooDeep`); a rendered URL longer than `MaxURL = 2048` bytes is `TooLong`. Graph's own limits are `[UNVERIFIED — lab OD-L6]`. Caps only tighten after the lab |
| **V6 Literal by Edm type** | `Prop[GUID]` renders the unquoted lower-case canonical form; `Prop[GUIDText]` renders it quoted; `Bool` renders `true`/`false`; `Int` renders decimal (range checked); `Time` renders RFC 3339 UTC with `Z`. Which Graph properties are `Edm.Guid` and which are `Edm.String` comes from Graph `$metadata`, cited per declaration in `graphschema`. Example: `appRoleAssignment.principalId` is `Edm.Guid` and `unifiedRoleAssignment.principalId` is `Edm.String` `[UNVERIFIED — lab OD-L4]`. Today's code quotes both |
| **V7 Canonical filter text** | `Eq`: `prop eq lit`. `In`: `prop in (lit, lit)`. `And`: every operand in parentheses, joined by ` and `. Nothing else |
| **V8 Query encoding** | Each option value is percent-encoded with `url.QueryEscape`, and the `+` it produces for a space becomes `%20`. So `&`, `=`, `#`, `+`, `'`, `(`, `)` and `,` in data are always encoded. Option names are emitted only as `$filter`, `$select`, `$expand`, `$top`, `$count` and `$orderby`, each at most once |
| **V9 Key segments** | `Key(GUID)` renders `/` + the canonical GUID. `KeyStr` and `AltKey` render `set(` [`prop=`] `'` value `')`. The parentheses, `=` and the delimiting quotes are literal (they are RFC 3986 sub-delims, valid in a path). The value is V1-doubled. Every byte outside `A–Z a–z 0–9 - . _ ~ @ '` is then percent-encoded, which covers `$` (as `%24`), `#`, `?`, `(`, `)`, space and all non-ASCII. `RawPath` carries this text and `Path` its decoding |
| **V10 No slash in a string key** | `/` and `\` in a `KeyStr`/`AltKey` string value are `SlashInKey`. Fail closed until lab OD-L2. Entra UPNs cannot contain either (§1), so no legitimate value is refused |
| **V11 No dot-segments** | Segment names are `Name`s, which cannot be `.` or `..`. A string key is always inside `('…')`. The path therefore never has a `.` or `..` segment |
| **V12 One base** | `Request.URL` takes the pinned Graph base. `@odata.nextLink` stays an opaque server URL, followed only after the existing host pin (`request.go:25`). P8 neither parses nor builds it |

## 4. Migration of the T-0094 call sites (part of the P8 build ticket)

| Site (main `7cf9dfd`) | Today | After |
| --- | --- | --- |
| `reads.go:125`, `:142` | `"servicePrincipals(appId='"+c.cfg.ClientID+"')"`, `"applications(appId='"+…+"')"` | `odata.AltKey("servicePrincipals", graphschema.ServicePrincipalAppID, odata.GUIDTextOf(c.clientID))`. `Config.ClientID` is parsed once into `guid.GUID` in `New`, so the regex in `client.go:71` goes |
| `reads.go:198` | `q.Set("$filter", "principalId eq '"+principalID+"'")` | `odata.Eq(graphschema.RoleAssignmentPrincipalID, …)` over a `guid.GUID` parameter |
| `reads.go:200` | `$expand` literal with a nested `$select` | `Query.Expand("roleDefinition", …).Expand("principal", graphschema.DirectoryObjectID)` |
| `reads.go:231` | constant `"isAssignableToRole eq true"` | `odata.Eq(graphschema.GroupIsAssignableToRole, odata.BoolOf(true))`. Constant filters go through the builder too, so the `$filter` literal exists in one package only |
| `reads.go:242`, `:253` | `appId='"+appID+"'` after `needGUID` | `AltKey` over `guid.GUID`. `needGUID` and `guidRE` are deleted (CLAUDE.md rule 6) |
| `reads.go:99–111` `q`, `paged` | `url.Values` with `$select`, `$top` | `odata.Query{}.Select(…).Top(c.cfg.PageSize)` |
| `request.go:96–107` `endpoint` | `url.PathEscape` per segment, `RawQuery` from `url.Values` | deleted; `get` takes `odata.Request` plus the pinned base. `list` takes the first `Request` and then the host-pinned nextLink |
| `graphtest/fake.go:253–310` | parses `servicePrincipals(appId='…` and `$filter` with string prefixes | parses with `odata/odatatest.ParseRequest`, a strict parser for exactly the V7/V9 subset that decodes the URL once, as Graph does. The fake then rejects anything the real primitive would not emit, and the parser is the round-trip oracle (§5) |

`client.go:114` builds the token URL with `url.PathEscape(cfg.TenantID)`. That is not OData and stays
as it is, but the tenant becomes `guid.GUID.String()` (P3) in place of a regex-checked string. The
public method signatures that take `string` IDs (`ServicePrincipalByID(ctx, id string)` and the like)
change to `guid.GUID`, so the caller parses once (R1). The only caller today is
`internal/connector/tier0/entra.go`.

## 5. Hostile vectors (corpus unit `odata`)

`F:` is the canonical decoded `$filter` text, which is the `render` expectation. `Q:` is the encoded
query value, which is the `query` expectation; it is given where encoding is the point. The property is
`graphschema.UserPrincipalName` (a `Prop[String]`) unless stated. Inputs follow the `\xNN` notation of
safe-primitives.md.

| ID | Call and input | Expected | Hostile |
| --- | --- | --- | --- |
| OD-01 | `Eq(upn, "alice@contoso.com")` | F: `userPrincipalName eq 'alice@contoso.com'` · Q: `userPrincipalName%20eq%20%27alice%40contoso.com%27` | false |
| OD-02 | `Eq(upn, "O'Neil@contoso.com")` | F: `userPrincipalName eq 'O''Neil@contoso.com'` · Q: `userPrincipalName%20eq%20%27O%27%27Neil%40contoso.com%27` | true |
| OD-03 | `Eq(upn, "x' or 1 eq 1 or userPrincipalName eq 'y")` | F: `userPrincipalName eq 'x'' or 1 eq 1 or userPrincipalName eq ''y'`, one literal and no `or` operator | true |
| OD-04 | `Eq(upn, "'")` | F: `userPrincipalName eq ''''` | true |
| OD-05 | `Eq(upn, "''")` | F: `userPrincipalName eq ''''''` | true |
| OD-06 | `Str("x%27 or true")` | error `PercentTriplet` | true |
| OD-07 | `Str("%2527")` · `Str("%2f")` | error `PercentTriplet` | true |
| OD-08 | `Eq(upn, "O’Neil")` | F: `userPrincipalName eq 'O’Neil'`, not doubled · Q: `…%27O%E2%80%99Neil%27` | true |
| OD-09 | `Eq(upn, "O＇Neil")` | F: not doubled · Q: `…%27O%EF%BC%87Neil%27` | true |
| OD-10 | `Eq(upn, "OʼNeil")` | F: not doubled · Q: `…%27O%CA%BCNeil%27` | true |
| OD-11 | `Eq(upn, "a&$filter=id eq 'x'")` | Q: `userPrincipalName%20eq%20%27a%26%24filter%3Did%20eq%20%27%27x%27%27%27`; the rendered query has exactly one `$filter` option | true |
| OD-12 | `Eq(upn, "a#b")` · `Eq(upn, "a+b c")` | Q: `…%27a%23b%27` · `…%27a%2Bb%20c%27` | true |
| OD-13 | `Str("a\x00b")` | error `ControlChar` | true |
| OD-14 | `Str("a\x1fb")` · `Str("a\x7fb")` · `Str("a\u0085b")` | error `ControlChar` | true |
| OD-15 | `Str` of bytes `61 ff 62` · of `ed a0 80` (an encoded surrogate) | error `InvalidUTF8` | true |
| OD-16 | `Str` of 1025 × `a` | error `TooLong` | true |
| OD-17 | `In(upn)` with 0 values · with 16 values | error `Empty` · `TooMany` | true |
| OD-18 | `In(upn, "a','b", "c")` | F: `userPrincipalName in ('a'',''b', 'c')`: two members, not three | true |
| OD-19 | `And` nested 5 deep · with 9 operands | error `TooDeep` · `TooMany` | true |
| OD-20 | `Eq(graphschema.AppRoleAssignmentPrincipalID, GUIDOf(7B3C…))` · same GUID on `RoleAssignmentPrincipalID` (`GUIDText`) | F: `principalId eq 7b3c…` (unquoted, lower case) · `principalId eq '7b3c…'` | false |
| OD-21 | `And(Eq(groupRole, BoolOf(true)), Eq(displayName, "a) or (b"))` | F: `(isAssignableToRole eq true) and (displayName eq 'a) or (b')` | true |
| OD-22 | `Str("50%")` · `Str("%zz")` | accepted. Q encodes `%` as `%25` | false |
| OK-01 | `Get(Seg("users"), Key(GUIDOf(…)))` | path `/v1.0/users/<lowercase-guid>` | false |
| OK-02 | `KeyStr("users", "$adele@contoso.com")` | raw path `/v1.0/users('%24adele@contoso.com')` | true |
| OK-03 | `KeyStr("users", "O'Neil@contoso.com")` | raw path `/v1.0/users('O''Neil@contoso.com')` | true |
| OK-04 | `KeyStr("users", "a/b")` · `"a\\b"` | error `SlashInKey` | true |
| OK-05 | `KeyStr("users", "..")` | raw path `/v1.0/users('..')`: one segment, no dot-segment | true |
| OK-06 | `KeyStr("users", "x')?$top=999#")` | raw path `/v1.0/users('x''%29%3F%24top%3D999%23')`, with no query and no fragment | true |
| OK-07 | `KeyStr("users", "a%2Fb")` | error `PercentTriplet` | true |
| OK-08 | `KeyStr("users", "adele_fabrikam.com#EXT#@contoso.com")` | raw path `/v1.0/users('adele_fabrikam.com%23EXT%23@contoso.com')` | false |
| OK-09 | `AltKey("servicePrincipals", ServicePrincipalAppID, GUIDTextOf(upper-case GUID))` | raw path `/v1.0/servicePrincipals(appId='<lowercase-guid>')` | false |
| OK-10 | `Seg(odata.Name(v))` with `v` a variable, outside `odata` | static: FF-SP2 `odataname` fails (`"kind":"static"`) | true |
| OK-11 | an `@odata.nextLink` whose scheme or host differs from the pinned base | `CodeIdentityMismatch`, no request sent (as today, `request.go:25`) | true |

Count: 43 records after `·` expansion (OD-07, -12, -14, -15, -17, -19, -20, -22 and OK-04 expand to
two or three), 35 hostile. The records marked `false` are OD-01, OD-20#1–2, OD-22#1–2, OK-01, OK-08 and
OK-09. That clears FF-SP4's floor of 10 hostile records per unit with room to spare. The corpus file
is `testdata/safe-primitives/odata.jsonl`, and the build ticket adds the `odata` row to the §8 table in
safe-primitives.md.

**Lab vectors** (`"kind":"lab"`, against a Graph test tenant, with the G-series Entra lab of the
threat model). Until they run, every record stays `"verified": "doc"`.

| ID | Question | Outcome that changes the spec |
| --- | --- | --- |
| OD-L1 | Does a filter value of `%27` (sent as `%2527`) match the literal three characters, or act as a quote? | Literal on every endpoint tested: V3 may be relaxed for `$filter`. Quote: V3 stays, and is recorded as a Graph defect |
| OD-L2 | Does `%2F` inside `users('…')` reach the key, or split the path? | Reaches the key: V10 may be relaxed (never needed for UPNs) |
| OD-L3 | Are `users('%24…')`, `servicePrincipals(appId='…')` with literal delimiters, and today's fully encoded `servicePrincipals%28appId=%27…%27%29` all routed? | V9 is amended to the form that routes |
| OD-L4 | `Edm.Guid` versus `Edm.String` for each `graphschema` GUID property: does Graph accept both quoted and unquoted? | `graphschema` types follow `$metadata`, whatever the answer |
| OD-L5 | Does `userPrincipalName eq 'O’Neil@…'` match a user `O'Neil@…`? | Either way C1's `EqualFold` check catches it. The answer goes into the AD/Entra semantics notes |
| OD-L6 | Graph's limits on `in` list length, filter clauses and URL length | V5 caps tighten to the observed limits, never loosen past them |

**Properties (FF-SP5).** Corpus-seeded fuzz on `Str`, `Eq`, `In`, `And`, `KeyStr` and `AltKey`:
- `odatatest.ParseRequest(render(x)) == x`;
- the decoded filter has exactly as many string literals as the AST has values;
- a decoded query never has a second option name;
- a rendered raw path has exactly the segment count of the `Request`.

`odatatest` is the oracle and also the fake Graph's parser (§4). A second, independent oracle is the
Microsoft OData ABNF test harness, if the licence register clears it for dev tooling; otherwise none
`[UNVERIFIED]`.

## 6. Lint and fitness rules (bans the unsafe alternative)

All rules run in `fitness-safeprim`. The home of P8 is `policy.OData = "internal/directory/odata"`.
Tests and tier L are exempt, as for P1–P7 (safe-primitives.md §2.1).
`internal/connector/graph/graphtest` is *not* exempt: it migrates to `odatatest` (§4).

| Rule | Family | Fails when (outside the home) |
| --- | --- | --- |
| `odata-option-literal` | FF-SP3, flagged on its own (`Always`) | a Go string literal whose text, case-insensitively, is or starts with a system query option name, with or without `$` and in plain or `%24` spelling: `$filter`, `filter=`, `%24filter`, and the same for `search`, `orderby`, `select`, `expand`, `apply`, `compute`, `skiptoken`, `top`, `count`, `skip`, `deltatoken` and `format`. The bare-name forms (`filter=`) are matched only with `=` or as the key argument of `url.Values.Set/Add`, so the English word "filter" is not flagged. **Every** `$filter` in product code outside the home is a finding, constant or not. That is what makes the builder the only path |
| `odata-filter-shape` | FF-SP3, when combined with data or carrying a printf verb | literals matching `(?i)\b(?:eq\|ne\|gt\|ge\|lt\|le\|has)\s+'` or `(?i)\bin\s*\(\s*'` or `(?i)\b(?:startswith\|endswith\|contains\|any\|all)\s*\(` or a closing `'` (with optional `)`) followed by `and`/`or` that ends the literal or is followed by another `prop op` clause. Two deviations from the first draft, both from running the rule on main: `in` needs its parenthesis (OData's `in` always has one, and the English "in '_'" matched), and `' and ` alone no longer matches (prose such as "digits, '_' and '.'" did) |
| `odata-key-shape` | FF-SP3, when combined with data or carrying a printf verb | literals matching `[A-Za-z_]\w*\(\s*(?:[A-Za-z_]\w*\s*=\s*)?'?\s*$` (an opening `set(`, `set('` or `set(prop='`) or `[A-Za-z_]\w*\(\s*(?:[A-Za-z_]\w*\s*=\s*)?'?%[-+# 0-9.]*[a-zA-Z]` (a printf verb inside the key parentheses, FX-3, from the T-0106 review). The closing piece `^'?\s*\)` of the first draft is dropped: it also matched the `')` that ends a `startswith(…)` piece (FX-6), and every key built from text has an opening piece that matches |
| `quote-doubling` | FF-SP3 (existing rule) | the existing check (`goscan.go:719–725`), with `policy.OData` added to its home list |
| `odataname` | FF-SP2, go/analysis pass (`tools/analyzers/odataname`) | a conversion to `odata.Name` from a non-constant expression, or a call of `odata.StringProp`/`GUIDProp`/… outside `internal/directory/odata/graphschema` |
| `graph-url-assembly` | FF-SP2, go/analysis pass (`tools/analyzers/graphurl`; category `graph-url-assembly`) | inside `internal/connector/graph/**`: an assignment to, or a `url.URL{…}` literal key (or unkeyed literal) of, any `url.URL` field (`Opaque`, `Host`, `Scheme`, `Path`, `RawPath`, `RawQuery`, `ForceQuery`, …); any *use*, not only a call, of the functions below (`p := url.Parse` is flagged); `url.PathEscape`/`QueryEscape`/`url.Values.Encode` except in the methods named in `policy.GraphTokenURL` (receiver *and* name; today `(*Client).bearer`, the client-credentials POST); `url.Parse`, `url.ParseRequestURI`, `url.JoinPath`, `(*url.URL).Parse`/`JoinPath`/`ResolveReference` except at the sites in `policy.GraphURLParse` (today `New`, the configured bases, and `list`, the host-pinned nextLink); `http.NewRequest*` anywhere except the sites in `policy.GraphHTTPSite` (`(*Client).get`, `(*Client).bearer`), and there only with a URL argument that is `x.String()` on a `*url.URL` (the `odata.Request.URL` result, or the nextLink parsed and checked against the pinned base in `get`); `http.Get`/`Head`/`Post`/`PostForm`, `(*http.Client).Get`/`Head`/`Post`/`PostForm`/`Do`, any `http.Request` composite literal and any write to `http.Request.URL`/`Host`, all except at `policy.GraphHTTPSite` |
| `web-odata` | FF-SP3 `web/` ESLint (`safe-primitives/web-odata`) | any `$filter`/`$search` literal, or a template literal containing ` eq '`. Our own API is not OData, and tier W never talks to Graph |

**CI fixtures (acceptance 2).** They are inline in `tools/fitness/safeprim/scan/odata_test.go`
(`TestODataFixtures`), written into a throw-away module at a package path *outside* the home, so they
are scanned as product code. Each fixture must produce exactly the named rules, and the test fails
if one passes or reports a different rule. `TestODataPreMigrationReadsFail` holds the pre-T-0117
`reads.go` lines verbatim. The ESLint half is in `web/eslint/safe-primitives.test.js`.
The fake Graph's own paging token is `fakepage=N`, not a system option name, so `graphtest` needs no exemption.

| Fixture | Code | Expected finding |
| --- | --- | --- |
| FX-1 | `q.Set("$filter", "principalId eq '"+id+"'")` (today's `reads.go:198`) | `odata-option-literal` + `odata-filter-shape` |
| FX-2 | `"servicePrincipals(appId='"+id+"')"` (today's `reads.go:125`) | `odata-key-shape` |
| FX-3 | `fmt.Sprintf("users('%s')", upn)` | `odata-key-shape` (verb) |
| FX-4 | `fmt.Sprintf("displayName eq '%s'", n)` | `odata-filter-shape` (verb) |
| FX-5 | `const p = "mail eq '"; f := p + x + "'"` | `odata-filter-shape` (through a const) |
| FX-6 | `strings.Join([]string{"startswith(displayName,'", x, "')"}, "")` | `odata-filter-shape` |
| FX-7 | `strings.ReplaceAll(v, "'", "''")` | `quote-doubling` |
| FX-8 | `raw := "%24filter=" + x` · `q.Add("filter", x)` · `q.Set("$Search", x)` | `odata-option-literal` |
| FX-9 | `q.Set("$filter", "isAssignableToRole eq true")`: constant, but outside the home | `odata-option-literal` |
| FX-10 | `u.RawQuery = v.Encode()` in a `internal/connector/graph` fixture | `graph-url-assembly` |
| FX-11 | `odata.Seg(odata.Name(userInput))` | `odataname` |
| FX-12 | `u, _ := url.Parse(base + "/users/" + upn); http.NewRequest("GET", u.String(), nil)` in a `internal/connector/graph` fixture | `graph-url-assembly` |
| FX-13 | `b.JoinPath("users", upn)` then `u.String()` into `NewRequest`, same place | `graph-url-assembly` |
| FX-14 | `url.URL{… Opaque: "//g/users/"+upn}` literal, and `u.Opaque = …`, in a `internal/connector/graph` fixture | `graph-url-assembly` |
| FX-15 | `u.Host = h`, same place | `graph-url-assembly` |
| FX-16 | `p := url.Parse; p(base+upn)`, same place | `graph-url-assembly` |
| FX-17 | `http.NewRequest("GET", u.String(), nil)` in a function not listed in `policy.GraphHTTPSite` | `graph-url-assembly` |
| FX-18 | `http.Get(base+…)`, `c.Get(base+…)`, and `c.Do(&http.Request{URL: u})` (or a write to `req.URL`/`req.Host`) in a function not listed in `policy.GraphHTTPSite` | `graph-url-assembly` |
| FX-N1 | negative control: `odata.Get(odata.Seg("users")).With(odata.Query{}.Filter(odata.Eq(graphschema.UserPrincipalName, v)))` | no finding |
| FX-N2 | negative control: a log message `"filter applied"`, and a struct field named `Filter` | no finding |

The migration (§4) and the rule must land in this order: primitive and migration first, then the
rule. The rule's ticket depends on the migration ticket, so `make ci` never goes red on main. Today's
`reads.go` is FX-1 and FX-2 verbatim, so turning the rule on early is itself the proof that it
catches them.

## 7. Tier W

Tier W builds no OData. The console calls the activeDIQ API (ADR-0004), which is not OData.
Entra object pickers send a GUID (`GUIDRef`) or opaque search text. The server renders that text with
P8, and with C1 when a single object is meant. This is the same contract as the P1/P2 rows in
safe-primitives.md §2.1.

## 8. Out of scope and how to extend

- **`$search`** has its own quoting (`"displayName:…"` inside double quotes) and a documented Graph
  issue with encoded `&`
  ([Graph query parameters](https://learn.microsoft.com/graph/query-parameters)). It stays banned
  (`odata-option-literal`) until a P8 amendment adds `Search` with its own vectors.
- **`startswith`/`endswith`/`contains`, `Or`, `Not` and lambdas** (`any`, `all`) are left out. Each is
  an amendment with vectors, because each widens what a filter can match. `In` covers the set-match
  need.
- **Writes.** JSON bodies to Graph are not OData URL text. They are encoded by `encoding/json/v2` from
  typed structs (ADR-0004 rule 6). Any write that addresses an object addresses it by `Key(GUID)`,
  after C1.
- **Exchange OPATH** stays banned (safe-primitives.md §6.1 rule 2, §11).

## 9. Follow-ups (tickets)

- **T-0117 — P8 build + migration** (directory-engineer, `security-sensitive`): `internal/directory/odata`,
  `graphschema`, `odatatest`, the `odata.jsonl` corpus and its `implementations.json` row, fuzz
  targets, §4 migration including the fake Graph, `Client.Unique` (C1), `policy.OData` in `UnitHomes`,
  and blueprint §1.1 plus safe-primitives.md §8 table rows.
- **T-0118 — FF-SP3/FF-SP2 OData rules** (devops-engineer, `security-sensitive`, depends on T-0117):
  the §6 rules and fixtures FX-1 to FX-11, FX-N1 and FX-N2.
- **T-0119 — Graph lab vectors OD-L1 to OD-L6**: these join the Entra lab work (G-series in
  [threat-model.md](threat-model.md)). They need a Graph test tenant.

## Sources

- OASIS, OData Version 4.01 Part 2: URL Conventions, §2.1, §2.2, §4.3.6, §5.1, §5.1.1.1.11:
  https://docs.oasis-open.org/odata/odata/v4.01/odata-v4.01-part2-url-conventions.html
- OASIS, OData 4.01 ABNF construction rules (SQUOTE as `'` or `%27`):
  https://docs.oasis-open.org/odata/odata/v4.01/csprd06/abnf/odata-abnf-construction-rules.txt
- Microsoft Learn, Use query parameters to customize responses (Graph; encoding, escaping single
  quotes, `$search`): https://learn.microsoft.com/graph/query-parameters
- Microsoft Learn, Get user (Graph; `$`-prefixed UPN, `#` as `%23`):
  https://learn.microsoft.com/graph/api/user-get
- Microsoft Learn, Password policies and account restrictions in Microsoft Entra ID (UPN characters
  and lengths): https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy

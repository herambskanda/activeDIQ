---
title: "ADR-0004: The public API is one OpenAPI 3.1 contract, one file per tag, generated in-house into strict json/v2 types and per-tag handlers on net/http.ServeMux, one permission per operation, and one /api/v1 that only grows"
date: 2026-10-02
updated: 2026-10-02
status: proposed
owner: heramb
kind: technical
ticket: T-0046
---

# ADR-0004: The public API is one OpenAPI 3.1 contract, one file per tag, generated in-house into strict `encoding/json/v2` types and per-tag handlers on `net/http.ServeMux`, one permission per operation, and one `/api/v1` that only grows

**Status:** proposed (rework 1, after the director's review of 2026-10-02). The factory-director ratifies it when reviewing T-0046, then files a `notice`. It becomes `accepted` when `fitness-api` (A1–A14 below) runs green in `make ci` on `main`.
**Kind:** technical. No customer, partner or brand sees the generator or the router. Customers see the result: one documented, stable, unmetered API. That result follows from decisions the CEO already made: the house stack (D-0003) and the API-first, unmetered positioning (parity matrix enhancement 18).
**Deciders:** solution-architect (author). api-engineer was consulted twice on 2026-10-02, both recorded on T-0046. The first consult covered the generator, router, client and tooling evaluation and a local test of `encoding/json/v2` defaults. The second, in the rework, covered in-house type emission, the size estimate and gaps in the construct table. factory-director ratifies. **Ticket:** T-0046. **Parity / scope refs:** ADM-188, ADM-189 (ADM-190 indirectly, through rate classes).

> Amendments (ratified ADRs only): none.
>
> **Rework 1 (before ratification).** The first draft generated Go models with oapi-codegen, but its templates emit `encoding/json` v1 for unions and for objects with additional properties, and its format types come from a package we reject. That would have let v1 decoding into the request path through nested values, including the filter AST. This version emits every Go type in-house from the restricted dialect (rule 4) and fixes the secret-bearing decode path (rule 6). It also closes the director's nits: ports for `apihost`, `authenticated` operations, CSRF and pre-auth limits in the chain, hostname-bound anonymous operations, and the exact-or-suffix secret-name match.

## Context

**The public API is the product boundary** (blueprint §0, §6). The console, ITSM integrations (ServiceNow, ServiceDesk Plus), customer scripts, and later the PowerShell module and the MCP server (ENH-11, M3) all call the same operations. The console has no private endpoints. Several decisions already constrain this ADR:

- **ADR-0001** chose Go 1.27 (pure Go, `CGO_ENABLED=0`) and React + TypeScript. It left the HTTP router and the OpenAPI generator to this ADR. Every tool needs a licence-register row first (F4).
- **ADR-0002** check T5 already fails a tenant-scope operation with a `tenant_id` or `X-Tenant-*` parameter, and marks platform operations `x-activediq-scope: platform` (`tools/fitness/tenancy/static/openapi.go`, which reads `api/openapi/`).
- **ADR-0003** (ratified, D-0013) makes the Registrar the only on-ramp. `Registrar.API(h apihost.TagHandlers)` is EP-2, and this ADR fixes its shape. A module ID **is** its OpenAPI tag. Modules may not touch `http.Handle`, `HandleFunc` or a `ServeMux`, because `apihost` owns the mux (M4). Adding a module edits only its own directory, its migration, **its OpenAPI file** and its architecture page.
- **Safe primitives §2.1** fixes the wire shapes for DNs (`GUIDRef` in, `{guid, dn, rdns}` out), filters (AST in) and PowerShell (display-only out). R3 says to reject and never repair: invalid UTF-8, unpaired surrogates and NUL are refused.
- **Safe primitives §5.6** says a secret-bearing body is read into a capped buffer the code owns, decoded with `secretjson.Decode`, then zeroed, and never streamed through a decoder. The `secretjson` analyzer (FF-SP2) reports any decode into a `Secret`-bearing type by any other route. Rule 6 says who does this for the API.
- **The threat model** asks this ADR for four things:
  - TM-D16 (§7.4, §7.6): exactly one `x-permission` per operation, deny by default, and an anonymous route set equal to a reviewed allow-list (AN-1 to AN-7, proof TM-F-ANON).
  - §9.7: secret fields are write-only, and a response linter fails any response schema that can carry one (proof TM-F-SECRETOUT, the CVE-2022-24978 lesson).
  - TM-TB2-T6: credentials never travel in a query string.
  - TM-Q2: rate limits and body caps are declared per operation in the contract.

**What PatchIQ teaches.** PatchIQ had a correct module interface with zero implementations. Its 36 subpackages were passed to a `NewRouter` with 53 parameters, and 94 of 156 handler files imported the store (`../UEM/knowledge/development/legacy/patchiq-postmortem.md` §5–§6, §11; ADR-0003 Context). A contract that is not the only way to serve a route becomes decoration.

**The ManageEngine baseline.** ADManager Plus ships two REST APIs. "v1" covers users, groups, computers, OUs and authtokens (ADM-188). "v2" publishes an OpenAPI document covering a subset (ADM-189). Calls are metered: 50 successful calls per technician per day, then US$1 per extra call per day (ADM-190; [API v2 intro](https://www.manageengine.com/products/ad-manager/active-directory-api/v2/introduction/)). The parity matrix scores ADM-188 as a lead and ADM-189 as parity. **ADM-188 and ADM-189 are rows about ManageEngine's two APIs. They are not a plan for ours to have two versions.**

**Facts that shape the choice.** These were checked 2026-10-02. "Tested" means a scratch program run by solution-architect on **go1.27.0 darwin/arm64**, with the outcome recorded on T-0046.

- **`encoding/json/v2` and `encoding/json/jsontext` are GA in Go 1.27** ([Go 1.27 release notes](https://go.dev/doc/go1.27)). In 1.27, plain `encoding/json` (v1) is implemented on top of v2 but **keeps v1 semantics**. `GOEXPERIMENT=nojsonv2` restores the old implementation.
- **Defaults of v2 Unmarshal (tested)** ([json/v2](https://pkg.go.dev/encoding/json/v2), [jsontext](https://pkg.go.dev/encoding/json/jsontext)). Nested values are covered too, with the error naming the JSON pointer.
  - **Rejected by default:** invalid UTF-8, escaped lone surrogates (`"\ud800"`), duplicate member names and trailing data.
  - **Matched case-sensitively:** member names.
- **What v2 does *not* do (tested).** These gaps are why rules 4 and 6 exist:
  - Unknown members, and wrong-case members such as `"A"` for `a`, are silently ignored unless `json.RejectUnknownMembers(true)` is set.
  - A string containing `\u0000` is accepted.
  - There is no required-member check: `{}` decodes into any struct.
  - `time.Time` accepts any RFC 3339 offset (`+05:30`).
- **A nested v1 method defeats the strict options (tested).** A type with a v1 `UnmarshalJSON([]byte)` method, nested inside a struct decoded by v2 with `RejectUnknownMembers(true)`, **accepts both an unknown member and a wrong-case member without error**. It decodes them with v1 semantics.
  - A type with a v2 `UnmarshalJSONFrom(*jsontext.Decoder)` gets the caller's options and rejects both. That holds whether it calls `json.UnmarshalDecode(d, …)` or buffers with `d.ReadValue()` and calls `json.Unmarshal(v, …, d.Options())`.
  - When a type has both methods, v2 calls `UnmarshalJSONFrom`.
- **`ReadValue` aliases the input buffer (tested).** When decoding from a `[]byte`, the `jsontext.Value` that a nested `UnmarshalJSONFrom` gets from `d.ReadValue()` points into the caller's buffer. A secret can therefore be unescaped straight from a buffer `apihost` owns, with no intermediate copy.
- **oapi-codegen** (Apache-2.0) gained "initial" OpenAPI 3.1 support in v2.8.0 (2026-07-17). v2.7.1 and v2.7.2 fixed code injection from malicious specs ([releases](https://github.com/oapi-codegen/oapi-codegen/releases)). Its model templates are not v2-clean. This was checked on `main` on 2026-10-02:
  - `pkg/codegen/templates/union.tmpl` builds discriminated unions on `json.RawMessage`, `json.Unmarshal`/`json.Marshal` (v1) and `runtime.JSONMerge`.
  - `additional-properties.tmpl` hand-writes v1 `UnmarshalJSON`/`MarshalJSON` for objects that mix `properties` with `additionalProperties`.
  - `imports.tmpl` offers `github.com/oapi-codegen/runtime`, `runtime/types` (`openapi_types` for uuid, date, email and binary) and `oapi-codegen/nullable` to generated files ([templates](https://github.com/oapi-codegen/oapi-codegen/tree/main/pkg/codegen/templates)).
- **ogen** (Apache-2.0, [repo](https://github.com/ogen-go/ogen)) brings its own router and the go-faster/jx codec (MIT). jx documents no UTF-8 or surrogate validation `[UNVERIFIED]`.
- **The TypeScript client.** openapi-typescript 7.13 (MIT) emits types only, for OpenAPI 3.0 and 3.1. openapi-fetch 0.17 (MIT) is a type-safe `fetch` wrapper of about 6 kB ([openapi-ts.dev](https://openapi-ts.dev/introduction)).
- **Lint, diff and cross-check tools.** vacuum (MIT, v0.30.6, Go, [repo](https://github.com/daveshanley/vacuum)) lints with Spectral-compatible rulesets for OpenAPI 3.0, 3.1 and 3.2. oasdiff (Apache-2.0, v1.33.0, Go, [repo](https://github.com/oasdiff/oasdiff)) detects breaking changes. ajv 8.20 (MIT, [npm](https://www.npmjs.com/package/ajv)) validates JSON Schema 2020-12. Its dependencies are MIT, plus fast-uri, which is BSD-3-Clause.

**What makes this non-obvious.** Taking a full-stack generator is the obvious move, and it fails three times:

1. Every mature Go generator either decodes with v1 semantics or replaces the mux that ADR-0003 gives to `apihost`. v1 semantics include repairing invalid input into U+FFFD, which could set a password nobody typed (`lessons.md`).
2. Every generator produces **one** server interface for the whole API. That is PatchIQ's `NewRouter` in a new shape: one type that must implement every module's operations.
3. **Taking only the types does not help either.** The model output of the leading Go generator is v1 code wherever the dialect is not trivial: unions, maps mixed with properties, and formats. Because a v1 method nested inside a v2 decode silently drops the strict options (tested), one generated union in the filter AST reopens the hole in a safe-primitive input.

json/v2 alone is not enough either. It does not check required members, it accepts NUL, and it accepts unknown members unless told otherwise.

The design below therefore emits every Go type of the contract from our own generator. It is restricted to a dialect small enough to emit correctly, and it decodes through v2 methods only. It keeps third-party tools where they are sound: TypeScript types, linting and breaking-change diff.

## Decision

We will define the public API as **one OpenAPI 3.1 contract, split into one file per tag under `api/openapi/`**, bundled into one document. **Our own generator, `tools/gen/api`, emits from it every Go type, decoder, validator and per-tag handler interface.** Modules hand those interfaces to the Registrar. The console must use a TypeScript client generated from the same bundle.

All of it is served by `apihost` on the standard `ServeMux`, with:
- strict `encoding/json/v2` decoding that reaches every nested value;
- one decode path for secret-bearing bodies;
- exactly one permission per operation;
- a closed problem catalogue;
- a single `/api/v1` that changes only additively.

Thirteen rules follow, and `fitness-api` enforces them.

### Rule 1: Source layout (owner of each path in brackets)

```
api/openapi/
  openapi.yaml            root: info, servers (/api/v1), securitySchemes, the tag list    [api-engineer]
  shared/*.yaml           components used by more than one tag: Problem and the catalogue,
                          paging, GUIDRef/ObjectView, filter AST, scalars, SecretInput     [api-engineer]
  modules/<id>.yaml       one per server module that serves API: its paths + its components [module owner]
  platform/<pkg>.yaml     one per kernel package that serves API (authn, jobs, audit, report…) [package owner]
  policy.yaml             security policy for the contract (rule 9)                          [security-architect]
```

- **Tags.**
  - A module's tag equals its module ID (ADR-0003 rule 3, `^[a-z][a-z0-9]{1,30}$`). A kernel package's tag is `platform.<pkg>`. The dot cannot appear in a module ID, so the two namespaces cannot collide.
  - Every operation has **exactly one tag**, and it must equal the tag of the file that declares it.
  - The root's tag list names each tag's file.
- **References mirror the import graph.**
  - A module or platform file may `$ref` only its own components and `shared/`. `shared/` may `$ref` only `shared/`. A cross-module reference fails A1.
  - A shape that two tags need moves to `shared/` (parameterise, don't clone). That move is reviewed by api-engineer and solution-architect.
- **Names.**
  - `operationId` is camelCase and unique across the bundle (`listUsers`, `resetUserPassword`).
  - Component names are PascalCase and unique across the bundle. A collision fails the bundle, never "last one wins".
  - Paths are kebab-case and have no trailing slash.
  - JSON members are camelCase.
- **Paths are relative to `servers: [{url: /api/v1}]`.** Directory objects are addressed by `objectGUID`, never by DN (api-design §2, safe-primitives §2.1).
- **The bundle is a generated artefact.** `tools/gen/api` merges the files under the rules above and normalises them: it orders deterministically and resolves cross-file `$ref` into `#/components/…`. It uses no third-party bundler.
  - The output is `internal/platform/apihost/spec/openapi.gen.json`. That file is committed, embedded in the server, and served as the operation `getApiDocument` (`GET /api/v1/openapi.json`, rule 5).
  - It is **the one input** of every generator, linter, diff and cross-check below, the TypeScript generator included. No tool reads the per-tag files directly.

### Rule 2: The OpenAPI dialect we write

We use OpenAPI **3.1** with the JSON Schema 2020-12 dialect ([OAS 3.1.1](https://spec.openapis.org/oas/v3.1.1)). The dialect is a closed list. `tools/gen/api` models exactly these keywords, and anything else fails A2 before any code is emitted. Rule 4's table maps each allowed construct to its Go type.

- **Allowed schema keywords:**
  - structure: `type`, `properties`, `required`, `additionalProperties`, `items`;
  - unions: `oneOf` with `discriminator`, and `const` (only on `kind`);
  - values: `enum`, `format` (the rule 4 list only), `pattern`;
  - bounds: `minLength`/`maxLength`, `minimum`/`maximum`, `minItems`/`maxItems`, `maxProperties`;
  - annotations: `description`, `title`, `examples`, `deprecated`, and `writeOnly` (only on `SecretInput`);
  - references: `$ref`.
- **Banned keywords** (each with the reason that cost us something elsewhere):
  - `anyOf`, `not`, `if`/`then`/`else`, `patternProperties`, `$dynamicRef`, `unevaluatedProperties`: undecidable or expensive to decode strictly.
  - `allOf`: composition hides which members an object has. Write the object out, or move the shared part to `shared/`.
  - `readOnly`: use separate request and response schemas instead.
  - `default`: a default is a server behaviour, not a wire fact. openapi-typescript may also type a defaulted member as present `[UNVERIFIED]`.
  - `uniqueItems`, `multipleOf`, `format` outside the list.
  - A `type: number`. There are no floats in v1; an amendment adds them when an operation needs one.
- **Objects.**
  - A request object declares `additionalProperties: false`. A response object never declares `additionalProperties: true`.
  - A **map** is an object with `additionalProperties: <schema>` and **no** `properties`. Mixing the two is banned, which removes the construct oapi-codegen's `additional-properties.tmpl` hand-decodes with v1.
  - An **enum** is reachable from requests or from responses, **never both**, `shared/` included, because a request enum is closed and a response enum is open. There is no `readOnly`, so a resource whose request and response differ uses two schemas (`UserCreate`, `User`).
- **Optional and nullable.**
  - Nullable means `type: [T, "null"]` and is allowed only on a **required** member. "Optional and nullable" is banned, because absent and `null` would mean the same thing.
  - A **PATCH** body is `application/merge-patch+json` ([RFC 7396](https://www.rfc-editor.org/rfc/rfc7396)). Every writable member is optional and maps to `Opt[T]` (rule 4), so the Go type keeps three states: absent, `null` and value.
- **Unions.** A `oneOf` must carry a `discriminator` whose property is `kind`. Every variant must be an object that declares `kind` as a single-value `const`, required. TypeScript narrows on that value and ignores `mapping`.
- **Numbers.**
  - Every `integer` declares `minimum` and `maximum` within ±(2⁵³−1). Otherwise JavaScript rounds it ([MDN: MAX_SAFE_INTEGER](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER)).
  - A larger value is `$ref: shared/scalars.yaml#/components/schemas/Int64String`.
- **Strings.**
  - `maxLength`/`minLength` count Unicode code points, as JSON Schema defines.
  - A `pattern` must lie in the intersection of RE2 and ECMA-262: no lookaround and no backreferences. A2 compiles every pattern with Go `regexp`, and the A7 cross-check runs it in ajv.
  - Timestamps are `format: date-time`. They decode from any RFC 3339 offset into UTC and always encode in UTC with `Z` (api-design §2).
- **Secrets.** A secret input field is `$ref: shared/secret.yaml#/components/schemas/SecretInput`. That schema is `writeOnly: true` and `x-activediq-secret: true`, and its Go type is `secret.Secret`. It is never a `string`, and rule 6 fixes its decode path.
- **Enums.** A request enum is closed: an unknown value is a validation error. An enum reachable from a response carries `x-activediq-enum: open`. Clients must accept values they do not know, and the generated TypeScript type admits them (rule 4).
- **Binary.** A binary payload is only ever a whole request or response body with its own media type (`application/octet-stream`, `text/csv`). There is no `format: binary` inside JSON.

### Rule 3: Vendor extensions (the complete list)

| Extension | Where | Required | Meaning |
| --- | --- | --- | --- |
| `x-permission` | operation | **yes, exactly one** | What `authz` checks before the handler runs (DM-33.I1, TM-D16). It takes one of three forms: a permission ID from the EP-6 catalogue; the literal `authenticated`, meaning any authenticated principal, for a rule 9 `authenticated` row; or the literal `anonymous`, for a rule 9 `anonymous` row. The name keeps its short form because DM-33 and the threat model already use it. |
| `x-activediq-scope` | operation | only for `platform` | ADR-0002: `platform` marks a platform-scope operation, and the default is `tenant`. |
| `x-activediq-stability` | operation | **yes** | `preview` or `stable` (rule 7) |
| `x-activediq-sunset` | operation | with `deprecated: true` | The first product release in which the operation may be removed (rule 7) |
| `x-activediq-limits` | operation | no | `{class, maxBodyBytes}` (rule 10). It defaults by method. |
| `x-activediq-anonymous` | operation | with `x-permission: anonymous` | The allow-list row it uses (`AN-4`, `AN-5`, `AN-7`) |
| `x-activediq-secret` | schema | on `SecretInput` only | The schema carries a secret, so it is write-only (rule 9) |
| `x-activediq-enum` | schema | on every enum reachable from a response | `open` (rule 2) |
| `x-activediq-parity` | operation | no | ManageEngine feature IDs, for traceability |

Any other `x-` key fails A2. Third-party generator keys (`x-go-type` and similar) have no meaning here, because no third-party Go generator reads the bundle.

### Rule 4: Generation

| Output | Generated by | From | Into |
| --- | --- | --- | --- |
| Bundle | `tools/gen/api` | `api/openapi/**` | `internal/platform/apihost/spec/openapi.gen.json` |
| Shared Go types, their decoders and validators, and the problem catalogue | `tools/gen/api` | bundle, `shared/` components | `internal/platform/apihost/apitypes/*.gen.go`, beside the hand-written scalars of the table below |
| Per-tag Go types, decoders, validators | `tools/gen/api` | bundle, filtered by tag | `internal/modules/<id>/api/*.gen.go`, `internal/platform/<pkg>/api/*.gen.go` |
| Per-tag handler interface, `Bind`, route rows | `tools/gen/api` | bundle | the same `api` packages |
| TypeScript types | openapi-typescript, fed the bundle, with open enums widened (below) | bundle | `web/src/api/schema.gen.d.ts` |
| Web client | openapi-fetch over those types, in `web/src/api/client.ts` (the one hand-written file in that directory: base URL, CSRF header, problem decoding) | — | `web/src/api/` |

**Every construct and the Go type that carries it.** The json/v2 column says how the strict options reach nested values. Every row except plain values either has a v2 method or has no JSON method at all.

| Rule 2 construct | Wire | Go type | Provided by | json/v2 behaviour |
| --- | --- | --- | --- | --- |
| Object (`properties`; request objects `additionalProperties: false`) | object | Generated struct. A required member is `T`, with no omit tag. An optional member is `*T` with `omitzero`. | `tools/gen/api` | **Generated `UnmarshalJSONFrom`:** a token loop with an exact, case-sensitive name switch. Each value is decoded with `json.UnmarshalDecode(d, &field)`, which passes the caller's options on. A presence bit is set per member. An unknown name is an error at `d.StackPointer()`. Encoding uses v2 reflection over the tags. |
| Map (`additionalProperties: <schema>`, no `properties`) | object | `map[string]T` | `tools/gen/api` | **Generated `UnmarshalJSONFrom`:** a token loop. Values go through `UnmarshalDecode`. `maxProperties` is checked. |
| Array (`items`) | array | `[]T` | `tools/gen/api` | Elements decode through their own type, so the options reach them. |
| `string`, `boolean`, bounded `integer` | value | `string`, `bool`, `int64` | `tools/gen/api` | Built in. No methods. |
| Request enum (closed) | string | `type E string` plus constants | `tools/gen/api` | Built in. Membership is checked by the generated validator. |
| Response enum (`x-activediq-enum: open`) | string | the same kind of type, never checked on encode | `tools/gen/api` | Built in. The TypeScript type is widened with `string & {}` through openapi-typescript's `transform` hook, or a post-pass if that hook cannot `[UNVERIFIED]`. A5's fixture proves an unknown value type-checks. |
| Required nullable member | value or `null` | `*T`, no omit tag | `tools/gen/api` | Built in: `null` becomes `nil`. `null` on a required non-nullable member is a validation error. |
| PATCH writable member | absent / `null` / value | `apitypes.Opt[T]`, with `omitzero` | hand-written in `apitypes` | `UnmarshalJSONFrom` / `MarshalJSONTo`. Absent stays the zero value. |
| Discriminated `oneOf` (`kind`) | object with `kind` | Generated sum type: a `Kind` field plus one pointer per variant, exactly one set. Recursive unions (filter `and`/`or`/`not`) go through pointers and slices. | `tools/gen/api` | **Generated `UnmarshalJSONFrom`:** `d.ReadValue()`, then read `kind` from that value, then `json.Unmarshal(v, &variant, d.Options())`. Each variant is a generated struct that declares `kind`, so its own decoder applies the unknown-member and case rules. A missing, unknown or wrong-case `kind` is a validation error. `MarshalJSONTo` writes the variant that is set. |
| Safe-primitive wire form (`shared/` `FilterAst`, `ReportAst`, `GUIDRef`, `ObjectView`) | as the primitive defines | **the primitive's own type** (P1, P5, P2/P3), through the binding table in `tools/gen/api` | the owning primitive | Must implement `UnmarshalJSONFrom` **and** `MarshalJSONTo` (A7 static). This way there is one AST type, not a generated copy plus a converter (parameterise, don't clone). A binding is a `security-sensitive` change. |
| `format: uuid` | string | `apitypes.UUID` | hand-written | v2 methods. Either case is accepted, and lowercase is always encoded ([RFC 9562 §4](https://www.rfc-editor.org/rfc/rfc9562#section-4)). |
| `format: date` | string | `apitypes.Date` | hand-written | v2 methods. Full-date only. |
| `format: date-time` | string | `apitypes.Timestamp` | hand-written | v2 methods. RFC 3339 with any offset decodes to UTC, and encodes with `Z`. `time.Time` never appears in a contract type. |
| `format: email` | string | `string` | `tools/gen/api` | Built in. The validator calls `apitypes.CheckEmail` (addr-spec only, no display name). |
| `Int64String` | string matching `^-?[0-9]{1,19}$` | `apitypes.Int64String` | hand-written | v2 methods. The value must fit in `int64`. |
| Binary body (`application/octet-stream`, `text/csv`) | bytes | `apihost.Upload` (a capped `io.Reader`) in, `apihost.Stream` out | `apihost` | Not JSON. |
| `SecretInput` | string | `secret.Secret` | P3 (safe-primitives §5.6) | **`UnmarshalJSONFrom` only.** It calls `d.ReadValue()`, which aliases `apihost`'s buffer (tested). It unescapes into a fresh, pre-sized `[]byte` and rejects NUL and invalid UTF-16 (PW-15, PW-16). It never calls `ReadToken`, because a string `Token` allocates a Go string nobody can zero. `MarshalJSONTo` returns `Unserializable`. There is no v1 `UnmarshalJSON`/`MarshalJSON` method. |

**The type-closure rule.** Every Go type reachable from an operation's `Input` or `Output` must be one of these:
- a generated type;
- a built-in, slice, map or pointer of allowed types;
- an `apitypes` scalar;
- `secret.Secret`;
- a type in the binding table.

**No reachable type implements the v1 `json.Unmarshaler` or `json.Marshaler` interfaces.** A7 checks this by reflection over the generated route table. That is what stops a v1 method nested anywhere, such as a union, a bound primitive or a future scalar, from reopening the tested hole.

**Validators.** Each generated type gets `validate(at jsontext.Pointer, errs *apitypes.Errors)`. `apihost` calls it after decoding and collects **every** violation, each with its JSON pointer. It checks:
- required members (from the presence bits);
- `null` on non-nullable members;
- closed enums;
- string length in code points;
- patterns;
- integer bounds;
- item and property counts;
- e-mail syntax.

v2's own error text names Go types, so `apihost` maps it to the `malformed-request` or `validation` problem and **never returns it**.

**Generated files and the build.**
- Generated Go files start with `// Code generated by tools/gen/api; DO NOT EDIT.`
- `make gen-api` regenerates everything. CI regenerates into a temporary tree and fails on any difference.
- Generated code imports only the standard library, `apitypes`, `secret` and the bound primitive packages.
- **oapi-codegen, its runtime and `nullable` are registered Rejected**, so F4 fails if any of them appears.
- `tools/gen/api` parses YAML with `go.yaml.in/yaml/v3`, which is already registered for tools. It models only the rule 2 dialect, and anything else fails before any code is emitted.
- vacuum and oasdiff are pinned with `tool` directives in their own module, `tools/apitools/go.mod`. That module is declared in the stack manifest as an `extraGoModules` exception citing this ADR, which keeps their dependency trees out of the product `go.mod`. Their module prefixes, together with `go.yaml.in/yaml`, are appended to the stack denylist (F3), so no shipped binary can link them.
- openapi-typescript and ajv are `web/package.json` devDependencies.

**Imports and ownership.** Generated packages sit inside their owner's directory, so ADR-0003's import matrix needs no change. A module imports its own `api` package, and the "own `<id>` only" rule forbids importing another's. Kernel `api` packages are kernel packages.

**Build order (T-0147).** The first deliverable is the dialect model and its A2 rejection of everything outside rule 2. After that comes a **vertical slice**: one request struct, one map, one recursive union, one PATCH body with `Opt`, one secret input and one route, with the TypeScript types generated from the same bundle. Breadth comes after the slice.

### Rule 5: The router and EP-2, the only way to serve a route

- **Router: `net/http.ServeMux` from the standard library.** No third-party router.
- **The EP-2 shape.** Each tag's generated package exposes:

  ```go
  // internal/modules/objects/api (generated)
  type Handlers interface {                  // one method per operation of the tag
      ListUsers(ctx context.Context, in ListUsersInput) (ListUsersOutput, error)
      ResetUserPassword(ctx context.Context, in ResetUserPasswordInput) (ResetUserPasswordOutput, error)
  }
  func Bind(h Handlers) apihost.TagHandlers  // generated; the only caller of apihost's route constructors
  ```

  A module's `Register` calls `r.API(objectsapi.Bind(m))`. A kernel package exports `API() apihost.TagHandlers` for `compose/server` to pass along (ADR-0003 rule 5).
- **What a handler receives, and what it never receives.**
  - `Input` holds the decoded path, query, declared headers (`If-Match`, `Idempotency-Key`) and body. `Output` is a typed union of the responses the operation declares.
  - A handler never sees `*http.Request`, `http.ResponseWriter` or the raw body.
  - Streaming bodies (CSV upload, export download) appear as `apihost.Upload` and `apihost.Stream`. They are never secret-bearing (A12).
- **`apihost` depends on ports, not on `authn` or `authz`.** `platform/authn` and `platform/authz` serve API themselves (rule 1), so their generated `api` packages import `apihost`. If `apihost` imported them back, that would be a cycle. `apihost` therefore declares the interfaces it calls, and `compose/server` injects the implementations:

  ```go
  type Ports struct {
      Authn   Authenticator   // session cookie or bearer token → principal; also performs the CSRF check
      Authz   Authorizer      // principal × x-permission → allow/deny
      Limits  Limiter         // per-source-IP and per-principal rate classes
      StepUp  StepUpChecker   // fresh-MFA check for policy.stepUp permissions
  }
  func Build(doc Document, tags []TagHandlers, policy Policy, catalogue PermissionCatalogue, ports Ports) (*Server, error)
  ```

  ADR-0003's matrix already lets `compose/server` import every kernel package. `apihost` imports no other kernel package that serves API.
- **Startup builds the route table and refuses to serve if it is wrong.** `apihost.Build` is one function, used both by `compose/server` at startup and by `fitness-api` (with the same port implementations `compose/server` wires, over an in-memory store), so the test and production cannot diverge. It fails start-up when any of these holds:
  1. a contributed route does not match a document operation exactly (method, pattern, `operationId`, tag);
  2. an operation of an **enabled** tag has no handler. Tags of capability-disabled modules are not mounted, and startup logs them;
  3. an operation's `x-permission` is not in the EP-6 catalogue, or is `anonymous` or `authenticated` with no matching rule 9 row;
  4. two patterns conflict. ServeMux's own panic is converted into a startup error.
- **One fixed middleware chain.** Every route gets the same chain, built from its row in the route table. Modules cannot add or reorder steps, because no Registrar method exists for it. In order:
  1. recover
  2. trace ID
  3. **per-source-IP rate limit**, before any authentication work
  4. host binding: a route bound to a hostname by its `policy.anonymous` row answers `not-found` on any other host
  5. query-credential refusal
  6. body cap
  7. `Content-Type` check: `application/json`, `application/merge-patch+json` or the declared binary type, else 415
  8. authentication, skipped only for `anonymous` rows
  9. **CSRF check** for cookie-session requests with an unsafe method (POST, PUT, PATCH, DELETE). The header must match the session's token. Bearer-token requests are exempt.
  10. per-principal rate limit by class
  11. step-up (rule 9)
  12. `authz` check of `x-permission`; `authenticated` rows pass any authenticated principal
  13. buffer, validate and decode (rule 6)
  14. handler
  15. JSON v2 encode, plus `Deprecation`/`Sunset` headers for deprecated operations
  16. secret clean-up (rule 6)

  An unauthenticated or unauthorised body is therefore never parsed. Object-level delegation scope is checked again inside the Action (blueprint §11; T-0047).
- **`getApiDocument`** is `x-permission: authenticated`, stability `stable`. The document lists every operation and permission, so it is not anonymous. The published API reference serves the same content to people without an account (docs-writer).
- **What is not product API** (the complete list). Anything else the server serves is an operation in the document.

  | Route group | Why it is outside the contract | Allow-list row |
  | --- | --- | --- |
  | `GET /healthz`, `GET /readyz`: status only | Load balancers and orchestrators, not clients | AN-1 |
  | `GET /` and `GET /assets/{path...}`, plus the console's client-side routes falling back to `index.html` | Static files. **The fallback never answers under `/api/` or `/auth/`.** An unknown `/api/…` path returns the `not-found` problem, never HTML | AN-2 |
  | `/auth/sso/{idpId}/start`, `/auth/sso/{idpId}/callback` (OIDC redirect, SAML ACS) | Browser redirects and form posts, signed by the IdP; not JSON | AN-3 |
  | The fleet gRPC gateway (`platform/fleet`), including its `Enroll` RPC | A separate mTLS listener carrying protobuf contracts under `proto/` (TM-F-FLEET). It is not on this router at all | AN-6 |
  | [M4] the SSPR routes of the edge tunnel router | Its own process (blueprint §5.5), with its own contract | AN-7 (edge path) |

  These routes are declared in `policy.yaml` under `nonApiRoutes`, and `apihost` mounts exactly that list.
- **Anonymous operations that are in the contract.** Three are JSON, on this listener, and therefore **operations** with `x-permission: anonymous`, each with its `policy.anonymous` row:
  - first-run setup (AN-4);
  - end-user TOTP enrolment (AN-5, bound by hostname);
  - [M4] SSPR served on the console/API listener (AN-7, bound by hostname).

  A hostname binding is part of the row, and step 4 of the chain enforces it.

### Rule 6: Strict JSON at the boundary, and the one decode path for secrets

`apihost` is the only code that touches a request body. For every operation with a JSON body, it runs these steps:

1. **Buffer, capped and pre-sized.**
   - `apihost` reads the body into a `[]byte` it owns, allocated once. The size is `Content-Length` if that is present and within the cap, otherwise the operation's `maxBodyBytes` plus one byte, to detect overflow. The buffer is never grown with `append`, so no stale copy is left behind (safe-primitives §5.6).
   - Over the cap → `413 /problems/payload-too-large`.
   - Body buffers are not pooled.
   - The generated route row marks an operation `secret` when its `Input` type closure reaches `SecretInput`. A12 keeps a secret-bearing operation at `maxBodyBytes` ≤ 64 KiB, never `bulk`, never binary.
2. **Validate, without turning strings into Go strings.** A `jsontext.Decoder` with default options walks the whole buffer. It rejects invalid UTF-8, escaped lone surrogates, duplicate names and trailing data (tested), and applies our own limits:
   - nesting depth ≤ 32, read from `StackDepth()`;
   - ≤ 10,000 values per body, unless the operation's class is `bulk`;
   - **no `\u0000` escape in any string or member name** (R3). A raw NUL byte is already invalid JSON.

   String values are read with `ReadValue` and scanned as raw bytes. The pass never converts a string value into a Go string, so a secret never becomes an immutable copy. `"\\u0000"`, an escaped backslash followed by `u0000`, is legal text. The corpus requires it to be accepted.
3. **Decode through `secretjson.Decode`, for every operation.** `secretjson.Decode(buf, &in.Body)` is the single decode entry point for API bodies, so the analyzer and this ADR agree:
   - It is `json.Unmarshal(buf, v, json.RejectUnknownMembers(true))` and nothing more. Names match case-sensitively, which is the v2 default.
   - The strict options reach every nested value through the rule 4 decoders and the type-closure rule.
   - The `secretjson` analyzer (FF-SP2) already allows a decode into a `Secret`-bearing type only through `secretjson.Decode`. `apihost` is its one caller for request bodies, because handlers have no body to decode (rule 5).
4. **Validate the decoded value** with the generated `validate`.
5. **Errors.** Malformed input (steps 1–2) → `400 /problems/malformed-request`. A schema violation (steps 3–4) → `400 /problems/validation`, with an `errors[]` entry per violation carrying its JSON pointer. The violations are:
   - an unknown member or a wrong-case member;
   - a missing required member;
   - `null` where it is not allowed;
   - a type, enum, format or bound.

   **Nothing is ever repaired.** v2 error text never reaches the client.
6. **Secret clean-up.** For a `secret` operation, after the handler returns, and on panic too (a deferred step of the chain), `apihost`:
   - calls the generated `in.destroySecrets()`, which runs `Destroy()` on every `Secret` in the `Input`;
   - then zeroes the buffer with `clear(buf)`.

   A handler that hands a secret to asynchronous work must take its own copy through the `secret` package, whose owner (P3) defines that call. The request's copies are always destroyed. The copies safe-primitives §5.6 lists as outside our control (`net/http`/`bufio` and TLS record buffers) remain outside it.
7. **Banned in product code** (`internal/**`, `cmd/**`, generated code included):
   - importing `encoding/json` (v1);
   - the options `jsontext.AllowInvalidUTF8`, `jsontext.AllowDuplicateNames` and `json.MatchCaseInsensitiveNames`;
   - a v1 `UnmarshalJSON`/`MarshalJSON` method on any type reachable from an API `Input` or `Output` (rule 4);
   - any `GOEXPERIMENT` value containing `nojsonv2`, anywhere in the build.

   Tools and tests may use v1.
8. **Responses** are encoded with v2. `secret.Secret` refuses to marshal (P3), so a secret cannot reach a response body, whatever the schema says.

### Rule 7: One API version that only grows, with explicit stability

- **There is one major version, `/api/v1`, for the whole API.**
  - Product releases (activeDIQ v1, v2) and ManageEngine's two APIs (ADM-188 "v1" and ADM-189 "v2") **both map onto `/api/v1`**. Each parity row is satisfied by `/api/v1` operations, which can be traced through `x-activediq-parity`.
  - We ship **no ManageEngine-compatible URL facade** in the product API. Helping customers move ADMP scripts is a migration-kit concern (E-017: a mapping guide or a client-side shim), and any shim calls these same operations.
- **Additive changes are free:** a new operation, an optional request field, a new response field, a new value in an open enum. Clients must ignore unknown response members, and the generated client does.
- **Breaking changes never happen in place on a `stable` operation.**
  - These count as breaking: removing or renaming anything, tightening validation, making an optional field required, removing a value from a request enum, changing a meaning, or changing an operation's permission.
  - A breaking change ships as a **new operation** (a new path or resource name, a new `operationId`) next to the old one. The old operation gets `deprecated: true` plus `x-activediq-sunset`.
  - While the old operation lives, the server sends `Deprecation` ([RFC 9745](https://www.rfc-editor.org/rfc/rfc9745)) and `Sunset` ([RFC 8594](https://www.rfc-editor.org/rfc/rfc8594)) on every response from it. It is removed only in or after its sunset release.
- **`/api/v2` exists only through a superseding ADR.** That means a coordinated major version for the whole API, never "v2 of one resource". This is a deliberate change from api-design §9, which allowed per-resource `/api/v2`: mixed prefixes give every client two base URLs and two auth stories.
- **Stability.** Every operation is `x-activediq-stability: preview` or `stable`.
  - A `preview` operation may change incompatibly. The docs, the generated client and the PowerShell module flag it.
  - Promoting an operation to `stable` is a reviewed change. Demoting one is itself a breaking change.
  - At GA, the release checklist requires every operation the console depends on to be `stable`.
  - This lets the API evolve quickly before GA without switching the check off.
- **The support window.** The proposed default is at least two minor releases **and** at least 12 months, whichever is longer (api-design §9). Publishing that promise is a commitment that leaves the building, so it is a CEO decision before GA (T-0152), not decided here. `info.version` carries the product's semantic version.

### Rule 8: Problems are a closed catalogue

- Every 4xx and 5xx response is `application/problem+json` ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)) using the shared `Problem` schema. It carries `type`, `title`, `status`, `detail`, `instance`, `code`, `traceId`, `errors[]` (each with a JSON `pointer`), and `directory{resultCode, diagnostic}` with secrets stripped.
- **`type` is the relative reference `/problems/<slug>`.** RFC 9457 §3.1.1 permits a relative URI. Clients match on the string. Rendered pages are the API reference's job (docs-writer).
- The slugs form a **closed catalogue** in `shared/problems.yaml`. It is seeded from api-design `reference/conventions.md` §2 and adds `malformed-request` (400), `step-up-required` (401), `csrf-failed` (403), `method-not-allowed` (405), `payload-too-large` (413) and `unsupported-media-type` (415).
- `apitypes` generates one constructor per slug. A handler returns either one of these constructors or a plain `error`. A plain error renders as `/problems/internal` with only the `traceId`. No stack trace, SQL, host name or decoder message ever reaches the client.
- Only `apihost` writes HTTP status codes. `http.Error` and `WriteHeader` are banned elsewhere in `internal/**`.

### Rule 9: The security policy of the contract (`api/openapi/policy.yaml`, owner security-architect)

| Section | What it holds | Enforced by |
| --- | --- | --- |
| `anonymous` | One entry per anonymous operation or non-API route: method, path, AN row, gate, optional `host` binding, reason | A4 (TM-F-ANON): the routes the built router serves **without authentication** equal this list exactly, per hostname |
| `authenticated` | Operations any authenticated principal may call with no specific permission. The seed is `getApiDocument`; T-0151 adds the rest, such as the caller's own profile and sign-out | A3, A4 (the probe expects these to succeed for a principal with no permissions), A13 |
| `nonApiRoutes` | The rule 5 table | A4: the routes mounted outside the document equal this list exactly |
| `secretResponses` | Operations allowed to return a secret once: LAPS and BitLocker reveal (`secret.*` permissions, DM-33.I2), and API-token and enrollment-token creation (shown once, TM §7.5). Each names its single response schema | A8 (TM-F-SECRETOUT linter half) |
| `stepUp` | The permissions that require a fresh MFA (TM-D16 §7.4 table) | `apihost` enforces it from the route table. A13 fails stale entries |
| `largeBodies` | Operations allowed `maxBodyBytes` above 16 MiB, with a reason | A12 |

- **The secret linter (A8).** It fails when any schema reachable from any response, followed through `$ref`, `oneOf`, `items` and `additionalProperties`, carries any of these:
  - `x-activediq-secret`, `writeOnly: true` or `format: password`;
  - a property whose name matches the secret-name list (`password`, `pwd`, `secret`, `token`, `apiKey`, `privateKey`, `recoveryKey`, `clientSecret`).

  **Matching is exact or by camelCase suffix, never by substring or prefix.** A name matches when it equals a listed word, ignoring case, or when it ends with that word starting at an uppercase boundary. `adminPassword`, `refreshToken`, `unicodePwd` and `bitlockerRecoveryKey` all match. `passwordLastSet`, `passwordNeverExpires`, `pwdLastSet`, `badPwdCount`, `maxPwdAge`, `tokenGroups` and `apiKeyId` do not. These cases are A8's fixtures. Without them every user read would fail.

  The only exceptions are the operations listed in `secretResponses`.
- **Credentials.** Security schemes are only `bearer` (`adq_` API tokens, `Authorization` header) and the session cookie plus a CSRF header. There is no `apiKey` scheme `in: query` and no credential-named query parameter. At runtime, `apihost` refuses with 400 any `/api/` request whose query string carries a credential-named key (chain step 5).
- **Who reviews `policy.yaml`.** Every change to it is tagged `security-sensitive`, so security-architect reviews it (review-checklist). When hosted CI exists, a CODEOWNERS entry adds a required review. Until then, that review is the manual half.
- **Two anonymous routes are missing from the allow-list.** Local break-glass sign-in (ADM-142) and AD-identity sign-in via SPNEGO (blueprint §11) both need routes reachable before authentication, and neither is in AN-1 to AN-7 today. Amending §7.6 belongs to security-architect (T-0151). Until that lands, those routes cannot be added, because A4 would fail.

### Rule 10: Limits are declared, not improvised (TM-Q2)

- **Rate classes.** `x-activediq-limits.class` is one of `read`, `write`, `bulk`, `auth`, `reveal` or `anonymous`.
  - The default is `read` for GET and HEAD, and `write` for everything else.
  - Anonymous operations must declare `anonymous` or `auth`.
  - Operations in `secretResponses` must declare `reveal`.
- **How the limits work.** Limits apply per source IP (before authentication, chain step 3) and per principal (chain step 10). A limited request gets `429 /problems/rate-limited` with `Retry-After`. There is **no daily quota and no metering**, which keeps the ADM-190 lead. The numbers per class are `apihost` configuration, and their defaults are set by T-0151 with security-architect.
- **Body caps.**
  - `maxBodyBytes` defaults to 1 MiB for JSON bodies.
  - An operation with a binary or CSV upload must declare it.
  - Anything above 16 MiB needs a `largeBodies` entry.
  - A `secret` operation is capped at 64 KiB (rule 6).

### Rule 11: Tenancy

The tenant never travels in the contract (ADR-0002 rule 5). T5 (`openapi-tenant-param`) remains the single implementation of that check. `fitness-api` does not duplicate it. It only fails if T5's scanner cannot parse a file that `tools/gen/api` bundles.

### Rule 12: The console uses the generated client only

- `web/src/api/` holds only the generated types and `client.ts`.
- Outside that directory, `web/src/**` may not call `fetch`, `XMLHttpRequest` or `EventSource`, may not import an HTTP library, and may not contain a string literal starting with `/api/`. An ESLint rule enforces this, and A5 runs it.
- A console feature that needs data gets an operation in the contract first (blueprint §6: no private endpoints).

### Rule 13: The contract changes first

- A change to an operation starts as a change to `api/openapi/**`, reviewed against api-design §10, before any handler exists.
- vacuum lints the bundle with our ruleset (`api/openapi/.vacuum.yaml`: OpenAPI 3.1 validity, rule 1 names, the rule 2 dialect).
- oasdiff compares the bundle with `main` and with the latest release tag (A10).

## Alternatives considered

| Alternative | What it would buy us | Why not |
| --- | --- | --- |
| **oapi-codegen end to end** (`std-http-server` + `strict-server` + models) | <ul><li>One mature, popular tool.</li><li>It targets ServeMux.</li><li>A typed strict-server interface.</li><li>3.1 support since v2.8 ([releases](https://github.com/oapi-codegen/oapi-codegen/releases)).</li></ul> | <ul><li>It generates **one** `StrictServerInterface` for the whole API. Nothing ties a route to `x-permission`.</li><li>Its model templates decode unions and mixed maps with v1 `encoding/json` (`union.tmpl`, `additional-properties.tmpl`, checked on `main`).</li><li>Generated code pulls `oapi-codegen/runtime` into the binary.</li></ul> |
| **oapi-codegen for models only**, with `x-go-type` injection for formats, `Opt`, secrets and unions, plus our decode and validate methods in sibling files (the first draft of this ADR) | <ul><li>Less type-emission code of our own.</li></ul> | <ul><li>It would supply only the easy rows of the rule 4 table: struct and enum declarations. Every hard row (unions, maps, `Opt`, formats, secrets, required-member presence, validation) would still be ours.</li><li>The sibling methods would depend on oapi-codegen's field naming. Template internals are not a stable API (api-engineer).</li><li>Two interpreters of the same YAML: types from one, decoders and validators from the other.</li><li>Its 3.1 handling of `type: [T, "null"]` is "initial".</li><li>A new release that starts emitting a v1 method for some construct would reopen the tested hole. Only A7's reflection check would catch it.</li></ul> |
| **ogen** | <ul><li>Strong typing with `Opt`/`Nil` wrappers.</li><li>Generated validation.</li><li>A static router.</li><li>No reflection ([repo](https://github.com/ogen-go/ogen)).</li></ul> | <ul><li>Its own router replaces the mux ADR-0003 gives `apihost`.</li><li>Its jx codec documents no rejection of invalid UTF-8 or lone surrogates `[UNVERIFIED]`, so R3 would rest on a library we would have to audit and pin.</li><li>It generates one global `Handler`.</li><li>3.1 support is undocumented.</li></ul> |
| **In-house generator over a general OpenAPI parser** (libopenapi or kin-openapi) | <ul><li>Full OpenAPI coverage.</li></ul> | <ul><li>We need a closed dialect, not full coverage. A small model of rule 2 rejects everything else by construction (A2), which a general parser does not.</li><li>vacuum already checks OpenAPI 3.1 validity.</li></ul> |
| **Code-first** (handlers annotated, OpenAPI generated from Go, e.g. huma) | <ul><li>No YAML.</li><li>The document can never drift from the handlers.</li></ul> | <ul><li>The contract becomes a by-product of the code. The opposite is what we need: reviewed before any handler exists (api-design §1), the source for the TypeScript client and the PowerShell module, and diffable for breaking changes.</li><li>It would also add a framework dependency.</li></ul> |
| **chi or another router** | <ul><li>Middleware composition helpers.</li><li>Route groups.</li></ul> | <ul><li>ServeMux has had method and wildcard patterns since Go 1.22 ([docs](https://pkg.go.dev/net/http#ServeMux)).</li><li>Our middleware chain is fixed and generated per route.</li><li>It is one less dependency.</li></ul> |
| **Per-resource `/api/v2`** (api-design §9 as written) | Breaking fixes stay local to one resource. | Clients juggle two prefixes. A new operation next to a deprecated one gives the same locality with one base URL. |
| **Decode with v1 plus `DisallowUnknownFields` and a UTF-8 pre-check** | No dependence on json/v2. | json/v2 is GA in 1.27. The v1 path still matches names case-insensitively and repairs strings. |
| **Redocly CLI or Spectral** for bundling and lint | Popular, with rich rulesets. | Node tools on the Go CI path. vacuum lints Spectral-compatible rulesets in Go, and our bundling is a rule 1 merge we own anyway. |
| **@hey-api/openapi-ts or orval** for the client | <ul><li>Generated SDK functions.</li><li>Query hooks.</li></ul> | More generated runtime code to review and ship. openapi-typescript emits types only, and openapi-fetch is about 6 kB ([openapi-ts.dev](https://openapi-ts.dev/introduction)). |
| **Defer until the first endpoint** | Nothing is decided early. | E1.6 (T-0086, T-0069) is on the checkpoint 2a critical path. Deciding late is how PatchIQ's first feature skipped the interface. |

## Consequences

**Positive**

- A route can exist only as a document operation or a `policy.yaml` entry. It cannot skip authentication, CSRF, its permission or strict decoding, because a handler never touches HTTP. This closes, in the structure itself, the CVE-2021-40539 class the threat model cites.
- Strictness reaches every nested value: unions, maps and bound primitive ASTs included. One generator emits every contract type, and the type-closure rule plus A7's per-level corpus prove it.
- One decode path for every body, secrets included. It agrees with safe-primitives §5.6 and its `secretjson` analyzer. The request's own copies of a secret are destroyed and its buffer zeroed by one owner.
- No module-shaped growth in core. Adding a module's API touches its own YAML file and its own generated package.
- The console, scripts, ITSM connectors and later the PowerShell module and MCP see one contract with one stability promise. Unmetered rate classes keep the ADM-190 lead.

**Negative**

- **We own a real generator: about 3,000 to 4,000 lines**, plus golden tests. This is api-engineer's estimate. The first draft's 600 lines assumed oapi-codegen supplied the types. The size goes into:
  - the bundle with cross-file `$ref`, cycles and deterministic naming and ordering;
  - the dialect model;
  - type emission;
  - decoders for structs, maps and recursive unions;
  - validators;
  - handlers, `Bind` and route rows.

  It is a component with an owner (api-engineer), built dialect-model-first and then as a vertical slice (T-0147).
- **The dialect costs expressiveness:**
  - no `anyOf`, `allOf`, `default` or floats;
  - separate request and response schemas wherever they differ;
  - no "optional and nullable".

  Each can be added later by amending rule 2, together with its row in the rule 4 table and its corpus cases.
- **Writing YAML by hand is slower than code-first.** That is the price of reviewing the contract first.
- `GOEXPERIMENT=nojsonv2` stops being an escape hatch for us. If a json/v2 regression lands in a Go point release, the remedy is to pin the previous toolchain, not to fall back to v1.
- **Two readers of the bundle stay third-party:** openapi-typescript and ajv. The A7 cross-check makes our Go decoders and ajv agree on one corpus. A disagreement is a generator bug or a dialect gap, and is fixed before merge.

**Follow-on work**

These were filed with the first draft and amended by notes on this rework:

- **T-0147** build (api-engineer): `tools/gen/api` and the `api/openapi/` skeleton.
  - The skeleton comprises: the root; `shared/` with Problem, the catalogue, paging, `GUIDRef`/`ObjectView`, scalars and `SecretInput`; and `policy.yaml` seeded from TM §7.6.
  - Also in scope: the hand-written `apitypes` scalars and `Opt`; `tools/apitools/go.mod`; the manifest exception and denylist entries; `make gen-api` and its staleness check; and the web client skeleton with its ESLint rule.
  - **Its generator fixture must contain every construct in the rule 4 table.** It is built dialect-model-first, then as the vertical slice.
  - T-0086 (apihost) depends on it.
- **T-0148** chore (devops-engineer): `fitness-api`, static half: A1, A2, A3 (document side), A5, A7 (static and cross-check), A8, A10, A11, A12, A13. Its checks activate when their inputs appear, each with a failing fixture. T-0069 (the first operations) depends on it and on T-0151.
- **T-0149** chore (api-engineer): `fitness-api`, runtime half: A3 (catalogue side), A4, A6, A7 (type closure and corpus), A14, all on `apihost.Build`. Depends on T-0086.
- **T-0150** chore (solution-architect): align blueprint §1, §6, §16 and §17 and api-design §1 and §9 with this ADR. **Also align safe-primitives §5.6 and FF-SP2.** For a secret-bearing API request, `apihost` buffers, validates, decodes through `secretjson.Decode`, destroys the secrets and zeroes the buffer. `Secret` implements v2 `UnmarshalJSONFrom` via `ReadValue`, not v1 `UnmarshalJSON`.
- **T-0151** chore (security-architect): amend TM §7.6 for local break-glass sign-in and SPNEGO sign-in routes. Seed `policy.yaml`'s `anonymous` (with host bindings for AN-5 and AN-7), `authenticated`, `secretResponses` and `stepUp`. Set the default numbers per rate class (TM-Q2).
- **T-0152** decision-prep (product-manager): the published deprecation and support window (rule 7), for the CEO before GA.
- **T-0033** (devops-engineer, existing): the `secretjson` analyzer must also report `ReadToken` inside `Secret`'s decoder, and must allow `apihost` as the request-body caller of `secretjson.Decode` (a note on the ticket).

**Revisit when**

- json/v2 changes a default we rely on (the A7 corpus fails).
- An operation needs a construct rule 2 bans. That takes an amendment adding its rule 4 row and corpus cases, never a one-off exception.
- Partner-built modules need their own contracts.
- We need a coordinated `/api/v2`, which takes a superseding ADR.

## Fitness function

**Job:** `fitness-api`. It is a Go program at `tools/fitness/api/`, invoked by `make fitness` (and therefore `make ci`). Its parts include `make lint-api` (vacuum), the oasdiff step and the ajv cross-check (run through the `web/` toolchain).

Every check has a failing fixture in `check_test.go`, so a check that silently matches nothing is itself a failure. A check whose input does not exist yet (no `api/openapi/`, no `apihost`) reports itself as **inactive** rather than passing silently. **The ADR is not `accepted` while any check is inactive.**

| Check | What fails the build | Closes |
| --- | --- | --- |
| **A1** Layout and bundle | <ul><li>A file under `api/openapi/` outside the rule 1 places.</li><li>A `modules/<id>.yaml` whose `<id>` is not a module in the generated module list.</li><li>A `platform/<pkg>.yaml` with no `internal/platform/<pkg>`.</li><li>An operation with zero or two or more tags, or a tag different from its file's.</li><li>A cross-module or upward `$ref`.</li><li>A duplicate `operationId` or component name.</li><li>A stale bundle (`openapi.gen.json` ≠ regeneration).</li></ul> | Contract drift; cross-module coupling through schemas |
| **A2** Dialect and style | <ul><li>vacuum errors under `.vacuum.yaml`.</li><li>A keyword outside the rule 2 list.</li><li>An `x-` key not in rule 3.</li><li>A map with `properties`.</li><li>An enum reachable from both requests and responses.</li><li>An optional nullable member.</li><li>A `oneOf` without a `kind` discriminator, or a variant without a required single-value `kind` const.</li><li>An integer without bounds, or with bounds beyond ±(2⁵³−1).</li><li>A pattern Go `regexp` rejects, or one with lookaround or backreferences.</li><li>A response enum without `x-activediq-enum: open`.</li><li>A trailing slash, or a non-camelCase member.</li><li>A path parameter or field named `dn`/`distinguishedName` used as an identifier in a path.</li></ul> | Constructs the generator cannot emit strictly; DN-as-ID |
| **A3** Permission | <ul><li>An operation without exactly one `x-permission`.</li><li>`anonymous` without `x-activediq-anonymous` and a `policy.anonymous` row.</li><li>`authenticated` without a `policy.authenticated` row.</li><li>Runtime half: a permission that no Registrar or kernel contribution declares in the EP-6 catalogue.</li></ul> | TM-TB2-T2; DM-33.I1 |
| **A4** Route set (TM-F-ANON) | For **each** profile manifest (`windows`, `linux-oci`, `saas`), the router built by `apihost.Build` from the real module list does any of these:<ul><li>serves a route that is neither an operation of an enabled tag nor a `nonApiRoutes` entry, or misses one;</li><li>serves without authentication a set of routes that differs from `policy.anonymous`, checked per bound hostname and on an unbound hostname.</li></ul>Then an **HTTP probe**, generated from the route table:<ul><li>every non-anonymous route answers 401 to an unauthenticated request;</li><li>every route that is neither anonymous nor `authenticated` answers 403 to a principal with no permissions;</li><li>an `authenticated` route does not answer 403 to that principal;</li><li>a cookie-session unsafe request without the CSRF header answers `csrf-failed`.</li></ul>This proves the middleware enforces what the table says. | Unauthenticated or unpermissioned routes; private endpoints; CSRF gaps |
| **A5** Generated client | <ul><li>`web/src/api/schema.gen.d.ts` is stale.</li><li>A file in `web/src/api/` other than the generated files and `client.ts`.</li><li>The rule 12 ESLint rule finds `fetch`/`XMLHttpRequest`/`EventSource`, an HTTP-library import, or an `/api/` literal elsewhere in `web/src`.</li><li>The open-enum fixture: an unknown value of a response enum fails to type-check.</li></ul> | A hand-written client; brittle clients |
| **A6** Generated server | <ul><li>A `*.gen.go` in an `api` package or `apitypes` is stale.</li><li>`apihost`'s route constructors are called from a file without the generated header.</li><li>`Registrar.API` is called with anything but the module's own `api.Bind(…)`.</li><li>A handler package imports `net/http` to reach the request or response (only `apihost` and generated code may).</li><li>`apihost` imports a kernel package that serves API, instead of using `Ports`.</li></ul> | Hand-built `TagHandlers`; handlers bypassing decode; import cycles |
| **A7** Strict JSON | Four parts:<ul><li>**Static:** an `encoding/json` (v1) import in `internal/**` or `cmd/**`; a banned v2 option outside tests; a `GOEXPERIMENT` containing `nojsonv2` in any Makefile, script, Dockerfile or env file.</li><li>**Type closure** (reflection over the route table): a type reachable from any `Input`/`Output` that is outside the rule 4 list, implements v1 `json.Unmarshaler`/`json.Marshaler`, or (if bound or `apitypes`) lacks `UnmarshalJSONFrom`/`MarshalJSONTo`.</li><li>**Corpus**, generated per operation by walking its request schema. The handler is never called, and each case returns the expected problem with the expected JSON pointer. See the case lists below.</li><li>**Cross-check:** the schema-level part of the corpus, plus generated valid instances, run against ajv (2020-12, `strict` mode) on the same bundle. Any accept/reject disagreement with the Go decoders fails.</li></ul> | The U+FFFD repair (`lessons.md`); R3; the nested-v1-method hole; generator bugs |
| **A8** Secrets out (TM-F-SECRETOUT, linter half) | <ul><li>A rule 9 secret marker or secret-named property (exact or camelCase-suffix match) reachable from a response not listed in `secretResponses`. The pass and fail name fixtures of rule 9 are part of the check.</li><li>A credential-named query parameter.</li><li>An `apiKey` scheme `in: query`.</li><li>A `secretResponses` operation whose class is not `reveal`, or whose permission is neither a `secret.*` permission nor a token-creation permission.</li></ul> The runtime half (the canary through every sink) belongs to T-0033 and T-0034. | CVE-2022-24978 class; TM-TB2-T6 |
| **A9** Tenancy | No separate check: T5 `openapi-tenant-param` runs in `fitness-tenancy`. A1 fails if a bundled file is one T5 cannot parse. | — |
| **A10** Versioning | <ul><li>oasdiff reports a breaking change, against `main` and against the latest release tag, on a `stable` operation.</li><li>A `stable` → `preview` demotion.</li><li>An operation without `x-activediq-stability`.</li><li>`deprecated: true` without `x-activediq-sunset`.</li><li>A deprecated operation removed before its sunset release.</li></ul> | In-place breaking changes |
| **A11** Problems | <ul><li>A 4xx or 5xx response that is not `application/problem+json` with the shared `Problem`.</li><li>A `type` outside the catalogue.</li><li>`http.Error` or `WriteHeader` in `internal/**` outside `apihost`.</li></ul> | Leaky, ad-hoc errors |
| **A12** Limits | <ul><li>An unknown rate class.</li><li>An anonymous operation not in class `anonymous` or `auth`.</li><li>An upload operation without `maxBodyBytes`.</li><li>`maxBodyBytes` above 16 MiB without a `largeBodies` entry.</li><li>A `secret` operation above 64 KiB, of class `bulk`, or with a binary body.</li></ul> | TM-Q2; secret buffer size |
| **A13** Policy hygiene | <ul><li>A `policy.yaml` entry that is stale: it names a missing route, operation, permission or hostname binding.</li><li>An entry with no reason, or with no AN/TM reference.</li></ul> | Exemptions becoming permanent |
| **A14** Responses conform | In the runtime tests (A4 probe, A7 corpus, and every module's contract tests through the shared harness), each response body is validated against the operation's declared response schema with the generated validators before it is encoded. A violation fails the test. | Handlers drifting from the contract on output |

**The A7 corpus cases.**
- **At every object node:** an unknown member, a wrong-case member, a duplicate member, each missing required member, and `null` for each non-nullable member. "Every object node" includes nested objects, each `oneOf` variant, each map value, each array item and each bound primitive AST.
- **At every union node:** `kind` missing, unknown, or in the wrong case (`Kind`).
- **For the whole body:** `\xff`; `"\ud800"`; `"\udc00"`; `\u0000` in a value and in a member name; trailing data; depth 33; an oversize body; a `Content-Length` above the cap; a wrong `Content-Type`.
- **Must-accept:** `"\\u0000"`, plus a generated valid instance.
- **For each `secret` operation:** after the response, the request buffer is zeroed and every `Secret` in the `Input` is destroyed. This is observed through a test-build hook in `apihost`.

**Bypasses, and what closes them:**

- **A module mounting its own route.** ADR-0003 M4 bans `http.Handle`, `HandleFunc`, `ServeMux` and `net.Listen` in modules, and back doors into kernel hosts.
- **A hand-built `TagHandlers`.** Closed three ways: A6, `apihost.Build` refusing anything not in the embedded document, and the staleness check on that document.
- **A handler reading the raw body.** It has no `*http.Request` (rule 5), and A6 bans `net/http` in handler packages.
- **A second JSON decoder, or a v1 method nested in a contract type.** A7: static checks, type closure, corpus at every level, and the cross-check.
- **A secret decoded outside the one path.** The `secretjson` analyzer (FF-SP2, T-0033), plus A7's clean-up assertion.
- **A console call around the client.** A5.
- **A secret in an unmarked field.** The name heuristic (A8), plus `secret.Secret` refusing to marshal, plus the TM-F-SECRETOUT canary.
- **A route served only in one profile or on one hostname.** A4 runs per profile and per hostname binding.

**Not automatable, and who checks it.** Three things stay manual:

- Whether an operation's `x-permission` is the **right** permission for what it does. code-reviewer checks it, and security-architect checks it for `security-sensitive` tickets.
- Whether an operation belongs in `policy.authenticated` at all. security-architect checks it, through the `policy.yaml` review.
- Who reviews `policy.yaml` and binding-table changes. security-architect does, by ticket tag, until CODEOWNERS can enforce it.

**Status path.** Ratified when the director signs it off at review of T-0046. Accepted when `fitness-api` A1–A14 (A9 delegated to T5) all run **active** and green in `make ci` on `main`.

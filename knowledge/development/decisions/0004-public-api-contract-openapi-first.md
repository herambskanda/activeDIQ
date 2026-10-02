---
title: "ADR-0004: The public API is one OpenAPI 3.1 contract, one file per tag, generated into per-tag handlers on net/http.ServeMux, decoded strictly with encoding/json/v2, one permission per operation, and one /api/v1 that only grows"
date: 2026-10-02
updated: 2026-10-02
status: proposed
owner: heramb
kind: technical
ticket: T-0046
---

# ADR-0004: The public API is one OpenAPI 3.1 contract, one file per tag, generated into per-tag handlers on `net/http.ServeMux`, decoded strictly with `encoding/json/v2`, one permission per operation, and one `/api/v1` that only grows

**Status:** proposed. The factory-director ratifies it when reviewing T-0046, then files a `notice`. It becomes `accepted` when `fitness-api` (A1–A13 below) runs green in `make ci` on `main`.
**Kind:** technical. No customer, partner or brand sees the generator or the router. Customers see the result: one documented, stable, unmetered API. That result follows from decisions the CEO already made: the house stack (D-0003) and the API-first, unmetered positioning (parity matrix enhancement 18).
**Deciders:** solution-architect (author), with api-engineer consulted on 2026-10-02 (generator, router, client and tooling evaluation, plus a local test of `encoding/json/v2` defaults; recorded on T-0046). factory-director ratifies. **Ticket:** T-0046. **Parity / scope refs:** ADM-188, ADM-189 (ADM-190 indirectly, through rate classes).

> Amendments (ratified ADRs only): none.

## Context

**The public API is the product boundary** (blueprint §0, §6). The console, ITSM integrations (ServiceNow, ServiceDesk Plus), customer scripts, and later the PowerShell module and the MCP server (ENH-11, M3) all call the same operations. The console has no private endpoints. Several decisions already constrain this ADR:

- **ADR-0001** chose Go 1.27 (pure Go, `CGO_ENABLED=0`) and React + TypeScript. It left the HTTP router and the OpenAPI generator to this ADR. Every tool needs a licence-register row first (F4).
- **ADR-0002** check T5 already fails a tenant-scope operation with a `tenant_id` or `X-Tenant-*` parameter, and marks platform operations `x-activediq-scope: platform` (`tools/fitness/tenancy/static/openapi.go`, which reads `api/openapi/`).
- **ADR-0003** (proposed) makes the Registrar the only on-ramp. `Registrar.API(h apihost.TagHandlers)` is EP-2, and this ADR fixes its shape. A module ID **is** its OpenAPI tag. Modules may not touch `http.Handle`, `HandleFunc` or a `ServeMux`, because `apihost` owns the mux (M4). Adding a module edits only its own directory, its migration, **its OpenAPI file** and its architecture page.
- **Safe primitives §2.1** fixes the wire shapes for DNs (`GUIDRef` in, `{guid, dn, rdns}` out), filters (AST in) and PowerShell (display-only out). R3 says to reject and never repair: invalid UTF-8, unpaired surrogates and NUL are refused.
- **The threat model** asks this ADR for four things. TM-D16 (§7.4, §7.6): exactly one `x-permission` per operation, deny by default, and an anonymous route set equal to a reviewed allow-list (AN-1 to AN-7, proof TM-F-ANON). §9.7: secret fields are write-only, and a response linter fails any response schema that can carry one (proof TM-F-SECRETOUT, the CVE-2022-24978 lesson). TM-TB2-T6: credentials never travel in a query string. TM-Q2: rate limits and body caps are declared per operation in the contract.

**What PatchIQ teaches.** PatchIQ had a correct module interface with zero implementations. Its 36 subpackages were passed to a `NewRouter` with 53 parameters, and 94 of 156 handler files imported the store (`../UEM/knowledge/development/legacy/patchiq-postmortem.md` §5–§6, §11; ADR-0003 Context). A contract that is not the only way to serve a route becomes decoration.

**The ManageEngine baseline.** ADManager Plus ships two REST APIs. "v1" covers users, groups, computers, OUs and authtokens (ADM-188). "v2" publishes an OpenAPI document covering a subset (ADM-189). Calls are metered: 50 successful calls per technician per day, then US$1 per extra call per day (ADM-190; [API v2 intro](https://www.manageengine.com/products/ad-manager/active-directory-api/v2/introduction/)). The parity matrix scores ADM-188 as a lead and ADM-189 as parity. **ADM-188 and ADM-189 are rows about ManageEngine's two APIs. They are not a plan for ours to have two versions.**

**Facts that shape the choice (checked 2026-10-02):**

- **`encoding/json/v2` and `encoding/json/jsontext` are GA in Go 1.27** ([Go 1.27 release notes](https://go.dev/doc/go1.27)). In 1.27, plain `encoding/json` (v1) is implemented on top of v2 but **keeps v1 semantics**. `GOEXPERIMENT=nojsonv2` restores the old implementation.
- **The v2 defaults, as tested by api-engineer** on go1.25.6 with `GOEXPERIMENT=jsonv2`, which runs the same code ([json/v2](https://pkg.go.dev/encoding/json/v2), [jsontext](https://pkg.go.dev/encoding/json/jsontext)):
  - invalid UTF-8 is rejected;
  - escaped lone surrogates (`"\ud800"`) are rejected;
  - duplicate member names are rejected;
  - names match case-sensitively;
  - trailing data is rejected.
- **Unknown members are silently ignored** unless `json.RejectUnknownMembers(true)` is set. A wrong-case key such as `"A"` for `a` is dropped silently. This option is therefore load-bearing. The opt-outs that would undo the strictness are `jsontext.AllowInvalidUTF8`, `jsontext.AllowDuplicateNames` and `json.MatchCaseInsensitiveNames`. A re-test on Go 1.27 itself belongs in the A7 corpus `[UNVERIFIED on go1.27]`.
- **The standard `net/http.ServeMux`** has matched `METHOD /path/{wildcard}` patterns since Go 1.22. It answers 405 with `Allow` on its own, panics when two registered patterns conflict, and exposes the matched pattern as `Request.Pattern` ([net/http ServeMux](https://pkg.go.dev/net/http#ServeMux)). OpenAPI path templating writes `{id}` exactly as ServeMux does. One difference: a ServeMux pattern ending in `/` matches the whole subtree, while an OpenAPI path ending in `/` names one path. oapi-codegen v2.8 anchors such paths with `{$}` for that reason ([releases](https://github.com/oapi-codegen/oapi-codegen/releases)).
- **Go generators:**
  - **oapi-codegen** (Apache-2.0) gained "initial" OpenAPI 3.1 support in v2.8.0 (2026-07-17). v2.7.1 and v2.7.2 fixed code injection from malicious specs ([releases](https://github.com/oapi-codegen/oapi-codegen/releases)). Its strict-server templates decode with `encoding/json` v1 `[UNVERIFIED]`, and generated code imports `github.com/oapi-codegen/runtime`.
  - **ogen** (Apache-2.0, [repo](https://github.com/ogen-go/ogen)) brings its own router and the go-faster/jx codec (MIT). jx documents no UTF-8 or surrogate validation `[UNVERIFIED]`.
- **The TypeScript client.** openapi-typescript 7.13 (MIT) emits types only, for OpenAPI 3.0 and 3.1. openapi-fetch 0.17 (MIT) is a type-safe `fetch` wrapper of about 6 kB ([openapi-ts.dev](https://openapi-ts.dev/introduction)).
- **Lint and diff tools, both written in Go.** vacuum (MIT, v0.30.6, [repo](https://github.com/daveshanley/vacuum)) lints with Spectral-compatible rulesets for OpenAPI 3.0, 3.1 and 3.2. oasdiff (Apache-2.0, v1.33.0, [repo](https://github.com/oasdiff/oasdiff)) detects breaking changes.

**What makes this non-obvious.** Taking a full-stack generator is the obvious move, and it fails here twice:

1. Every mature Go generator either decodes with v1 semantics (and repairs invalid input into U+FFFD, which could set a password nobody typed, per `lessons.md`) or replaces the mux that ADR-0003 gives to `apihost`.
2. Every generator produces **one** server interface for the whole API. That is PatchIQ's `NewRouter` in a new shape: one type that must implement every module's operations.

The design below keeps the generators for what they do well, which is types. It keeps the request path for us: routing, decoding, permission and problems, in about 600 lines of generator that we own.

## Decision

We will define the public API as **one OpenAPI 3.1 contract, split into one file per tag under `api/openapi/`**, bundled into one document. We will generate **per-tag** Go handler interfaces that modules hand to the Registrar, and a TypeScript client the console must use. All of it is served by `apihost` on the standard `ServeMux`, with strict `encoding/json/v2` decoding, exactly one permission per operation, a closed problem catalogue, and a single `/api/v1` that changes only additively. Thirteen rules follow. `fitness-api` enforces them.

### Rule 1: Source layout (owner of each path in brackets)

```
api/openapi/
  openapi.yaml            root: info, servers (/api/v1), securitySchemes, the tag list    [api-engineer]
  shared/*.yaml           components used by more than one tag: Problem and the catalogue,
                          paging, GUIDRef/ObjectView, filter AST, Job, Opt, Secret input   [api-engineer]
  modules/<id>.yaml       one per server module that serves API: its paths + its components [module owner]
  platform/<pkg>.yaml     one per kernel package that serves API (authn, jobs, audit, report…) [package owner]
  policy.yaml             security policy for the contract (rule 9)                          [security-architect]
```

- **Tags.** A module's tag equals its module ID (ADR-0003 rule 3, `^[a-z][a-z0-9]{1,30}$`). A kernel package's tag is `platform.<pkg>`. The dot cannot appear in a module ID, so the two namespaces cannot collide. Every operation has **exactly one tag**, and it must equal the tag of the file that declares it. The root's tag list names each tag's file.
- **References mirror the import graph.** A module or platform file may `$ref` only its own components and `shared/`. `shared/` may `$ref` only `shared/`. A cross-module reference fails A1. A shape that two tags need moves to `shared/` (parameterise, don't clone), and that move is reviewed by api-engineer and solution-architect.
- **Names.**
  - `operationId` is camelCase and unique across the bundle (`listUsers`, `resetUserPassword`).
  - Component names are PascalCase and unique across the bundle. A collision fails the bundle, never "last one wins".
  - Paths are kebab-case and have no trailing slash.
  - JSON members are camelCase.
- **Paths are relative to `servers: [{url: /api/v1}]`.** Directory objects are addressed by `objectGUID`, never by DN (api-design §2, safe-primitives §2.1).
- **The bundle is a generated artefact.** `tools/gen/api` merges the files under the rules above (no third-party bundler) and writes `internal/platform/apihost/spec/openapi.gen.json`. That file is committed, embedded in the server, and served as the operation `getApiDocument` (`GET /api/v1/openapi.json`). It is the one input of every generator, linter and diff below.

### Rule 2: The OpenAPI dialect we write

We use OpenAPI **3.1** with the JSON Schema 2020-12 dialect ([OAS 3.1.1](https://spec.openapis.org/oas/v3.1.1)). We restrict it so that the generators are predictable and the strictness rules hold:

- No `anyOf`, `not`, `if`/`then`/`else`, `patternProperties`, `$dynamicRef` or `unevaluatedProperties`. `oneOf` is allowed only with a `discriminator` whose property is `kind`.
- **Request objects** declare `additionalProperties: false`. Response objects never declare `additionalProperties: true`. A map is `additionalProperties: <schema>`.
- Nullable means `type: [T, "null"]`. A **PATCH** body is `application/merge-patch+json` ([RFC 7396](https://www.rfc-editor.org/rfc/rfc7396)). Its writable fields use the shared `Opt` wrapper, so the Go type keeps three states: absent, `null` and value. Pointers cannot tell absent from null, so they are not used for this.
- An integer that can exceed 2⁵³−1 is sent as a `string` with a `pattern`. Otherwise JavaScript rounds it ([MDN: MAX_SAFE_INTEGER](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER)). Timestamps are `date-time` in UTC (api-design §2).
- A secret input field is `$ref: shared/secret.yaml#/components/schemas/SecretInput`. That schema is `writeOnly: true` and `x-activediq-secret: true`, and its Go type is `secret.Secret`, decoded from the raw bytes (P3 §5.6). It is never a `string`.
- **Response enums are open.** Clients must accept values they do not know. Request enums are closed.

### Rule 3: Vendor extensions (the complete list)

| Extension | Where | Required | Meaning |
| --- | --- | --- | --- |
| `x-permission` | operation | **yes, exactly one** | The permission `authz` checks before the handler runs (DM-33.I1, TM-D16). It is a permission ID from the EP-6 catalogue, or the literal `anonymous` for a rule 9 allow-list row. The name keeps its short form because DM-33 and the threat model already use it. |
| `x-activediq-scope` | operation | only for `platform` | ADR-0002: `platform` marks a platform-scope operation, and the default is `tenant`. |
| `x-activediq-stability` | operation | **yes** | `preview` or `stable` (rule 7) |
| `x-activediq-sunset` | operation | with `deprecated: true` | The first product release in which the operation may be removed (rule 7) |
| `x-activediq-limits` | operation | no | `{class, maxBodyBytes}` (rule 10). It defaults by method. |
| `x-activediq-anonymous` | operation | with `x-permission: anonymous` | The allow-list row it uses (`AN-4`, `AN-5`, …) |
| `x-activediq-secret` | schema | on secret inputs | The schema carries a secret, so it is write-only (rule 9) |
| `x-activediq-parity` | operation | no | ManageEngine feature IDs, for traceability |

Any other `x-` key fails A2. Generator-specific keys (`x-go-type` and similar) are injected by `tools/gen/api` into the bundle only and never written by hand.

### Rule 4: Generation

| Output | Generated by | From | Into |
| --- | --- | --- | --- |
| Bundle | `tools/gen/api` (ours) | `api/openapi/**` | `internal/platform/apihost/spec/openapi.gen.json` |
| Shared Go types and the problem catalogue | oapi-codegen v2.8+, **models only** | bundle, `shared/` components | `internal/platform/apihost/apitypes/*.gen.go` |
| Per-tag Go models | oapi-codegen, **models only** (shared schemas map to `apitypes` through injected `x-go-type`, never copied) | bundle, filtered by tag | `internal/modules/<id>/api/*.gen.go`, `internal/platform/<pkg>/api/*.gen.go` |
| Per-tag handler interface, `Bind`, route rows | `tools/gen/api` (ours) | bundle | the same `api` packages |
| TypeScript types | openapi-typescript | bundle | `web/src/api/schema.gen.d.ts` |
| Web client | openapi-fetch over those types, in `web/src/api/client.ts` (the one hand-written file in that directory: base URL, CSRF header, problem decoding) | — | `web/src/api/` |

- Generated Go files start with `// Code generated by tools/gen/api; DO NOT EDIT.` (or oapi-codegen's equivalent header). `make gen-api` regenerates everything. CI regenerates into a temporary tree and fails on any difference.
- **Generated model code imports only the standard library, `apitypes` and `secret`.** `github.com/oapi-codegen/runtime` and `github.com/oapi-codegen/nullable` carry v1 decoding into the request path. They are registered **Rejected**, so F4 fails if either ever becomes a product dependency.
- The Go generator tools (oapi-codegen, vacuum, oasdiff) are pinned with `tool` directives in their own module, `tools/apitools/go.mod`. That module is declared in the stack manifest as an `extraGoModules` exception citing this ADR, which keeps their dependency trees out of the product `go.mod`. Their module prefixes are appended to the stack denylist (F3), so no shipped binary can link them.
- Generated packages sit inside their owner's directory, so ADR-0003's import matrix needs no change. A module imports its own `api` package, and the "own `<id>` only" rule forbids importing another's. Kernel `api` packages are kernel packages.

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
- **What a handler never receives.** `Input` holds the decoded path, query, declared headers (`If-Match`, `Idempotency-Key`) and body. `Output` is a typed union of the responses the operation declares. A handler never sees `*http.Request`, `http.ResponseWriter` or the raw body. Streaming bodies (CSV upload, export download) appear as a capped `io.Reader` and an `apihost.Stream`.
- **Startup builds the route table and refuses to serve if it is wrong.** `apihost.Build(doc, tagHandlers, policy, catalogue)` is one function, used both by `compose/server` at startup and by `fitness-api`, so the test and production cannot diverge. It fails start-up when any of these holds:
  1. a contributed route does not match a document operation exactly (method, pattern, `operationId`, tag);
  2. an operation of an **enabled** tag has no handler. Tags of capability-disabled modules are not mounted, and startup logs them;
  3. an operation's `x-permission` is not in the EP-6 catalogue, or is `anonymous` with no matching rule 9 row;
  4. two patterns conflict. ServeMux's own panic is converted into a startup error.
- **One fixed middleware chain.** Every route gets the same chain, built from its row in the route table. Modules cannot add or reorder steps, because no Registrar method exists for it:

  recover → trace ID → body cap → `Content-Type` check (`application/json`, `application/merge-patch+json` or the declared binary type, else 415) → query-credential refusal → authentication (skipped only for allow-listed anonymous rows) → rate limit by class → step-up (rule 9) → `authz` check of `x-permission` → strict decode (rule 6) → handler → JSON v2 encode, plus `Deprecation`/`Sunset` headers for deprecated operations.

  Object-level delegation scope is checked again inside the Action (blueprint §11; T-0047).
- **What is not product API** (the complete list; anything else the server serves is an operation in the document):

  | Route group | Why it is outside the contract | Allow-list row |
  | --- | --- | --- |
  | `GET /healthz`, `GET /readyz`: status only | Load balancers and orchestrators, not clients | AN-1 |
  | `GET /` and `GET /assets/{path...}`, plus the console's client-side routes falling back to `index.html` | Static files. **The fallback never answers under `/api/` or `/auth/`.** An unknown `/api/…` path returns the `not-found` problem, never HTML | AN-2 |
  | `/auth/sso/{idpId}/start`, `/auth/sso/{idpId}/callback` (OIDC redirect, SAML ACS) | Browser redirects and form posts, signed by the IdP; not JSON | AN-3 |
  | The fleet gRPC gateway (`platform/fleet`) | A separate mTLS listener carrying protobuf contracts under `proto/` (TM-F-FLEET). It is not on this router at all | AN-6 |
  | [M4] the edge tunnel router | Its own process (blueprint §5.5) | AN-7 |

  These routes are declared in `policy.yaml` under `nonApiRoutes`, and `apihost` mounts exactly that list. First-run setup (AN-4) and end-user TOTP enrolment (AN-5) are JSON and **are** operations in the contract, with `x-permission: anonymous`.

### Rule 6: Strict JSON at the boundary

1. **Cap first.** `http.MaxBytesReader` applies the operation's `maxBodyBytes` before any byte is parsed. Over the cap → 413.
2. **Validate, then decode.** The whole body is first read through a `jsontext.Decoder` with default options. That rejects invalid UTF-8, escaped lone surrogates, duplicate names and trailing data, and applies our own limits:
   - nesting depth ≤ 32;
   - ≤ 10,000 values per body, unless the operation's class is `bulk`;
   - **no U+0000 in any string** (R3).
3. **Then decode** into the generated `Input` with `json.UnmarshalRead(…, json.RejectUnknownMembers(true))`. Names match case-sensitively, which is the v2 default. Because step 2 has already validated every byte, a nested custom unmarshaler can only ever see valid input.
4. **Errors.** Malformed input → `400 /problems/malformed-request`. A schema violation (an unknown member, a missing required member, a type, a format or a bound) → `400 /problems/validation` with field-level `errors[]`. **Nothing is ever repaired.**
5. **Banned in product code** (`internal/**`, `cmd/**`, generated code included):
   - importing `encoding/json` (v1);
   - the options `jsontext.AllowInvalidUTF8`, `jsontext.AllowDuplicateNames` and `json.MatchCaseInsensitiveNames`;
   - any `GOEXPERIMENT` value containing `nojsonv2`, anywhere in the build.

   Tools and tests may use v1.
6. **Responses** are encoded with v2. `secret.Secret` refuses to marshal (P3), so a secret cannot reach a response body, whatever the schema says.

### Rule 7: One API version that only grows, with explicit stability

- **There is one major version, `/api/v1`, for the whole API.** Product releases (activeDIQ v1, v2) and ManageEngine's two APIs (ADM-188 "v1" and ADM-189 "v2") **both map onto `/api/v1`**. Each parity row is satisfied by `/api/v1` operations, which can be traced through `x-activediq-parity`. We ship **no ManageEngine-compatible URL facade** in the product API. Helping customers move ADMP scripts is a migration-kit concern (E-017: a mapping guide or a client-side shim), and any shim calls these same operations.
- **Additive changes are free:** a new operation, an optional request field, a new response field, a new value in an open enum. Clients must ignore unknown response members, and the generated client does.
- **Breaking changes never happen in place on a `stable` operation.** These count as breaking: removing or renaming anything, tightening validation, making an optional field required, changing a meaning, or changing an operation's permission. A breaking change ships as a **new operation** (a new path or resource name, a new `operationId`) next to the old one. The old operation gets `deprecated: true` plus `x-activediq-sunset`. While it lives, the server sends `Deprecation` ([RFC 9745](https://www.rfc-editor.org/rfc/rfc9745)) and `Sunset` ([RFC 8594](https://www.rfc-editor.org/rfc/rfc8594)) on every response from it. The operation is removed only in or after its sunset release.
- **`/api/v2` exists only through a superseding ADR.** That means a coordinated major version for the whole API, never "v2 of one resource". This is a deliberate change from api-design §9, which allowed per-resource `/api/v2`: mixed prefixes give every client two base URLs and two auth stories.
- **Stability.** Every operation is `x-activediq-stability: preview` or `stable`.
  - A `preview` operation may change incompatibly. The docs, the generated client and the PowerShell module flag it.
  - Promoting an operation to `stable` is a reviewed change. Demoting one is itself a breaking change.
  - At GA, the release checklist requires every operation the console depends on to be `stable`.
  - This lets the API evolve quickly before GA without switching the check off.
- **The support window.** The proposed default is at least two minor releases **and** at least 12 months, whichever is longer (api-design §9). Publishing that promise is a commitment that leaves the building, so it is a CEO decision before GA. It is filed as a follow-on and decided there, not here. `info.version` carries the product's semantic version.

### Rule 8: Problems are a closed catalogue

- Every 4xx and 5xx response is `application/problem+json` ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)) using the shared `Problem` schema. It carries `type`, `title`, `status`, `detail`, `instance`, `code`, `traceId`, `errors[]`, and `directory{resultCode, diagnostic}` with secrets stripped.
- **`type` is the relative reference `/problems/<slug>`.** RFC 9457 §3.1.1 permits a relative URI. Clients match on the string. Rendered pages are the API reference's job (docs-writer).
- The slugs form a **closed catalogue** in `shared/problems.yaml`. It is seeded from api-design `reference/conventions.md` §2 and adds `malformed-request` (400), `step-up-required` (401), `method-not-allowed` (405), `payload-too-large` (413) and `unsupported-media-type` (415).
- `apitypes` generates one constructor per slug. A handler returns either one of these constructors or a plain `error`. A plain error renders as `/problems/internal` with only the `traceId`. No stack trace, SQL or host name ever reaches the client.
- Only `apihost` writes HTTP status codes. `http.Error` and `WriteHeader` are banned elsewhere in `internal/**`.

### Rule 9: The security policy of the contract (`api/openapi/policy.yaml`, owner security-architect)

| Section | What it holds | Enforced by |
| --- | --- | --- |
| `anonymous` | One entry per anonymous operation or non-API route: method, path, AN row, gate, reason | A4 (TM-F-ANON): the routes the built router serves **without authentication** equal this list exactly |
| `nonApiRoutes` | The rule 5 table | A4: the routes mounted outside the document equal this list exactly |
| `secretResponses` | Operations allowed to return a secret once: LAPS and BitLocker reveal (`secret.*` permissions, DM-33.I2), and API-token and enrollment-token creation (shown once, TM §7.5). Each names its single response schema | A8 (TM-F-SECRETOUT linter half) |
| `stepUp` | The permissions that require a fresh MFA (TM-D16 §7.4 table) | `apihost` enforces it from the route table. A13 fails stale entries |
| `largeBodies` | Operations allowed `maxBodyBytes` above 16 MiB, with a reason | A12 |

- **The secret linter (A8).** It fails when any schema reachable from any response, followed through `$ref`, `allOf`, `oneOf`, `items` and `additionalProperties`, carries any of these:
  - `x-activediq-secret`, `writeOnly: true` or `format: password`;
  - a property whose name matches the secret-name list (`password`, `secret`, `token`, `apiKey`, `privateKey`, `recoveryKey`, `clientSecret`, case-insensitive, suffixes included).

  The only exceptions are the operations listed in `secretResponses`.
- **Credentials.** Security schemes are only `bearer` (`adq_` API tokens, `Authorization` header) and the session cookie plus a CSRF header. There is no `apiKey` scheme `in: query` and no credential-named query parameter. At runtime, `apihost` refuses with 400 any `/api/` request whose query string carries a credential-named key.
- **Who reviews `policy.yaml`.** Every change to it is tagged `security-sensitive`, so security-architect reviews it (review-checklist). When hosted CI exists, a CODEOWNERS entry adds a required review. Until then, that review is the manual half.
- **Two anonymous routes are missing from the allow-list.** Local break-glass sign-in (ADM-142) and AD-identity sign-in via SPNEGO (blueprint §11) both need routes reachable before authentication, and neither is in AN-1 to AN-7 today. Amending §7.6 belongs to security-architect (follow-on below). Until that lands, those routes cannot be added, because A4 would fail.

### Rule 10: Limits are declared, not improvised (TM-Q2)

- **Rate classes.** `x-activediq-limits.class` is one of `read`, `write`, `bulk`, `auth`, `reveal` or `anonymous`. The default is `read` for GET and HEAD and `write` for everything else. Anonymous operations must declare `anonymous` or `auth`. Operations in `secretResponses` must declare `reveal`.
- **How the limits work.** Limits apply per token and per source IP. A limited request gets `429 /problems/rate-limited` with `Retry-After`. There is **no daily quota and no metering**, which keeps the ADM-190 lead. The numbers per class are `apihost` configuration. Their defaults are set by the apihost build ticket with security-architect.
- **Body caps.** `maxBodyBytes` defaults to 1 MiB for JSON bodies. An operation with a binary or CSV upload must declare it. Anything above 16 MiB needs a `largeBodies` entry.

### Rule 11: Tenancy

The tenant never travels in the contract (ADR-0002 rule 5). T5 (`openapi-tenant-param`) remains the single implementation of that check. `fitness-api` does not duplicate it. It only fails if T5's scanner cannot parse a file that `tools/gen/api` bundles.

### Rule 12: The console uses the generated client only

- `web/src/api/` holds only the generated types and `client.ts`.
- Outside that directory, `web/src/**` may not call `fetch`, `XMLHttpRequest` or `EventSource`, may not import an HTTP library, and may not contain a string literal starting with `/api/`. An ESLint rule enforces this, and A5 runs it.
- A console feature that needs data gets an operation in the contract first (blueprint §6: no private endpoints).

### Rule 13: The contract changes first

- A change to an operation starts as a change to `api/openapi/**`, reviewed against api-design §10, before any handler exists.
- vacuum lints the bundle with our ruleset (`api/openapi/.vacuum.yaml`: OpenAPI 3.1 validity, rule 1 names, rule 2 dialect). oasdiff compares it with `main` and with the latest release tag (A10).

## Alternatives considered

| Alternative | What it would buy us | Why not |
| --- | --- | --- |
| **oapi-codegen end to end** (`std-http-server` + `strict-server` + models) | One mature, popular tool. It targets ServeMux, so `apihost` could keep the mux. A typed strict-server interface. 3.1 support since v2.8 ([releases](https://github.com/oapi-codegen/oapi-codegen/releases)). Almost no generator code of our own. | <ul><li>It generates **one** `StrictServerInterface` for the whole API, unless we run it once per tag. Even then the routing glue is its own, and nothing ties a route to `x-permission`.</li><li>Its decode path is v1 `encoding/json` `[UNVERIFIED]`, which repairs invalid UTF-8 and ignores unknown members. Overriding its templates means maintaining a fork of them across releases.</li><li>Generated code pulls `oapi-codegen/runtime` into the binary.</li><li>We keep it for what it does well: model types.</li></ul> |
| **ogen** | <ul><li>Strong typing with `Opt`/`Nil` wrappers.</li><li>Generated validation of every schema constraint.</li><li>A static router.</li><li>No reflection, and fast ([repo](https://github.com/ogen-go/ogen)).</li></ul> | <ul><li>Its own router replaces the mux ADR-0003 gives `apihost`.</li><li>Its jx codec documents no rejection of invalid UTF-8 or lone surrogates `[UNVERIFIED]`, so R3 would rest on a library we would have to audit and pin.</li><li>It generates one global `Handler`. Per-group interfaces need a per-operation `x-ogen-operation-group`.</li><li>3.1 support is undocumented.</li></ul> |
| **Fully in-house generator** (types too, using libopenapi or kin-openapi as the parser) | <ul><li>One tool we fully control.</li><li>Types shaped exactly for json/v2 and `Opt`.</li><li>No oapi-codegen dependency.</li></ul> | <ul><li>Emitting types from JSON Schema (unions, enums, formats, nullability) is the large, bug-prone part.</li><li>oapi-codegen's models already serve it within the rule 2 dialect.</li><li>**Revisit** if model output blocks rule 2 or rule 6.</li></ul> |
| **Code-first** (handlers annotated, OpenAPI generated from Go, e.g. huma) | <ul><li>No YAML.</li><li>The document can never drift from the handlers.</li></ul> | <ul><li>The contract becomes a by-product of the code. The opposite is what we need: reviewed before any handler exists (api-design §1), the source for the TypeScript client and the PowerShell module, and diffable for breaking changes.</li><li>It would also add a framework dependency.</li></ul> |
| **chi or another router** | <ul><li>Middleware composition helpers.</li><li>Route groups.</li></ul> | <ul><li>ServeMux has had method and wildcard patterns since Go 1.22 ([docs](https://pkg.go.dev/net/http#ServeMux)).</li><li>Our middleware chain is fixed and generated per route, so route groups add nothing.</li><li>It is one less dependency to register.</li></ul> |
| **Per-resource `/api/v2`** (api-design §9 as written) | Breaking fixes stay local to one resource. | Clients juggle two prefixes. A new operation next to a deprecated one gives the same locality with one base URL. |
| **Decode with v1 plus `DisallowUnknownFields` and a UTF-8 pre-check** | No dependence on json/v2 being GA. | json/v2 is GA in 1.27. Hand-rolling validation that jsontext already does is a second implementation of R3, and the v1 path still matches names case-insensitively. |
| **Redocly CLI or Spectral** for bundling and lint | Popular, with rich rulesets. | Both are Node tools, adding Node to the Go CI path, and vacuum lints Spectral-compatible rulesets in Go. Our bundling is a merge under rule 1, which we own anyway. |
| **@hey-api/openapi-ts or orval** for the client | <ul><li>Generated SDK functions.</li><li>Query hooks.</li></ul> | <ul><li>More generated runtime code to review and ship.</li><li>openapi-typescript emits types only, and openapi-fetch is about 6 kB ([openapi-ts.dev](https://openapi-ts.dev/introduction)).</li></ul> |
| **Defer until the first endpoint** | Nothing is decided early. | E1.6 (T-0086, T-0069) is on the checkpoint 2a critical path. Deciding late is how PatchIQ's first feature skipped the interface. |

## Consequences

**Positive**

- A route can exist only as a document operation or a `policy.yaml` entry. It cannot skip authentication, its permission or strict decoding, because a handler never touches HTTP. This closes, in the structure itself, the CVE-2021-40539 class the threat model cites.
- No module-shaped growth in core. Adding a module's API touches its own YAML file and its own generated package.
- One strictness implementation for the whole API (rule 6). Passwords cannot be silently repaired.
- The console, scripts, ITSM connectors and later the PowerShell module and MCP see one contract with one stability promise. Unmetered rate classes keep the ADM-190 lead.

**Negative**

- **We own about 600 lines of generator** (`tools/gen/api`: bundle, interfaces, `Bind`, route rows), plus its staleness check. It is a component with an owner (api-engineer) and its own tests.
- **Two generators in Go.** oapi-codegen's 3.1 support is "initial". The rule 2 dialect contains the risk, and the A2 corpus pins the output we rely on. A bad oapi-codegen release is caught by the staleness diff, not in production.
- **The dialect costs some expressiveness.** No `anyOf` and no free-form objects in requests. Polymorphic filter ASTs therefore use a discriminated `oneOf` and are parsed by P1, not by the schema.
- **Writing YAML by hand is slower than code-first.** That is the price of reviewing the contract first.
- `GOEXPERIMENT=nojsonv2` stops being an escape hatch for us. If a json/v2 regression lands in a Go point release, the remedy is to pin the previous toolchain, not to fall back to v1.

**Follow-on work** (filed with this ADR)

- **T-0147** build (api-engineer): `tools/gen/api` + the `api/openapi/` skeleton (root, `shared/` with Problem, the catalogue, paging, `GUIDRef`/`ObjectView`, `Opt`, `SecretInput`, `policy.yaml` seeded from TM §7.6) + `tools/apitools/go.mod` + the manifest exception and denylist entries + `make gen-api` and its staleness check + the web client skeleton and its ESLint rule. T-0086 (apihost) depends on it.
- **T-0148** chore (devops-engineer): `fitness-api`, static half: A1, A2, A3 (document side), A5, A7 (static), A8, A10, A11, A12, A13. Its checks activate when their inputs appear, each with a failing fixture. T-0069 (the first operations) depends on it, and on T-0151.
- **T-0149** chore (api-engineer): `fitness-api`, runtime half: A3 (catalogue side), A4, A6, A7 (corpus), all on `apihost.Build`. Depends on T-0086.
- **T-0150** chore (solution-architect): align blueprint §1, §6, §16 and §17 and api-design §1 and §9 (paths, per-API major version, stability, extension names) with this ADR.
- **T-0151** chore (security-architect): amend TM §7.6 for local break-glass sign-in and SPNEGO sign-in routes; seed `policy.yaml`'s `anonymous`, `secretResponses` and `stepUp`; set the default numbers per rate class (TM-Q2).
- **T-0152** decision-prep (product-manager): the published deprecation and support window (rule 7), for the CEO before GA.

**Revisit when**

- json/v2 changes a default we rely on (the A7 corpus fails).
- oapi-codegen's model output blocks rule 2 or 6, in which case we take the fully in-house alternative.
- Partner-built modules need their own contracts.
- We need a coordinated `/api/v2`, which takes a superseding ADR.

## Fitness function

**Job:** `fitness-api`. It is a Go program at `tools/fitness/api/`, invoked by `make fitness` (and therefore `make ci`), with `make lint-api` (vacuum) and the oasdiff step as parts of it. Every check has a failing fixture in `check_test.go`, so a check that silently matches nothing is itself a failure. A check whose input does not exist yet (no `api/openapi/`, no `apihost`) reports itself as **inactive** rather than passing silently. **The ADR is not `accepted` while any check is inactive.**

| Check | What fails the build | Closes |
| --- | --- | --- |
| **A1** Layout and bundle | <ul><li>A file under `api/openapi/` outside the rule 1 places.</li><li>A `modules/<id>.yaml` whose `<id>` is not a module in the generated module list.</li><li>A `platform/<pkg>.yaml` with no `internal/platform/<pkg>`.</li><li>An operation with zero or two or more tags, or a tag different from its file's.</li><li>A cross-module or upward `$ref`.</li><li>A duplicate `operationId` or component name.</li><li>A stale bundle (`openapi.gen.json` ≠ regeneration).</li></ul> | Contract drift; cross-module coupling through schemas |
| **A2** Dialect and style | <ul><li>vacuum errors under `.vacuum.yaml`.</li><li>A rule 2 construct.</li><li>An `x-` key not in rule 3.</li><li>A trailing slash.</li><li>A non-camelCase member.</li><li>An unbounded integer that is not a string.</li><li>A path parameter or field named `dn`/`distinguishedName` used as an identifier in a path.</li></ul> | Generator surprises; DN-as-ID |
| **A3** Permission | <ul><li>An operation without exactly one `x-permission`.</li><li>`anonymous` without `x-activediq-anonymous` and a `policy.yaml` row.</li><li>Runtime half: a permission that no Registrar or kernel contribution declares in the EP-6 catalogue.</li></ul> | TM-TB2-T2; DM-33.I1 |
| **A4** Route set (TM-F-ANON) | For **each** profile manifest (`windows`, `linux-oci`, `saas`), the router built by `apihost.Build` from the real module list serves a route that is neither an operation of an enabled tag nor a `nonApiRoutes` entry, or misses one. The routes it serves without authentication differ from `policy.anonymous`. Then an **HTTP probe**, generated from the route table: every non-anonymous route answers 401 to an unauthenticated request and 403 to a principal holding no permissions, which proves the middleware enforces what the table says. | Unauthenticated or unpermissioned routes; private endpoints |
| **A5** Generated client | <ul><li>`web/src/api/schema.gen.d.ts` is stale.</li><li>A file in `web/src/api/` other than the generated files and `client.ts`.</li><li>The rule 12 ESLint rule finds `fetch`/`XMLHttpRequest`/`EventSource`, an HTTP-library import, or an `/api/` literal elsewhere in `web/src`.</li></ul> | A hand-written client |
| **A6** Generated server | <ul><li>A `*.gen.go` in an `api` package is stale.</li><li>`apihost`'s route constructors are called from a file without the generated header.</li><li>`Registrar.API` is called with anything but the module's own `api.Bind(…)`.</li><li>A handler package imports `net/http` to reach the request or response (only `apihost` and generated code may).</li></ul> | Hand-built `TagHandlers`; handlers bypassing decode |
| **A7** Strict JSON | Static: an `encoding/json` (v1) import in `internal/**` or `cmd/**`; a banned v2 option outside tests; a `GOEXPERIMENT` containing `nojsonv2` in any Makefile, script, Dockerfile or env file. Corpus: for **every** operation with a body, generated from the route table, these return the expected problem, and the handler is never called: `\xff`, `"\ud800"`, `"\udc00"`, a duplicate member, an unknown member, a wrong-case member, `\u0000` in a string, trailing data, depth 33, an oversize body and a wrong `Content-Type`. | The U+FFFD repair (`lessons.md`); R3 |
| **A8** Secrets out (TM-F-SECRETOUT, linter half) | <ul><li>A rule 9 secret marker or secret-named property reachable from a response not listed in `secretResponses`.</li><li>A credential-named query parameter.</li><li>An `apiKey` scheme `in: query`.</li><li>A `secretResponses` operation whose class is not `reveal`, or whose permission is neither a `secret.*` permission nor a token-creation permission.</li></ul> The runtime half (the canary through every sink) belongs to T-0033 and T-0034. | CVE-2022-24978 class; TM-TB2-T6 |
| **A9** Tenancy | No separate check: T5 `openapi-tenant-param` runs in `fitness-tenancy`. A1 fails if a bundled file is one T5 cannot parse. | — |
| **A10** Versioning | <ul><li>oasdiff reports a breaking change, against `main` and against the latest release tag, on a `stable` operation.</li><li>A `stable` → `preview` demotion.</li><li>An operation without `x-activediq-stability`.</li><li>`deprecated: true` without `x-activediq-sunset`.</li><li>A deprecated operation removed before its sunset release.</li></ul> | In-place breaking changes |
| **A11** Problems | <ul><li>A 4xx or 5xx response that is not `application/problem+json` with the shared `Problem`.</li><li>A `type` outside the catalogue.</li><li>`http.Error` or `WriteHeader` in `internal/**` outside `apihost`.</li></ul> | Leaky, ad-hoc errors |
| **A12** Limits | <ul><li>An unknown rate class.</li><li>An anonymous operation not in class `anonymous` or `auth`.</li><li>An upload operation without `maxBodyBytes`.</li><li>`maxBodyBytes` above 16 MiB without a `largeBodies` entry.</li></ul> | TM-Q2 |
| **A13** Policy hygiene | A `policy.yaml` entry that is stale: it names a missing route, operation or permission. Or an entry with no reason or no AN/TM reference. | Exemptions becoming permanent |

**Bypasses, and what closes them:**

- **A module mounting its own route.** ADR-0003 M4 bans `http.Handle`, `HandleFunc`, `ServeMux` and `net.Listen` in modules, and back doors into kernel hosts.
- **A hand-built `TagHandlers`.** Closed three ways: A6, `apihost.Build` refusing anything not in the embedded document, and the staleness check on that document.
- **A handler reading the raw body.** It has no `*http.Request` (rule 5), and A6 bans `net/http` in handler packages.
- **A second JSON decoder.** A7, static and corpus.
- **A console call around the client.** A5.
- **A secret in an unmarked field.** The name heuristic (A8), plus `secret.Secret` refusing to marshal, plus the TM-F-SECRETOUT canary.
- **A route served only in one profile.** A4 runs per profile.

**Not automatable, and who checks it.** Two things stay manual:

- Whether an operation's `x-permission` is the **right** permission for what it does. code-reviewer checks it, and security-architect checks it for `security-sensitive` tickets.
- Who reviews `policy.yaml` changes. security-architect does, by ticket tag, until CODEOWNERS can enforce it.

**Status path.** Ratified when the director signs it off at review of T-0046. Accepted when `fitness-api` A1–A13 (A9 delegated to T5) all run **active** and green in `make ci` on `main`.

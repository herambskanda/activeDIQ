---
title: "API contract pipeline: api/openapi, tools/gen/api, apihost and the web client"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: api-engineer
ticket: T-0147
sources_last_checked: 2026-10-02
---

# API contract pipeline

ADR-0004 (`decisions/0004-public-api-contract-openapi-first.md`) rules 1-4, 12 and 13, as built by T-0147.
The contract is the only source: Go types, decoders, validators, handler interfaces, route rows and the
TypeScript types are all generated from it, and `make gen-api-check` (part of `make ci`) fails when any of them is stale.

```
api/openapi/openapi.yaml + shared/*.yaml + modules/<tag>.yaml + platform/<tag>.yaml
        │  tools/gen/api: bundle (rule 3) → dialect check (rule 2) → emit
        ▼
internal/platform/apihost/spec/openapi.gen.json          the bundle: served, linted, diffed
internal/platform/apihost/spec/policy.gen.json           policy.yaml as JSON (tools/gen/policyjson, so no YAML parser ships); apihost.ParsePolicy is the one parser (server + fitness A4)
internal/platform/apihost/apitypes/{models,problems}.gen.go   shared schemas and the problem catalogue
internal/modules/<tag>/api/{models,handlers}.gen.go      per tag: bodies, Handlers interface, Bind, route rows
web/src/api/schema.gen.d.ts                              paths and components (openapi-typescript)
```

## Layout

| Path | What | Written by |
| --- | --- | --- |
| `api/openapi/openapi.yaml` | info, servers, security schemes, the tag list (a tag is a module id) | hand |
| `api/openapi/shared/*.yaml` | scalars, paging, secret, job, problems: components every tag may `$ref` | hand |
| `api/openapi/modules/<tag>.yaml` | one tag's paths and components; `$ref`s are rooted at `api/openapi/` | hand |
| `api/openapi/policy.yaml`, `.vacuum.yaml` | the generator's policy and the house vacuum ruleset (`make lint-api`) | hand |
| `tools/gen/api/` | the generator (`go run ./tools/gen/api`; `-check`, `-skip-ts`, `-repo`) | hand |
| `internal/platform/apihost/apitypes/` | hand-written runtime the generated code stands on: `Opt`, `Presence`, `Union`, `Problem`, `ViolationOf`, scalars | hand |
| `internal/platform/apihost/route.go` | the route types the generated route rows use | hand |
| `internal/platform/apihost/apitest/` | the A14 conformance harness: `Conform` wraps routes so every response body is validated with the generated validators; module contract tests and fitness-api use it (test support, never imported by product code) | hand |
| `tools/fitness/api/{a4,a6,a7corpus,a7gen,a7closure,a14,runtime}.go` | the runtime half of fitness-api (T-0018): per profile it builds the router with `apihost.Build` and probes it (A4), checks generated-server source rules (A6), walks the request schema into the A7 corpus and runs the type closure and the ajv cross-check, and runs every route through `apitest` (A14). The tag source is the module list and is empty until `Registrar.API` exists, so on the real tree these run on fixtures and the status line says so | hand |
| `internal/platform/apihost/{build,chain,body,render,ports,document,policy}.go` | `Build` (checks routes against the embedded document and policy), the fixed middleware chain, capped body read and strict JSON pass, problem and response rendering, the ports `compose/server` injects, and the exported `HostBindings` table | hand |
| `internal/compose/server/ops.go`, `internal/platform/opsmetrics/` | optional operator metrics listener L4 (T-0533): off unless `ACTIVEDIQ_OPS_ADDR` and `ACTIVEDIQ_OPS_TOKEN_FILE` are both set (one alone, or an ops address equal to `ACTIVEDIQ_API_ADDR`, or a non-loopback bind without `ACTIVEDIQ_API_TLS_DIR`, fails startup). `ops.go` starts a second TLS-only server (the API's per-install certificate) whose mux holds `GET /metrics` and nothing else; `opsmetrics` is the handler: one operator bearer token (>= 32 bytes, 0600 owner-only file opened by `openSecretFile`, constant-time compare), every other credential (session cookie, tenant API key, Basic) gets 401, and the body is `keys.WriteMetrics` (`activediq_keys_dek_unwraps_total{tenant,outcome}`). The API handler has no `/metrics` route, so the metrics are never reachable from the internet-facing listener. Runbook: `knowledge/development/runbooks/ops-metrics.md`; threat model §8.1 L4. The listening-socket proof for L4 is T-0137 (TM-F-PORTS) | hand |
| `internal/compose/server/{server,httpserver,apiports}.go` | `Run` builds the API with `apihost.Build` (budget from `ACTIVEDIQ_API_BODY_BUDGET`, default 64 MiB, non-positive fails startup; `ACTIVEDIQ_TRUSTED_PROXIES`, comma-separated CIDRs/IPs, default none: only when the TCP peer is listed is the right-most untrusted `X-Forwarded-For` hop the client address for rate limits, audit and `Request.PeerIP`, otherwise forwarded headers are ignored; an invalid entry fails startup) (T-0442), listens on `ACTIVEDIQ_API_ADDR` through `newAPIServer` and serves TLS only (TLS 1.2+, per-install certificate from `internal/platform/apitls`, persisted in `ACTIVEDIQ_API_TLS_DIR`, key wrapped by the `platform/keys` provider as `api-key.sealed.json` via `apitls.LoadOrGenerateSealed` in the platform domain of `platform/keys` (`WrapPlatform` purpose `api-tls`, never a tenant context; a stale plaintext `api-key.pem` is removed on every start and a failed removal fails startup; a KMS-style provider's key rotation re-wraps under the current KEK on the next start, a single-KEK local provider cannot follow a KEK change) (T-0103; T-0407: `keyprovider.go` builds a `keys.LocalProvider` from the KEK profile `ACTIVEDIQ_KEK_FILE` (64 hex chars, regular file, 0600 on Unix, requires `ACTIVEDIQ_API_TLS_DIR`) and `ACTIVEDIQ_KEK_ID` (default `platform`); the file is opened once with no-follow and checked on the handle (regular, owned by the service uid, 0600, not all-zero), must sit outside the TLS directory (config check, symlink-resolved), and the profile is refused on Windows until a DACL check exists; a configured but missing, loose or malformed KEK fails startup naming the path and never its contents, a wrong KEK fails the unseal with the sealed file untouched, and only an unset `ACTIVEDIQ_KEK_FILE` keeps the legacy plaintext key), SHA-256 fingerprint logged at start; the directory must be owned by the server user and not group/other-writable (packaging sets this: Windows ACL script and linux-oci prepare script, T-0104, `make fitness-packaging`; the server does not yet check owner/DACL on Windows at runtime: T-0413), the key 0600 and regular files only, any unreadable, corrupt or mismatched file fails startup rather than regenerating, and only a missing certificate or near-expiry renewal (WARN with old and new fingerprints) generates; a non-loopback bind without that directory fails startup), and injects fail-closed ports until the auth/RBAC/limit kernels land. `operation.go` (T-0176): `buildOperation` asserts `operation.HoldsMinter` (boot fails with `ErrNoMinter`), installs the audit `Chainer` commit hook on the store, and gives `operation.Runner` the chainer as `audit.Sink`, `directory/client` as `LiveFacts` (refuses with `ErrNoFacts` until the transport lands) and a deny-all `Authorizer` until RBAC persistence lands | hand |
| `internal/platform/secret/secretjson/` | `Decode`, the one decode path for API bodies; only apihost calls it (FF-SP2) | hand |
| `tools/apitools/` | its own Go module: `tool` directives for vacuum and oasdiff; never linked into a shipped binary (stack manifest exception, ADR-0004) | hand |
| `web/src/api/client.ts` | the one hand-written client file (openapi-fetch over the generated `paths`); ESLint forbids any other API call (rule 12) | hand |

## What the generator refuses

Before any file is written the dialect check (about 40 refusals, each tested in `tools/gen/api/contract_test.go`) rejects:
a raw filter string, a DN or a free-form object where a typed schema belongs; an inline object, enum or `oneOf` member;
a nullable `$ref`, array or map; a secret (`SecretInput`) reachable from a response; objects of more than 64 members;
a body that is not a `$ref`; a component declared in two files; an operation whose tag is not in the tag list.
The set of bound primitives (`SecretInput` → `internal/platform/secret.Secret`, `FilterAst`, `ReportAst`, `GUIDRef`, `ObjectView`)
lives in `DefaultConfig` (`tools/gen/api/main.go`); a binding marked `Pending` is emitted as an ordinary generated type until its primitive exists.

## The fixture

`tools/gen/api/testdata/fixture/openapi/` is a small contract that uses every dialect construct (9 operations). Its generated
output is committed under `tools/gen/api/internal/fixture/` and compiled and exercised by `go test ./tools/gen/api/...`:
the decode corpus, patch states, unions, secret destruction, bind and validate, route rows. After changing an emitter run
`go test ./tools/gen/api -run Golden -update` (rewrites the fixture tree) and `go run ./tools/gen/api` (rewrites the real tree), and commit both.

## Gates

| Gate | Where | Proves |
| --- | --- | --- |
| `make gen-api-check` | `make ci` | every generated file is current; none missing or orphaned |
| `make lint-api` | `make ci` | the bundle passes vacuum with `api/openapi/.vacuum.yaml` |
| `go test ./tools/gen/api/...` | `make test` | emitters, dialect refusals, determinism, import allow-list of generated code |
| `tools/ci/proof.sh` | `make ci-proof` | a hand-edited or missing generated file, a duplicate component and each rule 12 ESLint rule fail |
| `make fitness-stack` | `make ci` | `tools/apitools` is a cited exception; kin-openapi, oapi-codegen, pb33f, daveshanley, oasdiff are denylisted from shipped binaries |

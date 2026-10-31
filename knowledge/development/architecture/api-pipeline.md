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
| `internal/platform/setup` + `internal/compose/server/firstrun.go` | First-run setup secret (T-0636, TM-TB16-T7, AN-4): a fresh install writes a 256-bit random secret (only its SHA-256 in `setup.json`) to `<ACTIVEDIQ_API_TLS_DIR>/setup/setup-secret` (dir 0700, file 0600; on Windows the directory's inherited ACL), expiring after `ACTIVEDIQ_SETUP_TTL` (default 1h, max 24h). `activediq-server setup show` prints it for the installing admin; the secret is never logged. `claimFirstRunSetup` (`POST /api/v1/setup/claim`, anonymous AN-4, class auth) consumes it and creates the first tenant owner in one step (T-0707): the body carries the secret and `owner{displayName,email}`; `Store.Reserve` renames `setup.json` to `setup.claiming` (atomic, one winner), `server.firstOwners` then creates the local account, its tenant-owner grant and the `setup.claimed` / `setup.owner_created` audit events (source IP, install id = tenant id, never the secret) in one tenant transaction, and `Reservation.Done` renames to `setup.claimed`; if the owner cannot be created `Abort` restores `setup.json` so the same secret can retry. Owner details are validated before the secret is looked at (a 400 never confirms the secret). Wrong, expired, used, in-flight and owner-already-exists are one 401 `/problems/setup-refused` (logged as `auth_failure`, no audit row); a claimed or interrupted-claim install never reissues (an operator clears `setup.claiming` to reset). The new account is `invited` with no credential: enrolling the first factor is separate work. File-backed and single-node by design | hand |
| `internal/compose/server/{server,httpserver,apiports}.go` | `Run` builds the API with `apihost.Build` (budget from `ACTIVEDIQ_API_BODY_BUDGET`, default 64 MiB, non-positive fails startup; `ACTIVEDIQ_PUBLIC_URL`, the https origin browsers use (no path, user or query; optional): it is the WebAuthn relying party (RP ID = its hostname, the one allowed origin = the origin itself), so with it set the console stack builds `authn.WebAuthnFactor` and mounts the WebAuthn sign-in routes (unset: they answer 501 and start-up logs once that WebAuthn sign-in is off), and it is also the attestation's redirect origin, which additionally needs `ACTIVEDIQ_ATTEST_CLIENT_ID` (T-0853); `ACTIVEDIQ_TRUSTED_PROXIES`, comma-separated CIDRs/IPs, default none: only when the TCP peer is listed is the right-most untrusted `X-Forwarded-For` hop the client address for rate limits, audit and `Request.PeerIP`, otherwise forwarded headers are ignored; an invalid entry fails startup) (T-0442), listens on `ACTIVEDIQ_API_ADDR` through `newAPIServer` and serves TLS only (TLS 1.2+, per-install certificate from `internal/platform/apitls`, persisted in `ACTIVEDIQ_API_TLS_DIR`, key wrapped by the `platform/keys` provider as `api-key.sealed.json` via `apitls.LoadOrGenerateSealed` in the platform domain of `platform/keys` (`WrapPlatform` purpose `api-tls`, never a tenant context; a stale plaintext `api-key.pem` is removed on every start and a failed removal fails startup; a KMS-style provider's key rotation re-wraps under the current KEK on the next start, a single-KEK local provider cannot follow a KEK change) (T-0103; T-0655: `keyprovider.go` unlocks the passphrase keystore (`kek.keystore.json`, `keys.OpenKeystore`) named by `KEKConfig` (`kekconfig.go`, the only reader of `ACTIVEDIQ_KEK_*`); no provider, an unknown one, another provider's key, a passphrase value or a loose keystore directory fails startup with a `KEK…` code; a wrong passphrase and a corrupt keystore are the same `keys.UnwrapFailed`; the KEK directory must sit outside the TLS directory; `kek init` (`kekinit.go`) is the only place a KEK is generated; the legacy `ACTIVEDIQ_KEK_FILE` profile is deleted and refused if set (`KEKSettingRemoved`); a KEK that cannot unwrap the sealed TLS key fails startup with the sealed file untouched), SHA-256 fingerprint logged at start; the directory must be owned by the server user and not group/other-writable (packaging sets this: Windows ACL script and linux-oci prepare script, T-0104, `make fitness-packaging`; the server does not yet check owner/DACL on Windows at runtime: T-0413), the key 0600 and regular files only, any unreadable, corrupt or mismatched file fails startup rather than regenerating, and only a missing certificate or near-expiry renewal (WARN with old and new fingerprints) generates; a non-loopback bind without that directory fails startup), and injects fail-closed ports until the auth/RBAC/limit kernels land. `operation.go` (T-0176): `buildOperation` asserts `operation.HoldsMinter` (boot fails with `ErrNoMinter`), installs the audit `Chainer` commit hook on the store, and gives `operation.Runner` the chainer as `audit.Sink`, `directory/client` as `LiveFacts` (refuses with `ErrNoFacts` until the transport lands) and a deny-all `Authorizer` until RBAC persistence lands | hand |
| `internal/platform/secret/secretjson/` | `Decode`, the one decode path for API bodies; only apihost calls it (FF-SP2) | hand |
| `tools/apitools/` | its own Go module: `tool` directives for vacuum and oasdiff; never linked into a shipped binary (stack manifest exception, ADR-0004) | hand |
| `web/src/api/client.ts` | the one hand-written client file (openapi-fetch over the generated `paths`); ESLint forbids any other API call (rule 12) | hand |
| `web/src/types/openapi-typescript-helpers.d.ts` | type-only stand-in for `openapi-typescript-helpers` (tsconfig `paths`): `Readable`/`Writable` pass strings through, so an open enum `(string & {})` survives openapi-fetch's response mapping instead of becoming a `String` copy; guarded by `web/src/types/open-enum.test.ts`; lives outside `web/src/api`, where A5 allows only generated files and `client.ts` | hand |

## What the generator refuses

Before any file is written the dialect check (about 40 refusals, each tested in `tools/gen/api/contract_test.go`) rejects:
a raw filter string, a DN or a free-form object where a typed schema belongs; an inline object, enum or `oneOf` member;
a nullable `$ref`, array or map; a secret (`SecretInput`) reachable from a response; objects of more than 64 members;
a body that is not a `$ref`; a component declared in two files; an operation whose tag is not in the tag list.
The set of bound primitives (`SecretInput` → `internal/platform/secret.Secret`, `FilterAst`, `ReportAst` → `internal/platform/report.Query`, `GUIDRef`, `ObjectView`)
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

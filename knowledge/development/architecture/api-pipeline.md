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
| `internal/platform/apihost/route.go` | the minimal route types the generated route rows use (the router itself is a later ticket) | hand |
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

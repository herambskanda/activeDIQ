---
title: "Runbook: change the public API contract"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: api-engineer
ticket: T-0147
---

# Runbook: change the public API contract

Design: `architecture/api-pipeline.md`. Conventions: the `api-design` skill. ADR-0004.

## Prerequisites

`make web-install` once (openapi-typescript runs under Node). Nothing else: the generator is `go run ./tools/gen/api`, vacuum and oasdiff come from `tools/apitools` by `go tool`.

## Steps

1. Edit `api/openapi/`: the tag file (`modules/<tag>.yaml`), `shared/` for a shared component, the root for tags and security. Never edit a `*.gen.*` file.
2. `make gen-api` regenerates the bundle, Go and TypeScript. A refusal names the file, the construct and the rule; fix the contract, not the generator.
3. `make lint-api` lints the bundle (vacuum, `api/openapi/.vacuum.yaml`). Errors fail; the current warnings are missing examples and component descriptions.
4. `go test ./tools/gen/api/... ./internal/platform/apihost/...` and, in `web/`, `npx vitest run`.
5. Commit the contract and every regenerated file in the same change. CI runs `make gen-api-check`: a stale or missing generated file fails the build.
6. Additive changes only within `/api/v1`. A rename, a removed member or a tightened type is a breaking change: it needs a new version and a migration note.

## Changing the generator

Edit `tools/gen/api`, then `go test ./tools/gen/api -run Golden -update` (rewrites the fixture's golden tree), `go run ./tools/gen/api`, review both diffs, and commit them with the emitter change.

## Gotchas

- `$ref` in a contract file is rooted at `api/openapi/` (`shared/paging.yaml#/components/schemas/Cursor`), also for parameters and responses.
- A plain YAML scalar containing `: ` (a summary, say) must be quoted.
- `GENAPI_DUMP=1 go run ./tools/gen/api` prints the numbered source of a generated file that fails to parse.
- The working directory must be the repository root, or pass `-repo`.

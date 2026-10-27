---
title: "Runbook: change the public API contract"
date: 2026-10-02
updated: 2026-10-21
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

## What CI asserts about the sources (`make fitness-api`)

`make ci` runs `fitness-api` (T-0011, ADR-0004 A1 and A13) beside `gen-api-check`: the layout of
`api/openapi/` (files only in the rule 1 places; `modules/<id>.yaml` only for a directory under
`internal/modules`, `platform/<pkg>.yaml` only for an `internal/platform/<pkg>`; one tag per operation,
equal to its file's; unique `operationId` and component names; no cross-module or upward `$ref`) and
the hygiene of `policy.yaml` (reason, AN/TM reference, and every name it uses exists). It reads the
sources itself, not the bundle, so it still catches what a generator change would let through. Run it
before `make gen-api` to get the rule and the line. The status table it prints lists the checks still
inactive; see `ci-and-build.md`.

## Changing the generator

Edit `tools/gen/api`, then `go test ./tools/gen/api -run Golden -update` (rewrites the fixture's golden tree), `go run ./tools/gen/api`, review both diffs, and commit them with the emitter change.

## Gotchas

- `$ref` in a contract file is rooted at `api/openapi/` (`shared/paging.yaml#/components/schemas/Cursor`), also for parameters and responses.
- A plain YAML scalar containing `: ` (a summary, say) must be quoted.
- `GENAPI_DUMP=1 go run ./tools/gen/api` prints the numbered source of a generated file that fails to parse.
- The working directory must be the repository root, or pass `-repo`.
- **Cookies, peer address, repeated headers (T-0417).** A parameter `in: cookie` is a plain string in the contract (no pattern or length) and an `apitypes.CookieValue` in the Input, which prints as [REDACTED] under fmt, slog and JSON and gives its text only through `Reveal()`; apihost passes a route only the cookies it declares, and the generator rejects `__Host-adiq_session` as a parameter. The field is empty when the cookie is absent or repeated, and it never yields a validation problem, so a missing credential cookie cannot be told from a wrong one. `x-activediq-peer-ip: true` on an operation adds `PeerIP` (the client address: the TCP peer, or the right-most untrusted X-Forwarded-For hop when the peer is a configured trusted proxy) to its Input. A response header whose schema is an array of strings (Set-Cookie) is a `[]string` field sent as one header line per value.

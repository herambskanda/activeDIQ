---
name: api-design
description: activeDIQ REST conventions — OpenAPI 3.1 contract-first, /api/v1, cursor paging, problem+json, idempotency, jobs and bulk, ETags, tokens and scopes, audit, rate limits, webhooks, deprecation. Use when designing, building or reviewing endpoints.
---

# API design

**The public API is the product boundary.** The UI, the PowerShell module, the CLI and customer
scripts all use the same documented `/api/v1`. The UI uses nothing private: if a screen needs
data, the public API gets an endpoint. ManageEngine admins automate heavily; a complete,
predictable API is a reason to switch. Paths, tools and libraries here are **provisional until
ADR-0001**. Owner: `api-engineer`; contracts reviewed by `solution-architect`.

`reference/conventions.md` has the full rules and worked examples (problem types, job resource,
webhook signing, LDAP-to-HTTP error mapping). Read it when writing or reviewing a contract.

## 1. Contract-first

1. A `spec` ticket changes `api/openapi.yaml` (OpenAPI 3.1, the **source of truth**) before any
   handler exists. Server stubs (Go) and the TypeScript client are **generated** from it and never
   edited by hand. The PowerShell module wraps the same contract.
2. CI: lint the spec (Spectral or Redocly CLI), detect breaking changes against `main` (oasdiff),
   and validate every integration-test response against the schema. A handler returning a field
   the spec lacks fails CI.
3. Every operation has `operationId` (`listUsers`, `resetUserPassword`), a summary, the RBAC
   permission it requires (`x-permission: users.password.reset`), its error responses, and an
   example. No `additionalProperties: true` on response objects.

## 2. Resources and URLs

- `/api/v1/<collection>/<id>/<sub-collection>` — plural nouns, kebab-case path segments,
  camelCase JSON. Directory data is addressed through its connection:
  `/api/v1/directories/{directoryId}/users/{userId}`.
- **IDs are opaque and stable**: directory objects use `objectGUID` (string form). Never a DN or
  `sAMAccountName` in a path — DNs change on rename/move. DN, SID and names are fields.
- Actions that are not CRUD are POST sub-resources with a verb:
  `POST …/users/{id}/password-reset`, `…/unlock`, `…/enable`, `…/disable`.
- Every directory object representation carries `observedAt` (when we last read it from AD/Entra)
  and `source` (`ad` | `entra`), so the UI can show freshness honestly.
- Timestamps ISO 8601 UTC (`2026-10-02T14:03:00Z`), never FILETIME or epoch numbers. "Never" is
  `null` plus a documented meaning, not a sentinel date.

## 3. Lists — cursor paging, filters, sorting

- `GET …/users?limit=50&cursor=…` → `{"items": [...], "nextCursor": "…" | null}`. Default 50,
  max 500. Cursors are opaque, signed, and encode sort key + GUID tiebreak. No offset paging.
- Totals are opt-in (`?count=true` → `"totalCount"`): counts over large estates cost.
- Filtering: `filter=` in a small documented expression language
  (`department eq 'Sales' and enabled eq true`), parsed to an AST and compiled through the safe
  filter builder (`ad-engineering` §1). Advanced: `ldapFilter=` is **parsed and validated**, then
  AND-composed with the caller's delegation scope — never concatenated.
- Sorting: `sort=displayName,-lastLogonAt` from a per-resource allow-list. Sparse fields:
  `fields=displayName,mail`.
- Budget: list endpoints p95 < 300 ms at 50k objects (`engineering-standards`).

## 4. Errors — RFC 9457 problem+json

Every 4xx/5xx is `application/problem+json`
(https://www.rfc-editor.org/rfc/rfc9457): `type` (`/problems/<slug>`, documented),
`title`, `status`, `detail` (safe for the admin to read), `instance`, plus extensions `code`,
`traceId`, `errors[]` (field-level: `{"field","code","message"}`) and, for directory failures,
`directory: {"resultCode", "diagnostic"}` with secrets stripped. Distinguish **our** RBAC denial
(`403 /problems/forbidden`) from **AD's** denial of our service account
(`403 /problems/directory-access-denied` — "activeDIQ's service account lacks rights on this
OU"). Never leak stack traces, SQL, or internal hostnames.

## 5. Mutations

- **Idempotency**: `Idempotency-Key` header required on every POST that creates something or
  starts a job (IETF draft: https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/).
  Store key + request hash + response for 24 h; same key with a different body → 422; in-flight
  duplicate → 409. AD creates are not idempotent by themselves — this is what makes retries safe.
- **Optimistic concurrency**: GET returns an `ETag`; PATCH/DELETE require `If-Match`
  (missing → 428, stale → 412). For directory objects the server enforces it with LDAP
  compare-and-swap (`ad-engineering` §3), not just a pre-read.
- PATCH is JSON Merge Patch (RFC 7396) on a documented set of writable fields.
- **Dry run**: every bulk or destructive operation accepts `"dryRun": true` and returns the exact
  per-object diff it would apply. Preview-before-commit is a core UX promise.

## 6. Long-running and bulk operations

- Anything that may exceed ~2 s or touch more than one object: `202 Accepted` +
  `Location: /api/v1/jobs/{jobId}`. A job has `status` (`queued running succeeded failed
  partiallySucceeded cancelled`), `progress {total, succeeded, failed}`, `startedAt`,
  `finishedAt`, and paginated per-item results at `/jobs/{id}/items` (object, outcome, problem).
- Clients poll (`Retry-After` hint) or subscribe to webhooks (`job.completed`). Cancel with
  `POST /jobs/{id}/cancel` — stops before the next item; completed items stay done and are listed.
- Bulk input (CSV or JSON) up to 10k objects per job with progress at least every 2 s. Partial
  failure is normal in AD: never all-or-nothing unless the spec says so, and say which.

## 7. AuthN, AuthZ, tenancy

- **UI**: session cookie (`HttpOnly`, `Secure`, `SameSite=Strict`) after SSO/MFA login, plus a
  CSRF token on mutations. **Automation**: API tokens (personal or service), shown once, stored
  hashed, prefixed (e.g. `adiq_`) so secret scanners catch leaks, with expiry and last-used.
- **Effective permission = token scopes ∩ the owner's RBAC role ∩ the role's delegation scope**
  (domains/OUs). Check the *target object* against the scope, not only the endpoint. A help-desk
  token for `OU=Sales` cannot reset a password in `OU=Finance` even on the same endpoint.
- **Tenancy** (if ADR-0001 includes MSP/SaaS): the tenant comes from the authenticated principal,
  **never** from the URL, body or a header the client sets. Cross-tenant IDs return 404.

## 8. Audit, rate limits, webhooks

- **Every mutation is audited** — success, failure and denial — with actor, token, source IP,
  `traceId`, target GUID and DN at the time, before/after of changed fields (secrets redacted),
  result. Written in the same transaction as the state change (outbox). Reads of secrets (LAPS,
  BitLocker keys) are audited too. Details: `security-baseline` §7.
- **Rate limits** per token and per source IP; `429` + `Retry-After`. Separately, an outbound
  per-DC concurrency cap protects customers' domain controllers from our own load.
- **Webhooks**: signed per Standard Webhooks (https://www.standardwebhooks.com/) —
  `webhook-id`, `webhook-timestamp`, `webhook-signature` (HMAC-SHA256), 5-minute replay window,
  retries with exponential backoff, two active secrets during rotation. Payloads carry IDs and a
  summary, never secrets.

## 9. Versioning and deprecation

- Additive changes (new endpoint, optional field, new enum value documented as open) are
  non-breaking. Removing or renaming anything, tightening validation, or changing a meaning is
  breaking → `/api/v2` for that resource. Clients must ignore unknown fields.
- Deprecate with `Deprecation` (RFC 9745) and `Sunset` (RFC 8594) headers, a changelog entry and
  a `deprecated: true` flag in the spec. Proposed default: support for at least two minor
  releases and 12 months, whichever is longer — on-prem customers upgrade slowly. Publishing that
  promise leaves the building → CEO decision (`ceo-decisions`) before GA.

## 10. Review checklist for a contract change

- [ ] OpenAPI changed first; generated code regenerated, not hand-edited; oasdiff clean or `/v2`.
- [ ] GUID IDs; ISO timestamps; `observedAt`; camelCase; no DN in paths.
- [ ] Lists paged by cursor with limits; filters compiled through the safe builder.
- [ ] Problem types documented; LDAP/Graph errors mapped (`reference/conventions.md` §3).
- [ ] Idempotency-Key on creates/jobs; If-Match on updates; dry run on bulk/destructive.
- [ ] `x-permission` set; scope check on the target object; audit event defined.
- [ ] The UI change in the same epic uses only this public contract.

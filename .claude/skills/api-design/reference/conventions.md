# API conventions — reference

Companion to `../SKILL.md`. Provisional until ADR-0001 where tools or paths are named.

## 1. A contract fragment done right

```yaml
/api/v1/directories/{directoryId}/users/{userId}/password-reset:
  post:
    operationId: resetUserPassword
    summary: Reset a user's password
    x-permission: users.password.reset
    parameters:
      - $ref: '#/components/parameters/DirectoryId'
      - $ref: '#/components/parameters/UserId'          # objectGUID, format: uuid
      - $ref: '#/components/parameters/IdempotencyKey'
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [newPassword]
            additionalProperties: false
            properties:
              newPassword: { type: string, format: password, writeOnly: true }
              mustChangeAtNextLogon: { type: boolean, default: true }
              unlock: { type: boolean, default: false }
    responses:
      '204': { description: Password reset }
      '403': { $ref: '#/components/responses/Forbidden' }               # our RBAC or scope
      '404': { $ref: '#/components/responses/NotFound' }
      '422': { $ref: '#/components/responses/PasswordPolicyViolation' }
      '503': { $ref: '#/components/responses/DirectoryUnavailable' }
```

`format: password` + `writeOnly` makes generators and our log redaction treat it as a secret.

## 2. Problem types (`type` → status)

| `type` | Status | When |
| --- | --- | --- |
| `/problems/validation` | 400 | Body or query invalid; `errors[]` lists fields |
| `/problems/unauthenticated` | 401 | No or expired session/token |
| `/problems/forbidden` | 403 | Our RBAC or delegation scope denies it |
| `/problems/directory-access-denied` | 403 | AD/Entra denied **our service account** (LDAP 50, Graph 403) |
| `/problems/not-found` | 404 | Unknown ID, or outside the caller's tenant/scope (never reveal which) |
| `/problems/conflict` | 409 | Object already exists (LDAP 68); in-flight idempotent duplicate |
| `/problems/precondition-failed` | 412 | `If-Match` stale; LDAP compare-and-swap lost (16 on the delete half) |
| `/problems/password-policy-violation` | 422 | LDAP 19 / 53 with `0000052D`; lists domain/PSO requirements |
| `/problems/directory-constraint` | 422 | Other constraint violations (length, syntax, illegal character) |
| `/problems/idempotency-key-reuse` | 422 | Same key, different request body |
| `/problems/precondition-required` | 428 | Missing `If-Match` |
| `/problems/rate-limited` | 429 | With `Retry-After` |
| `/problems/directory-unavailable` | 503 | LDAP 51 busy / 52 unavailable / timeout / Graph 503; with `Retry-After` |
| `/problems/internal` | 500 | Anything else; `traceId` only |

### LDAP result code mapping (connector → problem)

| LDAP | Name | Problem |
| --- | --- | --- |
| 10 | referral | Never surfaced — the connector routes to the right DC; if it cannot, `directory-unavailable` |
| 16 | noSuchAttribute | On a CAS delete → `precondition-failed`; else `directory-constraint` |
| 19 | constraintViolation | `password-policy-violation` if on `unicodePwd`, else `directory-constraint` |
| 20 | attributeOrValueExists | Should not happen (permissive modify); else `conflict` |
| 32 | noSuchObject | `not-found` |
| 49 | invalidCredentials | Connector health problem; to callers `directory-unavailable` (never echo bind details) |
| 50 | insufficientAccessRights | `directory-access-denied` |
| 51, 52 | busy, unavailable | `directory-unavailable` |
| 53 | unwillingToPerform | `password-policy-violation` if `0000052D`; else `directory-constraint` |
| 66 | notAllowedOnNonLeaf | `directory-constraint` with "object has children" detail |
| 68 | entryAlreadyExists | `conflict` |

Keep the Windows diagnostic strings captured from the Windows lab in the mapper's test table —
Samba's differ.

## 3. Problem body example

```json
{
  "type": "/problems/password-policy-violation",
  "title": "Password does not meet the policy",
  "status": 422,
  "detail": "The domain requires at least 14 characters and blocks the last 24 passwords.",
  "instance": "/api/v1/directories/3f1c…/users/9a7e…/password-reset",
  "code": "password_policy_violation",
  "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
  "directory": { "resultCode": 19, "diagnostic": "0000052D: Constraint violation" }
}
```

## 4. Job resource

```json
{
  "id": "job_01J9…",
  "kind": "users.bulkCreate",
  "status": "running",
  "dryRun": false,
  "createdBy": { "type": "user", "id": "…" },
  "progress": { "total": 10000, "succeeded": 6120, "failed": 14 },
  "createdAt": "2026-10-02T14:03:00Z",
  "startedAt": "2026-10-02T14:03:01Z",
  "finishedAt": null,
  "links": { "items": "/api/v1/jobs/job_01J9…/items", "cancel": "/api/v1/jobs/job_01J9…/cancel" }
}
```

Items: `{"index", "objectId" | null, "dn", "outcome": "succeeded|failed|skipped", "problem": {…} | null}`.
A job is resumable after a server restart (persisted state, idempotent per item); its audit events
link back to the job ID.

## 5. Tokens and scopes

- Format: `adiq_<kind>_<random>` (kind `pat` or `svc`); ≥ 256 bits of randomness; stored as a
  hash; displayed once. The prefix is registered with our own secret-scanning rules.
- Scopes mirror permission families: `users:read`, `users:write`, `users.password:reset`,
  `groups:write`, `reports:read`, `audit:read`, `jobs:read`, `admin:*`. A token can never exceed
  its owner's current permissions; revoking the owner's role narrows the token immediately.
- Service tokens belong to a named service principal with an owner human; expiry ≤ 1 year,
  rotation without downtime (two valid tokens during overlap).

## 6. Webhook delivery

- Headers per Standard Webhooks: `webhook-id` (unique, also the dedupe key),
  `webhook-timestamp` (Unix seconds), `webhook-signature: v1,<base64 HMAC-SHA256 of
  "{id}.{timestamp}.{body}">`. Receivers reject timestamps older than 5 minutes.
- Retries: exponential backoff for 24 h, then the endpoint is marked failing and the admin is told.
- Events are `<resource>.<pastTenseVerb>`: `user.created`, `user.passwordReset`, `job.completed`,
  `approval.requested`. Payload: `{ "type", "occurredAt", "data": { ids + summary } }`.
- Delivery to customer URLs is an SSRF surface: block link-local, loopback and metadata addresses
  unless an admin explicitly allows an internal range.

## 7. Breaking vs non-breaking (quick test)

Non-breaking: new endpoint; new optional request field; new response field; new problem `type`;
new enum value **if** the enum is documented as open. Breaking: removing or renaming anything;
making an optional field required; narrowing a type or format; changing defaults, status codes,
pagination or a field's meaning. oasdiff in CI is the arbiter; a reviewer may not waive it.

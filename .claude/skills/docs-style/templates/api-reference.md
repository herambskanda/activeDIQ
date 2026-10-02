---
title: <Resource or guide title: "Bulk jobs">
kind: reference
audience: developer
applies_to: ">=<version>"
api_version: v1
verified_on: <version or sha> YYYY-MM-DD
---

<!-- The endpoint reference is GENERATED from the OpenAPI contract owned by api-engineer; never
hand-edit generated pages. This template is (a) the shape the generator output must have and
(b) the hand-written resource overview that sits above it. Auth, paging, errors and rate limits
are documented once in docs/api/conventions.md and linked, not repeated. -->

# <Bulk jobs>

<What the resource is, in two sentences, and when to use it instead of single-object calls.>

**Required permission:** `<activeDIQ permission>` in scope of the target objects.

## Operations

| Method | Path | Does |
| --- | --- | --- |
| `POST` | `/api/v1/<resource>` | |
| `GET` | `/api/v1/<resource>/{id}` | |

## `<METHOD> <path>`

<One sentence.>

### Request

| Field | Type | Required | Description |
| --- | --- | --- | --- |

```bash
curl -X POST "https://adiq.lab.activediq.test/api/v1/<resource>" \
  -H "Authorization: Bearer $ADIQ_TOKEN" \
  -H "Content-Type: application/json" \
  -d @request.json
```

### Response `<status>`

```json
{ }
```

### Errors

| Status | `code` | When | What to do |
| --- | --- | --- | --- |

### PowerShell equivalent

```powershell
# Parameters, never string-built commands
<Verb-AdiqNoun> -Parameter $value
```

## Changelog

| Version | Change |
| --- | --- |

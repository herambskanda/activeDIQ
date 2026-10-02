# Review checklist — item by item

Each item: what to check → how to check it fast. Default severity in brackets. Paths are
provisional until ADR-0001.

## Correctness
- [ ] Each AC maps to code and a test → list them in your note. **[blocker]**
- [ ] Unhappy paths: no RBAC permission, outside delegation scope, AD denies service account, DC
      unreachable mid-operation, partial bulk failure, empty result, 10k objects → find the test
      or try it on the lab. **[major]**
- [ ] AD semantics: identity by GUID; paged + ranged reads; computed lockout/expiry; last-logon
      attribute and lag stated; UTC handling → `ad-engineering/reference/gotchas.md`. **[blocker if wrong number shown]**
- [ ] Concurrency: compare-and-swap for edits; idempotent retries; jobs resumable; `go test -race` clean. **[major]**

## Tests
- [ ] Right layer (`testing-playbook` §1); connector tests hit Samba, not a fake. **[major]**
- [ ] Bug ticket: a reproducing test that fails on `main` → run it against `main`. **[blocker]**
- [ ] Each new test fails when the code is broken → mutate one line and run it. **[major]**
- [ ] Fuzz test for any new parser, encoder or builder. **[major]**
- [ ] Fixtures deterministic, synthetic, under `testdata/` `lab/seed/` `e2e/fixtures/` only. **[blocker if in product paths]**

## Safe primitives — `security-baseline` §2
- [ ] Grep the added lines and justify every hit **[blocker]**:
      ```bash
      git diff main...factory/<id> | grep -nE '^\+.*(Sprintf|Join\(|\+ *"|" *\+|\$\{)' \
        | grep -iE '\(&|\(\||objectClass|CN=|OU=|DC=|SELECT|INSERT|UPDATE|DELETE|WHERE|powershell|-Command|O:|D:\('
      ```
- [ ] Raw LDAP / SQL / exec libraries imported only in their allowed packages (lint passes). **[blocker]**
- [ ] Admin-supplied filters parsed to AST and AND-composed with scope. **[blocker]**

## Security triggers — `security-baseline` §1
- [ ] Auth, RBAC, AD writes, credentials, DC-resident code, listeners, crypto, untrusted parsing,
      audit → ticket tagged `security-sensitive` (add it if not). **[blocker if missing]**
- [ ] Authorisation checked server-side on the **target object**, per bulk item. **[blocker]**
- [ ] Every privileged mutation emits an audit event (success, failure, denial), secrets redacted. **[major]**

## Architecture
- [ ] Uses the existing extension point; no hand-wiring around the registry. **[blocker]**
- [ ] No imports of another module's internals; platform imports no module (import lint). **[blocker]**
- [ ] No clone-and-adapt → search for the most similar existing file; if ≥ ~60 % alike,
      parameterise. **[blocker]**
- [ ] Structural change → `knowledge/development/architecture/` page updated in this diff. **[major]**
- [ ] Consistent with ratified ADRs; a deviation needs a superseding ADR, not code. **[blocker]**

## UI — no fake data, no dead controls
- [ ] No literal data (numbers, names, lists, dates) in `web/src` outside tests and stories. **[blocker]**
- [ ] Every new button, link, menu item and shortcut does something real; disabled ones say why. **[blocker]**
- [ ] Loading, empty, error, partial states implemented; design-system components and tokens only. **[major]**
- [ ] Data via the generated client + TanStack Query; no private endpoints. **[blocker]**

## Dead code and hygiene
- [ ] Superseded code deleted in the same change (old component, old endpoint, old flag). **[major]**
- [ ] No commented-out code, `_old`, `v2_final`, unused exports, TODO without a ticket ID. **[minor → major if large]**
- [ ] No partner or customer names anywhere outside `knowledge/business/partnerships/`. **[blocker]**
- [ ] No secrets, tokens, real passwords, `.env*` files. **[blocker, P0]**

## Errors and logging
- [ ] Errors wrapped with context; mapped to problem types at the edge; never swallowed. **[major]**
- [ ] No partial result presented as complete (sizeLimitExceeded, failed chunk, unreachable DC). **[major]**
- [ ] Structured logs with trace ID; no secrets; GUIDs preferred over names. **[blocker if secret]**

## API — `api-design` §10
- [ ] `api/openapi.yaml` changed; generated code regenerated, not hand-edited. **[blocker]**
- [ ] oasdiff: no unversioned breaking change. **[blocker]**
- [ ] Problem types, `x-permission`, Idempotency-Key, If-Match, cursor paging as required. **[major]**

## Data and migrations
- [ ] Forward-only; expand/contract for breaking changes; no long locks on big tables. **[major]**
- [ ] Tenant key and RLS where multi-tenant; tenant context parameterised. **[blocker]**
- [ ] Rolled forward on the 50k fixture DB in a test. **[major]**

## Performance — `engineering-standards` §7
- [ ] LDAP paged, explicit attribute lists, no per-object round trips in loops (N+1). **[major]**
- [ ] List endpoints indexed; `EXPLAIN` sane on 50k; UI tables virtualised. **[major]**
- [ ] Bulk path reports progress ≤ 2 s and honours the per-DC concurrency cap. **[major]**

## Dependencies
- [ ] Justified in the ticket; pinned; licence register row added; no copyleft in shipped code. **[blocker if copyleft]**
- [ ] Scanner clean or findings triaged. **[major]**

## Docs and commits
- [ ] User-visible change → docs ticket exists or docs updated. **[major]**
- [ ] Conventional commits ending with the ticket ID; atomic. **[minor]**

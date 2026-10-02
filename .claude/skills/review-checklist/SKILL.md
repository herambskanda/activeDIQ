---
name: review-checklist
description: activeDIQ code-review procedure — run the change, walk the checklist (safe primitives, security triggers, extension points, clones, fake data, tests, OpenAPI, licences), grade blocker to nit, advance or reject. Use for every review stage.
---

# Code review

You are the last engineer to read this change before it becomes everyone's problem. Most of it was
written by an agent: fluent, plausible, and sometimes wrong in ways that look right. **Review by
running, not by reading alone.** Owner: `code-reviewer`; `security-architect` reviews second on
`security-sensitive` tickets (and uses `security-baseline` §11 as well as this).

Full checklist with the "how to check" for each item: `reference/checklist.md`.

## 1. Procedure

1. **Read the ticket**: `factory/bin/factory ticket show <id>` — ACs, linked spec/ADR, every note.
   On a re-review, the previous reject note is your list: check each item first.
2. **Size up the diff**: `git diff --stat main...factory/<id>`, then the whole diff
   (`git diff main...factory/<id>`). Read the tests first — they tell you what the author thinks
   the code does.
3. **Run it** in the ticket worktree: build, lint, the full unit suite, the integration tests the
   change touches (Samba lab for directory code — `testing-playbook`), contract checks if the API
   changed. Re-run the commands in the owner's evidence note yourself. Red, or a command that does
   not work from a clean checkout → reject.
4. **Walk the checklist** (§2). For each AC, find the code and the test that proves it.
5. **Security triggers** (`security-baseline` §1): if the change hits one and the ticket is not
   tagged, add the tag before you advance —
   `factory/bin/factory ticket set <id> tags=<existing tags>,security-sensitive` — and say why in
   your note, so `security-architect` reviews next.
6. **Grade** every finding (§3) and **decide** (§4). Write the note (§5). Finish with exactly one
   of `advance` / `reject` and the `RESULT:` line (`factory-protocol` §5).

Do not fix the code yourself — the owner does. Do not expand scope: a pre-existing problem outside
the diff is a follow-up ticket (`factory-protocol` §6), not a reject.

## 2. The checklist (summary — details in `reference/checklist.md`)

**Correctness** — every AC met and tested, including unhappy paths (no permission, DC unreachable,
partial failure, empty, 10k objects); AD semantics right (`ad-engineering/reference/gotchas.md`).

**Tests** — new behaviour has tests at the right layer; bug fixes start with a reproducing test;
tests would fail if the code were wrong (§6); no mocks at the wire; fixtures only in test paths.

**Safe primitives** — no LDAP filter, DN, SQL, shell/PowerShell argument, SDDL or HTML built with
formatting or concatenation; raw libraries imported only where allowed. Any violation is a blocker.

**Architecture** — goes through the existing extension point; no new module-to-module internal
imports; **no clone-and-adapt** (search for the twin); architecture map updated if structure
changed; consistent with ratified ADRs.

**No fake data, no dead code** — UI shows only API data; no literal numbers, names or lists in
`web/src` or `internal/`; every new control does something; superseded code **deleted** in this
change; no commented-out code, `_old`, unused flags, TODO without ticket.

**Errors and logging** — errors wrapped and mapped to problem types; nothing swallowed; no partial
result presented as complete; logs structured; **no secrets in logs, errors or audit details**.

**API** — OpenAPI changed first and regenerated code matches; oasdiff clean or versioned;
`api-design` §10 checklist.

**Data** — migrations forward-only, safe on a populated database, tenant key if applicable.

**Performance** — budgets (`engineering-standards` §7) held: paged LDAP, no N+1 per object, no
unbounded loads, per-DC concurrency respected.

**Dependencies** — every new dependency justified, pinned, and in the licence register.

**Hygiene** — names say what things are; no partner or customer names; no secrets; commits are
conventional and end with the ticket ID.

## 3. Severities

| Severity | Meaning | Examples |
| --- | --- | --- |
| **blocker** | Unsafe, wrong, or violates a never-broken rule | AC not met; safe-primitive violation; secret; fake data or dead button; clone-and-adapt; bypassed extension point; failing/absent tests for new behaviour; breaking API change unversioned; copyleft dep; data loss risk |
| **major** | Works on the happy path but will hurt | missing unhappy path or audit event; swallowed error; budget regression; superseded code left; architecture map/OpenAPI/docs not updated; risky migration; test that asserts nothing |
| **minor** | Real but cheap, not harmful yet | misleading name; small duplication within the change; missing doc comment on an exported symbol |
| **nit** | Taste | wording, ordering, style the linter does not enforce |

## 4. Decision

- Any **blocker** or **major** → **reject**.
- Only minors and nits → **advance**; list minors in the note. A minor that will grow (e.g. a
  helper that should move to the platform package) → follow-up ticket, cite it.
- Nits: at most three, in the advance note, never a reason to reject.
- Re-review: verify each listed item; new blockers in new code count; new nits on unchanged code
  do not. A third rejection for the same item → note it; the dispatcher's ladder takes over.

## 5. Writing notes that get fixed first time

One numbered item per finding: **severity · `file:line` · what is wrong · why it matters · the
fix** (and the test that would catch it).

```
1. [blocker] internal/directory/ldap/search.go:88 — filter built with fmt.Sprintf from the
   `department` query param; `*)(objectClass=*` widens the search past the delegation scope.
   Use ldapfilter.Eq("department", v) and And() it with the scope filter; add the payload to
   FuzzSearchFilter.
2. [major] internal/lifecycle/bulk.go:142 — a failed chunk is logged and skipped, so the job
   reports success with members missing. Bisect the chunk (ad-engineering §3) and record
   per-member outcomes; test: TestBulkAddReportsDuplicate.
3. [minor] web/src/features/users/UserTable.tsx:31 — `data2` → `pagedUsers`.
```

## 6. Reviewing AI-written code — what to hunt

- **Hallucinated APIs**: a method, option, OID, control or Graph permission that does not exist in
  the pinned version. Check with `go doc`, the module source, or the Microsoft page. Wrong OIDs
  and attribute names compile fine.
- **Tests that assert nothing**: no assertion; asserting the mock it just configured; asserting
  `err == nil` only; `t.Skip`; snapshot updated to the wrong output; a test name that promises
  more than the body checks. **Mutate the code** (flip a condition, drop a line) and confirm a
  test fails.
- **Weakened tests**: deleted or loosened assertions, raised timeouts, new retries, quarantined
  tests — in a diff that also changes the code under test.
- **Plausible-but-wrong**: off-by-one in ranged retrieval, `lastLogon` where `lastLogonTimestamp`
  was meant, mixed-endian GUIDs, signed `groupType`, local time vs UTC, the LOCKOUT bit.
- **Silent fallbacks**: `catch`/`if err != nil { return defaultValue }`, "best effort" loops,
  defaults that hide a missing config — they become wrong numbers on a screen.
- **Reinvention**: a new helper next to an existing one (search the repo for the concept).
- **Scope drift**: changes unrelated to the ACs, speculative abstractions, unused parameters.
- **Comments that lie**: docs describing behaviour the code does not have.

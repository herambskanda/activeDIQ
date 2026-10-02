---
name: factory-protocol
description: The worker protocol for every factory session working a ticket stage — read the ticket, gather context, work in small steps, git on the ticket branch, follow-ups, escalation, Definition of Done, and the closing advance/reject/block + RESULT line.
---

# Factory protocol

You work **one ticket, one stage, one session**. The ticket file is the source of truth; the
dispatcher picks the next stage and the next owner, never you. `$FACTORY_TICKET`,
`$FACTORY_ROLE` and `$FACTORY_RUN_ID` are set for headless workers.
Below, `<id>` is your ticket and `<role>` is your agent name.

## 1. Start

1. `factory/bin/factory ticket show <id>` — read the summary, body, acceptance criteria, links, `depends_on`,
   `decisions`, tags and **every note**. A reject note from review or QA is your work order.
2. Continuation? (the prompt names a handoff, or `factory/bin/factory handoff latest <id>` prints a path.) Read it,
   then **verify before trusting it**: `git status`, `git log --oneline -5`, and the handoff's
   "How to verify" commands. Resume at "Next steps" #1. Never redo finished work.
3. Check the preconditions. A dependency not `done`, or a linked decision still `pending`, means
   you should not be here: `factory/bin/factory ticket block <id> --by <role> --note "<what is missing>"` and stop.

## 2. Gather context — targeted, never wholesale

- Read the files the ticket links (spec, ADR, research). Then stop and ask what is still unknown.
- For anything you would have to search for, use the `Explore` agent with a precise question
  ("Where is the LDAP filter builder and what does it escape?"). Take the conclusion, not dumps.
- Hot memory: read only the files your task touches — `lessons.md` before code,
  `conventions.md` before naming or structure, `ceo-preferences.md` before anything the CEO will
  see, `glossary.md` when a term is unclear. Never preload `knowledge/` whole.
- Load the craft skill for the work: `engineering-standards`, `ad-engineering`, `api-design`,
  `testing-playbook`, `security-baseline`, `adr`, `feature-spec`, `docs-style`,
  `review-checklist`, `qa-verification`, `design-system`, `video-production`, as relevant.

## 3. Plan, then work in small verifiable steps

1. Write a plan of 3–8 steps, each ending in something you can check (a test passes, a file
   renders, a command prints X). Map every acceptance criterion to the step that proves it.
2. Do one step, verify it, commit (code types) — then the next. Never stack unverified steps.
3. At meaningful milestones — not every step — record progress:
   `factory/bin/factory ticket note <id> --by <role> "<done so far · what is next>"`.
4. Stuck on the same failure twice? Stop changing things. Re-read the error, form one
   hypothesis, test it. Three failed hypotheses → escalate (§8), do not thrash.

## 4. What each stage must produce

| Stage | Role | Produce, then advance with evidence |
| --- | --- | --- |
| `in_progress` · `build` `bug` | owner | Code + tests on the ticket branch; every AC demonstrably met; architecture map and docs updated if structure or anything user-visible changed; superseded code deleted. `bug`: a failing test that reproduces it first. |
| `in_progress` · `test` | owner | Tests that fail for the right reason before the fix exists; fixtures only under test paths. |
| `in_progress` · `chore` `ops` | owner | The change plus proof it works (CI run, command output). |
| `in_progress` · `spec` | owner | Spec under `knowledge/product/specs/` or `knowledge/development/` with frontmatter, platform matrix, parity refs. `feature-spec` skill. |
| `in_progress` · `design` | owner | Flows, mockups on `../design-system/tokens.css`, states incl. empty/error/loading. |
| `in_progress` · `docs` `video` | owner | Content from the **running product**; `docs-style` / `video-production` skill. |
| `in_progress` · `research` `proposal` | owner | Every external claim with an inline URL; unverified ones tagged `[UNVERIFIED]`. |
| `in_progress` · `decision-prep` | owner | A filed decision meeting the `ceo-decisions` bar; advance note names the D-id. |
| `in_progress` · `spike` | owner | Prototype in `garage/<name>/` with `OWNER` and `EXPIRES` in its README; findings doc; the recommendation. |
| `in_progress` · `meta` | owner | The ritual (grooming, triage, digest, gardening) per its skill. `advance` closes it. |
| `review` | reviewer | `git diff main...factory/<id>` (code) or the produced docs; `review-checklist` skill. Advance, or reject with numbered must-fix items. Taste nits are notes, not rejects. |
| `qa` | `qa-verifier` | Each AC verified against the running system with evidence (test output, screenshots); every control on a changed screen clicked. `qa-verification` skill. |

## 5. Finish — exactly one, then the RESULT line

```bash
factory/bin/factory ticket advance <id> --by <role> --note "<what changed and why · evidence · where to look>"
factory/bin/factory ticket reject  <id> --by <role> --note "1. <must change> 2. <must change>"   # review / qa only
factory/bin/factory ticket block   <id> --by <role> --note "<blocker> · <what would unblock it> · <who>"
```

The advance note on the final build stage is the ticket's **two-line summary** (what changed,
why). End your final message with exactly one line:

```
RESULT: advanced|rejected|blocked|handoff|failed — <one sentence>
```

The `Stop` hook will not let a worker end before the ticket was advanced, rejected, blocked,
noted, or a handoff written.

## 6. Scope — follow-up tickets, never scope creep

Found other work (a bug, a refactor, a missing spec)? Do not do it. File it and keep going:

```bash
factory/bin/factory ticket new --title "<outcome, imperative>" --type <type> --owner <role> --priority P2 \
  --epic <E> --milestone <M> --depends <T-…> --parity <ADM-…> \
  --summary "<one paragraph: the outcome in plain words>" --body-file <tmp.md> \
  --ac "Given … when … then …" --ac "…" --status backlog
factory/bin/factory ticket note <id> --by <role> "Filed T-…: <why it is out of scope here>"
```

Fill every Definition-of-Ready field (`ticket-craft` skill). Status is always `backlog` —
grooming makes tickets ready. If the follow-up genuinely blocks you, block your ticket and name it.

## 7. WIP and git

- One ticket and one stage per session. Never claim, start or change the status of another ticket.
- Code types (`build bug test chore ops`) run in the worktree on branch `factory/<id>`. Commit
  there only; the dispatcher merges to `main` after the final stage. Never commit to `main`, never
  merge, rebase onto or reset `main`, never force-push, never rewrite pushed history.
- Document types run in the main checkout: commit only the files you produced, by explicit path
  (`git add <paths>`, never `-A` or `.`), once, at the end of your stage — downstream worktrees
  branch from `main` and cannot see uncommitted specs.
- No worktree on a code ticket (repo has no commits yet)? Do not switch branches; leave the change
  uncommitted and say so in the advance note.
- Conventional commits, small and atomic: `feat(directory): add DN builder (T-0012)`. Types:
  `feat fix test refactor docs chore ci perf`. Always end the subject with the ticket ID.
- Never commit secrets, `.env*`, keys, tokens, lab passwords or customer data. If the guard hook
  blocks a write, it is right — fix the content, do not route around it.

## 8. Escalation

| Situation | Do |
| --- | --- |
| Technical and stuck (three hypotheses failed) | `block` with what you tried and the best remaining hypothesis. The dispatcher's ladder raises effort, then hands it to `principal-engineer`. Never raise your own effort. |
| Unclear requirement, conflicting specs, wrong owner, missing access | `block`; the `factory-director` triages. |
| Directional — scope, taste, commercial, money, legal, external, acceptance | `ceo-decisions` skill. Never ask the CEO about implementation. |
| A Type-2 call you can make | Make it, write one line of why in the note (an ADR if it is architectural). |

## 9. Definition of Done (build types)

All ACs demonstrably met · tests written and passing · code review passed · QA passed with
evidence · docs and `knowledge/development/architecture/` updated if anything user-visible or
structural changed · superseded code deleted · merged to `main` · two-line summary on the ticket.
As owner you deliver the first, second, fifth and sixth before you advance.

## 10. Output rules — review blockers, not style

- **No fake data.** The UI renders only API data. Fixtures live in tests, Storybook and the demo
  seed. No placeholder numbers, no dead buttons — a control that does nothing is not shipped.
- **Safe primitives only** for LDAP filters and DNs, SQL, PowerShell and shell arguments, security
  descriptors. Never string formatting or concatenation. No primitive yet? File the ticket for it.
- **Delete superseded code** in the same change. No `_old`, no commented-out blocks, no flags
  left on for dead paths.
- **Parameterise, don't clone.** A second copy-and-adapt is a reject.
- Partner and customer names only in `knowledge/business/partnerships/`. Check
  `knowledge/business/licensing/` before adding any dependency.

## 11. Context and memory

- Context warnings at 70 / 85 / 95 % follow the `handoff` skill. At 85 %: finish the atomic step,
  write the handoff, note the ticket, end with `RESULT: handoff`.
- A lesson that would save a future session 15 minutes, or a new convention → `memory` skill.
  Do it before you advance; it is part of the work.

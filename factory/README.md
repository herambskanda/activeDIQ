---
title: Factory Runtime — Reference
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
---

# Factory Runtime — Reference

The runtime that makes `OPERATING-MODEL.md` real: a CLI, a dispatcher that launches headless
Claude Code workers, a file-based state store, and the Factory Board. **Zero dependencies** —
Node.js ≥ 20 standard library only (the machine has Node 26). Generic by design: nothing here is
specific to Active Directory, so the factory can be reused for other skenzeriq products.

## Quick start

```bash
factory/bin/factory up          # start board + dispatcher (detached)  → http://127.0.0.1:4747
factory/bin/factory status      # terminal summary
factory/bin/factory pause       # stop launching new work (running workers finish)
factory/bin/factory down        # stop dispatcher + board; running workers asked to hand off
factory/bin/factory doctor      # validate config, state, agents, model policy
```

## Layout

```
factory/
  OPERATING-MODEL.md     the organisational model (humans read this)
  README.md              this file (runtime reference)
  config.json            runtime configuration (tracked)
  bin/factory            executable entrypoint (#!/usr/bin/env node)
  lib/                   runtime modules (store, ids, locks, flows, dispatcher, launcher, notify…)
  board/                 Factory Board: server.mjs + public/ (index.html, app.js, styles.css)
  templates/             handoff.md, worker-prompt.md, digest.md, demo-script.md, decision.md
  reports/               daily digests and weekly reviews (tracked)
  demos/                 milestone demo packages (tracked; large media gitignored)
  test/                  node:test suites  →  node --test factory/test/
  state/                 RUNTIME DATABASE — gitignored
  handoffs/              RUNTIME — gitignored
```

## Locating FACTORY_HOME

Every command resolves the factory home in this order:

1. `$FACTORY_HOME` if set (the dispatcher sets it for every worker);
2. otherwise the main checkout of the git repository, found with
   `git rev-parse --path-format=absolute --git-common-dir` → its parent directory → `factory/`;
3. otherwise the `factory/` directory that contains the running `bin/factory`.

This is what lets a worker running inside a git worktree write to the one shared state store
in the main checkout.

## State store (`factory/state/`)

One JSON file per entity, written atomically (write `*.tmp` then `rename`). IDs come from
`state/counters.json`, guarded by a `mkdir`-based lock (`state/.lock/`, stale after 10 s).
Timestamps are ISO-8601 UTC strings.

```
state/
  counters.json                      {"T":12,"D":3,"A":1,"F":0,"E":4,"R":57}
  control.json                       {"paused":false,"reason":null,"by":null,"ts":"…"}
  dispatcher.json                    {"pid":123,"started":"…","heartbeat":"…","active":["R-…"],"last_action":"…","backoff_until":null,"runs_today":{"date":"2026-10-02","count":7}}
  board.json                         {"pid":124,"port":4747,"started":"…"}
  tickets/T-0001.json
  epics/E-001.json
  milestones/M1.json
  decisions/D-0001.json
  actions/A-0001.json                CEO action items
  feedback/F-0001.json
  runs/R-20261002-153012-ab12.json   one per worker session
  runs/R-…​.log                      raw stream-json from the worker
  sessions/<session_id>.json         live context usage of any Claude session (written by hooks)
  events/2026-10-02.jsonl            activity feed, one JSON object per line
```

### Ticket — `tickets/T-0001.json`

```json
{
  "id": "T-0001",
  "title": "Safe LDAP filter builder",
  "type": "build",
  "status": "backlog",
  "priority": "P1",
  "owner": "directory-engineer",
  "epic": "E-002",
  "milestone": "M1",
  "depends_on": ["T-0000"],
  "decisions": ["D-0002"],
  "tags": ["security-sensitive"],
  "parity_refs": ["ADM-014"],
  "summary": "One paragraph: the outcome, in plain words.",
  "body": "Markdown: context, scope, approach notes, links.",
  "acceptance": ["Given … when … then …"],
  "links": {"spec": "knowledge/product/specs/…", "branch": null, "worktree": null},
  "effort_override": null,
  "attempts": 0,
  "stage_role": null,
  "handoff": {"pending": false, "latest": null},
  "result": null,
  "notes": [{"ts": "…", "by": "directory-engineer", "text": "…"}],
  "history": [{"ts": "…", "by": "project-manager", "from": null, "to": "backlog", "note": "created"}],
  "created": "…",
  "updated": "…"
}
```

- `type` ∈ `build bug test chore ops spec design docs video research proposal decision-prep spike meta`
- `status` ∈ `backlog ready in_progress review qa done blocked cancelled`
- `priority` ∈ `P0 P1 P2 P3`
- `stage_role` — the agent working the current stage (owner, reviewer or QA); set by the dispatcher.
- `notes` and `history` are append-only.

### Flows (`config.json → flows`)

Each ticket type maps to an ordered list of stages. `advance` moves to the next stage; `reject`
returns to `in_progress` (with the reason as a note and `attempts` unchanged).

```json
"flows": {
  "build":  [["in_progress","$owner"],["review","code-reviewer","+security-architect:security-sensitive"],["qa","qa-verifier"],["done",null]],
  "bug":    "build",
  "test":   [["in_progress","$owner"],["review","code-reviewer"],["done",null]],
  "chore":  "test", "ops": "test",
  "spec":   [["in_progress","$owner"],["review","solution-architect"],["done",null]],
  "design": [["in_progress","$owner"],["review","product-manager"],["done",null]],
  "docs":   "design", "video": "design",
  "research": [["in_progress","$owner"],["review","factory-director"],["done",null]],
  "proposal": "research", "decision-prep": "research", "spike": "research",
  "meta":   [["in_progress","$owner"],["done",null]]
}
```

A string value aliases another flow. A third element `"+<role>:<tag>"` adds a second sequential
reviewer for that stage when the ticket carries `<tag>`.

`ready → in_progress` happens when the dispatcher claims the ticket. A ticket whose `owner` equals the stage reviewer gets `factory-director` as reviewer instead.

### Decision — `decisions/D-0001.json`

```json
{
  "id": "D-0001",
  "kind": "directional",
  "title": "Deployment model for v1",
  "question": "Where should activeDIQ v1 run?",
  "context": "Markdown, ≤150 words.",
  "options": [{"id": "a", "label": "Self-hosted first", "summary": "…", "pros": ["…"], "cons": ["…"], "preview": null}],
  "multi": false,
  "recommendation": "a",
  "rationale": "…",
  "default_option": null,
  "default_at": null,
  "blocks": ["T-0004"],
  "status": "pending",
  "answer": null,
  "applied": false,
  "created_by": "factory-director",
  "created": "…",
  "updated": "…"
}
```

- `kind` ∈ `directional advisory notice`
- `status` ∈ `pending answered defaulted withdrawn vetoed acknowledged`
- `answer` = `{"options": ["a"], "note": "…", "ts": "…", "via": "board|cli"}`
- `preview` = repo-relative path (served by the board) or URL.
- advisory → `default_option` + `default_at` required; the dispatcher applies the default when due.
- notice → the factory already decided; the CEO can `acknowledge` or `veto` (veto creates feedback).

### Action item — `actions/A-0001.json`
`{"id","title","detail","why","status":"open|done|dismissed","created_by","created","updated","done_note"}`

### Feedback — `feedback/F-0001.json`
`{"id","target":"demo:M1|ticket:T-0001|doc:<path>|decision:D-0001|general","text","sentiment":"love|ok|change|null","status":"new|triaged|done","triage_note","tickets":[],"created","updated"}`

### Epic / Milestone
- `epics/E-001.json`: `{"id","title","goal","milestone","status":"planned|active|done","parity_refs":[],"created","updated"}`
- `milestones/M1.json`: `{"id","name","goal","status":"planned|active|demo-ready|accepted|rejected","target":null,"demo":{"script":null,"video":null,"url":null},"created","updated"}`

### Run — `runs/R-….json`
```json
{"id","ticket","stage","role","model","effort","pid","session_id","worktree",
 "status":"running|done|failed|handoff|killed","started","ended","exit_code",
 "context_tokens":0,"peak_context_tokens":0,"cost_usd":0,"num_turns":0,
 "result_line":null,"last_activity":null,"log":"state/runs/R-….log"}
```

### Event — `events/YYYY-MM-DD.jsonl`
`{"ts","actor","kind","ticket":null,"run":null,"text"}` — `kind` ∈ `ticket decision action feedback run dispatcher session tool memory ceo system`.

## CLI (`factory/bin/factory`)

Every mutating command appends an event. `--json` prints machine-readable output. Errors exit 1
with a one-line message; usage errors exit 2.

```
up | down | status [--json] | pause [--reason …] | resume | doctor
board [--port N]                     run the board in the foreground
run [--once] [--dry-run]             run the dispatcher in the foreground

ticket new --title T --type TYPE --owner ROLE [--priority P2] [--epic E] [--milestone M]
           [--depends T-1,T-2] [--decisions D-1] [--tags a,b] [--parity ADM-1,ADM-2]
           [--summary S] [--body-file F] [--ac "…"]... [--status backlog|ready]
ticket list [--status S] [--owner R] [--epic E] [--json]
ticket show ID [--json]
ticket ready ID                      backlog → ready (checks Definition of Ready fields)
ticket note ID --by ROLE "text"
ticket advance ID --by ROLE --note "what was done"
ticket reject ID --by ROLE --note "what must change"
ticket block ID --by ROLE --note "why"     |  ticket unblock ID --by ROLE --note "…"
ticket cancel ID --by ROLE --note "why"
ticket set ID field=value …          priority, owner, epic, milestone, effort_override, tags, depends_on

decision new --kind K --title T --question Q [--context-file F] --option "a|Label|summary" …
             [--recommend a] [--rationale R] [--default a --default-in 72h] [--blocks T-1,T-2] [--multi] [--by ROLE]
decision list [--status pending] [--json]   |   decision show ID
decision answer ID --option a[,b] [--note "…"] [--via cli|board]
decision applied ID --by ROLE        mark the answer as propagated (memory, tickets)
decision withdraw ID --by ROLE --note "…"

action new --title T --detail D --why W [--by ROLE]  |  action list  |  action done ID [--note]
feedback new --target X --text T [--sentiment s]      |  feedback list  |  feedback triage ID --note N [--tickets T-1]
epic new|list|show  ·  milestone new|list|show|set ID status=…
handoff new ID --by ROLE             create factory/handoffs/<ID>/<ts>.md from the template; print path; set handoff.pending
handoff latest ID                    print the latest handoff path for a ticket (or session id)
event --actor A --kind K [--ticket T] "text"
digest                               print today's machine summary (for project-manager to narrate)
```

Rules the CLI enforces:
- Only legal transitions per the flow; `advance` on the last stage sets `done`.
- `ticket ready` refuses unless title, owner, acceptance (≥1) and summary are present.
- A ticket listing an unanswered decision cannot be claimed.
- `decision new` refuses a 4th open `directional`/`advisory` decision (`ceo.max_open_decisions`)
  unless `--force`; it fires a macOS notification when `ceo.notify.macos` is true.
- Answering a decision unblocks nothing directly: the next dispatcher tick sees
  `answered && !applied` and launches `factory-director` triage.

## Dispatcher (`factory run`)

Deterministic loop; never calls a model itself. Every `dispatcher.tick_seconds` (20 s):

1. Write the heartbeat to `state/dispatcher.json`.
2. **Reap** finished child processes: parse the last `result` line of the run log (cost, turns,
   session id, `is_error`, the `RESULT:` line in `result`); finalise the run record; then:
   - ticket moved forward / blocked / done → fine;
   - ticket `handoff.pending` → leave it for a continuation;
   - nothing changed → `attempts += 1`; at `max_retries` (2) apply the escalation ladder
     (`effort_override` one step up → reassign to `principal-engineer`) → then `blocked`.
   - a usage-limit or rate-limit error → set `backoff_until` (15 min), do not count an attempt.
3. **Defaults**: advisory decisions past `default_at` → `status: defaulted`, answer = default.
4. If `control.paused`, `backoff_until` in the future, or `runs_today ≥ daily_run_cap` → stop here.
5. **Fill free slots** (`max_parallel` − running), one candidate per slot, in this order:
   1. tickets in `review` / `qa` without a running session;
   2. `in_progress` tickets with `handoff.pending` (continuation);
   3. `ready` tickets — highest priority, then oldest — whose `depends_on` are all `done` and whose
      `decisions` are all answered/defaulted;
   4. a `meta` triage ticket for `factory-director` when there are decisions `answered && !applied`,
      feedback with `status: new`, or `blocked` tickets not triaged in the last 6 h (auto-created,
      never more than one open triage ticket);
   5. a `meta` grooming ticket for `project-manager` when fewer than `grooming_min_ready` tickets
      are `ready` and the backlog is not empty (cooldown `grooming_cooldown_minutes`);
   6. a `meta` digest ticket for `project-manager` once per day after `digest_hour_local`.
6. **Launch** a worker for each candidate (below), record the run, append an event.

### Worker launch

```bash
claude -p "<rendered templates/worker-prompt.md>" \
  --agent <stage_role> \
  [--effort <effort_override>]            # only when escalated
  --output-format stream-json --verbose \
  --permission-mode <dispatcher.permission_mode>  --permission-prompts none \
  --autocompact <context.budget_tokens> \
  --strict-mcp-config [--mcp-config <role-specific json>] \
  --name "<ticket id> · <stage_role>"
```

- `cwd` = the ticket worktree for code-bearing types (`build bug test chore ops`) when
  `dispatcher.isolation` is `worktree`; otherwise the main checkout.
- `env` adds `FACTORY_HOME`, `FACTORY_TICKET`, `FACTORY_RUN_ID`, `FACTORY_ROLE`,
  `FACTORY_CONTEXT_BUDGET`.
- stdout → `state/runs/<id>.log`; the dispatcher tails it for `assistant` messages and records
  `context_tokens = input + cache_creation + cache_read` of the latest one, `peak_context_tokens`,
  and `last_activity` (the latest tool name + short input summary). The board shows these live.
- Hard wall-clock limit per run: `dispatcher.run_timeout_minutes` (90). On timeout: SIGTERM,
  then SIGKILL after 30 s; status `killed`.
- Model and effort come from the agent definition; the dispatcher validates them against
  `models.allowed` before launching and refuses violations.

### Worktrees and merging

- Branch `factory/<ticket-id>`, worktree at `<dispatcher.worktree_root>/<ticket-id>`, created from
  `main` on first claim and reused for every later stage of the same ticket.
- When a code-bearing ticket reaches `done`, the dispatcher merges with
  `git merge --no-ff factory/<id>` in the main checkout. On conflict: `git merge --abort`, the
  ticket returns to `in_progress` with a note, owner unchanged. On success: remove the worktree,
  delete the branch, append an event.
- If the repository has no commits, or `isolation` is `none`, workers run in the main checkout and
  `max_parallel` is forced to 1 for code-bearing types.

## Board (`factory/board/`)

`server.mjs` — Node `http`, bound to `127.0.0.1` only. Reads state on each request (cheap).
Writes are atomic and go through the same `lib/store.mjs` as the CLI. Mutating requests require
header `X-Factory-Board: 1` (blocks cross-site form posts).

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` `/app.js` `/styles.css` `/tokens.css` | the app |
| GET | `/api/state` | everything the UI needs in one payload (below) |
| GET | `/api/ticket/:id` | full ticket incl. notes, history, runs, handoffs list |
| GET | `/api/run/:id/tail?lines=80` | readable tail of a run log (assistant text + tool calls) |
| GET | `/api/doc?path=…` | raw markdown of a file under `knowledge/`, `factory/reports/`, `factory/demos/`, `docs/` (no traversal) |
| GET | `/api/file?path=…` | serve preview assets (images, html, video) under the same roots |
| POST | `/api/decisions/:id/answer` | `{"options":["a"],"note":"…"}` |
| POST | `/api/decisions/:id/ack` · `/veto` | for notices |
| POST | `/api/actions/:id/done` | `{"note":"…"}` |
| POST | `/api/feedback` | `{"target":"…","text":"…","sentiment":"…"}` |
| POST | `/api/control` | `{"paused":true,"reason":"…"}` |

`/api/state` payload: `{generated, product, control, dispatcher:{alive, heartbeat, active, backoff_until, runs_today}, milestones, epics, tickets:[summaries], decisions, actions, feedback, runs:{active, recent(20)}, sessions:[live], events:[last 150], library:[{path,title,group,updated}], digest:{date, path}}`.

The UI is a single page, vanilla JS, no build step, using `tokens.css` (the skenzeriq design
system). Tabs: **Overview** (needs you · running now · milestone progress · today's digest ·
activity), **Board** (kanban by status, filter by epic/owner), **Decisions** (pending, answered,
factory notices), **Library** (knowledge base reader), **Demos**. It polls `/api/state` every
`board.poll_ms` and never clobbers a form the CEO is typing in.

## Hooks (`.claude/hooks/`, registered in `.claude/settings.json`)

| Hook | Script | Does |
| --- | --- | --- |
| `SessionStart` | `session-start.mjs` | Registers the session; injects a compact factory brief (worker: ticket + latest handoff; CEO session: what needs the CEO). On `compact`: re-injects the latest handoff. |
| `PostToolUse` | `post-tool.mjs` | Context guard (reads usage from the transcript — or the subagent transcript when `agent_id` is present — and injects 70/85/95 % warnings once per threshold); updates `state/sessions/`; logs notable tool activity to the event feed; warns when a memory file exceeds its budget. |
| `PreToolUse` | `guard.mjs` | Blocks destructive shell commands, secret-shaped writes, direct edits of `factory/state/`, and edits outside the repository. |
| `PreCompact` | `pre-compact.mjs` | Writes a mechanical snapshot (ticket, git status, recent notes, files touched) next to the handoffs. |
| `Stop` | `stop-guard.mjs` | Workers: refuses to stop until the ticket was advanced, rejected, blocked, noted, or a handoff was written in this session. |
| `SubagentStop`, `SessionEnd`, `Notification`, `StopFailure` | `events.mjs` | Activity feed; macOS notification when a CEO session needs input; rate-limit signal for the dispatcher. |

All hooks are fast (< 200 ms typical), never throw (on internal error they exit 0 silently), and
read `FACTORY_*` environment variables when present.

## Development

Node ≥ 20, standard library only, ESM (`.mjs`), no build step.

### Tests

```sh
node --test factory/test/*.test.mjs
```

Use the glob: on Node 26 `node --test factory/test/` treats the directory as a module path and fails.
Every test builds a throw-away factory in a temp directory (`test/helpers.mjs`: the real
`config.json` and templates, fixture agents, an injectable clock) and never touches `factory/state/`.
Workers are `test/fixtures/fake-claude`, selected with `FACTORY_CLAUDE_BIN`; it speaks the
`stream-json` format and drives the real CLI (`FAKE_CLAUDE_MODE=advance|reject|noop|ratelimit|hang`).
Git behaviour (worktrees, merge, conflict) is tested against real repositories in the temp directory.

### Module map (`lib/`)

| Module | Responsibility |
| --- | --- |
| `store` | home resolution, atomic JSON, the `mkdir` lock (re-entrant, stale after 10 s), ids, events, control, dispatcher state |
| `flows` · `policy` · `agents` · `settings` | flow resolution and transitions (pure) · model/effort policy (pure) · agent files · optional dispatcher knobs |
| `tickets` · `decisions` · `items` · `handoffs` | ticket lifecycle · CEO decisions · actions, feedback, epics, milestones · handoff files |
| `candidates` · `escalation` | what to launch next, meta-ticket proposals · the no-progress ladder (both pure, plus one writer in `escalation`) |
| `dispatcher` · `launcher` · `prompt` · `runlog` | the loop · spawning `claude` · worker prompt · incremental `stream-json` parsing |
| `git` · `worktree` | git as argument arrays · worktrees, merge, cleanup |
| `status` · `doctor` · `format` · `library` · `lifecycle` · `cli` | `status`/`digest` data · `doctor` · terminal output · library listing and path checks · `up`/`down` · the command table |

`board/server.mjs` is the HTTP server. `bin/factory` only calls `lib/cli.mjs`.

### Optional `dispatcher` settings

`config.json` is authoritative; these keys are optional and default as shown.

| Key | Default | Meaning |
| --- | --- | --- |
| `poll_seconds` | 2 | log tailing, exit detection and time-limit checks between ticks |
| `persist_seconds` | 5 | at most this often, live context usage and activity are written to the run record |
| `shutdown_grace_seconds` | 120 | on SIGTERM, running workers may finish for this long, then get SIGTERM |
| `kill_grace_seconds` | 30 | after SIGTERM (timeout or shutdown), SIGKILL follows |
| `launch_failure_backoff_minutes` | 5 | back-off after `claude` could not be started |
| `blocked_retriage_hours` | 6 | a blocked ticket is offered to triage again after this long |

### Fields and files beyond the reference above

- **Ticket:** `escalations` (0–2), `reassigned_from` (the role displaced by an escalation, so `advance` continues the original reviewer sequence), `blocked_from` (where `unblock` returns to), `triaged_at`, `meta` (the auto-created triage/grooming/digest payload), `links.merged` and `links.merge_commit`.
- **Run:** `continuation`, `snapshot` (status, stage role and latest handoff at launch: how "no progress" is judged), `kill_reason` (`timeout` or `shutdown`), `error`; stderr is kept in `state/runs/<id>.err` next to `<id>.log`.
- **State:** `state/board.json` and `state/dispatcher.json` hold pids; `state/board.log` and `state/dispatcher.log` capture the detached processes; `state/signals/rate-limit.json` is written by the `StopFailure` hook and read by the dispatcher.
- **Environment:** `FACTORY_HOME`, `FACTORY_CLAUDE_BIN` (the executable to launch, default `claude`), `FACTORY_DEBUG=1` (stack traces).
- **API:** `/api/state` also carries `company` and `dispatcher.pid`; ticket summaries include `summary`, `created`, `parity_refs`, `effort_override`, `stage_role` and `last_note`.

### Where the runtime deliberately differs from, or extends, the reference

- **Meta tickets compete in the ready pool** by priority (triage P0, grooming P1, digest P1) instead of strictly after all ready work; with a permanently full queue, CEO answers would otherwise never be triaged. Ties go to real tickets.
- **Idle `in_progress` tickets are always re-dispatched** (continuations first), not only those with `handoff.pending`, so a ticket sent back by a reviewer, or whose worker died, is never orphaned.
- **Triage also covers `defaulted` advisory decisions** that have not been applied, not only answered ones.
- **Refused launches:** a missing agent file or a policy violation skips that candidate with one deduplicated event and leaves the ticket `ready`; a worktree failure blocks the ticket. A model other than Opus or Sonnet is always a violation.
- **Effort overrides** (escalation) are exempt from `models.escalation_only` but must be in `models.allowed`.
- **Rate limits** are detected from an error result or stderr (`rate limit`, `usage limit`, `overloaded`, `429`), or from a `StopFailure` signal for the run's session; the signal also backs the dispatcher off when it comes from the CEO's own session (the limit is account-wide). No attempt is counted.
- **Spawn failure** (`claude` missing) backs off `launch_failure_backoff_minutes` and counts no attempt.
- **`factory run --once`** performs one tick and returns; workers it started keep running and are adopted by the next dispatcher.
- **`factory feedback triage --done`** closes feedback that needs no ticket.
- **Repository without commits, or `isolation: "none"`:** one code ticket at a time runs in the main checkout; other tickets run in parallel.
- **`config.json` currently defines `"ceo"` twice** (a name string, then the settings object). JSON keeps the last, so the settings apply and the name is lost; `factory doctor` warns about duplicate top-level keys.

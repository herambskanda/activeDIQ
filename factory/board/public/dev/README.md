# Board dev fixture

`fixture-state.json` lets you work on the Factory Board UI without a running factory.

## Preview

```bash
python3 -m http.server 4800 --directory factory/board/public
# open http://127.0.0.1:4800/?fixture=1
```

With the real server (`factory/bin/factory board`) use `http://127.0.0.1:4747/?fixture=1`,
provided the server also serves `/dev/fixture-state.json`.

## What `?fixture=1` does

- Loads `dev/fixture-state.json` instead of `GET /api/state`, re-polled every 4 s like the real thing.
- Shifts every ISO timestamp so the fixture "happened" just now (heartbeat is always fresh, so the
  status pill reads **Running**; advisory countdowns tick down).
- POSTs (answer, ack, veto, done, feedback, pause/resume) send nothing. They show a
  "Fixture mode" toast and keep the optimistic result visible for the life of the page.
- The ticket drawer, run tail, `/api/doc` and `/api/file` read from the `_fixture` block.

## Shape

The file is the `/api/state` payload from `factory/README.md`, plus one extra top-level key the
app strips before use:

```
_fixture: {
  tickets: { "T-0012": { body, acceptance, notes, history, runs, handoffs, links, result } },
  tails:   { "<run id>": ["log line", …] },
  docs:    { "<repo-relative path>.md": "markdown" },
  files:   { "<repo-relative path>.html": "html" }   // decision previews, served from blob: URLs
}
```

A ticket missing from `_fixture.tickets` still opens: the drawer falls back to its list summary.

## Content

Fictional Active Directory management work for activeDIQ. 2 milestones, 6 epics, 39 tickets across
every status (one cancelled), 8 decisions (3 pending: one directional, one advisory with a default
in ~2 days, one notice; plus answered, defaulted, acknowledged, vetoed, withdrawn), 3 action items
(2 open), 2 active runs (one at 80% context), 2 live sessions, 31 events, 16 library docs in
8 groups, and one digest.

**It is fake data.** Documents say so in their first line; competitor and parity statements in it
are illustrative and carry no research value. Do not copy anything from it into
`knowledge/`. It lives under `public/dev/` for development only.

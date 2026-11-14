---
title: "Spec: Home pinned report widgets (ADM-002) and the account layout preference"
date: 2026-11-14
updated: 2026-11-14
status: draft
owner: heramb
author: solution-architect
ticket: T-1840
epic: E-007
milestone: M2b
parity: [ADM-002]
binding_sources: domain-model.md §9 (dashboards), DM-71, DM-72; modules/reports.md §6.2, §6.4, §6.6; ADR-0002 (tenancy); ADR-0003 (modules); ADR-0004 (contract first); ADR-0010; information-architecture.md §4.2
sources_last_checked: 2026-11-14
---

# Spec: Home pinned report widgets and the account layout preference

> An admin pins a report to Home, and below the fold sees that report's result **as they last ran it**,
> trimmed to **their own** scope, with the age of the data written on it. Home never runs a report on
> its own, never shows someone else's rows, and never says "live".

Competitor behaviour (ManageEngine's dashboard with custom tabs and widgets, ADM-002) is recorded
in [manageengine-admanager-plus.md](../../business/market-research/manageengine-admanager-plus.md)
(row ADM-002, help-page link there). We take the parity (pinned report widgets) and decline the
dashboard-as-landing-page: Home is "my work" ([IA §4.2](../design-system/information-architecture.md)).

## 1. Decisions (no ADR: reversible, inside ADR-0002/0003/0004/0010)

| # | Decision | Why |
| --- | --- | --- |
| W1 | **A widget shows the viewer's own latest succeeded run** of the pinned definition and preset, never the schedule owner's and never another account's. | DM-72.I5 and §6.6: a run is readable only by its runner under the scope it was computed with. Showing the owner's run would leak rows past the viewer's scope. |
| W2 | **Home never creates a run.** A widget with no usable run says so and offers **Run now** (an explicit `createReportRun` as the viewer). | A page load of 12 widgets would hit the 4-active-run tenant cap (§6.1 step 5) and burn the job queue for a screen nobody asked to be fresh. |
| W3 | **The layout is a preference, not a domain entity** (domain-model §9). It lives in a new module `uiprefs`, one row per account per key, tenant-keyed. | Preferences are per account, are not authority, and do not belong in `authn` (already the largest module) or `reports`. The key set is closed and typed, so later preferences (density, pinned views) reuse the table rather than cloning it. |
| W4 | **No history store.** A trend widget draws from the viewer's retained runs only (7 days, modules/reports.md §11). | A snapshot table would be a second copy of scoped data with its own retention and tenancy rules. Not worth it for parity. If customers want longer trends, that is a separate spec. |
| W5 | **The write class is `bookkeeping`** (ADR-0005 rule 10 class test): no widening decision, no step-up, no `step.Step`, not audited per write. | Setting your own layout widens nothing. O3 requires the table to be classified: the build ticket adds the row. |

## 2. The preference store (module `uiprefs`)

```
ui_preferences                       -- owned by modules/uiprefs; tenant table, RLS ENABLE + FORCE (ADR-0002 T2)
  tenant_id uuid NOT NULL, account_id uuid NOT NULL, key text NOT NULL
  schema_version int NOT NULL, revision bigint NOT NULL, value jsonb NOT NULL
  updated_at timestamptz NOT NULL
  PK (tenant_id, account_id, key)
  FK (tenant_id, account_id) → authn_accounts (tenant_id, id)
  CHECK key IN the registered keys; CHECK octet_length(value::text) <= 16384
```

- **Tenant key** is first in the primary key and the FK pairs `tenant_id` (fitness T2). The tenant
  comes from the principal, never from a request field (T5 `openapi-tenant-param`).
- **Per account.** `account_id` is the session's account, taken from the principal. No operation
  names an account, so one account can neither read nor write another's preference. A tenant admin
  has no route to it either.
- **Session principals only.** An API token is refused with 403, like universal search (§6.6 style).
  Layout is a console concern.
- **Closed key registry.** `uiprefs` holds `Keys []Key{ID, SchemaVersion, Validate func}`; a value for
  an unregistered key is a 400. The first key is `home.widgets`.
- **Optimistic concurrency.** `revision` increments on every write; `PUT` carries `ifRevision`
  (0 = create). A mismatch is 409 `preference_revision_conflict` with the current value, so two tabs
  do not silently overwrite each other.
- **Retention.** Rows stay while the account exists. Accounts are never deleted (DM-30 `deleted` is
  final), so there is no purge job at v1. The value holds ids and enums only, no free text.

### 2.1 Value of `home.widgets` (schema_version 1)

```json
{ "widgets": [
  { "id": "<uuid minted by the server>", "definitionId": "inventory.users.stale",
    "presetId": "default", "view": "count|table|trend" }
] }
```

- Order in the array is the order on screen. At most **12** widgets. Duplicate
  (`definitionId`, `presetId`, `view`) triples are refused (400).
- `definitionId` and `presetId` are **references**, validated for shape only on write (the same
  identifier pattern the reports contract uses). Whether the definition still exists, is published
  and is visible to the viewer is decided **on read** (§3.3), so an archived or unshared report
  shows "Report unavailable" with a Remove control instead of making the whole Home fail.
- No run parameters are pinned at v1 (a widget uses the preset's defaults). A run made with other
  parameters is a different run and does not feed the widget.
- No layout coordinates. Widgets stack in one column on narrow screens and two on wide ones; the
  frontend decides. Reordering is array order.

### 2.2 API (`uiprefs` tag; the contract is written first, ADR-0004)

| operationId | Method / path | Permission | Notes |
| --- | --- | --- | --- |
| `getUiPreference` | `GET /me/preferences/{key}` | `uiprefs.self` | 200 with `{key, schemaVersion, revision, value}`; **404 when never set**, and the client uses its default (no widgets). Never invents a value. |
| `putUiPreference` | `PUT /me/preferences/{key}` | `uiprefs.self` | Body `{ifRevision, value}`. Validates the value against the key's schema. 200 with the new revision; 400 / 409 as above. |
| `deleteUiPreference` | `DELETE /me/preferences/{key}` | `uiprefs.self` | Reset to default. Idempotent. |

`uiprefs.self` is a new permission held by **every** built-in role (so any signed-in console user
has it), added to the permission catalogue. It grants access to the caller's own rows only; the
handler has no account parameter to widen it. Limit class `read` for GET, `write` for the others.
Not audited (W5). Platform matrix: server side only, identical on Linux and Windows servers
(ADR-0001/0002); no agent or DC component is involved.

## 3. The widget contract

### 3.1 What a widget may render

A widget is a view over **one** report run. The host asks the reports module for the viewer's
latest run and renders it as one of three views. A definition declares which views it supports in its
**widget profile** (data in the definition, owned by `reporting-engineer`):

```
WidgetProfile { views []View; tableColumns []ColumnID (<= 5); trendMeasure = row_count }
```

| View | Renders | Allowed when | Data source |
| --- | --- | --- | --- |
| `count` | the run's `row_count` as one number, with the report name | **every** definition (the number is already trimmed by the runner's scope) | run header |
| `table` | the first **10** rows, the profile's `tableColumns` (at most 5), a "View all N" link to the report run screen | the profile lists `table`, and the run is current (§3.2) | `listReportRunRows` page of 10 in run order |
| `trend` | a sparkline of `row_count` over the viewer's succeeded runs of the same definition and preset, oldest to newest, up to 30 points | the profile lists `trend`, **and** at least 2 points exist | `listReportRuns` filtered by definition, `scopeCurrent = true` only |

- **Trend points only come from runs whose scope fingerprint still equals the viewer's current
  one** (`scopeCurrent`). A run under an older scope is dropped, not plotted. With fewer than 2
  points the widget falls back to `count` and says "Trend needs two runs" rather than drawing a line.
  It never interpolates, and it states the span ("last 7 days at most").
- **Hidden groups.** A table or count that excludes a preset's hidden groups says so with the
  report's own "N hidden" text (§6.4, `hiddenGroups`). The widget must not show a total that the
  report screen would not.
- **Derived-state cells** follow FR-09 (unknown, never inferred). Export and act-on-results are not
  on a widget: it links to the report.
- **Shipped definitions get a profile in the shipped-library change.** A definition with no profile
  supports `count` only. Nothing is guessed from column types.

### 3.2 Which run, and the scope rule (the answer to "whose scope?")

The reports module gains **one read operation**, the widget host's single backend call:

`getLatestReportRun` — `GET /reports/runs/latest?definitionId=&presetId=&rows=0|10`, permission
`reports.run`, limit class `read`.

Selection and trimming (all server-side, in `run.Service`, never in the client):

1. `WHERE runner_account = chain.Requester AND definition_id = $1 AND preset = $2 AND state IN
   (succeeded, queued, running, failed, expired)` ordered `created_at DESC, id DESC`, **limit 1**,
   with the **latest succeeded** run preferred over a newer failed or running one (a running run
   is reported alongside it as `inFlight`, so the old numbers stay visible while a refresh runs).
   The index `(tenant_id, runner_account, created_at DESC, id DESC)` already serves this.
2. `runner_account` is the **caller**, taken from the principal. There is no parameter that names
   another account. A scheduled run belongs to the schedule owner (§6.6), so if the viewer is not
   the owner it is **never** a candidate, whatever the schedule's recipients are. If the viewer
   owns the schedule, those runs are theirs and are candidates.
3. When `rows=10`, the page goes through **`run.ReadAccess`** (§6.6, checks 1 to 5) like every other
   read. The latest-run operation adds **no second gate**. A run whose stored `scope_fingerprint`
   differs from `rbac.ReadScopes.For(chain, reports.run).Fingerprint()` is **not served**: the
   response carries the header only, `state: scope_changed`, `rowCount: null` (the same
   behaviour as `scopeCurrent: false` in the history list), and the widget offers **Run now**.
4. The response never carries the digest, the parameters or the scope text. Those are on
   `getReportRun`.
5. A refused or absent run leaves the same bytes for "someone else's run exists" and "no run": the
   operation only ever looks at the caller's rows, so there is nothing to distinguish.

Fitness (**WG1**, `fitness-reports`): `getLatestReportRun` reaches run rows only through
`run.ReadAccess`, the SQL for it contains `runner_account =` bound to the principal, and a probe
with accounts A and B (same definition, B holding a wider scope, a schedule owned by B delivering to A)
asserts A gets no rows or header of B's runs, and gets `scope_changed` after A's assignment narrows.

### 3.3 Widget states (the stale-run behaviour)

The API answers one `state` per widget; the frontend renders exactly these and nothing else:

| `state` | When | Shown |
| --- | --- | --- |
| `current` | latest run succeeded, scope fingerprint matches | the view, plus the data-age label (§3.4) |
| `stale_data` | as `current` and the run's freshness state is `stale`, `resync_required` or `paused` (§6.4) | the view, the label in the warning style naming the connection and age from `freshness.stale[]` |
| `scope_changed` | succeeded, but the viewer's scope differs from the run's | no rows, "Your access changed since this ran", **Run now** |
| `expired` | past `expires_at` (7 days) | no rows, "Result expired on {date}", **Run now** |
| `running` | a run is `queued` or `running` | the previous result if one is current, plus "Refreshing…"; polls `getReportRun` every 5 s, backing off to 30 s, stopping after 10 min |
| `failed` | the latest attempt failed and no earlier run is current | the failure reason in the user-facing wording the reports contract defines, **Retry** (`retryReportRun`) |
| `never_run` | the viewer has never run this definition and preset | "Not run yet", **Run now** |
| `unavailable` | definition archived, removed or no longer visible to the viewer, or the viewer lost `reports.run` | "Report unavailable", **Remove from Home**. A viewer without `reports.run` sees no reports block at all (absent, not disabled) |
| `error` | the request itself failed | the shared error state with Retry. Never a blank card, never zeros |

- **Run now** calls `createReportRun` as the viewer (reuse window, tenant job cap and 429 behave as
  on the report screen, and a 429 is shown as such). It is the only way a widget produces data.
- There is **no automatic refresh** other than polling an in-flight run. Opening Home does not
  make the data newer. The label says how old it is.
- Widgets load **lazily** as they enter the viewport, at most 3 requests in flight. Search and the
  blocks above the fold never wait for them (IA §4.2: "search first, the rest streams in").

### 3.4 Data-age display

Two ages exist and the card shows both, in this order and wording (frontend copy is the
design system's; the fields are fixed here):

- **Primary: "Data as of {as_of}"**, where `as_of` is the run's freshness watermark, the oldest
  last successful sync pass among the naming contexts covered (§6.4). Shown as a relative time with
  the absolute timestamp in a tooltip and for screen readers ("as of 14:05, 2 hours ago").
- **Secondary: "Run {finished_at relative}"** for when the report was last run.
- `stale_data` names the connection and age from `freshness.stale[]` ("Contoso DC sync is 3 h old").
- The label never says "live", "real-time" or "now". A per-DC read, if the definition uses one
  (§6.5), shows its `read_from` coverage ("answered by 9 of 10 DCs").
- Times use the viewer's locale and time zone (localization ticket T-1839 provides the formatter;
  until it lands the widget uses the shell's existing formatter and does not hard-code a format).
- `never_run`, `unavailable` and `error` show no age, because there is no data.

## 4. Home integration and pinning

- **Pinning** is an action on the report screen ("Pin to Home" / "Unpin"), a `PUT` of the whole
  list with the current `revision`. Home reads the preference once, then resolves each widget. The
  frontend pins nothing silently: no default widgets are created, and a fresh account's Home shows
  **no reports block** until the first pin (no sample data, IA §4.2 "Optional").
- The Home block lives in the `home` web module (T-1832's module). It imports the reports and
  uiprefs clients only through the generated API client (ADR-0004 rule 12), never another
  module's screen code (ESLint module boundary).
- The pin list is validated against `reports.run` when read: widgets whose definition the viewer can
  no longer see turn into `unavailable` (§3.3) and are never silently deleted from the preference.

## 5. Architecture consequences

- **New module `uiprefs`** (`internal/modules/uiprefs`): owns `ui_preferences`; registers through
  `Registrar` (API handlers, one permission, the key registry) per ADR-0003 and ADR-0013; it has a
  page under `architecture/modules/uiprefs.md` (fitness M3 fails the build without one). It imports
  `platform/...` only, and no other module imports it (it exposes no port).
- **`reports`** gains `getLatestReportRun`, the `widget profile` on definitions, and WG1. It does
  not learn about Home or layout: the host is a client of two APIs.
- **Tenancy fitness** needs no new rule: T2 and T4 already cover a new tenant table. The build
  ticket adds `ui_preferences` to the O3 write-class list as `bookkeeping`.
- **No new dependency** (licence register unaffected).

## 6. Acceptance criteria (Given/When/Then for the build tickets)

1. Given an account with no `home.widgets` preference, when Home loads, then no reports block is shown and no request is made to `reports`.
2. Given account A pins a report, when account B in the same tenant reads `GET /me/preferences/home.widgets`, then B sees B's own value (404 if never set), never A's; and a request naming another tenant or account is impossible by contract.
3. Given two tabs hold revision 3, when both `PUT`, then the second gets 409 `preference_revision_conflict` carrying the current value.
4. Given a schedule owned by B delivering to A, when A's widget for that definition loads, then A sees `never_run` (not B's run), and after A runs it, A sees A's rows trimmed to A's scope.
5. Given A's delegation is narrowed after A's last run, when the widget loads, then the state is `scope_changed`, no rows or counts are returned, and **Run now** produces a run under the narrower scope.
6. Given a current run with `freshness.state = stale`, when the widget renders, then it shows "Data as of {time}" in the warning style naming the connection, and never the word "live".
7. Given a run older than 7 days, then the state is `expired` and no row page is requested.
8. Given a trend widget with one run, then the widget shows the count and "Trend needs two runs"; with a run under a former scope in history, that point is not plotted.
9. Given 12 widgets, when Home loads, then at most 3 widget requests are in flight and no run is created without a click.
10. Given a pinned definition later archived, then the widget shows "Report unavailable" with Remove and the preference is unchanged.
11. Given a viewer without `reports.run`, then the reports block is absent, and `getLatestReportRun` answers 403.

## 7. Open items

- The widget profile of each shipped definition (which support `table` and `trend`, and the 5
  columns) is `reporting-engineer`'s, in the shipped-library change. Until a definition has one it
  offers `count` only. `[OPEN → T-1840 backend ticket]`
- Whether the 7-day trend window is enough for sales is a product question; extending it needs
  its own spec (W4). Not blocking.

## 8. Build tickets cut from this spec (all under E-007)

Tickets: T-2081 preference API contract (api-engineer), T-2082 `uiprefs`
module and store (backend-engineer), T-2083 `getLatestReportRun` and widget profile (reporting-engineer),
T-2085 Home reports block and widget host (frontend-engineer), T-2084 WG1 fitness probe (test-engineer).

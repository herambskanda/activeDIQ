---
title: "2a report flows: library, search, run, results, export, schedule"
date: 2026-10-30
updated: 2026-10-30
status: draft
owner: product-designer
ticket: T-0867
decisions: [D-0005, D-0012]
---

# 2a report flows: design and prototype

**What it is.** The screen-level design of the 2a report flows for [reports-2a.md](../specs/reports-2a.md) §5, §6.2, §8.2 to §8.4, as a clickable Storybook prototype on the Ledger tokens plus this note. The frontend tickets build from it; nothing is left to decide except the items under *Open items*. Every name, count, address and DC in the prototype is **sample data** (`web/src/prototype/reports/fixtures.ts`), labelled "Prototype · sample data" on screen. The prototype is not part of the console bundle.

**Run it.** `cd web && npm run storybook`, then **Prototype / Reports 2a / End To End**. Press `/`, type `domain admins nested`, Enter, `E`, `X` (T19). For T20: `/`, `password never expires`, Enter, `S`, pick **Monthly**, type a recipient, Save. The counter at the top counts interactions in total and "from the open report". Story ids are `prototype-reports-2a--<kebab-name>`. 49 stories; axe: 0 violations on all of them. 51 screenshots (48 stories plus the end states `T19-export-done`, `T20-saved` and `schedules-bulk-pause-confirm`) are in `factory/demos/evidence/T-0867/<kebab-name>.png`.

**No token change.** `git diff web/src/ds/tokens.css` is empty and `reports.css` contains no hex or `rgb` value. Where a value was missing it is listed as a component gap below, not invented.

## 1. Task-time tables (acceptance 1)

Counting follows benchmark §1.2: **I** interactions (click, key press or typed field = 1; a drop-down is open + choose = 2), **F** typed fields, **S** screens. ME steps are copied from [top-admin-tasks-benchmark.md](../specs/top-admin-tasks-benchmark.md) T19 and T20, where each step carries its source ([doc] = ManageEngine help or page, [inferred] = not documented). Ours are **measured** by driving the built prototype with Playwright, not estimated.

### T19 · Export nested membership of Domain Admins for an auditor

| # | ManageEngine ADManager Plus | I | Source | activeDIQ | I |
|---|---|---|---|---|---|
| 1 | Reports tab | 1 | doc | `/` | 1 |
| 2 | "Group Reports" menu | 1 | doc | Type "domain admins nested": the first hit is *Detailed Group Members · Domain Admins* with the group already filled in | 1 (+ typed field) |
| 3 | "Detailed Group Members" | 1 | doc | Enter: results open, effective (nested) members, default run, no Generate | 1 |
| 4 | Domain: preselected | 0 | demo pattern | (none: all permitted domains are the default) | 0 |
| 5 | Group: object picker (open, type, choose, confirm, and so on) | 5 | inferred | `E`: export menu opens | 1 |
| 6 | Generate | 1 | doc | `X`: XLSX evidence pack starts downloading | 1 |
| 7 | "Export As" → PDF | 2 | doc | | |
| | **Total** | **11** | benchmark 20.2 s | **Total** | **5** (budget 6) |

- **Export from results = 2** (`E`, then `X` or `C`), against ME's "Export As" + format = 2 at step 7, but ours starts with the file, not after a Generate.
- The download starts by itself when the job finishes. If the browser blocks an automatic download, the toast carries a **Download** link: **+1**, so "2, or 3 if the browser blocks it".
- **Fallback if the search cannot return a report+object hit** (it depends on the global search carrying report names; see *Open items*): open the group page, Members › Effective toggle, Export, PDF/XLSX = the benchmark's own 6.
- The XLSX on this report is the **evidence pack** (About sheet with scope, filters, freshness label, digest; a "Via" column with the nesting path of every member). PDF and HTML appear in the menu only when T-0102 ships them; the menu lists formats that exist, never greyed promises.

### T20 · Schedule a monthly "password never expires" report by e-mail, PDF-equivalent, 1st at 08:00

| # | ManageEngine ADManager Plus | I | Source | activeDIQ | I |
|---|---|---|---|---|---|
| 1 | Reports tab | 1 | doc | `/` | 1 |
| 2 | "Schedule Reports" | 1 | doc | Type "password never expires" | 1 |
| 3 | "Standard Scheduler" | 1 | doc | Enter: the report opens | 1 |
| 4 | "+ Create Schedule" | 1 | doc | `S`: side sheet opens with report, filters and columns as on screen | 1 |
| 5 | "Schedule Name" (typed) | 1 | doc | *Monthly 1st 08:00* preset chip | 1 |
| 6 | Domain: preselected | 0 | default inferred | Recipient typed (+ Enter) | 1 |
| 7 | "Select Reports": category drop-down | 2 | doc | Save (the sheet is the action preview; Save is the confirm) | 1 |
| 8 | Pick the report in "Available Reports" | 1 | doc | | |
| 9 | "Monthly" | 1 | doc | | |
| 10 | Time drop-down → 08:00 | 2 | inferred | | |
| 11 | Format: PDF | 1 | doc | | |
| 12 | "Email To" (typed) | 1 | doc | | |
| 13 | Save | 1 | doc | | |
| | **Total** | **14** | benchmark 26.1 s | **Total** | **7 from `/`; 4 from results** (budget 7 / 6) |

- **From results: 4** (`S`, preset, recipient, Save). Acceptance asks for ≤ 6.
- **External recipient: 8 from `/`, 5 from results.** Typing an address outside the allowed domains shows a required checkbox *"Data leaves your organisation: <address>. I confirm."* (TM-TB15-T2, spec §8.4). It is the one added interaction and it is the point of the safety rule; it is required before Save, not after.
- **Opening by an ME name** ("Recently Logged on Users") is 3 interactions and the header says *Also known as: Recently Logged on Users* so the migrating admin sees the concept maps.
- **Time targets stay the benchmark's** (T19 ≤ 16 s, T20 ≤ 22 s). Our interaction counts are at or below the benchmark's, so no new time is claimed; the stopwatch re-measure is the `ux-review` job (T-0106).

## 2. Screens and the decisions behind them

Layout is one page: a report header, a filter bar, the grid, and layers (search overlay, popover menus, side sheet) that never stack on each other.

| Decision | Why (task-time) |
|---|---|
| **No Generate step.** Opening a report runs its default preset and shows the first page (FR-04). | Removes 1 interaction per report in every ME flow. |
| **Changing preset, period, domains, column filter or columns makes a new run with a new run id** (FR-11). **Sorting only re-orders the same run.** | The header's run id and "as of" always describe exactly what is on screen; an export or schedule made from it is that run. |
| **Search is the front door.** `/` anywhere; hits are report names, ME names (crosswalk of spec §6.2), and report+object composites ("domain admins nested"). Each hit shows its category; ME names show "Logon activity · preset Recently Logged on Users". | Saves ME's Reports › category › report (3) for every report. |
| **Library** is a category-grouped, filterable list, for browsing only; the header filter understands ME names. Never needed for T19/T20. | Browsing stays possible for people who don't know the name; it is not on the fast path. |
| **Header** shows scope applied, freshness label (§8.2: Synced hh:mm / Stale / Not synced yet / Expired / "Read from 5 of 6 DCs"), row count, preset chips, **Export (E)**, **Schedule (S)**, and the deep link `/reports/<id>?preset=…&days=…&group=…`. | A shared URL reproduces the view (data trimmed per viewer). |
| **Service accounts are hidden by default** with a visible "N probable service accounts hidden · Show" toggle (E2). | Admin never ticks them off one by one. |
| **Grid** is windowed (22 DOM rows for a 3,000-member group; 12,000-user sample), sticky header, sortable, column chooser as a popover, 40+ character names truncated with full text in `title`. **No row selection at 2a** (FR-13). | Dense tables are a feature; selection arrives with 2b actions. |
| **Group member reports hide the Domains control** (the group fixes the domain set). | A control that does nothing is a dead button. |
| **Export menu lists formats that exist** (XLSX default, CSV). A format over its tenant row cap is `aria-disabled` with its limit shown; the menu says *"No file was created."* and, when the other format is within its cap, names it ("CSV allows 1,000,000 rows: choose CSV (C)"). Formats can have different caps because a tenant may lower each one separately (spec §8.3). | Never truncates silently (§8.3); refusal always offers a narrower filter or another format. |
| **The schedule sheet is the Action preview** (ADR-0005 rule 10): what will run, who receives it, "recipients receive what you can see", Save is the confirm. Nothing precedes it. | A separate preview/confirm screen would add 1 to 2 interactions to a rare task for no extra information. |
| **Preset is not preselected** in the sheet. | A silent default schedule is the wrong kind of speed for something that e-mails data; counted as 1 click. |
| **Schedules list**: filter All / Needs attention / Paused, row selection with bulk Pause and Resume and an **inline** confirmation naming how many will change and how many are skipped (no modal). Row opens a detail sheet with per-recipient delivery. | Bulk wherever a single action exists. |
| **Undo** of `reports.schedule.create` removes the schedule (toast: "Schedule removed. Nothing was sent."). | Prior version is "none"; see *Open items*. |

## 3. States and exact messages (acceptance 2)

All are stories; the screenshot is `factory/demos/evidence/T-0867/<story>.png`. Text in quotes is exactly what the prototype shows. **Spec** = text taken from spec §5; **designed** = written by the designer and needing PM / reporting-engineer review.

| State | Message / treatment | Story | Origin |
|---|---|---|---|
| **Empty scope** (role has a `reports.run` but no scope) | Title "Your role covers no directory objects". Body: "Ask an administrator to grant a scope. There are zero rows because nothing is in your scope; this is not an error and nothing is broken." Header chip "○ No data in scope". Button "Copy a request for your administrator". Zero rows, never an error. | `empty-scope` | Spec |
| **Expired result** (result older than the 7-day retention) | Title "This result has expired". Body: "Results are kept 7 days; this one was run on 23 Oct at 09:43. It is not shown as current. Run it again with the same settings to see today's data. Exporting does this for you first." Primary button *Run again with the same settings*. Header chip "○ Expired: was synced 09:41 on 23 Oct". | `expired-result`, `expired-result-export-reruns` | Designed (spec: "expired result") |
| **Stale data** | Banner (warn, glyph ⚠, role=status): "Stale data. The last successful sync of emea.corp.example was 3 hours ago (06:41) because that connection is waiting for a full resync. This report ran on what activeDIQ last saw. Exports and scheduled deliveries carry this warning." Header chip "⚠ Stale: last sync 3 h ago (emea.corp.example)". Rows are shown. | `stale-data` | Spec §5, §8.2 |
| **Unsupported scope kind** | Title "Reports can’t use your role’s scope yet". Body names the kind, one variant per story: **group members** — "Your role is scoped by group members, which reports don’t support at this stage. Reports return nothing rather than guess, so there are zero rows. Ask an administrator to scope your role by domain or OU." (`unsupported-scope-kind`); **Entra administrative unit** — "Your role is scoped by an Entra administrative unit, which reports don’t support at this stage. Reports return nothing rather than guess, so there are zero rows. Ask an administrator to scope your role by domain or OU." (`unsupported-scope-entra`). Button "Copy a request for your administrator". Fails closed. | `unsupported-scope-kind`, `unsupported-scope-entra` | Designed |
| **No permission: no `reports.run`** | No Reports entry, no report hits in search. A deep link shows "You don't have access to reports. Your role does not include running reports (`reports.run`). Ask an administrator to add it to your role. Nothing here was changed." | `no-reports-permission`, `search-no-permission` | Spec (no entry, no hits); deep-link wording designed |
| **No permission: run but not export/schedule** | The Export and Schedule buttons stay visible and are truly `disabled` (same grey disabled treatment as in `empty-scope`, never a live-looking button that does nothing); `E` and `S` do nothing because they follow their buttons. A note directly under the buttons (role=note, linked by `aria-describedby`) says: "You can run this report but not export or schedule it. Ask an administrator for “export reports” and “schedule reports”." One-permission variants: "You can run this report but not export it. Ask an administrator for “export reports” (reports.export)." and "You can run and export this report but not schedule it. Ask an administrator for “schedule reports” (reports.schedule)." | `no-export-or-schedule-permission` | Designed |
| Not synced yet | Banner "Not synced yet: labs.example. That domain has not finished its first sync, so it is skipped. The rows below cover the other 2 of 3 domains." | `not-synced-yet` | Spec |
| Run failed | Title "This run failed: the query timed out". Body: "The database did not answer within 30 s. Nothing was changed and no file or e-mail was sent. Run R-… is kept with this reason." Button *Retry* (new run). The reason is the typed reason from the run record; only this sample is drawn. | `run-failed` | Spec (typed reason + retry); wording designed |
| Run cancelled | Title "Run cancelled". Body: "Nothing was changed. No partial result is kept as current." Button *Run again*. | (Cancel run button on `per-dc-running`) | Designed |
| Loading | Skeleton rows, "Running… the first page appears as soon as it is ready." | `loading` | Designed |
| Empty result | Title "No users match". Body: "12,431 users were checked in 3 domains as of 09:41. Your row filter “zzqx” matched none of them." Button "Remove filter “zzqx”". Never a blank grid. | `empty-result-filter` | Spec |
| Per-DC running | "Reading domain controllers…" with progress and "This runs in the background; you can leave the page and it keeps going." | `per-dc-running` | Spec §6.5 |
| Per-DC partial | Banner "Read from 5 of 6 domain controllers. dc-ams-03.emea.corp.example did not answer (LDAP timeout after 30 s). Dates are the latest logon found, "at least"; "Not confirmed" means none of the 5 DCs that answered recorded a logon. It does not mean the account never logged on." | `per-dc-partial` | Spec |
| Per-DC over read cap | "This run is too large to start. It would read 52,000 accounts from 6 domain controllers (312,000 reads). The limit is 250,000 per run, to protect the DCs. Nothing was read. Narrow the domains, the period or the filter, then run it again." | `per-dc-over-read-cap` | Designed |
| Export over tenant row limit, both formats | In the menu, both formats disabled with "limit 10,000 rows" and: "This export has 12,431 rows. Your organisation limits CSV and XLSX to 10,000. No file was created. Narrow the filters (period, domain or column filter) and export again." (Users, All Users, 12,431 rows, sample caps lowered to 10,000.) | `export-over-tenant-limit` | Spec §8.3 |
| Export over limit, one format | XLSX disabled; CSV still works. "This export has 12,431 rows. Your organisation limits XLSX to 10,000. No file was created. CSV allows 1,000,000 rows: choose CSV (C), or narrow the filters (period, domain or column filter)." Focus lands on the first format that works. | `export-over-one-format-limit` | Spec §8.3 ("a narrower filter or another format") |
| Expired result, then export | Menu note "This result has expired. Exporting runs the report again first and says so."; toast says the file carries the new time. | `expired-result-export-reruns` | Designed |
| External recipient | Required checkbox "Data leaves your organisation: <address>. I confirm." | `schedule-external-confirm` | Spec §8.4 |
| External recipient not allowed | Save refused, nothing saved: "You can't send to <address>: it is outside your organisation's allowed domains and you don't have permission to deliver outside it (reports.deliver.external). Remove it, or ask an administrator." | `schedule-external-not-allowed` | Spec §8.4; wording designed |
| Schedule validation | An error list (role=alert) above Save, one line per problem, nothing saved: "Choose when it runs.", "Add at least one recipient.", "“x” is not an e-mail address. Remove it or fix the spelling.", "Tick the box to confirm data leaves your organisation." | `schedule-validation` | Designed |
| Hourly refused for a per-DC report | Save refused: "This report reads domain controllers, so it can run no more often than daily. Choose Daily or slower." | `schedule-hourly-refused-for-dc-report` | Spec §6.5 |
| Delivery failure | List chip "⚠ 1 failed"; detail lists per recipient sent / queued / failed / gave up with the reason: "Owner lacks external delivery permission. The other 2 recipients were sent. Ask an administrator for reports.deliver.external, or remove this address." | `schedule-delivery-failure` | Spec §8.4; wording designed |
| Paused, owner disabled | "Paused 29 Oct 08:00: the owner, Dana Whitlock, is disabled. Tenant owners were notified. Nothing is sent until someone with "manage all schedules" reassigns it and the new owner resumes it." | `schedule-paused-owner-disabled` | Spec §8.4 |
| Ran, nothing to send | "Nothing queued: "Only send if there is data" is on and the last run had 0 rows." | `schedule-ran-nothing-to-send` | Spec §8.4 |
| Bulk pause | Inline: "Pause 2 active schedule(s)? Nothing is sent until they are resumed. Already paused ones are skipped." | `schedules-bulk-pause-confirm` | Designed |
| Library / search, no match | Library: title "No report matches “zzqx”", body "Checked report names, categories and the 54 ManageEngine report names. Try fewer letters, or clear the filter to see all 16." and a Clear filter button. Search overlay: "Nothing matches “zzqx”. Search checks report names, ManageEngine report names and categories; try fewer letters." | `library-no-match`, `search-no-match` | Designed |

Every glyph state pairs the symbol with words (✓ Synced, ⚠ Stale, ◷ Not synced yet, ○ Expired, ● Read from n of m), so no meaning is carried by colour alone. Contrast follows the tokens (axe: 0 violations).

## 4. Keyboard map

| Key | Does | Where |
|---|---|---|
| `/` | Open search | Anywhere; not while typing or with a layer open; only with `reports.run` |
| `↑ ↓`, Enter, Esc | Move, open, close | Search overlay |
| `E` | Open the Export menu | Results; only with the export permission |
| `X` / `C` | XLSX / CSV, starts the export | Export menu |
| `S` | Open the schedule sheet | Results; only with the schedule permission |
| Esc | Close the menu, popover or sheet; focus returns to the control that opened it | All layers |
| Tab order | Header › filter bar › grid › pager; sheets trap focus and restore it on close | |

Layers never stack: opening one closes the previous (search closes before the report opens; the schedule sheet replaces any popover).

## 5. URL scheme

`/reports` (library), `/reports/<ID>?preset=<id>&days=<n>&group=<name>&domains=…` (a run's parameters; the first page is on screen on open), `/reports/<ID>/runs/<runId>` (run details with files and deletion), `/reports/schedules`, `/reports/schedules/<id>`. The URL holds parameters only, never results; the data is trimmed to what the viewer may see.

## 6. Component gaps (acceptance 3)

What exists in `web/src/ds/components`: Button, TextInput, Chip (`ok`, `muted` only), Table (not virtualised), Skeleton, StatePanel. The prototype therefore carries **local** versions in `reports.css` built from existing tokens; each gap below replaces one.

| Ticket | Component | Needed by (screens) |
|---|---|---|
| (a) T-0897 → T-0952 DataGrid (**done**: `web/src/ds/components/data-grid.tsx`; the local grid CSS is deleted) | Virtualised rows, sticky header, sortable columns, column sizing, row-header, truncation with `title`; row selection as an option (2b, schedules) | Results grid, schedules list, library |
| (b) T-0898 Overlays | Popover menu with accelerator keys, SideSheet (focus trap/restore), Toast with action | Export menu, columns and domains popovers, schedule sheet, schedule detail, run-details, toasts |
| (c) T-0899 Form controls | Select, Checkbox, RadioCard, SegmentedControl (preset chips), TokenInput with typeahead | Filter bar, schedule sheet (preset, recipients, format, external confirm) |
| (d) T-0900 Feedback | Banner (warn / crit / info, with glyph), Chip tones `warn` and `crit`, Progress, Kbd hint, StatePanel with actions | Every state banner, per-DC running, header freshness chips |

Frontend tickets: (e) T-0901 library, search hits, run and results screens; (f) T-0902 export and schedule screens and the schedules list. They depend on the report API contract (T-0866) and on the component tickets. T-0869 (breakdown of the reports module) should fold them in, not duplicate them.

## 7. Open items

- **Composite search hit.** "domain admins nested" → *Detailed Group Members · Domain Admins* needs the global search to return report+object hits (the console search today covers users only). If it slips, the fallback is the group page route (6 interactions, inside the budget).
- **Not drawn, to avoid dead controls:** reassign-owner UI for a paused schedule, a custom period range, OU include/exclude pickers for scope, and the admin screen for allowed recipient domains. Each is a follow-up design ticket when its API exists.
- **Undo of `reports.schedule.create`** removes the schedule; confirm with solution-architect that this matches ADR-0005 rule 10 (T-0892 covers the preview/undo surface).
- **Messages needing review** (marked *Designed* above): unsupported scope, expired, failed-run text, read cap (the 250,000 figure is a sample, not a decided limit), tenant export cap. The failure-reason taxonomy belongs to the reporting-engineer; one sample reason is drawn.
- **No file is produced** in the prototype: a hand-written CSV writer would bypass the shared encoder (formula neutralisation, T-0150).
- **Browser-blocked downloads** are described, not simulated.
- No CEO decision is needed: this is usability on the Ledger system (D-0012).

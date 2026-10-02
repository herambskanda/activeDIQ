---
title: "activeDIQ information architecture and navigation"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
ticket: T-0009
sources_last_checked: 2026-10-02
---

# activeDIQ information architecture and navigation

**What this is.** This is the structure of the activeDIQ console. It covers:
- the sitemap and primary navigation;
- global search and the command palette;
- the anatomy of an object page;
- how delegation scopes shape what a technician sees.

It makes one console out of what ManageEngine (ME) sells as separate products. Every top-20 task from the T-0008 benchmark has a path from Home within its budget. [`ia-paths.py`](information-architecture/ia-paths.py) proves it (§9).

**What it is not.** It is not a visual style. The wireframes are greyscale and brand-neutral on purpose (D-0005; factory-director note on T-0009). Style comes from T-0042 (the CEO's pick) and T-0043 (the design system). It is not a spec either: behaviours here become acceptance criteria in the module specs (T-0066 find, T-0067 reports, and the E-011 delegation spec).

**Artefacts**
- Wireframes: [`information-architecture/wireframes.html`](information-architecture/wireframes.html). Open it in a browser. It has 9 frames, and **all data in it is sample data**.
- Screenshots: [`information-architecture/screens/`](information-architecture/screens/), `01-home.png` … `09-states.png`.
- Path check: [`information-architecture/ia-paths.py`](information-architecture/ia-paths.py). Run `python3 ia-paths.py`; it exits 1 if any path is over budget. Its budgets are parsed from T-0008's `klm.py`, so the two documents cannot drift apart.

**Abbreviations**
- `BM` = [`../specs/top-admin-tasks-benchmark.md`](../specs/top-admin-tasks-benchmark.md) (T-0008)
- `DM` = `knowledge/development/domain/domain-model.md`
- `TM` = `knowledge/development/architecture/threat-model.md`
- `SP` = `knowledge/development/architecture/safe-primitives.md`
- `PAT` = `.claude/skills/design-system/patterns.md`
- `ADM` = `knowledge/business/market-research/manageengine-admanager-plus.md`
- `CV` = `knowledge/business/market-research/manageengine-ad-customer-voice-and-security.md`

## Key decisions

1. **Eight top-level sections, stable through M5.** The operating sections are Home · Directory · Clean up · Reports · Requests · Audit. The configuration sections are Automation · Settings. Later milestones add children, never new top-level sections (§4.4). By comparison, ADMP alone has 11 top tabs, and ADAP and ADSSP are separate consoles (§1.2).
2. **Search is the front door, and the object page is the workspace.** 16 of the 20 tasks start with `/`. Actions live on the object they change (BM P1, P2). There is no separate help-desk console: the help desk's console is search plus the object page.
3. **One object, one page, AD and cloud together.** A hybrid user has one page with an AD section and a cloud section, never two products. ME's Microsoft 365 tab is a separate embedded app ([demo](https://demo.admanagerplus.com/); ADM :736).
4. **No global domain selector.** Search and lists span every domain in your scope, and the domain is a facet. ME's form warns that "Changing domain in middle of things will reset all domain specific attributes" ([help](https://www.manageengine.com/products/ad-manager/help/user_management/creating_a_windows_user.html)).
5. **One visibility rule for delegation (§8.2).** It reconciles PAT ("hide what the role can never do") with BM P8 ("nothing silently disappears"):
   - hide a capability the account never holds;
   - show a held action as disabled with its reason when it cannot apply to *this* object;
   - turn a held action into **Request…** when the role holds it in request mode;
   - never show objects the account cannot read.
6. **Tier 0 is visible but read-only.** v1 never writes a `tier0` object (TM-D2, DM-35.I5). Write actions on Tier-0 objects are shown disabled with that reason, so the boundary teaches itself. This corrects five T-0008 states (§9.4).
7. **Least privilege by default.** A delegation reaches only what it names. "Read-wide, write-narrow" is an explicit, visible option in the Delegate wizard, and it is off by default (§8.6).
8. **No modal stacks.** At most one side sheet. Pickers are inline type-aheads, and step-up MFA is an inline prompt inside the sheet or panel that asked for it (§6.4).
9. **Search speaks ME.** Typing an ME page name such as "Help Desk Reset Password Console", "Create Bulk Users" or "Account Lockout Analyzer" lands on the activeDIQ equivalent (§4.5). Migrating admins get recognisable concepts without the maze.
10. **Keyboard map.** Object-page actions use single keys (`R`, `U`, `A`, `M`, `O`, `E`, `D`), go-to uses `g` + key, and `/` or Ctrl/⌘+K opens search. All keys can be switched off (WCAG 2.1.4), and every key has a button that costs the same. The T-0008 letter `G` for "Add to group" becomes `A`, which keeps `g` free for go-to. Counts do not change.

## 1. Inputs and constraints

### 1.1 What the IA must satisfy

| Input | What it demands of the IA |
|---|---|
| BM §2, §4 (P1–P8) | The interaction budget for each of the 20 tasks; search overlay; object page as workspace; preview; bulk equals single; undo; friction that scales with impact; background jobs; permission-aware UI |
| DM-33…36 | Authority is role ∩ delegation scope. A scope is a set of GUID-rooted OU subtrees or levels, group members, naming contexts, Entra tenants or AUs, with include/exclude (exclude wins). Privileges have a mode (`execute`/`request`) and constraints (`max_batch`, attribute and template allowlists, report categories, `csv_allowed`). Counts and pages are computed after scope trimming (DM-35.I4) |
| TM-D2, TM §6.4 | v1 never writes a `tier0` object. The set is computed (C1–C16, E1–E5) plus customer additions |
| TM-D16 | Step-up MFA for secret reveals, RBAC changes, connection and credential changes, audit export, Tier-0 designations and more |
| SP §3.7 | A secret is read for one object per reveal, never in a list or a file. Presence checks never return values |
| DM-18.I2/I3 | History is observation-based. v1 never attributes a native change to a person |
| m2-plan, roadmap | 2a find and report; 2b manage safely; 2c hybrid, ME import, report builder; 2d workflow, JML, ITSM. M3 audit, M4 self-service, M5 breadth |
| ENH-01, -02, -04, -05, -09 | Task-first console, migration kit, preview and undo, report builder, caller verification (enhancement catalog) |

### 1.2 What ME does today, and what admins say about it

- **ADMP top tabs** (public demo, build 8041, [demo.admanagerplus.com](https://demo.admanagerplus.com/); ADM :729): Home, Management, Reports, Microsoft 365, Governance, Delegation, Workflow, Automation, Admin, Backup, Support.
  - Each tab has three navigation levels: a sub-menu bar, a left pane, and landing pages of grouped links.
  - The User Management landing page shows **87 links** (BM §1.5, [me-05](../specs/top-admin-tasks-benchmark-evidence/me-05-management-user-landing.png)).
- **ADAP** is a separate console ([demo.adauditplus.com](https://demo.adauditplus.com/)): Dashboard · Active Directory · Cloud Directory · File Audit · Server Audit · Endpoint · Analytics · Alerts. Under AD › Auditing alone it has 43 categories and 438 report entries (`knowledge/business/market-research/manageengine-adaudit-plus.md` :406-418).
- **ADSSP** has two deep configuration trees. For example: `Configuration > Administrative Tools > GINA/Mac/Linux (Ctrl+Alt+Del) > GINA/Mac/Linux Installation > Installed Machines` ([evaluator guide](https://download.manageengine.com/products/self-service-password/adselfservice-plus-evaluator-guide.pdf); `knowledge/business/market-research/manageengine-adselfservice-plus.md` :477-481).
- **AD360** is a launcher over separate component UIs: "access the individual components using the applications panel on the left-hand side" (`knowledge/business/market-research/manageengine-ad360-suite-and-commercials.md` :83-105).
- **What admins say:** UI and navigation is the #1 complaint theme (CV :22). Examples:
  - "The program itself is somewhat clunky." ([Capterra, ADMP, 2026-06-29](https://www.capterra.com/p/143496/ADManager-Plus/reviews/))
  - "functions buried in sub-menus" (Capterra critics, ADM :770-776)
  - "It's almost like you need to take a course on how to manoeuvre within it" ([PeerSpot, 2023-05-10](https://www.peerspot.com/products/manageengine-admanager-plus-reviews); CV :151)
  - "For reports, we have to go back to ADAudit, which is not ideal." ([PeerSpot, 2023-07-18](https://www.peerspot.com/products/manageengine-admanager-plus-reviews))
  - "some configuration settings are not always intuitive or easy to find" ([Capterra, ADSSP](https://www.capterra.com/p/172556/ADSelfService-Plus/reviews/))
- **Caveat.** Many 2026 G2 and TrustRadius reviews are vendor-invited (CV :101-103). No review we found complains about search specifically. Other vendors' console IA is not captured in our research `[TODO → T-0001]`.

## 2. IA principles

1. **Find first, then act where the thing is.** Every object is one search away. Every action sits on the object, list or report it changes. There are no action-named menu pages like "Bulk User Modification › Group Attributes".
2. **Nouns in the navigation, verbs on the objects.** The navigation names places (Directory, Reports, Requests). Actions belong to objects and selections, never to the navigation.
3. **One console, one object model.** AD, Entra and M365 objects share lists and pages. Audit, reports and management share the same object pages and links.
4. **Structure follows permission.** What you cannot do is hidden. What you could do elsewhere is explained. What you cannot read does not exist for you (§8.2).
5. **Stable top level.** New capabilities arrive as children of existing sections (§4.4), so the navigation an admin learns in M2 still holds in M5.
6. **Every place has an address.** Every object, tab, filtered list, drawer, report run, job, request and audit entry has a URL (§11).

## 3. Shell and primary navigation

### 3.1 Shell anatomy ([01-home](information-architecture/screens/01-home.png))

| Region | Contents | Rules |
|---|---|---|
| **Top bar** | Product name · global search field (`/`) · **scope chip** (scoped accounts only) · jobs indicator · notifications · help `?` · account menu | Always visible. The search field opens the overlay (§5); it does not search inline |
| **Rail (left)** | The 8 sections. Directory's children are always expanded. A Pinned views group (the user's saved views, with live counts) | Children of other sections show only while that section is active. Collapses to icons at < 1280 px |
| **Content** | Page title, breadcrumbs, page body | One primary action per view |
| **Sheet layer** | At most one side sheet or drawer, from the right, 480–640 px | §6.4 |
| **Shell banner slot** | Install-wide states: "activeDIQ is Tier 0 in this forest" (the TM-D1 override, permanent); connection down; update ready (ENH-07) | One banner at a time, most severe first. It never hides the focused element (WCAG 2.4.11) |

Top-bar details:
- **Jobs indicator:** "⟳ 2 jobs running". It opens a popover with progress and links, plus "All jobs", which goes to Audit › Jobs (P7).
- **Help `?`:** docs for the current page, keyboard shortcuts, what's new, diagnostics bundle.
- **Account menu:** My profile · My activity · Step-up status ("verified, 12 min left") · Preferences (shortcuts on or off, density, theme, time-zone display) · Sign out.

### 3.2 Primary navigation

| # | Section | What lives there | ME equivalent (where it went) | Visible to | First at |
|---|---|---|---|---|---|
| 1 | **Home** | Search, Needs you, quick actions, pinned views, recent items and changes with Undo, directory health (§4.2) | Home dashboard, Help Desk Reset Password Console tile | Everyone | 2a |
| 2 | **Directory** | Users · Groups · Computers · Contacts · Service accounts · Explorer (OU tree) · Deleted objects. 2c adds Devices (Entra) and Licences | Management tab (object actions move onto object pages), AD Explorer, Microsoft 365 tab | Any object read permission | 2a |
| 3 | **Clean up** | Hygiene findings as cards, pending deletion and quarantine, review and approve (§4.3) | Reports › Inactive …, Management › cleanup, Automation (cleanup policies) | `lifecycle.cleanup.*` | 2b |
| 4 | **Reports** | Library by category, favourites, compliance packs, My reports, Schedules. 2c adds Builder (ENH-05) | Reports tab, Governance reports | Any `reports.*` | 2a |
| 5 | **Requests** | To approve · My requests · All requests (workflow inbox). M3/M5 adds access reviews | Workflow tab › Requests | Requesters, approvers, `workflow.admin` | 2d |
| 6 | **Audit** | Directory changes (observed) · activeDIQ activity (who did what through activeDIQ) · Jobs · Secret access (reveals) · Console sign-ins. M3 adds native "who", alerts, lockouts | Admin › audit reports (ADM-137…139); ADAudit Plus from M3 | `audit.read`; everyone else gets *My activity* in the account menu | 2a |
| 7 | **Automation** | Policies (joiner, mover, leaver, cleanup, password-expiry reminders) · Workflows (approval definitions) · Schedules · Templates (creation and modification templates, naming formats, creation rules) · Data sources (HR, CSV drop) | Automation tab, Workflow tab (configuration), Management › templates | Policy, workflow or template permissions | 2b/2d |
| 8 | **Settings** | Delegation · Directories (domains, forests, Entra tenants, DCs, sync) · Security (console sign-in, SSO, MFA, step-up and reveal policy, caller verification, Tier-0 designations, approval thresholds) · Notifications · Integrations (API tokens, ITSM, SIEM) · Migration (import from ME) · System (updates, HA, licence, diagnostics) | Admin tab, Delegation tab, Directory/Application Settings | Any `admin`-kind permission; each child separately | 2a |

The permission names in "Visible to" are **proposed**. The permission catalogue (EP-6, T-0089) fixes them, and §8.5 lists the full mapping.

### 3.3 Rail behaviour

- **Directory stays expanded.** Its seven children are one click from anywhere. T12 needs "Users" in one interaction (BM T12 step 1). The other sections expand only while active, which keeps the rail under 20 rows at 1440×900.
- **Pinned views** come from saved views the user pins. They show a live count and open in one click (BM T13 bulk variant). The counts are API values, scope-trimmed (DM-35.I4).
- The badge on Requests is "waiting for me". No other section carries a count, because a count that never reaches zero is noise.
- **Navigation presentation: a labelled left rail** (D-0012, direction A · Ledger). T-0042 had kept a labelled rail, an icon rail with flyouts and a top bar with a sub-bar open. Any presentation must keep three things true: Directory's children are one interaction away, Clean up is one interaction away, and pinned views are one interaction away. Those three are what the budgets depend on.

### 3.4 No global domain or tenant mode

- Search, lists and reports span every domain and tenant in the account's scope. Domain is a facet and a column, shown only when there is more than one.
- Create flows take the domain from the template or the OU. Changing the OU in the New user sheet re-derives the domain-specific values and shows the diff. It never silently resets fields.
- T-0008's start state assumed one domain. ME adds about 2 interactions per flow in a multi-domain install (BM §1.2). We add none.

### 3.5 Keyboard map

Single keys are active only when focus is not in a text field. All of them can be switched off in Preferences (WCAG 2.1.4). The full list is under `?`.

| Scope | Keys |
|---|---|
| Anywhere | `/` or Ctrl/⌘+K search · `N` new user · `?` shortcuts · `Esc` close the sheet or overlay · `g h` Home · `g u` Users · `g g` Groups · `g c` Computers · `g r` Reports · `g q` Requests · `g a` Audit · `g j` Jobs |
| Object page | `R` reset password (becomes "Reset & unlock" when locked) · `U` unlock · `A` add to group or add members · `M` change role (mover) · `O` offboard · `E` edit attributes · `D` disable or enable · `[` / `]` previous or next tab. **Delete has no key**: it is in the More menu only (P6) |
| Table | `↑↓` move · `Space` select · `Enter` open page · click opens the drawer · `Ctrl+A` all matching (stated in words, §7.1) · `Esc` clear the selection |
| Search overlay | `↑↓` · `Enter` open · `⇧Enter` new tab · `→` actions for the highlighted result · `Tab` cycle type filter · `>` actions-only mode |

### 3.6 Sizes and reflow

- **≥ 1280 px:** full layout.
- **1024–1279 px:** the rail collapses to icons, with accessible names and tooltips.
- **< 1024 px:** the rail moves behind a menu button. Object pages stack.
- Every page reflows at 320 CSS px (WCAG 1.4.10). Data tables may scroll horizontally, which is the WCAG exception.
- End-user surfaces are not part of the console: the v1 TOTP enrolment page, and self-service from M4. They are mobile-first, use plain language and have no AD vocabulary.

## 4. Sitemap

### 4.1 v1 tree (M2), with routes

```
/                                    Home
/search?q=&type=                     full search results (the overlay is `/` or Ctrl+K)
/directory/users | groups | computers | contacts | service-accounts      object lists (§7.1)
/directory/explorer[/{ouGuid}]       OU and container tree + contents (ADM-004)
/directory/deleted                   deleted objects (Recycle Bin and tombstones, §5.6)
/directory/devices | licences        Entra devices, M365 SKUs and seats (2c)
/directory/{kind}/{guid}[/{tab}]     object page (§6); ?drawer={guid} on any list
/directory/users/import              import page: Map → Validate → Run (§7.3)
/clean-up                            findings (§4.3)
/clean-up/{finding}                  e.g. stale-computers, inactive-users
/clean-up/pending                    quarantine and pending deletion
/reports                             library (categories, favourites, compliance packs)
/reports/{reportId}?{params}         a report with results
/reports/mine | schedules | builder  (builder 2c)
/requests?box=to-approve|mine|all    workflow inbox (2d)
/requests/{id}
/audit/changes | activity | jobs | reveals | sign-ins
/audit/jobs/{id} · /audit/changes/{id} · /audit/activity/{seq}
/automation/policies | workflows | schedules | templates | data-sources
/settings/delegation[/technicians|roles|scopes|assignments]   (§8)
/settings/directories | security | notifications | integrations | migration | system
/me · /me/activity · /me/preferences
/go/{identifier}                     resolver: DOMAIN\sam, UPN, e-mail, SID, GUID or DN → object page (§11)
```

### 4.2 Home ([01-home](information-architecture/screens/01-home.png))

Home is "my work", not a dashboard. The ME demo's dashboard took 23.8 s to render (BM §1.5). Ours renders search first and the rest streams in.

| Block | Contents | Notes |
|---|---|---|
| Search field | Large, **focused on load** | So `/` is optional on Home. The budgets still count it (conservative) |
| Needs you | Approvals waiting, pending-deletion reviews, jobs I started that failed or partly failed, connection problems in my scope | Each row deep-links to the place that resolves it. Role-filtered |
| Quick actions | New user (`N`) · Import users from a file · Reset a password… (opens search in action mode) · Clean up | Only actions the role holds (§8.2 rule 1) |
| Pinned views | Saved views with live counts | Help-desk default: "Locked out now" |
| Recent | Objects I opened. Changes I made, with Undo while the window lasts (P5) | |
| Directory health | One line per connection: synced / lagging / DC unreachable | Shown to accounts holding `connections.read` |
| Pinned report widgets | Optional, below the fold (ADM-002 dashboard parity) | A widget renders a ReportDefinition's latest ReportRun (DM, dashboards: `domain-model.md` §9) |

The **first-run** state replaces Needs you with a checklist ([09-states](information-architecture/screens/09-states.png)):
1. connect a domain;
2. confirm Tier-0 additions (TM §6.4 customer-designated);
3. import from ME (lands as proposals, TM-D21);
4. delegate to the help desk.

No sample data is ever shown.

### 4.3 Clean up ([07-cleanup](information-architecture/screens/07-cleanup.png))

- **Cards:** stale computers · inactive users · disabled but still in groups · never signed in · empty groups · passwords that never expire (people). Each card shows the count, the rule in words, its exclusions and its data age.
- **Pending deletion** sits at the top as a banner with "Review & approve" (BM T17 visit 2).
- A card opens `/clean-up/{finding}`. That page is a standard server-side table with the finding's filter applied: Ctrl+A, then "Quarantine" or another plan sheet (BM T17/T18).
- "Repeat monthly" in the plan sheet creates a cleanup policy. The policy lives in Automation › Policies, and its card links to it. There is one home for policies.
- **Why top level:** stale-object cleanup is a monthly to quarterly job, the brief's own benchmark (BM T17, T18), and its budget needs one interaction from anywhere. Inside Directory it would cost one more interaction than T17's budget allows.

### 4.4 Growth map: where M3–M5 land

| Milestone | Capability | Lands in |
|---|---|---|
| M3 change auditing | Native changes with "who" (DC events), lockout source, alerts, ADAP history bridge | Audit › Directory changes gains a "who" column; the object History tab gains actors; Audit › Alerts and Audit › Lockouts; Settings › Directories › Collectors (DC agents) |
| M3 | File servers / NTFS, AD backup | Directory › File servers; Settings › Backup; Directory › Deleted objects gains point-in-time restore |
| M3/M5 | Governance: access reviews | Requests › Reviews (campaign items are requests to keep or revoke) |
| M4 self-service | Admin side: policies, enrolment, coexistence | Settings › Self-service; Reports › Self-service category. The end-user portal is a separate surface, not this navigation |
| M5 | Exchange, GPO, RMP, M365 breadth | Directory › Mailboxes, Directory › Group Policy (read first), Directory › Deleted objects (restore) |
| Later (SaaS/MSP) | Several tenants per operator | A tenant switcher left of the product name. One tenant per self-hosted install (ADR-0002) |

### 4.5 Where ME concepts went

| ME place | activeDIQ place | Search synonym (lands there) |
|---|---|---|
| Help Desk Reset Password Console | Search → user page → `R` (Home is the help-desk console) | "reset password console", "help desk console" |
| Management › User Management (87 links) | Object page actions + Directory lists + bulk bar | each ME action name, e.g. "Create Bulk Users" → import page |
| Bulk User Modification › Group Attributes | Selection → Add to group; group page → Add members | "group attributes" |
| AD Explorer | Directory › Explorer | "AD explorer" |
| Microsoft 365 tab | The same object pages (Cloud tab); Directory › Licences; Settings › Directories | "office 365", "azure active directory" |
| Reports tab (12 categories) | Reports (library, categories kept recognisable) | each ME report name (crosswalk from ENH-02) |
| Delegation tab › Help Desk Delegation | Settings › Delegation | "help desk technicians", "OU-based delegation" |
| Workflow tab | Requests (inbox) + Automation › Workflows | "workflow", "requests" |
| Automation tab | Automation › Policies, Schedules | "automation" |
| Admin tab | Settings | "admin", "personalize" |
| ADAudit Plus · Account Lockout Analyzer | User page lockout panel (data from M3) | "account lockout analyzer" |
| ADAudit Plus · group reports | Group page History tab; Audit › Directory changes | "group change report" |
| Support tab | Help `?` menu | "support" |

The synonym catalogue is search data, owned by T-0066 and extended by ENH-02's report crosswalk.

## 5. Global search and the command palette

([02-search](information-architecture/screens/02-search.png)) One overlay serves both roles. The patterns library has one command palette (PAT § Command palette), and BM P1 has one search. Both entry points open the same thing.

### 5.1 Entry points

- `/` or Ctrl/⌘+K from anywhere, or clicking the top-bar field. Home's own field is focused on load.
- The overlay is a dialog over the page. It counts as 1 screen (BM §1.2).
- The last query is kept for 5 minutes. With an empty query, the overlay shows recent objects, pinned views and suggested actions for the current page.

### 5.2 What it matches

The overlay recognises the identifier's shape. An exact identifier match is pinned at the top as **Exact**, and Enter opens it.

| Input shape | Matches (AD semantics confirmed with ad-expert, 2026-10-02) |
|---|---|
| Free text | displayName, cn, givenName + sn in both orders ("Raman, Priya"), title, department. Prefix match on words |
| `sam`, `DOMAIN\sam`, `sam@dnsdomain` | sAMAccountName (computers with or without the trailing `$`); the down-level and implicit-UPN forms ([user name formats](https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats)) |
| `x@y` | userPrincipalName, mail, proxyAddresses, mailNickname |
| Digits | employeeID, employeeNumber |
| `S-1-5-…` | objectSid, sIDHistory |
| GUID (with or without braces) | objectGUID; Entra object ID; ms-DS-ConsistencyGuid as base64 (hybrid) |
| `CN=…,DC=…` | distinguishedName |
| Host name or FQDN | computer name, dNSHostName, servicePrincipalName |
| 8 hex characters | **BitLocker recovery key ID.** Matched on the `msFVE-RecoveryInformation` child's CN (`<timestamp>{GUID}`), never by a raw-byte prefix on `msFVE-RecoveryGuid`, which is stored in little-endian GUID order ([MS Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj835234(v=ws.11))). Keys escrowed to Entra come from Graph |
| A 48-digit recovery password | **Refused in the browser and never sent:** "That looks like a recovery password. Search by the 8-character key ID instead." A recovery password is a secret (SP §3.7) |
| Words | Report names and their synonyms; page and setting names; ME page names (§4.5); action verbs |

Search runs over the inventory index and is trimmed by RBAC on the server (T-0097; DM-35.I4). It is never a live LDAP query per keystroke. Filters compile on the server; the UI never sends a filter string (PAT § Data table; SP).

### 5.3 Results: anatomy and ranking

- **Groups,** in this order: Exact · Users · Groups · Computers · Contacts · Reports · Pages & settings · Actions. Each group shows up to 5 results with "Show all N" (→ `/search`). The group heading carries the count "in your scope".
- **A result row** has:
  - a type tag;
  - the display name with the match highlighted;
  - a mono secondary identifier (sAMAccountName · UPN or e-mail);
  - **status chips** in text: `Locked 09:12`, `Disabled`, `Password expired`, `Password expires in 3 d`, `Expires 31 Mar`, `Deleted 1 Oct 16:42`, `TIER 0`, `Cloud only`;
  - a disambiguator (title · office or department);
  - the DN in mono, truncated in the middle, with the full value on hover and focus;
  - the domain, when there is more than one.

  Two "Priya Raman"s are always distinguishable without opening either.
- **Ranking:** exact identifier, then the user's recent objects, then prefix match on name, then fuzzy match. Deleted objects rank below live ones. Disabled objects rank below enabled ones within the same match class.

### 5.4 Actions in the overlay

- `→` on a result opens its action list: the object's contextual actions in page order (§6.3) plus Copy DN and Open in new tab. Enter runs the action, which opens the object page with that action's sheet.
- `>` switches to actions-only mode: "> reset password priya" resolves the action, then the object.
- **The visibility rule applies** (§8.2): actions the account never holds are absent; actions blocked for this object appear disabled with the reason; request-mode actions read "Request…". Palette actions arrive at checkpoint 2b (T-0105 scope note).

### 5.5 Accessibility

- The overlay is a `dialog` containing an ARIA 1.2 combobox with a grouped listbox.
- A polite live region announces "12 results, 3 groups" after typing stops.
- Focus returns to the element that opened the overlay when it closes.
- Chips carry text, so meaning never relies on colour (WCAG 1.4.1).
- Matches are highlighted with weight as well as colour.

### 5.6 States ([09-states](information-architecture/screens/09-states.png))

| State | Behaviour |
|---|---|
| No match in scope | "No objects match *kowalski* in your scope (London Help Desk)". Suggests another identifier, Include deleted, and "If you expected a result, your scope may not cover it: ask activeDIQ administrators". Never a blank list |
| Domain unreachable | Banner naming the domain and since when. That domain's results come from the last sync, chipped `as of 09:11`. The other domains are live |
| Stale index | The footer always shows "index as of 1 min ago". Over the lag threshold, the footer turns into a warning with its state text |
| Deleted objects | Included by default with a dashed `Deleted` chip. **Recycle Bin on:** most attributes are kept, so name, UPN and e-mail match. **Recycle Bin off (tombstone):** only the last-known RDN, sAMAccountName, SID, GUID, last parent, userAccountControl and whenCreated survive, plus preserve-on-delete attributes. So a tombstone matches by name and logon name only, and the chip says "limited details" ([MS-ADTS tombstone](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/e2afecb0-4408-4343-878d-86a5ad9d150e)). Listing `CN=Deleted Objects` needs rights the connector identity may lack. If so, the toggle is disabled with that reason |
| Who deleted it | v1 never attributes a native change to a person (DM-18.I3). The chip says when, not who, unless activeDIQ did the delete ("via activeDIQ by J. Ops"). This corrects the BM T15 sample "by svc-hr-sync" (§9.4) |
| Slow | A skeleton appears after 300 ms, and results stream in by group. Target: first results at p95 ≤ 300 ms on the 100k-object tier. This is a design budget for T-0065/T-0097 to confirm (BM §6) |

### 5.7 Full results page

`/search?q=…&type=user` is a standard server-side table (§7.1), with type facets on the left and the same chips as columns. It is the "Show all" target and the page that "Search AD Objects" ME users expect. ME's equivalent is a report with name columns only (BM §1.5, me-04).

### 5.8 Freshness: the lockout chip

Lock state is **computed at read time, never stored**:
- The overlay derives `Locked` from `lockoutTime` plus the effective lockout duration (fine-grained policy, else domain policy). An expired lockout writes nothing to AD, so a stored chip would stay wrong ([lockoutTime](https://learn.microsoft.com/en-us/windows/win32/adschema/a-lockouttime)).
- The **object page re-reads `msDS-User-Account-Control-Computed` (`UF_LOCKOUT`) from the PDC emulator** when it opens. The lock is replicated urgently to the PDC emulator, then to other DCs on their schedule ([attr](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-user-account-control-computed); [lockout overview](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/hh994566(v=ws.10))).
- If the PDC emulator is unreachable, the chip reads "Locked (as of 09:20, PDC emulator unreachable)".
- `lastLogonTimestamp` is always worded "3 Oct, or up to 14 days later", with "exact (all DCs)" available on demand (BM T03).

## 6. Object page anatomy

([03-user](information-architecture/screens/03-user.png), [04-group-tier0](information-architecture/screens/04-group-tier0.png))

### 6.1 Regions, top to bottom

1. **Breadcrumb:** Directory › Users › domain.
2. **Identity header.**
3. **Banner slot:** one banner at a time.
4. **Tabs.**
5. **Tab body.**
6. **Sheet layer:** at most one sheet.

### 6.2 Identity header

- **Display name** (page title), then the object type and its key identifiers in mono: sAMAccountName, UPN or mail, and the DN with Copy. objectGUID and SID sit under "More identifiers".
- **Status chips** in text: Enabled/Disabled, Locked since 09:12, Password expires in N days, Account expires, `TIER 0`, Protected (AdminSDHolder), Synced to Entra / Cloud only / Matched with ⟨Entra object⟩, Deleted.
- **Primary actions** on the right: up to 3 contextual actions (§6.3), then More ▾, which lists everything else the role holds, with its key. Delete is only in More.

### 6.3 Contextual primary actions (state decides the order)

| Object state | Primary actions, in order |
|---|---|
| User, locked | Reset & unlock `R` · Unlock `U` · Add to group `A` |
| User, normal | Reset password `R` · Add to group `A` · Edit `E` |
| User, disabled | Enable `D` · Offboard `O` (if not done) · Edit `E` |
| User, scheduled leaver | View leaver plan · Change date · Cancel offboarding |
| User, deleted | Restore · Copy DN |
| Group | Add members `A` · Edit `E` · Export |
| Computer | Show recovery key · Show local admin password · Move |
| OU | New user here `N` · New group · Delegate… |
| Tier-0 object (any) | Export / Report actions only. Write actions are disabled with the Tier-0 reason (§8.3) |

An action whose state does not apply is hidden, not disabled. Unlock does not appear on an unlocked user (BM T01). That is state, not permission; it keeps the header honest.

### 6.4 The side sheet: no modal stacks

- An action opens **one** sheet from the right. The page stays visible and keeps its scroll position.
- A sheet never opens another sheet or a dialog:
  - pickers are inline type-aheads;
  - the reveal reason is an inline chooser;
  - **step-up MFA is an inline prompt inside the sheet or panel**, with focus moved to the code field. BM still counts it as 1 screen.
- Every change sheet ends with **What will change** (P3): counts, named objects, side effects, Tier-0 objects skipped, and what is not reversible. The confirm button names the verb and the count ("Disable 1,284 computers").
- Typed confirmation is required for more than 100 objects, for delete, and for privileged non-Tier-0 targets (P6).
- `Esc` closes the sheet. Unsaved input prompts once. Focus returns to the control that opened the sheet.
- Larger work leaves the sheet for a page through an explicit link ("Import from a file" → the import page, BM T08). The page has its own URL and its own Back.
- **Drawer vs sheet:** clicking a list row opens a **drawer** (quick view plus the role's actions). An action opens a **sheet**. Both use the same layer, and only one is ever open.

### 6.5 Tabs per object kind (default tab first)

| Kind | Tabs |
|---|---|
| User | **Overview** · Groups (direct / effective) · Devices · Cloud (licences, mailbox; 2c) · Attributes · History · Who can manage |
| Group | **Members** (direct / effective, with the "via" path) · Member of · Attributes · History · Who can manage |
| Computer | **Overview** (OS, last sign-in, `pwdLastSet`, BitLocker and LAPS panels) · Member of · Attributes · History · Who can manage |
| Contact | **Overview** · Member of · Attributes · History |
| Service account (gMSA/sMSA) | **Overview** (principals allowed to retrieve the password, SPNs; never the password) · Member of · Attributes · History · Who can manage |
| OU / container | **Contents** (a table of children) · Attributes · History · Who can manage · Linked GPOs (read-only, later) |
| Deleted object | **Overview** (what is restorable, and from where) · Attributes (retained) · History |

The user **Overview** holds the sections the budgets need without a tab switch:
- Sign-in & password;
- Account, with **Account expires** editable inline (BM T13);
- Organisation (title, department, manager, office);
- **Licences**, with Assign (BM T14);
- Lockout panel when locked (BM T02);
- Recent changes, the last 5 History rows.

The group **Members** tab:
- has a Direct · Effective toggle with both counts (BM T19);
- includes primary-group members and labels well-known SIDs and foreign security principals as such;
- detects circular nesting and shows it;
- marks disabled members "still counts".

It is server-paged for 3,000+ members (ranged `member` retrieval). This guidance is from the ad-expert consult on 2026-10-02 ([range retrieval](https://learn.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval)).

### 6.6 History tab: two streams, one timeline

The History tab merges two streams:
1. **ChangeRecords** observed by sync (DM-18);
2. **AuditEvents** that target this object (DM-80): reveals, operations, approvals.

The v1 wording rules (T-0066 AC3 fixes the exact strings):

| Case | Row reads |
|---|---|
| A change made through activeDIQ | "Title changed · via activeDIQ by `CORP\j.ops` · 1 Oct 10:02 · Undo / Revert" |
| A native change, observed | "Added to SG-Sales-EMEA · observed 28 Sep 14:10 · **who: not recorded** (needs DC event collection, M3)". When replication metadata exists: "originated on `DC02` at 14:07 (DC02's clock)" (DM-18.I2a) |
| Two changes between two observations | "Changed (possibly more than once) between 09:00 and 09:15" (DM-18.I2) |
| A link removal on a big group (BM T16) | "Removed Priya Raman · 1 Oct 22:14 (DC02's clock) · originating DC `DC02` · who: not recorded (M3)". Without our own observation, AD's `msDS-ReplValueMetaData` keeps **only the latest** add or remove per member and is garbage-collected after the tombstone lifetime. So repeated removals are visible only from activeDIQ's own history, which runs from install onward (ad-expert, [msDS-ReplValueMetaData](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-replvaluemetadata)) |
| A secret reveal | "LAPS password shown to `CORP\a.mensah` · reason: Caller on phone · 09:41". It never shows the value (DM-80.I4) |

The tab has a filter box (BM T16 step 5) and a type facet. Every row links to its audit entry.

### 6.7 "Who can manage" tab

This is the reverse view of delegation:
- every role assignment that reaches this object, with its subject, role, the scope entry that matched, and the relevant privileges with their modes;
- the Tier-0 note where it applies;
- the owners and managers of any role-granting group (TM-D18).

The tab is named for its question. "Permissions" reads as the user's own permissions, and "Delegation" collides with Kerberos delegation on computer objects. Native AD ACL analysis is later `[TODO]`.

### 6.8 States

| State | What the page does |
|---|---|
| Loading | The header skeleton shows first, after 300 ms. Tabs load on demand |
| Lockout source, before M3 | "Lockout source needs DC event collection (M3)", with what it needs. Never a blank panel (BM T02) |
| Stale | The banner says "Data from the last sync (09:11): `emea.corp.example.com` unreachable". Write actions are disabled with that reason. The live re-read failed, so a plan would be unsafe |
| Tier 0 | Banner plus disabled write actions (§8.3) |
| Readable, not writable by this account | Banner: "View only: your access does not cover changes here", with who can help (§8.2). Actions are disabled with reasons |
| Not readable / not found | One message for both: "You do not have access to this object", with Back to search and Your access. Not distinguishing the two stops URLs being used to probe the directory. **This deviates from PAT's "distinguish no permission and not found" for object deep links only** `[confirm with security-architect, §14]` |
| Deleted | A Deleted banner with what can be restored (BM T15 preview), or "beyond the deleted-object lifetime" |

## 7. Lists, Explorer, import and jobs

### 7.1 Directory lists ([05-list](information-architecture/screens/05-list.png))

- **Server-side data table** (PAT): cursor paging; "1–50 of 12,431" (≈ when estimated); state in the URL; column chooser; DN, SID and GUID in mono with copy.
- **Header count** in words: "128,904 users · 3 domains" for wide roles, "**4,212 users in your scope**" for scoped ones. Totals are scope-trimmed (DM-35.I4), so a scoped technician never mistakes their total for the directory's.
- **Saved views** sit as tabs above the filter bar. Shipped defaults: Locked out now · Disabled · Password expired · Expiring ≤ 30 d · Inactive > 90 d · Created in the last 7 d · Cloud only. Any view can be pinned to the rail.
- **Selection:**
  - `Ctrl+A` or the header checkbox then the banner selects **all N matching**, and the banner says so in words: "All 300 matching users are selected — not just the 50 on this page" (BM T12).
  - Bulk acts on the query, which the preview re-evaluates.
  - With `max_batch` = 1, checkboxes are not rendered at all, because bulk can never apply (§8.2 rule 1, [06-technician](information-architecture/screens/06-technician.png)).
- **Bulk bar:** the count, then the actions the account may run **on the whole selection**. An action allowed on only part of the selection runs on that part, and the preview lists the rest as "skipped, and why" (Tier 0, outside scope). Nothing is silently dropped.
- Row click opens the drawer; `Enter` opens the page.
- Export runs as a job above 10k rows.

### 7.2 Explorer

`/directory/explorer` (ADM-004) has an OU tree on the left and the selected container's contents on the right, as a standard table. It covers browsing by structure, Tier-0 containers (C6, read-only) and empty or mis-placed OUs. The tree is trimmed to the scope: a scoped technician's tree starts at their scope roots.

### 7.3 Import page (BM T08)

`/directory/users/import` is one page in three states, Map → Validate → Run. It is reached from the New user sheet ("Import from a file") and from the Users list's Import button. A dropped file costs 1 interaction and no screen; the OS picker costs 2 interactions and 1 screen.

The validation result reads "196 ready · 4 need attention". The run result reads "187 of 200 created — 13 failed, here is why", with Fix & retry, Export failures and Undo this batch ([09-states](information-architecture/screens/09-states.png)). It runs as a background job (P7).

### 7.4 Jobs

- **Top-bar indicator:** a popover lists running and recent jobs.
- **Audit › Jobs** keeps the history. Each job page `/audit/jobs/{id}` shows:
  - progress, with Cancel for the pending items;
  - per-object results;
  - Retry failed, Export, and Undo batch where reversible;
  - links to its audit entries.

Jobs are Operations (DM-41): `partially_succeeded` is a designed state, not an error.

## 8. Delegation: how scopes shape what a technician sees

### 8.1 The model in one paragraph (DM-33…36)

A **Permission** is a named capability (`helpdesk.password.reset`, `secret.read:laps`). A **Role** is a set of privileges. Each privilege is a permission plus a mode (`execute` or `request`) plus constraints: attribute allowlist, template allowlist, report categories, `max_batch`, `csv_allowed`. A **DelegationScope** is a set of GUID-rooted entries: naming context, OU subtree or level, group members, Entra tenant, or administrative unit, each include or exclude, with exclusion winning. A **RoleAssignment** gives a subject a role over a scope, optionally time-boxed. The subject is an account, a directory security group, or an automation policy. Authority is the union of assignments, each privilege applying only within its own assignment's scope (DM-36.I3). Tier-0 objects are outside every write scope (DM-35.I5). Only `tenant-owner` is a named built-in role today. The role names below ("Help desk · tier 1", "Directory reader") are **working names**: the E-011 delegation spec fixes the shipped catalogue.

### 8.2 The visibility rule

This rule supersedes the wording in PAT § Permission-aware UI and BM P8 where they differ. T-0043 should fold it into `patterns.md` (§14).

| # | Situation | UI | Example |
|---|---|---|---|
| 1 | The account holds the capability in **no** assignment | **Hidden**: the section, the action, the palette entry, even the checkbox column | A tier-1 technician never sees Settings, Delete or row checkboxes (`max_batch` 1) |
| 2 | Held, but **not over this object** (the object is readable through another assignment) | **Shown disabled with the reason and who can help**. "Who can help" lists up to two group subjects that hold the privilege over this object, otherwise "activeDIQ administrators" `[confirm with security-architect]` | "Reset password — your access covers OU=London Users; this user is in OU=Finance. Ask: Finance-IT-Desk" |
| 3 | Held in **request** mode | **Shown as "Request…"**. It creates a Request bound to the exact plan; an approver signs it off (DM-34.I2, DM-65) | "Add to group → Request…" ([06-technician](information-architecture/screens/06-technician.png)) |
| 4 | The target is **Tier 0** | **Shown disabled with the Tier-0 reason** (§8.3) | "Domain Admins is Tier 0. activeDIQ never changes Tier-0 objects." |
| 5 | Blocked by a **condition**: a constraint (attribute not in the allowlist, batch too large), a DC unreachable, a restricted-management AU (DM-35.I7) | **Shown disabled with that reason**. Plan returns `blocked` with a reason; it never fails at apply | "Your role can change at most 1 object per action" |
| 6 | Needs **step-up** | **Enabled**; the inline step-up prompt appears at the point of action (TM-D16) | Show recovery key |
| 7 | The state makes it meaningless | **Hidden** (state, not permission) | Unlock on an unlocked account |
| 8 | The object is **not readable** through any assignment | **Not shown anywhere**: not in lists, search or counts (DM-35.I4). Empty states name the scope instead | Search "kowalski": "No objects match in your scope (London Help Desk)…" |

Why this split:
- Hiding never-held capabilities keeps a tier-1 console simple, and its rail holds 4 items.
- Explaining held-but-blocked actions answers "why can't I?" before it turns into a ticket. That is BM P8's intent.
- Not showing unreadable objects means search never discloses objects outside the read scope.
- If a team needs to look up callers it cannot change, "read-wide, write-narrow" is granted explicitly (§8.6), and rule 2 then explains the blocked actions.

### 8.3 Tier 0 in the UI

- **Chips and banner.** A `TIER 0` chip on every result, row and header. The page banner reads: "activeDIQ never changes Tier-0 objects, whatever its rights (TM-D2). You can view, report on and export it. Make changes through your Tier-0 admin process. Why?" ([04-group-tier0](information-architecture/screens/04-group-tier0.png)).
- **Pickers.** Tier-0 groups appear in the Add-to-group type-ahead **disabled, with the reason**, so the admin knows why Domain Admins cannot be picked ([09-states](information-architecture/screens/09-states.png)).
- **Bulk.** Tier-0 objects in a selection are listed in the preview as "skipped: Tier 0 (N)".
- **Members of Tier-0 groups are Tier 0** (TM §6.4 C2). A leaver who is in Domain Admins therefore cannot be offboarded by activeDIQ in v1. The leaver plan opens in a blocked state that names the path: "member of Domain Admins via Tier0-Ops-Admins".
- **Designations.** Customer-designated Tier-0 additions live in Settings › Security › Tier 0. Designating one needs step-up and is audited.
- **The TM-D1 override** shows the permanent shell banner "activeDIQ is Tier 0 in this forest" (§3.1).

### 8.4 What a scoped help-desk technician sees ([06-technician](information-architecture/screens/06-technician.png))

The example is a technician with "Help desk · tier 1" over `OU=London Users` (subtree, excluding `OU=Service Accounts`), granted through the group `LON-Helpdesk`.

| Surface | What changes |
|---|---|
| Rail | Home · Directory (Users, Computers) · Reports · Requests. Clean up, Audit, Automation and Settings are absent (rule 1). Groups is absent unless the role reads groups |
| Top bar | A **scope chip**, "Scope: London Help Desk ▾". It opens **Your access**: role × scope entries with DNs in mono, validity dates, the granting group, the Tier-0 note, and whom to ask |
| Home | Search focused; pinned view "Locked out now · 2"; My requests; Recent. No Needs-you rows for things they cannot resolve |
| Search | Only objects their assignments can read. The group headings say "in your scope". Actions per §8.2 |
| Lists | "4,212 users in your scope". No checkboxes (`max_batch` 1). Tier-0 rows inside the scope are chipped, with actions disabled |
| Object page | Reset `R` executes (with caller verification). Add to group reads **Request…**. Delete, Move and Edit are absent (never held) |
| Reports | Only the categories their role allows (DM-34 constraint). Results are trimmed to their scope, and the report header says "Scope: London Help Desk" (DM-72) |
| History | Visible on objects they can read. Their own trail is under My activity |

### 8.5 Section visibility (proposed permission mapping)

| Section | Shown when the account holds any of |
|---|---|
| Home, Help, Account | always |
| Directory | `objects.*.read`, or any `helpdesk.*` |
| Clean up | `lifecycle.cleanup.*` |
| Reports | `reports.run` (filtered by category constraints) |
| Requests | `workflow.request`, approver in any WorkflowDefinition, or has open requests |
| Audit | `audit.read` (others get /me/activity) |
| Automation | `lifecycle.policy.*`, `workflow.define`, `objects.template.*` |
| Settings | any `admin`-kind permission; each child separately (`delegation.*`, `connections.*`, `security.*`, …) |

These names are illustrative until T-0089 publishes the catalogue. The rule is fixed: a section is visible if and only if at least one of its pages would render something actionable or readable.

### 8.6 Delegation setup ([08-delegation](information-architecture/screens/08-delegation.png))

**Settings › Delegation** has these parts:
- **Technicians:** accounts and the groups they sign in through. The technician page shows assignments, an effective-permission summary ("Can reset passwords for 4,212 users in 1 OU; 3 Tier-0 objects there are never writable"), activity and sessions.
- **Roles:** built-in roles are read-only and cloned to change (DM-34.I1). A role page shows its privileges grouped by area, with mode and constraints, its assignments, and **Preview as this role**.
- **Scopes:** each scope page shows its entries (DNs in mono, "follows the OU if it moves", exclusions), its computed reach, the Tier-0 objects inside it, and the `root_deleted` state.
- **Assignments:** a list, plus a **Delegate** wizard with the steps Who → Role → Where → When → **Review**.

The Review step shows:
- the reach counts;
- the privileges with their modes;
- the Tier-0 objects inside the scope (never writable);
- the toggle **"Also let them look up anyone in ⟨domain⟩ (read only)", off by default**. It creates a second assignment of "Directory reader" over the naming context;
- a note that saving re-evaluates the members' sessions (TM: role changes revoke sessions);
- the inline step-up prompt (TM-D16).

No escalation: you can only delegate what you hold over the whole scope (DM-36.I1).

**Preview as role or technician** renders the console read-only as that subject: rail, lists, the state of each action, and reasons. The data shown is the subject's scope ∩ the previewer's own read scope. Nothing can execute. A banner says "Previewing as LON-Helpdesk · read only", and the preview is audited `[confirm with security-architect]`. It answers "what will my help desk see?" before go-live.

**Task-time: delegate reset and unlock over one OU to a help-desk group (D01).** This is not a top-20 task. It is a one-time setup (BM §1.1), costed here because this IA introduces the flow. Counting rules and time model: BM §1.2, §1.3.

| # | ME step ([OU-based delegation help](https://www.manageengine.com/products/ad-manager/help/help-desk-delegation/ou-based-delegation.html)) | I | F | S | Tag |
|---|---|---|---|---|---|
| 1 | Delegation tab | 1 | | 1 | doc |
| 2 | Help Desk Delegation (sub-menu) | 1 | | | doc |
| 3 | Help Desk Technician | 1 | | 1 | doc |
| 4 | Edit technician | 1 | | 1 | doc |
| 5 | "OU-based Delegation"; a pop-up opens | 1 | | 1 | doc |
| 6 | "Switch Now" | 1 | | | doc |
| 7 | Select domain (preselected in one domain) | 0 | | | doc |
| 8 | Tick "Select OUs" | 1 | | | doc |
| 9 | OU picker (BM §1.2 standard) | 4 | | 1 | inferred |
| 10 | Choose the role under "Help Desk Roles" | 2 | | | doc; control inferred |
| 11 | "Save Changes" | 1 | | | doc |
| | **Total** | **14** | **0** | **5** | **T = 24.9 s** |

The ME count assumes the technician already exists. Adding one is `[UNVERIFIED]` (its help page returned 404 on 2026-10-02) and is left out, which favours ME. ME's page warns: "Once you switch to OU-based delegation from the Domain based delegation, you will not be able to revert to Domain-based delegation."

| # | activeDIQ step | I | F | S |
|---|---|---|---|---|
| 1 | Settings (rail; lands on Delegation) | 1 | | 1 |
| 2 | "Delegate" (wizard opens) | 1 | | 1 |
| 3 | Who: type "LON-Helpdesk" | 1 | 1 | |
| 4 | Enter to pick | 1 | | |
| 5 | Role: pick "Help desk · tier 1" | 1 | | |
| 6 | Where: type "London Users" in the OU type-ahead | 1 | 1 | |
| 7 | Enter to pick | 1 | | |
| 8 | Review: step-up code (TM-D16) | 1 | 1 | 1 |
| 9 | "Delegate to LON-Helpdesk" | 1 | | |
| | **Total** | **9** | **3** | **3** |

- **Model:** activeDIQ 21.5 s, which is −14% against ME's 24.9 s. **Target: ≤ 27 s** (⌈1.1 × (21.5 + 3)⌉).
- **Why the step-up is there.** It adds an interaction and a screen on purpose, because RBAC changes are Tier-0-adjacent (TM-D16).
- **The time win is small. The real gains are elsewhere:**
  - one group assignment covers the whole team;
  - the reach and the Tier-0 contents are shown before saving;
  - nothing is irreversible;
  - Preview as role exists.

### 8.7 States

| State | Behaviour |
|---|---|
| Scope root deleted | The entry shows `root_deleted` and grants nothing. Reactivation is an audited operation (DM-35.I1) |
| Assignment expiring | The technician's scope chip shows "until 31 Dec". Home shows "Your access to ⟨scope⟩ ends in 3 days" |
| Escalation attempt | The Delegate wizard disables Review with "You can delegate only privileges you hold over the whole scope (DM-36.I1)" |
| Imported ME roles | They land as proposals, with a banner: "12 roles imported from ADManager Plus — review before activating" (TM-D21) |
| Last tenant-owner | Removing it is disabled with "At least one active tenant-owner is required" (DM-30.I4) |

## 9. Top-20 task paths (AC1)

### 9.1 Paths from Home

- **Budget** is the activeDIQ I/F/S from BM §2, and the interaction count is a hard limit.
- **Target** is ⌈1.1 × (T + 1 s × S)⌉ (BM §1.3).
- **ME** figures are wait-free, from BM §2.
- Path notation: `/` = search overlay · `⏎` = Enter · `→` = next step.

| ID | Task | Path from Home through the IA | IA I/F/S | Budget | Target | ME I/F/S · T |
|---|---|---|---|---|---|---|
| T01 | Reset + unlock for a caller | `/` → name → ⏎ user page (lockout banner) → `R` sheet → Send code → type code → ⏎ | 7/2/3 | 7/2/3 | ≤ 22 s | 8/1/2 · 15.0 s |
| T02 | Lockout source, then unlock | `/` → name → ⏎ (lockout panel) → expand "failed sign-ins" → `U` | 5/1/2 | 5/1/2 | ≤ 15 s | 10/1/5 · 21.7 s |
| T03 | Look up account status | `/` → name (status chips answer it) → ⏎ page | 3/1/2 | 3/1/2 | ≤ 12 s | 8/1/2 · 15.0 s |
| T04 | BitLocker recovery key | `/` → computer name or key ID → ⏎ → Show recovery key → reason → inline step-up | 6/2/3 | 6/2/3 | ≤ 21 s | 7/1/2 · 13.7 s |
| T05 | LAPS password | `/` → computer → ⏎ → Show local admin password → reason → inline step-up | 6/2/3 | 6/2/3 | ≤ 21 s | 5/0/1 · 7.8 s |
| T06 | Add a user to a group | `/` → user → ⏎ → `A` sheet → group type-ahead → ⏎ → Confirm | 7/2/3 | 7/2/3 | ≤ 22 s | 11/2/3 · 22.2 s |
| T07 | Create one joiner | `N` sheet → first name → last name → manager type-ahead → ⏎ → Create | 6/3/1 | 6/3/1 | ≤ 18 s | 13/3/3 · 26.7 s |
| T08 | Bulk-create 200 from CSV | `N` → "Import from a file" (page) → file picker → confirm mapping → "Create 196" | 6/0/3 | 6/0/3 | ≤ 17 s | 12/0/4 · 21.0 s |
| T09 | Offboard a leaver | `/` → name → ⏎ → `O` leaver plan → Confirm | 5/1/3 | 5/1/3 | ≤ 17 s | 17/2/4 · 31.3 s |
| T10 | Mover | `/` → name → ⏎ → `M` sheet → title → department → manager → ⏎ → colleague → ⏎ diff → Confirm | 11/5/3 | 11/5/3 | ≤ 34 s | 36/5/10 · 69.8 s |
| T11 | Add 50 users to a group | `/` → group → ⏎ → `A` Add members → paste → resolve ×2 → Confirm | 8/1/3 | 8/1/3 | ≤ 22 s | 11/1/3 · 20.2 s |
| T12 | One attribute on 300 users | Rail **Users** → filter → ⏎ → `Ctrl+A` (all matching) → Edit attribute → attribute → ⏎ → value → Confirm | 9/3/2 | 9/3/2 | ≤ 25 s | 11/1/3 · 20.2 s |
| T13 | Set or extend expiry | `/` → name → ⏎ → Account expires (inline) → "+90d" → ⏎ | 6/2/2 | 6/2/2 | ≤ 18 s | 13/1/5 · 25.6 s |
| T14 | Assign an M365 licence | `/` → user → ⏎ → Licences › Assign → SKU → Confirm | 6/1/3 | 6/1/3 | ≤ 19 s | 12/1/3 · 21.6 s |
| T15 | Restore a deleted user | `/` → name (Deleted chip) → ⏎ → Restore sheet → Confirm | 5/1/3 | 5/1/3 | ≤ 17 s | 6/1/2 · 12.4 s |
| T16 | Who removed X from Domain Admins | `/` → "domain admins" → ⏎ → History tab → filter by member | 5/2/2 | 5/2/2 | ≤ 17 s | 9/1/2 · 16.3 s |
| T17 | Stale computers, two visits | Rail **Clean up** → Stale computers → `Ctrl+A` → Quarantine → Repeat monthly → type count → Confirm ‖ Clean up → Review & approve → type count → Confirm | 11/2/5 | 11/2/5 | ≤ 33 s | 26/0/8 · 44.6 s |
| T18 | Inactive users, two visits | Rail **Clean up** → Inactive users → expand "probably service accounts" → re-include 1 → `Ctrl+A` → Quarantine → Repeat monthly → count → Confirm ‖ as T17 visit 2 | 13/2/5 | 13/2/5 | ≤ 36 s | 34/0/8 · 55.0 s |
| T19 | Export nested Domain Admins | `/` → "domain admins" → ⏎ (Members tab) → Effective → Export → PDF | 6/1/2 | 6/1/2 | ≤ 16 s | 11/1/3 · 20.2 s |
| T20 | Schedule a monthly report | `/` → "password never expires" → ⏎ report → Schedule sheet → preset → recipient → Save | 7/2/3 | 7/2/3 | ≤ 22 s | 14/2/3 · 26.1 s |
| | **Total** | | **138/36/56** | **138/36/56** | | **274/25/76** |

**Result: 20 of 20 within budget.** Every path uses only elements this document defines, which is the element catalogue in `ia-paths.py`:
- the search overlay (§5);
- the object page, sheets, inline edit, inline reveal and step-up (§6);
- rail items and pinned views (§3.3);
- `Ctrl+A` all-matching and the bulk bar (§7.1);
- Clean up cards (§4.3);
- the import page (§7.3).

The IA adds no step beyond T-0008: no domain selector, no template chooser, no landing page between the rail and the list. The wait-free model total is 323.4 s, the same as BM.

### 9.2 Re-checking

```
cd knowledge/product/design-system/information-architecture && python3 ia-paths.py
```

The script parses the budgets out of BM's `klm.py`. It fails on an unknown IA element, and on any path whose interactions or target time exceed its budget. T-0063 (the Playwright task-time harness) should drive the same element sequences against real screens.

### 9.3 Robustness variants (each stays within the same budget)

| Variant | Effect on the paths |
|---|---|
| Single-key shortcuts off (WCAG 2.1.4) | Each key has a visible button that costs the same: `R` → "Reset & unlock", `N` → Home quick action "New user". T07 and T08 were checked by script (6/3/1, 6/0/3) |
| Scoped help-desk technician | Same paths. The scope only trims results. A request-mode action (T06 as "Request…") ends at submit, with the same count, and approval is a separate actor's task |
| Multi-domain forest | +0 interactions (no domain selector, §3.4). ME is about +2 per flow |
| Inside the step-up window | T04 and T05 drop to 5/1/2 (≤ 15 s), checked as T04w |
| Without caller verification | T01 drops to 5/1/3 (≤ 17 s), checked as T01b |
| Target is Tier 0 | T01, T06, T09, T10 and T16-revert end at a disabled action with the Tier-0 reason, after the same reading steps. The write is refused by design (§8.3), not a missed budget |

### 9.4 Corrections this IA makes to T-0008's state lists

The counts are unchanged. Filed as a follow-up to amend BM (§14).

1. **Tier 0 (TM-D2, DM-35.I5).** activeDIQ v1 never writes a `tier0` object.
   - T06 "protected group: typed confirmation plus approver" becomes: the group is shown disabled in the picker, with the Tier-0 reason.
   - T09 "leaver in privileged groups: typed confirmation, removes Tier-0 access" becomes: the leaver is Tier 0 (C2), so the plan opens blocked with the path.
   - T10 "colleague's privileged groups are flagged" becomes: they are flagged and cannot be copied.
   - T16 "revert (re-add, with P6)" becomes: Revert is disabled with the Tier-0 reason.
   - T01 "privileged account: typed confirmation plus second approver" now applies only to privileged **non**-Tier-0 accounts. A Tier-0 target is refused.
   - P6's "protected and Tier-0 groups" applies to sensitive groups that are not Tier 0.
2. **Native deletes are not attributed (DM-18.I3).** T15's sample chip "Deleted 1 Oct 16:42 by svc-hr-sync" becomes "Deleted 1 Oct 16:42". "By" appears only when activeDIQ did the delete.
3. **The lock chip is computed at read time** (§5.8). It is never stored, because expired lockouts write nothing.
4. **LVR keeps only the latest add or remove per member** (§6.6). T16 before M3 shows when and which DC, never who. Repeats are visible from activeDIQ's own history from install onward.
5. **Keymap:** "Add to group" is `A`, not `G` (§3.5). Counts are unchanged.

## 10. Coverage (AC2): one console

| Area the ticket names | Where it lives | v1 parity rows (feature-parity-matrix.md) |
|---|---|---|
| **Management** | Directory (lists, Explorer, object pages, sheets, import), Home quick actions | ADM-001, -003, -004, -008, -010, -011, -016, -033, -034, -038, -048, -050, -055, -056, -057, -060, -161, -162, -164, -169 |
| **Cleanup** (part of management) | Clean up | ADM-146, -147, -148 |
| **Reports** | Reports (library, compliance packs, schedules, builder 2c); act on results through the same bulk bar | ADM-083…087, -093, -097…-101 |
| **Workflows / automation** | Requests (inbox); Automation (policies, workflows, schedules, templates, data sources) | ADM-012, -013, -015, -017, -018, -039, -041…-045, -047, -104, -105, -107, -116…-118, -120, -121 |
| **Delegation** | Settings › Delegation; scope chip; Who can manage tab; Preview as role; the visibility rule (§8) | ADM-125…-130, -134, -136 |
| **Audit** | Audit (directory changes, activeDIQ activity, jobs, secret access, sign-ins); History tab on every object | ADM-005, -114, -137, -138; ADA rows from M3 |
| **Settings** | Settings (directories, security, notifications, integrations, migration, system) | ADM-142, -143, -145, -159, -188, -189, -191, -192, -198, -204, -205, -209, -210, -212; the no-ID migration and least-privilege requirements |

All seven live in one console, under one search, one object model and one sign-in. ME spreads them across ADMP tabs plus ADAP and ADSSP consoles (§1.2).

## 11. Deep links and URL scheme

| Target | URL | Notes |
|---|---|---|
| Object page | `/directory/{kind}/{objectGuid}` | Keyed by GUID (DM: directory references are GUID-keyed), so it survives renames and moves |
| Object tab | `/directory/{kind}/{guid}/history?member={guid}` | Tab state and tab filters in the query |
| Action sheet | `/directory/{kind}/{guid}?action=reset` | Opens the sheet. **Never executes.** The user still confirms, and the server still plans |
| Drawer over a list | `/directory/users?…&drawer={guid}` | PAT § Side drawer |
| Filtered list or saved view | `/directory/users?q=&f=department:Retail%20Ops&sort=&view={id}` | Filters are structured parameters compiled on the server. Never a raw LDAP filter |
| Resolver | `/go/{identifier}` | For ITSM tickets and e-mails (`/go/CORP%5Cpraman`, `/go/priya.raman@corp.example.com`). Resolves within the reader's scope, then redirects. Ambiguous → the search page. Unreadable → the §6.8 message |
| Report run | `/reports/{id}?{params}` · `/reports/runs/{runId}` | A run link shows its data time and scope |
| Job, request, audit entry | `/audit/jobs/{id}` · `/requests/{id}` · `/audit/activity/{seq}` · `/audit/changes/{id}` | Toasts and results link here (PAT § Audit) |
| Settings | `/settings/{area}/{item}` | Each setting has a URL, and search finds it by name |

## 12. Object model in the UI

| UI object | Domain entity | Listed in | Page | Who sees it |
|---|---|---|---|---|
| User, group, computer, contact, OU, service account | DirectoryObject (DM-16), Link (DM-17) | Directory › … | §6 | By read scope |
| Deleted object | DM-16 (deleted state) | Directory › Deleted; search with a chip | §6.5 | By read scope, if the connector can list deleted objects |
| Entra device, licence SKU | DM-16 (Entra), Correlation (DM-20) | Directory › Devices / Licences (2c) | §6 | Entra scope (DM-35 `entra_tenant`/AU) |
| Change | ChangeRecord (DM-18) | Audit › Directory changes; History tab | `/audit/changes/{id}` | Readers of the object; `audit.read` |
| activeDIQ activity entry | AuditEvent (DM-80) | Audit › activeDIQ activity, Secret access, Sign-ins | `/audit/activity/{seq}` | `audit.read`; own entries in My activity |
| Job / operation | Operation (DM-41), OperationItem (DM-42) | Top-bar jobs; Audit › Jobs | `/audit/jobs/{id}` | Its initiator; `audit.read` |
| Request | Request (DM-65), ApprovalDecision (DM-66) | Requests | `/requests/{id}` | Requester, approvers, `workflow.admin` |
| Report, run, schedule | ReportDefinition (DM-71), ReportRun (DM-72), ReportSchedule (DM-73) | Reports | `/reports/{id}` | Report-category constraint |
| Policy, workflow, schedule, template, naming format | AutomationPolicy (DM-60), WorkflowDefinition (DM-64), Schedule (DM-44), Template (DM-50), NamingFormat (DM-51) | Automation | `/automation/{area}/{id}` | Matching permissions |
| Technician | Account (DM-30) | Settings › Delegation › Technicians | `/settings/delegation/technicians/{id}` | `delegation.read` |
| Role, scope, assignment | Role (DM-34), DelegationScope (DM-35), RoleAssignment (DM-36) | Settings › Delegation | `/settings/delegation/{roles,scopes}/{id}` | `delegation.read` |
| Connection, DC | Connection (DM-10), DomainController (DM-15) | Settings › Directories; Home health | `/settings/directories/{id}` | `connections.read` |
| Saved view | (per-account preference) | View tabs; rail Pinned | the list URL | Its owner (sharing later) |

## 13. Wireframes

All 9 frames are greyscale, brand-neutral and **sample data** ([wireframes.html](information-architecture/wireframes.html)):

| # | Frame | Shows | Screenshot |
|---|---|---|---|
| 1 | Home (admin) | Shell, rail, Needs you (including "187 of 200 created — 13 failed"), quick actions, pinned views, Undo in Recent, directory health | [01-home.png](information-architecture/screens/01-home.png) |
| 2 | Search overlay | Grouped results, status chips, two "Priya Raman"s told apart, deleted result, action panel, footer freshness | [02-search.png](information-architecture/screens/02-search.png) |
| 3 | User page + sheet | Header chips, lockout banner (v1 state, before M3), tabs, Overview, the one sheet with caller verification and What will change | [03-user.png](information-architecture/screens/03-user.png) |
| 4 | Domain Admins | Tier-0 banner, disabled write action, Direct 4 / Effective 11, via paths, FSP from a trusted forest, disabled member still counts | [04-group-tier0.png](information-architecture/screens/04-group-tier0.png) |
| 5 | Users list | 128,904 users, view tabs, filter, "All 300 matching selected", bulk bar, Unicode and 40-character names | [05-list.png](information-architecture/screens/05-list.png) |
| 6 | Scoped technician | 4-item rail, scope chip and Your access, "4,212 users in your scope", no checkboxes, Request…, Tier-0 reason | [06-technician.png](information-architecture/screens/06-technician.png) |
| 7 | Clean up | Pending-deletion banner, finding cards with rules and exclusions | [07-cleanup.png](information-architecture/screens/07-cleanup.png) |
| 8 | Delegate review | Reach, Tier-0 inside the scope, privileges and modes, read-wide toggle off, inline step-up, Preview as | [08-delegation.png](information-architecture/screens/08-delegation.png) |
| 9 | States | Nothing in scope, domain unreachable, unreadable deep link, first run, Tier-0 picker item, job partial failure | [09-states.png](information-architecture/screens/09-states.png) |

## 14. Open items and follow-ups

- **Security-architect** (filed): confirm four things:
  - the "who can help" disclosure in §8.2 rule 2;
  - one message for not-readable and not-found deep links (§6.8);
  - Preview as role (§8.6);
  - the read-wide toggle defaulting to off.
- **T-0043** (note added): fold the §8.2 visibility rule into `patterns.md` § Permission-aware UI. Also remove that file's example of a "Tier-0 operator role", which does not exist in v1 (DM-35.I5, TM-D2).
- **BM amendment** (filed, product-designer): apply §9.4 to T-0008's state lists.
- **T-0042:** navigation presentation may vary across the three directions, within the three reachability constraints in §3.3.
- **T-0066, T-0105, T-0112, T-0113:** take §5 and §6 as their IA. Search's p95 ≤ 300 ms first-results figure is a design budget, to be confirmed by T-0065/T-0097.
- **E-011 delegation spec:** fixes the shipped role catalogue and the permission names used in §8.5.
- `[UNVERIFIED]`: the ME add-technician steps (its help page returned 404); ME's group-based delegation flow.
- `[TODO → T-0001]`: other vendors' console IA (Active Roles, Netwrix Directory Manager, Cayosoft, Adaxes), for the competitive section.

## Changelog

- 2026-10-02 · v1 (T-0009). First IA:
  - sitemap, navigation, search, object page and delegation visibility rule;
  - top-20 path check (20 of 20 within budget, `ia-paths.py`);
  - D01 delegation task-time;
  - 9 greyscale wireframes;
  - AD semantics for search, lockout, tombstones, LVR and membership confirmed by the ad-expert consult on 2026-10-02.

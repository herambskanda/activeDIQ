---
name: design-system
description: Build or review activeDIQ UI — activeDIQ's own tokens (--diq-*, direction A Ledger, D-0012) and brand guidelines, type, 4 px grid, signal-colour discipline, the standard admin patterns (tables, drawers, wizards, impact preview), states, WCAG 2.2 AA, copy. Use for any UI design or code.
---

# Design system — activeDIQ's own (Ledger)

> **activeDIQ is a separate brand (D-0005); its look is Ledger (D-0012).** The source of truth is:
>
> - **Tokens:** `web/src/ds/tokens.css` (prefix `--diq-`; light and dark; fonts are IBM Plex Sans and Mono). With
>   `base.css` (focus ring, mono, sort-header buttons, reduced motion) and `brand.css` (wordmark, ledger rule).
> - **Brand guidelines:** `knowledge/product/design-system/brand-guidelines.md` (logo, palette, signal rules, type,
>   motif, voice, publisher line). The IA is `knowledge/product/design-system/information-architecture.md`.
> - **Taste decisions:** `knowledge/memory/ceo-preferences.md` § Taste wins where it says otherwise.
>
> **Scope.** This skill covers every product-facing surface: console, SSPR pages, docs screenshots,
> product videos, datasheets. The **Factory Board** (internal tooling) and **company documents issued
> by skenzeriq** (proposals, SOWs, SLAs; see the `service-proposal` skill) stay on the skenzeriq brand and
> its own tokens. skenzeriq's design system (`../design-system/`) is a craft reference only: never link
> its `tokens.css`, never use `--sk-*`, its indigo or Geist in activeDIQ.

`patterns.md` in this directory is the pattern library — read the pattern you are building before
you build it.

**Style direction is settled; a change is the CEO's call.** `product-designer` prepares 2–3 options with
real clickable previews (`ceo-decisions` §4) if the CEO reopens it; answers are recorded in
`knowledge/memory/ceo-preferences.md`.

## 1. The four principles, applied

1. **Structure over decoration** — hairlines (`--diq-line`) and the grid separate things; no
   shadows, gradients, illustrations or coloured panels. Ledger is flat: 2 px radii, hairlines.
2. **Monochrome first, one signal** — §3.
3. **Grid discipline** — everything on 4 px (§2).
4. **Say it exactly** — §6. Directory data is exact: DNs, SIDs, GUIDs and counts are never
   abbreviated or rounded silently.

## 2. Tokens — never raw values

- Colour, type, space, radius, motion: **`var(--diq-…)` only.** No hex, `rgb()`, px font sizes,
  or ad-hoc spacing in components. A raw value is a review blocker; propose a token instead (§8).
- Themes: light (warm paper, the base and the shipped default) and dark (warm ink) both come from
  the tokens (`data-theme` on `<html>`, else the OS preference). Both must work, and every
  text/background pair must pass WCAG 2.2 AA in both: add new pairs to `web/src/ds/tokens.test.ts`.
- **Type**: `--diq-font-sans` (IBM Plex Sans) for UI; `--diq-font-mono` (IBM Plex Mono) for directory
  data — DNs, `sAMAccountName`, UPNs, SIDs, GUIDs, attribute names, timestamps, IDs, counts — with
  `font-variant-numeric: tabular-nums` (`.diq-mono`). Scale: table cells, controls, labels
  `--diq-text-ui` / `--diq-text-table` (13); body and form help `--diq-text-body` (14); section
  `--diq-text-section` (16); page title `--diq-text-title` (22); captions `--diq-text-cap` (12); mono
  eyebrows `--diq-text-micro` (11, `--diq-tracking-label`, uppercase). No marketing sizes in the app.
  Weights: 400 body, 500 controls, 600 headings. Prose ≤ 65ch.
- **Space**: `--diq-space-1…10` (4–128 px). Inside controls 8–12; between related fields 16;
  between sections 24–48. Rows 32 (`compact`, default) or 40 (`comfortable`) via `--diq-row` and
  `<html data-density>`. Controls 28 high (`--diq-control`); targets stay ≥ 24×24.
- **Radii**: `--diq-radius-1` and `-2` (2) chips, checkboxes, buttons, inputs, menus, panels;
  `--diq-radius-3` (4) sheets, dialogs, popovers. Only status dots and avatars are round
  (`--diq-radius-round`). Shadows are `none`: a floating layer is separated by a `--diq-line-strong` border.
- **Motion**: `--diq-dur-fast` (120 ms) hover/press; `--diq-dur` (200 ms) sheets, reveals; easing
  `--diq-ease`. No bounce, parallax or looping decoration. Reduced motion: the tokens become 0 ms.
- **Focus**: 2 px `--diq-focus` ring, 2 px offset, on every focusable element; never removed.
- Sortable column headers: the `<button>` in a `<th>` inherits font, `text-transform` and
  `letter-spacing` (`base.css`), or Chrome renders it mixed-case beside uppercase headers.

## 3. Signal-colour discipline

- `--diq-signal` (cobalt) does **one job per view**: the primary action, a link, live state, or the key
  number. One primary button per view or dialog. Never a background wash; `--diq-signal-soft` is
  for the selected row and the current nav item only. Cobalt as text is `--diq-signal-text`;
  the label on a cobalt fill is `--diq-signal-ink`.
- Status colours mean state, nothing else, and are **always paired with text or an icon**
  (WCAG 1.4.1):

| State in activeDIQ | Token | Label |
| --- | --- | --- |
| Operation succeeded; DC/connector healthy | `--diq-ok` | "Succeeded", "Healthy" |
| Locked out; password expired or expiring; stale (inactive > policy); sync lagging; partial bulk failure | `--diq-warn` | the exact state |
| Operation failed; DC unreachable; Tier-0 change alert; replication failure | `--diq-crit` | the exact state |
| Disabled account; unknown; not applicable | `--diq-muted` | "Disabled" |
| Tier 0 | none: text-colour outline and the label "Tier 0" | "Tier 0" |
| Enabled, normal | no colour | — |

## 4. Patterns we standardise

Details, states and rules are in `patterns.md`. Use the pattern; do not invent a variant.

| Need | Pattern |
| --- | --- |
| Any list of directory objects, audit events, report rows | **Server-side data table** — paging, sorting, filtering, saved views, bulk actions, "select all N matching" |
| One object in full | **Object detail page** — identity header, tabs, activity |
| Quick look or small edit without losing the list | **Side drawer** |
| Go anywhere, find anything | **Command palette** (`⌘K` / `Ctrl+K`) and search-first navigation |
| Multi-step operation (create from template, CSV import, migration) | **Wizard** with a review step |
| Any input | **Inline validation**, server-checked for directory rules |
| Destructive, bulk, or Tier-0 change | **Impact preview + confirmation**, dry run first |
| Reversible change | **Undo** (toast + audit-linked revert) |
| Nothing / waiting / failed | **Empty, loading, error states** |
| Who did what | **Audit-trail visibility** on every object and every change |
| Role-limited users | **Permission-aware UI** — no dead buttons |

## 5. Density and accessibility

- Density: compact (32 px rows) by default, with a per-user comfortable toggle (40 px), persisted
  (CEO taste, D-0012: density and restraint win; about 19 rows fit a 1440×900 screen).
- **WCAG 2.2 AA is the floor**: text contrast ≥ 4.5:1 (3:1 for large text and UI boundaries);
  visible focus that is never obscured by sticky headers or drawers (2.4.11); targets ≥ 24×24
  (2.5.8); every drag has a click alternative (2.5.7); help in a consistent place (3.2.6); no
  re-entering data already given in a wizard (3.3.7); end-user sign-in and SSPR never require a
  cognitive test — allow paste and password managers (3.3.8).
- **Keyboard-first**: every action reachable without a mouse; tables navigable with arrows,
  `Space` selects, `Enter` opens; shortcuts listed under `?`. Single-key shortcuts only when
  the table has focus, and can be turned off (2.1.4).
- Screen readers: tables are real `<table>` semantics (or the ARIA grid pattern), live regions
  announce bulk-job progress and results, every icon button has an accessible name.

## 6. Copy

Precise, calm, blameless (brand guidelines §7). Buttons are verbs with their object
and count: "Reset password", "Disable 12 users", never "OK"/"Submit"/"Yes". Confirm in past
tense: "Password reset for j.doe". Errors: what happened, why (if known), what to do next, and a
"Details" disclosure with the DC, LDAP result code and trace ID (`traceId`) — never "Something went
wrong", never blame the admin. Attribute labels: friendly name, with the LDAP name in mono as
secondary text ("Logon name · `sAMAccountName`"). Timestamps: absolute with time zone in audit
and detail views; relative ("4 min ago") only in feeds, with absolute on hover.

## 7. Where components live (ADR-0001, tier W)

React + TypeScript (strict) built by Vite, under `web/` only. The design system lives in
`web/src/ds/` (tokens, base, brand, fonts, and the components built on them; it never imports
`src/modules`, enforced by `make fitness`). Components style themselves with `var(--diq-…)`
and nothing else; each has a story or fixture-backed test covering every state. `tokens.css`
is activeDIQ's own file, edited in place through a ticket, never copied from another repo. Owners: `component-designer` builds components and motion;
`frontend-engineer` composes screens from them; `product-designer` owns flows and direction.

## 8. Proposing a new pattern or token

Only when no pattern in `patterns.md` fits. File a `design` ticket (owner `product-designer`,
review `product-manager`) with: the problem and the screens that need it; how ManageEngine and
one other vendor handle it (sourced, `competitive-intel`); the proposal as an HTML mockup on
`web/src/ds/tokens.css` with every state; a11y notes. The draft lives in
`knowledge/product/design-system/<pattern>.md`. Once accepted, `component-designer` builds it
and adds it to `patterns.md`. A new token is added in `web/src/ds/tokens.css` by `component-designer` through a ticket, with
the contrast test updated in the same change; never added locally in a component.

## 9. Review checklist (UI code and design tickets)

- [ ] No raw colours, sizes or spacing; mono for directory data; tabular numbers.
- [ ] One accent job per view; status colours paired with text.
- [ ] Pattern used as specified; empty, loading, error, no-permission states all present.
- [ ] Destructive or bulk actions go through impact preview; reversible ones offer undo.
- [ ] Every control works against real API data — no fixtures in app code, no dead buttons.
- [ ] Keyboard path complete; focus visible; contrast checked in both themes.

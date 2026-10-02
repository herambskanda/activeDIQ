---
name: design-system
description: Build or review activeDIQ UI on the skenzeriq design system — tokens only, type, 4 px grid, signal-colour discipline, the standard admin patterns (tables, drawers, wizards, impact preview), states, WCAG 2.2 AA, copy. Use for any UI design or code.
---

# Design system — how activeDIQ applies skenzeriq

Source of truth: `../design-system/README.md`, `../design-system/tokens.css` (`--sk-*`), and
`../design-system/brand-guidelines.html` (open it in a browser; §01 principles, §08 voice and
motion). This skill is the activeDIQ application of it. `patterns.md` in this directory is the
pattern library — read the pattern you are building before you build it.

**Style direction is the CEO's call.** `product-designer` prepares 2–3 options with real
clickable previews (`ceo-decisions` §4); the answer is recorded in
`knowledge/memory/ceo-preferences.md`. Until then, **this skill is the default.** Check
`ceo-preferences.md` first; where it says otherwise, it wins.

## 1. The four principles, applied

1. **Structure over decoration** — hairlines (`--sk-line`) and the grid separate things; no
   shadows-as-decoration, gradients, illustrations or coloured panels.
2. **Monochrome first, one signal** — §3.
3. **Grid discipline** — everything on 4 px (§2).
4. **Say it exactly** — §6. Directory data is exact: DNs, SIDs, GUIDs and counts are never
   abbreviated or rounded silently.

## 2. Tokens — never raw values

- Colour, type, space, radius, motion: **`var(--sk-…)` only.** No hex, `rgb()`, px font sizes,
  or ad-hoc spacing in components. A raw value is a review blocker; propose a token instead (§8).
- Themes: light and dark come from the tokens (`data-theme` on `<html>`, else OS). Both must
  work. The brand guide shows product UI on dark; the shipped default is part of the CEO's style
  decision.
- **Type**: `--sk-font-sans` (Geist) for UI; `--sk-font-mono` (Geist Mono) for directory data —
  DNs, `sAMAccountName`, UPNs, SIDs, GUIDs, attribute names, timestamps, IDs, counts — with
  `font-variant-numeric: tabular-nums`. Scale: table cells, controls, labels `--sk-text-sm`
  (13); body and form help `--sk-text-body` (15); page title `--sk-text-h3` (25); section
  `--sk-text-h4` (20); captions `--sk-text-caption` (12); mono eyebrows `--sk-text-micro` (11,
  `--sk-tracking-label`, uppercase). `--sk-text-h1`/`display` are for marketing, not the app.
  Weights: 400 body, 500 controls, 600 headings. Prose ≤ 65ch.
- **Space**: `--sk-space-1…10` (4–128 px). Inside controls 8–12; between related fields 16;
  between sections 32–48. Row heights 40 (comfortable) / 32 (compact). Controls 32 high.
- **Radii**: `--sk-radius-1` (2) badges and checkboxes; `--sk-radius-2` (4) buttons, inputs,
  cards, menus; `--sk-radius-3` (6) dialogs, drawers, popovers. Only status dots are round.
- **Motion**: `--sk-dur-fast` (150 ms) hover/press; `--sk-dur` (220 ms) drawers, dialogs,
  reveals; easing `--sk-ease`. No bounce, parallax or looping decoration (the cursor blink is
  the only loop). Honour `prefers-reduced-motion`: transitions become instant.

## 3. Signal-colour discipline

- `--sk-accent` does **one job per view**: the primary action, a link, live state, or the key
  number. One primary button per view or dialog. Never a background wash; `--sk-accent-soft` is
  for the selected row and the focused nav item only.
- Status colours mean state, nothing else, and are **always paired with text or an icon**
  (WCAG 1.4.1):

| State in activeDIQ | Token | Label |
| --- | --- | --- |
| Operation succeeded; DC/connector healthy | `--sk-ok` | "Succeeded", "Healthy" |
| Locked out; password expired or expiring; stale (inactive > policy); sync lagging; partial bulk failure | `--sk-warn` | the exact state |
| Operation failed; DC unreachable; Tier-0 change alert; replication failure | `--sk-crit` | the exact state |
| Disabled account; unknown; not applicable | `--sk-muted` | "Disabled" |
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

- Density: comfortable (40 px rows) by default with a per-table compact toggle (32 px),
  persisted per user. The final default is a CEO taste call (advisory decision); this is the
  factory default until then.
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

Precise, calm, blameless, lowercase-comfortable (brand §08). Buttons are verbs with their object
and count: "Reset password", "Disable 12 users", never "OK"/"Submit"/"Yes". Confirm in past
tense: "Password reset for j.doe". Errors: what happened, why (if known), what to do next, and a
"Details" disclosure with the DC, LDAP result code and trace ID (`traceId`) — never "Something went
wrong", never blame the admin. Attribute labels: friendly name, with the LDAP name in mono as
secondary text ("Logon name · `sAMAccountName`"). Timestamps: absolute with time zone in audit
and detail views; relative ("4 min ago") only in feeds, with absolute on hover.

## 7. Where components live (provisional until ADR-0001)

House stack assumption: React + TypeScript, Vite, Tailwind (mapped onto `--sk-*` tokens, no
default palette), TanStack Table/Query/Router. Primitives in `web/src/components/ui/`, patterns
in `web/src/components/patterns/` (e.g. `DataTable`, `ImpactPreview`, `ObjectHeader`), each with
a Storybook story showing every state. `tokens.css` is copied from `../design-system/` by a sync
script, never edited in place. Owners: `component-designer` builds components and motion;
`frontend-engineer` composes screens from them; `product-designer` owns flows and direction.

## 8. Proposing a new pattern or token

Only when no pattern in `patterns.md` fits. File a `design` ticket (owner `product-designer`,
review `product-manager`) with: the problem and the screens that need it; how ManageEngine and
one other vendor handle it (sourced, `competitive-intel`); the proposal as an HTML mockup on
`tokens.css` with every state; a11y notes. The draft lives in
`knowledge/product/design-system/<pattern>.md`. Once accepted, `component-designer` builds it
and adds it to `patterns.md`. A new token is requested from the design-system owner, never
added locally.

## 9. Review checklist (UI code and design tickets)

- [ ] No raw colours, sizes or spacing; mono for directory data; tabular numbers.
- [ ] One accent job per view; status colours paired with text.
- [ ] Pattern used as specified; empty, loading, error, no-permission states all present.
- [ ] Destructive or bulk actions go through impact preview; reversible ones offer undo.
- [ ] Every control works against real API data — no fixtures in app code, no dead buttons.
- [ ] Keyboard path complete; focus visible; contrast checked in both themes.

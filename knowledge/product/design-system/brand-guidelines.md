---
title: "activeDIQ brand guidelines (direction A · Ledger)"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: component-designer
ticket: T-0043
decisions: [D-0005, D-0012]
---

# activeDIQ brand guidelines

activeDIQ is a **separate brand** from skenzeriq (D-0005). Its look is **Ledger** (D-0012): the record that auditors trust. It is exact, ruled, flat, dense, and has nothing on screen that is not data. This page is the short rule set. The tokens are the source of truth for every value: [`web/src/ds/tokens.css`](../../../web/src/ds/tokens.css) (prefix `--diq-`). The rendered sample, in both themes, is in [`factory/demos/evidence/T-0043/`](../../../factory/demos/evidence/T-0043/sample.html). The candidate sheet the CEO chose from is [`a-brand.html`](../../../factory/demos/previews/brand-ui/a-brand.html).

**What this covers.** Every product-facing surface: the admin console, the SSPR pages, docs screenshots, product videos, datasheets. **What it does not cover.** The Factory Board (internal tooling) and company documents issued by skenzeriq (proposals, SOWs, SLAs). Those stay on the skenzeriq brand and its own tokens.

## 1. Principles

1. **The data is the interface.** Density and restraint beat distinctiveness. 32 px rows, hairlines, 2 px radii, no shadows, no cards for their own sake.
2. **One signal, one job.** Cobalt marks the primary action, a link, live state or the key number, once per view. It is never a background wash.
3. **Loud means dangerous.** The impact preview and Tier 0 states are the loudest things on screen. If a decoration competes with them, remove the decoration.
4. **Say it exactly.** Directory data (DNs, SIDs, GUIDs, counts) is never abbreviated or rounded silently.

## 2. Logo, wordmark and icon

| Element | Definition | Where |
| --- | --- | --- |
| **Wordmark** | "active" in IBM Plex Sans 600 in the text colour, "DIQ" in IBM Plex Mono 500 in cobalt (`--diq-signal-text`) behind a 2 px cobalt rule. Always set as `activeDIQ`, never `ActiveDIQ`, `Active DIQ` or `ACTIVEDIQ`. | `.diq-wordmark` in [`brand.css`](../../../web/src/ds/brand.css) |
| **Icon** | A single-storey "a" (ring and stem) in white, reversed out of a cobalt square with 4 px radius on a 32 px grid. | [`web/src/ds/brand/icon.svg`](../../../web/src/ds/brand/icon.svg) (512 px master) |
| **Lockup** | Icon, then the wordmark, 8 px apart, vertically centred. The icon is as tall as the wordmark's line height. | Left-rail header, sign-in, installer |

- **Clear space:** the height of the "D" in the wordmark on every side. Nothing else enters it.
- **Minimum size:** wordmark 14 px type size; icon 16 px. Below 16 px use the icon alone with no rule or stroke detail added.
- **Themes:** the wordmark follows the active theme through tokens. The icon is the same in both themes: a cobalt tile with a white mark. Logos are exempt from the 3:1 non-text contrast rule, but never place the icon on a cobalt-adjacent ground.
- **Misuse:** no recolouring (not to skenzeriq's indigo, not to lime), no gradients, shadows or outlines, no stretching, no rotation, no animation, no placing the wordmark in a colour other than the text colour plus cobalt. No lockup with the skenzeriq name.
- The live-type wordmark is for the app. Final outlined art (so it does not depend on an installed font) is a marketing task, not yet made.

## 3. Palette and signal-colour rules

Two themes, both WCAG 2.2 AA. **Light, warm paper, is the base** and the shipped default. **Dark, warm ink,** follows the OS preference and can be forced with `<html data-theme="light|dark">`. Dark was derived from Ledger's own cobalt and warm-neutral palette (D-0012 factory call). It does not use any other direction's lime. Values are in `tokens.css`; the table shows roles.

| Role | Tokens | Use |
| --- | --- | --- |
| Neutrals | `--diq-bg`, `--diq-surface`, `--diq-surface-2`, `--diq-line`, `--diq-line-strong` | Page, tables and sheets, headers and hover, hairlines, control borders (≥ 3:1) |
| Text | `--diq-text`, `--diq-text-2`, `--diq-text-3` | Body, secondary, captions and hints. All pass 4.5:1 on every surface they sit on |
| **Signal** | `--diq-signal` (fill), `--diq-signal-ink` (label on fill), `--diq-signal-text` (link, key number), `--diq-signal-hover`, `--diq-signal-active`, `--diq-signal-soft`, `--diq-focus` | Primary action, link, live state, key number: **one job per view, one primary button per view or dialog.** `--diq-signal-soft` is only the selected row and the current nav item |
| Status | `--diq-ok`, `--diq-warn`, `--diq-crit`, `--diq-muted` with `-bg` fills | State, nothing else |

Status mapping (never colour alone: every status carries a word and a glyph, WCAG 1.4.1):

| State | Token | Glyph and label |
| --- | --- | --- |
| Succeeded; healthy | `--diq-ok` | ✓ "Succeeded", "Healthy" |
| Locked out; expiring; stale; sync lagging; partial failure | `--diq-warn` | △ the exact state |
| Failed; unreachable; replication failure | `--diq-crit` | ✕ the exact state |
| Disabled; unknown; not applicable | `--diq-muted` | – "Disabled" |
| Tier 0 | none: a text-colour outline and the label "Tier 0" | The outline stays when colour is stripped |
| Enabled, normal | no colour | none |

Key contrast results (the full set of 36 pairs is checked in both themes by [`web/src/ds/tokens.test.ts`](../../../web/src/ds/tokens.test.ts) on every `npm test`):

| Pair | Needs | Light | Dark |
| --- | --- | --- | --- |
| Body text on surface | 4.5:1 | 17.40 | 14.67 |
| Muted text on sunken surface (table header) | 4.5:1 | 5.30 | 5.99 |
| Signal text on surface | 4.5:1 | 6.62 | 7.81 |
| Primary button label on signal | 4.5:1 | 6.62 | 4.77 |
| Warning chip | 4.5:1 | 6.12 | 7.88 |
| Control border on page | 3:1 | 3.52 | 4.86 |
| Focus ring on selected row | 3:1 | 5.54 | 6.61 |

Add a pair to the test when a component starts using a new combination. A raw hex, `rgb()` or `hsl()` in a component is a review blocker.

## 4. Type

| Role | Token | Rule |
| --- | --- | --- |
| UI and prose | `--diq-font-sans` (IBM Plex Sans 400, 500, 600) | Weights: 400 body, 500 controls, 600 headings |
| Directory data | `--diq-font-mono` (IBM Plex Mono 400, 500) | DNs, `sAMAccountName`, UPNs, SIDs, GUIDs, attribute names, timestamps, IDs and counts, with tabular figures (`.diq-mono`) |
| Scale | `--diq-text-micro` 11, `-cap` 12, `-ui` and `-table` 13, `-body` 14, `-section` 16, `-title` 22 | Table cells, controls and labels 13; body and form help 14; page title 22; mono eyebrows 11, uppercase, `--diq-tracking-label` |

Prose is at most 65 characters wide. The 4 px grid applies to space, row height and control height (`--diq-space-1…10`, `--diq-row`, `--diq-control`). Fonts are SIL OFL 1.1, embedded as unmodified `.woff2` files in `web/src/ds/fonts/`, each with its licence text. Non-Latin names fall back to the operating system's font. If a customer needs Cyrillic or other scripts set in Plex, adding that subset is a token-level change.

Sortable column headers: the `<button>` inside a `<th>` inherits `font`, `text-transform` and `letter-spacing` from the header ([`base.css`](../../../web/src/ds/base.css)). Without that, Chrome renders sortable headers in mixed case beside uppercase ones.

## 5. Shape, elevation, density, motion

- **Shape:** 2 px radii on chips, controls and panels (`--diq-radius-1`, `-2`); 4 px on sheets and dialogs (`--diq-radius-3`); only status dots and avatars are round. **Flat:** `--diq-shadow-*` are `none`. A floating layer (menu, popover) is separated by a `--diq-line-strong` border, not a shadow.
- **Density:** 32 px rows (`compact`, default) and 40 px (`comfortable`, `<html data-density="comfortable">`). Controls are 28 px high; targets stay at least 24×24 (WCAG 2.5.8).
- **Motion:** `--diq-dur-fast` 120 ms for hover and press, `--diq-dur` 200 ms for sheets and reveals, `--diq-ease`. No bounce, parallax or looping decoration. Under `prefers-reduced-motion` both durations are 0 ms.
- **Focus:** a 2 px `--diq-focus` ring with 2 px offset on every focusable element. Never removed.

## 6. Motif: the ledger rule

A ticked ruler under the top bar (`.diq-ruler`, hairlines only: a long tick every 40 px, a short one every 8 px), plus a 3 px cobalt tick on the current nav item. It is the only decoration. One ruler per screen, on the top bar only. Do not repeat it on cards, dividers or empty states.

## 7. Voice hooks

Precise, calm, blameless, and honest about limits.

- Buttons are verbs with their object and count: "Reset password", "Disable 12 users". Never "OK", "Submit" or "Yes".
- Confirmations are in past tense: "Password reset for j.doe".
- Errors say what happened, why if known, and what to do next, with a "Details" disclosure (DC, LDAP result code, trace ID). Never "Something went wrong", never blame the admin.
- Say plainly when something cannot be undone, and when an action is absent because of Tier 0 protection or the admin's role.
- No exclamation marks, no marketing adjectives in product UI, no "AI-powered" labels.
- Directory attribute labels: friendly name, with the LDAP name in mono as secondary text.

## 8. The publisher line

"skenzeriq" appears **as the legal entity only**: the copyright line, the about and licence screens, the installer and the EULA. Example: "© 2026 skenzeriq. activeDIQ is a product of skenzeriq." It never appears in the lockup, the navigation, the tab title, error text, marketing headlines or the product palette. skenzeriq's indigo, its Geist pairing and its `--sk-*` tokens are not used anywhere in activeDIQ.

## 9. Assets and where they live

| Asset | Path |
| --- | --- |
| Tokens, both themes | `web/src/ds/tokens.css` |
| Base rules (focus, mono, sort-header buttons, reduced motion) | `web/src/ds/base.css` |
| Wordmark and ledger rule | `web/src/ds/brand.css` |
| App icon master | `web/src/ds/brand/icon.svg` |
| Fonts and licence texts | `web/src/ds/fonts/` |
| Contrast gate | `web/src/ds/tokens.test.ts` (`npm test` in `web/`, part of `make ci`) |
| Rendered sample, light and dark | `factory/demos/evidence/T-0043/` |

A new token or a changed value is a `design` or `chore` ticket owned by `component-designer`, with the contrast test updated in the same change. Nothing is copied from `../design-system/`.

## 10. Open items

- Outlined final wordmark art and favicon set (16/32/48 px `.ico`, 180 px touch icon) are not made yet.
- Non-Latin font subsets: only Latin and Latin Extended are embedded.
- The fonts are now vendored in `web/src/ds/fonts/`, so the licence register row for IBM Plex moved from Candidate to Clear (T-0043). The installer must carry the two licence texts when the console ships.

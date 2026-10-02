// Writes ../index.md from the real token values and measurements. Run after build.mjs and shots.mjs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rows, readTokens } from './contrast.mjs';
const here = path.dirname(fileURLToPath(import.meta.url));
const m = JSON.parse(fs.readFileSync(path.join(here, 'measure.json'), 'utf8'));
const R = { a: rows('a'), b: rows('b'), c: rows('c') };
const fail = Object.values(R).flat().filter((r) => !r.pass).length;
if (fail) throw new Error(`${fail} failing contrast pairs`);
const table = R.a.map((r, i) => `| ${r.label} | ${r.min}:1 | ${['a', 'b', 'c'].map((x) => `${R[x][i].fgHex} on ${R[x][i].bgHex} = **${R[x][i].ratio.toFixed(2)}**`).join(' | ')} |`).join('\n');
const tk = { a: readTokens('a'), b: readTokens('b'), c: readTokens('c') };
const md = `---
title: "activeDIQ brand and UI directions: three clickable previews (T-0042)"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: product-designer
---

# Three brand + UI directions for activeDIQ

**Question for the CEO (taste, advisory):** which of three complete identities, each applied to the same two real screens, should activeDIQ's own brand start from? D-0005 made activeDIQ a separate brand; none of these uses skenzeriq's Electric Indigo (#6E5BFF) or the Geist pairing.

Everything here is a **preview with invented sample data** (labelled "Preview — sample data" on every screen). No directory is read or changed. Open the \`.html\` files through the board; each one is self-contained (CSS, fonts and script inline), so they also work from disk.

| | A · Ledger | B · Harbor | C · Night Shift |
| --- | --- | --- | --- |
| Preview | [a.html](a.html) · [brand sheet](a-brand.html) | [b.html](b.html) · [brand sheet](b-brand.html) | [c.html](c.html) · [brand sheet](c-brand.html) |
| Signal colour | Cobalt \`${tk.a.signal}\` | Teal \`${tk.b.signal}\` | Lime \`${tk.c.signal}\` |
| Theme | Light, warm paper | Light, cool grey | Dark-first |
| Type (UI + mono) | IBM Plex Sans + Plex Mono | Source Sans 3 + JetBrains Mono | Atkinson Hyperlegible Next + Mono |
| Navigation | Labelled left rail | Top bar + sub-bar | 56 px icon rail with flyouts, docked side panel |
| Row height (comfortable ↔ alt) | ${m.a.rowHeight} px ↔ 40 px | ${m.b.rowHeight} px ↔ 36 px | ${m.c.rowHeight} px ↔ 36 px |
| Rows visible, list, 1440×900 (measured) | **${m.a.fullyVisible}** | **${m.b.fullyVisible}** | **${m.c.fullyVisible}** |
| Weight | Flat hairlines, 2 px radii | Cards, soft shadows, 8 px radii | Layered dark surfaces, hairlines |
| Motif | The rule (ticked ruler) | The beacon (open ring + dot) | The caret (block cursor) |
| Honest cost | Least distinctive | About half the rows per screen | Needs a light theme later; lime is loud |

## What to click

Each direction has the same preview-states strip at the bottom (that strip is preview-only, not product chrome). Every state is also a link: \`#/users…\`.

| State | What it shows |
| --- | --- |
| List | 12,431 sample users (3 domains; Unicode and 40+-character names; long DNs in the tooltip), saved-view tabs with counts, filter that understands name, logon name, UPN, email and DN, sortable columns, density toggle |
| Selected / All 12,431 | Row checkboxes, the bulk bar, "Select all 12,431 matching users" with the not-just-this-page wording |
| Bulk impact | **ENH-04 impact preview** for "Disable 11,298 users": what changes, what is skipped and why (2 Tier 0 accounts), what is unchanged, how to undo, and a typed confirmation because the count is over 100. Confirming applies it to the sample data and shows an Undo toast |
| User | Object page for a locked-out user: identity header, status chips, lockout banner, contextual actions (Reset & unlock R, Unlock U), Overview / Groups / History tabs |
| Reset: send code → impact, ready | **ENH-04 impact preview** in the reset sheet: generated password, caller verification, then "What will change" ending in one confirm button named for the exact action |
| Done | Result inside the sheet: what changed, who/what/when, and honestly that this change cannot be undone |
| Tier 0 user | Write actions are absent and the reason is stated (IA §8.3) |
| No results | Empty state with a way out |

Keyboard: \`/\` focuses the filter; ↑/↓ move between rows; Space selects; Enter opens the page; clicking a name opens a quick-look drawer; \`R\` and \`U\` on the user page; \`Esc\` closes the sheet or clears the selection. "↺ Restart" resets the sample data.

## Why the same screens, and what they are built on

Both screens follow the T-0009 IA ([information-architecture.md](../../../../knowledge/product/design-system/information-architecture.md)): the 8 sections, Directory expanded with pinned views one interaction away, object page anatomy (§6), the sheet-not-modal rule (§6.4), bulk bar and "all N matching" (§7.1). The three directions differ in the navigation presentation (which §3.3 leaves open), density, weight and identity — **not** in the flows. So the T01 reset-and-unlock path stays 7 interactions / 2 typed fields / 3 screens in every direction ([benchmark T01](../../../../knowledge/product/specs/top-admin-tasks-benchmark.md)), and the preview shows that path end to end.

## Recommendation: A · Ledger

1. **Who buys.** AD admins and help-desk staff at ManageEngine shops live in dense grids. A shows ${m.a.fullyVisible} rows per screen against B's ${m.b.fullyVisible}, and nothing in A needs explaining to someone who has used ADManager Plus.
2. **The T-0008 benchmark.** Several of the tasks in the benchmark are list-heavy ([T10 movers, T11 add 50 users to a group, T12 change an attribute on 300 users](../../../../knowledge/product/specs/top-admin-tasks-benchmark.md), and stale cleanup): they are scanning and selecting many rows. Density and the "all N matching" bulk path decide those task times more than colour does. A and C are close on density; B costs roughly half the rows per screen.
3. **Safety and restraint.** A's flat, hairline weight keeps the impact preview and the Tier 0 states the loudest things on screen, which is the product's argument against ME.

C is the strongest identity and the densest, and it is the right pick if you want activeDIQ to look unmistakably different from ManageEngine on a screenshot; its cost is that a light theme has to be designed before enterprises that mandate one can use it. B is the right pick if occasional users and delegated technicians matter more than 12,000-row lists. **You may mix** — for example A's identity with B's navigation, or C's palette as the dark theme of A. Say so in the answer note and the factory will apply it.

Reversibility: cheap until M2 screens exist. Colour, type, radius and density are tokens (\`--diq-*\`, same names in all three \`tokens-*.css\`), so switching later is a token swap plus screenshot updates; after M2 it is the same swap plus re-checking contrast.

## Contrast (WCAG 2.2 AA) — every text/background pair used

Ratios are computed from the token files by [\`_build/contrast.mjs\`](_build/contrast.mjs) (WCAG 2.x relative-luminance formula, [definition](https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio)). Text pairs need 4.5:1; UI boundaries (control borders, focus rings, button edges) need 3:1. Result: **${Object.values(R).flat().length} of ${Object.values(R).flat().length} pairs pass.** Status is never colour alone: every chip carries a glyph and a word, and Tier 0 uses an outline and a label.

| Pair | Needs | A · Ledger | B · Harbor | C · Night Shift |
| --- | --- | --- | --- | --- |
${table}

## Typefaces and licences

All six families are SIL OFL 1.1, which allows embedding and redistribution with a proprietary product. Rows are in the [licence register](../../../../knowledge/business/licensing/open-source-license-register.md); copyright notes are in [fonts/NOTICE.md](fonts/NOTICE.md). One open point: Source Sans 3's copyright holder line is \`[UNVERIFIED]\` and is checked before B could ship. Non-Latin names in the sample (Cyrillic, Japanese) fall back to the operating system's font in these previews because only Latin and Latin Extended subsets are embedded; the product build would embed the subsets it needs.

## Files

\`a.html\` \`b.html\` \`c.html\` (the three previews) · \`a-brand.html\` \`b-brand.html\` \`c-brand.html\` (one brand sheet each: wordmark, app icon at 16/32/64 and the 512 master, palette, type, motif, shape, UI style) · \`tokens-a.css\` \`tokens-b.css\` \`tokens-c.css\` (candidate tokens) · \`icon-a.svg\` \`icon-b.svg\` \`icon-c.svg\` (512 px masters) · \`screens/\` (PNG of every state, for viewing without the board) · \`fonts/\` · \`_build/\` (sources and generators: \`node _build/build.mjs\`, then \`node _build/shots.mjs\`, then \`node _build/index.mjs\`).

## Notes for the build that follows (not decisions for the CEO)

- The generated passphrase in the reset sheet is drawn as created in the browser and sent only in the request, which matches the write-only-secrets rule (threat model TM-TB1-T7). The IA says the sheet opens with a generated passphrase; whether it is generated in the browser or by the server is for security-architect to confirm in T-0130 \`[UNVERIFIED]\`.
- Wordmarks are live type here; final art is outlined. The one-signal-colour, 4 px grid and admin-pattern rules from the design-system skill hold in all three; token names are \`--diq-*\` so nothing collides with skenzeriq's \`--sk-*\`.
- Each direction is designed in its native theme only. A and B need a dark theme and C a light one before M2 theming is complete; that is token work, not a redesign.
- Preview-only simplifications, identical across directions: the quick-look drawer shows a subset of fields, the global search is represented by the filter (the overlay is specified in IA §5), and controls outside Directory › Users say so in a toast.
`;
fs.writeFileSync(path.join(here, '..', 'index.md'), md);
console.log('index.md written');

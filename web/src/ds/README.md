# `src/ds`: design system

activeDIQ's own design system (a separate brand from skenzeriq, D-0005; direction A "Ledger", D-0012).
Brand rules: [`knowledge/product/design-system/brand-guidelines.md`](../../../knowledge/product/design-system/brand-guidelines.md).
Craft rules and patterns: the `design-system` skill. It never imports `src/modules` (blueprint §2 rule 8,
enforced by `make fitness`).

| File             | What                                                                                                                                                                                          |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tokens.css`     | The `--diq-*` tokens: colour (light base, dark theme), type, 4 px space, shape, density, motion, and the `@font-face` rules. Components use `var(--diq-…)` only                               |
| `tokens.test.ts` | WCAG 2.2 AA gate: 36 text, boundary and focus pairs, in both themes. Add a pair when a component uses a new one                                                                               |
| `base.css`       | Global rules: focus ring, `.diq-mono`, sort-header buttons inherit case, reduced motion                                                                                                       |
| `brand.css`      | `.diq-wordmark` and `.diq-ruler` (the ledger rule)                                                                                                                                            |
| `brand/icon.svg` | The app icon master (512 px)                                                                                                                                                                  |
| `components/`    | `Button`, `TextInput`, `Chip`, `Banner`, `Progress`, `Kbd`, `Table`, `DataGrid`, `Skeleton`, `StatePanel` + `components.css` (T-0685). Usage: `knowledge/product/design-system/components.md` |
| `fonts/`         | IBM Plex Sans and Mono `.woff2`, the two OFL texts and `NOTICE.md`                                                                                                                            |

`src/app/main.tsx` imports `tokens.css`, `base.css` and `brand.css`. Themes: dark follows the OS; force one with
`<html data-theme="light|dark">`. Density: `<html data-density="comfortable">` for 40 px rows (default 32).
Components arrive with their own tickets. `main.tsx` also imports `components/components.css`. Component tests opt in to jsdom with `// @vitest-environment jsdom`.

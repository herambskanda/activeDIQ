# T-0043 evidence: activeDIQ design system (Ledger)

- `sample.html`: a sample Users page rendered from the real `web/src/ds/tokens.css`, `base.css` and `brand.css` (fixture data, evidence only).
- `sample-light.png`, `sample-dark.png`: the same page in both themes (dark via `prefers-color-scheme`, which exercises the OS-preference block). Regenerate: `node tools/playwright/screenshot.mjs file://$PWD/factory/demos/evidence/T-0043/sample.html <out>.png --width 1440 --height 900 [--dark]`.

## Checks run

| Check | Result |
| --- | --- |
| `web/src/ds/tokens.test.ts`: 36 text, boundary and focus pairs in light and dark, same token set in both themes, OS dark block identical to `data-theme` dark block, no indigo or `--sk-` in the file | 80 tests pass (`npm test` in `web/`) |
| `npm run typecheck`, `lint`, `format:check`, `build` in `web/` | pass; the build emits the five Plex font files used by the CSS |
| `make fitness-stack` (F1 to F5) and `make secrets-scan` | pass |
| Keyboard pass (Tab through the sample, both themes, Chromium): focus ring | 2 px solid cobalt `#0A5CB0` (light) and `#7DB4F5` (dark), 2 px offset, on links and buttons |
| Sort-header buttons (carry-over 1) | all three `<th> button`s compute `text-transform: uppercase` and the same letter-spacing as the header |
| `prefers-reduced-motion: reduce` | `--diq-dur-fast` computes to `0ms` |
| Plex Sans loaded from `tokens.css` | `document.fonts.check` true in both themes |

Not run: a screen-reader pass. No interactive component exists yet; this ticket ships tokens, base rules and brand elements. Each component ticket runs axe and a keyboard pass.

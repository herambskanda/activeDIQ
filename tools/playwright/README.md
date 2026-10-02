# tools/playwright — screenshots, E2E and demo recording

Pinned Playwright (`@playwright/test` **1.63.0**, Apache-2.0, exact version + `package-lock.json`).
Dev tooling only: never imported by product code, never shipped. Runbook:
`knowledge/development/runbooks/playwright-tooling.md`.

```bash
npm ci --prefix tools/playwright                 # once; needs Node >= 20
npm --prefix tools/playwright run install-browsers   # once per Playwright version; Chromium goes to the per-user cache, not the repo

node tools/playwright/screenshot.mjs <url> <out.png> [--width 1280 --height 800 --scale 1 --dark --full-page --wait-for <css> --timeout <ms> --allow-http-error]
node tools/playwright/record.mjs <spec.mjs> <out.webm> [--base-url <url> --width 1280 --height 720 --timeout <ms>]
npm --prefix tools/playwright run e2e            # Playwright test runner over web/e2e/
npm --prefix tools/playwright test               # self-test of these scripts (needs Chromium)
```

Or `make playwright-install`, `make playwright-test`.

## Exit codes

`0` ok · `2` bad usage (bad URL/scheme, wrong extension, unknown flag, unloadable spec, Chromium
missing) · `1` runtime failure (HTTP ≥ 400 without `--allow-http-error`, navigation timeout, a spec
that throws). A failing `record` run still keeps the take for debugging but exits `1`.

## Record specs

A spec is an ES module with a default async function; `options` is optional:

```js
export const options = { viewport: { width: 1920, height: 1080 }, colorScheme: 'dark' };
export default async function ({ page, context, baseURL }) {
  await page.goto(baseURL);
  await page.getByRole('button', { name: 'Go' }).click();
}
```

`baseURL` comes from `--base-url`, else `$ADIQ_BASE_URL`, else `options.baseURL`. Output is VP8 WebM.
Demo scripts (beats, cursor overlay, fixed clock) build on this; see `.claude/skills/video-production/`.

## Notes

- Only `http`, `https` and `file` URLs are accepted.
- `e2e` uses `--pass-with-no-tests` until `web/e2e/` has suites (frontend tickets); remove the flag
  then, so an empty suite cannot go green. `retries: 1` is the only retry allowed, every retry is a flake.
- The scripts are plain `.mjs` under `tools/` because Playwright is a Node tool. Node is
  dev-time only here (ADR-0001 tier L/W rules: nothing of this is in a shipped artefact).
- Ignored by git: `node_modules/`, `test-results/`, `playwright-report/`, `ms-playwright/`.

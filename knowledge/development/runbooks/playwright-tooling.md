---
title: "Runbook: Playwright tooling (screenshots, E2E, recording)"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: devops-engineer
ticket: T-0011
---

# Runbook: Playwright tooling

Pinned Playwright in `tools/playwright/` for QA evidence screenshots, design previews, E2E and demo
recording. Reference for flags and the spec format: `tools/playwright/README.md`.

## 1. Set up (once per machine, and after a Playwright version bump)

```bash
npm ci --prefix tools/playwright
npm --prefix tools/playwright run install-browsers    # or: make playwright-install
npm --prefix tools/playwright test                    # or: make playwright-test — all green means the machine is ready
```

Chromium downloads to the per-user cache (`~/Library/Caches/ms-playwright` on macOS,
`~/.cache/ms-playwright` on Linux), or to `$PLAYWRIGHT_BROWSERS_PATH` if set (use that on CI runners
to cache it). **Browsers are never committed**; the self-test fails if any browser file, `.webm`,
`node_modules` or Playwright output becomes tracked.

## 2. Everyday use

- **QA evidence:** `node tools/playwright/screenshot.mjs <url> factory/demos/evidence/<ticket>/<ac#>-<state>.png`
  (add `--dark`, `--width 1920 --height 1080` for the variants the testing-playbook asks for).
- **Demo take:** write a spec (README), then `node tools/playwright/record.mjs <spec.mjs> <out.webm> --base-url <demo-url>`.
  Raw takes belong under `factory/demos/<M>/video/raw/` (gitignored); credentials come from the
  environment, never from the spec.
- **E2E:** suites live in `web/e2e/`; run `npm --prefix tools/playwright run e2e`.

## 3. Upgrading Playwright

1. Check the new version's licence is still Apache-2.0 and update the register row
   (`knowledge/business/licensing/`).
2. `npm install --prefix tools/playwright --save-exact @playwright/test@<version>`, commit `package.json` and the lockfile.
3. `npm run install-browsers` (the browser build is tied to the Playwright version), then run the self-test.

## 4. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Chromium is not installed for this Playwright version` (exit 2) | Run `install-browsers`; the cache may hold only older builds |
| `answered HTTP 404` (exit 1) | The URL is wrong or the app is not up; `--allow-http-error` only to capture an error page on purpose |
| Video text looks smeared | VP8 at modest bitrate; see `.claude/skills/video-production/recording.md` |
| Download blocked on CI | Mirror the browser archive or pre-populate `PLAYWRIGHT_BROWSERS_PATH`; do not vendor it into git |

## 5. Known gaps

- No CI pipeline exists yet (T-0014/T-0015). When it does, add `npm ci` + `npm test` for this tool
  as a job with a cached `PLAYWRIGHT_BROWSERS_PATH`.
- Playwright's bundled ffmpeg (VP8 capture) is a build artefact fetched with the browser; it is not shipped.

# Recording with Playwright

Playwright is pinned in `tools/playwright/` (T-0011). Two ways to record; headless is fine — the
cursor is injected, not the OS cursor:

- **Plain spec** (default): an `.mjs` module with a default `async ({ page, baseURL })` function and
  optional `options` (viewport, colorScheme) — `node tools/playwright/record.mjs <spec.mjs> <out.webm> --base-url <url>`.
  See `tools/playwright/README.md`; the beat/cursor helpers below work unchanged inside it.
- **Playwright test runner**: the skeleton below, run with
  `npx --prefix tools/playwright playwright test -c tools/playwright/playwright.config.mjs <spec>`
  (set `testDir` for your clip); the video lands in `test-results/`.

## Recording script skeleton

```ts
import { test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// Beat durations in ms, measured from the narration audio (ffprobe), written by the edit step.
const beats: Record<string, number> = JSON.parse(
  readFileSync(new URL('../raw/<clip>/beats.json', import.meta.url), 'utf8'));

test.use({
  viewport: { width: 1920, height: 1080 },
  deviceScaleFactor: 1,
  colorScheme: 'dark',                         // the style decision's theme; default dark for product video
  video: { mode: 'on', size: { width: 1920, height: 1080 } },
});

test('<clip>', async ({ page }) => {
  await page.clock.setFixedTime(new Date('2026-10-02T10:30:00Z')); // stable "x min ago" text
  await page.addInitScript(CURSOR_OVERLAY);                         // below
  await page.goto(process.env.ADIQ_DEMO_URL!);                      // demo env URL; creds from the local secret store

  await beat(page, '01', async () => {
    await page.keyboard.press('Meta+K');
    await page.keyboard.type('jane', { delay: 90 });                // human typing speed
    await page.keyboard.press('Enter');
  });
  // … one beat() per script row
});

async function beat(page: Page, id: string, act: () => Promise<void>) {
  const start = Date.now();
  await act();
  const rest = beats[id] - (Date.now() - start);
  if (rest > 0) await page.waitForTimeout(rest);                    // hold until the narration ends
}

// Smooth pointer travel so the injected cursor is followable: use before every click.
export async function glideClick(page: Page, selector: string) {
  const box = (await page.locator(selector).boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 25 });
  await page.waitForTimeout(150);
  await page.mouse.down(); await page.mouse.up();
}
```

The raw video lands in Playwright's `test-results/`; move it to
`factory/demos/<M>/video/raw/<clip>/take-<n>.webm`. Playwright records VP8 at a modest bitrate:
check text legibility at 100 %. If small text smears, record at `deviceScaleFactor: 1` with
larger UI zoom only for the affected beat, never by faking the UI.

## Cursor highlight (inject with `addInitScript`)

```ts
const CURSOR_OVERLAY = `
addEventListener('DOMContentLoaded', () => {
  const dot = document.createElement('div');
  dot.setAttribute('aria-hidden', 'true');
  Object.assign(dot.style, {
    position: 'fixed', zIndex: 2147483647, pointerEvents: 'none',
    width: '22px', height: '22px', margin: '-11px 0 0 -11px', borderRadius: '50%',
    background: 'rgba(10, 92, 176, 0.28)', border: '2px solid #0A5CB0',   /* --diq-signal; raw value OK: recording tool, not product UI */
    transition: 'transform 120ms cubic-bezier(.2,.7,.2,1)', left: '-50px', top: '-50px'
  });
  document.body.appendChild(dot);
  addEventListener('mousemove', e => { dot.style.left = e.clientX + 'px'; dot.style.top = e.clientY + 'px'; }, true);
  addEventListener('mousedown', () => { dot.style.transform = 'scale(0.7)'; }, true);
  addEventListener('mouseup',   () => { dot.style.transform = 'scale(1)'; }, true);
});`;
```

## Title card template (`cards/<clip>-<nn>.html`)

Cards are activeDIQ's own brand (Ledger, D-0005 and D-0012): `web/src/ds/tokens.css` plus
`brand.css`, light warm paper by default, the wordmark and the ledger rule.

```html
<!doctype html>
<html><head>
<link rel="stylesheet" href="../../../../../web/src/ds/tokens.css"><!-- adjust depth: factory/demos/<M>/video/cards/ is 5 levels below the repo root -->
<link rel="stylesheet" href="../../../../../web/src/ds/brand.css">
<style>
  html,body{margin:0;width:1920px;height:1080px;background:var(--diq-bg);color:var(--diq-text);font-family:var(--diq-font-sans)}
  .bar{position:absolute;left:0;right:0;top:0;height:96px;background:var(--diq-surface);border-bottom:1px solid var(--diq-line-strong)}
  .wrap{position:absolute;left:var(--diq-space-9);bottom:var(--diq-space-9);right:var(--diq-space-9)}
  .eyebrow{font:500 22px/1 var(--diq-font-mono);letter-spacing:var(--diq-tracking-label);text-transform:uppercase;color:var(--diq-text-3)}
  h1{font-weight:600;font-size:92px;letter-spacing:var(--diq-tracking-title);margin:var(--diq-space-5) 0 0;max-width:22ch}
  .mark{position:absolute;left:var(--diq-space-9);top:32px;font-size:34px}
</style></head><body>
  <div class="bar diq-ruler"></div>
  <div class="mark"><span class="diq-wordmark"><span class="diq-wordmark-a">active</span><span class="diq-wordmark-b">DIQ</span></span></div>
  <div class="wrap"><div class="eyebrow">[ M1 · USER LIFECYCLE ]</div><h1>Unlock and reset in one step</h1></div>
</body></html>
```

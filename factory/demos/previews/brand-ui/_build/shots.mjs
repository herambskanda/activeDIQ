// Screenshots every state of a/b/c into ../screens/ and reports console errors. Uses tools/playwright's pinned Playwright.
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../../../..');
const { chromium } = await import(pathToFileURL(path.join(root, 'tools/playwright/node_modules/playwright/index.mjs')).href);
const out = path.join(here, '..', 'screens'); fs.mkdirSync(out, { recursive: true });
const STATES = [['01-list', '#/users'], ['02-selected', '#/users?sel=few'], ['03-bulk-impact', '#/users?sel=all&sheet=disable'], ['04-user', '#/users/praghunathan'], ['05-reset-impact', '#/users/praghunathan?sheet=reset&code=typed'], ['06-done', '#/users/praghunathan?sheet=done'], ['07-tier0', '#/users/adm_madeyemi'], ['08-no-results', '#/users?q=zzzz'], ['09-compact', '#/users?compact=1&sel=all']];
const only = process.argv[2];
const measure = {};
const browser = await chromium.launch();
let errs = 0;
for (const x of ['a', 'b', 'c']) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error') { errs++; console.log(x, 'console error:', m.text()); } });
  page.on('pageerror', (e) => { errs++; console.log(x, 'page error:', e.message); });
  for (const [name, hash] of STATES) {
    if (only && !name.includes(only)) continue;
    await page.goto(pathToFileURL(path.join(here, '..', `${x}.html`)).href + hash);
    await page.waitForTimeout(150);
    await page.screenshot({ path: path.join(out, `${x}-${name}.png`) });
    if (name === '01-list') measure[x] = await page.evaluate(() => { const m = document.querySelector('.main').getBoundingClientRect(); const rows = [...document.querySelectorAll('.tbl tbody tr')]; const th = document.querySelector('.tbl th').getBoundingClientRect(); return { rowHeight: rows[0].getBoundingClientRect().height, fullyVisible: rows.filter((r) => { const b = r.getBoundingClientRect(); return b.top >= th.bottom - 1 && b.bottom <= m.bottom; }).length }; });
  }
  await ctx.close();
}
await browser.close();
fs.writeFileSync(path.join(here, 'measure.json'), JSON.stringify(measure, null, 1));
console.log(JSON.stringify(measure));
console.log(errs ? `${errs} errors` : 'no console errors');

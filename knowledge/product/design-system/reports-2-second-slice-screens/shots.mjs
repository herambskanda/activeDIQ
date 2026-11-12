// node shots.mjs — screenshots every state (1440x900) + the live picker key count; fails on console errors.
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const { launch } = await import(pathToFileURL(resolve(here, '../../../../tools/playwright/lib.mjs')));
const url = pathToFileURL(resolve(here, 'preview.html')).href;
const S = { changes: ['default', 'deleted', 'big', 'partial', 'empty', 'error', 'loading'], pso: ['default', 'empty', 'error', 'partial', 'big', 'loading'], repl: ['default', 'partial', 'error', 'empty', 'cap', 'big', 'loading'], picker: ['empty', 'typing', 'ambiguous', 'nomatch', 'done'] };
const DETAIL = { 'changes-default': 3, 'changes-deleted': 2, 'pso-default': 4, 'repl-default': 2, 'repl-partial': 1 };
await mkdir(resolve(here, 'shots'), { recursive: true });
const b = await launch(); const errs = [];
for (const theme of ['light', 'dark']) {
  const ctx = await b.newContext({ viewport: { width: 1440, height: 900 } }); const p = await ctx.newPage();
  p.on('pageerror', (e) => errs.push(String(e))); p.on('console', (m) => m.type() === 'error' && errs.push(m.text()));
  for (const [scr, sts] of Object.entries(S)) for (const st of sts) {
    const row = DETAIL[`${scr}-${st}`]; if (theme === 'dark' && !(st === 'default' || st === 'partial' && scr === 'changes')) continue;
    await p.goto(`${url}#/${scr}?state=${st}${row != null ? '&row=' + row : ''}&theme=${theme}`); await p.reload(); await p.waitForTimeout(150);
    await p.screenshot({ path: resolve(here, `shots/${scr}-${st}${row != null ? '-detail' : ''}${theme === 'dark' ? '-dark' : ''}.png`) });
  }
  await ctx.close();
}
// big states: scroll to prove virtualisation and still a selected detail
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 } }); const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(String(e)));
for (const [scr, st] of [['changes', 'big'], ['pso', 'big'], ['repl', 'big']]) { await p.goto(`${url}#/${scr}?state=${st}`); await p.reload(); await p.evaluate(() => { const g = document.querySelector('.gb'); g.scrollTop = 200000; }); await p.waitForTimeout(100); await p.keyboard.press('ArrowDown'); await p.screenshot({ path: resolve(here, `shots/${scr}-${st}-scrolled.png`) }); console.log(scr, st, 'dom rows', await p.locator('.gr').count()); }
// live picker count
await p.goto(`${url}#/picker?state=live`); await p.reload();
await p.keyboard.press('/'); await p.keyboard.type('manager'); await p.keyboard.press('Enter'); await p.waitForTimeout(200); await p.keyboard.type('ana'); await p.keyboard.press('Enter'); await p.waitForTimeout(150);
console.log('picker keys', await p.locator('body').getAttribute('data-keys'), 'hash', await p.evaluate(() => location.hash));
await p.screenshot({ path: resolve(here, 'shots/picker-live-done.png') });
await b.close(); console.log(errs.length ? 'ERRORS ' + errs.join(' | ') : 'no console errors');

// Tests for the Playwright tooling (T-0011). Needs Chromium: npm run install-browsers.
// Negative cases prove each script fails when it should, not only that it passes.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const html = readFileSync(join(here, 'fixtures/page.html'));
let server, base, tmp;

before(async () => {
  tmp = mkdtempSync(join(tmpdir(), 'pw-tooling-'));
  server = createServer((req, res) => {
    if (req.url === '/missing') { res.writeHead(404).end('nope'); return; }
    res.writeHead(200, { 'content-type': 'text/html' }).end(html);
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server.close(); rmSync(tmp, { recursive: true, force: true }); });

const run = (script, ...args) => new Promise((ok) => {
  execFile(process.execPath, [join(root, script), ...args], { encoding: 'utf8', timeout: 120_000 },
    (err, stdout, stderr) => ok({ status: err ? (err.code ?? 1) : 0, stdout, stderr }));
});

const isPng = (f) => readFileSync(f).subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
const isWebm = (f) => readFileSync(f).subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3])); // EBML header

test('screenshot: produces a PNG of a URL (AC1)', async () => {
  const out = join(tmp, 'nested/shot.png');
  const r = await run('screenshot.mjs', base, out, '--width', '800', '--height', '600');
  assert.equal(r.status, 0, r.stderr);
  assert.ok(statSync(out).size > 1000);
  assert.ok(isPng(out));
});

test('screenshot: honours --dark, --full-page and --wait-for', async () => {
  const out = join(tmp, 'opts.png');
  const r = await run('screenshot.mjs', base, out, '--dark', '--full-page', '--wait-for', '#go');
  assert.equal(r.status, 0, r.stderr);
  assert.ok(isPng(out));
});

test('screenshot: HTTP 404 fails unless --allow-http-error', async () => {
  const out = join(tmp, 'missing.png');
  const bad = await run('screenshot.mjs', `${base}/missing`, out);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /HTTP 404/);
  assert.equal(existsSync(out), false);
  const ok = await run('screenshot.mjs', `${base}/missing`, out, '--allow-http-error');
  assert.equal(ok.status, 0, ok.stderr);
});

test('screenshot: rejects bad input with exit code 2 and no output', async () => {
  for (const args of [
    ['javascript:alert(1)', join(tmp, 'a.png')],
    ['not a url', join(tmp, 'b.png')],
    [base, join(tmp, 'c.jpg')],
    [base],
    [base, join(tmp, 'd.png'), '--bogus'],
    [base, join(tmp, 'e.png'), '--width', '-3'],
  ]) {
    const r = await run('screenshot.mjs', ...args);
    assert.equal(r.status, 2, `${args.join(' ')} -> ${r.stderr}`);
  }
  assert.equal(existsSync(join(tmp, 'a.png')), false);
});

test('screenshot: unreachable host fails with exit code 1', async () => {
  const r = await run('screenshot.mjs', 'http://127.0.0.1:1/', join(tmp, 'down.png'), '--timeout', '3000');
  assert.equal(r.status, 1);
});

test('record: produces a WebM video from a spec (AC2)', async () => {
  const out = join(tmp, 'take/clip.webm');
  const r = await run('record.mjs', join(here, 'fixtures/session.mjs'), out, '--base-url', base);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(statSync(out).size > 1000);
  assert.ok(isWebm(out));
  assert.equal(existsSync(join(tmp, 'take/.record-tmp')), false, 'temp dir cleaned up');
});

test('record: reads baseURL from ADIQ_BASE_URL', async () => {
  const out = join(tmp, 'env.webm');
  const r = await new Promise((ok) => execFile(process.execPath,
    [join(root, 'record.mjs'), join(here, 'fixtures/session.mjs'), out],
    { env: { ...process.env, ADIQ_BASE_URL: base }, encoding: 'utf8', timeout: 120_000 },
    (err, stdout, stderr) => ok({ status: err ? 1 : 0, stderr })));
  assert.equal(r.status, 0, r.stderr);
  assert.ok(isWebm(out));
});

test('record: a failing spec fails the run (exit 1) but keeps the take', async () => {
  const out = join(tmp, 'fail.webm');
  const r = await run('record.mjs', join(here, 'fixtures/failing-session.mjs'), out, '--base-url', base);
  assert.equal(r.status, 1);
  assert.ok(existsSync(out), 'failed take kept for debugging');
});

test('record: bad spec path, missing default export and wrong extension exit 2', async () => {
  const cases = [
    [join(tmp, 'nope.mjs'), join(tmp, 'x.webm')],
    [join(root, 'lib.mjs'), join(tmp, 'y.webm')],
    [join(here, 'fixtures/session.mjs'), join(tmp, 'z.mp4')],
  ];
  for (const args of cases) {
    const r = await run('record.mjs', ...args);
    assert.equal(r.status, 2, `${args.join(' ')} -> ${r.stderr}`);
  }
});

test('no browser binaries or Playwright output are tracked by git (AC3)', () => {
  const repo = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: root, encoding: 'utf8' }).trim();
  const tracked = execFileSync('git', ['ls-files'], { cwd: repo, encoding: 'utf8' }).split('\n').filter(Boolean);
  const banned = /(^|\/)(ms-playwright|node_modules|test-results|playwright-report)\/|\.(webm|zip|dmg|exe)$|chrome-headless-shell|chromium-\d+|headless_shell/i;
  assert.deepEqual(tracked.filter((f) => banned.test(f)), []);
  const ignored = execFileSync('git', ['check-ignore', 'tools/playwright/node_modules/x', 'tools/playwright/test-results/x',
    'tools/playwright/playwright-report/x', 'ms-playwright/x'], { cwd: repo, encoding: 'utf8' }).split('\n').filter(Boolean);
  assert.equal(ignored.length, 4, 'node_modules, test-results, playwright-report and ms-playwright are gitignored');
});

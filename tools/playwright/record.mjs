#!/usr/bin/env node
// record <spec> <out.webm> — run a scripted browser session and keep its video (demo takes, QA evidence).
//
// A spec is an ES module:
//   export const options = { viewport: {width:1920,height:1080}, colorScheme: 'dark', baseURL: '…' }; // optional
//   export default async function ({ page, context, baseURL }) { await page.goto(baseURL); … }
// baseURL comes from --base-url, else the ADIQ_BASE_URL environment variable, else options.baseURL.
import { mkdir, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { launch, parseArgs, parseUrl, run, UsageError } from './lib.mjs';

const USAGE = `usage: node tools/playwright/record.mjs <spec.mjs> <out.webm> [options]
  --base-url <url>    passed to the spec as baseURL (default: $ADIQ_BASE_URL)
  --width <px>        video/viewport width  (default 1280)
  --height <px>       video/viewport height (default 720)
  --timeout <ms>      default action timeout (default 30000)`;

await run(async () => {
  const { positional, flags } = parseArgs(process.argv.slice(2), {
    'base-url': 'string', width: 'number', height: 'number', timeout: 'number',
  });
  if (positional.length !== 2) throw new UsageError(`expected <spec> <out.webm>\n${USAGE}`);
  const specPath = resolve(positional[0]);
  const out = resolve(positional[1]);
  if (!out.toLowerCase().endsWith('.webm')) throw new UsageError(`output must end in .webm: ${positional[1]}`);

  const mod = await import(pathToFileURL(specPath).href).catch((err) => {
    throw new UsageError(`cannot load spec ${positional[0]}: ${err.message}`);
  });
  if (typeof mod.default !== 'function') throw new UsageError(`spec ${positional[0]} must export a default async function`);
  const options = mod.options ?? {};

  const baseRaw = flags['base-url'] ?? process.env.ADIQ_BASE_URL ?? options.baseURL;
  const baseURL = baseRaw ? parseUrl(baseRaw) : undefined;
  const viewport = options.viewport ?? { width: flags.width ?? 1280, height: flags.height ?? 720 };

  const browser = await launch();
  let page;
  let failure;
  try {
    const context = await browser.newContext({
      viewport,
      colorScheme: options.colorScheme ?? 'light',
      recordVideo: { dir: resolve(dirname(out), '.record-tmp'), size: viewport },
    });
    context.setDefaultTimeout(flags.timeout ?? 30_000);
    page = await context.newPage();
    try {
      await mod.default({ page, context, baseURL });
    } catch (err) {
      failure = err;
    }
    await page.close(); // finalises the video file
    await mkdir(dirname(out), { recursive: true });
    await page.video().saveAs(out);
    await context.close();
  } finally {
    await browser.close();
    await rm(resolve(dirname(out), '.record-tmp'), { recursive: true, force: true });
  }
  if (failure) throw failure; // the take is kept for debugging, but the run still fails
  console.log(out);
});

#!/usr/bin/env node
// screenshot <url> <out.png> — headless Chromium screenshot of a URL (QA evidence, design previews).
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { launch, parseArgs, parseUrl, run, UsageError } from './lib.mjs';

const USAGE = `usage: node tools/playwright/screenshot.mjs <url> <out.png> [options]
  --width <px>        viewport width   (default 1280)
  --height <px>       viewport height  (default 800)
  --scale <n>         device scale factor (default 1)
  --dark              emulate prefers-color-scheme: dark
  --full-page         capture the whole scrollable page
  --wait-for <sel>    wait for a CSS selector before capturing
  --timeout <ms>      navigation / wait timeout (default 30000)
  --allow-http-error  do not fail when the page answers with HTTP >= 400`;

await run(async () => {
  const { positional, flags } = parseArgs(process.argv.slice(2), {
    width: 'number', height: 'number', scale: 'number', dark: 'boolean',
    'full-page': 'boolean', 'wait-for': 'string', timeout: 'number', 'allow-http-error': 'boolean',
  });
  if (positional.length !== 2) throw new UsageError(`expected <url> <out.png>\n${USAGE}`);
  const url = parseUrl(positional[0]);
  const out = resolve(positional[1]);
  if (!out.toLowerCase().endsWith('.png')) throw new UsageError(`output must end in .png: ${positional[1]}`);
  const timeout = flags.timeout ?? 30_000;

  const browser = await launch();
  try {
    const context = await browser.newContext({
      viewport: { width: flags.width ?? 1280, height: flags.height ?? 800 },
      deviceScaleFactor: flags.scale ?? 1,
      colorScheme: flags.dark ? 'dark' : 'light',
    });
    const page = await context.newPage();
    const response = await page.goto(url, { waitUntil: 'load', timeout });
    if (response && response.status() >= 400 && !flags['allow-http-error']) {
      throw new Error(`${url} answered HTTP ${response.status()} (use --allow-http-error to capture it anyway)`);
    }
    if (flags['wait-for']) await page.waitForSelector(flags['wait-for'], { timeout });
    await mkdir(dirname(out), { recursive: true });
    await page.screenshot({ path: out, fullPage: flags['full-page'] ?? false });
    console.log(out);
  } finally {
    await browser.close();
  }
});

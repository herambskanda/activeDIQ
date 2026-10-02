// Shared helpers for the Playwright tooling scripts (T-0011). Dev tooling only; never shipped.
import { chromium } from '@playwright/test';

export class UsageError extends Error {}

// Only http(s) and file URLs: a screenshot tool has no business with javascript:, data: or chrome: URLs.
export function parseUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new UsageError(`not a valid absolute URL: ${raw}`);
  }
  if (!['http:', 'https:', 'file:'].includes(url.protocol)) {
    throw new UsageError(`unsupported URL scheme ${url.protocol} (use http, https or file)`);
  }
  return url.href;
}

// Minimal flag parser: `--name value`, `--name=value` and bare `--flag`; everything else is positional.
// `spec` maps flag name -> 'string' | 'number' | 'boolean'. Unknown flags are an error, not ignored.
export function parseArgs(argv, spec) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const [name, inline] = arg.slice(2).split(/=(.*)/s);
    const type = spec[name];
    if (!type) throw new UsageError(`unknown option --${name}`);
    if (type === 'boolean') {
      flags[name] = inline === undefined ? true : inline !== 'false';
      continue;
    }
    const value = inline ?? argv[++i];
    if (value === undefined) throw new UsageError(`--${name} needs a value`);
    if (type === 'number') {
      const n = Number(value);
      if (!Number.isFinite(n) || n <= 0) throw new UsageError(`--${name} must be a positive number, got ${value}`);
      flags[name] = n;
    } else {
      flags[name] = value;
    }
  }
  return { positional, flags };
}

export async function launch() {
  try {
    return await chromium.launch({ headless: true });
  } catch (err) {
    if (/Executable doesn't exist/.test(String(err))) {
      throw new UsageError(
        'Chromium is not installed for this Playwright version. Run: npm --prefix tools/playwright run install-browsers',
      );
    }
    throw err;
  }
}

// Run `main`, turning UsageError into exit code 2 and any other failure into exit code 1.
export async function run(main) {
  try {
    await main();
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(`error: ${err.message}`);
      process.exitCode = 2;
    } else {
      console.error(`error: ${err?.stack ?? err}`);
      process.exitCode = 1;
    }
  }
}

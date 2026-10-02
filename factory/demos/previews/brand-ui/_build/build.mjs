// Builds a/b/c.html (+ brand sheets, svg icons, contrast table, index.md) from the shared sources in this folder.
// Run: node factory/demos/previews/brand-ui/_build/build.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rows, readTokens } from './contrast.mjs';
import { brandSheet, COPY } from './brandsheet.mjs';
const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, '..');
const rd = (f) => fs.readFileSync(path.join(here, f), 'utf8');

export const DIRS = {
  a: { name: 'Ledger', tag: 'Dense, labelled, flat', font: 'IBM Plex Sans + IBM Plex Mono', uiFont: 'IBM Plex Sans', monoFont: 'IBM Plex Mono' },
  b: { name: 'Harbor', tag: 'Comfortable, top-bar, soft', font: 'Source Sans 3 + JetBrains Mono', uiFont: 'Source Sans 3', monoFont: 'JetBrains Mono' },
  c: { name: 'Night Shift', tag: 'Dark, icon rail, ultra-dense', font: 'Atkinson Hyperlegible Next + Atkinson Hyperlegible Mono', uiFont: 'Atkinson Hyperlegible Next', monoFont: 'Atkinson Hyperlegible Mono' },
};
// App icons, 32-unit grid. Colours come from the tokens in the page; the standalone .svg files use the hex values.
const iconSvg = (x, fill, ink, size) => ({
  a: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="${size}" height="${size}" role="img" aria-label="activeDIQ"><rect width="32" height="32" rx="4" fill="${fill}"/><circle cx="14" cy="16.5" r="5.5" fill="none" stroke="${ink}" stroke-width="3"/><path d="M19.5 9v14" stroke="${ink}" stroke-width="3"/></svg>`,
  b: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="${size}" height="${size}" role="img" aria-label="activeDIQ"><rect width="32" height="32" rx="9" fill="${fill}"/><path d="M16 7.5A8.5 8.5 0 1 0 24.5 16" fill="none" stroke="${ink}" stroke-width="3" stroke-linecap="round"/><circle cx="16" cy="16" r="3" fill="${ink}"/></svg>`,
  c: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="${size}" height="${size}" role="img" aria-label="activeDIQ"><rect width="32" height="32" rx="2" fill="${fill}"/><path d="M8.5 9.5l7 6.5-7 6.5" fill="none" stroke="${ink}" stroke-width="3.2" stroke-linecap="square"/><path d="M18.5 23h6" stroke="${ink}" stroke-width="3.2" stroke-linecap="square"/></svg>`,
}[x]);
const iconTokens = (x, size) => iconSvg(x, 'var(--diq-signal)', 'var(--diq-signal-ink)', size).replace(/ xmlns="[^"]+"/, '');

function inlineFonts(css) {
  return css.replace(/url\(fonts\/([^)]+\.woff2)\)/g, (_, f) => `url(data:font/woff2;base64,${fs.readFileSync(path.join(out, 'fonts', f)).toString('base64')})`);
}
const read = (f) => fs.readFileSync(path.join(out, f), 'utf8');

for (const x of Object.keys(DIRS)) {
  const t = readTokens(x);
  fs.writeFileSync(path.join(out, `icon-${x}.svg`), iconSvg(x, t.signal, t['signal-ink'], 512) + '\n');
  const tokens = inlineFonts(read(`tokens-${x}.css`));
  const css = `${tokens}\n${rd('base.css')}\n${rd(`ui-${x}.css`)}\n${rd(`wordmark-${x}.css`)}`;
  const js = `window.APP_ICON=${JSON.stringify(iconTokens(x, '{PX}'))};\n${rd('data.js')}\n${rd('app.js')}`;
  const html = `<!doctype html>
<html lang="en" data-theme="${x === 'c' ? 'dark' : 'light'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>activeDIQ preview ${x.toUpperCase()} — ${DIRS[x].name}</title>
<link rel="icon" href="data:image/svg+xml,${encodeURIComponent(iconSvg(x, t.signal, t['signal-ink'], 32))}">
<style>${css}</style>
</head>
<body data-dir="${x}">
<script>${js}</script>
</body>
</html>
`;
  fs.writeFileSync(path.join(out, `${x}.html`), html);
}
const wm = (x) => ({ a: '<span class="wm wm-a"><span class="wm-1">active</span><span class="wm-2">DIQ</span></span>', b: '<span class="wm wm-b"><span class="wm-1">active</span><span class="wm-2">DIQ</span></span>', c: '<span class="wm wm-c"><span class="wm-1">active</span><span class="wm-2">DIQ</span></span>' }[x]);
for (const x of Object.keys(DIRS)) fs.writeFileSync(path.join(out, `${x}-brand.html`), brandSheet(x, iconTokens, inlineFonts, wm));
console.log('built a/b/c.html and brand sheets');

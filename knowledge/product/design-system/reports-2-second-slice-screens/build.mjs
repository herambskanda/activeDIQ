// node build.mjs → preview.html (self-contained: tokens, fonts base64, CSS, JS inlined)
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const ds = resolve(here, '../../../../web/src/ds');
let tokens = readFileSync(resolve(ds, 'tokens.css'), 'utf8').replace(/@font-face\s*\{[^}]*\}/g, '');
const faces = [['Plex Sans', 400, 'ibm-plex-sans-latin-400-normal'], ['Plex Sans', 500, 'ibm-plex-sans-latin-500-normal'], ['Plex Sans', 600, 'ibm-plex-sans-latin-600-normal'], ['Plex Mono', 400, 'ibm-plex-mono-latin-400-normal'], ['Plex Mono', 500, 'ibm-plex-mono-latin-500-normal'],
  ['Plex Sans', 400, 'ibm-plex-sans-latin-ext-400-normal'], ['Plex Sans', 500, 'ibm-plex-sans-latin-ext-500-normal'], ['Plex Sans', 600, 'ibm-plex-sans-latin-ext-600-normal']];
const ff = faces.map(([f, w, n]) => `@font-face{font-family:"${f}";font-weight:${w};font-display:swap;src:url(data:font/woff2;base64,${readFileSync(resolve(ds, 'fonts', n + '.woff2')).toString('base64')}) format("woff2")}`).join('\n');
const css = readFileSync(resolve(here, 'src/app.css'), 'utf8'), js = readFileSync(resolve(here, 'src/app.js'), 'utf8');
writeFileSync(resolve(here, 'preview.html'), `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>T-1123 preview — sample data</title><style>${ff}\n${tokens}\n${css}</style></head><body></body><script>${js}</script></html>`);
console.log('built preview.html');

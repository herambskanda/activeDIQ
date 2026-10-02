// WCAG 2.x contrast for the candidate token pairs. Reads ../tokens-<x>.css; exports rows for the brand sheets and index.md.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
export function readTokens(x) {
  const css = fs.readFileSync(path.join(here, '..', `tokens-${x}.css`), 'utf8');
  const t = {};
  for (const m of css.matchAll(/--diq-([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6})\b/g)) t[m[1]] = m[2].toUpperCase();
  return t;
}
const lin = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
const lum = (h) => { const n = parseInt(h.slice(1), 16); return 0.2126 * lin(n >> 16) + 0.7152 * lin((n >> 8) & 255) + 0.0722 * lin(n & 255); };
export const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
// [label, fg token, bg token, minimum, kind]
export const PAIRS = [
  ['Body text on page', 'text', 'bg', 4.5, 'text'],
  ['Body text on surface (table, sheet)', 'text', 'surface', 4.5, 'text'],
  ['Secondary text on surface', 'text-2', 'surface', 4.5, 'text'],
  ['Secondary text on page', 'text-2', 'bg', 4.5, 'text'],
  ['Muted text (captions, hints) on surface', 'text-3', 'surface', 4.5, 'text'],
  ['Muted text on page', 'text-3', 'bg', 4.5, 'text'],
  ['Muted text on sunken surface', 'text-3', 'surface-2', 4.5, 'text'],
  ['Body text on selected row', 'text', 'signal-soft', 4.5, 'text'],
  ['Muted text on selected row', 'text-3', 'signal-soft', 4.5, 'text'],
  ['Signal as link / key number on surface', 'signal-text', 'surface', 4.5, 'text'],
  ['Signal as link on page', 'signal-text', 'bg', 4.5, 'text'],
  ['Signal as text on selected row', 'signal-text', 'signal-soft', 4.5, 'text'],
  ['Primary button label on signal', 'signal-ink', 'signal', 4.5, 'text'],
  ['Primary button hover: label on hover fill', 'signal-ink', 'signal-hover', 4.5, 'text'],
  ['Status OK chip', 'ok', 'ok-bg', 4.5, 'text'],
  ['Status warning chip', 'warn', 'warn-bg', 4.5, 'text'],
  ['Status critical chip', 'crit', 'crit-bg', 4.5, 'text'],
  ['Status disabled/neutral chip', 'muted', 'muted-bg', 4.5, 'text'],
  ['OK text on surface', 'ok', 'surface', 4.5, 'text'],
  ['Warning text on surface', 'warn', 'surface', 4.5, 'text'],
  ['Critical text on surface', 'crit', 'surface', 4.5, 'text'],
  ['Body text on warning banner', 'text', 'warn-bg', 4.5, 'text'],
  ['Body text on success banner', 'text', 'ok-bg', 4.5, 'text'],
  ['Input and control border on surface (UI boundary)', 'line-strong', 'surface', 3, 'ui'],
  ['Input and control border on page (UI boundary)', 'line-strong', 'bg', 3, 'ui'],
  ['Focus ring on surface (UI, 2.4.11 / 1.4.11)', 'focus', 'surface', 3, 'ui'],
  ['Focus ring on page', 'focus', 'bg', 3, 'ui'],
  ['Focus ring on selected row', 'focus', 'signal-soft', 3, 'ui'],
  ['Signal fill against surface (button boundary)', 'signal', 'surface', 3, 'ui'],
];
export function rows(x) {
  const t = readTokens(x);
  return PAIRS.map(([label, fg, bg, min, kind]) => {
    if (!t[fg] || !t[bg]) throw new Error(`direction ${x}: token missing for "${label}" (${fg}/${bg})`);
    const r = ratio(t[fg], t[bg]);
    return { label, fg, bg, fgHex: t[fg], bgHex: t[bg], min, kind, ratio: r, pass: r >= min };
  });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let bad = 0;
  for (const x of ['a', 'b', 'c']) {
    for (const r of rows(x)) if (!r.pass) { bad++; console.log(`FAIL ${x} ${r.label}: ${r.fgHex} on ${r.bgHex} = ${r.ratio.toFixed(2)} (< ${r.min})`); }
    const t = readTokens(x);
    console.log(x, 'signal', t.signal, 'forbidden #6E5BFF?', Object.values(t).includes('#6E5BFF'));
  }
  console.log(bad ? `${bad} failing pairs` : 'ALL PASS');
  process.exit(bad ? 1 : 0);
}

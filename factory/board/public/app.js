/* ============================================================
   activeDIQ Factory Board — vanilla ES module, no build step.
   Contract: factory/README.md → "State store" and "Board".
   Rendering model: every region is reconciled by key + data hash,
   so a poll only touches what actually changed. Form state lives in
   `ui` (not the DOM) and is restored on any re-render, and keyboard
   focus + caret are carried across replacements.
   ============================================================ */

/* ---------- constants ---------- */
const POLL_MS = 4000;
const BUDGET_TOKENS = 300000;
const HEARTBEAT_STALE_S = 60;
const FIXTURE = (() => {
  const v = new URLSearchParams(location.search).get('fixture');
  return v !== null && v !== '0' && v !== 'false';
})();
const TABS = ['overview', 'board', 'decisions', 'library', 'demos'];
const STATUSES = [
  ['backlog', 'Backlog'], ['ready', 'Ready'], ['in_progress', 'In progress'],
  ['review', 'Review'], ['qa', 'QA'], ['blocked', 'Blocked'], ['done', 'Done'],
];
const STATUS_LABEL = {
  backlog: 'Backlog', ready: 'Ready', in_progress: 'In progress', review: 'Review', qa: 'QA',
  done: 'Done', blocked: 'Blocked', cancelled: 'Cancelled',
};
const SEG_ORDER = ['done', 'qa', 'review', 'in_progress', 'ready', 'backlog', 'blocked'];
const KIND_LABEL = { directional: 'Directional', advisory: 'Advisory', notice: 'Factory decided' };
const SENTIMENT_LABEL = { love: 'Love it', ok: 'OK', change: 'Change it' };
const DONE_LIMIT = 15;
const THEME_KEY = 'adiq-theme';

/* ---------- tiny helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESC_MAP[c]);
const ic = (name, cls = '') => `<svg class="ic ${cls}" aria-hidden="true" focusable="false"><use href="#i-${name}"/></svg>`;
const jh = (v) => JSON.stringify(v);
const enc = encodeURIComponent;
const clone = (v) => JSON.parse(JSON.stringify(v));
const safe = (fn, label) => { try { return fn(); } catch (e) { console.error(`[board] ${label || fn.name}:`, e); } };
const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;
const dirname = (p) => (p || '').split('/').slice(0, -1).join('/');

/* ---------- time ---------- */
const ts = (v) => { const t = Date.parse(v); return Number.isFinite(t) ? t : null; };
function fmtDur(sec) {
  sec = Math.max(0, Math.floor(sec));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${String(m).padStart(2, '0')}m`;
  if (m) return `${m}m ${String(s).padStart(2, '0')}s`;
  return `${s}s`;
}
function fmtCountdown(sec) {
  sec = Math.max(0, Math.floor(sec));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${sec}s`;
}
function fmtRel(t, now = Date.now()) {
  const d = (now - t) / 1000;
  if (d < 0) return `in ${fmtCountdown(-d)}`;
  if (d < 5) return 'just now';
  if (d < 60) return `${Math.floor(d)}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  if (d < 7 * 86400) return `${Math.floor(d / 86400)}d ago`;
  return fmtDate(t);
}
function fmtDate(v) {
  const t = typeof v === 'number' ? v : ts(v);
  if (t == null) return v ? String(v) : '';
  const d = new Date(t);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function fmtFull(v) { const t = ts(v); return t == null ? '' : new Date(t).toLocaleString(); }
/** A <time> whose text the 1s ticker keeps fresh. */
function relEl(iso, cls = '') {
  const t = ts(iso);
  if (t == null) return '';
  return `<time class="mono ${cls}" data-rel="${esc(iso)}" datetime="${esc(iso)}" title="${esc(fmtFull(iso))}">${esc(fmtRel(t))}</time>`;
}
const fmtK = (n) => `${Math.round((n || 0) / 1000)}k`;

/* ---------- UI state (survives every re-render) ---------- */
const ui = {
  tab: 'overview',
  scroll: {},                 // tab → scrollY
  f: { milestone: '', epic: '', owner: '', q: '' },
  doneAll: false,
  sel: {},                    // decisionId → [optionIds]
  text: {},                   // 'dec:D-1' | 'act:A-1' | 'fb:<target>' | 'sent:<target>' → string
  open: {},                   // preview <details> open state
  libPath: '',
  libQ: '',
  doc: null,                  // { path, text, status, err, updated }
  digest: { path: null, text: '', at: 0 },
  drawer: null,               // { id, detail, err, tailRun, tailPinned, tailText, tailFetched }
  drawerPushed: false,
  fb: null,                   // { target, label }
  route: { tab: 'overview', arg: '', t: '' },
  routed: false,
};
const S = { server: null, data: null, fetchedAt: 0, failures: 0, offline: false, nextPollAt: 0 };

/* ---------- theme (remembered in localStorage, never throws) ---------- */
try {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
} catch { /* storage blocked: follow OS */ }
const currentTheme = () => document.documentElement.dataset.theme
  || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem(THEME_KEY, t); } catch { /* ignore */ }
  updateThemeBtn();
}
function updateThemeBtn() {
  const b = $('#btn-theme'); if (!b) return;
  const dark = currentTheme() === 'dark';
  b.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
  b.title = dark ? 'Light theme' : 'Dark theme';
  b.innerHTML = ic(dark ? 'sun' : 'moon');
}

/* ============================================================
   Safe markdown renderer. HTML is escaped first; the only tags
   ever emitted are the ones built here. URLs are allow-listed.
   ============================================================ */
const SEP_RE = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;
const HR_RE = /^\s{0,3}([-*_])(?:\s*\1){2,}\s*$/;
const LI_RE = /^(\s*)([-*+]|\d{1,9}[.)])\s+(.*)$/;
const slug = (s) => String(s).toLowerCase().replace(/<[^>]*>|[`*_~]/g, '').trim().replace(/[^\p{L}\p{N}\s-]/gu, '').replace(/\s+/g, '-');

function normPath(p) {
  const out = [];
  for (const seg of p.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') out.pop(); else out.push(seg);
  }
  return out.join('/');
}
let libSetCache = { src: null, set: new Set() };
function libSet() {
  const lib = S.data?.library;
  if (lib !== libSetCache.src) libSetCache = { src: lib, set: new Set((lib || []).map((d) => d.path)) };
  return libSetCache.set;
}
function resolveDocPath(base, rel) {
  rel = rel.replace(/^\/+/, '');
  const root = normPath(rel);
  if (!base) return root;
  const rel2 = normPath(`${base}/${rel}`);
  const set = libSet();
  if (set.has(root) && !set.has(rel2)) return root;
  return rel2;
}
function safeDecode(s) { try { return decodeURIComponent(s); } catch { return s; } }

let fixtureBlobs = {};
function fileUrl(path) {
  if (FIXTURE && FX?.detail?.files?.[path] != null) {
    if (!fixtureBlobs[path]) {
      const type = /\.html?$/i.test(path) ? 'text/html' : 'text/plain';
      fixtureBlobs[path] = URL.createObjectURL(new Blob([FX.detail.files[path]], { type }));
    }
    return fixtureBlobs[path];
  }
  return `/api/file?path=${enc(path)}`;
}

function linkHTML(href, inner, o) {
  href = href.trim();
  if (/^(javascript|data|vbscript|file):/i.test(href.replace(/[\s\u0000-\u001f]/g, ''))) return inner;
  if (/^(https?:\/\/|mailto:)/i.test(href)) return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${inner}</a>`;
  if (href.startsWith('#')) return `<a href="#" data-anchor="${esc(slug(safeDecode(href.slice(1))))}">${inner}</a>`;
  if (/^[a-z][a-z0-9+.-]*:/i.test(href)) return inner;
  const resolved = resolveDocPath(o.base, safeDecode(href.split('#')[0]));
  if (/\.md$/i.test(resolved)) {
    return `<a href="#library/${encodeURI(resolved).replace(/[?#]/g, enc)}" data-doc="${esc(resolved)}">${inner}</a>`;
  }
  return `<a href="${esc(fileUrl(resolved))}" target="_blank" rel="noopener noreferrer">${inner}</a>`;
}

/** Inline formatting on already-escaped text. */
function fmtInline(s) {
  return s
    .replace(/\*\*(?=\S)([\s\S]*?\S)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^\w])__(?=\S)([\s\S]*?\S)__(?!\w)/g, '$1<strong>$2</strong>')
    .replace(/(^|[^*\w])\*(?=[^\s*])([\s\S]*?[^\s*])\*(?!\*)/g, '$1<em>$2</em>')
    .replace(/(^|[^_\w])_(?=[^\s_])([\s\S]*?[^\s_])_(?!\w)/g, '$1<em>$2</em>')
    .replace(/~~(?=\S)([\s\S]*?\S)~~/g, '<del>$1</del>');
}

function mdInline(src, o = {}) {
  const stash = [];
  const keep = (html) => { stash.push(html); return `\u0000${stash.length - 1}\u0000`; };
  let s = String(src ?? '');
  s = s.replace(/(`+)(?!`)([\s\S]*?[^`])\1(?!`)/g, (_, _t, code) => keep(`<code>${esc(code.trim())}</code>`));
  s = s.replace(/\\([\\`*_{}[\]()#+\-.!|~>])/g, (_, ch) => keep(esc(ch)));
  s = s.replace(/<(https?:\/\/[^>\s]+)>/g, (_, u) => keep(`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a>`));
  s = s.replace(/!\[([^\]]*)\]\(\s*([^)\s]+)(?:\s+"[^"]*")?\s*\)/g, (_, alt, src2) => {
    if (/^[a-z][a-z0-9+.-]*:/i.test(src2) || src2.startsWith('//')) {
      return keep(linkHTML(src2, esc(alt || src2), o)); // remote images are links, never auto-loaded
    }
    const p = resolveDocPath(o.base, safeDecode(src2.split('#')[0]));
    return keep(`<img src="${esc(fileUrl(p))}" alt="${esc(alt)}" loading="lazy">`);
  });
  s = s.replace(/\[([^\]]+)\]\(\s*([^)\s]+)(?:\s+"[^"]*")?\s*\)/g, (_, text, href) => keep(linkHTML(href, fmtInline(esc(text)), o)));
  s = esc(s);
  s = fmtInline(s);
  s = s.replace(/(^|[\s(])(https?:\/\/[^\s<]+[^\s<.,;:!?)\]'"])/g,
    (_, pre, u) => `${pre}<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>`);
  for (let i = 0; i < 4 && /\u0000\d+\u0000/.test(s); i++) s = s.replace(/\u0000(\d+)\u0000/g, (_, n) => stash[+n] ?? '');
  return s.replace(/\u0002/g, '<br>');
}

function splitRow(line) {
  let t = line.trim();
  if (t.startsWith('|')) t = t.slice(1);
  if (t.endsWith('|') && !t.endsWith('\\|')) t = t.slice(0, -1);
  return t.split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
}
const isTableStart = (lines, i) => lines[i].includes('|') && i + 1 < lines.length && lines[i + 1].includes('|') && SEP_RE.test(lines[i + 1]) && /-/.test(lines[i + 1]);
const startsBlock = (l, lines, i) => /^\s{0,3}#{1,6}\s/.test(l) || /^\s*(```|~~~)/.test(l) || HR_RE.test(l)
  || /^\s{0,3}>/.test(l) || (LI_RE.test(l) && !HR_RE.test(l)) || /^\s*<!--/.test(l) || isTableStart(lines, i);

function renderList(items, o) {
  let idx = 0;
  const build = () => {
    const base = items[idx].indent, ordered = items[idx].ordered;
    let html = '';
    while (idx < items.length && items[idx].indent === base) {
      const it = items[idx++];
      let kid = '';
      if (idx < items.length && items[idx].indent > base) kid = build();
      let text = it.text.replace(/\n/g, ' ');
      let task = '';
      const tm = text.match(/^\[([ xX])\]\s+/);
      if (tm) { task = `<input type="checkbox" disabled${tm[1] === ' ' ? '' : ' checked'}>`; text = text.slice(tm[0].length); }
      html += `<li>${task}${mdInline(text, o)}${kid}</li>`;
    }
    return `<${ordered ? 'ol' : 'ul'}>${html}</${ordered ? 'ol' : 'ul'}>`;
  };
  let out = '';
  while (idx < items.length) out += build();
  return out;
}

function mdBlocks(lines, o) {
  const out = [];
  let i = 0;
  const blank = (l) => /^\s*$/.test(l);
  while (i < lines.length) {
    const line = lines[i];
    if (blank(line)) { i++; continue; }
    if (/^\s*<!--/.test(line)) { while (i < lines.length && !/-->/.test(lines[i])) i++; i++; continue; }
    let m = line.match(/^(\s*)(`{3,}|~{3,})\s*([\w+#.-]*)/);
    if (m) {
      const ind = m[1].length, ch = m[2][0], len = m[2].length, lang = m[3];
      const closer = new RegExp(`^\\s*\\${ch}{${len},}\\s*$`);
      const buf = [];
      i++;
      while (i < lines.length && !closer.test(lines[i])) {
        const lead = lines[i].length - lines[i].trimStart().length;
        buf.push(lines[i].slice(Math.min(ind, lead)));
        i++;
      }
      i++;
      out.push(`<pre class="md-code"${lang ? ` data-lang="${esc(lang)}"` : ''}><code>${esc(buf.join('\n'))}</code></pre>`);
      continue;
    }
    m = line.match(/^\s{0,3}(#{1,6})\s+(.*?)(?:\s+#+)?\s*$/);
    if (m) {
      const lvl = m[1].length, tag = `h${Math.min(6, o.h + lvl - 1)}`;
      let id = '';
      if (o.ids) {
        let sl = slug(m[2]);
        o._slugs = o._slugs || {};
        o._slugs[sl] = (o._slugs[sl] || 0) + 1;
        if (o._slugs[sl] > 1) sl += `-${o._slugs[sl] - 1}`;
        id = ` id="md-${esc(sl)}"`;
      }
      out.push(`<${tag} class="md-h md-h${lvl}"${id}>${mdInline(m[2], o)}</${tag}>`);
      i++; continue;
    }
    if (HR_RE.test(line)) { out.push('<hr>'); i++; continue; }
    if (/^\s{0,3}>/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s{0,3}>/.test(lines[i])) { buf.push(lines[i].replace(/^\s{0,3}>\s?/, '')); i++; }
      out.push(`<blockquote>${mdBlocks(buf, o)}</blockquote>`);
      continue;
    }
    if (isTableStart(lines, i)) {
      const head = splitRow(line);
      const aligns = splitRow(lines[i + 1]).map((c) => (/^:-+:$/.test(c) ? 'al-c' : /-:$/.test(c) ? 'al-r' : ''));
      i += 2;
      const rows = [];
      while (i < lines.length && !blank(lines[i]) && lines[i].includes('|')) { rows.push(splitRow(lines[i])); i++; }
      const cell = (tag, c, k) => `<${tag}${aligns[k] ? ` class="${aligns[k]}"` : ''}>${mdInline(c ?? '', o)}</${tag}>`;
      out.push(`<div class="md-table"><table><thead><tr>${head.map((c, k) => cell('th', c, k)).join('')}</tr></thead><tbody>${
        rows.map((r) => `<tr>${head.map((_, k) => cell('td', r[k], k)).join('')}</tr>`).join('')}</tbody></table></div>`);
      continue;
    }
    if (LI_RE.test(line)) {
      const items = [];
      while (i < lines.length) {
        const l = lines[i];
        const lm = l.match(LI_RE);
        if (lm && !HR_RE.test(l)) { items.push({ indent: lm[1].length, ordered: /\d/.test(lm[2]), text: lm[3] }); i++; continue; }
        if (blank(l)) {
          let j = i + 1;
          while (j < lines.length && blank(lines[j])) j++;
          if (items.length && j < lines.length && ((LI_RE.test(lines[j]) && !HR_RE.test(lines[j])) || /^\s{2,}\S/.test(lines[j]))) { i = j; continue; }
          break;
        }
        if (/^\s{2,}\S/.test(l) && items.length) { items[items.length - 1].text += `\n${l.trim()}`; i++; continue; }
        break;
      }
      out.push(renderList(items, o));
      continue;
    }
    const buf = [];
    while (i < lines.length && !blank(lines[i]) && (buf.length === 0 || !startsBlock(lines[i], lines, i))) {
      const l = lines[i];
      buf.push(i + 1 < lines.length && !blank(lines[i + 1]) && !startsBlock(lines[i + 1], lines, i + 1) && /( {2,}|\\)$/.test(l)
        ? `${l.replace(/( {2,}|\\)$/, '')}\u0002` : l.trim());
      i++;
    }
    out.push(`<p>${mdInline(buf.join(' ').replace(/\u0002 /g, '\u0002'), o)}</p>`);
  }
  return out.join('\n');
}

/** md(text, { base: dir for relative links, h: first heading level, ids: anchor ids }) → safe HTML */
function md(src, opts = {}) {
  const o = { base: '', h: 3, ids: false, ...opts };
  const text = String(src ?? '').replace(/\r\n?/g, '\n').replace(/\t/g, '    ');
  return mdBlocks(text.split('\n'), o);
}
const mdi = (s) => mdInline(s, { base: '' });

function splitFrontmatter(text) {
  const m = String(text).match(/^---\s*\n([\s\S]*?)\n---\s*(?:\n|$)/);
  if (!m) return { fm: {}, body: String(text) };
  const fm = {};
  for (const l of m[1].split('\n')) {
    const k = l.match(/^([\w-]+):\s*(.*)$/);
    if (k) fm[k[1]] = k[2].replace(/^["']|["']$/g, '');
  }
  return { fm, body: String(text).slice(m[0].length) };
}

/* ============================================================
   DOM reconciliation (keyed, hash-gated, focus-preserving)
   ============================================================ */
const tpl = document.createElement('template');
function nodeFrom(html) { tpl.innerHTML = html.trim(); return tpl.content.firstElementChild; }
/** CSP-safe dynamic widths: elements carry data-w (percent) / data-flex. */
function hydrate(root) {
  if (!root || !root.querySelectorAll) return;
  const list = root.matches?.('[data-w],[data-flex]') ? [root] : [];
  for (const e of [...list, ...root.querySelectorAll('[data-w],[data-flex]')]) {
    if (e.dataset.w != null) e.style.width = `${e.dataset.w}%`;
    if (e.dataset.flex != null) e.style.flex = e.dataset.flex;
  }
}
function captureFocus(container) {
  const a = document.activeElement;
  if (!a || a === document.body || !container.contains(a)) return null;
  const fk = a.dataset?.fk;
  if (!fk) return null;
  return { fk, s: a.selectionStart, e: a.selectionEnd, d: a.selectionDirection };
}
function restoreFocus(container, f) {
  if (!f) return;
  const el = container.querySelector(`[data-fk="${CSS.escape(f.fk)}"]`);
  if (!el || el === document.activeElement) return;
  el.focus({ preventScroll: true });
  if (f.s != null && el.setSelectionRange) { try { el.setSelectionRange(f.s, f.e, f.d || 'none'); } catch { /* not a text control */ } }
}
/** items: [{ key, html (single root element), hash? }] — only changed items are rebuilt. */
function reconcile(container, items) {
  const focus = captureFocus(container);
  const first = !container._inited;
  const existing = new Map();
  for (const ch of container.children) if (ch.dataset.key != null) existing.set(ch.dataset.key, ch);
  const next = [];
  for (const it of items) {
    let node = existing.get(it.key);
    const h = it.hash ?? it.html;
    if (!node || node._h !== h) {
      const fresh = nodeFrom(it.html);
      fresh.dataset.key = it.key;
      fresh._h = h;
      if (!fresh.dataset.fk && /^(A|BUTTON)$/.test(fresh.tagName)) fresh.dataset.fk = `root:${it.key}`;
      hydrate(fresh);
      if (node) node.replaceWith(fresh);
      else if (!first) fresh.classList.add('enter');
      node = fresh;
    }
    next.push(node);
  }
  const keepSet = new Set(next);
  for (const n of existing.values()) if (!keepSet.has(n)) n.remove();
  next.forEach((n, idx) => { if (container.children[idx] !== n) container.insertBefore(n, container.children[idx] || null); });
  container._inited = true;
  restoreFocus(container, focus);
}
function setHTML(el, html, key = html) {
  if (!el || el._k === key) return false;
  const focus = captureFocus(el);
  el.innerHTML = html;
  hydrate(el);
  el._k = key;
  restoreFocus(el, focus);
  return true;
}
function setText(el, text) { if (el && el.textContent !== text) el.textContent = text; }

/* ============================================================
   Toasts
   ============================================================ */
function toast(msg, kind = 'info', ms) {
  const host = $('#toasts');
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `${ic(kind === 'error' ? 'alert' : kind === 'ok' ? 'check' : 'bolt')}<span>${esc(msg)}</span>`;
  host.appendChild(el);
  try { host.hidePopover(); host.showPopover(); } catch { /* popover unsupported: still visible */ }
  const life = ms ?? (kind === 'error' ? 7000 : 3800);
  setTimeout(() => {
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 260);
  }, life);
  while (host.children.length > 4) host.firstElementChild.remove();
}

/* ============================================================
   Data layer: fixture, API, optimistic mutations
   ============================================================ */
let FX = null;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
function shiftTimes(v, d) {
  if (typeof v === 'string') return ISO_RE.test(v) ? new Date(Date.parse(v) + d).toISOString() : v;
  if (Array.isArray(v)) return v.map((x) => shiftTimes(x, d));
  if (v && typeof v === 'object') for (const k of Object.keys(v)) v[k] = shiftTimes(v[k], d);
  return v;
}
async function loadFixture() {
  if (!FX) {
    const r = await fetch('dev/fixture-state.json', { cache: 'no-store' });
    if (!r.ok) throw new Error(`fixture not found (${r.status})`);
    const raw = await r.json();
    shiftTimes(raw, Date.now() - Date.parse(raw.generated)); // make the fixture feel "now"
    const detail = raw._fixture || {};
    delete raw._fixture;
    FX = { state: raw, detail };
  }
  const s = structuredClone(FX.state);
  const now = Date.now();
  s.generated = new Date(now).toISOString();
  if (s.dispatcher) s.dispatcher.heartbeat = new Date(now - 6000).toISOString();
  return s;
}

class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }
async function http(path, { method = 'GET', body, timeout = 10000 } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);
  try {
    const opts = { method, signal: ctl.signal, headers: { Accept: 'application/json, text/plain, */*' }, cache: 'no-store' };
    if (method !== 'GET') {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['X-Factory-Board'] = '1';
      opts.body = JSON.stringify(body ?? {});
    }
    const res = await fetch(path, opts);
    if (!res.ok) {
      let msg = `${res.status} ${res.statusText}`.trim();
      try {
        const txt = await res.text();
        try { const j = JSON.parse(txt); msg = j.error || j.message || msg; } catch { if (txt && txt.length < 200) msg = txt; }
      } catch { /* keep status text */ }
      throw new ApiError(msg, res.status);
    }
    const ct = res.headers.get('content-type') || '';
    return ct.includes('json') ? res.json() : res.text();
  } catch (e) {
    if (e.name === 'AbortError') throw new ApiError('request timed out', 0);
    if (e instanceof ApiError) throw e;
    throw new ApiError(e.message || 'network error', 0);
  } finally { clearTimeout(timer); }
}

function normalizeState(d) {
  if (!d || typeof d !== 'object') throw new ApiError('bad state payload', 0);
  const arr = (k) => { if (!Array.isArray(d[k])) d[k] = []; };
  ['milestones', 'epics', 'tickets', 'decisions', 'actions', 'feedback', 'sessions', 'events', 'library'].forEach(arr);
  d.control = d.control || {};
  d.dispatcher = d.dispatcher || {};
  d.runs = d.runs || {};
  if (!Array.isArray(d.runs.active)) d.runs.active = [];
  if (!Array.isArray(d.runs.recent)) d.runs.recent = [];
  return d;
}

async function fetchState() {
  return FIXTURE ? loadFixture() : http('/api/state');
}
async function fetchTicket(id) {
  let r;
  if (FIXTURE) {
    await loadFixture();
    const base = FX.state.tickets.find((t) => t.id === id);
    const det = FX.detail.tickets?.[id];
    if (!base && !det) throw new ApiError('ticket not found', 404);
    r = { ...(base || {}), ...(det || {}) };
  } else r = await http(`/api/ticket/${enc(id)}`);
  const t = r.ticket && typeof r.ticket === 'object' ? r.ticket : r;
  return { ...t, runs: r.runs ?? t.runs ?? [], handoffs: r.handoffs ?? t.handoffs ?? [] };
}
async function fetchTail(runId) {
  let r;
  if (FIXTURE) {
    await loadFixture();
    r = FX.detail.tails?.[runId] ?? ['(no log captured for this run in the fixture)'];
  } else r = await http(`/api/run/${enc(runId)}/tail?lines=80`);
  if (typeof r === 'string') return r;
  if (Array.isArray(r)) return r.map((x) => (typeof x === 'string' ? x : x.text ?? jh(x))).join('\n');
  if (r && typeof r === 'object') {
    const v = r.lines ?? r.tail ?? r.text ?? '';
    return Array.isArray(v) ? v.map((x) => (typeof x === 'string' ? x : x.text ?? jh(x))).join('\n') : String(v);
  }
  return '';
}
async function fetchDoc(path) {
  if (FIXTURE) {
    await loadFixture();
    const t = FX.detail.docs?.[path];
    if (t == null) throw new ApiError('This document is not part of the fixture.', 404);
    return t;
  }
  const r = await http(`/api/doc?path=${enc(path)}`);
  return typeof r === 'string' ? r : (r.text ?? r.content ?? r.markdown ?? '');
}

/* optimistic mutations: re-applied on top of every fresh server state until the server catches up */
const mutations = [];
function rebuildData() {
  if (!S.server) return;
  if (!mutations.length) { S.data = S.server; return; }
  S.data = clone(S.server);
  for (const m of mutations) safe(() => m.fn(S.data), 'mutation');
}
function addMutation(fn) {
  const m = { fn, settled: false };
  mutations.push(m);
  rebuildData();
  renderAll();
  return m;
}
function dropMutation(m) {
  const i = mutations.indexOf(m);
  if (i >= 0) mutations.splice(i, 1);
  rebuildData();
  renderAll();
}
/** POST with optimistic UI + toast. Returns true on success. */
async function act({ path, body, mutate, ok, fail }) {
  const m = mutate ? addMutation(mutate) : null;
  if (FIXTURE) {
    toast('Fixture mode — nothing was sent.', 'info');
    return true;
  }
  try {
    await http(path, { method: 'POST', body });
    if (m) m.settled = true;
    toast(ok, 'ok');
    pollSoon();
    return true;
  } catch (e) {
    if (m) dropMutation(m);
    toast(`${fail}: ${e.message}`, 'error');
    return false;
  }
}

/* ---------- polling with backoff ---------- */
let pollTimer = null, polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  clearTimeout(pollTimer);
  const settledAtStart = mutations.filter((m) => m.settled);
  try {
    const fresh = normalizeState(await fetchState());
    S.server = fresh;
    for (const m of settledAtStart) { const i = mutations.indexOf(m); if (i >= 0) mutations.splice(i, 1); }
    rebuildData();
    S.fetchedAt = Date.now();
    S.failures = 0; S.offline = false;
    $('#boot')?.remove();
    renderAll();
    afterState();
  } catch (e) {
    S.failures++; S.offline = true; S.err = e;
    const boot = $('#boot');
    if (boot && !S.data) boot.textContent = 'Can’t reach the factory board yet. Retrying…';
  } finally {
    polling = false;
    const delay = S.failures ? Math.min(30000, POLL_MS * 2 ** Math.min(S.failures, 4)) : (document.hidden ? 15000 : POLL_MS);
    S.nextPollAt = Date.now() + delay;
    pollTimer = setTimeout(poll, delay);
    updateChrome();
  }
}
function pollSoon() { clearTimeout(pollTimer); pollTimer = setTimeout(poll, 250); }

function afterState() {
  safe(refreshDigest, 'digest');
  safe(refreshDrawer, 'drawer refresh');
  safe(ensureDoc, 'doc');
}

/* ============================================================
   Derived data helpers
   ============================================================ */
const D = () => S.data;
const ticketById = (id) => D()?.tickets.find((t) => t.id === id);
const decisionById = (id) => D()?.decisions.find((d) => d.id === id);
const allRuns = () => {
  const seen = new Set(), out = [];
  for (const r of [...(D()?.runs.active || []), ...(D()?.runs.recent || [])]) if (!seen.has(r.id)) { seen.add(r.id); out.push(r); }
  return out;
};
const activeRuns = () => (D()?.runs.active || []).filter((r) => !r.status || r.status === 'running');
const pendingDecisions = () => (D()?.decisions || []).filter((d) => d.status === 'pending');
const openActions = () => (D()?.actions || []).filter((a) => a.status === 'open');
const needsCount = () => pendingDecisions().length + openActions().length;
const optLabel = (dec, id) => dec.options?.find((o) => o.id === id)?.label ?? id;
const KIND_RANK = { directional: 0, advisory: 1, notice: 2 };
const byDecision = (a, b) => (KIND_RANK[a.kind] ?? 9) - (KIND_RANK[b.kind] ?? 9) || (ts(a.created) ?? 0) - (ts(b.created) ?? 0);
const PRI_RANK = { P0: 0, P1: 1, P2: 2, P3: 3 };
const byPriority = (a, b) => (PRI_RANK[a.priority] ?? 9) - (PRI_RANK[b.priority] ?? 9);
const isSecurity = (t) => (t.tags || []).includes('security-sensitive');

function msStats(m) {
  const counts = {};
  let total = 0;
  for (const t of D().tickets) {
    if (t.milestone !== m.id || t.status === 'cancelled') continue;
    counts[t.status] = (counts[t.status] || 0) + 1;
    total++;
  }
  const done = counts.done || 0;
  return { counts, total, done, pct: total ? Math.round((done / total) * 100) : 0 };
}
function activeMilestone() {
  const ms = D().milestones;
  return ms.find((m) => m.status === 'active') || ms.find((m) => m.status === 'demo-ready') || ms.find((m) => m.status === 'planned') || ms[0];
}

/* ---------- factory status ---------- */
function heartbeatAge() {
  const hb = ts(D()?.dispatcher?.heartbeat);
  if (hb == null) return Infinity;
  const gen = ts(D().generated);
  const base = gen != null ? (gen - hb) / 1000 : (S.fetchedAt - hb) / 1000;
  return Math.max(0, base) + (Date.now() - S.fetchedAt) / 1000; // robust to client/server clock skew
}
function computeStatus() {
  if (!S.data) return S.failures ? { key: 'offline', label: 'Offline' } : { key: 'connecting', label: 'Connecting' };
  if (S.offline) return { key: 'offline', label: 'Offline' };
  if (D().dispatcher.alive === false || heartbeatAge() > HEARTBEAT_STALE_S) return { key: 'offline', label: 'Offline' };
  if (D().control.paused) return { key: 'paused', label: 'Paused' };
  if (activeRuns().length) return { key: 'running', label: 'Running' };
  return { key: 'idle', label: 'Idle' };
}

/* ============================================================
   Chrome: pill, updated-ago, pause, tabs, banner, title
   ============================================================ */
function updateChrome() {
  const st = computeStatus();
  const pill = $('#pill');
  if (pill.dataset.state !== st.key) pill.dataset.state = st.key;
  setText($('#pill-label'), st.label);
  const upd = S.fetchedAt ? Math.floor((Date.now() - S.fetchedAt) / 1000) : null;
  setText($('#updated'), upd == null ? '' : `updated ${upd < 60 ? `${upd}s` : `${Math.floor(upd / 60)}m`} ago`);
  const pb = $('#btn-pause');
  const paused = !!D()?.control.paused;
  pb.disabled = !S.data;
  const lbl = paused ? 'Resume' : 'Pause';
  if (pb._k !== lbl) {
    pb._k = lbl;
    pb.innerHTML = `${ic(paused ? 'play' : 'pause')}<span>${lbl}</span>`;
    pb.title = paused ? 'Let the dispatcher start new work again' : 'Stop launching new work (running workers finish)';
  }
  $('#fixture-chip').hidden = !FIXTURE;
  const banner = $('#banner');
  if (S.failures > 0) {
    banner.hidden = false;
    const secs = Math.max(0, Math.ceil((S.nextPollAt - Date.now()) / 1000));
    const last = S.fetchedAt ? ` Showing data from ${fmtRel(S.fetchedAt)}.` : '';
    setText($('#banner-text'), `Can’t reach the factory board.${last} ${polling ? 'Retrying…' : `Retrying in ${secs}s.`}`);
  } else banner.hidden = true;
  const n = S.data ? pendingDecisions().length : 0;
  const cnt = $('#count-decisions');
  cnt.hidden = !n;
  setText(cnt, String(n));
  const title = `${S.data && needsCount() ? `(${needsCount()}) ` : ''}activeDIQ factory`;
  if (document.title !== title) document.title = title;
}

function applyTabs() {
  for (const t of TABS) {
    const tab = $(`#tab-${t}`), panel = $(`#panel-${t}`);
    const on = ui.tab === t;
    tab.setAttribute('aria-selected', on ? 'true' : 'false');
    tab.tabIndex = on ? 0 : -1;
    panel.hidden = !on;
  }
}

/* ============================================================
   Routing — #tab[/arg][?t=TICKET]
   ============================================================ */
function parseHash() {
  let h = location.hash.replace(/^#/, '');
  let q = '';
  const qi = h.indexOf('?');
  if (qi >= 0) { q = h.slice(qi + 1); h = h.slice(0, qi); }
  const si = h.indexOf('/');
  const tab = si >= 0 ? h.slice(0, si) : h;
  const arg = si >= 0 ? safeDecode(h.slice(si + 1)) : '';
  return { tab: TABS.includes(tab) ? tab : 'overview', arg, t: new URLSearchParams(q).get('t') || '' };
}
function buildHash(tab, arg = '', t = '') {
  return `${tab}${arg ? `/${encodeURI(arg).replace(/[?#]/g, enc)}` : ''}${t ? `?t=${enc(t)}` : ''}`;
}
const tkHref = (id) => `#${buildHash(ui.tab, ui.tab === 'library' ? ui.libPath : '', id)}`;
function tabHash(tab) { return buildHash(tab, tab === 'library' ? ui.libPath : ''); }

function route() {
  const r = parseHash();
  const prevTab = ui.tab;
  if (r.tab !== prevTab) ui.scroll[prevTab] = window.scrollY;
  ui.tab = r.tab;
  if (r.tab === 'library') {
    const changed = r.arg !== ui.libPath;
    ui.libPath = r.arg;
    if (changed) ensureDoc(true);
  }
  if (r.t && !ui.route.t) ui.drawerPushed = ui.routed; // opened by a click (history entry) vs deep link
  if (!r.t) ui.drawerPushed = false;
  ui.route = r;
  ui.routed = true;
  applyTabs();
  if (r.t) openDrawer(r.t); else closeDrawerUI();
  renderActive();
  if (r.tab !== prevTab) requestAnimationFrame(() => window.scrollTo(0, ui.scroll[r.tab] || 0));
  else if (r.tab === 'library') window.scrollTo(0, 0);
}

/* ============================================================
   Rendering orchestration
   ============================================================ */
function renderAll() {
  updateChrome();
  if (!S.data) return;
  renderActive();
  if (ui.drawer) safe(renderDrawer, 'drawer');
}
function renderActive() {
  if (!S.data) return;
  const fn = { overview: renderOverview, board: renderBoard, decisions: renderDecisions, library: renderLibrary, demos: renderDemos }[ui.tab];
  safe(fn, `render ${ui.tab}`);
}

/* ---------- shared card pieces ---------- */
function meterHTML(tokens) {
  const pct = Math.max(0, Math.min(100, ((tokens || 0) / BUDGET_TOKENS) * 100));
  const cls = pct < 70 ? 'ok' : pct < 85 ? 'warn' : 'crit';
  return `<span class="meter ${cls}" role="meter" aria-label="Context used" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(pct)}" aria-valuetext="${Math.round(pct)} percent of the 300k context budget"><span class="meter-bar" data-w="${pct.toFixed(1)}"></span></span><span class="meter-l mono ${cls === 'ok' ? '' : cls}">${fmtK(tokens)} / ${fmtK(BUDGET_TOKENS)} · ${Math.round(pct)}%</span>`;
}
const modelChip = (r) => `<span class="chip model" title="Model · effort">${esc([r.model, r.effort].filter(Boolean).join(' · ') || 'model n/a')}</span>`;
const ownerChip = (o) => `<span class="chip owner">${esc(o || 'unassigned')}</span>`;
const ticketChip = (id, extra = '') => `<a class="chip tlink" href="${tkHref(id)}" ${extra}>${esc(id)}</a>`;
const statusChip = (s) => `<span class="chip st-${esc(s)}">${esc(STATUS_LABEL[s] || s)}</span>`;
function emptyBlock(text, quiet) {
  return `<div class="empty${quiet ? ' quiet' : ''}">${ic('check')}<span>${esc(text)}</span></div>`;
}

/* ============================================================
   Overview
   ============================================================ */
function renderOverview() {
  renderGlance();
  renderNeeds();
  renderRunning();
  renderMilestones();
  renderDigest();
  renderActivity();
}

function renderGlance() {
  const d = D();
  const needs = needsCount();
  const running = activeRuns().length;
  const blocked = d.tickets.filter((t) => t.status === 'blocked').length;
  const m = activeMilestone();
  let msTile = '<div class="tile"><span class="tile-k">Milestone</span><span class="tile-v mono">—</span><span class="tile-s">none planned</span></div>';
  if (m) {
    const st = msStats(m);
    const tgt = ts(m.target);
    const sub = tgt ? `target ${fmtDate(tgt)}` : (STATUS_LABEL[m.status] || m.status);
    msTile = `<div class="tile"><span class="tile-k">${esc(m.id)} progress</span><span class="tile-v mono">${st.pct}%</span><span class="tile-s">${esc(st.done)} of ${esc(st.total)} done · ${esc(sub)}</span></div>`;
  }
  const html = `
    <div class="tile ${needs ? 'hot' : ''}"><span class="tile-k">Needs you</span><span class="tile-v mono">${needs}</span><span class="tile-s">${needs ? `${plural(pendingDecisions().length, 'decision')} · ${plural(openActions().length, 'action')}` : 'all clear'}</span></div>
    <div class="tile"><span class="tile-k">Running now</span><span class="tile-v mono">${running}</span><span class="tile-s">${d.dispatcher.runs_today ? `${d.dispatcher.runs_today.count} runs today` : 'workers'}</span></div>
    <div class="tile ${blocked ? 'bad' : ''}"><span class="tile-k">Blocked</span><span class="tile-v mono">${blocked}</span><span class="tile-s">${blocked ? 'tickets stuck' : 'nothing stuck'}</span></div>
    ${msTile}`;
  setHTML($('#glance'), html);
}

/* ---------- decision cards ---------- */
function formSel(dec) {
  if (!ui.sel[dec.id]) ui.sel[dec.id] = dec.kind === 'advisory' && dec.default_option ? [dec.default_option] : [];
  return ui.sel[dec.id];
}
const PREVIEW_EXT = { html: 'frame', htm: 'frame', png: 'img', jpg: 'img', jpeg: 'img', gif: 'img', webp: 'img', svg: 'img', mp4: 'video', webm: 'video', mov: 'video' };
function previewKind(p) { return PREVIEW_EXT[(p.split('.').pop() || '').toLowerCase()] || 'link'; }
function previewBody(kind, url, label) {
  if (kind === 'frame') return `<iframe class="prev-frame" src="${esc(url)}" title="Preview: ${esc(label)}" sandbox="allow-scripts" loading="lazy"></iframe>`;
  if (kind === 'img') return `<img src="${esc(url)}" alt="Preview: ${esc(label)}" loading="lazy">`;
  if (kind === 'video') return `<video controls preload="metadata" src="${esc(url)}"></video>`;
  return '';
}
function previewHTML(dec, opt) {
  const p = opt.preview;
  if (!p) return '';
  if (/^https?:\/\//i.test(p)) {
    return `<div class="opt-prev-link"><a class="linkbtn" href="${esc(p)}" target="_blank" rel="noopener noreferrer">${ic('external')}Open preview</a></div>`;
  }
  const url = fileUrl(p), kind = previewKind(p);
  if (kind === 'link') {
    return `<div class="opt-prev-link"><a class="linkbtn" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${ic('external')}Open preview</a></div>`;
  }
  const key = `prev:${dec.id}:${opt.id}`;
  const open = !!ui.open[key];
  return `<details class="prev" data-prev="${esc(key)}" data-kind="${kind}" data-url="${esc(url)}" data-label="${esc(opt.label)}"${open ? ' open' : ''}>
    <summary>${ic('eye')}Preview${ic('chev', 'chev')}</summary>
    <div class="prev-body">${open ? previewBody(kind, url, opt.label) : ''}</div>
    <div class="prev-foot"><a class="linkbtn" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${ic('external')}Open in new tab</a></div>
  </details>`;
}
function isRecommended(dec, id) {
  const r = dec.recommendation;
  return Array.isArray(r) ? r.includes(id) : r === id;
}
function optionHTML(dec, o, sel) {
  const multi = !!dec.multi;
  const rec = isRecommended(dec, o.id);
  const pros = (o.pros || []).map((p) => `<span class="pc pro">${ic('plus')}<span>${mdi(p)}</span></span>`).join('');
  const cons = (o.cons || []).map((p) => `<span class="pc con">${ic('minus')}<span>${mdi(p)}</span></span>`).join('');
  return `<div class="opt${multi ? ' multi' : ''}">
    <label class="opt-label">
      <input class="opt-input" type="${multi ? 'checkbox' : 'radio'}" name="o-${esc(dec.id)}" value="${esc(o.id)}" data-opt="${esc(dec.id)}" data-fk="opt:${esc(dec.id)}:${esc(o.id)}"${sel.includes(o.id) ? ' checked' : ''}>
      <span class="opt-mark" aria-hidden="true"></span>
      <span class="opt-body">
        <span class="opt-top"><span class="opt-name">${esc(o.label)}</span>${rec ? `<span class="badge rec">${ic('check')}Recommended</span>` : ''}</span>
        ${o.summary ? `<span class="opt-sum">${mdi(o.summary)}</span>` : ''}
        ${pros || cons ? `<span class="pc-list">${pros}${cons}</span>` : ''}
      </span>
    </label>
    ${previewHTML(dec, o)}
  </div>`;
}
function blocksHTML(dec) {
  const ids = dec.blocks || [];
  if (!ids.length) return `<p class="blocks"><span class="label">Blocks</span><span>Nothing — all other work continues.</span></p>`;
  return `<p class="blocks"><span class="label">Blocks</span>${ids.map((id) => {
    const t = ticketById(id);
    return `<a class="chip tlink" href="${tkHref(id)}" title="${esc(t?.title || id)}">${esc(id)}</a>`;
  }).join('')}<span>while this is open.</span></p>`;
}
function decisionCard(dec) {
  const kind = dec.kind || 'directional';
  const noteKey = `dec:${dec.id}`;
  const head = `<header class="dcard-h">
      <span class="badge kind-${esc(kind)}">${esc(KIND_LABEL[kind] || kind)}</span>
      <span class="mono muted">${esc(dec.id)}</span>
      <span class="when">${dec.created ? `asked ${relEl(dec.created)}` : ''}</span>
    </header>
    <h3 class="dcard-title" id="dt-${esc(dec.id)}">${esc(dec.title)}</h3>`;
  const ctx = dec.context ? `<div class="md ctx">${md(dec.context, { h: 4 })}</div>` : '';
  const note = `<div class="field"><label for="n-${esc(dec.id)}">Note <span class="muted">optional</span></label>
      <textarea id="n-${esc(dec.id)}" rows="2" data-note="${noteKey}" data-fk="note:${esc(dec.id)}" placeholder="${kind === 'notice' ? 'Why you agree or object (sent with Veto)' : 'Anything the factory should know'}">${esc(ui.text[noteKey] || '')}</textarea></div>`;

  if (kind === 'notice') {
    const decidedId = Array.isArray(dec.recommendation) ? dec.recommendation[0] : (dec.recommendation ?? dec.default_option);
    const chosen = dec.options?.find((o) => o.id === decidedId);
    const others = (dec.options || []).filter((o) => o.id !== decidedId);
    return `<article class="dcard kind-notice" aria-labelledby="dt-${esc(dec.id)}">
      ${head}
      ${dec.question ? `<p class="dcard-q">${mdi(dec.question)}</p>` : ''}
      ${ctx}
      <div class="notice-box"><span class="label">Factory decided</span>
        <strong>${esc(chosen?.label || dec.title)}</strong>
        ${chosen?.summary ? `<span class="opt-sum">${mdi(chosen.summary)}</span>` : ''}
        ${dec.rationale ? `<span class="opt-sum">${mdi(dec.rationale)}</span>` : ''}
        ${others.length ? `<details class="alts"><summary>Alternatives considered</summary><ul>${others.map((o) => `<li><strong>${esc(o.label)}</strong>${o.summary ? ` — ${mdi(o.summary)}` : ''}</li>`).join('')}</ul></details>` : ''}
      </div>
      ${note}
      <footer class="dcard-f">
        <span class="default-hint">Stands unless you veto it.</span>
        <button class="btn danger" type="button" data-act="dec-veto" data-id="${esc(dec.id)}">${ic('x')}Veto</button>
        <button class="btn" type="button" data-act="dec-ack" data-id="${esc(dec.id)}">${ic('check')}Acknowledge</button>
      </footer>
    </article>`;
  }

  const sel = formSel(dec);
  const defLabel = dec.default_option ? optLabel(dec, dec.default_option) : '';
  const hint = kind === 'advisory' && dec.default_at
    ? `<span class="default-hint">${ic('clock')}Defaults to <strong>${esc(defLabel)}</strong> in <span class="mono" data-until="${esc(dec.default_at)}">${esc(fmtCountdown((ts(dec.default_at) - Date.now()) / 1000))}</span></span>`
    : '<span class="default-hint"></span>';
  return `<article class="dcard kind-${esc(kind)}" aria-labelledby="dt-${esc(dec.id)}">
    ${head}
    ${dec.question ? `<p class="dcard-q">${mdi(dec.question)}</p>` : ''}
    ${ctx}
    <fieldset class="opts" data-opts="${esc(dec.id)}">
      <legend class="opts-legend">${dec.multi ? 'Choose any that apply' : 'Choose one'}</legend>
      <div class="opts-grid">${(dec.options || []).map((o) => optionHTML(dec, o, sel)).join('')}</div>
    </fieldset>
    ${dec.rationale ? `<p class="why"><span class="label">Why</span><span>${mdi(dec.rationale)}</span></p>` : ''}
    ${blocksHTML(dec)}
    ${note}
    <p class="form-err" role="alert" hidden></p>
    <footer class="dcard-f">
      ${hint}
      <button class="btn primary" type="button" data-act="dec-submit" data-id="${esc(dec.id)}">${kind === 'advisory' ? 'Confirm choice' : 'Submit decision'}</button>
    </footer>
  </article>`;
}

/* ---------- action items ---------- */
function actionRow(a) {
  const nk = `act:${a.id}`;
  const done = a.status !== 'open';
  return `<article class="arow${done ? ' is-done' : ''}">
    <div class="arow-main">
      <h3 class="arow-title"><span>${esc(a.title)}</span><span class="mono muted">${esc(a.id)}</span></h3>
      ${a.detail ? `<div class="md">${md(a.detail, { h: 4 })}</div>` : ''}
      ${a.why ? `<p class="arow-why"><span class="label">Why you</span> ${mdi(a.why)}</p>` : ''}
      ${done && a.done_note ? `<p class="done-note">Note: ${esc(a.done_note)}</p>` : ''}
      ${done ? `<p class="done-note">${a.status === 'dismissed' ? 'Dismissed' : 'Done'} ${relEl(a.updated)}</p>` : ''}
    </div>
    ${done ? '' : `<div class="arow-act">
      <input type="text" data-note="${nk}" data-fk="note:${esc(a.id)}" value="${esc(ui.text[nk] || '')}" placeholder="Note (optional)" aria-label="Note for ${esc(a.title)}" autocomplete="off">
      <button class="btn" type="button" data-act="act-done" data-id="${esc(a.id)}">${ic('check')}Mark done</button>
    </div>`}
  </article>`;
}

function renderNeeds() {
  const d = D();
  const pend = pendingDecisions().sort(byDecision);
  const acts = openActions().sort((a, b) => (ts(a.created) ?? 0) - (ts(b.created) ?? 0));
  const items = [];
  for (const dec of pend) items.push({ key: `d:${dec.id}`, hash: jh(dec), html: decisionCard(dec) });
  if (acts.length) {
    items.push({ key: 'h:actions', html: '<h3 class="sub">Action items</h3>' });
    for (const a of acts) items.push({ key: `a:${a.id}`, hash: jh(a), html: actionRow(a) });
  }
  if (!items.length) {
    const st = computeStatus().key;
    const msg = st === 'paused' ? 'Nothing needs you. The factory is paused.'
      : st === 'offline' ? 'Nothing needs you. The factory looks offline.'
        : st === 'idle' ? 'Nothing needs you. The factory is idle.' : 'Nothing needs you. The factory is working.';
    items.push({ key: 'empty', hash: `empty:${st}`, html: emptyBlock(msg) });
  }
  setText($('#needs-count'), needsCount() ? String(needsCount()) : '');
  reconcile($('#needs-list'), items);
  void d;
}

/* ---------- running now ---------- */
function runCard(r, t) {
  return `<a class="run" href="#${buildHash('overview', '', r.ticket)}" aria-label="Open ${esc(r.ticket)} and its live log">
    <span class="run-top"><span class="live-dot" aria-hidden="true"></span><span class="role">${esc(r.role || r.stage_role || 'worker')}</span>${modelChip(r)}<span class="elapsed mono" data-elapsed="${esc(r.started)}" title="Elapsed">${esc(r.started ? fmtDur((Date.now() - ts(r.started)) / 1000) : '')}</span></span>
    <span class="run-title"><span class="id mono">${esc(r.ticket)}</span>${esc(t?.title || '')}</span>
    <span class="run-stage">Stage <b>${esc(r.stage || t?.status || '')}</b> · <span class="mono">${esc(r.id)}</span></span>
    <span class="run-ctx">${meterHTML(r.context_tokens)}</span>
    ${r.last_activity ? `<span class="run-act mono" title="${esc(r.last_activity)}">▸ ${esc(r.last_activity)}</span>` : ''}
  </a>`;
}
function sessionRow(s) {
  const label = s.name || s.role || s.agent || 'session';
  const id = String(s.session_id || s.id || '').slice(0, 8);
  const when = s.updated || s.ts || s.last_seen;
  return `<li class="sess"><span class="nm">${esc(label)}</span>${id ? `<span class="mono muted">${esc(id)}</span>` : ''}${s.ticket ? `<span class="chip">${esc(s.ticket)}</span>` : ''}
    ${s.context_tokens != null ? `<span class="run-ctx">${meterHTML(s.context_tokens)}</span>` : ''}${when ? `<span class="when mono">${relEl(when)}</span>` : ''}</li>`;
}
function renderRunning() {
  const d = D();
  const runs = activeRuns();
  const items = runs.map((r) => ({ key: `r:${r.id}`, hash: jh([r, ticketById(r.ticket)?.title]), html: runCard(r, ticketById(r.ticket)) }));
  if (!items.length) items.push({ key: 'none', html: '<div class="empty quiet"><span>No workers running right now.</span></div>' });
  setText($('#running-count'), runs.length ? String(runs.length) : '');
  const parts = [];
  const bo = ts(d.dispatcher.backoff_until);
  if (d.control.paused) parts.push('Paused — running workers finish, nothing new starts.');
  else if (bo && bo > Date.now()) parts.push(`Rate-limit back-off until ${new Date(bo).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} — nothing new starts until then.`);
  setText($('#running-note'), parts.join(' '));
  reconcile($('#running-list'), items);
  const sess = d.sessions || [];
  $('#session-wrap').hidden = !sess.length;
  reconcile($('#session-list'), sess.map((s) => ({ key: `s:${s.session_id || s.id || s.name}`, hash: jh(s), html: sessionRow(s) })));
}

/* ---------- milestones ---------- */
function milestoneCard(m) {
  const st = msStats(m);
  const segs = SEG_ORDER.filter((k) => st.counts[k]);
  const label = segs.map((k) => `${st.counts[k]} ${(STATUS_LABEL[k] || k).toLowerCase()}`).join(', ') || 'no tickets';
  const tgt = ts(m.target);
  return `<article class="ms">
    <div class="ms-top"><h3 class="ms-name">${esc(m.id)} · ${esc(m.name)}</h3><span class="ms-pct mono">${st.pct}<small>%</small></span></div>
    <p class="ms-goal">${mdi(m.goal || '')}</p>
    <div class="seg" role="img" aria-label="${esc(label)}">${segs.map((k) => `<span class="s-${k}" data-flex="${st.counts[k]}" title="${esc(`${st.counts[k]} ${STATUS_LABEL[k]}`)}"></span>`).join('')}</div>
    <div class="seg-legend">${segs.map((k) => `<span><i class="s-${k}"></i>${st.counts[k]} ${esc((STATUS_LABEL[k] || k).toLowerCase())}</span>`).join('') || '<span>No tickets yet</span>'}</div>
    <div class="ms-meta"><span class="chip ${m.status === 'demo-ready' ? 'live' : m.status === 'accepted' ? 'ok' : m.status === 'rejected' ? 'crit' : ''}">${esc(m.status)}</span>
      <span class="mono">${st.done}/${st.total} done</span>${tgt ? `<span class="mono">target ${esc(fmtDate(tgt))}</span>` : ''}
      ${m.status === 'demo-ready' ? `<a class="linkbtn" href="#demos">Open demo ${ic('chev')}</a>` : ''}</div>
  </article>`;
}
function renderMilestones() {
  const d = D();
  const items = d.milestones.map((m) => ({ key: m.id, hash: jh([m, msStats(m)]), html: milestoneCard(m) }));
  if (!items.length) items.push({ key: 'none', html: '<div class="empty quiet"><span>No milestones defined yet.</span></div>' });
  reconcile($('#milestone-list'), items);
}

/* ---------- digest ---------- */
async function refreshDigest() {
  const dg = D()?.digest;
  const path = dg?.path;
  if (!path) { ui.digest = { path: null, text: '', at: 0 }; return; }
  if (ui.digest.path === path && Date.now() - ui.digest.at < 120000) return;
  const prev = ui.digest.path;
  ui.digest.at = Date.now();
  ui.digest.path = path;
  if (prev !== path) ui.digest.text = '';
  try {
    const text = await fetchDoc(path);
    if (ui.digest.path !== path) return;
    ui.digest.text = splitFrontmatter(text).body;
    ui.digest.err = null;
  } catch (e) { ui.digest.err = e.message; }
  if (ui.tab === 'overview') renderDigest();
}
function renderDigest() {
  const dg = D().digest;
  setText($('#digest-date'), dg?.date ? fmtDate(dg.date) : '');
  const body = $('#digest-body');
  if (!dg?.path) { setHTML(body, '<p class="muted">No digest yet today. The project manager writes one daily.</p>'); return; }
  if (ui.digest.err && !ui.digest.text) { setHTML(body, `<p class="muted">Couldn’t load today’s digest: ${esc(ui.digest.err)}</p>`); return; }
  if (!ui.digest.text) { setHTML(body, '<p class="muted">Loading digest…</p>'); return; }
  setHTML(body, md(ui.digest.text, { base: dirname(dg.path), h: 4 }), ui.digest.text);
}

/* ---------- activity ---------- */
const KIND_WORD = { ticket: 'ticket', decision: 'decision', action: 'action', feedback: 'feedback', run: 'run', dispatcher: 'dispatcher', session: 'session', tool: 'tool', memory: 'memory', ceo: 'you', system: 'system' };
function eventRow(e) {
  const you = e.actor === 'ceo' || e.actor === 'heramb';
  const text = e.text || `${e.kind || 'event'}${e.ticket ? ` on ${e.ticket}` : ''}`;
  const hasId = e.ticket && text.includes(e.ticket);
  return `<li class="ev"><span class="ev-t">${relEl(e.ts)}</span>
    <span class="ev-main"><span class="chip${you ? ' ceo' : ''}">${esc(you ? 'you' : e.actor || 'system')}</span>
      <span class="ev-text">${mdi(text)}</span>${e.ticket && !hasId ? ticketChip(e.ticket) : ''}<span class="ev-kind">${esc(KIND_WORD[e.kind] || e.kind || '')}</span></span></li>`;
}
function renderActivity() {
  const evs = [...D().events].sort((a, b) => (ts(b.ts) ?? 0) - (ts(a.ts) ?? 0)).slice(0, 30);
  const items = evs.map((e, i) => ({ key: `${e.ts}|${e.actor}|${e.kind}|${(e.text || '').slice(0, 40)}|${i}`, hash: jh(e), html: eventRow(e) }));
  if (!items.length) items.push({ key: 'none', html: '<li class="ev"><span></span><span class="muted">No activity yet.</span></li>' });
  // duplicate-safe keys: index suffix is stable per position, ids shift as new events arrive, so key on content only
  const seen = new Map();
  for (const it of items) {
    const base = it.key.replace(/\|\d+$/, '');
    const n = (seen.get(base) || 0) + 1;
    seen.set(base, n);
    it.key = `${base}#${n}`;
  }
  reconcile($('#activity-list'), items);
}

/* ============================================================
   Board
   ============================================================ */
let boardBuilt = false;
function buildBoardSkeleton() {
  if (boardBuilt) return;
  $('#board-cols').innerHTML = STATUSES.map(([k, label]) => `<section class="col-k" data-status="${k}" aria-labelledby="ch-${k}">
    <header class="col-h"><h3 id="ch-${k}">${label}</h3><span class="count mono" data-count></span></header>
    <ul class="col-list" data-list></ul><div class="col-foot" data-foot></div></section>`).join('');
  boardBuilt = true;
}
function fillSelect(sel, opts, val) {
  const el = $(sel);
  const key = jh(opts);
  if (el._k !== key) { el.innerHTML = opts.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join(''); el._k = key; }
  if (el.value !== val) el.value = val;
  return el.value;
}
function syncFilters() {
  const d = D();
  if (ui.f.milestone && !d.milestones.some((m) => m.id === ui.f.milestone)) ui.f.milestone = '';
  ui.f.milestone = fillSelect('#f-milestone', [['', 'All milestones'], ...d.milestones.map((m) => [m.id, `${m.id} · ${m.name}`])], ui.f.milestone);
  const epics = d.epics.filter((e) => !ui.f.milestone || e.milestone === ui.f.milestone);
  ui.f.epic = fillSelect('#f-epic', [['', 'All epics'], ...epics.map((e) => [e.id, `${e.id} · ${e.title}`])], ui.f.epic);
  const owners = [...new Set(d.tickets.map((t) => t.owner).filter(Boolean))].sort();
  ui.f.owner = fillSelect('#f-owner', [['', 'All owners'], ...owners.map((o) => [o, o])], ui.f.owner);
  const q = $('#f-q');
  if (document.activeElement !== q && q.value !== ui.f.q) q.value = ui.f.q;
}
function filteredTickets() {
  const q = ui.f.q.trim().toLowerCase();
  return D().tickets.filter((t) => {
    if (t.status === 'cancelled') return false;
    if (ui.f.milestone && t.milestone !== ui.f.milestone) return false;
    if (ui.f.epic && t.epic !== ui.f.epic) return false;
    if (ui.f.owner && t.owner !== ui.f.owner) return false;
    if (q && !`${t.id} ${t.title} ${(t.tags || []).join(' ')} ${t.owner || ''} ${t.summary || ''}`.toLowerCase().includes(q)) return false;
    return true;
  });
}
function waitingOn(t) {
  return (t.decisions || []).filter((id) => decisionById(id)?.status === 'pending');
}
function ticketCard(t, live, waiting) {
  const tags = t.tags || [];
  return `<li><a class="tcard${live ? ' is-live' : ''}" href="${tkHref(t.id)}" data-fk="tc:${esc(t.id)}">
    <span class="tc-top"><span class="id mono">${esc(t.id)}</span>${waiting.length ? `<span class="lock" title="Waiting on your decision: ${esc(waiting.join(', '))}" role="img" aria-label="Waiting on your decision">${ic('lock')}</span>` : ''}${live ? '<span class="live-dot" title="A worker is running this now" role="img" aria-label="Worker running"></span>' : ''}<span class="pri mono ${esc((t.priority || '').toLowerCase())}">${esc(t.priority || '')}</span></span>
    <span class="tc-title">${esc(t.title)}</span>
    <span class="tc-meta">${ownerChip(t.owner)}${t.type ? `<span class="chip">${esc(t.type)}</span>` : ''}</span>
    ${tags.length ? `<span class="tc-tags">${tags.map((g) => (g === 'security-sensitive' ? `<span class="tag sec">${ic('shield')}security-sensitive</span>` : `<span class="tag">${esc(g)}</span>`)).join('')}</span>` : ''}
  </a></li>`;
}
function renderBoard() {
  buildBoardSkeleton();
  syncFilters();
  const all = filteredTickets();
  const liveSet = new Set(activeRuns().map((r) => r.ticket));
  const anyFilter = ui.f.milestone || ui.f.epic || ui.f.owner || ui.f.q;
  setText($('#f-count'), `${all.length} ticket${all.length === 1 ? '' : 's'}`);
  $('#f-clear').hidden = !anyFilter;
  for (const [status] of STATUSES) {
    const col = $(`.col-k[data-status="${status}"]`);
    let list = all.filter((t) => t.status === status);
    if (status === 'done') list.sort((a, b) => (ts(b.updated) ?? 0) - (ts(a.updated) ?? 0));
    else list.sort((a, b) => byPriority(a, b) || (status === 'backlog' || status === 'ready' ? (a.id < b.id ? -1 : 1) : (ts(b.updated) ?? 0) - (ts(a.updated) ?? 0)));
    const total = list.length;
    if (status === 'done' && !ui.doneAll) list = list.slice(0, DONE_LIMIT);
    const cnt = $('[data-count]', col);
    setText(cnt, String(total));
    cnt.classList.toggle('has', total > 0);
    const items = list.map((t) => {
      const waiting = waitingOn(t);
      const live = liveSet.has(t.id);
      return { key: t.id, hash: jh([t, live, waiting]), html: ticketCard(t, live, waiting) };
    });
    if (!items.length) items.push({ key: '_empty', html: `<li class="col-empty">${anyFilter ? 'No match' : 'Empty'}</li>` });
    reconcile($('[data-list]', col), items);
    if (status === 'done') {
      const foot = $('[data-foot]', col);
      setHTML(foot, total > DONE_LIMIT ? `<button class="linkbtn" type="button" data-act="done-toggle" aria-expanded="${ui.doneAll}">${ui.doneAll ? `Show latest ${DONE_LIMIT}` : `Show all ${total}`}</button>` : '', `${total}|${ui.doneAll}`);
    }
  }
}

/* ============================================================
   Decisions tab
   ============================================================ */
function decisionRow(dec) {
  const ans = dec.answer;
  const labels = (ans?.options || []).map((id) => `<span class="chip ok">${esc(optLabel(dec, id))}</span>`).join('');
  const st = dec.status;
  const stChip = st === 'defaulted' ? '<span class="chip warn">defaulted</span>'
    : st === 'vetoed' ? '<span class="chip crit">vetoed</span>'
      : st === 'acknowledged' ? '<span class="chip ok">acknowledged</span>'
        : st === 'withdrawn' ? '<span class="chip">withdrawn</span>'
          : `<span class="chip ok">${esc(st)}</span>`;
  const when = ans?.ts || dec.updated;
  const applied = (st === 'answered' || st === 'defaulted' || st === 'vetoed')
    ? (dec.applied ? `<span class="applied">${ic('check')}Applied</span>` : '<span class="applied pending">Not applied yet</span>') : '';
  return `<article class="drow">
    <div class="drow-top"><span class="badge kind-${esc(dec.kind)}">${esc(KIND_LABEL[dec.kind] || dec.kind)}</span><span class="mono muted">${esc(dec.id)}</span>${stChip}<span class="when">${when ? relEl(when) : ''}</span></div>
    <h3 class="drow-title">${esc(dec.title)}</h3>
    ${labels ? `<div class="drow-ans"><span class="muted">${st === 'defaulted' ? 'Defaulted to' : 'Answer'}</span>${labels}${ans?.via ? `<span class="mono muted">via ${esc(ans.via)}</span>` : ''}</div>` : ''}
    ${ans?.note ? `<p class="drow-note">${esc(ans.note)}</p>` : ''}
    ${st === 'withdrawn' ? `<p class="drow-note">${esc(dec.answer?.note || dec.rationale || 'Withdrawn by the factory.')}</p>` : ''}
    ${applied}
  </article>`;
}
function renderDecisions() {
  const d = D();
  const items = [];
  const heading = (key, text, n) => items.push({ key: `h:${key}`, hash: `${text}|${n}`, html: `<header class="dec-sec-h"><h2 class="sub flush">${esc(text)}</h2><span class="count mono">${n}</span></header>` });
  const pending = d.decisions.filter((x) => x.status === 'pending' && x.kind !== 'notice').sort(byDecision);
  heading('pending', 'Pending', pending.length);
  if (!pending.length) items.push({ key: 'pending-empty', html: emptyBlock('No pending decisions. Nothing is waiting on you.', true) });
  pending.forEach((x) => items.push({ key: `d:${x.id}`, hash: jh(x), html: decisionCard(x) }));

  const acts = d.actions.filter((a) => a.status === 'open');
  const doneActs = d.actions.filter((a) => a.status !== 'open').sort((a, b) => (ts(b.updated) ?? 0) - (ts(a.updated) ?? 0)).slice(0, 5);
  if (acts.length || doneActs.length) {
    heading('actions', 'Action items', acts.length);
    [...acts, ...doneActs].forEach((a) => items.push({ key: `a:${a.id}`, hash: jh(a), html: actionRow(a) }));
  }

  const answered = d.decisions.filter((x) => (x.status === 'answered' || x.status === 'defaulted') && x.kind !== 'notice')
    .sort((a, b) => (ts(b.answer?.ts || b.updated) ?? 0) - (ts(a.answer?.ts || a.updated) ?? 0));
  heading('answered', 'Answered & defaulted', answered.length);
  if (!answered.length) items.push({ key: 'answered-empty', html: '<div class="empty quiet"><span>Nothing answered yet.</span></div>' });
  answered.forEach((x) => items.push({ key: `r:${x.id}`, hash: jh(x), html: decisionRow(x) }));

  const notices = d.decisions.filter((x) => x.kind === 'notice' && x.status !== 'withdrawn')
    .sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1) || (ts(b.updated) ?? 0) - (ts(a.updated) ?? 0));
  heading('notices', 'Factory notices', notices.length);
  if (!notices.length) items.push({ key: 'notices-empty', html: '<div class="empty quiet"><span>No factory notices.</span></div>' });
  notices.forEach((x) => (x.status === 'pending'
    ? items.push({ key: `d:${x.id}`, hash: jh(x), html: decisionCard(x) })
    : items.push({ key: `r:${x.id}`, hash: jh(x), html: decisionRow(x) })));

  const withdrawn = d.decisions.filter((x) => x.status === 'withdrawn');
  if (withdrawn.length) {
    const key = 'fold:withdrawn';
    items.push({
      key, hash: jh([withdrawn, !!ui.open[key]]),
      html: `<details class="fold" data-fold="${key}"${ui.open[key] ? ' open' : ''}><summary>${ic('chev', 'chev')}Withdrawn <span class="count mono">${withdrawn.length}</span></summary><div class="fold-in">${withdrawn.map(decisionRow).join('')}</div></details>`,
    });
  }
  reconcile($('#dec-list'), items);
}

/* ---------- decision / action handlers ---------- */
function setFormErr(card, msg) {
  const p = card?.querySelector('.form-err');
  if (!p) return;
  p.textContent = msg || '';
  p.hidden = !msg;
}
const cardOf = (id) => document.querySelector(`[data-key="d:${CSS.escape(id)}"]`);
async function submitDecision(id) {
  const dec = decisionById(id);
  if (!dec || dec.status !== 'pending') return;
  const sel = formSel(dec).slice();
  const card = cardOf(id);
  if (!sel.length) {
    setFormErr(card, dec.multi ? 'Select at least one option.' : 'Choose an option first.');
    card?.querySelector('.opt-input')?.focus();
    return;
  }
  setFormErr(card, '');
  const note = (ui.text[`dec:${id}`] || '').trim();
  const ok = await act({
    path: `/api/decisions/${enc(id)}/answer`,
    body: { options: sel, note },
    mutate: (s) => { const x = s.decisions.find((q) => q.id === id); if (x) { x.status = 'answered'; x.answer = { options: sel, note, ts: new Date().toISOString(), via: 'board' }; } },
    ok: 'Decision sent. The factory picks it up on its next tick.',
    fail: 'Couldn’t send your decision',
  });
  if (ok) { delete ui.sel[id]; delete ui.text[`dec:${id}`]; }
}
async function noticeAction(id, verb) {
  const dec = decisionById(id);
  if (!dec || dec.status !== 'pending') return;
  const note = (ui.text[`dec:${id}`] || '').trim();
  const veto = verb === 'veto';
  const ok = await act({
    path: `/api/decisions/${enc(id)}/${veto ? 'veto' : 'ack'}`,
    body: { note },
    mutate: (s) => { const x = s.decisions.find((q) => q.id === id); if (x) x.status = veto ? 'vetoed' : 'acknowledged'; },
    ok: veto ? 'Vetoed. The factory will treat this as feedback.' : 'Acknowledged.',
    fail: veto ? 'Couldn’t send your veto' : 'Couldn’t acknowledge',
  });
  if (ok) delete ui.text[`dec:${id}`];
}
async function markActionDone(id) {
  const note = (ui.text[`act:${id}`] || '').trim();
  const ok = await act({
    path: `/api/actions/${enc(id)}/done`,
    body: { note },
    mutate: (s) => { const x = s.actions.find((q) => q.id === id); if (x) { x.status = 'done'; x.done_note = note; x.updated = new Date().toISOString(); } },
    ok: 'Marked done.',
    fail: 'Couldn’t mark that done',
  });
  if (ok) delete ui.text[`act:${id}`];
}
async function togglePause() {
  if (!S.data) return;
  const paused = !D().control.paused;
  await act({
    path: '/api/control',
    body: paused ? { paused: true, reason: 'Paused from the board' } : { paused: false, reason: null },
    mutate: (s) => { s.control.paused = paused; },
    ok: paused ? 'Factory paused. Running workers will finish; nothing new starts.' : 'Factory resumed.',
    fail: paused ? 'Couldn’t pause the factory' : 'Couldn’t resume the factory',
  });
}

/* ============================================================
   Library
   ============================================================ */
function renderLibrary() {
  const d = D();
  const q = ui.libQ.trim().toLowerCase();
  const docs = d.library.filter((x) => !q || `${x.title} ${x.path} ${x.group}`.toLowerCase().includes(q));
  const groups = new Map();
  for (const x of docs) { const g = x.group || 'Other'; if (!groups.has(g)) groups.set(g, []); groups.get(g).push(x); }
  const items = [];
  for (const g of [...groups.keys()].sort((a, b) => a.localeCompare(b))) {
    const list = groups.get(g).sort((a, b) => (ts(b.updated) ?? 0) - (ts(a.updated) ?? 0) || String(a.title).localeCompare(String(b.title)));
    items.push({ key: `g:${g}`, hash: `${g}|${list.length}`, html: `<h3 class="lib-gh"><span>${esc(g)}</span><span class="mono">${list.length}</span></h3>` });
    for (const x of list) {
      const cur = x.path === ui.libPath;
      items.push({
        key: `p:${x.path}`, hash: jh([x, cur]),
        html: `<a class="lib-item" href="#library/${encodeURI(x.path).replace(/[?#]/g, enc)}"${cur ? ' aria-current="page"' : ''} data-fk="li:${esc(x.path)}"><span class="lib-t">${esc(x.title || x.path)}</span><span class="lib-m mono">${esc(fmtDate(x.updated))}</span></a>`,
      });
    }
  }
  $('#lib-empty').hidden = docs.length > 0;
  reconcile($('#lib-list'), items);
  $('#lib').dataset.view = ui.libPath ? 'reader' : 'list';
  renderReader();
}
async function ensureDoc(force) {
  if (ui.tab !== 'library' && !force) return;
  const path = ui.libPath;
  if (!path) { ui.doc = null; if (S.data) renderReader(); return; }
  const entry = D()?.library.find((x) => x.path === path);
  const cur = ui.doc;
  if (cur && cur.path === path && !force && (cur.status === 'loading' || cur.updated === entry?.updated)) return;
  const silent = cur && cur.path === path && cur.status === 'ok';
  ui.doc = { path, text: silent ? cur.text : '', status: silent ? 'ok' : 'loading', err: null, updated: entry?.updated };
  if (!silent) renderReader();
  try {
    const text = await fetchDoc(path);
    if (ui.doc?.path !== path) return;
    ui.doc = { path, text, status: 'ok', err: null, updated: entry?.updated };
  } catch (e) {
    if (ui.doc?.path !== path) return;
    ui.doc = { path, text: '', status: 'error', err: e.message, updated: entry?.updated };
  }
  renderReader();
}
function renderReader() {
  const host = $('#lib-reader');
  const doc = ui.doc;
  if (!ui.libPath || !doc) {
    setHTML(host, '<div class="rd-empty"><span>Select a document to read it here.</span></div>', 'empty');
    return;
  }
  const entry = S.data?.library.find((x) => x.path === doc.path);
  const back = `<button class="btn back-only" type="button" data-act="lib-back">${ic('arrow-left')}Library</button>`;
  if (doc.status === 'loading') { setHTML(host, `<div class="rd-head"><div class="rd-top">${back}<h2 class="rd-title">${esc(entry?.title || doc.path)}</h2></div></div><div class="rd-body"><p class="muted">Loading…</p></div>`, `load:${doc.path}`); return; }
  if (doc.status === 'error') { setHTML(host, `<div class="rd-head"><div class="rd-top">${back}<h2 class="rd-title">${esc(entry?.title || doc.path)}</h2></div><div class="rd-meta mono">${esc(doc.path)}</div></div><div class="rd-body"><p class="muted">This document couldn’t be loaded: ${esc(doc.err)}</p></div>`, `err:${doc.path}:${doc.err}`); return; }
  const { fm, body } = splitFrontmatter(doc.text);
  const title = entry?.title || fm.title || doc.path;
  const bodyMd = body.replace(/^\s*#\s+(.+)\n/, (m0, h1) => (h1.trim().toLowerCase() === String(title).trim().toLowerCase() ? '' : m0));
  const upd = fm.updated || entry?.updated;
  const html = `<div class="rd-head">
      <div class="rd-top">${back}<h2 class="rd-title">${esc(title)}</h2><span class="grow"></span>
        <button class="btn" type="button" data-act="feedback" data-target="doc:${esc(doc.path)}" data-label="${esc(title)}">${ic('msg')}Give feedback</button></div>
      <div class="rd-meta"><span class="mono">${esc(doc.path)}</span>${fm.status ? `<span class="chip">${esc(fm.status)}</span>` : ''}${fm.owner ? `<span>owner ${esc(fm.owner)}</span>` : ''}${upd ? `<span class="mono">updated ${esc(fmtDate(upd))}</span>` : ''}</div>
    </div>
    <div class="rd-body md">${md(bodyMd, { base: dirname(doc.path), h: 3, ids: true })}</div>`;
  if (setHTML(host, html, `ok:${doc.path}:${doc.text.length}:${hashStr(doc.text)}:${upd}`)) host._docPath = doc.path;
}
function hashStr(s) { let h = 0; for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0; return h; }

/* ============================================================
   Demos
   ============================================================ */
function feedbackFor(target) {
  return (D().feedback || []).filter((f) => f.target === target).sort((a, b) => (ts(b.created) ?? 0) - (ts(a.created) ?? 0));
}
function feedbackRow(f) {
  const tk = (f.tickets || []).map((id) => ticketChip(id)).join('');
  return `<li class="fbrow"><div class="fbrow-top">${f.sentiment ? `<span class="chip ${f.sentiment === 'love' ? 'ok' : f.sentiment === 'change' ? 'warn' : ''}">${esc(SENTIMENT_LABEL[f.sentiment] || f.sentiment)}</span>` : ''}
    <span class="chip ${f.status === 'done' ? 'ok' : f.status === 'triaged' ? 'live' : ''}">${esc(f.status || 'new')}</span><span class="mono muted">${esc(String(f.id).startsWith('pending-') ? 'sending…' : f.id)}</span><span class="when">${relEl(f.created)}</span></div>
    ${f.text ? `<p>${esc(f.text)}</p>` : ''}
    ${f.triage_note ? `<p class="tri">Factory: ${mdi(f.triage_note)}</p>` : ''}${tk ? `<div class="chips">${tk}</div>` : ''}</li>`;
}
function mediaUrl(p) { return /^https?:\/\//i.test(p) ? p : fileUrl(p); }
function demoCard(m) {
  const demo = m.demo || {};
  const target = `demo:${m.id}`;
  const sent = ui.text[`sent:${target}`] || '';
  const fbs = feedbackFor(target);
  const links = [];
  if (demo.script) {
    links.push(/\.md$/i.test(demo.script)
      ? `<a class="linkbtn" href="#library/${encodeURI(demo.script).replace(/[?#]/g, enc)}">${ic('doc')}Demo script</a>`
      : `<a class="linkbtn" href="${esc(mediaUrl(demo.script))}" target="_blank" rel="noopener noreferrer">${ic('doc')}Demo script</a>`);
  }
  if (demo.url && /^https?:\/\//i.test(demo.url)) links.push(`<a class="linkbtn" href="${esc(demo.url)}" target="_blank" rel="noopener noreferrer">${ic('external')}Live environment</a>`);
  else if (demo.url) links.push(`<span class="mono muted">${esc(demo.url)}</span>`);
  const ready = demo.script || demo.video || demo.url;
  return `<article class="demo" aria-labelledby="dm-${esc(m.id)}">
    <header class="demo-h"><h2 id="dm-${esc(m.id)}">${esc(m.id)} · ${esc(m.name)}</h2><span class="chip ${m.status === 'demo-ready' ? 'live' : m.status === 'accepted' ? 'ok' : m.status === 'rejected' ? 'crit' : ''}">${esc(m.status)}</span></header>
    <p class="demo-goal">${mdi(m.goal || '')}</p>
    ${links.length ? `<div class="demo-links">${links.join('')}</div>` : ''}
    ${demo.video ? `<video controls preload="metadata" src="${esc(mediaUrl(demo.video))}" aria-label="Demo video for ${esc(m.name)}"></video>` : ''}
    ${ready ? '' : '<div class="empty quiet"><span>No demo package yet. It appears here when the milestone is demo-ready.</span></div>'}
    <div class="demo-fb">
      <form data-demo-form="${esc(m.id)}" autocomplete="off">
        <fieldset class="seg-radio"><legend>Your verdict</legend>
          ${['love', 'ok', 'change'].map((s) => `<label><input type="radio" name="sent-${esc(m.id)}" value="${s}" data-sent="${esc(target)}" data-fk="sent:${esc(m.id)}:${s}"${sent === s ? ' checked' : ''}><span>${SENTIMENT_LABEL[s]}</span></label>`).join('')}
        </fieldset>
        <div class="field"><label for="dfb-${esc(m.id)}">What should change, or what landed well?</label>
          <textarea id="dfb-${esc(m.id)}" rows="4" data-note="fb:${esc(target)}" data-fk="dfb:${esc(m.id)}" placeholder="Plain words are fine.">${esc(ui.text[`fb:${target}`] || '')}</textarea></div>
        <p class="form-err" role="alert" hidden></p>
        <div><button class="btn primary" type="submit">Send feedback</button></div>
      </form>
      <div><h3 class="sub flush">Feedback so far</h3>
        ${fbs.length ? `<ul class="fb-list">${fbs.map(feedbackRow).join('')}</ul>` : '<p class="muted">None yet.</p>'}</div>
    </div>
  </article>`;
}
function renderDemos() {
  const d = D();
  const items = d.milestones.map((m) => ({ key: m.id, hash: jh([m, feedbackFor(`demo:${m.id}`)]), html: demoCard(m) }));
  if (!items.length) items.push({ key: 'none', html: '<div class="empty quiet"><span>No milestones yet, so no demos.</span></div>' });
  reconcile($('#demo-list'), items);
}

/* ---------- feedback (shared by demos, tickets, docs, general) ---------- */
async function sendFeedback(target, errEl) {
  const textKey = `fb:${target}`, sentKey = `sent:${target}`;
  const text = (ui.text[textKey] || '').trim();
  const sentiment = ui.text[sentKey] || null;
  if (!text && !sentiment) {
    const msg = 'Add a few words or pick a verdict first.';
    if (errEl) { errEl.textContent = msg; errEl.hidden = false; }
    return false;
  }
  if (errEl) errEl.hidden = true;
  const draft = { text: ui.text[textKey], sentiment: ui.text[sentKey] };
  delete ui.text[textKey]; delete ui.text[sentKey];
  resetFeedbackControls(target);
  const ok = await act({
    path: '/api/feedback',
    body: { target, text, sentiment },
    mutate: (s) => { s.feedback.push({ id: `pending-${Date.now()}`, target, text, sentiment, status: 'new', triage_note: null, tickets: [], created: new Date().toISOString() }); },
    ok: 'Feedback sent. The factory triages it into tickets.',
    fail: 'Couldn’t send your feedback',
  });
  if (!ok) {
    if (draft.text != null) ui.text[textKey] = draft.text;
    if (draft.sentiment != null) ui.text[sentKey] = draft.sentiment;
    restoreFeedbackControls(target);
  }
  return ok;
}
function resetFeedbackControls(target) {
  for (const el of $$(`[data-note="${CSS.escape(`fb:${target}`)}"]`)) el.value = '';
  for (const el of $$(`input[data-sent="${CSS.escape(target)}"]`)) el.checked = false;
  if (ui.fb?.target === target) { $('#fb-text').value = ''; $$('#fb-sent input').forEach((i) => { i.checked = false; }); }
}
function restoreFeedbackControls(target) {
  for (const el of $$(`[data-note="${CSS.escape(`fb:${target}`)}"]`)) el.value = ui.text[`fb:${target}`] || '';
  for (const el of $$(`input[data-sent="${CSS.escape(target)}"]`)) el.checked = el.value === ui.text[`sent:${target}`];
  if (ui.fb?.target === target) {
    $('#fb-text').value = ui.text[`fb:${target}`] || '';
    $$('#fb-sent input').forEach((i) => { i.checked = i.value === ui.text[`sent:${target}`]; });
  }
}

const fbDlg = () => $('#fb-dialog');
function openFeedback(target, label) {
  ui.fb = { target, label };
  $('#fb-title').textContent = 'Give feedback';
  setText($('#fb-target'), `on ${target.startsWith('general') ? 'the factory in general' : `${label || target}`}${target.includes(':') ? ` · ${target}` : ''}`);
  $('#fb-text').value = ui.text[`fb:${target}`] || '';
  $$('#fb-sent input').forEach((i) => { i.checked = i.value === ui.text[`sent:${target}`]; });
  $('#fb-err').hidden = true;
  if (!fbDlg().open) fbDlg().showModal();
  $('#fb-text').focus();
}
function closeFeedback() { if (fbDlg().open) fbDlg().close(); }

/* ============================================================
   Ticket drawer
   ============================================================ */
const dlg = () => $('#drawer');
function openDrawer(id) {
  if (ui.drawer?.id === id && dlg().open) return;
  const same = ui.drawer?.id === id;
  ui.drawer = same ? ui.drawer : { id, detail: null, err: null, loading: false, tailRun: null, tailPinned: false, tailText: '', tailFetched: null };
  if (!dlg().open) dlg().showModal();
  if (!same) $('#dr-scroll').scrollTop = 0;
  if (S.data) renderDrawer();
  loadTicket(id);
  startTail();
}
function closeDrawerUI() {
  if (!ui.drawer && !dlg().open) return;
  ui.drawer = null;
  stopTail();
  if (dlg().open) dlg().close();
}
function requestCloseDrawer() {
  if (!parseHash().t) { closeDrawerUI(); return; }
  if (ui.drawerPushed) { ui.drawerPushed = false; history.back(); return; }
  const r = parseHash();
  history.replaceState(null, '', `${location.pathname}${location.search}#${buildHash(r.tab, r.arg)}`);
  route();
}
function navTicket(id) {
  const r = parseHash();
  history.replaceState(null, '', `${location.pathname}${location.search}#${buildHash(r.tab, r.arg, id)}`);
  route();
}
async function loadTicket(id) {
  const dr = ui.drawer;
  if (!dr || dr.id !== id || dr.loading) return;
  dr.loading = true;
  try { const d = await fetchTicket(id); if (ui.drawer?.id === id) { dr.detail = d; dr.err = null; } }
  catch (e) { if (ui.drawer?.id === id) dr.err = e; }
  dr.loading = false;
  if (ui.drawer?.id === id) { dr.loaded = true; renderDrawer(); pollTail(); }
}
function refreshDrawer() { if (ui.drawer && dlg().open) loadTicket(ui.drawer.id); }

function drawerKv(label, val) { return val ? `<div><dt>${esc(label)}</dt><dd>${val}</dd></div>` : ''; }
function drawerSection(title, inner) { return inner ? `<section class="dr-sec"><h3>${esc(title)}</h3>${inner}</section>` : ''; }
function runDuration(r) {
  const a = ts(r.started), b = ts(r.ended);
  return a && b ? fmtDur((b - a) / 1000) : (a ? fmtDur((Date.now() - a) / 1000) : '');
}
function drawerBody(t, dr) {
  const d = D();
  const epic = d.epics.find((e) => e.id === t.epic);
  const ms = d.milestones.find((m) => m.id === t.milestone);
  const kv = [
    drawerKv('Owner', ownerChip(t.owner)),
    drawerKv('Working stage', t.stage_role && t.stage_role !== t.owner ? ownerChip(t.stage_role) : ''),
    drawerKv('Milestone', t.milestone ? `${esc(t.milestone)}${ms ? ` · ${esc(ms.name)}` : ''}` : ''),
    drawerKv('Epic', t.epic ? `${esc(t.epic)}${epic ? ` · ${esc(epic.title)}` : ''}` : ''),
    drawerKv('Priority', t.priority ? `<span class="mono">${esc(t.priority)}</span>` : ''),
    drawerKv('Attempts', t.attempts ? `<span class="mono">${esc(t.attempts)}</span>` : ''),
    drawerKv('Parity', (t.parity_refs || []).length ? `<span class="chips">${t.parity_refs.map((p) => `<span class="chip">${esc(p)}</span>`).join('')}</span>` : ''),
    drawerKv('Updated', t.updated ? relEl(t.updated) : ''),
  ].join('');
  const tags = (t.tags || []).length ? `<div class="chips">${t.tags.map((g) => (g === 'security-sensitive' ? `<span class="tag sec">${ic('shield')}security-sensitive</span>` : `<span class="chip">${esc(g)}</span>`)).join('')}</div>` : '';
  const waiting = (t.decisions || []).map((id) => {
    const dec = decisionById(id);
    return dec ? `<a class="chip ${dec.status === 'pending' ? 'warn' : ''}" href="#decisions" title="${esc(dec.title)}">${dec.status === 'pending' ? ic('lock') : ''}${esc(id)} · ${esc(dec.title)} (${esc(dec.status)})</a>` : `<span class="chip">${esc(id)}</span>`;
  });
  const deps = (t.depends_on || []).map((id) => {
    const dt = ticketById(id);
    return `<a class="chip tlink" href="#" data-ticket-nav="${esc(id)}" title="${esc(dt?.title || id)}">${esc(id)}${dt ? ` · ${esc(dt.status)}` : ''}</a>`;
  });
  const notes = [...(t.notes || [])].reverse();
  const hist = [...(t.history || [])].reverse();
  const runs = (dr.detail?.runs?.length ? dr.detail.runs : allRuns().filter((r) => r.ticket === t.id));
  const handoffs = dr.detail?.handoffs || [];
  const link = (p) => (/\.md$/i.test(p) ? `<a class="linkbtn" href="#library/${encodeURI(p).replace(/[?#]/g, enc)}">${ic('doc')}${esc(p)}</a>` : `<span class="mono">${esc(p)}</span>`);
  const links = t.links ? Object.entries(t.links).filter(([, v]) => v).map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${typeof v === 'string' ? link(v) : esc(jh(v))}</dd></div>`).join('') : '';
  const result = t.result ? (typeof t.result === 'string' ? `<div class="md">${md(t.result, { h: 4 })}</div>` : `<pre class="md-code tail">${esc(JSON.stringify(t.result, null, 2))}</pre>`) : '';
  return [
    `<dl class="kv">${kv}</dl>`,
    tags,
    drawerSection('Summary', t.summary ? `<div class="md">${md(t.summary, { h: 4 })}</div>` : ''),
    drawerSection('Waiting on you', waiting.length ? `<div class="chips">${waiting.join('')}</div>` : ''),
    drawerSection('Acceptance criteria', (t.acceptance || []).length ? `<ol class="ac-list">${t.acceptance.map((a) => `<li><span>${mdi(a)}</span></li>`).join('')}</ol>` : ''),
    drawerSection('Details', t.body ? `<div class="md">${md(t.body, { h: 4 })}</div>` : ''),
    drawerSection('Result', result),
    drawerSection('Depends on', deps.length ? `<div class="chips">${deps.join('')}</div>` : ''),
    drawerSection('Notes', notes.length ? `<ol class="timeline">${notes.map((n) => `<li><div class="tl-h"><span class="chip">${esc(n.by || '')}</span>${relEl(n.ts)}</div><div class="tl-b">${mdi(n.text || '')}</div></li>`).join('')}</ol>` : ''),
    drawerSection('History', hist.length ? `<table class="hist"><tbody>${hist.map((h) => `<tr><td>${relEl(h.ts)}</td><td><span class="mono">${esc(h.from || '∅')} → ${esc(h.to || '')}</span> <span class="muted">${esc(h.by || '')}</span>${h.note ? `<br>${mdi(h.note)}` : ''}</td></tr>`).join('')}</tbody></table>` : ''),
    drawerSection('Runs', runs.length ? runs.map((r) => `<div class="runrow">${r.status === 'running' ? '<span class="live-dot" aria-hidden="true"></span>' : ''}<span class="mono">${esc(r.id)}</span><span class="chip">${esc(r.role || '')}</span><span class="mono muted">${esc(r.stage || '')}</span>${modelChip(r)}<span class="chip ${r.status === 'done' ? 'ok' : r.status === 'failed' || r.status === 'killed' ? 'crit' : r.status === 'running' ? 'live' : ''}">${esc(r.status || '')}</span><span class="mono muted">${esc(runDuration(r))}</span>${r.cost_usd ? `<span class="mono muted">$${Number(r.cost_usd).toFixed(2)}</span>` : ''}<span class="grow"></span><button class="linkbtn" type="button" data-act="tail" data-run="${esc(r.id)}">View log</button></div>`).join('') : ''),
    drawerSection('Handoffs', handoffs.length ? `<ul class="chips">${handoffs.map((h) => `<li class="chip">${esc(typeof h === 'string' ? h : h.path || jh(h))}</li>`).join('')}</ul>` : ''),
    drawerSection('Links', links ? `<dl class="kv">${links}</dl>` : ''),
  ].join('');
}
function renderDrawer() {
  const dr = ui.drawer;
  if (!dr || !S.data) return;
  const list = ticketById(dr.id);
  const t = { ...(list || {}), ...(dr.detail || {}) };
  const tt = t.id ? t : { id: dr.id };
  setHTML($('#dr-ids'), `<span class="id mono">${esc(dr.id)}</span>${tt.type ? `<span class="chip">${esc(tt.type)}</span>` : ''}${tt.status ? statusChip(tt.status) : ''}${waitingOn(tt).length ? `<span class="chip warn" title="Waiting on your decision">${ic('lock')}needs you</span>` : ''}${activeRuns().some((r) => r.ticket === dr.id) ? '<span class="chip live"><span class="live-dot" aria-hidden="true"></span>running</span>' : ''}`, jh([dr.id, tt.type, tt.status, waitingOn(tt), activeRuns().some((r) => r.ticket === dr.id)]));
  setText($('#dr-title'), t.title || (dr.err ? 'Ticket not found' : 'Loading…'));
  setHTML($('#dr-foot'), `<button class="btn" type="button" data-act="feedback" data-target="ticket:${esc(dr.id)}" data-label="${esc(dr.id)}">${ic('msg')}Give feedback</button><span class="grow"></span><button class="btn" type="button" data-act="close-drawer">Close</button>`, dr.id);
  // default live tail: the ticket's active run (unless the CEO picked another)
  if (!dr.tailPinned) {
    const live = activeRuns().find((r) => r.ticket === dr.id);
    if (live && dr.tailRun !== live.id) { dr.tailRun = live.id; dr.tailFetched = null; }
    if (!live && dr.tailRun && !dr.tailPinned) { /* keep showing the last run's log until closed */ }
  }
  renderLive();
  if (!list && !dr.detail) {
    setHTML($('#dr-body'), dr.err ? `<p class="muted">This ticket couldn’t be loaded: ${esc(dr.err.message || dr.err)}</p>` : '<p class="muted">Loading…</p>', `ph:${!!dr.err}`);
    return;
  }
  setHTML($('#dr-body'), drawerBody(t, dr), jh([t, (t.decisions || []).map((id) => decisionById(id)?.status), allRuns().filter((r) => r.ticket === dr.id).map((r) => [r.id, r.status]), (D().tickets || []).filter((x) => (t.depends_on || []).includes(x.id)).map((x) => x.status)]));
}
function renderLive() {
  const dr = ui.drawer;
  const host = $('#dr-live');
  if (!dr?.tailRun) { setHTML(host, '', 'none'); return; }
  const run = allRuns().find((r) => r.id === dr.tailRun) || (dr.detail?.runs || []).find((r) => r.id === dr.tailRun);
  const live = run?.status === 'running';
  const changed = setHTML(host, `<section class="live" aria-label="Run log">
    <div class="live-h">${live ? '<span class="live-dot" aria-hidden="true"></span>' : ''}<h3>${live ? 'Live run' : 'Run log'}</h3><span class="mono">${esc(dr.tailRun)}</span>${run ? `<span class="chip">${esc(run.role || '')}</span><span class="mono muted">${esc(run.stage || '')}</span>` : ''}
      <button class="linkbtn" type="button" data-act="tail-hide">Hide</button></div>
    <pre class="tail" id="dr-tail" tabindex="0" aria-label="Tail of run ${esc(dr.tailRun)}"></pre></section>`, `${dr.tailRun}|${live}|${run?.role}|${run?.stage}`);
  if (changed) paintTail(true);
}
const TOOL_LINE = /^\s*(▸|›|→|\[tool|tool:|\$ )/i;
function paintTail(force) {
  const pre = $('#dr-tail');
  const dr = ui.drawer;
  if (!pre || !dr) return;
  const text = dr.tailText || (dr.tailFetched ? '' : 'Loading log…');
  if (!force && pre._k === text) return;
  const near = force || pre.scrollHeight - pre.scrollTop - pre.clientHeight < 40;
  pre.innerHTML = text.split('\n').map((l) => `<span class="${TOOL_LINE.test(l) ? 'tl-tool' : ''}">${esc(l)}</span>`).join('\n');
  pre._k = text;
  if (near) pre.scrollTop = pre.scrollHeight;
}
let tailTimer = null;
function startTail() { stopTail(); tailTimer = setInterval(() => pollTail(), 2500); }
function stopTail() { clearInterval(tailTimer); tailTimer = null; }
async function pollTail(force) {
  const dr = ui.drawer;
  if (!dr || !dr.tailRun || !dlg().open) return;
  if (document.hidden && !force) return;
  const id = dr.tailRun;
  const run = allRuns().find((r) => r.id === id);
  if (!force && dr.tailFetched === id && run?.status !== 'running') return;
  try {
    const text = await fetchTail(id);
    if (ui.drawer?.tailRun !== id) return;
    dr.tailText = text; dr.tailFetched = id;
  } catch (e) { dr.tailText = `Couldn’t load the log: ${e.message}`; dr.tailFetched = id; }
  paintTail();
}

/* ============================================================
   Ticker (relative times, elapsed, countdowns, status pill)
   ============================================================ */
function tick() {
  const now = Date.now();
  for (const el of $$('[data-rel]')) { const t = ts(el.dataset.rel); if (t != null) setText(el, fmtRel(t, now)); }
  for (const el of $$('[data-elapsed]')) { const t = ts(el.dataset.elapsed); if (t != null) setText(el, fmtDur((now - t) / 1000)); }
  for (const el of $$('[data-until]')) { const t = ts(el.dataset.until); if (t != null) setText(el, t <= now ? 'now' : fmtCountdown((t - now) / 1000)); }
  updateChrome();
}

/* ============================================================
   Events
   ============================================================ */
document.addEventListener('click', (e) => {
  const nav = e.target.closest('[data-ticket-nav]');
  if (nav) { e.preventDefault(); navTicket(nav.dataset.ticketNav); return; }
  const anchor = e.target.closest('a[data-anchor]');
  if (anchor) {
    e.preventDefault();
    const root = anchor.closest('.md');
    const target = root?.querySelector(`[id="md-${CSS.escape(anchor.dataset.anchor)}"]`);
    target?.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    return;
  }
  // backdrop click closes a modal dialog (content fills the dialog, so a hit on the dialog itself is the backdrop)
  if (e.target.tagName === 'DIALOG') {
    if (e.target.id === 'drawer') requestCloseDrawer(); else if (e.target.id === 'fb-dialog') closeFeedback();
    return;
  }
  const a = e.target.closest('[data-act]');
  if (!a) return;
  const act2 = a.dataset.act;
  switch (act2) {
    case 'tab': location.hash = tabHash(a.dataset.tab); break;
    case 'pause': togglePause(); break;
    case 'theme': setTheme(currentTheme() === 'dark' ? 'light' : 'dark'); break;
    case 'retry': pollSoon(); break;
    case 'dec-submit': submitDecision(a.dataset.id); break;
    case 'dec-ack': noticeAction(a.dataset.id, 'ack'); break;
    case 'dec-veto': noticeAction(a.dataset.id, 'veto'); break;
    case 'act-done': markActionDone(a.dataset.id); break;
    case 'feedback': openFeedback(a.dataset.target, a.dataset.label); break;
    case 'close-drawer': requestCloseDrawer(); break;
    case 'close-fb': closeFeedback(); break;
    case 'done-toggle': ui.doneAll = !ui.doneAll; renderBoard(); break;
    case 'filters-clear':
      ui.f = { milestone: '', epic: '', owner: '', q: '' };
      $('#f-q').value = '';
      renderBoard();
      break;
    case 'lib-back': location.hash = buildHash('library'); break;
    case 'tail': { const dr = ui.drawer; if (dr) { dr.tailRun = a.dataset.run; dr.tailPinned = true; dr.tailFetched = null; dr.tailText = ''; renderLive(); pollTail(true); $('#dr-live').scrollIntoView({ block: 'nearest' }); } break; }
    case 'tail-hide': { const dr = ui.drawer; if (dr) { dr.tailRun = null; dr.tailPinned = true; renderLive(); } break; }
    default: break;
  }
});

document.addEventListener('input', (e) => {
  const t = e.target;
  if (t.dataset?.note) { ui.text[t.dataset.note] = t.value; return; }
  if (t.id === 'fb-text' && ui.fb) { ui.text[`fb:${ui.fb.target}`] = t.value; return; }
  if (t.dataset?.filter) { ui.f[t.dataset.filter] = t.value; if (t.dataset.filter === 'milestone') ui.f.epic = ''; renderBoard(); return; }
  if (t.id === 'lib-q') { ui.libQ = t.value; renderLibrary(); }
});
document.addEventListener('change', (e) => {
  const t = e.target;
  if (t.dataset?.opt) {
    const id = t.dataset.opt;
    const fs = t.closest('fieldset');
    ui.sel[id] = $$('input.opt-input', fs).filter((i) => i.checked).map((i) => i.value);
    setFormErr(cardOf(id), '');
    return;
  }
  if (t.dataset?.sent) {
    const target = t.dataset.sent === 'x' ? ui.fb?.target : t.dataset.sent;
    if (target) ui.text[`sent:${target}`] = t.value;
    return;
  }
  if (t.dataset?.filter) { ui.f[t.dataset.filter] = t.value; if (t.dataset.filter === 'milestone') ui.f.epic = ''; renderBoard(); }
});
document.addEventListener('toggle', (e) => {
  const d = e.target;
  if (!d.matches?.('details')) return;
  if (d.dataset.prev) {
    ui.open[d.dataset.prev] = d.open;
    const body = d.querySelector('.prev-body');
    body.innerHTML = d.open ? previewBody(d.dataset.kind, d.dataset.url, d.dataset.label) : '';
  } else if (d.dataset.fold) ui.open[d.dataset.fold] = d.open;
}, true);
document.addEventListener('submit', (e) => {
  const f = e.target;
  if (f.id === 'fb-form') {
    e.preventDefault();
    const target = ui.fb?.target;
    if (!target) return;
    sendFeedback(target, $('#fb-err')).then((ok) => { if (ok) closeFeedback(); });
  } else if (f.dataset?.demoForm) {
    e.preventDefault();
    sendFeedback(`demo:${f.dataset.demoForm}`, f.querySelector('.form-err'));
  }
});
document.addEventListener('keydown', (e) => {
  // Cmd/Ctrl+Enter inside a decision note submits it
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && e.target.dataset?.note?.startsWith('dec:')) {
    const id = e.target.dataset.note.slice(4);
    const dec = decisionById(id);
    if (dec && dec.kind !== 'notice') { e.preventDefault(); submitDecision(id); }
  }
  // tablist arrows
  if (e.target.matches?.('[role="tab"]') && ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) {
    const i = TABS.indexOf(e.target.dataset.tab);
    const n = e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : (i + (e.key === 'ArrowRight' ? 1 : -1) + TABS.length) % TABS.length;
    e.preventDefault();
    location.hash = tabHash(TABS[n]);
    $(`#tab-${TABS[n]}`).focus();
  }
});
for (const id of ['drawer', 'fb-dialog']) {
  $(`#${id}`).addEventListener('cancel', (e) => {
    e.preventDefault();
    if (id === 'drawer') requestCloseDrawer(); else closeFeedback();
  });
}
$('#fb-dialog').addEventListener('close', () => { ui.fb = null; });
window.addEventListener('hashchange', route);
document.addEventListener('visibilitychange', () => { if (!document.hidden) pollSoon(); });
matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', updateThemeBtn);

/* ============================================================
   Boot
   ============================================================ */
updateThemeBtn();
applyTabs();
route();
updateChrome();
setInterval(tick, 1000);
poll();

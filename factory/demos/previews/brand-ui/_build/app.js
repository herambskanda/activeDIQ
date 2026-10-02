/* activeDIQ brand+UI preview app. Shared by a/b/c; the direction only changes tokens, layout CSS, nav and wordmark. PREVIEW — sample data. */
(() => {
const DIR = document.body.dataset.dir;
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const I = (n, c = '') => `<svg class="ic ${c}" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n]}</svg>`;
const ICONS = {
  lock: '<rect x="3.5" y="7" width="9" height="6.5" rx="1"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>', ban: '<circle cx="8" cy="8" r="5.5"/><path d="M4.2 11.8l7.6-7.6"/>',
  clock: '<circle cx="8" cy="8" r="5.5"/><path d="M8 5v3.2l2 1.3"/>', shield: '<path d="M8 2l5 2v4c0 3-2.2 5-5 6-2.8-1-5-3-5-6V4z"/>', check: '<path d="M3.5 8.5l3 3 6-7"/>',
  warn: '<path d="M8 2.5l6 10.5H2z"/><path d="M8 7v3M8 11.6v.1"/>', x: '<path d="M4 4l8 8M12 4l-8 8"/>', search: '<circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/>',
  home: '<path d="M2.5 7.5L8 3l5.5 4.5V13h-11z"/>', users: '<circle cx="6" cy="6" r="2.5"/><path d="M1.5 13c.4-2.6 2.2-4 4.5-4s4.1 1.4 4.5 4"/><path d="M10.5 3.8a2.3 2.3 0 0 1 0 4.4M12 9.3c1.4.5 2.3 1.6 2.5 3.7"/>',
  broom: '<path d="M9.5 2.5l4 4M8.5 5.5l2 2L6 12l-3.5 1 1-3.5z"/>', chart: '<path d="M2.5 13.5h11M4.5 11V8M8 11V4.5M11.5 11V6.5"/>', inbox: '<path d="M2.5 9l1.5-5.5h8L13.5 9v4h-11z"/><path d="M2.5 9h3.5l.8 1.5h2.4L10 9h3.5"/>',
  audit: '<path d="M3 3.5h10M3 8h10M3 12.5h6"/>', bolt: '<path d="M9 2L3.5 9H8l-1 5L12.5 7H8z"/>', gear: '<circle cx="8" cy="8" r="2"/><path d="M8 1.8v2M8 12.2v2M1.8 8h2M12.2 8h2M3.6 3.6L5 5M11 11l1.4 1.4M12.4 3.6L11 5M5 11l-1.4 1.4"/>',
  copy: '<rect x="5.5" y="5.5" width="8" height="8" rx="1"/><path d="M10.5 5.5v-2h-8v8h2"/>', down: '<path d="M4 6l4 4 4-4"/>', right: '<path d="M6 4l4 4-4 4"/>', bell: '<path d="M4 11V7.5a4 4 0 0 1 8 0V11l1 1.5H3zM6.5 14h3"/>',
  jobs: '<path d="M13 8a5 5 0 1 1-1.5-3.5M13 2.5V5h-2.5"/>', eye: '<path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/>',
  eyeoff: '<path d="M2 2l12 12M6.4 4a6 6 0 0 1 1.6-.5c4 0 6.5 4.5 6.5 4.5a11 11 0 0 1-2 2.6M4.3 5.6A11 11 0 0 0 1.5 8S4 12.5 8 12.5c.9 0 1.7-.2 2.4-.5"/>',
  plus: '<path d="M8 3v10M3 8h10"/>', upload: '<path d="M8 11V3M4.5 6.5L8 3l3.5 3.5M3 13h10"/>', download: '<path d="M8 3v8M4.5 7.5L8 11l3.5-3.5M3 13h10"/>', refresh: '<path d="M13 8a5 5 0 1 1-1.5-3.5M13 2.5V5h-2.5"/>', mail: '<rect x="2" y="3.5" width="12" height="9" rx="1"/><path d="M2.5 4.5L8 9l5.5-4.5"/>', pin: '<path d="M8 14V9M5 9h6l-.8-4 1.3-1.5h-7L5.8 5z"/>',
};
const SECTIONS = [['home','Home','Home'],['users','Directory','Directory'],['broom','Clean up','Clean up'],['chart','Reports','Reports'],['inbox','Requests','Requests'],['audit','Audit','Audit'],['bolt','Automation','Automation'],['gear','Settings','Settings']];
const DIRKIDS = ['Users','Groups','Computers','Contacts','Service accounts','Explorer','Deleted objects'];

/* ---------- formatting ---------- */
const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const p2 = (n) => String(n).padStart(2, '0');
const fmtDate = (t) => { const d = new Date(t); return `${d.getUTCDate()} ${MON[d.getUTCMonth()]} ${d.getUTCFullYear()}`; };
const fmtTime = (t) => { const d = new Date(t); return `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`; };
const fmtAbs = (t) => `${fmtDate(t)}, ${fmtTime(t)} UTC`;
const rel = (t) => { const m = Math.round((NOW - t) / 60000); if (m < 1) return 'just now'; if (m < 60) return `${m} min ago`; const h = Math.round(m / 60); if (h < 24) return `${h} h ago`; const d = Math.round(h / 24); return `${d} d ago`; };
const num = (n) => n.toLocaleString('en-US');
const days = (t) => Math.floor((t - NOW) / DAY);

/* ---------- derived state ---------- */
const edits = new Map();            // sam -> {disabled?, locked?, pwdSet?}
const extraHistory = new Map();     // sam -> [events]
const stat = (u) => {
  const s = [];
  if (u.tier0) s.push(['t0', 'Tier 0', 'shield']);
  if (u.locked) s.push(['warn', 'Locked', 'lock']);
  if (u.disabled) s.push(['muted', 'Disabled', 'ban']);
  else if (u.pwdExpires && u.pwdExpires < NOW) s.push(['warn', 'Password expired', 'clock']);
  else if (u.pwdExpires && days(u.pwdExpires) <= 30) s.push(['warn', `Expires in ${days(u.pwdExpires)} d`, 'clock']);
  return s;
};
const chip = ([k, label, icon]) => `<span class="chip chip-${k}">${I(icon)}<span>${esc(label)}</span></span>`;
const chips = (u) => { const s = stat(u); return s.length ? s.map(chip).join('') : `<span class="chip chip-ok">${I('check')}<span>Enabled</span></span>`; };
const VIEWS = [
  ['all', 'All users', () => true],
  ['locked', 'Locked out now', (u) => u.locked],
  ['disabled', 'Disabled', (u) => u.disabled],
  ['expired', 'Password expired', (u) => !u.disabled && u.pwdExpires && u.pwdExpires < NOW],
  ['expiring', 'Expiring ≤ 30 d', (u) => !u.disabled && u.pwdExpires && u.pwdExpires >= NOW && days(u.pwdExpires) <= 30],
  ['inactive', 'Inactive > 90 d', (u) => !u.disabled && (u.lastLogon === null || NOW - u.lastLogon > 90 * DAY)],
];
const counts = () => Object.fromEntries(VIEWS.map(([k, , f]) => [k, USERS.reduce((n, u) => n + (f(u) ? 1 : 0), 0)]));
let COUNTS = counts();
const SEARCHKEY = new Map(USERS.map((u) => [u.sam, fold(`${u.name} ${u.sam} ${u.upn} ${u.mail} ${u.dn}`).toLowerCase()]));
function query() {
  const f = VIEWS.find((v) => v[0] === S.view)[2]; const words = fold(S.q).toLowerCase().split(/\s+/).filter(Boolean);
  let r = USERS.filter((u) => f(u) && words.every((w) => SEARCHKEY.get(u.sam).includes(w)));
  const k = S.sort.key, d = S.sort.dir === 'asc' ? 1 : -1;
  const val = { changed: (u) => u.n, name: (u) => fold(u.name).toLowerCase(), sam: (u) => u.sam, last: (u) => u.lastLogon ?? -1, pwd: (u) => u.pwdExpires ?? Infinity }[k];
  r = r.slice().sort((a, b) => (val(a) < val(b) ? -1 : val(a) > val(b) ? 1 : 0) * d);
  return r;
}
const PAGE = 50;

/* ---------- state + hash routing ---------- */
const S = { route: 'list', sam: null, tab: 'overview', view: 'all', q: '', sort: { key: 'changed', dir: 'asc' }, page: 0, sel: new Set(), allMatching: false, sheet: null, compact: false, step: {}, lastFocus: null };
function readHash() {
  const [path, qs = ''] = location.hash.slice(1).split('?'); const p = new URLSearchParams(qs); const m = /^\/users\/([^/]+)/.exec(path || '');
  S.view = VIEWS.some((v) => v[0] === p.get('view')) ? p.get('view') : 'all'; S.q = p.get('q') || ''; S.page = Math.max(0, +p.get('page') || 0);
  S.route = m && BY_SAM.has(decodeURIComponent(m[1])) ? 'user' : 'list'; S.sam = m ? decodeURIComponent(m[1]) : null; S.tab = ['overview', 'groups', 'history'].includes(p.get('tab')) ? p.get('tab') : 'overview';
  S.sel = new Set(); S.allMatching = false; S.sheet = null; S.step = {};
  if (p.get('sel') === 'page' || p.get('sel') === 'all' || p.get('sel') === 'few') {
    const rows = query().slice(S.page * PAGE, S.page * PAGE + PAGE);
    if (p.get('sel') === 'few') rows.slice(0, 6).forEach((u) => S.sel.add(u.sam)); else rows.forEach((u) => S.sel.add(u.sam));
    S.allMatching = p.get('sel') === 'all';
  }
  const sh = p.get('sheet');
  if (sh === 'disable' && S.sel.size) S.sheet = { kind: 'disable' };
  if (['reset', 'unlock'].includes(sh) && S.sam) { S.sheet = { kind: sh }; S.step = { sent: p.get('code') === '1' || p.get('code') === 'typed', code: p.get('code') === 'typed' ? '482916' : '', typed: '' }; }
  if (sh === 'quick' && S.sam) S.sheet = { kind: 'quick' };
  if (sh === 'done' && S.sam) { const u = BY_SAM.get(S.sam); const was = u.locked; if (was) applyReset(u, 'reset+unlock', true); S.sheet = { kind: 'done-reset', mode: 'reset+unlock', at: NOW + 60000, wasLocked: true }; }
  if (p.get('compact') === '1') S.compact = true;
}
function writeHash() {
  const p = new URLSearchParams(); if (S.view !== 'all') p.set('view', S.view); if (S.q) p.set('q', S.q); if (S.page) p.set('page', S.page); if (S.route === 'user' && S.tab !== 'overview') p.set('tab', S.tab);
  const h = (S.route === 'user' ? `#/users/${encodeURIComponent(S.sam)}` : '#/users') + (p.toString() ? '?' + p : '');
  history.replaceState(null, '', h);
}

/* ---------- shell ---------- */
const BRAND = { a: 'wm-a', b: 'wm-b', c: 'wm-c' }[DIR];
const wordmark = () => ({ a: '<span class="wm wm-a"><span class="wm-1">active</span><span class="wm-2">DIQ</span></span>', b: '<span class="wm wm-b"><span class="wm-1">active</span><span class="wm-2">DIQ</span></span>', c: '<span class="wm wm-c"><span class="wm-1">active</span><span class="wm-2">DIQ</span></span>' }[DIR]);
const appIcon = (px) => window.APP_ICON.replaceAll('{PX}', px);
const navItem = (s) => { const [ic, key, label] = s; const on = key === 'Directory'; return `<a href="#/users" class="nav-i${on ? ' on' : ''}"${on ? ' aria-current="page"' : ` data-stub="${esc(label)}"`}>${I(ic)}<span class="nav-l">${esc(label)}</span>${key === 'Requests' ? '<span class="nav-n" aria-label="3 waiting for me">3</span>' : ''}</a>`; };
function pinned() { const c = COUNTS; return [['locked', 'Locked out now'], ['expiring', 'Expiring ≤ 30 d'], ['inactive', 'Inactive > 90 d']].map(([k, l]) => `<a href="#/users?view=${k}" class="nav-p" data-view="${k}">${I('pin')}<span class="nav-l">${l}</span><span class="nav-c mono">${num(c[k])}</span></a>`).join(''); }
function shell() {
  const search = `<button class="search" id="search" type="button" aria-keyshortcuts="/" data-palette>${I('search')}<span class="search-t">Search users, groups, computers, actions</span><kbd>/</kbd></button>`;
  const right = `<div class="tb-r"><button class="tb-btn" type="button" data-stub="Jobs">${I('jobs')}<span>2 jobs running</span></button><button class="tb-btn icon" type="button" aria-label="Notifications" data-stub="Notifications">${I('bell')}</button><button class="tb-btn icon" type="button" aria-label="Help" data-stub="Help"><span aria-hidden="true">?</span></button><button class="avatar" type="button" aria-label="Account: Dana Whitfield, Help desk tier 1" data-stub="Account menu">DW</button></div>`;
  const scope = `<span class="scope" title="Your delegation scope (sample)">${I('shield')}<span>Scope: Help desk · tier 1</span></span>`;
  let h;
  if (DIR === 'a') h = `<div class="app"><nav class="nav" aria-label="Primary"><div class="brand"><a href="#/users" class="brand-l" aria-label="activeDIQ home">${appIcon(24)}${wordmark()}</a></div>${SECTIONS.map((s) => { const x = navItem(s); return s[1] === 'Directory' ? x + `<div class="nav-kids">${DIRKIDS.map((k, i) => `<a href="#/users" class="nav-k${i === 0 ? ' on' : ''}"${i === 0 ? ' aria-current="page"' : ` data-stub="${k}"`}>${k}</a>`).join('')}</div>` : x; }).join('')}<div class="nav-h">Pinned views</div>${pinned()}</nav><div class="col"><header class="topbar">${search}${scope}${right}</header><main id="main" class="main"></main></div><aside id="sheet" class="sheet" hidden></aside></div>`;
  if (DIR === 'b') h = `<div class="app"><header class="topbar"><a href="#/users" class="brand-l" aria-label="activeDIQ home">${appIcon(32)}${wordmark()}</a><nav class="tabsnav" aria-label="Primary">${SECTIONS.map((s) => { const [ic, key, label] = s; return `<a href="#/users" class="tn${key === 'Directory' ? ' on' : ''}"${key === 'Directory' ? ' aria-current="page"' : ` data-stub="${label}"`}>${esc(label)}${key === 'Requests' ? '<span class="nav-n" aria-label="3 waiting for me">3</span>' : ''}</a>`; }).join('')}</nav>${search}${scope}${right}</header><div class="subbar" aria-label="Directory">${DIRKIDS.map((k, i) => `<a href="#/users" class="sb${i === 0 ? ' on' : ''}"${i === 0 ? ' aria-current="page"' : ` data-stub="${k}"`}>${k}</a>`).join('')}<span class="sb-sp"></span>${pinned().replace(/nav-p/g, 'sb-p')}</div><div class="body"><main id="main" class="main"></main><aside id="sheet" class="sheet" hidden></aside></div></div>`;
  if (DIR === 'c') h = `<div class="app"><nav class="rail" aria-label="Primary"><a href="#/users" class="rail-brand" aria-label="activeDIQ home">${appIcon(28)}</a>${SECTIONS.map((s) => { const [ic, key, label] = s; const on = key === 'Directory'; return `<div class="rail-g${on ? ' on' : ''}"><a href="#/users" class="rail-i${on ? ' on' : ''}" aria-label="${label}"${on ? ' aria-current="page"' : ` data-stub="${label}"`}>${I(ic)}${key === 'Requests' ? '<span class="rail-dot" aria-label="3 waiting for me"></span>' : ''}</a><div class="fly" role="group" aria-label="${label}"><div class="fly-t">${label}</div>${on ? DIRKIDS.map((k, i) => `<a href="#/users" class="fly-k${i === 0 ? ' on' : ''}"${i === 0 ? ' aria-current="page"' : ` data-stub="${k}"`}>${k}</a>`).join('') + '<div class="fly-h">Pinned views</div>' + pinned() : `<span class="fly-m">Preview covers Directory › Users</span>`}</div></div>`; }).join('')}</nav><div class="col"><header class="topbar">${wordmark()}${search}${scope}${right}</header><main id="main" class="main"></main></div><aside id="sheet" class="sheet" hidden></aside></div>`;
  document.body.insertAdjacentHTML('afterbegin', h);
}

/* ---------- list ---------- */
function listHTML() {
  const rows = query(); const total = rows.length; const start = S.page * PAGE; const pageRows = rows.slice(start, start + PAGE);
  const nSel = S.allMatching ? total : S.sel.size; const pageAll = pageRows.length && pageRows.every((u) => S.sel.has(u.sam));
  const sortBtn = (k, label) => `<th scope="col" aria-sort="${S.sort.key === k ? (S.sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}"><button class="th-b" type="button" data-sort="${k}">${label}<span class="sort" aria-hidden="true">${S.sort.key === k ? (S.sort.dir === 'asc' ? '▲' : '▼') : ''}</span></button></th>`;
  const tb = pageRows.map((u) => `<tr data-sam="${esc(u.sam)}" class="${S.sel.has(u.sam) ? 'sel' : ''}"><td class="c-chk"><input type="checkbox" aria-label="Select ${esc(u.name)}" ${S.sel.has(u.sam) ? 'checked' : ''}></td><td class="c-name"><a href="#/users/${encodeURIComponent(u.sam)}" class="rowlink" title="${esc(u.name)}">${esc(u.name)}</a></td><td class="mono c-sam">${esc(u.sam)}</td><td class="mono c-upn" title="${esc(u.upn)}">${esc(u.upn)}</td><td class="mono c-ou" title="${esc(u.dn)}">${esc([...u.ou].reverse().join(' / '))}</td><td class="c-last">${u.lastLogon ? `<span class="mono">${fmtDate(u.lastLogon)}</span>` : '<span class="dim">Never</span>'}</td><td class="c-status">${chips(u)}</td></tr>`).join('');
  const vtabs = VIEWS.map(([k, l]) => `<button class="vt${S.view === k ? ' on' : ''}" type="button" role="tab" aria-selected="${S.view === k}" data-view="${k}">${l}<span class="vt-c mono">${num(COUNTS[k])}</span></button>`).join('');
  const banner = pageAll && !S.allMatching && total > pageRows.length ? `<div class="selbanner" role="status">All ${pageRows.length} users on this page are selected. <button type="button" class="link" data-act="select-all">Select all ${num(total)} matching users</button></div>` : S.allMatching ? `<div class="selbanner" role="status">All ${num(total)} matching users are selected — not just the ${pageRows.length} on this page. <button type="button" class="link" data-act="clear">Clear selection</button></div>` : '';
  const bulk = nSel ? `<div class="bulk" role="region" aria-label="Bulk actions"><span class="bulk-n"><b class="mono">${num(nSel)}</b> selected</span><button class="btn" type="button" data-act="bulk-disable">${I('ban')}Disable ${num(nSel)} ${nSel === 1 ? 'user' : 'users'}</button><button class="btn" type="button" data-act="bulk-export">${I('download')}Export ${num(nSel)} to CSV</button><button class="btn ghost" type="button" data-act="clear">Clear <kbd>Esc</kbd></button></div>` : '';
  const empty = `<tr class="empty"><td colspan="7"><div class="empty-b"><div class="empty-t">No users match “${esc(S.q)}” in ${esc(VIEWS.find((v) => v[0] === S.view)[1])}</div><div class="dim">Search covers display name, logon name, UPN, email and DN.</div><button class="btn" type="button" data-act="reset-filters">Clear search and view</button></div></td></tr>`;
  return `<div class="page-h"><div><h1>Users</h1><p class="sub"><span class="mono">${num(USERS.length)}</span> users · 3 domains · <span class="pv-tag">sample data</span></p></div><div class="page-a"><button class="btn" type="button" data-stub="Import from a file">${I('upload')}Import from a file</button><button class="btn primary" type="button" data-stub="New user">${I('plus')}New user <kbd>N</kbd></button></div></div>
  <div class="views" role="tablist" aria-label="Saved views">${vtabs}</div>
  <div class="toolbar"><label class="fld grow">${I('search')}<span class="sr">Filter users</span><input id="filter" type="search" value="${esc(S.q)}" placeholder="Filter by name, logon name, UPN, email or DN" autocomplete="off" spellcheck="false"></label><button class="btn" type="button" data-act="density" aria-pressed="${S.compact}">${S.compact ? 'Comfortable rows' : 'Compact rows'}</button><button class="btn" type="button" data-stub="Column chooser">Columns</button></div>
  ${bulk}${banner}
  <div class="tablewrap"><table class="tbl ${S.compact ? 'alt' : ''}" aria-label="Users"><thead><tr><th scope="col" class="c-chk"><input type="checkbox" id="chkall" aria-label="Select all ${pageRows.length} on this page" ${pageAll ? 'checked' : ''}></th>${sortBtn('name', 'Display name')}${sortBtn('sam', 'Logon name')}<th scope="col" class="c-upn">UPN</th><th scope="col">Location</th>${sortBtn('last', 'Last logon')}<th scope="col">Status</th></tr></thead><tbody>${total ? tb : empty}</tbody></table></div>
  <div class="pager"><span class="mono">${total ? `${num(start + 1)}–${num(start + pageRows.length)} of ${num(total)}` : '0 of 0'}</span><span class="dim">Sorted by ${S.sort.key === 'changed' ? 'recently changed' : esc({ name: 'display name', sam: 'logon name', last: 'last logon' }[S.sort.key]) + (S.sort.dir === 'asc' ? ' ↑' : ' ↓')} · lockout state as of <span class="mono">${fmtTime(NOW)} UTC</span></span><span class="sp"></span><button class="btn" type="button" data-act="prev" ${S.page === 0 ? 'disabled' : ''}>‹ Previous</button><button class="btn" type="button" data-act="next" ${start + PAGE >= total ? 'disabled' : ''}>Next ›</button></div>`;
}

/* ---------- user detail ---------- */
function userHistory(u) {
  const dir = []; const act = (extraHistory.get(u.sam) || []);
  if (u.lockedAt || u.lockouts) { for (let i = 0; i < Math.max(u.lockouts, 1); i++) dir.push({ ts: (u.lockedAt || NOW - 90 * 60000) - i * 21 * 60000, stream: 'Directory', what: `Account locked out · caller ${u.lockSource || 'WS-LON-0421'}`, who: 'Observed on DC LON-DC02', ev: 'Event 4740' }); }
  dir.push({ ts: u.pwdSet, stream: 'Directory', what: 'Password changed', who: u.sam, ev: 'Event 4723' }); dir.push({ ts: u.created, stream: 'Directory', what: 'Account created', who: 'HR onboarding policy', ev: 'Event 4720' });
  return [...act, ...dir].sort((a, b) => b.ts - a.ts);
}
const kv = (rows) => `<dl class="kv">${rows.map(([k, v, sub]) => `<div class="kv-r"><dt>${k}${sub ? `<span class="kv-s mono">${sub}</span>` : ''}</dt><dd>${v}</dd></div>`).join('')}</dl>`;
const copyBtn = (t, l) => `<button type="button" class="copy" data-copy="${esc(t)}" aria-label="Copy ${l}">${I('copy')}</button>`;
function userHTML() {
  const u = BY_SAM.get(S.sam); const hist = userHistory(u);
  const actions = u.tier0 ? `<span class="t0note">${I('shield')}Tier 0 account: write actions are disabled. Export and report actions only.</span><button class="btn" type="button" data-stub="Export">Export</button>`
    : u.disabled ? `<button class="btn primary" type="button" data-stub="Enable">Enable <kbd>D</kbd></button><button class="btn" type="button" data-stub="Offboard">Offboard <kbd>O</kbd></button><button class="btn" type="button" data-stub="Edit">Edit <kbd>E</kbd></button>`
    : u.locked ? `<button class="btn primary" type="button" data-act="open-reset">Reset &amp; unlock <kbd>R</kbd></button><button class="btn" type="button" data-act="open-unlock">Unlock <kbd>U</kbd></button><button class="btn" type="button" data-stub="Add to group">Add to group <kbd>A</kbd></button><button class="btn ghost" type="button" data-stub="More actions" aria-haspopup="menu">More ${I('down')}</button>`
    : `<button class="btn primary" type="button" data-act="open-reset">Reset password <kbd>R</kbd></button><button class="btn" type="button" data-stub="Add to group">Add to group <kbd>A</kbd></button><button class="btn" type="button" data-stub="Edit">Edit <kbd>E</kbd></button><button class="btn ghost" type="button" data-stub="More actions" aria-haspopup="menu">More ${I('down')}</button>`;
  const banner = u.locked ? `<div class="banner warn" role="status">${I('lock')}<div><b>Locked out since ${fmtTime(u.lockedAt)} UTC</b> · ${u.lockouts}× today · last from <span class="mono">${esc(u.lockSource)}</span> <button type="button" class="link" data-tab="history">Show lockout events</button></div></div>` : '';
  const tabs = [['overview', 'Overview'], ['groups', `Groups <span class="vt-c mono">${u.groups.length}</span>`], ['history', 'History']].map(([k, l]) => `<button class="tab${S.tab === k ? ' on' : ''}" type="button" role="tab" aria-selected="${S.tab === k}" data-tab="${k}">${l}</button>`).join('');
  const activity = `<section class="panel act"><h2>Recent activity</h2>${tl(hist.slice(0, 5))}<button type="button" class="link" data-tab="history">All history</button></section>`;
  let body;
  if (S.tab === 'groups') body = `<section class="panel"><h2>Member of ${u.groups.length} groups</h2><table class="mini"><thead><tr><th scope="col">Group</th><th scope="col">Type</th></tr></thead><tbody>${u.groups.map(([g, t]) => `<tr><td class="mono">${esc(g)}</td><td>${/Tier 0/.test(t) ? `<span class="chip chip-t0">${I('shield')}<span>Tier 0</span></span> ` : ''}${esc(t.replace(' · Tier 0', ''))}</td></tr>`).join('')}</tbody></table></section>`;
  else if (S.tab === 'history') body = `<section class="panel"><h2>History</h2><p class="dim">Two streams, one timeline: what the directory observed, and what was done through activeDIQ.</p>${tl(hist)}</section>`;
  else body = `<div class="grid"><section class="panel"><h2>Account</h2>${kv([['Status', chips(u)], ['Last logon', u.lastLogon ? `<span class="mono">${fmtAbs(u.lastLogon)}</span> <span class="dim">${rel(u.lastLogon)}</span>` : 'Never'], ['Password last set', `<span class="mono">${fmtAbs(u.pwdSet)}</span>`], ['Password expires', u.pwdNever ? 'Never (policy exception)' : `<span class="mono">${fmtDate(u.pwdExpires)}</span> <span class="dim">${days(u.pwdExpires) < 0 ? `${-days(u.pwdExpires)} d ago` : `in ${days(u.pwdExpires)} d`}</span>`], ['Created', `<span class="mono">${fmtDate(u.created)}</span>`], ['Entra ID', u.entra ? 'Synced to Entra' : 'Not synced']])}</section>
  <section class="panel"><h2>Identity</h2>${kv([['Display name', esc(u.name)], ['Logon name', `<span class="mono">${esc(u.sam)}</span>${copyBtn(u.sam, 'logon name')}`, 'sAMAccountName'], ['UPN', `<span class="mono">${esc(u.upn)}</span>${copyBtn(u.upn, 'UPN')}`], ['Email', `<span class="mono">${esc(u.mail)}</span>`, 'mail'], ['Distinguished name', `<span class="mono wrapany">${esc(u.dn)}</span>${copyBtn(u.dn, 'distinguished name')}`, 'distinguishedName']])}<details class="more"><summary>More identifiers</summary>${kv([['SID', `<span class="mono">${u.sid}</span>`], ['objectGUID', `<span class="mono">${u.guid}</span>`]])}</details></section>
  <section class="panel"><h2>Organization</h2>${kv([['Title', esc(u.title)], ['Department', esc(u.dept)], ['Office', esc(u.office)], ['Manager', esc(u.manager)]])}</section>${activity}</div>`;
  return `<nav class="crumb" aria-label="Breadcrumb"><a href="#/users" data-act="back">Directory</a><span aria-hidden="true">›</span><a href="#/users" data-act="back">Users</a><span aria-hidden="true">›</span><span class="mono">${DOMAIN}</span></nav>
  <header class="objh"><div class="objh-main"><div class="avatar-l" aria-hidden="true">${esc(u.name.split(/\s+/).filter((w) => /^\p{L}/u.test(w)).slice(0, 2).map((w) => [...w][0]).join(''))}</div><div class="objh-t"><h1 title="${esc(u.name)}">${esc(u.name)}</h1><div class="objh-id mono"><span>${esc(u.kind)}</span><span>${esc(u.sam)}</span><span>${esc(u.upn)}</span></div><div class="objh-ch">${chips(u)}${u.entra ? `<span class="chip chip-muted">${I('check')}<span>Synced to Entra</span></span>` : ''}</div></div></div><div class="objh-a">${actions}</div></header>
  ${banner}<div class="tabs" role="tablist">${tabs}</div><div class="tabbody">${body}</div>`;
}
function tl(ev) { return `<ol class="tl">${ev.map((e) => `<li><span class="tl-t mono" title="${fmtAbs(e.ts)}">${fmtDate(e.ts)} ${fmtTime(e.ts)}</span><span class="tl-s">${e.stream === 'activeDIQ' ? 'activeDIQ' : 'Directory'}</span><span class="tl-w">${esc(e.what)}<span class="dim"> · ${esc(e.who)}${e.ev ? ' · ' + esc(e.ev) : ''}</span></span></li>`).join('')}</ol>`; }

/* ---------- sheets ---------- */
const PASSPHRASE = 'copper-lantern-wobble-7-stream';
function head(title, sub) { return `<header class="sh-h"><div><h2 id="sh-t">${title}</h2>${sub ? `<p class="dim">${sub}</p>` : ''}</div><button class="btn ghost icon" type="button" data-act="close" aria-label="Close (Esc)">${I('x')}</button></header>`; }
function impactReset(u, mode) {
  const rows = [];
  if (mode !== 'unlock') { rows.push(['change', 'Password', `Replaced. Current password was set <span class="mono">${fmtDate(u.pwdSet)}</span>; the previous one is not stored and <b>cannot be restored</b>.`]); rows.push(['change', 'At next logon', 'User must choose a new password.']); }
  if (u.locked && S.step.unlock !== false) rows.push(['change', 'Lockout', `Cleared. Locked since <span class="mono">${fmtTime(u.lockedAt)} UTC</span> by <span class="mono">${esc(u.lockSource)}</span>; ${u.lockouts} lockouts today.`]);
  if (u.locked && S.step.unlock === false) rows.push(['same', 'Lockout', 'Stays locked. The user still cannot sign in.']);
  rows.push(['same', 'Not changed', 'Group memberships, mailbox, Entra licence and manager.']);
  rows.push(['note', 'Sign-ins', `Existing sign-ins keep working until their Kerberos tickets expire (10 h by default).${u.entra ? ' The new password reaches Entra through your existing sync.' : ''}`]);
  rows.push(['note', 'Recorded as', `Dana Whitfield · Help desk tier 1 · ${fmtTime(NOW)} UTC · caller verified by code.`]);
  return `<section class="impact" aria-labelledby="imp-t"><h3 id="imp-t">What will change</h3><ul class="imp">${rows.filter(Boolean).map(([k, t, d]) => `<li class="imp-${k}"><span class="imp-k">${k === 'change' ? 'Changes' : k === 'same' ? 'Unchanged' : 'Note'}</span><span><b>${t}</b> — ${d}</span></li>`).join('')}</ul></section>`;
}
function sheetReset(mode) {
  const u = BY_SAM.get(S.sam); const st = S.step; const verified = st.sent && /^\d{6}$/.test(st.code || '');
  const doPw = mode !== 'unlock';
  const pw = doPw ? `<section class="sh-s"><h3>New password</h3><div class="pwbox"><input class="mono" id="pw" type="${st.show ? 'text' : 'password'}" value="${PASSPHRASE}" readonly aria-label="Generated password"><button class="btn icon" type="button" data-act="pw-show" aria-label="${st.show ? 'Hide' : 'Show'} password">${I(st.show ? 'eyeoff' : 'eye')}</button><button class="btn icon" type="button" data-act="pw-copy" aria-label="Copy password">${I('copy')}</button><button class="btn icon" type="button" data-act="pw-regen" aria-label="Generate another">${I('refresh')}</button></div><p class="dim">Generated in your browser from the domain's password policy; sent only in this request, never stored or logged. Read it to the caller.</p><label class="chk"><input type="checkbox" checked disabled> User must change password at next logon</label></section>` : '';
  const unl = u.locked && doPw ? `<label class="chk"><input type="checkbox" id="unl" ${st.unlock === false ? '' : 'checked'}> Unlock the account <span class="dim">(locked since ${fmtTime(u.lockedAt)} UTC)</span></label>` : '';
  const ver = `<section class="sh-s"><h3>Verify the caller</h3>${st.sent ? `<p class="ok-t">${I('check')}Code sent to <span class="mono">•••• 4821</span> <span class="dim">· expires in 5 min</span></p>` : `<p class="dim">Send a one-time code to the phone on file, then ask the caller to read it back.</p><button class="btn" type="button" data-act="send-code">${I('mail')}Send code to •••• 4821</button>`}<label class="fld2"><span>Code from caller</span><input id="code" class="mono" inputmode="numeric" maxlength="6" autocomplete="one-time-code" value="${esc(st.code || '')}" ${st.sent ? '' : 'disabled'} placeholder="6 digits"></label></section>`;
  const label = mode === 'unlock' ? 'Unlock account' : u.locked && st.unlock !== false ? 'Reset password and unlock' : 'Reset password';
  return `${head(mode === 'unlock' ? 'Unlock account' : u.locked ? 'Reset password and unlock' : 'Reset password', `<span class="mono">${esc(u.sam)}</span> · ${esc(u.name)}`)}<div class="sh-b">${pw}${unl}${ver}${impactReset(u, mode)}</div><footer class="sh-f"><span class="why" id="why">${verified ? 'Caller verified. Ready.' : st.sent ? 'Enter the 6-digit code to continue.' : 'Send the code to continue.'}</span><button class="btn ghost" type="button" data-act="close">Cancel <kbd>Esc</kbd></button><button class="btn primary" type="button" id="confirm" data-act="confirm-reset" ${verified ? '' : 'aria-disabled="true" disabled'}>${label} <kbd>⏎</kbd></button></footer>`;
}
function bulkTargets() {
  const rows = query(); const base = S.allMatching ? rows : rows.filter((u) => S.sel.has(u.sam));
  const t0 = base.filter((u) => u.tier0), already = base.filter((u) => u.disabled && !u.tier0), change = base.filter((u) => !u.disabled && !u.tier0);
  return { base, t0, already, change };
}
function sheetDisable() {
  const { base, t0, already, change } = bulkTargets(); const big = change.length > 100; const need = `disable ${change.length}`;
  const entra = change.filter((u) => u.entra).length; const locked = change.filter((u) => u.locked).length; const names = (a, n = 4) => a.slice(0, n).map((u) => `<li><span>${esc(u.name)}</span> <span class="mono dim">${esc(u.sam)}</span></li>`).join('') + (a.length > n ? `<li class="dim">and ${num(a.length - n)} more</li>` : '');
  const typedOk = !big || (S.step.typed || '').trim().toLowerCase() === need;
  return `${head(`Disable ${num(change.length)} ${change.length === 1 ? 'user' : 'users'}`, `${num(base.length)} selected${S.allMatching ? ' (all matching the current view)' : ''}`)}<div class="sh-b"><section class="impact" aria-labelledby="imp-t"><h3 id="imp-t">What will change</h3><ul class="imp"><li class="imp-change"><span class="imp-k">Changes</span><span><b>${num(change.length)} accounts will be disabled</b> — they can no longer sign in to the domain${entra ? `; ${num(entra)} are synced and are blocked in Entra after the next sync` : ''}.${locked ? ` ${locked} of them are locked out now.` : ''}</span></li>
  ${t0.length ? `<li class="imp-skip"><span class="imp-k">Skipped</span><span><b>${num(t0.length)} Tier 0 ${t0.length === 1 ? 'account' : 'accounts'}</b> — never writable from help-desk scope.<ul class="names">${names(t0)}</ul></span></li>` : ''}
  ${already.length ? `<li class="imp-same"><span class="imp-k">Unchanged</span><span><b>${num(already.length)} already disabled</b> — nothing to do.</span></li>` : ''}
  <li class="imp-same"><span class="imp-k">Unchanged</span><span>Group memberships, mailboxes and licences are kept. Nothing is deleted.</span></li>
  <li class="imp-note"><span class="imp-k">Undo</span><span><b>Reversible.</b> “Undo” on the result re-enables exactly these ${num(change.length)} accounts, and it stays in History.</span></li></ul>
  <details class="more"><summary>The ${num(Math.min(change.length, 5))} first of ${num(change.length)} accounts</summary><ul class="names">${names(change, 5)}</ul></details></section>
  ${big ? `<section class="sh-s"><h3>Type to confirm</h3><label class="fld2"><span>Type <b class="mono">${need}</b> — more than 100 accounts</span><input id="typed" class="mono" value="${esc(S.step.typed || '')}" autocomplete="off" spellcheck="false"></label></section>` : ''}</div>
  <footer class="sh-f"><span class="why">${change.length === 0 ? 'Nothing to disable in this selection.' : typedOk ? 'Ready.' : `Type “${need}” to continue.`}</span><button class="btn ghost" type="button" data-act="close">Cancel <kbd>Esc</kbd></button><button class="btn primary danger" type="button" id="confirm" data-act="confirm-disable" ${typedOk && change.length ? '' : 'aria-disabled="true" disabled'}>Disable ${num(change.length)} ${change.length === 1 ? 'user' : 'users'}</button></footer>`;
}
function sheetQuick() {
  const u = BY_SAM.get(S.sam); return `${head(esc(u.name), `<span class="mono">${esc(u.sam)}</span>`)}<div class="sh-b"><div class="objh-ch">${chips(u)}</div>${u.locked ? `<div class="banner warn" role="status">${I('lock')}<div><b>Locked out since ${fmtTime(u.lockedAt)} UTC</b> · ${u.lockouts}× today</div></div>` : ''}${kv([['UPN', `<span class="mono">${esc(u.upn)}</span>`], ['Title', esc(u.title)], ['Location', esc(u.ou.slice().reverse().join(' / '))], ['Last logon', u.lastLogon ? `<span class="mono">${fmtAbs(u.lastLogon)}</span>` : 'Never'], ['Password expires', u.pwdNever ? 'Never' : `<span class="mono">${fmtDate(u.pwdExpires)}</span>`]])}</div><footer class="sh-f"><span class="why"></span>${u.locked && !u.tier0 ? '<button class="btn" type="button" data-act="quick-reset">Reset &amp; unlock <kbd>R</kbd></button>' : ''}<a class="btn primary" href="#/users/${encodeURIComponent(u.sam)}" data-open-page>Open page <kbd>⏎</kbd></a></footer>`;
}
function sheetDone() {
  const sh = S.sheet; const u = BY_SAM.get(S.sam); const m = sh.mode;
  return `${head(m === 'unlock' ? 'Account unlocked' : sh.wasLocked ? 'Password reset and account unlocked' : 'Password reset', `<span class="mono">${esc(u.sam)}</span> · ${esc(u.name)}`)}<div class="sh-b"><div class="banner ok" role="status">${I('check')}<div><b>Done at ${fmtTime(sh.at)} UTC.</b> ${m === 'unlock' ? 'The account is unlocked.' : 'Tell the caller the password; they must change it at next logon.'}</div></div><ul class="imp"><li class="imp-change"><span class="imp-k">Changed</span><span>${m === 'unlock' ? '' : '<b>Password</b> replaced · must change at next logon<br>'}${sh.wasLocked ? '<b>Lockout</b> cleared' : ''}</span></li><li class="imp-note"><span class="imp-k">Recorded</span><span>Dana Whitfield · Help desk tier 1 · ${fmtTime(sh.at)} UTC · caller verified by code. <button type="button" class="link" data-act="view-history">View in History</button></span></li><li class="imp-note"><span class="imp-k">Undo</span><span>Not available: the previous password is not stored.</span></li></ul></div><footer class="sh-f"><span class="why"></span><button class="btn primary" type="button" data-act="close">Close <kbd>Esc</kbd></button></footer>`;
}
function renderSheet() {
  const el = $('#sheet'); const sh = S.sheet; document.body.classList.toggle('sheet-open', !!sh);
  if (!sh) { el.hidden = true; el.innerHTML = ''; return; }
  const html = { reset: () => sheetReset('reset+unlock'), unlock: () => sheetReset('unlock'), disable: sheetDisable, quick: sheetQuick, 'done-reset': sheetDone }[sh.kind]();
  const fresh = el.hidden; el.hidden = false; el.setAttribute('role', 'dialog'); el.setAttribute('aria-modal', 'false'); el.setAttribute('aria-labelledby', 'sh-t'); el.innerHTML = html;
  if (fresh || sh.focus) { const t = $('#code:not([disabled])') || $('[data-act=send-code]') || $('#typed') || $('#confirm:not([disabled])') || $('.sh-f .btn.primary') || $('.sh-h button'); if (sh.kind === 'reset' || sh.kind === 'unlock') { ($('[data-act=send-code]') || $('#code') || t)?.focus(); } else t?.focus(); sh.focus = false; }
}

/* ---------- render + events ---------- */
function toast(msg, undo) { const t = document.createElement('div'); t.className = 'toast'; t.innerHTML = `<span>${msg}</span>${undo ? '<button type="button" class="link" data-undo>Undo</button>' : ''}<button type="button" class="toast-x" aria-label="Dismiss">${I('x')}</button>`; $('#toasts').append(t); t.querySelector('.toast-x').onclick = () => t.remove(); if (undo) t.querySelector('[data-undo]').onclick = () => { undo(); t.remove(); }; setTimeout(() => t.remove(), 12000); }
function render(keepScroll) {
  COUNTS = counts(); const main = $('#main'); const y = main.scrollTop; main.innerHTML = S.route === 'user' ? userHTML() : listHTML();
  document.title = S.route === 'user' ? `${BY_SAM.get(S.sam).name} · Users · activeDIQ preview ${DIR.toUpperCase()}` : `Users · activeDIQ preview ${DIR.toUpperCase()}`;
  document.body.dataset.route = S.route; if (keepScroll) main.scrollTop = y; renderSheet(); document.querySelectorAll('.nav-c').forEach((n) => { const v = n.closest('[data-view]')?.dataset.view; if (v) n.textContent = num(COUNTS[v]); }); document.querySelectorAll('.sb-p .nav-c').forEach((n) => { const v = n.closest('[data-view]')?.dataset.view; if (v) n.textContent = num(COUNTS[v]); }); writeHash(); updateStates();
}
function closeSheet() { const had = S.sheet; S.sheet = null; renderSheet(); if (had && S.lastFocus && document.contains(S.lastFocus)) S.lastFocus.focus(); }
function openSheet(sh, from) { S.lastFocus = from || document.activeElement; S.sheet = { ...sh, focus: true }; S.step = sh.kind === 'reset' || sh.kind === 'unlock' ? { sent: false, code: '', show: false } : { typed: '' }; renderSheet(); }
function doReset(mode) {
  const u = BY_SAM.get(S.sam); const wasLocked = u.locked && !(S.step.unlock === false); applyReset(u, mode, wasLocked);
  S.sheet = { kind: 'done-reset', mode, at: NOW + 60000, wasLocked }; render(true);
  $('#sheet .sh-f .btn')?.focus();
}
function applyReset(u, mode, wasLocked) {
  if (wasLocked) u.locked = false; if (mode !== 'unlock') { u.pwdSet = NOW + 60000; u.pwdExpires = u.pwdNever ? null : u.pwdSet + 90 * DAY; }
  const ev = extraHistory.get(u.sam) || []; const via = 'Dana Whitfield · Help desk tier 1 · caller verified by code';
  if (mode !== 'unlock') ev.push({ ts: NOW + 60000, stream: 'activeDIQ', what: 'Password reset · must change at next logon', who: via }); if (wasLocked) ev.push({ ts: NOW + 60000, stream: 'activeDIQ', what: 'Account unlocked', who: via });
  extraHistory.set(u.sam, ev);
}
function doDisable() {
  const { change, t0, already } = bulkTargets(); const prev = change.map((u) => u.sam); const n = change.length;
  change.forEach((u) => { u.disabled = true; const e = extraHistory.get(u.sam) || []; e.push({ ts: NOW + 60000, stream: 'activeDIQ', what: 'Account disabled · bulk action', who: 'Dana Whitfield · Help desk tier 1' }); extraHistory.set(u.sam, e); });
  S.sel = new Set(); S.allMatching = false; S.sheet = null; render(true);
  toast(`<b>Disabled ${num(n)} ${n === 1 ? 'user' : 'users'}.</b> ${t0.length ? `${t0.length} Tier 0 skipped. ` : ''}${already.length ? `${already.length} were already disabled.` : ''}`, () => { prev.forEach((s) => { BY_SAM.get(s).disabled = false; const e = extraHistory.get(s); e.push({ ts: NOW + 120000, stream: 'activeDIQ', what: 'Account re-enabled · undo of bulk disable', who: 'Dana Whitfield · Help desk tier 1' }); }); render(true); toast(`Re-enabled ${num(prev.length)} users.`); });
}
function go(h) { location.hash = h; }
document.addEventListener('click', (e) => {
  const t = e.target.closest('a, button, th, tr[data-sam]'); if (!t) return;
  if (t.dataset.stub !== undefined) { e.preventDefault(); toast(`<b>${esc(t.dataset.stub)}</b> is outside this preview (it covers Directory › Users and one user).`); return; }
  if (t.matches('.rowlink')) { e.preventDefault(); const sam = t.closest('tr').dataset.sam; if (e.ctrlKey || e.metaKey || e.detail === 0) { S.route = 'user'; S.sam = sam; S.tab = 'overview'; S.sheet = null; render(); $('#main').scrollTop = 0; $('#main h1')?.focus?.(); } else { S.sam = sam; openSheet({ kind: 'quick' }, t); } return; }
  if (t.matches('[data-open-page]')) { e.preventDefault(); S.route = 'user'; S.sheet = null; S.tab = 'overview'; render(); return; }
  if (t.matches('[data-act=back]')) { e.preventDefault(); S.route = 'list'; S.sheet = null; render(); return; }
  if (t.dataset.view !== undefined && (t.matches('.vt') || t.matches('[data-view]'))) { e.preventDefault(); S.route = 'list'; S.view = t.dataset.view; S.page = 0; S.sel = new Set(); S.allMatching = false; S.sheet = null; render(); return; }
  if (t.dataset.tab) { S.tab = t.dataset.tab; S.sheet = null; render(true); return; }
  if (t.dataset.sort) { const k = t.dataset.sort; S.sort = { key: k, dir: S.sort.key === k && S.sort.dir === 'asc' ? 'desc' : 'asc' }; S.page = 0; render(true); return; }
  if (t.matches('[data-palette]')) { $('#search').blur(); toast('Search and the command palette are specified in the IA (§5). This preview filters the table below with “Filter users”.'); return; }
  if (t.dataset.copy) { navigator.clipboard?.writeText(t.dataset.copy).catch(() => {}); toast(`Copied <span class="mono">${esc(t.dataset.copy.slice(0, 48))}${t.dataset.copy.length > 48 ? '…' : ''}</span>`); return; }
  const a = t.dataset.act; if (!a) return;
  const act = {
    'select-all': () => { S.allMatching = true; render(true); }, clear: () => { S.sel = new Set(); S.allMatching = false; render(true); },
    'bulk-disable': () => openSheet({ kind: 'disable' }, t), 'bulk-export': () => { const rows = query(); const sel = S.allMatching ? rows : rows.filter((u) => S.sel.has(u.sam)); if (sel.length > 10000) return toast('Export of ' + num(sel.length) + ' rows runs as a job and lands in Audit › Jobs.'); const csv = ['sAMAccountName,displayName,userPrincipalName,distinguishedName', ...sel.map((u) => [u.sam, u.name, u.upn, u.dn].map((v) => '"' + String(v).replace(/"/g, '""') + '"').join(','))].join('\r\n'); try { const a2 = document.createElement('a'); a2.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a2.download = 'users-preview.csv'; a2.click(); } catch (_) {} toast(`Exported ${num(sel.length)} rows (preview data).`); },
    density: () => { S.compact = !S.compact; render(true); }, 'reset-filters': () => { S.q = ''; S.view = 'all'; render(); }, prev: () => { S.page--; render(true); }, next: () => { S.page++; render(true); },
    'open-reset': () => openSheet({ kind: 'reset' }, t), 'open-unlock': () => openSheet({ kind: 'unlock' }, t), 'quick-reset': () => { S.route = 'user'; render(); openSheet({ kind: 'reset' }, $('[data-act=open-reset]')); },
    close: closeSheet, 'send-code': () => { S.step.sent = true; renderSheet(); $('#code').focus(); }, 'pw-show': () => { S.step.show = !S.step.show; renderSheet(); $('[data-act=pw-show]').focus(); }, 'pw-copy': () => toast('Password copied. It is not stored or logged (preview).'), 'pw-regen': () => toast('Another passphrase generated (preview shows one fixed sample).'),
    'confirm-reset': () => { if (!t.disabled) doReset(S.sheet.kind === 'unlock' ? 'unlock' : 'reset+unlock'); }, 'confirm-disable': () => { if (!t.disabled) doDisable(); }, 'view-history': () => { S.tab = 'history'; closeSheet(); render(true); },
  }[a]; if (act) { e.preventDefault(); act(); }
});
document.addEventListener('input', (e) => {
  const t = e.target;
  if (t.id === 'filter') { S.q = t.value; S.page = 0; S.sel = new Set(); S.allMatching = false; const pos = t.selectionStart; render(true); const f = $('#filter'); f.focus(); f.setSelectionRange(pos, pos); }
  else if (t.id === 'chkall') { const rows = query().slice(S.page * PAGE, S.page * PAGE + PAGE); if (t.checked) rows.forEach((u) => S.sel.add(u.sam)); else { S.sel = new Set(); S.allMatching = false; } render(true); $('#chkall').focus(); }
  else if (t.closest('td.c-chk')) { const sam = t.closest('tr').dataset.sam; t.checked ? S.sel.add(sam) : S.sel.delete(sam); S.allMatching = false; render(true); document.querySelector(`tr[data-sam="${CSS.escape(sam)}"] input`)?.focus(); }
  else if (t.id === 'code') { S.step.code = t.value.replace(/\D/g, ''); t.value = S.step.code; const ok = /^\d{6}$/.test(S.step.code); const b = $('#confirm'); b.disabled = !ok; ok ? b.removeAttribute('aria-disabled') : b.setAttribute('aria-disabled', 'true'); $('#why').textContent = ok ? 'Caller verified. Ready.' : 'Enter the 6-digit code to continue.'; }
  else if (t.id === 'unl') { S.step.unlock = t.checked ? undefined : false; const keep = $('.sh-b').scrollTop; renderSheet(); $('#unl').focus(); }
  else if (t.id === 'typed') { S.step.typed = t.value; const pos = t.selectionStart; renderSheet(); const f = $('#typed'); f.focus(); f.setSelectionRange(pos, pos); }
});
document.addEventListener('keydown', (e) => {
  const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) && e.target.type !== 'checkbox';
  if (e.key === 'Escape') { if (S.sheet) { e.preventDefault(); closeSheet(); } else if (S.sel.size) { S.sel = new Set(); S.allMatching = false; render(true); } return; }
  if (e.key === 'Enter' && S.sheet && !e.target.closest('button, a') && $('#confirm') && !$('#confirm').disabled) { e.preventDefault(); $('#confirm').click(); return; }
  if (inField) return;
  if (e.key === '/' && !e.metaKey) { e.preventDefault(); ($('#filter') || $('#search')).focus(); return; }
  if (S.route === 'user' && !S.sheet && !BY_SAM.get(S.sam).tier0) { const u = BY_SAM.get(S.sam); if (e.key.toLowerCase() === 'r' && !u.disabled) { e.preventDefault(); openSheet({ kind: 'reset' }, document.activeElement); } if (e.key.toLowerCase() === 'u' && u.locked) { e.preventDefault(); openSheet({ kind: 'unlock' }, document.activeElement); } }
  if (e.target.closest('.tbl tbody') && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) { const tr = e.target.closest('tr'); const nx = e.key === 'ArrowDown' ? tr.nextElementSibling : tr.previousElementSibling; if (nx) { e.preventDefault(); const sel = e.target.matches('input') ? 'input' : 'a'; nx.querySelector(sel)?.focus(); } }
});
window.addEventListener('hashchange', () => { readHash(); render(); });

/* preview-only state strip (not product chrome) */
function updateStates() { document.querySelectorAll('.pv-st a').forEach((a) => a.removeAttribute('aria-current')); }
function pvBar() {
  const base = location.pathname.split('/').pop();
  const items = [['List', '#/users'], ['Locked view', '#/users?view=locked'], ['Selected', '#/users?sel=few'], ['All 12,431', '#/users?sel=all'], ['Bulk impact', '#/users?sel=all&sheet=disable'], ['Compact', '#/users?compact=1'], ['User', '#/users/praghunathan'], ['Reset: send code', '#/users/praghunathan?sheet=reset'], ['Reset: impact, ready', '#/users/praghunathan?sheet=reset&code=typed'], ['Done', '#/users/praghunathan?sheet=done'], ['Tier 0 user', '#/users/adm_madeyemi'], ['No results', '#/users?q=zzzz'], ['↺ Restart', '#restart']];
  document.body.insertAdjacentHTML('beforeend', `<div class="pv" role="complementary" aria-label="Preview controls"><span class="pv-tag">Preview — sample data</span><nav class="pv-st" aria-label="Preview states">${items.map(([l, h]) => `<a href="${h}" data-pv>${l}</a>`).join('')}</nav></div><div id="toasts" class="toasts" role="status" aria-live="polite"></div>`);
  document.addEventListener('click', (e) => { const a = e.target.closest('a[data-pv]'); if (!a) return; e.preventDefault(); const h = a.getAttribute('href'); if (h === '#restart') { location.hash = '#/users'; location.reload(); return; } if (location.hash === h) { readHash(); render(); } else location.hash = h; });
}
shell(); pvBar(); readHash(); render();
if (S.sheet && ['reset', 'unlock'].includes(S.sheet.kind)) renderSheet();
})();

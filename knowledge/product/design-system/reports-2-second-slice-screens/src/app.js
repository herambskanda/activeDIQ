// T-1123 preview. ALL DATA BELOW IS SAMPLE (generated); nothing is read from a directory.
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let seed = 7; const rnd = () => (seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296;
const pick = (a) => a[Math.floor(rnd() * a.length)];
const fmt = (n) => n.toLocaleString('en-US');

/* ---------- sample data ---------- */
const NAMES = ['Ana Kowalska', 'Bjørn Ødegård', 'Chen Wei', 'Dmitri Petrov', 'Élodie Marchetti-Lefèvre', 'Fatima Al-Hashimi', 'Grzegorz Brzęczyszczykiewicz', '山田 太郎', 'Ünal Çağlayan', 'Olivia Hartwell-Montgomery-Featherstonehaugh III', 'Priya Raghunathan', 'Søren Kierkegaard-Nielsen'];
const OUS = ['Corp/Finance/Accounts Payable', 'Corp/Engineering/Platform/SRE', 'Corp/Sales/EMEA/Nordics', 'Corp/HR', 'Service Accounts/SQL', 'Corp/Contractors/2026'];
const ATTRS = ['title', 'department', 'manager', 'telephoneNumber', 'description', 'mail', 'userAccountControl', 'accountExpires', 'proxyAddresses', 'memberOf', 'scriptPath', 'physicalDeliveryOfficeName'];
const KINDS = [['edited', 'Edited'], ['moved', 'Moved'], ['renamed', 'Renamed'], ['membership', 'Membership changed'], ['perm', 'Permissions changed'], ['cred', 'Credential event'], ['created', 'Created']];
const KG = { edited: '✎', moved: '→', renamed: 'Ab', membership: '±', perm: '🔒', cred: '🔑', created: '+', deleted: '✕' };
const fmtT = (d) => d.toISOString().slice(0, 16).replace('T', ' ');
const NOW = new Date('2026-11-04T14:02:00Z');

function genChanges(n, mode) {
  seed = 11; const rows = [];
  for (let i = 0; i < n; i++) {
    const del = mode === 'del';
    const k = del ? 'deleted' : KINDS[Math.floor(rnd() * rnd() * KINDS.length)][0];
    const nm = pick(NAMES) + (i % 3 ? '' : ' ' + (i + 100));
    const at = new Date(NOW - rnd() * 7 * 864e5);
    const obs = new Date(+at + Math.floor(rnd() * 3e6));
    const attrs = k === 'edited' ? Array.from({ length: 1 + Math.floor(rnd() * 4) }, () => pick(ATTRS)).filter((v, j, a) => a.indexOf(v) === j) : k === 'perm' ? ['nTSecurityDescriptor'] : k === 'membership' ? ['member'] : k === 'cred' ? ['unicodePwd', 'pwdLastSet'] : k === 'renamed' ? ['cn', 'name'] : k === 'moved' ? ['distinguishedName'] : [];
    const ou = pick(OUS); const sam = nm.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 20) || 'user' + i;
    rows.push({ id: i, name: nm, sam, kind: k, ou, domain: i % 9 === 0 ? 'emea.corp.example' : 'corp.example', attrs, at, obs, basis: k === 'created' || i % 17 === 0 ? 'observed' : 'DC time, originating', op: i % 41 === 0 ? 'ana.kowalska' : null, dn: `CN=${nm},OU=${ou.split('/').reverse().join(',OU=')},DC=corp,DC=example` });
  }
  return rows.sort((a, b) => b.at - a.at);
}

/* ---------- virtual table ---------- */
function vtable(host, o) {
  const { rows, cols, tpl, onSel, sel, rowH = 32 } = o;
  host.innerHTML = `<div class="gh" style="grid-template-columns:${tpl}" role="row">${cols.map((c) => `<div role="columnheader">${c.h}</div>`).join('')}</div><div class="gb" tabindex="0" aria-label="Results, ${fmt(rows.length)} rows"><div style="height:${rows.length * rowH}px;position:relative"></div></div><div class="gf"></div>`;
  const gb = $('.gb', host), inner = gb.firstChild, foot = $('.gf', host);
  let selIdx = sel ?? -1;
  function paint() {
    const top = gb.scrollTop, vh = gb.clientHeight || 400;
    const a = Math.max(0, Math.floor(top / rowH) - 4), b = Math.min(rows.length, Math.ceil((top + vh) / rowH) + 4);
    let h = '';
    for (let i = a; i < b; i++) h += `<div class="gr" role="row" data-i="${i}" aria-selected="${i === selIdx}" style="position:absolute;left:0;right:0;top:${i * rowH}px;grid-template-columns:${tpl}">${cols.map((c) => `<div role="cell">${c.r(rows[i], i)}</div>`).join('')}</div>`;
    inner.innerHTML = h;
    foot.innerHTML = `<span>Rows ${fmt(Math.min(rows.length, a + 1))}–${fmt(b)} of ${fmt(rows.length)}</span>${o.foot || ''}<span class="sp" style="margin-left:auto">↑↓ move · Enter or → open detail · Esc close · <span class="mono">Ctrl+C</span> copy link</span>`;
  }
  const select = (i, scroll) => { selIdx = Math.max(0, Math.min(rows.length - 1, i)); if (scroll) { const t = selIdx * rowH; if (t < gb.scrollTop) gb.scrollTop = t; else if (t + rowH > gb.scrollTop + gb.clientHeight) gb.scrollTop = t + rowH - gb.clientHeight; } paint(); onSel && onSel(selIdx); };
  gb.addEventListener('scroll', paint);
  gb.addEventListener('click', (e) => { const r = e.target.closest('.gr'); if (r) select(+r.dataset.i); });
  gb.addEventListener('keydown', (e) => { if (e.key === 'ArrowDown') { e.preventDefault(); select(selIdx + 1, 1); } else if (e.key === 'ArrowUp') { e.preventDefault(); select(selIdx - 1, 1); } else if (e.key === 'Enter' || e.key === 'ArrowRight') { select(Math.max(selIdx, 0), 1); } else if (e.key === 'PageDown') { e.preventDefault(); select(selIdx + 15, 1); } else if (e.key === 'PageUp') { e.preventDefault(); select(selIdx - 15, 1); } });
  host.style.setProperty('--mw', (o.minW || 0) + 'px'); paint(); if (selIdx >= 0) { gb.scrollTop = Math.max(0, selIdx * rowH - 80); paint(); onSel && onSel(selIdx); }
  return { select, paint };
}

/* ---------- shell ---------- */
const SCREENS = [['changes', 'A · Change history'], ['pso', 'B · Account policies'], ['repl', 'C · DC replication'], ['picker', 'D · Picker budget']];
const STATES = {
  changes: [['default', 'Default'], ['deleted', 'Deleted preset'], ['big', '12,408 rows'], ['partial', 'Partial coverage'], ['empty', 'Empty'], ['error', 'Error'], ['loading', 'Loading']],
  pso: [['default', 'Default'], ['empty', 'None exist'], ['error', 'Unreadable'], ['partial', 'Partial coverage'], ['big', '10,240 rows'], ['loading', 'Loading']],
  repl: [['default', 'Default'], ['partial', '5 of 6 DCs'], ['error', '0 of 6 DCs'], ['empty', 'No DCs in scope'], ['cap', '100 DC cap'], ['big', '10,240 rows'], ['loading', 'Loading']],
  picker: [['empty', 'Empty prompt'], ['typing', 'Typing'], ['ambiguous', 'Two same names'], ['nomatch', 'No match'], ['done', 'Result'], ['live', 'Live: count keys']],
};
function parse() { const h = location.hash.replace(/^#\/?/, ''); const [p, q] = h.split('?'); const u = new URLSearchParams(q || ''); return { screen: p || 'changes', state: u.get('state') || (p === 'picker' ? 'empty' : 'default'), row: u.get('row'), theme: u.get('theme') }; }
const link = (screen, state, extra = '') => `#/${screen}?state=${state}${extra}`;
function shell(r, inner, dock) {
  document.documentElement.dataset.theme = r.theme || 'light';
  const st = STATES[r.screen] || [];
  document.body.innerHTML = `<div class="pv"><span><b>PREVIEW · SAMPLE DATA</b> T-1123, not the product. Every name, count and DC is generated.</span><span>${SCREENS.map(([s, l]) => `<a href="${link(s, STATES[s][0][0])}" ${s === r.screen ? 'aria-current="true"' : ''}>${l}</a>`).join('')}</span><span>States: ${st.map(([s, l]) => `<a href="${link(r.screen, s)}" ${s === r.state ? 'aria-current="true"' : ''}>${l}</a>`).join('')}</span><a href="#/${r.screen}?state=${r.state}&theme=${r.theme === 'dark' ? 'light' : 'dark'}">${r.theme === 'dark' ? 'Light' : 'Dark'}</a></div>
<div class="top"><span class="brand">activeDIQ</span><div class="search" role="search">Search objects, reports, ME names <kbd>/</kbd></div><span class="sub">corp.example · <span class="mono">h.tanaka</span> · Reports operator</span></div>
<div class="app"><main class="main" id="main">${inner}</main>${dock || ''}</div>`;
}
const notes = (a) => `<div class="notes">${a.join('')}</div>`;
const note = (cls, html) => `<div class="note ${cls}">${html}</div>`;
const loading = (cols) => `<div class="grid" aria-busy="true"><div class="gh" style="grid-template-columns:${'1fr '.repeat(cols)}"><div>Loading…</div></div><div style="padding:16px"><div class="sr" role="status">Loading report, reading stored observations</div>${Array.from({ length: 12 }, (_, i) => `<div class="skel" style="width:${60 + ((i * 17) % 40)}%"></div>`).join('')}</div></div>`;

/* ================= A: change history ================= */
function stK(k) { const l = k === 'deleted' ? 'Removed' : KINDS.find((x) => x[0] === k)[1]; const cls = k === 'perm' || k === 'cred' ? 'warn' : k === 'deleted' ? 'crit' : 'mut'; return `<span class="st ${cls}"><span aria-hidden="true">${KG[k]}</span>${l}</span>`; }
function screenChanges(r) {
  const del = r.state === 'deleted';
  const big = r.state === 'big';
  let rows = r.state === 'empty' || r.state === 'error' || r.state === 'loading' ? [] : genChanges(big ? 12408 : del ? 38 : 214, del ? 'del' : 'mod');
  if (r.state === 'partial') rows = rows.map((x, i) => (i % 5 === 0 ? { ...x, basis: 'whenChanged read from DC-EMEA2 (includes automatic updates)', fallback: true } : x));
  const title = del ? 'User changes · Recently Deleted Users' : 'User changes · Recently Modified Users';
  const n = [];
  n.push(note('', `<b class="g">Change history starts 2026-09-14</b> for corp.example. Earlier changes are not listed. <span class="sub">History is observation-based: two changes between two observations show as one.</span>`));
  if (!del) n.push(note('', `<span>3,412 automatic updates hidden · <button class="lk">Show</button></span><span>2 credential events not shown · <button class="lk">Show</button></span><span>41 permission changes not shown · <button class="lk">Show</button></span>`));
  n.push(note('', `<span class="sub">No “Changed by” column: AD does not record who edited or deleted an object. Changes made through activeDIQ show the operator. Who-did-it arrives with the DC event collectors (M3).</span>`));
  if (r.state === 'partial') {
    n.length = 0;
    n.push(note('warn', `<b class="g">⚠ Partial history coverage — 2 of 3 domains.</b> <span>The period (90 days) starts before history does. Rows marked <span class="st mut">whenChanged</span> come from one DC’s <span class="mono">whenChanged</span> and include automatic updates.</span><details style="width:100%"><summary class="lk">Coverage by domain</summary><table style="margin-top:8px;font-size:12px"><tr><th align=left>Domain</th><th align=left>History starts</th><th align=left>Rows in the uncovered part</th></tr><tr><td>corp.example</td><td>2026-09-14</td><td>Basis “whenChanged read from DC-CORP1”</td></tr><tr><td>emea.corp.example</td><td>2026-11-01</td><td>Basis “whenChanged read from DC-EMEA2”</td></tr><tr><td>apac.corp.example</td><td><b>Not yet synced</b></td><td>No rows. This domain is <b>not</b> reported as “no changes”.</td></tr></table></details>`));
  }
  const cols = [
    { h: 'Name', r: (x) => `<span title="${esc(x.name)}">${esc(x.name)}</span>` },
    { h: 'Change', r: (x) => stK(x.kind) },
    { h: del ? 'Last known OU path' : 'Attributes changed', r: (x) => (del ? `<span class="mono">${esc(x.ou)}</span>` : x.attrs.length ? `<span class="mono">${esc(x.attrs.slice(0, 2).join(', '))}</span>${x.attrs.length > 2 ? ` <span class="sub">+${x.attrs.length - 2}</span>` : ''}` : '<span class="sub3">—</span>') },
    { h: 'Domain', r: (x) => esc(x.domain) },
    { h: del ? 'Deleted at' : 'Changed at', r: (x) => `${del ? 'on or before ' : ''}${fmtT(x.at)}` },
    { h: 'Basis', r: (x) => (x.fallback ? '<span class="st mut">whenChanged · DC-EMEA2</span>' : del ? 'last seen by activeDIQ' : esc(x.basis)) },
    { h: del ? 'State' : 'Observed at', r: (x) => (del ? 'Removed (restore status unknown)' : fmtT(x.obs)) },
  ];
  const tpl = 'minmax(180px,2fr) 150px minmax(160px,1.6fr) 150px 150px minmax(120px,1.4fr) 190px';
  let body;
  if (r.state === 'loading') body = loading(6);
  else if (r.state === 'error') body = `<div class="grid"><div class="empty"><h2>The change history could not be read</h2><p>The store that holds observed changes did not answer (ref <span class="mono">E-OC-0412</span>, 14:02). Nothing is shown rather than a partial list.</p><div class="bar"><a class="btn pri" href="${link('changes', 'default')}">Retry (preview: loads the default state)</a><span class="sub">Last good read: 13:47 · other reports are unaffected</span></div></div></div>`;
  else if (r.state === 'empty') body = `<div class="grid"><div class="empty"><h2>No user changes in the last 7 days</h2><p>History for corp.example covers 2026-09-14 to now, so this is a real “none”, not a gap. 3,412 automatic updates are hidden.</p><div class="bar"><button class="btn pri">Widen to 30 days</button><button class="btn">Show automatic updates</button></div></div></div>`;
  else body = `<div class="grid" id="g"></div>`;
  const bar = `<div class="bar" role="toolbar" aria-label="Report filters"><span class="chip" aria-pressed="true">${del ? 'Deleted' : 'Modified'}</span><span class="chip" aria-pressed="false">Credential events</span><span class="chip" aria-pressed="false">Permissions changed</span><button class="chip">Period: ${r.state === 'partial' ? 'last 90 days' : 'last 7 days'} ▾</button><button class="chip">Domain: all permitted ▾</button><span class="sp"></span><button class="btn">Columns</button><button class="btn">Export <kbd>E</kbd></button></div>`;
  shell(r, `<div class="crumbs">Reports › Users › USR-06</div><h1>${title}</h1><p class="meta"><span>As of 14:02 · observed data</span><span>Scope: corp.example, emea.corp.example</span><span>Definition v3</span></p>${notes(n)}${bar}${body}`, null);
  if ($('#g')) {
    const i0 = r.row != null ? +r.row : -1;
    const sel = (i) => { const x = rows[i]; history.replaceState(null, '', `#/changes?state=${r.state}&row=${i}`); const d = $('.dock'); const h = dockChanges(x, i, rows.length); if (d) d.outerHTML = h; else $('.app').insertAdjacentHTML('beforeend', h); bindDock(rows.length, (j) => t.select(j, 1)); };
    var t = vtable($('#g'), { rows, cols, tpl, sel: i0, onSel: sel, minW: 1280 });
    $('.gb', $('#g')).focus();
  }
}
const sampleMembers = (n, p) => Array.from({ length: n }, (_, i) => `${NAMES[(i + p) % NAMES.length]} ${i + 1}`);
function dockChanges(x, i, total) {
  let body = '';
  const fx = (k, v) => `<dt>${k}</dt><dd>${v}</dd>`;
  const common = `<dl class="kv">${fx('Object', `<span class="mono">${esc(x.sam)}</span> · user`)}${fx('Domain', esc(x.domain))}${fx('OU path', `<span class="mono">${esc(x.ou)}</span>`)}${fx('DN', `<span class="mono">${esc(x.dn)}</span>`)}</dl>`;
  const when = x.kind === 'deleted'
    ? `<dl class="kv">${fx('Deleted at', `on or before ${fmtT(x.at)} <span class="st mut">observed</span>`)}${fx('Name, OU path', 'from the last inventory observation <span class="st mut">last seen by activeDIQ</span>')}${fx('State', 'Removed (restore status unknown)')}${fx('Restorable until', 'Unknown')}</dl><p class="why">Why unknown: the connection account cannot list <span class="mono">CN=Deleted Objects</span>, so activeDIQ cannot tell whether this is a restorable tombstone or already recycled. It does not guess from elapsed time.</p>`
    : `<dl class="kv">${fx('Changed at', `${fmtT(x.at)} <span class="st mut">${esc(x.basis)}</span>`)}${fx('Observed at', fmtT(x.obs))}${fx('Gap', `${Math.round((x.obs - x.at) / 60000)} min between change and observation`)}</dl>${x.basis === 'observed' ? '<p class="why">This change has no replicated originating time; the time shown is when activeDIQ saw it.</p>' : ''}<p class="why">If more than one change happened between two observations, they appear here as one.</p>`;
  if (x.kind === 'membership') body = `<h3>Members, this period</h3><p><span class="st ok">+ 1,204 added</span> <span class="st mut">− 8 removed</span> <span class="sub">group has 3,000 members now (sample)</span></p><ul class="plist" aria-label="Members added">${sampleMembers(60, 3).map((m) => `<li>+ ${esc(m)}</li>`).join('')}</ul><p class="why">Showing 60 of 1,204 added · <button class="lk">Show 60 more</button> · 37 members are outside your scope: counted above, not named. A member added and removed between two observations shows as neither.</p>`;
  else if (x.kind === 'cred') body = `<h3>Credential event</h3><p>A password was changed or reset (recognised from replication metadata of <span class="mono">unicodePwd</span>, <span class="mono">pwdLastSet</span>). The value is never recorded or shown. This is not an edit.</p>`;
  else if (x.kind === 'perm') body = `<h3>Permissions changed</h3><p><span class="mono">nTSecurityDescriptor</span> was rewritten (version 14). Metadata cannot say whether an administrator edited the ACL or inheritance / SDProp propagated it from a parent, so this is not hidden as noise and not called an edit. No descriptor was read.</p>`;
  else if (x.attrs.length) body = `<h3>Attributes changed (${x.attrs.length})</h3><table><tr><th>Attribute</th><th>Changed at</th><th>Version</th></tr>${x.attrs.map((a, j) => `<tr><td class="mono">${esc(a)}</td><td>${fmtT(new Date(+x.at - j * 36e5))}</td><td>${3 + j * 2}</td></tr>`).join('')}</table><p class="why">Names only. Old and new values are not recorded (personal values are erasable; secrets are never kept).</p>`;
  const actor = x.op ? `<dl class="kv">${fx('Changed by', `<b>${esc(x.op)}</b> through activeDIQ <a class="lk" href="#/changes?state=default">Operation OP-2291</a>`)}</dl>` : `<p class="why">Changed by: <b>not recorded by AD.</b> The directory does not hold who made this change.</p>`;
  return `<aside class="dock" aria-label="Change detail"><header><div class="row1"><h2>${esc(x.name)}</h2><button class="btn" id="prev" aria-label="Previous row">↑</button><button class="btn" id="next" aria-label="Next row">↓</button><button class="btn" id="cls" aria-label="Close detail (Esc)">✕</button></div><div>${stK(x.kind)} <span class="sub">row ${fmt(i + 1)} of ${fmt(total)}</span></div></header><div class="body"><h3>When</h3>${when}${body}<h3>Who</h3>${actor}<h3>Object</h3>${common}<p style="margin-top:12px"><a class="lk" href="#/changes">Open ${esc(x.sam)}</a> · <button class="lk">Copy link to this change</button></p></div><footer>Deep link: <span class="mono">/reports/usr-06?row=${esc(x.sam)}~${i}</span></footer></aside>`;
}
function bindDock(total, go) { const cur = () => +(parse().row || 0); $('#prev') && ($('#prev').onclick = () => go(cur() - 1)); $('#next') && ($('#next').onclick = () => go(cur() + 1)); $('#cls') && ($('#cls').onclick = () => { $('.dock').remove(); history.replaceState(null, '', `#/${parse().screen}?state=${parse().state}`); }); }
addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('.dock') && !$('.scrim')) { $('.dock').remove(); history.replaceState(null, '', `#/${parse().screen}?state=${parse().state}`); } });

/* ================= B: PSO table ================= */
const DOMAIN = { name: 'Domain policy (Default Domain Policy)', prec: null, len: 8, hist: 12, max: 90, min: 1, cx: 1, rev: 0, thr: 10, dur: 30, win: 30, targets: ['Domain Users'], nt: 1, dom: true };
const PSOS = [
  ['PSO-Admins-Tier0', 1, 20, 24, 45, 1, 1, 0, 3, 0, 60, ['Domain Admins', 'Enterprise Admins', 'Schema Admins'], 3],
  ['PSO-Service-Accounts', 5, 30, 24, 0, 0, 1, 0, 0, 0, 0, ['svc-sql01', 'svc-backup', 'svc-iis-prod'], 41],
  ['PSO-Contractors', 10, 14, 24, 60, 1, 1, 0, 5, 60, 30, ['Contractors-2026'], 1],
  ['PSO-Kiosk (Legacy) — wörkstation login terminals, Hamburg & Zürich sites', 20, 6, 0, 365, 0, 0, 1, 0, 0, 0, ['kiosk-hamburg', 'kiosk-zurich'], 2],
  ['PSO-Finance', 20, 12, 24, 90, 1, 1, 0, 10, 30, 30, ['Finance-Users'], 1],
].map((a) => ({ name: a[0], prec: a[1], len: a[2], hist: a[3], max: a[4], min: a[5], cx: a[6], rev: a[7], thr: a[8], dur: a[9], win: a[10], targets: a[11], nt: a[12] }));
// direction: +1 higher is stricter, -1 lower is stricter, 0 not ordered
const FIELDS = [
  ['len', 'Min length', 1, (v) => v + ' chars', 'pw'], ['hist', 'History', 1, (v) => v, 'pw'], ['max', 'Max age', -1, (v) => (v === 0 ? 'Never' : v + ' d'), 'pw', true], ['min', 'Min age', 1, (v) => v + ' d', 'pw'],
  ['cx', 'Complexity', 1, (v) => (v ? 'On' : 'Off'), 'pw'], ['rev', 'Reversible enc.', -1, (v) => (v ? 'On' : 'Off'), 'pw'],
  ['thr', 'Lock after', -1, (v) => (v === 0 ? 'Never locks' : v + ' fails'), 'lo', true], ['dur', 'Lock duration', 1, (v) => (v === 0 ? 'Until admin unlocks' : v + ' min'), 'lo', false, true], ['win', 'Obs. window', 1, (v) => v + ' min', 'lo'],
];
function delta(f, p, d) {
  const [k, , dir, , , zeroIsWeak, zeroIsMax] = f; const a = p[k], b = d[k]; if (a === b) return { t: '=', cls: 'd-x', w: 'same' };
  // zero special-cases: max age 0 = never expires (weaker); lock threshold 0 = never locks (weaker); duration 0 = until admin unlocks (stricter)
  let s;
  if (zeroIsWeak && (a === 0 || b === 0)) s = a === 0 ? -1 : 1; else if (zeroIsMax && (a === 0 || b === 0)) s = a === 0 ? 1 : -1; else s = (a > b ? 1 : -1) * dir;
  const diff = typeof a === 'number' && !['cx', 'rev'].includes(k) && a && b ? (a > b ? '+' : '−') + Math.abs(a - b) : '';
  return s > 0 ? { t: '▲' + (diff ? ' ' + diff : ''), cls: 'd-s', w: 'stricter' } : { t: '▼' + (diff ? ' ' + diff : ''), cls: 'd-w', w: 'weaker' };
}
function psoRows(count) {
  const base = [{ ...DOMAIN }, ...PSOS]; if (!count) return base;
  seed = 5; const extra = Array.from({ length: count - base.length }, (_, i) => ({ name: `PSO-Sample-${i + 1}`, prec: 100 + (i % 900), len: 6 + Math.floor(rnd() * 20), hist: Math.floor(rnd() * 24), max: [0, 30, 60, 90, 180][Math.floor(rnd() * 5)], min: Math.floor(rnd() * 3), cx: rnd() > 0.3 ? 1 : 0, rev: rnd() > 0.95 ? 1 : 0, thr: [0, 3, 5, 10][Math.floor(rnd() * 4)], dur: [0, 15, 30, 60][Math.floor(rnd() * 4)], win: [15, 30, 60][Math.floor(rnd() * 3)], targets: [pick(NAMES)], nt: 1 + Math.floor(rnd() * 300) }));
  return base.concat(extra);
}
function screenPso(r) {
  const preset = new URLSearchParams(location.hash.split('?')[1] || '').get('preset') || 'both';
  const fields = FIELDS.filter((f) => preset === 'both' || (preset === 'pw' ? f[4] === 'pw' : f[4] === 'lo'));
  const big = r.state === 'big';
  const unreadable = r.state === 'error';
  let rows = r.state === 'empty' || unreadable ? [{ ...DOMAIN }] : psoRows(big ? 10240 : 0);
  if (r.state === 'partial') rows = rows.concat([{ ...DOMAIN, name: 'Domain policy (emea.corp.example) — fine-grained policies not readable', targets: ['Domain Users'] }]);
  const n = [];
  if (r.state === 'error') n.push(note('crit', `<b class="g">✕ Fine-grained policies could not be read:</b> access denied. The connection account cannot read <span class="mono">CN=Password Settings Container</span> (Domain Admins only by default). <span><b>Users may be governed by policies not shown here.</b></span> <a class="lk" href="#/pso">Grant the read right (connection settings)</a>`));
  if (r.state === 'partial') n.push(note('warn', `<b class="g">⚠ Policies read for 1 of 2 domains.</b> emea.corp.example: fine-grained policies could not be read (access denied). Its domain row is shown; users there may be governed by policies not shown. corp.example is complete.`));
  if (r.state === 'empty') n.push(note('info', `<b class="g">No fine-grained policies exist in corp.example.</b> Read succeeded at 14:02 (readable: yes). Every user is governed by the domain policy.`));
  const tpl = `64px minmax(220px,2.2fr) minmax(190px,1.8fr) ${fields.map(() => '106px').join(' ')} 150px`;
  const cols = [
    { h: 'Prec.', r: (x) => (x.dom ? '<span class="sub">base</span>' : x.prec) },
    { h: 'Policy', r: (x) => `<span title="${esc(x.name)}">${x.dom ? '<span class="st sig">Baseline</span> ' : ''}${esc(x.name)}</span>` },
    { h: 'Applies to (direct)', r: (x) => `<span class="sub">${fmt(x.nt)}:</span> ${esc(x.targets.slice(0, 2).join(', '))}${x.targets.length > 2 ? ' …' : ''}` },
    ...fields.map((f) => ({ h: f[1], r: (x) => (x.dom || unreadable && x.dom ? esc(f[3](x[f[0]])) : (() => { const d = delta(f, x, DOMAIN); return `<span class="dv">${esc(f[3](x[f[0]]))} <span class="${d.cls}" aria-label="${d.w} than domain">${d.t}</span></span>`; })()) })),
    { h: 'Versus domain', r: (x) => { if (x.dom) return '<span class="sub">—</span>'; const ds = fields.map((f) => delta(f, x, DOMAIN).w); const s = ds.filter((v) => v === 'stricter').length, w = ds.filter((v) => v === 'weaker').length; return `${s} stricter · <span class="${w ? 'd-w' : ''}">${w} weaker</span>`; } },
  ];
  const seg = ['both', 'pw', 'lo'].map((p, i) => `<a class="chip" aria-pressed="${p === preset}" href="#/pso?state=${r.state}&preset=${p}">${['Both (default)', 'Password Policy', 'Account Lockout Policy'][i]}</a>`).join('');
  let body = r.state === 'loading' ? loading(8) : `<div class="grid" id="g"></div>`;
  shell(r, `<div class="crumbs">Reports › Domain and DCs › SYS-01</div><h1>Account policies</h1><p class="meta"><span>Policy read 13:58 (as of)</span><span>Scope: corp.example${r.state === 'partial' ? ', emea.corp.example' : ''}</span><span>Presets = ME “Password Policy”, “Account Lockout Policy”</span></p>${notes(n)}<div class="bar" role="toolbar" aria-label="Preset">${seg}<span class="sp"></span><span class="sub" id="leg">▲ stricter than domain · <span class="d-w">▼ weaker</span> · = same. Lock-out threshold 0 and max age 0 count as weaker.</span><button class="btn">Export <kbd>E</kbd></button></div>${body}`, null);
  if ($('#g')) {
    const i0 = r.row != null ? +r.row : -1;
    let t; const sel = (i) => { history.replaceState(null, '', `#/pso?state=${r.state}&row=${i}${preset !== 'both' ? '&preset=' + preset : ''}`); const h = dockPso(rows[i], rows.length, i, unreadable); const d = $('.dock'); if (d) d.outerHTML = h; else $('.app').insertAdjacentHTML('beforeend', h); bindDock(rows.length, (j) => t.select(j, 1)); };
    t = vtable($('#g'), { rows, cols, tpl, sel: i0, onSel: sel, minW: 1480, foot: r.state === 'partial' ? '<span class="d-w">⚠ emea.corp.example: policies not readable</span>' : '' });
    $('.gb', $('#g')).focus();
  }
}
function dockPso(x, total, i, unreadable) {
  if (x.dom) return `<aside class="dock" aria-label="Policy detail"><header><div class="row1"><h2>${esc(x.name)}</h2><button class="btn" id="cls" aria-label="Close">✕</button></div><span class="st sig">Baseline</span></header><div class="body"><p>Values read from the domain head (<span class="mono">minPwdLength</span>, <span class="mono">lockoutThreshold</span>, …). The attribute is the effective truth; the Default Domain Policy GPO normally agrees.</p>${unreadable ? '<p class="why">Fine-grained policies could not be read, so no comparison rows exist for this domain.</p>' : ''}</div></aside>`;
  const rows = FIELDS.map((f) => { const d = delta(f, x, DOMAIN); return `<tr><td>${f[1]}</td><td>${esc(f[3](DOMAIN[f[0]]))}</td><td><b>${esc(f[3](x[f[0]]))}</b></td><td class="${d.cls}">${d.t} ${d.w}</td></tr>`; }).join('');
  const tg = Array.from({ length: Math.min(x.nt, 40) }, (_, j) => x.targets[j] || `${NAMES[(j + 2) % NAMES.length]} ${j}`);
  const tie = PSOS.filter((p) => p.prec === x.prec && p !== x).map((p) => p.name);
  return `<aside class="dock" aria-label="Policy detail"><header><div class="row1"><h2>${esc(x.name)}</h2><button class="btn" id="prev" aria-label="Previous">↑</button><button class="btn" id="next" aria-label="Next">↓</button><button class="btn" id="cls" aria-label="Close">✕</button></div><span class="sub">Precedence ${x.prec} · ${fmt(x.nt)} direct targets</span></header><div class="body"><h3>Against the domain policy</h3><table><tr><th>Setting</th><th>Domain</th><th>This policy</th><th>Difference</th></tr>${rows}</table>${tie.length ? `<p class="note warn" style="margin-top:8px"><b>⚠ Same precedence as</b> ${esc(tie.join(', '))}. Which one wins for a user is shown per user, not here.</p>` : ''}<h3>Applies to (direct targets, not the resultant set)</h3><ul class="plist">${tg.map((t) => `<li>${esc(t)}</li>`).join('')}</ul><p class="why">${x.nt > 40 ? `Showing 40 of ${fmt(x.nt)} · <button class="lk">Show more</button> · ` : ''}Group targets apply to their members through the group; a user can also be governed by another policy with a lower precedence number.</p><p><a class="lk" href="#/pso">Users governed by this policy (USR-05, “Policy source” filter)</a></p></div><footer>This report lists policies and direct targets. It does not claim a per-user result.</footer></aside>`;
}

/* ================= C: replication ================= */
const DCS = [['DC-CORP1', 'corp.example'], ['DC-CORP2', 'corp.example'], ['DC-CORP3', 'corp.example'], ['DC-EMEA1', 'emea.corp.example'], ['DC-EMEA2', 'emea.corp.example'], ['DC-BRANCH-ZÜRICH-01', 'corp.example']];
const ERRS = { 1722: ['The RPC server is unavailable', 'The partner DC could not be reached over RPC.'], 8524: ['The DSA operation is unable to proceed because of a DNS lookup failure', 'The destination could not resolve the partner’s DNS name.'], 8453: ['Replication access was denied', 'The destination DC was refused by the source.'] };
function genRepl(n, state) {
  seed = 3; const rows = []; const dcs = n > 20 ? Array.from({ length: 100 }, (_, i) => [`DC-SAMPLE-${String(i + 1).padStart(3, '0')}`, i % 4 ? 'corp.example' : 'emea.corp.example']) : DCS;
  const parts = ['DC=corp,DC=example', 'CN=Configuration,DC=corp,DC=example', 'CN=Schema,CN=Configuration,DC=corp,DC=example'];
  dcs.forEach(([dc, dom], di) => {
    const unread = state === 'error' || (state === 'partial' && dc === 'DC-EMEA2');
    if (unread) { rows.push({ dc, dom, part: '—', partner: '—', att: null, suc: null, f: 0, err: null, status: 'nr', ling: 'nr', read: null, unread: true, why: dc === 'DC-EMEA2' && state === 'partial' ? 'LDAP connect to DC-EMEA2 timed out after 10 s (tcp/636)' : 'LDAP connect timed out after 10 s (tcp/636)' }); return; }
    const np = n > 20 ? 3 : 3;
    parts.slice(0, np).forEach((part, pi) => {
      const ps = n > 20 ? 2 + (di % 3) : 2;
      for (let k = 0; k < ps; k++) {
        const partner = (dcs[(di + k + 1) % dcs.length] || dcs[0])[0];
        let f = 0, err = null, ageH = rnd() * 0.6;
        if ((dc === 'DC-BRANCH-ZÜRICH-01' && pi < 2) || (n > 20 && rnd() > 0.93)) { f = 3 + Math.floor(rnd() * 40); err = pick([1722, 8524, 8453]); ageH = f > 30 ? 24 * 190 : 30 + rnd() * 10; if (dc === 'DC-BRANCH-ZÜRICH-01' && pi === 0 && k === 0) { ageH = 24 * 200; } }
        else if (dc === 'DC-CORP3' && pi === 0 && k === 1) { ageH = 3.5; }
        const status = f > 0 || ageH >= 24 ? 'fail' : ageH >= 1 ? 'warn' : 'ok';
        rows.push({ dc, dom, part, partner, att: new Date(NOW - 36e5 * Math.min(ageH, 24 * 12)), suc: new Date(NOW - 36e5 * ageH), f, err, status, ling: ageH >= 24 * 180 ? 'risk' : 'no', ageH, read: NOW, id: rows.length });
      }
    });
  });
  const ord = { fail: 0, warn: 1, ok: 2, nr: 3 };
  return rows.sort((a, b) => (b.unread ? 1 : 0) - (a.unread ? 1 : 0) || ord[a.status] - ord[b.status] || b.f - a.f);
}
const stR = (s) => ({ ok: '<span class="st ok"><span aria-hidden="true">✓</span>Healthy</span>', warn: '<span class="st warn"><span aria-hidden="true">▲</span>Warning</span>', fail: '<span class="st crit"><span aria-hidden="true">✕</span>Failing</span>', nr: '<span class="st mut"><span aria-hidden="true">?</span>Not reported</span>' }[s]);
function screenRepl(r) {
  const st = r.state; const big = st === 'big' || st === 'cap';
  let rows = st === 'empty' || st === 'loading' ? [] : genRepl(big ? 3400 : 0, st);
  if (st === 'big') { const b = rows; rows = []; for (let i = 0; i < 10240; i++) { const s = b[i % b.length]; rows.push({ ...s, id: i, dc: s.dc.replace(/\d+$/, (m) => String(((+m + i) % 100) + 1).padStart(3, '0')) }); } }
  const read = st === 'error' ? 0 : st === 'partial' ? 5 : st === 'cap' ? 100 : st === 'big' ? 100 : 6;
  const inScope = st === 'cap' ? 138 : st === 'big' ? 100 : 6;
  const tallies = { fail: rows.filter((x) => x.status === 'fail').length, warn: rows.filter((x) => x.status === 'warn').length, ok: rows.filter((x) => x.status === 'ok').length, nr: rows.filter((x) => x.unread).length };
  const n = [];
  if (st !== 'empty' && st !== 'loading') {
    const bad = st === 'error' || st === 'partial';
    n.push(note(bad ? (st === 'error' ? 'crit' : 'warn') : st === 'cap' ? 'warn' : '', `<b class="g">${bad ? (st === 'error' ? '✕' : '⚠') : st === 'cap' ? '⚠' : '✓'} Read from ${read} of ${inScope} DCs</b> ${st === 'error' ? '— no DC answered. <b>This is not “no problems”.</b> Replication state is unknown for all domains.' : st === 'partial' ? '— DC-EMEA2 did not answer (pinned below). Its inbound replication is <b>unknown</b>, and partners of DC-EMEA2 may look healthy from their side only.' : st === 'cap' ? `— a run reads at most 100 DCs. 38 in-scope DCs were <b>not read</b>. <button class="lk">Narrow the scope (domain or site)</button>` : '<span class="sub">each DC reports only its own inbound partners</span>'}`));
    n.push(note('', `<span class="sub">Thresholds: Warning after 1 h without success · Failing after 24 h or any failure (<button class="lk">edit</button>). “At risk” = a partner’s last success is older than the forest tombstone lifetime (180 d, sample). It is an indicator, not a detection of lingering objects.</span>`));
  }
  const tpl = '110px minmax(150px,1.3fr) minmax(170px,1.6fr) minmax(130px,1.1fr) 130px 130px 76px minmax(170px,1.8fr) 120px 80px';
  const cols = [
    { h: 'Status', r: (x) => stR(x.status) }, { h: 'Domain controller', r: (x) => `<b title="${esc(x.dc)}">${esc(x.dc)}</b>` },
    { h: 'Partition', r: (x) => `<span class="mono">${esc(x.part)}</span>` }, { h: 'Partner (source)', r: (x) => esc(x.partner) },
    { h: 'Last attempt', r: (x) => (x.att ? fmtT(x.att) : '—') }, { h: 'Last success', r: (x) => (x.suc ? fmtT(x.suc) : '—') }, { h: 'Failures', r: (x) => x.f },
    { h: 'Last error', r: (x) => (x.err ? `<span class="mono">${x.err}</span> ${esc(ERRS[x.err][0])}` : '<span class="sub3">—</span>') },
    { h: 'Lingering-object risk', r: (x) => (x.ling === 'risk' ? '<span class="st crit"><span aria-hidden="true">!</span>At risk</span>' : x.ling === 'nr' ? '<span class="st mut">Not reported</span>' : 'No indication') }, { h: 'Read at', r: (x) => (x.read ? fmtT(x.read).slice(11) : '—') },
  ];
  const chips = `<div class="bar" role="toolbar" aria-label="Status filter"><span class="chip" aria-pressed="true">All ${fmt(rows.length)}</span><span class="chip" aria-pressed="false">✕ Failing ${fmt(tallies.fail)}</span><span class="chip" aria-pressed="false">▲ Warning ${fmt(tallies.warn)}</span><span class="chip" aria-pressed="false">✓ Healthy ${fmt(tallies.ok)}</span><span class="chip" aria-pressed="false">? Not reported ${fmt(tallies.nr)}</span><button class="chip">Domain: all ▾</button><span class="sp"></span><span class="sub">Sorted worst first · read 14:02 · next read allowed after 15:02 (1 h floor)</span><button class="btn">Export <kbd>E</kbd></button></div>`;
  let body;
  if (st === 'loading') body = loading(8);
  else if (st === 'empty') body = `<div class="grid"><div class="empty"><h2>No domain controllers are in your scope</h2><p>Replication is read per DC. Your role’s scope contains no DC, so nothing was read. This is not “healthy”.</p><div class="bar"><a class="btn pri" href="#/repl?state=default">Show the report with a DC in scope (preview)</a></div></div></div>`;
  else body = `<div class="grid" id="g"></div>`;
  shell(r, `<div class="crumbs">Reports › Domain and DCs › SYS-03</div><h1>DC replication status</h1><p class="meta"><span>Read live from each DC, not stored</span><span>Scope: ${st === 'cap' ? '138' : '6'} DCs</span><span>ME name “DC Replication Status”</span></p>${notes(n)}${st === 'empty' || st === 'loading' ? '' : chips}${body}`, null);
  if ($('#g')) {
    const unreadRows = rows.filter((x) => x.unread); const rest = rows.filter((x) => !x.unread);
    const g = $('#g'); g.innerHTML = (unreadRows.length ? `<div class="band" role="rowgroup">✕ Did not answer (${unreadRows.length}) — pinned: a blind spot is more important than any row below</div>${unreadRows.slice(0, 4).map((x, i) => `<div class="gr pin" style="grid-template-columns:110px minmax(150px,1.3fr) 1fr" data-u="${i}">${stR('nr')}<b>${esc(x.dc)}</b><span>${esc(x.why)}</span></div>`).join('')}${unreadRows.length > 4 ? `<div class="gr pin sub"><span>+ ${unreadRows.length - 4} more · <button class="lk">show all</button></span></div>` : ''}` : '') + '<div id="gv" style="flex:1;min-height:0;display:flex;flex-direction:column"></div>';
    let t; const sel = (i) => { history.replaceState(null, '', `#/repl?state=${st}&row=${i}`); const h = dockRepl(rest[i], i, rest.length); const d = $('.dock'); if (d) d.outerHTML = h; else $('.app').insertAdjacentHTML('beforeend', h); bindDock(rest.length, (j) => t.select(j, 1)); };
    t = vtable($('#gv'), { rows: rest, cols, tpl, sel: r.row != null ? +r.row : -1, onSel: sel, minW: 1500 });
    $('.gb', g).focus();
  }
}
function dockRepl(x, i, total) {
  const fx = (k, v) => `<dt>${k}</dt><dd>${v}</dd>`;
  const e = x.err ? ERRS[x.err] : null;
  return `<aside class="dock" aria-label="Replication detail"><header><div class="row1"><h2>${esc(x.dc)} ← ${esc(x.partner)}</h2><button class="btn" id="prev" aria-label="Previous">↑</button><button class="btn" id="next" aria-label="Next">↓</button><button class="btn" id="cls" aria-label="Close">✕</button></div><div>${stR(x.status)} <span class="sub">row ${fmt(i + 1)} of ${fmt(total)}</span></div></header><div class="body"><h3>Link</h3><dl class="kv">${fx('Destination', esc(x.dc))}${fx('Partner (source)', esc(x.partner))}${fx('Partition', `<span class="mono">${esc(x.part)}</span>`)}${fx('Last attempt', fmtT(x.att))}${fx('Last success', `${fmtT(x.suc)} (${x.ageH < 1 ? Math.round(x.ageH * 60) + ' min' : x.ageH < 48 ? Math.round(x.ageH) + ' h' : Math.round(x.ageH / 24) + ' d'} ago)`)}${fx('Consecutive failures', x.f)}${fx('Read at', fmtT(x.read))}</dl>${e ? `<h3>Last error</h3><p><span class="mono">${x.err}</span> ${esc(e[0])}</p><h3>What it means</h3><p>${esc(e[1])}</p><p class="why">Meaning and next step come from Microsoft’s documented error text, worded by ad-expert with a source link on each. <b>Placeholder in this preview:</b> no remedy text ships without a source.</p>` : ''}<h3>Lingering-object risk</h3><p>${x.ling === 'risk' ? 'At risk: the last success from this partner is older than the tombstone lifetime. This is an indicator only; activeDIQ does not detect lingering objects.' : 'No indication from the dates read.'}</p></div><footer>No “Trigger replication” here: starting replication is a change, and arrives as an Action in 2b.</footer></aside>`;
}

/* ================= D: picker ================= */
const MGR = [['Ana Kowalska', 'akowalska', 'Corp/Engineering/Platform', 12], ['Ana Kowalska', 'akowalska2', 'Corp/Sales/EMEA', 4], ['Anastasia Łukasiewicz-Vandenberghe', 'alukasiewicz', 'Corp/Finance', 31], ['Anders Åkesson', 'aakesson', 'Corp/HR', 7]];
const RECENT = [['Priya Raghunathan', 'praghunathan', 'Corp/Engineering', 18], ['Chen Wei', 'cwei', 'Corp/Sales/APAC', 9]];
let keys = { i: 0, f: 0, s: 1 };
function screenPicker(r) {
  const s = r.state; const live = s === 'live' || s === 'livepick';
  const q = { empty: '', typing: 'ana', ambiguous: 'ana kow', nomatch: 'zz' }[s] || '';
  const list = s === 'empty' || s === 'livepick' ? RECENT : s === 'typing' ? MGR : s === 'ambiguous' ? MGR.slice(0, 2) : [];
  const pk = s === 'done' ? `<div class="pk"><label>Manager</label><span class="chip" aria-pressed="true">Ana Kowalska · akowalska · Corp/Engineering/Platform ✕</span> <span class="sub">press <kbd style="margin:0">M</kbd> to change</span></div>` : s === 'live' ? '' : `<div class="pk"><label for="pi">Manager (required)</label><input id="pi" role="combobox" aria-expanded="${list.length > 0}" aria-controls="pl" aria-autocomplete="list" value="${esc(q)}" placeholder="Type a name, sAMAccountName, UPN or e-mail">${s === 'nomatch' ? `<p class="why d-w">No manager matches “zz” in your scope. Managers are users with at least one direct report.</p>` : `<ul class="lb" id="pl" role="listbox" style="border:1px solid var(--diq-line);margin-top:4px">${list.map((m, i) => `<li role="option" aria-selected="${i === 0}"><b>${esc(m[0])}</b><span class="mono">${m[1]}</span><span class="sub">${esc(m[2])}</span><span class="sub" style="margin-left:auto">${m[3]} reports</span></li>`).join('')}</ul>`}<p class="why">${s === 'empty' || s === 'livepick' ? 'Recent managers shown. ' : ''}Enter picks the highlighted row and runs. ${s === 'ambiguous' ? '<b>Two people share a display name:</b> account and OU tell them apart.' : ''}</p></div>`;
  const ran = s === 'done';
  const rows = ran ? sampleMembers(12, 1) : [];
  const title = s === 'live' ? 'Reports library' : 'Managers · Manager Based Users';
  shell(r, `<div class="crumbs">Reports${s === 'live' ? '' : ' › Users › USR-12'}</div><h1>${title}</h1><p class="meta"><span>${s === 'live' ? 'Preview: press / , type “manager”, Enter, type “ana”, Enter. The counter counts only these.' : 'Requires one pick: no Generate step'}</span></p>${pk}${ran ? `<div class="grid" style="flex:none"><div class="gh" style="grid-template-columns:1fr 1fr 1fr"><div>Name</div><div>Logon name</div><div>Title</div></div><div class="gb">${rows.map((m) => `<div class="gr" style="grid-template-columns:1fr 1fr 1fr"><div>${esc(m)}</div><div class="mono">${esc(m.toLowerCase().replace(/\W/g, '').slice(0, 14))}</div><div>Analyst</div></div>`).join('')}</div></div>` : s === 'empty' || s === 'nomatch' || s === 'livepick' ? `<div class="empty" style="padding:32px 0"><h2>Pick a manager to run the report</h2><p>Nothing runs until there is something to run on. No Generate button.</p></div>` : ''}<div class="ctr" id="ctr" ${live || s === 'done' && window.__keys ? '' : 'hidden'}></div>`, null);
  if (s === 'live') { keys = { i: 0, f: 0, s: 1 }; window.__keys = keys; }
  const upd = () => { const c = $('#ctr'); if (c) c.textContent = `${keys.i} interactions · ${keys.f} typed fields · ${keys.s} screens`; }; upd();
  if (s === 'live') {
    const h = (e) => { if (e.key === '/' && !$('#scr')) { e.preventDefault(); keys.i++; upd(); document.body.insertAdjacentHTML('beforeend', `<div class="scrim" id="scr"><div class="pal" role="dialog" aria-label="Search"><input id="pq" placeholder="Report, ME name, object" role="combobox" aria-expanded="true"><ul class="lb"><li aria-selected="true"><b>Managers · Manager Based Users</b><span class="sub">ME name · USR-12 · requires a manager</span></li></ul></div></div>`); const pq = $('#pq'); pq.focus(); let t = false; pq.addEventListener('input', () => { if (!t) { t = true; keys.f++; keys.i++; upd(); } }); pq.addEventListener('keydown', (e2) => { if (e2.key === 'Enter') { e2.preventDefault(); keys.i++; keys.s++; removeEventListener('keydown', h); location.hash = '#/picker?state=livepick'; } }); } };
    addEventListener('keydown', h);
  }
  if (s === 'livepick') {
    const pi = $('#pi'); pi.focus(); let t = false;
    pi.addEventListener('input', () => { if (!t) { t = true; keys.f++; keys.i++; upd(); } $('#pl').innerHTML = MGR.map((m, i) => `<li role="option" aria-selected="${i === 0}"><b>${esc(m[0])}</b><span class="mono">${m[1]}</span><span class="sub">${esc(m[2])}</span></li>`).join(''); });
    pi.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); keys.i++; document.body.dataset.keys = JSON.stringify(keys); location.hash = '#/picker?state=done'; } });
  }
}

/* ---------- router ---------- */
function route() {
  seed = 7; document.body.dataset.keys = document.body.dataset.keys || ''; const r = parse();
  ({ changes: screenChanges, pso: screenPso, repl: screenRepl, picker: screenPicker }[r.screen] || screenChanges)(r);
  if (r.row != null && r.screen !== 'picker') { /* deep link: vtable preselects */ }
}
addEventListener('hashchange', route); route();

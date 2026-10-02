/* ============================================================
   Agents tab — the live agent graph. Vanilla ES module, no deps.
   Data: GET /api/graph?window=…  (nodes, edges, totals) and, for the
   side panel, GET /api/run/:id/tail. Nothing here is invented: every
   number on a card is a field of the API payload.

   Rendering: HTML cards absolutely positioned on a canvas, edges as
   SVG paths underneath. A deterministic layered layout (left → right)
   keys every card by its node id, so positions are stable between
   polls and cards glide to new positions.
   ============================================================ */

export const AG_WINDOWS = [['live', 'Live'], ['1h', '1h'], ['6h', '6h'], ['today', 'Today']];
export const AG_DEFAULT_WINDOW = '1h';

const POLL_MS = 4000;
const STALE_S = 12;
const GAP_X = 48;
const GAP_Y = 14;
const HEAD_H = 34;
const PAD = 8;
const SIZE = {
  ceo: [200, 118], dispatcher: [216, 150], director: [236, 138], worker: [244, 152], subagent: [220, 140], role: [200, 36],
};
const STAGE_LABEL = { in_progress: 'In progress', review: 'Review', qa: 'QA', other: 'Other' };
const STAGE_ORDER = ['in_progress', 'review', 'qa', 'other'];
const EDGE_GROUPS = [
  ['launch', 'Launch', ['launch']],
  ['spawn', 'Subagent spawn', ['spawn']],
  ['handoff', 'Hand-off', ['handoff']],
  ['reject', 'Reject', ['reject']],
  ['note', 'Note', ['note']],
  ['ceo', 'To / from CEO', ['ask', 'answer']],
];
const KIND_LABEL = {
  launch: 'Dispatcher launched', spawn: 'Subagent spawned', handoff: 'Ticket hand-off (advance)', reject: 'Ticket rejected back',
  note: 'Note on another role’s ticket', ask: 'Opened for the CEO', answer: 'CEO reply',
};
const ctxStateLabel = { ok: 'ok', warn: 'warning', checkpoint: 'checkpoint', critical: 'critical' };

/* ---------- helpers ---------- */
const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESC_MAP[c]);
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const ts = (v) => { const t = typeof v === 'number' ? v : Date.parse(v); return Number.isFinite(t) ? t : null; };
const fmtK = (n) => (n >= 1000 ? `${Math.round(n / 1000)}k` : String(Math.round(n || 0)));
const fmtUsd = (n) => (n == null ? '—' : `$${Number(n).toFixed(2)}`);
function fmtDur(sec) {
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  if (h) return `${h}h ${String(m).padStart(2, '0')}m`;
  if (m) return `${m}m ${String(s).padStart(2, '0')}s`;
  return `${s}s`;
}
function fmtRel(t, now = Date.now()) {
  const d = Math.max(0, (now - t) / 1000);
  if (d < 5) return 'just now';
  if (d < 60) return `${Math.floor(d)}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}
function modelLabel(n) {
  const m = /claude-(opus|sonnet|haiku)-(\d+)(?:-(\d{1,2}))?(?:-\d{8})?$/.exec(n.model_exact || '');
  if (m) return `${m[1][0].toUpperCase()}${m[1].slice(1)} ${m[2]}${m[3] ? `.${m[3]}` : ''}`;
  if (n.model) return n.model[0].toUpperCase() + n.model.slice(1);
  return n.model_exact || 'model n/a';
}
const pctText = (c) => `${Math.round(c.pct)}%`;
const tipTitle = (n) => `${n.label || n.role}${n.ticket ? ` · ${n.ticket}` : ''}`;
const jh = (v) => JSON.stringify(v);

/* ---------- node card HTML ---------- */
function ctxBar(c, { label = true } = {}) {
  const budget = c.budget || 0;
  return `<div class="ag-ctx st-${esc(c.state)}" role="meter" aria-label="Context used" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(c.pct)}" aria-valuetext="${esc(`${fmtK(c.tokens)} of ${fmtK(budget)} tokens, ${Math.round(c.pct)} percent, ${ctxStateLabel[c.state] || c.state}`)}">
    <span class="ag-ctx-track"><i data-w="${Math.min(100, c.pct).toFixed(1)}"></i><b data-x="60"></b><b data-x="72"></b><b data-x="80"></b></span>
    ${label ? `<span class="ag-ctx-l mono">${fmtK(c.tokens)} / ${fmtK(budget)}</span>` : ''}
  </div>`;
}

function modelChips(n) {
  const out = [];
  if (n.kind === 'subagent' && n.builtin) out.push(`<span class="chip ag-chip" title="Built-in subagent: no agent definition file">built-in</span>`);
  const label = `${modelLabel(n)}${n.effort ? ` · ${n.effort}` : ''}`;
  const bad = n.policy && !n.policy.ok;
  const title = [n.model_exact ? `Model ${n.model_exact}` : (n.model_source ? `Model ${n.model} (${n.model_source})` : ''), n.effort ? `effort ${n.effort}` : '', bad ? `policy: ${n.policy.problems.join('; ')}` : '']
    .filter(Boolean).join(' · ');
  out.push(`<span class="chip ag-chip model${bad ? ' warn' : ''}" title="${esc(title)}">${bad ? '⚠ ' : ''}${esc(label)}</span>`);
  if (n.effort_mismatch) out.push(`<span class="chip warn ag-chip" title="${esc(`Claude Code reports effective effort ${n.effort}; the agent definition says ${n.effort_configured}`)}">≠ ${esc(n.effort_configured)}</span>`);
  if (n.model_mismatch) out.push(`<span class="chip warn ag-chip" title="The log’s model does not match the run’s recorded model">model ≠</span>`);
  return out.join('');
}

function statusTag(n) {
  if (n.active) return `<span class="ag-st live"><span class="live-dot" aria-hidden="true"></span>${n.kind === 'director' ? 'live' : 'running'}</span>`;
  const cls = n.status === 'failed' || n.status === 'killed' ? 'crit' : n.status === 'done' || n.status === 'finished' ? 'ok' : '';
  return `<span class="ag-st ${cls}">${esc(n.status || '')}</span>`;
}

function workerCard(n) {
  const tool = n.active ? n.current_tool : n.result_line || n.last_activity;
  const elapsed = n.elapsed_ms != null ? fmtDur(n.elapsed_ms / 1000) : '';
  return `
    <div class="ag-r1"><span class="ag-name">${esc(n.role)}</span>${statusTag(n)}</div>
    <div class="ag-r2">${modelChips(n)}</div>
    ${ctxBar(n.context)}
    <div class="ag-r4"><span class="mono ag-tk">${esc(n.ticket || 'no ticket')}</span><span class="ag-stage-l">${esc(String(n.stage || '').replace('_', ' '))}</span>${n.handoff_pending ? '<span class="chip warn ag-chip" title="Stopped at a context checkpoint; the next session continues from the handoff">handoff</span>' : ''}${n.continuation ? '<span class="chip ag-chip" title="Continues an earlier session via its handoff">cont.</span>' : ''}</div>
    <div class="ag-r5 mono" title="${esc(tool || '')}">${esc(tool || (n.active ? 'working…' : '—'))}</div>
    <div class="ag-r6 mono">
      <span ${n.active ? `data-elapsed="${esc(n.started)}"` : ''}>${esc(elapsed)}</span>
      <span>${fmtUsd(n.cost_usd)}</span><span>${n.turns} turns</span>
      <span class="ag-co" title="${n.checkout === 'worktree' ? 'Working in the ticket worktree' : 'Working in the main checkout'}">${n.checkout === 'worktree' ? 'wt' : 'main'}</span>
    </div>
    ${n.active && n.pid_alive === false ? '<span class="ag-flag" title="The worker process is not alive although the run is marked running">process gone</span>' : ''}
    ${n.subagent_count ? `<button class="ag-sub-toggle mono" type="button" data-ag-expand="${esc(n.id)}" aria-label="Show or hide ${n.subagent_count} subagents of ${esc(n.role)}"></button>` : ''}`;
}

function subagentCard(n) {
  return `
    <div class="ag-r1"><span class="ag-name">${esc(n.label)}</span>${statusTag(n)}</div>
    <div class="ag-r2">${modelChips(n)}</div>
    ${ctxBar(n.context)}
    <div class="ag-r5 mono ag-desc" title="${esc(n.description)}">${esc(n.description || '—')}</div>
    <div class="ag-r5 mono" title="${esc((n.active ? n.current_tool : n.last_tool) || '')}">${esc((n.active ? n.current_tool : n.last_tool) || (n.active ? 'working…' : '—'))}</div>
    <div class="ag-r6 mono"><span ${n.active ? `data-elapsed="${esc(n.started)}"` : ''}>${n.elapsed_ms != null ? esc(fmtDur(n.elapsed_ms / 1000)) : ''}</span><span>${n.turns} turns</span>${n.tool_uses != null ? `<span>${n.tool_uses} tools</span>` : ''}</div>`;
}

function directorCard(n) {
  return `
    <div class="ag-r1"><span class="ag-name">${esc(n.role)}</span>${statusTag(n)}</div>
    <div class="ag-r2">${modelChips(n)}<span class="chip ag-chip" title="Your interactive session">interactive</span></div>
    ${ctxBar(n.context)}
    <div class="ag-r4"><span class="ag-stage-l">peak ${fmtK(n.context.peak)} · ${pctText(n.context)}</span></div>
    <div class="ag-r5 mono" title="${esc(n.current_tool || '')}">${esc(n.current_tool || 'idle')}</div>
    <div class="ag-r6 mono"><span data-since="${esc(n.started)}">${n.elapsed_ms != null ? `up ${esc(fmtDur(n.elapsed_ms / 1000))}` : ''}</span></div>`;
}

function ceoCard(n) {
  const d = n.open_decisions.length, a = n.open_actions.length, p = n.pending_notices.length;
  const row = (count, one, many) => `<div class="ag-r5 ${count ? 'ag-ask' : 'muted'}">${count ? `<b class="mono">${count}</b> ${esc(count === 1 ? one : many)}` : esc(`no ${many}`)}</div>`;
  return `
    <div class="ag-r1"><span class="ag-name">${esc(n.label)}</span><span class="chip ceo ag-chip">CEO</span></div>
    ${row(d, 'decision waiting', 'decisions waiting')}
    ${row(a, 'action open', 'actions open')}
    ${row(p, 'notice to acknowledge', 'notices to acknowledge')}
    <div class="ag-r6 mono"><a class="ag-link" href="#decisions">Open Decisions →</a></div>`;
}

function dispatcherCard(n) {
  const slots = `${n.active_runs} / ${n.max_parallel}`;
  const capPct = n.daily_run_cap ? Math.min(100, (n.runs_today / n.daily_run_cap) * 100) : 0;
  const capState = n.runs_today >= n.daily_run_cap ? 'critical' : capPct >= 80 ? 'warn' : 'ok';
  const backoff = n.backoff_until ? `<span class="chip warn ag-chip" title="Rate-limited; no launches until then">rate limit · <span data-until="${esc(n.backoff_until)}"></span></span>` : '';
  const hb = n.heartbeat ? `<span data-rel="${esc(n.heartbeat)}">${esc(fmtRel(ts(n.heartbeat)))}</span>` : 'never';
  return `
    <div class="ag-r1"><span class="ag-name">dispatcher</span><span class="ag-st ${n.alive ? 'ok' : 'crit'}">${n.alive ? 'alive' : 'no heartbeat'}</span></div>
    <div class="ag-r2">${n.paused ? `<span class="chip warn ag-chip" title="${esc(n.pause_reason || 'Paused from the board')}">paused</span>` : ''}${backoff}<span class="chip ag-chip" title="Running workers / max parallel">${slots} slots</span></div>
    <div class="ag-ctx st-${capState}" role="meter" aria-label="Runs today" aria-valuemin="0" aria-valuemax="${n.daily_run_cap}" aria-valuenow="${n.runs_today}" aria-valuetext="${n.runs_today} of ${n.daily_run_cap} runs today">
      <span class="ag-ctx-track"><i data-w="${capPct.toFixed(1)}"></i></span><span class="ag-ctx-l mono">${n.runs_today} / ${n.daily_run_cap} runs</span></div>
    <div class="ag-r5 mono" title="${esc(n.last_action || '')}">${esc(String(n.last_action || '').replace(/^\S+\s/, '') || '—')}</div>
    <div class="ag-r6 mono"><span>heartbeat ${hb}</span>${n.pid ? `<span>pid ${n.pid}</span>` : ''}</div>`;
}

function roleCard(n) {
  return `<div class="ag-r1"><span class="ag-name">${esc(n.role)}</span><span class="ag-st">no run</span></div>`;
}

function cardInner(n) {
  switch (n.kind) {
    case 'worker': return workerCard(n);
    case 'subagent': return subagentCard(n);
    case 'director': return directorCard(n);
    case 'ceo': return ceoCard(n);
    case 'dispatcher': return dispatcherCard(n);
    default: return roleCard(n);
  }
}

function ariaLabel(n) {
  if (n.kind === 'ceo') return `${n.label}, CEO: ${n.open_decisions.length} decisions, ${n.open_actions.length} actions waiting`;
  if (n.kind === 'dispatcher') return `Dispatcher, ${n.alive ? 'alive' : 'no heartbeat'}, ${n.runs_today} of ${n.daily_run_cap} runs today`;
  if (n.kind === 'role') return `${n.role}, no run in this window`;
  const c = n.context;
  return `${n.label}, ${n.active ? 'running' : n.status}, ${modelLabel(n)} ${n.effort || ''}, context ${fmtK(c.tokens)} of ${fmtK(c.budget)} (${Math.round(c.pct)} percent, ${ctxStateLabel[c.state]})${n.ticket ? `, ticket ${n.ticket}` : ''}`;
}

/* ---------- layout ---------- */
/** Deterministic layered layout. Returns node positions, column headers and the canvas size. */
export function layoutGraph(graph, expanded = new Set()) {
  const nodes = graph.nodes;
  const byKind = (k) => nodes.filter((n) => n.kind === k);
  const workers = byKind('worker');
  const directors = byKind('director').sort((a, b) => a.id.localeCompare(b.id));
  const stubs = byKind('role').sort((a, b) => a.role.localeCompare(b.role));
  const subsOf = new Map();
  for (const s of byKind('subagent')) {
    const list = subsOf.get(s.parent) ?? [];
    list.push(s);
    subsOf.set(s.parent, list);
  }
  const showSubs = (w) => (subsOf.get(w.id)?.length ?? 0) > 0 && (w.active || expanded.has(w.id));

  const columns = [];
  const pos = new Map();
  let x = PAD;
  const addColumn = (key, label, width) => {
    const col = { key, label, x, w: width, count: 0, y: HEAD_H + PAD };
    columns.push(col);
    x += width + GAP_X;
    return col;
  };
  const place = (col, n, h = SIZE[n.kind][1]) => {
    pos.set(n.id, { x: col.x, y: col.y, w: col.w, h, col: col.key });
    col.y += h + GAP_Y;
    col.count += 1;
  };

  const ceo = nodes.find((n) => n.kind === 'ceo');
  const disp = nodes.find((n) => n.kind === 'dispatcher');
  const cYou = addColumn('you', 'You', SIZE.ceo[0]);
  if (ceo) place(cYou, ceo);
  if (directors.length || stubs.length) {
    const cDir = addColumn('director', 'Director', SIZE.director[0]);
    for (const d of directors) place(cDir, d);
    if (stubs.length) {
      cDir.y += GAP_Y;
      cDir.stubStart = cDir.y;
      for (const s of stubs) place(cDir, s);
    }
  }
  const cDisp = addColumn('dispatcher', 'Dispatcher', SIZE.dispatcher[0]);
  if (disp) place(cDisp, disp);

  const groups = STAGE_ORDER.filter((g) => workers.some((w) => w.group === g));
  const stageCols = new Map(groups.map((g) => [g, addColumn(`stage:${g}`, STAGE_LABEL[g], SIZE.worker[0])]));
  const sortWorkers = (a, b) => (b.active - a.active) || String(b.run_id).localeCompare(String(a.run_id));
  for (const g of groups) for (const w of workers.filter((n) => n.group === g).sort(sortWorkers)) place(stageCols.get(g), w);

  const anySubs = workers.some(showSubs);
  if (anySubs) {
    const cSub = addColumn('sub', 'Subagents', SIZE.subagent[0]);
    // children sit next to their parent, in parent order, never overlapping
    const parents = workers.filter(showSubs).sort((a, b) => pos.get(a.id).y - pos.get(b.id).y);
    for (const w of parents) {
      cSub.y = Math.max(cSub.y, pos.get(w.id).y);
      for (const s of subsOf.get(w.id).sort((a, b) => String(a.started).localeCompare(String(b.started)) || a.id.localeCompare(b.id))) place(cSub, s);
    }
  }
  const hiddenSubs = new Set();
  for (const w of workers) if (!showSubs(w)) for (const s of subsOf.get(w.id) ?? []) hiddenSubs.add(s.id);

  const last = columns.at(-1);
  const width = last.x + last.w + PAD;
  const height = Math.max(...columns.map((c) => c.y)) + PAD;
  return { pos, columns, width, height, hiddenSubs, subsOf };
}

/* ---------- edge geometry ---------- */
function portSpread(edges, pos) {
  // fan the ends of several edges that meet at the same side of a card
  const ends = new Map();
  const add = (nodeId, side, edgeId, otherY) => {
    const k = `${nodeId}|${side}`;
    const list = ends.get(k) ?? [];
    list.push({ edgeId, otherY });
    ends.set(k, list);
  };
  const sides = (e) => {
    const a = pos.get(e.from), b = pos.get(e.to);
    const ca = a.x, cb = b.x;
    if (ca < cb) return ['r', 'l'];
    if (ca > cb) return ['l', 'r'];
    return ['r', 'r'];
  };
  for (const e of edges) {
    const a = pos.get(e.from), b = pos.get(e.to);
    const [sa, sb] = sides(e);
    add(e.from, sa, `${e.id}|a`, b.y);
    add(e.to, sb, `${e.id}|b`, a.y);
  }
  const offset = new Map();
  for (const [k, list] of ends) {
    const id = k.slice(0, k.lastIndexOf('|'));
    const h = pos.get(id).h;
    list.sort((p, q) => p.otherY - q.otherY || p.edgeId.localeCompare(q.edgeId));
    const step = list.length > 1 ? Math.min(7, (h - 28) / (list.length - 1)) : 0;
    list.forEach((it, i) => offset.set(it.edgeId, (i - (list.length - 1) / 2) * step));
  }
  return { sides, offset };
}

function edgePath(e, pos, spread) {
  const a = pos.get(e.from), b = pos.get(e.to);
  const [sa, sb] = spread.sides(e);
  const x1 = sa === 'r' ? a.x + a.w : a.x;
  const x2 = sb === 'l' ? b.x : b.x + b.w;
  const y1 = a.y + a.h / 2 + (spread.offset.get(`${e.id}|a`) ?? 0);
  const y2 = b.y + b.h / 2 + (spread.offset.get(`${e.id}|b`) ?? 0);
  let d;
  let mx, my;
  if (sa === 'r' && sb === 'r') {
    const out = 46 + Math.min(60, Math.abs(y2 - y1) / 6);
    d = `M${x1},${y1} C${x1 + out},${y1} ${x2 + out},${y2} ${x2},${y2}`;
    mx = Math.max(x1, x2) + out * 0.75; my = (y1 + y2) / 2;
  } else {
    const dx = Math.max(36, Math.abs(x2 - x1) * 0.5);
    const s = sa === 'r' ? 1 : -1;
    d = `M${x1},${y1} C${x1 + s * dx},${y1} ${x2 - s * dx},${y2} ${x2},${y2}`;
    mx = (x1 + x2) / 2; my = (y1 + y2) / 2;
  }
  return { d, mx, my };
}

/* ---------- the view ---------- */
/**
 * @param {{fixture?: boolean, onTicket?: (id:string)=>void}} opts
 */
export function createAgentsView({ fixture = false } = {}) {
  const els = {
    root: $('#ag'), totals: $('#ag-totals'), win: $('#ag-win'), updated: $('#ag-updated'), legend: $('#ag-legend'),
    err: $('#ag-err'), viewport: $('#ag-viewport'), scale: $('#ag-scale'), cols: $('#ag-cols'), edges: $('#ag-edges'),
    nodes: $('#ag-nodes'), side: $('#ag-side'), tip: $('#ag-tip'), empty: $('#ag-empty'),
  };
  const st = {
    window: AG_DEFAULT_WINDOW, graph: null, fetchedAt: 0, failures: 0, timer: null, active: false, inflight: null,
    sel: null, hover: null, expanded: new Set(), off: new Set(['note']), cards: new Map(), paths: new Map(),
    tail: { run: null, text: '', at: 0, err: null }, layoutKey: '', scale: 1,
  };
  let edgeLookup = new Map();

  /* ---- fetching ---- */
  async function fetchGraph() {
    if (st.inflight) return;
    const ctl = new AbortController();
    st.inflight = ctl;
    const win = st.window;
    try {
      const res = await fetch(`/api/graph?window=${encodeURIComponent(win)}`, { cache: 'no-store', signal: ctl.signal });
      if (!res.ok) throw new Error(`the board answered ${res.status}`);
      const g = await res.json();
      if (win !== st.window) return;
      st.graph = g; st.fetchedAt = Date.now(); st.failures = 0;
      render();
      if (st.sel) refreshTail();
    } catch (e) {
      if (e.name === 'AbortError') return;
      st.failures += 1;
      renderChrome(e);
    } finally {
      if (st.inflight === ctl) st.inflight = null;
    }
  }
  function schedule() {
    clearTimeout(st.timer);
    st.timer = null;
    if (!st.active || document.hidden) return;
    const delay = st.failures ? Math.min(30000, POLL_MS * 2 ** Math.min(st.failures, 4)) : POLL_MS;
    st.timer = setTimeout(async () => { await fetchGraph(); schedule(); }, delay);
  }
  function now() { return Date.now(); }

  /* ---- chrome: header, totals, banners ---- */
  function renderChrome(err) {
    const g = st.graph;
    for (const b of $$('[data-ag-win]', els.win)) b.setAttribute('aria-pressed', b.dataset.agWin === st.window ? 'true' : 'false');
    if (err || st.failures) {
      els.err.hidden = false;
      els.err.innerHTML = `Can’t read the agent graph${err?.message ? `: ${esc(err.message)}` : ''}. ${g ? `Showing data from ${esc(fmtRel(st.fetchedAt))}.` : ''} <button class="linkbtn" type="button" data-ag-retry>Retry now</button>`;
    } else els.err.hidden = true;
    if (!g) return;
    const t = g.totals;
    const stat = (label, value, sub, cls = '') => `<div class="ag-stat ${cls}"><span class="ag-stat-k">${esc(label)}</span><span class="ag-stat-v mono">${value}</span>${sub ? `<span class="ag-stat-s mono">${sub}</span>` : ''}</div>`;
    const html = [
      stat('Active agents', String(t.active_agents), `${t.active_workers} workers · ${t.active_subagents} subagents · ${t.active_directors} directors`, t.active_agents ? 'live' : ''),
      stat('Context in use', fmtK(t.context_tokens), 'summed across active agents'),
      stat(`Cost · ${AG_WINDOWS.find(([k]) => k === st.window)?.[1] ?? st.window}`, fmtUsd(t.cost_usd), `${t.runs_in_window} runs${t.runs_failed ? ` · ${t.runs_failed} failed` : ''}`),
      stat('Runs today', `${t.runs_today} / ${t.daily_run_cap}`, t.runs_today >= t.daily_run_cap ? 'daily cap reached' : `${t.daily_run_cap - t.runs_today} left`, t.runs_today >= t.daily_run_cap ? 'crit' : ''),
    ].join('');
    if (els.totals._k !== html) { els.totals.innerHTML = html; els.totals._k = html; }
    const stale = (now() - st.fetchedAt) / 1000;
    els.updated.textContent = `${st.fetchedAt ? `updated ${fmtRel(st.fetchedAt)}` : ''}`;
    els.updated.classList.toggle('stale', stale > STALE_S);
    els.updated.title = stale > STALE_S ? 'The graph has not refreshed recently' : 'Polls every 4 s while this tab is visible';
    renderLegend();
  }

  function renderLegend() {
    const present = new Set(st.graph?.edges.map((e) => e.kind) ?? []);
    const html = `<span class="ag-lg-h mono">Edges</span>${EDGE_GROUPS.map(([key, label, kinds]) => {
      const on = !st.off.has(key);
      const n = st.graph?.edges.filter((e) => kinds.includes(e.kind)).length ?? 0;
      return `<button class="ag-lg k-${key}${on ? ' on' : ''}" type="button" data-ag-kind="${key}" aria-pressed="${on}" title="${on ? 'Hide' : 'Show'} ${esc(label.toLowerCase())} edges"><svg width="22" height="8" aria-hidden="true"><path d="M1 4 H21" class="ag-lg-line e-${kinds[0]}"/></svg>${esc(label)}<span class="mono">${present.size ? n : ''}</span></button>`;
    }).join('')}
      <span class="ag-lg-sep" aria-hidden="true"></span><span class="ag-lg-h mono">Context</span>
      <span class="ag-lg-key st-ok"><i></i>&lt; 60%</span><span class="ag-lg-key st-warn"><i></i>60–72%</span><span class="ag-lg-key st-checkpoint"><i></i>72–80% checkpoint</span><span class="ag-lg-key st-critical"><i></i>≥ 80%</span>
      <span class="ag-lg-sep" aria-hidden="true"></span><span class="ag-lg-key"><span class="chip warn ag-chip">⚠ / ≠</span>policy or effort mismatch</span>
      <span class="ag-lg-key"><i class="ag-lg-dash"></i>animated = active now</span>`;
    if (els.legend._k !== html) { els.legend.innerHTML = html; els.legend._k = html; }
  }

  /* ---- main render ---- */
  function render() {
    const g = st.graph;
    renderChrome();
    if (!g) return;
    const lay = layoutGraph(g, st.expanded);
    const visibleNodes = g.nodes.filter((n) => lay.pos.has(n.id));
    renderCards(visibleNodes, lay);
    renderColumns(lay);
    renderEdges(g, lay);
    fit(lay);
    renderEmpty(g);
    applyHighlight();
    if (st.sel) renderSide();
    tick();
  }

  function renderCards(nodes, lay) {
    const keep = new Set();
    for (const n of nodes) {
      keep.add(n.id);
      const p = lay.pos.get(n.id);
      let el = st.cards.get(n.id);
      if (!el) {
        el = document.createElement('div');
        el.className = 'ag-node';
        el.dataset.id = n.id;
        el.tabIndex = 0;
        el.setAttribute('role', 'button');
        st.cards.set(n.id, el);
        els.nodes.appendChild(el);
        el.style.transform = `translate(${p.x}px, ${p.y}px)`; // first paint: no glide from the corner
      }
      el.className = `ag-node k-${n.kind}${n.active ? ' is-active' : ' is-idle'}${n.kind === 'worker' || n.kind === 'subagent' || n.kind === 'director' ? ` ctx-${n.context.state}` : ''}${n.status === 'failed' || n.status === 'killed' ? ' is-failed' : ''}${st.sel === n.id ? ' is-selected' : ''}`;
      el.style.width = `${p.w}px`;
      el.style.height = `${p.h}px`;
      el.style.transform = `translate(${p.x}px, ${p.y}px)`;
      el.setAttribute('aria-label', ariaLabel(n));
      el.setAttribute('aria-pressed', st.sel === n.id ? 'true' : 'false');
      const exp = st.expanded.has(n.id);
      const key = jh([n, exp]);
      if (el._k !== key) {
        el.innerHTML = cardInner(n);
        el._k = key;
        hydrate(el);
        const tog = $('.ag-sub-toggle', el);
        if (tog) tog.textContent = n.active ? `${n.subagent_count} subagent${n.subagent_count === 1 ? '' : 's'}` : `${exp ? '− hide' : '+ show'} ${n.subagent_count} subagent${n.subagent_count === 1 ? '' : 's'}`;
        if (tog && n.active) tog.disabled = true;
      }
    }
    for (const [id, el] of st.cards) if (!keep.has(id)) { el.remove(); st.cards.delete(id); }
  }

  /** Sets widths/positions through CSSOM (the board's CSP forbids inline style attributes). */
  function hydrate(root) {
    for (const i of $$('i[data-w]', root)) i.style.width = `${i.dataset.w}%`;
    for (const b of $$('b[data-x]', root)) b.style.left = `${b.dataset.x}%`;
  }

  function renderColumns(lay) {
    const html = lay.columns.map((c) => `<div class="ag-col-h mono" data-x="${c.x}" data-w="${c.w}">${esc(c.label)}${c.count ? ` <span>${c.count}</span>` : ''}</div>`).join('');
    const key = html;
    if (els.cols._k !== key) {
      els.cols.innerHTML = html;
      els.cols._k = key;
    }
    $$('.ag-col-h', els.cols).forEach((h) => { h.style.transform = `translateX(${h.dataset.x}px)`; h.style.width = `${h.dataset.w}px`; });
  }

  function renderEdges(g, lay) {
    const visible = g.edges.filter((e) => {
      if (!lay.pos.has(e.from) || !lay.pos.has(e.to)) return false;
      const group = EDGE_GROUPS.find(([, , kinds]) => kinds.includes(e.kind))?.[0];
      return !st.off.has(group);
    });
    edgeLookup = new Map(visible.map((e) => [e.id, e]));
    const spread = portSpread(visible, lay.pos);
    const keep = new Set();
    els.edges.setAttribute('width', lay.width);
    els.edges.setAttribute('height', lay.height);
    els.edges.setAttribute('viewBox', `0 0 ${lay.width} ${lay.height}`);
    const layer = $('#ag-edge-layer');
    const nowMs = now();
    // draw order: faint first, active last (so flowing edges are never hidden under idle ones)
    const sorted = [...visible].sort((a, b) => (a.active - b.active) || (ts(a.last_ts) - ts(b.last_ts)));
    for (const e of sorted) {
      keep.add(e.id);
      const { d, mx, my } = edgePath(e, lay.pos, spread);
      let grp = st.paths.get(e.id);
      if (!grp) {
        grp = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        grp.dataset.id = e.id;
        grp.innerHTML = '<path class="ag-hit"/><path class="ag-edge" marker-end=""/><g class="ag-cnt"><circle r="8"/><text text-anchor="middle" dy="3.5"></text></g>';
        st.paths.set(e.id, grp);
      }
      layer.appendChild(grp); // re-appending keeps the sorted draw order
      const [hit, vis, cnt] = grp.children;
      hit.setAttribute('d', d);
      vis.setAttribute('d', d);
      const recent = nowMs - ts(e.last_ts) < 15 * 60_000;
      grp.setAttribute('class', `ag-eg e-${e.kind}${e.active ? ' is-active' : ' is-idle'}${recent ? ' is-recent' : ''}`);
      vis.setAttribute('class', 'ag-edge');
      vis.setAttribute('marker-end', `url(#ag-arrow-${e.kind})`);
      if (e.count > 1 && e.kind !== 'launch' && e.kind !== 'spawn') {
        cnt.style.display = '';
        cnt.setAttribute('transform', `translate(${mx} ${my})`);
        cnt.lastChild.textContent = `${e.count}`;
      } else cnt.style.display = 'none';
    }
    for (const [id, grp] of st.paths) if (!keep.has(id)) { grp.remove(); st.paths.delete(id); }
  }

  function fit(lay) {
    const avail = els.viewport.clientWidth || lay.width;
    const s = Math.max(0.62, Math.min(1, (avail - 4) / lay.width));
    st.scale = s;
    els.scale.style.transform = `scale(${s})`;
    els.scale.style.width = `${lay.width}px`;
    els.scale.style.height = `${lay.height}px`;
    els.viewport.style.setProperty('--ag-h', `${Math.ceil(lay.height * s) + 4}px`);
  }

  function renderEmpty(g) {
    const workers = g.nodes.filter((n) => n.kind === 'worker');
    const running = g.totals.active_agents;
    const disp = g.nodes.find((n) => n.kind === 'dispatcher');
    let msg = '';
    if (!workers.length) msg = `No agent runs in this window${st.window === 'live' ? ' (last 5 minutes)' : ''}. ${disp?.last_action ? `Dispatcher: ${String(disp.last_action).replace(/^\S+\s/, '')}` : ''}`;
    else if (!g.totals.active_workers) msg = `Nothing is running right now. Faded cards finished inside this window.${disp?.last_action ? ` Dispatcher: ${String(disp.last_action).replace(/^\S+\s/, '')}` : ''}`;
    els.empty.hidden = !msg || running > 0 && g.totals.active_workers > 0;
    els.empty.textContent = msg;
  }

  /* ---- hover / selection highlighting ---- */
  function applyHighlight() {
    const focus = st.hover ?? st.sel;
    els.edges.classList.toggle('has-focus', Boolean(focus));
    for (const [id, grp] of st.paths) {
      const e = edgeLookup.get(id);
      grp.classList.toggle('hl', Boolean(focus && e && (e.from === focus || e.to === focus)));
    }
    for (const [id, el] of st.cards) {
      const linked = focus && [...edgeLookup.values()].some((e) => (e.from === focus && e.to === id) || (e.to === focus && e.from === id));
      el.classList.toggle('is-linked', Boolean(linked));
      el.classList.toggle('is-dim', Boolean(focus && id !== focus && !linked));
    }
  }

  /* ---- side panel ---- */
  function nodeById(id) { return st.graph?.nodes.find((n) => n.id === id) ?? null; }
  function ago(v) { const t = ts(v); return t == null ? '' : fmtRel(t); }
  function kv(label, val) { return val == null || val === '' ? '' : `<div><dt>${esc(label)}</dt><dd>${val}</dd></div>`; }

  function sideBody(n) {
    const g = st.graph;
    const c = n.context;
    const lines = [];
    const ctxRow = c ? kv('Context', `<div class="ag-side-ctx">${ctxBar(c, { label: false })}<span class="mono">${c.tokens.toLocaleString()} / ${c.budget.toLocaleString()} tokens · ${c.pct}% · <b class="st-${esc(c.state)}">${esc(ctxStateLabel[c.state])}</b></span></div><span class="muted mono">peak ${c.peak.toLocaleString()} · thresholds ${g.context_thresholds.warn_pct}/${g.context_thresholds.checkpoint_pct}/${g.context_thresholds.critical_pct}%</span>`) : '';
    if (n.kind === 'worker') {
      lines.push(
        kv('Status', `${esc(n.status)}${n.active ? ' · running' : ''}${n.pid_alive === false ? ' · <b class="st-critical">process not alive</b>' : ''}`),
        kv('Model', `${esc(modelLabel(n))}${n.model_exact ? ` <span class="mono muted">${esc(n.model_exact)}</span>` : ''}`),
        kv('Effort', `${esc(n.effort || '—')}${n.effort_mismatch ? ` <span class="chip warn ag-chip">agent definition says ${esc(n.effort_configured)}</span>` : ''}`),
        n.policy.ok ? '' : kv('Policy', `<span class="chip warn ag-chip">⚠ ${esc(n.policy.problems.join('; '))}</span>`),
        ctxRow,
        kv('Ticket', n.ticket ? `<a class="chip tlink" href="#" data-ticket-nav="${esc(n.ticket)}">${esc(n.ticket)}</a> ${esc(n.ticket_title || '')}${n.ticket_status ? ` <span class="muted mono">(${esc(n.ticket_status)})</span>` : ''}` : 'none'),
        kv('Stage', esc(n.stage || '—')),
        kv('Started', `${esc(new Date(n.started).toLocaleString())} · ${esc(fmtDur((n.elapsed_ms || 0) / 1000))}${n.active ? ' so far' : ''}`),
        kv('Turns · cost', `${n.turns} turns · ${fmtUsd(n.cost_usd)}${n.cost_usd == null ? ' <span class="muted">(reported when the run ends)</span>' : ''}`),
        kv('Checkout', n.checkout === 'worktree' ? 'ticket worktree' : 'main checkout'),
        n.continuation ? kv('Continuation', 'continues an earlier session from its handoff') : '',
        n.handoff_pending ? kv('Handoff', `<span class="chip warn ag-chip">pending</span> ${esc(n.handoff_latest || '')}`) : '',
        n.idle_ms != null ? kv('Log silent for', esc(fmtDur(n.idle_ms / 1000))) : '',
        n.pid ? kv('PID', `<span class="mono">${n.pid}</span>`) : '',
        n.result_line ? kv('Result', `<span class="mono">${esc(n.result_line)}</span>`) : '',
      );
    } else if (n.kind === 'subagent') {
      const parent = nodeById(n.parent);
      lines.push(
        kv('Status', esc(n.status)),
        kv('Task', esc(n.description || '—')),
        kv('Spawned by', parent ? `${esc(parent.role)} <span class="muted mono">${esc(parent.run_id)}</span>` : ''),
        kv('Model', `${esc(modelLabel(n))}${n.model_exact ? ` <span class="mono muted">${esc(n.model_exact)}</span>` : ''}${n.builtin ? ' <span class="chip ag-chip">built-in</span>' : ''}`),
        kv('Effort', esc(n.effort || (n.builtin ? 'built-in (no agent file)' : '—'))),
        ctxRow,
        kv('Turns', `${n.turns}${n.tool_uses != null ? ` · ${n.tool_uses} tool calls` : ''}${n.total_tokens != null ? ` · ${n.total_tokens.toLocaleString()} tokens processed` : ''}`),
        kv('Started', n.started ? `${esc(new Date(n.started).toLocaleString())} · ${esc(fmtDur((n.elapsed_ms || 0) / 1000))}` : ''),
        n.ticket ? kv('Ticket', `<a class="chip tlink" href="#" data-ticket-nav="${esc(n.ticket)}">${esc(n.ticket)}</a>`) : '',
      );
    } else if (n.kind === 'director') {
      lines.push(
        kv('Session', '<span class="chip ag-chip">interactive</span> your session'),
        kv('Model', `${esc(modelLabel(n))} <span class="muted">(${esc(n.model_source || '')}; interactive sessions do not report their model)</span>`),
        kv('Effort', esc(n.effort || '—')),
        ctxRow,
        kv('Current tool', `<span class="mono">${esc(n.current_tool || 'idle')}</span>`),
        kv('Up', esc(fmtDur((n.elapsed_ms || 0) / 1000))),
        kv('Last activity', esc(ago(n.updated))),
        n.ticket ? kv('Ticket', `<a class="chip tlink" href="#" data-ticket-nav="${esc(n.ticket)}">${esc(n.ticket)}</a>`) : '',
      );
    } else if (n.kind === 'dispatcher') {
      lines.push(
        kv('Heartbeat', n.alive ? `alive · ${esc(ago(n.heartbeat))}` : `<b class="st-critical">no heartbeat</b> · last ${esc(ago(n.heartbeat) || 'never')}`),
        kv('PID', n.pid ? `<span class="mono">${n.pid}</span>` : ''),
        kv('Slots', `${n.active_runs} of ${n.max_parallel} workers running`),
        kv('Runs today', `${n.runs_today} of ${n.daily_run_cap}`),
        n.paused ? kv('Paused', esc(n.pause_reason || 'paused from the board')) : '',
        n.backoff_until ? kv('Rate limit', `no launches until ${esc(new Date(n.backoff_until).toLocaleTimeString())}`) : '',
        kv('Last action', `<span class="mono">${esc(n.last_action || '—')}</span>`),
      );
    } else if (n.kind === 'ceo') {
      const list = (items, label) => (items.length ? kv(label, `<ul class="ag-list">${items.map((i) => `<li><span class="mono">${esc(i.id)}</span> ${esc(i.title)}</li>`).join('')}</ul>`) : '');
      lines.push(
        list(n.open_decisions, 'Decisions waiting'), list(n.open_actions, 'Actions open'), list(n.pending_notices, 'Notices to acknowledge'),
        !n.open_decisions.length && !n.open_actions.length && !n.pending_notices.length ? kv('Waiting on you', 'nothing') : '',
        kv('Open', '<a class="linkbtn" href="#decisions">Decisions tab →</a>'),
      );
    } else {
      lines.push(kv('Role', esc(n.role)), kv('Model', `${esc(modelLabel(n))}${n.effort ? ` · ${esc(n.effort)}` : ''} <span class="muted">(agent definition)</span>`),
        kv('Why shown', 'a ticket moved to or from this role inside the window, but it has no run in it'));
    }

    // who talks to whom
    const edges = g.edges.filter((e) => e.from === n.id || e.to === n.id);
    const label = (id) => { const o = nodeById(id); return o ? (o.kind === 'worker' ? o.role : o.label || o.role) : id; };
    const talk = edges.length ? `<ul class="ag-edges-l">${[...edges].sort((a, b) => ts(b.last_ts) - ts(a.last_ts)).map((e) => `<li class="e-${esc(e.kind)}"><span class="ag-arrow">${e.from === n.id ? '→' : '←'}</span><span><b>${esc(label(e.from === n.id ? e.to : e.from))}</b> <span class="muted">${esc(KIND_LABEL[e.kind] || e.kind)}</span><br><span class="mono">${esc(e.label)}</span> <span class="muted mono">${esc(ago(e.last_ts))}${e.active ? ' · active' : ''}</span></span></li>`).join('')}</ul>` : '<p class="muted">No traffic in this window.</p>';

    const act = n.activity?.length ? `<ul class="ag-act mono">${n.activity.map((a) => `<li class="${a.kind}"><span class="muted">${a.ts ? esc(new Date(a.ts).toLocaleTimeString()) : ''}</span> ${esc(a.text)}</li>`).join('')}</ul>` : '';
    const tail = n.kind === 'worker' ? `<pre class="ag-tail mono" id="ag-tail" tabindex="0" aria-label="Tail of run ${esc(n.run_id)}">${esc(st.tail.run === n.run_id ? (st.tail.err ? `Couldn’t load the log: ${st.tail.err}` : st.tail.text || 'Loading log…') : 'Loading log…')}</pre><a class="linkbtn" href="/api/run/${encodeURIComponent(n.run_id)}/tail?lines=200" target="_blank" rel="noopener noreferrer">Open the full run tail (JSON) ↗</a>` : '';
    const events = n.ticket_events?.length ? `<ol class="ag-ev">${n.ticket_events.map((ev) => `<li><span class="muted mono">${esc(ago(ev.ts))}</span> <span class="chip ag-chip">${esc(ev.actor)}</span> ${esc(ev.text)}</li>`).join('')}</ol>` : '';
    const sec = (title, inner) => (inner ? `<section class="ag-sec"><h3>${esc(title)}</h3>${inner}</section>` : '');
    return `<dl class="ag-kv">${lines.join('')}</dl>${sec('Talks to', talk)}${sec(n.active ? 'Doing now' : 'Last activity', act)}${sec('Recent ticket events', events)}${sec('Run log', tail)}`;
  }

  function renderSide() {
    const n = nodeById(st.sel);
    if (!n) { closeSide(); return; }
    els.side.hidden = false;
    const head = `<header class="ag-side-h"><div><span class="ag-side-k mono">${esc(n.kind)}</span><h2>${esc(n.kind === 'worker' || n.kind === 'subagent' ? n.label : (n.label || n.role || n.kind))}</h2></div><button class="btn icon" type="button" data-ag-close aria-label="Close details"><svg class="ic" aria-hidden="true"><use href="#i-x"/></svg></button></header>`;
    const body = sideBody(n);
    const key = `${n.id}|${jh([n, st.graph.edges.filter((e) => e.from === n.id || e.to === n.id)])}|${st.tail.run}|${st.tail.at}`;
    if (els.side._k === key) return;
    const scroller = $('.ag-side-b', els.side);
    const top = scroller ? scroller.scrollTop : 0;
    const sameNode = els.side._n === n.id;
    els.side.innerHTML = `${head}<div class="ag-side-b">${body}</div>`;
    hydrate(els.side);
    els.side._k = key; els.side._n = n.id;
    const sc = $('.ag-side-b', els.side);
    if (sameNode && sc) sc.scrollTop = top;
    const pre = $('#ag-tail', els.side);
    if (pre) pre.scrollTop = pre.scrollHeight;
  }
  function closeSide() {
    const had = st.sel;
    st.sel = null;
    els.side.hidden = true;
    els.side._k = null; els.side._n = null;
    for (const el of st.cards.values()) el.classList.remove('is-selected');
    applyHighlight();
    if (had) st.cards.get(had)?.focus({ preventScroll: true });
  }
  function select(id) {
    st.sel = id;
    for (const [k, el] of st.cards) { el.classList.toggle('is-selected', k === id); el.setAttribute('aria-pressed', k === id ? 'true' : 'false'); }
    els.side._k = null;
    renderSide();
    applyHighlight();
    refreshTail(true);
    $('.ag-side-h button', els.side)?.focus({ preventScroll: true });
  }
  async function refreshTail(force) {
    const n = nodeById(st.sel);
    if (!n || n.kind !== 'worker') return;
    if (!force && st.tail.run === n.run_id && !n.active && st.tail.text) return;
    try {
      const res = await fetch(`/api/run/${encodeURIComponent(n.run_id)}/tail?lines=60`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`the board answered ${res.status}`);
      const j = await res.json();
      if (st.sel !== n.id) return;
      st.tail = { run: n.run_id, text: (j.lines || []).join('\n'), at: Date.now(), err: null };
    } catch (e) {
      if (st.sel !== n.id) return;
      st.tail = { run: n.run_id, text: '', at: Date.now(), err: e.message };
    }
    renderSide();
  }

  /* ---- tooltip for edges ---- */
  function showTip(ev, e) {
    const g = st.graph;
    const lab = (id) => { const o = g.nodes.find((n) => n.id === id); return o ? (o.kind === 'worker' ? `${o.role} (${o.ticket || 'run'})` : o.label || o.role) : id; };
    els.tip.hidden = false;
    els.tip.innerHTML = `<b>${esc(lab(e.from))} → ${esc(lab(e.to))}</b><br>${esc(KIND_LABEL[e.kind] || e.kind)}<br><span class="mono">${esc(e.label)}</span><br><span class="muted mono">${e.count > 1 ? `${e.count} × · ` : ''}last ${esc(ago(e.last_ts))}${e.active ? ' · active now' : ''}</span>${e.tickets?.length ? `<br><span class="muted mono">${esc(e.tickets.join(', '))}</span>` : ''}`;
    moveTip(ev);
  }
  function moveTip(ev) {
    const r = els.viewport.parentElement.getBoundingClientRect();
    const x = Math.min(ev.clientX - r.left + 14, r.width - 270);
    els.tip.style.transform = `translate(${Math.max(8, x)}px, ${ev.clientY - r.top + 16}px)`;
  }
  function hideTip() { els.tip.hidden = true; }

  /* ---- live text (elapsed counters) ---- */
  function tick() {
    const t = now();
    for (const el of $$('[data-elapsed]', els.nodes)) { const s = ts(el.dataset.elapsed); if (s != null) { const v = fmtDur((t - s) / 1000); if (el.textContent !== v) el.textContent = v; } }
    for (const el of $$('[data-since]', els.nodes)) { const s = ts(el.dataset.since); if (s != null) { const v = `up ${fmtDur((t - s) / 1000)}`; if (el.textContent !== v) el.textContent = v; } }
    for (const el of $$('[data-rel]', els.nodes)) { const s = ts(el.dataset.rel); if (s != null) { const v = fmtRel(s, t); if (el.textContent !== v) el.textContent = v; } }
    for (const el of $$('[data-until]', els.nodes)) { const s = ts(el.dataset.until); if (s != null) { const v = s <= t ? 'now' : fmtDur((s - t) / 1000); if (el.textContent !== v) el.textContent = v; } }
    if (st.graph) {
      const stale = (t - st.fetchedAt) / 1000;
      els.updated.textContent = st.fetchedAt ? `updated ${fmtRel(st.fetchedAt, t)}` : '';
      els.updated.classList.toggle('stale', stale > STALE_S);
    }
  }
  let ticker = null;

  /* ---- events ---- */
  els.win.addEventListener('click', (e) => {
    const b = e.target.closest('[data-ag-win]');
    if (!b || b.dataset.agWin === st.window) return;
    api.setWindow(b.dataset.agWin, { fromUser: true });
  });
  els.legend.addEventListener('click', (e) => {
    const b = e.target.closest('[data-ag-kind]');
    if (!b) return;
    const k = b.dataset.agKind;
    if (st.off.has(k)) st.off.delete(k); else st.off.add(k);
    render();
  });
  els.err.addEventListener('click', (e) => { if (e.target.closest('[data-ag-retry]')) { fetchGraph().then(schedule); } });
  els.nodes.addEventListener('click', (e) => {
    const tog = e.target.closest('[data-ag-expand]');
    if (tog) {
      const id = tog.dataset.agExpand;
      if (st.expanded.has(id)) st.expanded.delete(id); else st.expanded.add(id);
      render();
      return;
    }
    if (e.target.closest('a')) return;
    const card = e.target.closest('.ag-node');
    if (card) select(card.dataset.id);
  });
  els.nodes.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.classList.contains('ag-node')) { e.preventDefault(); select(e.target.dataset.id); }
  });
  els.nodes.addEventListener('mouseover', (e) => {
    const card = e.target.closest('.ag-node');
    const id = card?.dataset.id ?? null;
    if (id !== st.hover) { st.hover = id; applyHighlight(); }
  });
  els.nodes.addEventListener('mouseleave', () => { if (st.hover) { st.hover = null; applyHighlight(); } });
  els.edges.addEventListener('mousemove', (e) => {
    const g = e.target.closest('g.ag-eg');
    if (!g) { hideTip(); return; }
    const edge = edgeLookup.get(g.dataset.id);
    if (!edge) return;
    showTip(e, edge);
  });
  els.edges.addEventListener('mouseleave', hideTip);
  els.viewport.addEventListener('click', (e) => {
    if (e.target === els.viewport || e.target === els.scale || e.target === els.edges || e.target.closest('#ag-cols')) if (st.sel) closeSide();
  });
  els.side.addEventListener('click', (e) => { if (e.target.closest('[data-ag-close]')) closeSide(); });
  els.root.addEventListener('keydown', (e) => { if (e.key === 'Escape' && st.sel) { e.stopPropagation(); closeSide(); } });
  document.addEventListener('visibilitychange', () => {
    if (!st.active) return;
    if (document.hidden) { clearTimeout(st.timer); st.timer = null; } else { fetchGraph().then(schedule); }
  });
  let resizeRaf = 0;
  window.addEventListener('resize', () => {
    if (!st.active || !st.graph) return;
    cancelAnimationFrame(resizeRaf);
    resizeRaf = requestAnimationFrame(() => fit(layoutGraph(st.graph, st.expanded)));
  });

  const api = {
    get window() { return st.window; },
    /** Switch time window (re-fetches). */
    setWindow(w, { fromUser = false } = {}) {
      if (!AG_WINDOWS.some(([k]) => k === w)) w = AG_DEFAULT_WINDOW;
      const changed = w !== st.window;
      st.window = w;
      if (changed) {
        st.inflight?.abort();
        st.inflight = null;
        st.graph = null;
        st.sel = null;
        els.side.hidden = true;
        showSkeleton();
        if (fromUser && api.onWindow) api.onWindow(w);
      }
      renderChrome();
      if (st.active && changed) fetchGraph().then(schedule);
    },
    onWindow: null,
    /** The tab became visible. */
    activate() {
      if (st.active) return;
      st.active = true;
      els.root.dataset.fixture = fixture ? '1' : '0';
      ticker = setInterval(tick, 1000);
      if (fixture) { renderFixtureNotice(); return; }
      if (!st.graph) showSkeleton();
      fetchGraph().then(schedule);
    },
    deactivate() {
      st.active = false;
      clearTimeout(st.timer);
      st.timer = null;
      clearInterval(ticker);
      ticker = null;
      st.inflight?.abort();
      st.inflight = null;
    },
    /** Test hook. */
    _state: st,
  };

  function showSkeleton() {
    els.empty.hidden = false;
    els.empty.textContent = 'Reading the agent graph…';
    for (const el of st.cards.values()) el.remove();
    st.cards.clear();
    for (const g of st.paths.values()) g.remove();
    st.paths.clear();
    els.cols.innerHTML = ''; els.cols._k = null;
  }
  function renderFixtureNotice() {
    els.empty.hidden = false;
    els.empty.textContent = 'Fixture mode has no live agents. Open the board without ?fixture to see the agent graph.';
  }
  renderChrome();
  return api;
}

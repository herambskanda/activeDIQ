// The live agent graph behind the board's Agents tab: who is running, on which model at what effort,
// how much context each one has used, and who is talking to whom. Read-only over the state store.
//
// Nodes: ceo, dispatcher, director (live interactive session), worker (one per run), subagent (one
// per Agent spawn inside a worker), role (a stub for a role that appears in a hand-off but has no
// run in the window). Edges: launch, spawn, handoff / reject / note (ticket traffic between roles)
// and ask / answer (traffic with the CEO).
//
// Worker logs are several MB: `GraphLogReader` keeps a byte offset and the parsed state per file in
// memory and reads only the new bytes on every request.
import fs from 'node:fs';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import {
  listEntities, listRecentRuns, localDate, pidAlive, readControl, readJson, readRange, readRecentEvents,
} from './store.mjs';
import { loadAgents } from './agents.mjs';
import { dispatcherInfo } from './status.mjs';
import { openCeoDecisions } from './decisions.mjs';
import { checkLaunchPolicy, modelFamily } from './policy.mjs';
import { findResultLine, resultKeyword, summarizeToolInput } from './runlog.mjs';

export const WINDOWS = ['live', '1h', '6h', 'today'];
const LIVE_WINDOW_MS = 5 * 60_000;
const DIRECTOR_FRESH_MS = 10 * 60_000;
const ACTIVE_EDGE_MS = 90_000;
const READ_CHUNK = 4 * 1024 * 1024;
const DEFAULT_SCAN_BUDGET = 48 * 1024 * 1024; // new log bytes parsed per request (cold start spreads over polls)
const MAX_CACHED_LOGS = 80;
const WORKER_ACTIVITY = 40;
const SPAWN_ACTIVITY = 12;
const STAGE_GROUPS = ['in_progress', 'review', 'qa'];
const SUBAGENT_TOOLS = new Set(['Agent', 'Task']);

const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const oneLine = (s) => String(s ?? '').replace(/\s+/g, ' ').trim();
const usageTokens = (u) => (u ? (u.input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0) : null);
const iso = (ms) => new Date(ms).toISOString();
const round2 = (n) => Math.round(n * 100) / 100;

// ---------------------------------------------------------------------------------------------
// incremental log reader

function newState() {
  return {
    model: null, session_id: null, context_tokens: null, peak_context_tokens: 0, turns: 0, last_ts: null,
    first_ts: null, result: null, spawns: new Map(), tasks: new Map(), activity: [],
  };
}

function toolLine(block) {
  return `${block.name} · ${summarizeToolInput(block.name, block.input)}`;
}

function pushRing(ring, entry, cap) {
  ring.push(entry);
  if (ring.length > cap) ring.shift();
}

function finishSpawn(spawn, status, ts) {
  if (!spawn || spawn.finished_ts) return;
  spawn.status = status;
  spawn.finished_ts = ts;
}

/** Fold one parsed stream-json message into a log state. */
function applyMessage(s, msg) {
  const ts = msg.timestamp ? Date.parse(msg.timestamp) : null;
  if (Number.isFinite(ts)) {
    s.last_ts = ts;
    s.first_ts ??= ts;
  }
  const now = s.last_ts;

  if (msg.type === 'system') {
    if (msg.subtype === 'init') {
      s.model = msg.model ?? s.model;
      s.session_id = msg.session_id ?? s.session_id;
    } else if (msg.subtype === 'task_started') {
      const sp = s.spawns.get(msg.tool_use_id);
      if (sp) {
        sp.task_id = msg.task_id;
        s.tasks.set(msg.task_id, msg.tool_use_id);
      }
    } else if (msg.subtype === 'task_progress') {
      const sp = s.spawns.get(msg.tool_use_id);
      if (sp && !sp.finished_ts) {
        if (msg.last_tool_name && !sp.last_tool) sp.last_tool = msg.last_tool_name;
        sp.total_tokens = msg.usage?.total_tokens ?? sp.total_tokens;
        sp.tool_uses = msg.usage?.tool_uses ?? sp.tool_uses;
      }
    } else if (msg.subtype === 'task_notification') {
      finishSpawn(s.spawns.get(msg.tool_use_id), msg.status === 'completed' ? 'finished' : (msg.status ?? 'finished'), now);
      const sp = s.spawns.get(msg.tool_use_id);
      if (sp) sp.total_tokens = msg.usage?.total_tokens ?? sp.total_tokens;
    } else if (msg.subtype === 'task_updated') {
      const status = msg.patch?.status;
      if (status && status !== 'running' && status !== 'pending') finishSpawn(s.spawns.get(s.tasks.get(msg.task_id)), status === 'completed' ? 'finished' : status, now);
    }
    return;
  }

  if (msg.type === 'assistant' && msg.message) {
    const parent = msg.parent_tool_use_id ?? null;
    const content = Array.isArray(msg.message.content) ? msg.message.content : [];
    const tokens = usageTokens(msg.message.usage);
    const sp = parent ? s.spawns.get(parent) : null;
    if (parent && !sp) return; // a spawn this reader never saw: nothing to attribute it to
    const target = sp ?? s;
    if (tokens != null) {
      if (sp) {
        sp.context_tokens = tokens;
        sp.peak_context_tokens = Math.max(sp.peak_context_tokens, tokens);
      } else {
        s.context_tokens = tokens;
        s.peak_context_tokens = Math.max(s.peak_context_tokens, tokens);
      }
    }
    target.turns += 1;
    if (msg.message.model) {
      if (sp) sp.model = msg.message.model;
      else s.model ??= msg.message.model;
    }
    for (const block of content) {
      if (block?.type === 'tool_use') {
        const line = toolLine(block);
        if (sp) sp.last_tool = line;
        pushRing(sp ? sp.activity : s.activity, { ts: now, kind: 'tool', text: clip(oneLine(line), 160) }, sp ? SPAWN_ACTIVITY : WORKER_ACTIVITY);
        if (!parent && SUBAGENT_TOOLS.has(block.name)) {
          s.spawns.set(block.id, {
            id: block.id, subagent_type: block.input?.subagent_type || 'general-purpose',
            description: clip(oneLine(block.input?.description || block.input?.prompt || ''), 120),
            started_ts: now, finished_ts: null, status: 'running', model: null, context_tokens: null,
            peak_context_tokens: 0, turns: 0, last_tool: null, task_id: null, total_tokens: null, tool_uses: null, activity: [],
          });
        }
      } else if (block?.type === 'text' && block.text?.trim()) {
        pushRing(sp ? sp.activity : s.activity, { ts: now, kind: 'text', text: clip(oneLine(block.text), 200) }, sp ? SPAWN_ACTIVITY : WORKER_ACTIVITY);
      }
    }
    return;
  }

  if (msg.type === 'user' && !msg.parent_tool_use_id && Array.isArray(msg.message?.content)) {
    for (const block of msg.message.content) {
      if (block?.type !== 'tool_result') continue;
      const sp = s.spawns.get(block.tool_use_id);
      if (!sp) continue;
      const r = msg.tool_use_result;
      if (r && typeof r === 'object' && r.status === 'async_launched') {
        sp.async = true;
        sp.task_id = r.agentId ?? sp.task_id;
        if (sp.task_id) s.tasks.set(sp.task_id, sp.id);
        sp.model = r.resolvedModel ?? sp.model;
      } else {
        finishSpawn(sp, block.is_error ? 'failed' : 'finished', now);
      }
    }
    return;
  }

  if (msg.type === 'result') {
    s.result = {
      is_error: Boolean(msg.is_error), cost_usd: msg.total_cost_usd ?? null, turns: msg.num_turns ?? null,
      result_line: findResultLine(typeof msg.result === 'string' ? msg.result : ''),
    };
  }
}

/** One growing log: byte offset, carry-over of a torn last line, and the parsed state. */
class LogEntry {
  constructor() {
    this.reset();
  }

  reset() {
    this.offset = 0;
    this.carry = '';
    this.decoder = new StringDecoder('utf8');
    this.state = newState();
    this.touched = 0;
  }

  line(text) {
    // thinking_tokens lines dominate a log and carry nothing we use: skip them without parsing
    if (!text.trim() || text.includes('"subtype":"thinking_tokens"')) return;
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    applyMessage(this.state, msg);
  }

  /** Parse new bytes up to `maxBytes`; returns how many bytes were consumed. */
  advance(file, size, maxBytes) {
    let used = 0;
    while (this.offset < size && used < maxBytes) {
      const end = Math.min(size, this.offset + READ_CHUNK);
      const chunk = readRange(file, this.offset, end);
      if (!chunk.length) break;
      this.offset += chunk.length;
      used += chunk.length;
      const parts = (this.carry + this.decoder.write(chunk)).split('\n');
      this.carry = parts.pop();
      for (const part of parts) this.line(part);
    }
    return used;
  }
}

/**
 * Keeps one parsed state per log file in memory. `read` parses only the bytes appended since the
 * last call; a file that shrank (replaced) is re-read from the start. A `budget` caps the bytes
 * parsed per request so a cold start with many large logs spreads over a few polls.
 */
export class GraphLogReader {
  constructor() {
    this.entries = new Map();
    this.tick = 0;
  }

  /**
   * @param {string} file
   * @param {{budget?: {left: number}}} [opts]
   * @returns {{state: object, mtimeMs: number|null, complete: boolean}}
   */
  read(file, { budget = { left: Infinity } } = {}) {
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      return { state: newState(), mtimeMs: null, complete: true };
    }
    let entry = this.entries.get(file);
    if (!entry) {
      entry = new LogEntry();
      this.entries.set(file, entry);
    }
    if (stat.size < entry.offset) entry.reset();
    entry.touched = ++this.tick;
    if (entry.offset < stat.size && budget.left > 0) budget.left -= entry.advance(file, stat.size, budget.left);
    this.#evict();
    return { state: entry.state, mtimeMs: stat.mtimeMs, complete: entry.offset >= stat.size };
  }

  #evict() {
    if (this.entries.size <= MAX_CACHED_LOGS) return;
    const oldest = [...this.entries.entries()].sort((a, b) => a[1].touched - b[1].touched).slice(0, this.entries.size - MAX_CACHED_LOGS);
    for (const [k] of oldest) this.entries.delete(k);
  }
}

const defaultReader = new GraphLogReader();

// ---------------------------------------------------------------------------------------------
// helpers

/**
 * The start of a graph window.
 * @param {string} name live | 1h | 6h | today
 * @param {Date} now
 */
export function windowStart(name, now) {
  if (name === 'live') return now.getTime() - LIVE_WINDOW_MS;
  if (name === '6h') return now.getTime() - 6 * 3_600_000;
  if (name === 'today') {
    const [y, m, d] = localDate(now).split('-').map(Number);
    return new Date(y, m - 1, d).getTime();
  }
  return now.getTime() - 3_600_000;
}

function contextState(pct, cfg) {
  if (pct >= cfg.critical_pct) return 'critical';
  if (pct >= cfg.checkpoint_pct) return 'checkpoint';
  if (pct >= cfg.warn_pct) return 'warn';
  return 'ok';
}

function contextOf(tokens, peak, budget, cfg) {
  const t = tokens ?? 0;
  const pct = budget > 0 ? Math.round((t / budget) * 1000) / 10 : 0;
  return { tokens: t, peak: Math.max(peak ?? 0, t), budget, pct, state: contextState(pct, cfg) };
}

function readSessions(ctx) {
  const dir = ctx.dir('sessions');
  const out = [];
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith('.json'));
  } catch {
    return out;
  }
  for (const name of names) {
    try {
      const s = readJson(path.join(dir, name));
      if (s) out.push(s);
    } catch {
      // half-written session file
    }
  }
  return out;
}

function ticketsById(ctx) {
  const map = new Map();
  for (const t of listEntities(ctx, 'tickets')) map.set(t.id, t);
  return map;
}

/** Model/effort policy of what is actually running; a differing effective effort counts as an override. */
function policyOf(config, agent, role, model, effective) {
  const family = modelFamily(model);
  if (!family || !effective) return { ok: true, problems: [] };
  const base = agent?.effort ?? effective;
  const problems = checkLaunchPolicy(config, { name: role, model: family, effort: base }, effective === base ? null : effective);
  return { ok: problems.length === 0, problems };
}

// ---------------------------------------------------------------------------------------------
// events → hand-off edges

const TRANSITION = /^(T-\d+) (advanced|rejected|blocked|reopened|unblocked|cancelled) (\w+)(?: → (\w+))?(?: \(([a-z][a-z0-9-]*)\))?:/;
const NOTE = /^note on (T-\d+):/;
const DECISION_OPEN = /^(directional|advisory|notice) decision (D-\d+) opened:/;
const ACTION_OPEN = /^action (A-\d+) opened:/;
const DECISION_REPLY = /^(D-\d+) (answered|acknowledged|vetoed)\b/;

/** Merge one occurrence into an aggregated edge. */
function bump(map, key, base, ts, ticket) {
  let e = map.get(key);
  if (!e) {
    e = { ...base, count: 0, last_ts: 0, last_ticket: null, tickets: [] };
    map.set(key, e);
  }
  e.count += 1;
  if (ts >= e.last_ts) {
    e.last_ts = ts;
    e.last_ticket = ticket ?? e.last_ticket;
  }
  if (ticket && !e.tickets.includes(ticket) && e.tickets.length < 6) e.tickets.push(ticket);
}

function trafficEdges(events, startMs, tickets, roleNames) {
  const hand = new Map();
  const isRole = (r) => roleNames.has(r);
  for (const ev of events) {
    const ts = Date.parse(ev.ts);
    if (!Number.isFinite(ts) || ts < startMs) continue;
    const text = ev.text ?? '';
    let m;
    if (ev.kind === 'ticket' && (m = TRANSITION.exec(text))) {
      const [, ticket, verb, , , to] = m;
      if (!to || !isRole(ev.actor) || !isRole(to) || ev.actor === to) continue;
      if (verb === 'advanced') bump(hand, `h|${ev.actor}|${to}|handoff`, { from_role: ev.actor, to_role: to, kind: 'handoff', verb: 'advance' }, ts, ticket);
      else if (verb === 'rejected') bump(hand, `h|${ev.actor}|${to}|reject`, { from_role: ev.actor, to_role: to, kind: 'reject', verb: 'reject' }, ts, ticket);
    } else if (ev.kind === 'ticket' && (m = NOTE.exec(text))) {
      const t = tickets.get(m[1]);
      const to = t?.stage_role ?? t?.owner;
      if (!to || !isRole(ev.actor) || !isRole(to) || ev.actor === to) continue;
      bump(hand, `h|${ev.actor}|${to}|note`, { from_role: ev.actor, to_role: to, kind: 'note', verb: 'note' }, ts, m[1]);
    } else if (ev.kind === 'decision' && (m = DECISION_OPEN.exec(text))) {
      if (!isRole(ev.actor)) continue;
      const verb = m[1] === 'notice' ? 'notice' : 'decision';
      bump(hand, `c|${ev.actor}|ceo|${verb}`, { from_role: ev.actor, to_role: 'ceo', kind: 'ask', verb }, ts, m[2]);
    } else if (ev.kind === 'action' && (m = ACTION_OPEN.exec(text))) {
      if (!isRole(ev.actor)) continue;
      bump(hand, `c|${ev.actor}|ceo|action`, { from_role: ev.actor, to_role: 'ceo', kind: 'ask', verb: 'action' }, ts, m[1]);
    } else if (ev.kind === 'decision' && ev.actor === 'ceo' && (m = DECISION_REPLY.exec(text))) {
      const verb = { answered: 'answer', acknowledged: 'ack', vetoed: 'veto' }[m[2]];
      bump(hand, `c|ceo|factory-director|${verb}`, { from_role: 'ceo', to_role: 'factory-director', kind: 'answer', verb }, ts, m[1]);
    }
  }
  return [...hand.values()];
}

// ---------------------------------------------------------------------------------------------
// the graph

/**
 * Build the agent graph.
 * @param {object} ctx store context
 * @param {{window?: string, reader?: GraphLogReader, scanBudgetBytes?: number}} [opts]
 * @returns {{generated: string, window: object, nodes: object[], edges: object[], totals: object}}
 */
export function buildGraph(ctx, { window = '1h', reader = defaultReader, scanBudgetBytes = DEFAULT_SCAN_BUDGET } = {}) {
  const win = WINDOWS.includes(window) ? window : '1h';
  const now = ctx.now();
  const nowMs = now.getTime();
  const startMs = windowStart(win, now);
  const cfg = ctx.config.context;
  const agents = loadAgents(ctx);
  const tickets = ticketsById(ctx);
  const sessions = readSessions(ctx);
  const sessionByRun = new Map();
  const sessionById = new Map();
  for (const s of sessions) {
    if (s.run) sessionByRun.set(s.run, s);
    if (s.session_id) sessionById.set(s.session_id, s);
  }
  const budget = { left: scanBudgetBytes };

  const nodes = [];
  const edges = [];
  const control = readControl(ctx);
  const disp = dispatcherInfo(ctx);
  const cap = ctx.config.dispatcher.daily_run_cap;
  const maxParallel = ctx.config.dispatcher.max_parallel;

  // ---- ceo + dispatcher
  const decisions = listEntities(ctx, 'decisions');
  const openDecisions = openCeoDecisions(decisions);
  const openActions = listEntities(ctx, 'actions').filter((a) => a.status === 'open');
  const pendingNotices = decisions.filter((d) => d.kind === 'notice' && d.status === 'pending');
  nodes.push({
    id: 'ceo', kind: 'ceo', label: ctx.config.ceo_name ?? 'ceo',
    open_decisions: openDecisions.map((d) => ({ id: d.id, title: d.title })),
    open_actions: openActions.map((a) => ({ id: a.id, title: a.title })),
    pending_notices: pendingNotices.map((d) => ({ id: d.id, title: d.title })),
  });
  nodes.push({
    id: 'dispatcher', kind: 'dispatcher', label: 'dispatcher', alive: disp.alive, heartbeat: disp.heartbeat, pid: disp.pid ?? null,
    active_runs: disp.active?.length ?? 0, max_parallel: maxParallel, runs_today: disp.runs_today.count, daily_run_cap: cap,
    paused: Boolean(control.paused), pause_reason: control.reason ?? null, backoff_until: disp.backoff_until,
    last_action: disp.last_action ?? null,
  });

  // ---- directors: live interactive sessions
  const directors = sessions.filter((s) => s.kind === 'interactive' && !s.ended
    && nowMs - Date.parse(s.updated ?? s.started ?? 0) < DIRECTOR_FRESH_MS);
  directors.sort((a, b) => String(a.session_id).localeCompare(String(b.session_id)));
  const directorNodes = [];
  for (const s of directors) {
    const def = agents.get(s.role ?? 'factory-director');
    const dn = {
      id: `director:${s.session_id}`, kind: 'director', label: s.role ?? 'factory-director', role: s.role ?? 'factory-director',
      session_id: s.session_id, model: def?.model ?? null, model_exact: null, model_source: def ? 'agent definition' : null,
      effort: s.effort ?? def?.effort ?? null, context: contextOf(s.context_tokens, s.peak_context_tokens, s.budget_tokens ?? cfg.budget_tokens, cfg),
      ticket: s.ticket ?? null, current_tool: s.last_tool ?? null, started: s.started ?? null, updated: s.updated ?? null,
      elapsed_ms: s.started ? nowMs - Date.parse(s.started) : null, active: true,
    };
    directorNodes.push(dn);
    nodes.push(dn);
  }

  // ---- workers
  const runs = listRecentRuns(ctx, 400).filter((r) => r.status === 'running'
    || Math.max(Date.parse(r.ended ?? r.updated ?? r.started) || 0, Date.parse(r.started) || 0) >= startMs);
  // running runs are scanned first within the byte budget, then the newest finished ones
  const ordered = [...runs].sort((a, b) => (b.status === 'running') - (a.status === 'running') || String(b.id).localeCompare(String(a.id)));
  const workers = [];
  const subagents = [];
  for (const run of ordered) {
    const running = run.status === 'running';
    const { state: log, mtimeMs, complete } = reader.read(path.join(ctx.dir('runs'), `${run.id}.log`), { budget });
    const session = sessionByRun.get(run.id) ?? sessionById.get(run.session_id) ?? null;
    const ticket = run.ticket ? tickets.get(run.ticket) : null;
    const agent = agents.get(run.role) ?? null;
    const effectiveEffort = session?.effort ?? run.effort ?? null;
    const effortMismatch = Boolean(session?.effort && run.effort && session.effort !== run.effort);
    const modelExact = log.model ?? null;
    const modelMismatch = Boolean(modelExact && run.model && modelFamily(modelExact) && modelFamily(modelExact) !== modelFamily(run.model));
    const tokens = running ? (log.context_tokens ?? session?.context_tokens ?? run.context_tokens ?? 0) : (run.context_tokens ?? log.context_tokens ?? 0);
    const peak = Math.max(run.peak_context_tokens ?? 0, log.peak_context_tokens ?? 0);
    const ended = run.ended ? Date.parse(run.ended) : null;
    const startedMs = Date.parse(run.started);
    const id = `run:${run.id}`;
    const cost = run.cost_usd || log.result?.cost_usd || 0;
    const node = {
      id, kind: 'worker', run_id: run.id, label: run.role, role: run.role,
      status: run.status, active: running, group: STAGE_GROUPS.includes(run.stage) ? run.stage : 'other', stage: run.stage ?? null,
      model: run.model ?? null, model_exact: modelExact, model_mismatch: modelMismatch,
      effort: effectiveEffort, effort_configured: run.effort ?? null, effort_mismatch: effortMismatch,
      policy: policyOf(ctx.config, agent, run.role, run.model, effectiveEffort),
      context: contextOf(tokens, peak, session?.budget_tokens ?? cfg.budget_tokens, cfg),
      ticket: run.ticket ?? null, ticket_title: ticket?.title ?? null, ticket_status: ticket?.status ?? null,
      started: run.started, ended: run.ended ?? null,
      elapsed_ms: Number.isFinite(startedMs) ? (ended ?? nowMs) - startedMs : null,
      turns: run.num_turns || log.result?.turns || log.turns || 0,
      cost_usd: cost ? round2(cost) : (running ? null : 0),
      current_tool: running ? (run.last_activity ?? session?.last_tool ?? null) : null,
      last_activity: run.last_activity ?? null,
      handoff_pending: run.status === 'handoff' || resultKeyword(run.result_line) === 'handoff',
      handoff_latest: run.snapshot?.handoff_latest ? path.basename(run.snapshot.handoff_latest) : null,
      checkout: run.worktree ? 'worktree' : 'main',
      continuation: Boolean(run.continuation),
      result_line: run.result_line ?? null,
      pid: run.pid ?? null, pid_alive: running && run.pid ? pidAlive(run.pid) : null,
      idle_ms: running && mtimeMs ? Math.max(0, nowMs - mtimeMs) : null,
      session_id: run.session_id ?? null, log_scanned: complete,
      activity: running ? log.activity.slice(-6) : [],
      subagent_count: 0,
    };
    workers.push(node);
    nodes.push(node);
    edges.push({
      id: `launch:${run.id}`, kind: 'launch', from: 'dispatcher', to: id, label: `launch · ${run.stage ?? 'run'}`,
      count: 1, last_ts: iso(Number.isFinite(startedMs) ? startedMs : nowMs), active: running,
    });

    for (const sp of log.spawns.values()) {
      const def = agents.get(sp.subagent_type) ?? null;
      const spRunning = running && !sp.finished_ts;
      const interrupted = !running && !sp.finished_ts;
      const subId = `sub:${run.id}:${sp.id}`;
      const sub = {
        id: subId, kind: 'subagent', label: sp.subagent_type, role: sp.subagent_type, parent: id, run_id: run.id,
        description: sp.description, status: spRunning ? 'running' : (interrupted ? 'ended' : sp.status),
        active: spRunning, builtin: !def,
        model: def?.model ?? modelFamily(sp.model), model_exact: sp.model, effort: def?.effort ?? null,
        context: contextOf(sp.context_tokens, sp.peak_context_tokens, cfg.budget_tokens, cfg),
        turns: sp.turns, tool_uses: sp.tool_uses, total_tokens: sp.total_tokens,
        current_tool: spRunning ? sp.last_tool : null, last_tool: sp.last_tool,
        started: sp.started_ts ? iso(sp.started_ts) : null, ended: sp.finished_ts ? iso(sp.finished_ts) : null,
        elapsed_ms: sp.started_ts ? (sp.finished_ts ?? (running ? nowMs : (ended ?? nowMs))) - sp.started_ts : null,
        async: Boolean(sp.async), activity: sp.activity.slice(-10), ticket: run.ticket ?? null,
      };
      node.subagent_count += 1;
      subagents.push(sub);
      nodes.push(sub);
      edges.push({
        id: `spawn:${run.id}:${sp.id}`, kind: 'spawn', from: id, to: subId, label: `spawn: ${sp.description || sp.subagent_type}`,
        count: 1, last_ts: iso(sp.started_ts ?? startedMs), active: spRunning,
      });
    }
  }

  // ---- ticket traffic + CEO traffic
  const roleNames = new Set([...agents.keys(), 'factory-director', ...workers.map((w) => w.role)]);
  const events = readRecentEvents(ctx, 4000);
  const traffic = trafficEdges(events, startMs, tickets, roleNames);

  const stubs = new Map();
  const resolve = (role) => {
    if (role === 'ceo') return 'ceo';
    const session = directors.find((d) => (d.role ?? 'factory-director') === role);
    if (session) return `director:${session.session_id}`;
    const mine = workers.filter((w) => w.role === role).sort((a, b) => (b.active - a.active) || String(b.run_id).localeCompare(String(a.run_id)));
    if (mine.length) return mine[0].id;
    const id = `role:${role}`;
    if (!stubs.has(id)) {
      const def = agents.get(role) ?? null;
      stubs.set(id, { id, kind: 'role', label: role, role, model: def?.model ?? null, effort: def?.effort ?? null, active: false });
    }
    return id;
  };
  for (const t of traffic) {
    const from = resolve(t.from_role);
    const to = resolve(t.to_role);
    if (from === to) continue;
    const verbs = { advance: 'advance', reject: 'reject', note: 'note', decision: 'decision', notice: 'notice', action: 'action', answer: 'answer', ack: 'ack', veto: 'veto' };
    const verb = verbs[t.verb] ?? t.verb;
    edges.push({
      id: `${t.kind}:${t.from_role}>${t.to_role}:${t.verb}`, kind: t.kind, from, to,
      label: `${verb}${t.count > 1 ? ` ×${t.count}` : ''}${t.last_ticket ? ` · ${t.last_ticket}` : ''}`,
      verb, count: t.count, last_ts: iso(t.last_ts), last_ticket: t.last_ticket, tickets: t.tickets,
      from_role: t.from_role, to_role: t.to_role, active: nowMs - t.last_ts < ACTIVE_EDGE_MS,
    });
  }
  nodes.push(...stubs.values());

  // recent ticket events per ticket, for the side panel
  const byTicket = new Map();
  for (const ev of events) {
    if (!ev.ticket || ev.kind === 'run') continue;
    const list = byTicket.get(ev.ticket) ?? [];
    if (list.length < 6) list.push({ ts: ev.ts, actor: ev.actor, kind: ev.kind, text: clip(oneLine(ev.text), 220) });
    byTicket.set(ev.ticket, list);
  }
  for (const w of workers) w.ticket_events = byTicket.get(w.ticket) ?? [];

  // ---- totals
  const running = workers.filter((w) => w.active);
  const liveSubs = subagents.filter((s) => s.active);
  const live = [...directorNodes, ...running, ...liveSubs];
  const totals = {
    active_agents: live.length,
    active_workers: running.length,
    active_subagents: liveSubs.length,
    active_directors: directors.length,
    context_tokens: live.reduce((sum, n) => sum + (n.context?.tokens ?? 0), 0),
    context_budget_tokens: cfg.budget_tokens,
    cost_usd: round2(workers.reduce((sum, w) => sum + (w.cost_usd ?? 0), 0)),
    runs_in_window: workers.length,
    runs_failed: workers.filter((w) => w.status === 'failed' || w.status === 'killed').length,
    runs_today: disp.runs_today.count,
    daily_run_cap: cap,
  };

  return {
    generated: now.toISOString(),
    window: { name: win, since: iso(startMs), until: now.toISOString() },
    context_thresholds: { warn_pct: cfg.warn_pct, checkpoint_pct: cfg.checkpoint_pct, critical_pct: cfg.critical_pct, budget_tokens: cfg.budget_tokens },
    nodes, edges, totals,
  };
}

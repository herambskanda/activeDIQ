// Read-only summaries of the factory: dispatcher liveness, the latest digest, and the data behind
// `factory status` and `factory digest`.
import fs from 'node:fs';
import path from 'node:path';
import {
  listEntities, listRecentRuns, localDate, pidAlive, readControl, readDispatcherState, readJson,
} from './store.mjs';
import { STATUSES } from './flows.mjs';
import { openCeoDecisions } from './decisions.mjs';

const HEARTBEAT_ALIVE_MS = 60_000;

/**
 * Dispatcher liveness and counters. Alive means a heartbeat in the last 60 s.
 * @param {object} ctx
 */
export function dispatcherInfo(ctx) {
  const s = readDispatcherState(ctx);
  const now = ctx.now();
  const age = s.heartbeat ? now.getTime() - Date.parse(s.heartbeat) : Infinity;
  const today = localDate(now);
  return {
    alive: age < HEARTBEAT_ALIVE_MS, heartbeat: s.heartbeat, pid: s.pid, active: s.active ?? [],
    backoff_until: s.backoff_until && Date.parse(s.backoff_until) > now.getTime() ? s.backoff_until : null,
    runs_today: { date: today, count: s.runs_today?.date === today ? s.runs_today.count : 0 },
    last_action: s.last_action,
  };
}

/**
 * The newest daily digest, as a repo-relative path.
 * @param {object} ctx
 * @returns {{date: string|null, path: string|null}}
 */
export function latestDigest(ctx) {
  let names = [];
  try {
    names = fs.readdirSync(ctx.reportsDir).filter((n) => /^digest-\d{4}-\d{2}-\d{2}\.md$/.test(n)).sort();
  } catch {
    // no reports directory yet
  }
  const newest = names.at(-1);
  if (!newest) return { date: null, path: null };
  return { date: newest.slice(7, 17), path: path.relative(ctx.root, path.join(ctx.reportsDir, newest)) };
}

/**
 * Everything `factory status` prints.
 * @param {object} ctx
 */
export function buildStatus(ctx) {
  const now = ctx.now();
  const tickets = listEntities(ctx, 'tickets');
  const counts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  for (const t of tickets) counts[t.status] = (counts[t.status] ?? 0) + 1;

  let board = null;
  try {
    const b = readJson(path.join(ctx.stateDir, 'board.json'));
    if (b && pidAlive(b.pid)) board = { pid: b.pid, port: b.port, url: `http://${ctx.config.board.host}:${b.port}` };
  } catch {
    // unreadable board.json reads as "not running"
  }

  return {
    product: ctx.config.product,
    limits: { daily_run_cap: ctx.config.dispatcher.daily_run_cap, max_parallel: ctx.config.dispatcher.max_parallel },
    control: readControl(ctx),
    dispatcher: dispatcherInfo(ctx),
    board,
    active_runs: listRecentRuns(ctx, 100).filter((r) => r.status === 'running').map((r) => ({
      id: r.id, ticket: r.ticket, role: r.role, started: r.started,
      elapsed_ms: now.getTime() - Date.parse(r.started), context_tokens: r.context_tokens ?? 0,
    })),
    counts,
    decisions: openCeoDecisions(listEntities(ctx, 'decisions')).map((d) => ({ id: d.id, kind: d.kind, title: d.title })),
    notices: listEntities(ctx, 'decisions').filter((d) => d.kind === 'notice' && d.status === 'pending').map((d) => ({ id: d.id, title: d.title })),
    actions: listEntities(ctx, 'actions').filter((a) => a.status === 'open').map((a) => ({ id: a.id, title: a.title })),
    digest: latestDigest(ctx),
  };
}

/**
 * The machine summary of today that `project-manager` narrates into the digest.
 * @param {object} ctx
 */
export function buildDigest(ctx) {
  const now = ctx.now();
  const today = localDate(now);
  const tickets = listEntities(ctx, 'tickets');
  const brief = (t) => ({ id: t.id, title: t.title, owner: t.owner, status: t.status, priority: t.priority });
  const isToday = (ts) => localDate(new Date(ts)) === today;
  const runs = listRecentRuns(ctx, 500).filter((r) => isToday(r.started));
  const decisions = listEntities(ctx, 'decisions');
  const pending = new Set(decisions.filter((d) => d.status === 'pending').map((d) => d.id));

  return {
    date: today,
    shipped: tickets.filter((t) => t.history?.some((h) => h.to === 'done' && isToday(h.ts))).map((t) => ({ ...brief(t), result: t.result })),
    in_progress: tickets.filter((t) => ['in_progress', 'review', 'qa'].includes(t.status)).map(brief),
    blocked: tickets.filter((t) => t.status === 'blocked').map((t) => ({ ...brief(t), note: t.notes?.at(-1)?.text ?? null })),
    at_risk: tickets.filter((t) => t.status !== 'done' && t.status !== 'cancelled'
      && (t.attempts > 0 || (t.decisions ?? []).some((d) => pending.has(d)))).map(brief),
    needs_ceo: {
      decisions: [...pending].map((id) => decisions.find((d) => d.id === id)).map((d) => ({ id: d.id, kind: d.kind, title: d.title })),
      actions: listEntities(ctx, 'actions').filter((a) => a.status === 'open').map((a) => ({ id: a.id, title: a.title })),
      feedback_new: listEntities(ctx, 'feedback').filter((f) => f.status === 'new').length,
    },
    runs_today: {
      count: runs.length, failed: runs.filter((r) => r.status === 'failed').length,
      cost_usd: Math.round(runs.reduce((sum, r) => sum + (r.cost_usd ?? 0), 0) * 100) / 100,
    },
  };
}

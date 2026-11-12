// The merge queue (T-1296): which finished ticket goes through the pre-merge gate next, and what the
// board shows of the line. One gate run takes 40-75 minutes, so the order matters: pick by ticket ID
// and a P3 waits ahead of a P0 and ahead of a done ticket that blocked work is waiting on.
import { isCodeType } from './flows.mjs';
import { listEntities } from './store.mjs';

/** A ticket with this tag is never merged (security-disclosure runbook §6). */
export const EMBARGO_TAG = 'embargoed';

/** Lower sorts first. Unknown priorities go last. */
function priorityRank(priority) {
  const n = Number(/^P(\d+)$/.exec(priority ?? '')?.[1]);
  return Number.isFinite(n) ? n : Number.MAX_SAFE_INTEGER;
}

/** When the ticket last reached `done` (ms); falls back to `updated`, then 0. */
export function doneAtMs(ticket) {
  const entry = [...(ticket.history ?? [])].reverse().find((h) => h.to === 'done');
  const t = Date.parse(entry?.ts ?? ticket.updated ?? '');
  return Number.isFinite(t) ? t : 0;
}

/**
 * Order done tickets for the gate: (1) tickets that a blocked or ready ticket lists in `depends_on`,
 * then (2) priority, P0 first, then (3) the earliest done time, then ticket ID. Pure; does not mutate.
 * @param {object[]} done done tickets to order
 * @param {object[]} all every ticket (to find the waiting dependents)
 * @returns {object[]}
 */
export function orderDoneQueue(done, all) {
  const awaited = new Set();
  for (const t of all) {
    if (t.status === 'blocked' || t.status === 'ready') for (const id of t.depends_on ?? []) awaited.add(id);
  }
  const key = (t) => [awaited.has(t.id) ? 0 : 1, priorityRank(t.priority), doneAtMs(t)];
  return [...done].sort((a, b) => {
    const ka = key(a), kb = key(b);
    for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] - kb[i];
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
}

/**
 * What the board shows: the done code tickets still to go through the gate (in gate order, not
 * counting the one in the gate), the ticket(s) in the gate (a merge train, T-1297, has several; `id` is the first), and when main last took a merge.
 * @param {object} ctx
 * @param {object} dispatcherState result of readDispatcherState
 * @param {boolean} dispatcherAlive a stale gate record from a dead dispatcher is not shown
 * @returns {{waiting: string[], in_gate: {id: string, ids: string[], started_at: string}|null, last_merged_at: string|null}}
 */
export function buildMergeQueue(ctx, dispatcherState, dispatcherAlive) {
  const all = listEntities(ctx, 'tickets');
  const gate = dispatcherAlive ? dispatcherState.merge_gate ?? null : null;
  const inGate = gate ? (gate.tickets?.length ? gate.tickets : [gate.ticket]) : [];
  const waiting = orderDoneQueue(
    all.filter((t) => t.status === 'done' && isCodeType(ctx.config, t.type) && t.links?.worktree
      && !(t.tags ?? []).includes(EMBARGO_TAG) && !inGate.includes(t.id)),
    all,
  ).map((t) => t.id);
  const merged = all.map((t) => t.links?.merged).filter(Boolean).sort();
  return {
    waiting,
    in_gate: gate ? { id: inGate[0], ids: inGate, started_at: gate.started_at } : null,
    last_merged_at: merged.at(-1) ?? null,
  };
}

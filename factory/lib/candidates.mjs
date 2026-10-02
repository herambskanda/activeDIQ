// Which work the dispatcher launches next. Pure: given a snapshot of the state, the time and the
// config, it returns the candidates for the free slots. No I/O, no clock.
import { claimBlockers, indexById, isOpen } from './tickets.mjs';
import { currentRole, isCodeType } from './flows.mjs';
import { localDate } from './store.mjs';
import { setting } from './settings.mjs';

const RANK = { P0: 0, P1: 1, P2: 2, P3: 3 };
/** Auto-created meta work competes in the ready pool at these priorities (see README "Development"). */
const META_PRIORITY = { triage: 'P0', grooming: 'P1', digest: 'P1' };
const STAGE_ORDER = { review: 0, qa: 1 };

const byPriority = (a, b) => (RANK[a.priority] ?? 9) - (RANK[b.priority] ?? 9)
  || String(a.created).localeCompare(String(b.created))
  || a.id.localeCompare(b.id);

/**
 * Why the dispatcher must not launch anything now, or null.
 * @param {{control?: {paused?: boolean}, dispatcher?: {backoff_until?: string|null, runs_today?: {date: string|null, count: number}}}} state
 * @param {Date} now
 * @param {object} config
 * @returns {string|null}
 */
export function launchGate(state, now, config) {
  if (state.control?.paused) return 'paused';
  const until = state.dispatcher?.backoff_until;
  if (until && Date.parse(until) > now.getTime()) return `backing off until ${until}`;
  const today = state.dispatcher?.runs_today;
  const count = today?.date === localDate(now) ? today.count : 0;
  if (count >= config.dispatcher.daily_run_cap) return `daily run cap reached (${count}/${config.dispatcher.daily_run_cap})`;
  return null;
}

/**
 * Meta tickets the dispatcher would create now: triage, grooming and the daily digest. Never more
 * than one open ticket of each kind.
 * @param {object} state tickets, decisions, feedback
 * @param {Date} now
 * @param {object} config
 * @returns {Array<object>} proposals {kind, owner, priority, title, summary, body, acceptance, tags, meta}
 */
export function metaProposals(state, now, config) {
  const d = config.dispatcher;
  const metas = state.tickets.filter((t) => t.type === 'meta');
  const ofKind = (kind) => metas.filter((t) => t.tags?.includes(kind));
  const isOpenKind = (kind) => ofKind(kind).some(isOpen);
  const coolingDown = (kind, minutes) => ofKind(kind).some((t) => now.getTime() - Date.parse(t.created) < minutes * 60_000);
  const out = [];

  if (!isOpenKind('triage') && !coolingDown('triage', d.triage_cooldown_minutes ?? 0)) {
    const retriageMs = setting(config, 'blocked_retriage_hours') * 3_600_000;
    const decisions = state.decisions.filter((x) => (x.status === 'answered' || x.status === 'defaulted') && !x.applied).map((x) => x.id);
    const feedback = state.feedback.filter((f) => f.status === 'new').map((f) => f.id);
    const blocked = state.tickets
      .filter((t) => t.status === 'blocked' && !(t.type === 'meta' && t.tags?.includes('triage'))
        && (!t.triaged_at || now.getTime() - Date.parse(t.triaged_at) >= retriageMs))
      .map((t) => t.id);
    if (decisions.length + feedback.length + blocked.length > 0) {
      out.push({
        kind: 'triage', owner: 'factory-director', priority: META_PRIORITY.triage,
        title: `Triage: ${decisions.length} answers · ${feedback.length} feedback · ${blocked.length} blocked`,
        summary: 'Propagate the CEO\'s answers and feedback and decide what to do with blocked tickets.',
        body: [
          `Decisions answered or defaulted, not yet applied: ${decisions.join(', ') || 'none'}`,
          `New feedback: ${feedback.join(', ') || 'none'}`,
          `Blocked tickets: ${blocked.join(', ') || 'none'}`,
        ].join('\n'),
        acceptance: ['Given the listed items, when triage ends, then every decision is applied, every feedback item is triaged and every blocked ticket has a next step.'],
        tags: ['triage'], meta: { kind: 'triage', decisions, feedback, blocked },
      });
    }
  }

  if (!isOpenKind('grooming') && !coolingDown('grooming', d.grooming_cooldown_minutes ?? 0)) {
    const work = state.tickets.filter((t) => t.type !== 'meta');
    const ready = work.filter((t) => t.status === 'ready').length;
    const backlog = work.filter((t) => t.status === 'backlog').map((t) => t.id);
    if (ready < d.grooming_min_ready && backlog.length > 0) {
      out.push({
        kind: 'grooming', owner: 'project-manager', priority: META_PRIORITY.grooming,
        title: `Groom the backlog: ${ready} ready, ${backlog.length} in backlog`,
        summary: `Fewer than ${d.grooming_min_ready} tickets are ready; refine backlog tickets so the factory does not run dry.`,
        body: `Ready now: ${ready} (minimum ${d.grooming_min_ready}).\nBacklog: ${backlog.join(', ')}`,
        acceptance: [`Given the backlog, when grooming ends, then at least ${d.grooming_min_ready} tickets are ready or nothing more can be made ready.`],
        tags: ['grooming'], meta: { kind: 'grooming', ready, min_ready: d.grooming_min_ready, backlog },
      });
    }
  }

  const today = localDate(now);
  if (now.getHours() >= d.digest_hour_local && !isOpenKind('digest')
    && !ofKind('digest').some((t) => localDate(new Date(t.created)) === today)) {
    out.push({
      kind: 'digest', owner: 'project-manager', priority: META_PRIORITY.digest,
      title: `Digest: ${today}`,
      summary: `Write the daily digest for ${today}.`,
      body: `Write factory/reports/digest-${today}.md.`,
      acceptance: [`Given today's activity, when the ticket ends, then factory/reports/digest-${today}.md exists and states facts only.`],
      tags: ['digest'], meta: { kind: 'digest', date: today },
    });
  }
  return out;
}

/**
 * Stable key of a candidate (used to skip a candidate that could not be launched this tick).
 * @param {{ticket: {id: string}|null, create?: {kind: string}}} candidate
 */
export function candidateKey(candidate) {
  return candidate.ticket ? candidate.ticket.id : `meta:${candidate.create.kind}`;
}

/**
 * Pick the candidates for the free worker slots, in this order:
 * 1. review, then qa tickets without a running session;
 * 2. in_progress tickets without a running session (handoff continuations first);
 * 3. ready tickets (priority, then age) whose dependencies are done and whose decisions are answered,
 *    competing with the meta tickets the dispatcher would create (triage, grooming, digest).
 *
 * @param {object} state {tickets, decisions, feedback, runs, control, dispatcher, sharedCheckout?, skip?}
 * @param {Date} now
 * @param {object} config
 * @returns {Array<{kind: string, ticket: object|null, create?: object, role: string, stage: string, continuation: boolean}>}
 */
export function selectCandidates(state, now, config) {
  if (launchGate(state, now, config)) return [];
  const running = state.runs.filter((r) => r.status === 'running');
  const free = config.dispatcher.max_parallel - running.length;
  if (free <= 0) return [];

  const busy = new Set(running.map((r) => r.ticket));
  const skip = state.skip ?? new Set();
  const tickets = indexById(state.tickets);
  const decisions = indexById(state.decisions);
  const idle = (t) => !busy.has(t.id) && !skip.has(t.id);
  const inflight = (t) => ({ ticket: t, role: currentRole(config, t), stage: t.status, continuation: Boolean(t.handoff?.pending) });

  const ordered = [];
  state.tickets
    .filter((t) => (t.status === 'review' || t.status === 'qa') && idle(t))
    .sort((a, b) => STAGE_ORDER[a.status] - STAGE_ORDER[b.status] || byPriority(a, b))
    .forEach((t) => ordered.push({ kind: t.status, ...inflight(t) }));

  state.tickets
    .filter((t) => t.status === 'in_progress' && idle(t))
    .sort((a, b) => Number(Boolean(b.handoff?.pending)) - Number(Boolean(a.handoff?.pending)) || byPriority(a, b))
    .forEach((t) => ordered.push({ kind: t.handoff?.pending ? 'continuation' : 'resume', ...inflight(t) }));

  const pool = state.tickets
    .filter((t) => t.status === 'ready' && idle(t))
    .filter((t) => {
      const b = claimBlockers(t, tickets, decisions);
      return b.deps.length === 0 && b.decisions.length === 0;
    })
    .map((t) => ({ sort: t, candidate: { kind: 'ready', ticket: t, role: t.owner, stage: 'in_progress', continuation: false } }));
  for (const p of metaProposals(state, now, config)) {
    const candidate = { kind: 'meta', ticket: null, create: p, role: p.owner, stage: 'in_progress', continuation: false };
    if (!skip.has(candidateKey(candidate))) {
      pool.push({ sort: { priority: p.priority, created: now.toISOString(), id: candidateKey(candidate) }, candidate });
    }
  }
  pool.sort((a, b) => byPriority(a.sort, b.sort)).forEach((p) => ordered.push(p.candidate));

  const sharedCode = (c) => state.sharedCheckout && c.ticket && isCodeType(config, c.ticket.type);
  let codeRunning = running.filter((r) => isCodeType(config, tickets.get(r.ticket)?.type)).length > 0 && state.sharedCheckout;
  const picks = [];
  for (const c of ordered) {
    if (picks.length >= free) break;
    if (sharedCode(c)) {
      if (codeRunning) continue;
      codeRunning = true;
    }
    picks.push(c);
  }
  return picks;
}

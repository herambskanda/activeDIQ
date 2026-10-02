// Ticket lifecycle: creation, Definition of Ready, claim, advance / reject / block / unblock /
// cancel, and field edits. Status changes always go through the flow (flows.mjs).
import {
  appendEvent, getEntity, nextId, nowIso, putEntity, requireEntity, updateEntity, withLock,
} from './store.mjs';
import { FactoryError } from './errors.mjs';
import {
  PRIORITIES, TICKET_TYPES, nextPosition, rejectPosition, resolveFlow,
} from './flows.mjs';

export const EFFORT_LEVELS = ['low', 'medium', 'high', 'xhigh', 'max'];
const TERMINAL = ['done', 'cancelled'];

function required(value, what) {
  if (typeof value !== 'string' || !value.trim()) throw new FactoryError(`${what} is required`);
  return value.trim();
}

/**
 * Index entities by id.
 * @template {{id: string}} T
 * @param {T[]} list
 * @returns {Map<string, T>}
 */
export function indexById(list) {
  return new Map(list.map((x) => [x.id, x]));
}

/**
 * Whether a ticket is still live (not done or cancelled).
 * @param {{status: string}} ticket
 */
export function isOpen(ticket) {
  return !TERMINAL.includes(ticket.status);
}

/**
 * Which Definition-of-Ready fields are missing.
 * @param {object} ticket
 * @returns {string[]} human-readable gaps; empty when ready
 */
export function readinessProblems(ticket) {
  const problems = [];
  if (!ticket.title?.trim()) problems.push('title');
  if (!ticket.owner?.trim()) problems.push('owner');
  if (!(ticket.acceptance ?? []).some((a) => String(a).trim())) problems.push('at least one acceptance criterion');
  if (!ticket.summary?.trim()) problems.push('summary');
  return problems;
}

/**
 * What still stands between a ticket and being claimed.
 * @param {object} ticket
 * @param {Map<string, object>} tickets by id
 * @param {Map<string, object>} decisions by id
 * @returns {{deps: string[], decisions: string[]}} unmet dependencies and unresolved decisions
 */
export function claimBlockers(ticket, tickets, decisions) {
  return {
    deps: (ticket.depends_on ?? []).filter((id) => tickets.get(id)?.status !== 'done'),
    decisions: (ticket.decisions ?? []).filter((id) => !decisions.has(id) || decisions.get(id).status === 'pending'),
  };
}

function history(ctx, t, by, from, note) {
  t.history.push({ ts: nowIso(ctx), by, from, to: t.status, note });
}

/**
 * Create a ticket.
 * @param {object} ctx
 * @param {object} input title, type, owner (required); priority, epic, milestone, depends_on, decisions,
 *   tags, parity_refs, summary, body, acceptance, status ('backlog'|'ready'), links, meta
 * @param {string} by
 * @returns {object} the ticket
 */
export function createTicket(ctx, input, by = 'cli') {
  const {
    title, type, owner, priority = 'P2', epic = null, milestone = null, depends_on = [], decisions = [],
    tags = [], parity_refs = [], summary = '', body = '', acceptance = [], status = 'backlog', links = {}, meta = null,
  } = input;
  required(title, 'title');
  required(owner, 'owner');
  if (!TICKET_TYPES.includes(type)) throw new FactoryError(`type must be one of ${TICKET_TYPES.join(' ')}`);
  if (!PRIORITIES.includes(priority)) throw new FactoryError(`priority must be one of ${PRIORITIES.join(' ')}`);
  if (!['backlog', 'ready'].includes(status)) throw new FactoryError('a new ticket starts as backlog or ready');
  resolveFlow(ctx.config, type);
  for (const id of depends_on) requireEntity(ctx, 'tickets', id, 'dependency');
  for (const id of decisions) requireEntity(ctx, 'decisions', id, 'decision');
  if (epic) requireEntity(ctx, 'epics', epic, 'epic');
  if (milestone) requireEntity(ctx, 'milestones', milestone, 'milestone');

  const now = nowIso(ctx);
  const ticket = {
    id: null, title: title.trim(), type, status, priority, owner: owner.trim(), epic, milestone,
    depends_on, decisions, tags, parity_refs, summary, body, acceptance,
    links: { spec: null, branch: null, worktree: null, ...links },
    effort_override: null, attempts: 0, escalations: 0, stage_role: null,
    handoff: { pending: false, latest: null }, result: null, notes: [],
    history: [], created: now, updated: now,
  };
  if (meta) ticket.meta = meta;
  if (status === 'ready') {
    const problems = readinessProblems(ticket);
    if (problems.length) throw new FactoryError(`not ready: missing ${problems.join(', ')}`);
  }
  withLock(ctx, () => {
    ticket.id = nextId(ctx, 'T');
    history(ctx, ticket, by, null, 'created');
    putEntity(ctx, 'tickets', ticket);
  });
  appendEvent(ctx, { actor: by, kind: 'ticket', ticket: ticket.id, text: `created ${ticket.id} (${type}, ${priority}, ${ticket.owner}, ${status}): ${ticket.title}` });
  return ticket;
}

/**
 * `backlog → ready`, refusing unless the Definition of Ready fields are present.
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 */
export function markReady(ctx, id, by) {
  const ticket = updateEntity(ctx, 'tickets', id, (t) => {
    if (t.status !== 'backlog') throw new FactoryError(`${id} is "${t.status}"; only backlog tickets can be marked ready`);
    const problems = readinessProblems(t);
    if (problems.length) throw new FactoryError(`${id} is not ready: missing ${problems.join(', ')}`);
    t.status = 'ready';
    history(ctx, t, by, 'backlog', 'marked ready');
  });
  appendEvent(ctx, { actor: by, kind: 'ticket', ticket: id, text: `${id} is ready` });
  return ticket;
}

/**
 * Append a note.
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 * @param {string} text
 */
export function addNote(ctx, id, by, text) {
  required(text, 'note text');
  const ticket = updateEntity(ctx, 'tickets', id, (t) => {
    t.notes.push({ ts: nowIso(ctx), by, text });
  });
  appendEvent(ctx, { actor: by, kind: 'ticket', ticket: id, text: `note on ${id}: ${text.slice(0, 160)}` });
  return ticket;
}

/**
 * Shared shape of every status change: validate the note, mutate under the lock, record history,
 * a note and an event.
 */
function transition(ctx, id, by, note, verb, mutate) {
  required(by, '--by');
  required(note, '--note');
  let from;
  const ticket = updateEntity(ctx, 'tickets', id, (t) => {
    from = { status: t.status, role: t.stage_role };
    mutate(t);
    history(ctx, t, by, from.status, `${verb}: ${note}`);
    t.notes.push({ ts: nowIso(ctx), by, text: `${verb}: ${note}` });
  });
  const where = ticket.status === from.status && ticket.stage_role === from.role ? ticket.status : `${from.status} → ${ticket.status}${ticket.stage_role ? ` (${ticket.stage_role})` : ''}`;
  appendEvent(ctx, { actor: by, kind: 'ticket', ticket: id, text: `${id} ${verb} ${where}: ${note.slice(0, 160)}` });
  return ticket;
}

/**
 * Finish the current stage: move to the next reviewer, the next stage, or done.
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 * @param {string} note what was done
 */
export function advanceTicket(ctx, id, by, note) {
  return transition(ctx, id, by, note, 'advanced', (t) => {
    const next = nextPosition(ctx.config, t);
    t.status = next.status;
    t.stage_role = next.stage_role;
    t.reassigned_from = null;
    t.attempts = 0;
    t.escalations = 0;
    t.effort_override = null;
    t.handoff = { ...t.handoff, pending: false };
    if (next.status === 'done') t.result = note;
  });
}

/**
 * Send a review / QA ticket back to in_progress with the owner. `attempts` is left alone.
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 * @param {string} note what must change
 */
export function rejectTicket(ctx, id, by, note) {
  return transition(ctx, id, by, note, 'rejected', (t) => {
    const back = rejectPosition(t);
    t.status = back.status;
    t.stage_role = back.stage_role;
    t.reassigned_from = null;
    t.escalations = 0;
    t.effort_override = null;
    t.handoff = { ...t.handoff, pending: false };
  });
}

/**
 * Park a ticket as blocked, remembering where it was so `unblock` can restore it.
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 * @param {string} note the blocker and what would unblock it
 */
export function blockTicket(ctx, id, by, note) {
  return transition(ctx, id, by, note, 'blocked', (t) => {
    if (t.status === 'blocked' || TERMINAL.includes(t.status)) throw new FactoryError(`${id} is ${t.status}; it cannot be blocked`);
    t.blocked_from = { status: t.status, stage_role: t.reassigned_from ?? t.stage_role };
    t.status = 'blocked';
    t.stage_role = null;
    t.reassigned_from = null;
  });
}

/**
 * Restore a blocked ticket to the stage it was blocked in, with a fresh retry budget.
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 * @param {string} note
 */
export function unblockTicket(ctx, id, by, note) {
  return transition(ctx, id, by, note, 'unblocked', (t) => {
    if (t.status !== 'blocked') throw new FactoryError(`${id} is "${t.status}", not blocked`);
    t.status = t.blocked_from?.status ?? 'ready';
    t.stage_role = t.blocked_from?.stage_role ?? null;
    t.blocked_from = null;
    t.attempts = 0;
    t.escalations = 0;
    t.effort_override = null;
  });
}

/**
 * Cancel a ticket from any live state.
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 * @param {string} note why
 */
export function cancelTicket(ctx, id, by, note) {
  return transition(ctx, id, by, note, 'cancelled', (t) => {
    if (TERMINAL.includes(t.status)) throw new FactoryError(`${id} is already ${t.status}`);
    t.status = 'cancelled';
    t.stage_role = null;
    t.reassigned_from = null;
  });
}

/**
 * Return a `done` ticket to in_progress (the dispatcher does this when the merge conflicts).
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 * @param {string} note
 */
export function reopenTicket(ctx, id, by, note) {
  return transition(ctx, id, by, note, 'reopened', (t) => {
    if (t.status !== 'done') throw new FactoryError(`${id} is "${t.status}", not done`);
    t.status = 'in_progress';
    t.stage_role = t.owner;
    t.attempts = 0;
    t.escalations = 0;
    t.effort_override = null;
    t.result = null;
  });
}

/**
 * The dispatcher's claim: `ready → in_progress` with the owner as stage role, refused while
 * dependencies are unfinished or a listed decision is unanswered.
 * @param {object} ctx
 * @param {string} id
 * @param {string} [by]
 */
export function claimTicket(ctx, id, by = 'dispatcher') {
  return updateEntity(ctx, 'tickets', id, (t) => {
    if (t.status !== 'ready') throw new FactoryError(`${id} is "${t.status}", not ready`);
    const blockers = claimBlockers(t, loadMany(ctx, 'tickets', t.depends_on ?? []), loadMany(ctx, 'decisions', t.decisions ?? []));
    if (blockers.deps.length) throw new FactoryError(`${id} waits for ${blockers.deps.join(', ')}`);
    if (blockers.decisions.length) throw new FactoryError(`${id} waits for decision ${blockers.decisions.join(', ')}`);
    t.status = 'in_progress';
    t.stage_role = t.owner;
    history(ctx, t, by, 'ready', 'claimed');
  });
}

function loadMany(ctx, kind, ids) {
  const found = new Map();
  for (const id of ids) {
    const entity = getEntity(ctx, kind, id);
    if (entity) found.set(id, entity);
  }
  return found;
}

const splitList = (value) => (value === 'null' || value === '' ? [] : value.split(',').map((s) => s.trim()).filter(Boolean));
const nullable = (value) => (value === 'null' || value === '' ? null : value);

/**
 * Edit: priority, owner, epic, milestone, effort_override, tags, depends_on, decisions.
 * @param {object} ctx
 * @param {string} id
 * @param {Record<string, string>} assignments
 * @param {string} by
 */
export function setTicketFields(ctx, id, assignments, by) {
  const ticket = updateEntity(ctx, 'tickets', id, (t) => {
    for (const [key, value] of Object.entries(assignments)) {
      switch (key) {
        case 'priority':
          if (!PRIORITIES.includes(value)) throw new FactoryError(`priority must be one of ${PRIORITIES.join(' ')}`);
          t.priority = value;
          break;
        case 'owner':
          required(value, 'owner');
          if (t.status === 'in_progress' && t.stage_role === t.owner) t.stage_role = value;
          t.owner = value;
          break;
        case 'epic':
          if (nullable(value)) requireEntity(ctx, 'epics', value, 'epic');
          t.epic = nullable(value);
          break;
        case 'milestone':
          if (nullable(value)) requireEntity(ctx, 'milestones', value, 'milestone');
          t.milestone = nullable(value);
          break;
        case 'effort_override':
          if (nullable(value) && !EFFORT_LEVELS.includes(value)) throw new FactoryError(`effort_override must be one of ${EFFORT_LEVELS.join(' ')} or null`);
          t.effort_override = nullable(value);
          break;
        case 'tags':
          t.tags = splitList(value);
          break;
        case 'depends_on': {
          const deps = splitList(value);
          if (deps.includes(id)) throw new FactoryError('a ticket cannot depend on itself');
          for (const dep of deps) requireEntity(ctx, 'tickets', dep, 'dependency');
          t.depends_on = deps;
          break;
        }
        case 'decisions': {
          const ids = splitList(value);
          for (const d of ids) requireEntity(ctx, 'decisions', d, 'decision');
          t.decisions = ids;
          break;
        }
        default:
          throw new FactoryError(`cannot set "${key}" (settable: priority owner epic milestone effort_override tags depends_on decisions)`);
      }
    }
  });
  appendEvent(ctx, { actor: by, kind: 'ticket', ticket: id, text: `${id} set ${Object.entries(assignments).map(([k, v]) => `${k}=${v}`).join(' ')}` });
  return ticket;
}

/**
 * Update the branch / worktree links the dispatcher maintains.
 * @param {object} ctx
 * @param {string} id
 * @param {object} links partial links object
 */
export function setTicketLinks(ctx, id, links) {
  return updateEntity(ctx, 'tickets', id, (t) => {
    t.links = { ...t.links, ...links };
  });
}

/**
 * The compact ticket shape the board lists.
 * @param {object} t
 */
export function summarizeTicket(t) {
  const last = t.notes?.at(-1);
  return {
    id: t.id, title: t.title, type: t.type, status: t.status, priority: t.priority, owner: t.owner,
    stage_role: t.stage_role ?? null, epic: t.epic ?? null, milestone: t.milestone ?? null,
    tags: t.tags ?? [], parity_refs: t.parity_refs ?? [], decisions: t.decisions ?? [], depends_on: t.depends_on ?? [],
    summary: t.summary ?? '', effort_override: t.effort_override ?? null,
    attempts: t.attempts ?? 0, handoff: t.handoff ?? { pending: false, latest: null },
    created: t.created, updated: t.updated, last_note: last ? String(last.text).slice(0, 280) : null,
  };
}

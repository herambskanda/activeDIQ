// Smaller entities: CEO action items, feedback, epics and milestones.
import {
  appendEvent, listEntities, nextId, nowIso, putEntity, requireEntity, updateEntity, withLock,
} from './store.mjs';
import { FactoryError } from './errors.mjs';

const SENTIMENTS = ['love', 'ok', 'change'];
const FEEDBACK_TARGET = /^(general|demo:\S+|ticket:T-\d+|doc:\S+|decision:D-\d+)$/;
export const MILESTONE_STATUSES = ['planned', 'active', 'demo-ready', 'accepted', 'rejected'];

function required(value, what) {
  if (typeof value !== 'string' || !value.trim()) throw new FactoryError(`${what} is required`);
  return value.trim();
}

// --- actions ---------------------------------------------------------------------------------

/**
 * File an action item for the CEO (something only they can do).
 * @param {object} ctx
 * @param {{title: string, detail?: string, why?: string, by?: string}} input
 */
export function createAction(ctx, { title, detail = '', why = '', by = 'factory-director' }) {
  const now = nowIso(ctx);
  const action = {
    id: nextId(ctx, 'A'), title: required(title, 'title'), detail, why, status: 'open',
    created_by: by, created: now, updated: now, done_note: null,
  };
  putEntity(ctx, 'actions', action);
  appendEvent(ctx, { actor: by, kind: 'action', text: `action ${action.id} opened: ${action.title}` });
  return action;
}

/**
 * Mark an open action item done.
 * @param {object} ctx
 * @param {string} id
 * @param {{note?: string, by?: string}} [opts]
 */
export function completeAction(ctx, id, { note = '', by = 'ceo' } = {}) {
  const action = updateEntity(ctx, 'actions', id, (a) => {
    if (a.status !== 'open') throw new FactoryError(`action ${id} is already ${a.status}`);
    a.status = 'done';
    a.done_note = note || null;
  });
  appendEvent(ctx, { actor: by, kind: 'action', text: `action ${id} done${note ? `: ${note}` : ''}` });
  return action;
}

// --- feedback --------------------------------------------------------------------------------

/**
 * Record CEO feedback.
 * @param {object} ctx
 * @param {{target: string, text: string, sentiment?: string|null, by?: string}} input
 */
export function createFeedback(ctx, { target, text, sentiment = null, by = 'ceo' }) {
  if (!FEEDBACK_TARGET.test(target ?? '')) {
    throw new FactoryError('feedback target must be general, demo:<M>, ticket:<T-id>, doc:<path> or decision:<D-id>');
  }
  if (sentiment !== null && !SENTIMENTS.includes(sentiment)) throw new FactoryError(`sentiment must be one of ${SENTIMENTS.join(', ')}`);
  const now = nowIso(ctx);
  const feedback = {
    id: nextId(ctx, 'F'), target, text: required(text, 'text'), sentiment, status: 'new',
    triage_note: null, tickets: [], created: now, updated: now,
  };
  putEntity(ctx, 'feedback', feedback);
  appendEvent(ctx, { actor: by, kind: 'feedback', text: `feedback ${feedback.id} on ${target}${sentiment ? ` (${sentiment})` : ''}` });
  return feedback;
}

/**
 * Triage feedback: record what was done with it and which tickets it produced.
 * @param {object} ctx
 * @param {string} id
 * @param {{note: string, tickets?: string[], done?: boolean, by?: string}} input
 */
export function triageFeedback(ctx, id, { note, tickets = [], done = false, by = 'factory-director' }) {
  required(note, 'note');
  for (const t of tickets) requireEntity(ctx, 'tickets', t, 'ticket');
  const feedback = updateEntity(ctx, 'feedback', id, (f) => {
    f.status = done ? 'done' : 'triaged';
    f.triage_note = note;
    f.tickets = [...new Set([...(f.tickets ?? []), ...tickets])];
  });
  appendEvent(ctx, { actor: by, kind: 'feedback', text: `feedback ${id} ${feedback.status}: ${note}` });
  return feedback;
}

// --- epics -----------------------------------------------------------------------------------

/**
 * Create an epic.
 * @param {object} ctx
 * @param {{title: string, goal?: string, milestone?: string|null, parity_refs?: string[], by?: string}} input
 */
export function createEpic(ctx, { title, goal = '', milestone = null, parity_refs = [], by = 'project-manager' }) {
  if (milestone) requireEntity(ctx, 'milestones', milestone, 'milestone');
  const now = nowIso(ctx);
  const epic = { id: nextId(ctx, 'E'), title: required(title, 'title'), goal, milestone, status: 'planned', parity_refs, created: now, updated: now };
  putEntity(ctx, 'epics', epic);
  appendEvent(ctx, { actor: by, kind: 'ticket', text: `epic ${epic.id} created: ${epic.title}` });
  return epic;
}

// --- milestones ------------------------------------------------------------------------------

/**
 * Create a milestone.
 * @param {object} ctx
 * @param {{name: string, goal?: string, target?: string|null, by?: string}} input
 */
export function createMilestone(ctx, { name, goal = '', target = null, by = 'project-manager' }) {
  const now = nowIso(ctx);
  const milestone = {
    id: nextId(ctx, 'M'), name: required(name, 'name'), goal, status: 'planned', target,
    demo: { script: null, video: null, url: null }, created: now, updated: now,
  };
  putEntity(ctx, 'milestones', milestone);
  appendEvent(ctx, { actor: by, kind: 'ticket', text: `milestone ${milestone.id} created: ${milestone.name}` });
  return milestone;
}

/**
 * Update milestone fields: status, name, goal, target, demo.script, demo.video, demo.url.
 * @param {object} ctx
 * @param {string} id
 * @param {Record<string, string>} assignments
 * @param {string} [by]
 */
export function setMilestone(ctx, id, assignments, by = 'factory-director') {
  const milestone = withLock(ctx, () => {
    const m = requireEntity(ctx, 'milestones', id, 'milestone');
    for (const [key, raw] of Object.entries(assignments)) {
      const value = raw === 'null' || raw === '' ? null : raw;
      if (key === 'status') {
        if (!MILESTONE_STATUSES.includes(value)) throw new FactoryError(`milestone status must be one of ${MILESTONE_STATUSES.join(', ')}`);
        m.status = value;
      } else if (['name', 'goal', 'target'].includes(key)) {
        m[key] = value;
      } else if (['demo.script', 'demo.video', 'demo.url'].includes(key)) {
        m.demo = { ...m.demo, [key.slice(5)]: value };
      } else {
        throw new FactoryError(`unknown milestone field "${key}"`);
      }
    }
    m.updated = nowIso(ctx);
    return putEntity(ctx, 'milestones', m);
  });
  appendEvent(ctx, { actor: by, kind: 'ticket', text: `milestone ${id} updated: ${Object.entries(assignments).map(([k, v]) => `${k}=${v}`).join(' ')}` });
  return milestone;
}

/**
 * Sort ids that share a prefix numerically (M2 before M10).
 * @param {Array<{id: string}>} items
 */
export function sortById(items) {
  const num = (id) => Number.parseInt(id.replace(/\D+/g, ''), 10) || 0;
  return [...items].sort((a, b) => num(a.id) - num(b.id) || a.id.localeCompare(b.id));
}

/**
 * List entities of a kind, numerically ordered by id.
 * @param {object} ctx
 * @param {'actions'|'feedback'|'epics'|'milestones'} kind
 */
export function listItems(ctx, kind) {
  return sortById(listEntities(ctx, kind));
}

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

/** A parity-matrix feature ID: ADM-045, ADSS-091, I360-004, M365-018. */
const PARITY_REF = /^[A-Z][A-Z0-9]*-\d+$/;

/**
 * Validate and de-duplicate parity refs, keeping first-seen order.
 * @param {string[]} refs
 * @returns {string[]}
 */
function parityRefs(refs) {
  const bad = refs.filter((r) => !PARITY_REF.test(r));
  if (bad.length) throw new FactoryError(`parity refs must look like ADM-045 (got ${bad.join(', ')})`);
  return [...new Set(refs)];
}

const refList = (value) => (value === 'null' || value === '' ? [] : value.split(',').map((s) => s.trim()).filter(Boolean));

/**
 * Create an epic.
 * @param {object} ctx
 * @param {{title: string, goal?: string, milestone?: string|null, parity_refs?: string[], by?: string}} input
 */
export function createEpic(ctx, { title, goal = '', milestone = null, parity_refs = [], by = 'project-manager' }) {
  if (milestone) requireEntity(ctx, 'milestones', milestone, 'milestone');
  const refs = parityRefs(parity_refs);
  const now = nowIso(ctx);
  const epic = { id: nextId(ctx, 'E'), title: required(title, 'title'), goal, milestone, status: 'planned', parity_refs: refs, created: now, updated: now };
  putEntity(ctx, 'epics', epic);
  appendEvent(ctx, { actor: by, kind: 'ticket', text: `epic ${epic.id} created: ${epic.title}` });
  return epic;
}

/**
 * Edit epic fields: title, goal, milestone, and parity_refs — replaced with `parity_refs=A,B`,
 * extended with `parity_refs+=C` or trimmed with `parity_refs-=A` (so a one-ref change cannot
 * drop the others). All assignments validate before anything is written; the event records the
 * actor and what changed (added/removed refs, old → new values).
 * @param {object} ctx
 * @param {string} id
 * @param {Record<string, string>} assignments
 * @param {string} [by]
 */
export function setEpic(ctx, id, assignments, by = 'project-manager') {
  const changes = [];
  const epic = updateEntity(ctx, 'epics', id, (e) => {
    for (const [key, raw] of Object.entries(assignments)) {
      switch (key) {
        case 'title': {
          const title = required(raw, 'title');
          if (title !== e.title) changes.push(`title "${e.title}" → "${title}"`);
          e.title = title;
          break;
        }
        case 'goal':
          if (raw !== e.goal) changes.push(`goal "${e.goal ?? ''}" → "${raw}"`);
          e.goal = raw;
          break;
        case 'milestone': {
          const milestone = raw === 'null' || raw === '' ? null : raw;
          if (milestone) requireEntity(ctx, 'milestones', milestone, 'milestone');
          if (milestone !== e.milestone) changes.push(`milestone ${e.milestone ?? 'none'} → ${milestone ?? 'none'}`);
          e.milestone = milestone;
          break;
        }
        case 'parity_refs':
        case 'parity_refs+':
        case 'parity_refs-': {
          const before = e.parity_refs ?? [];
          const given = parityRefs(refList(raw));
          if (key !== 'parity_refs' && !given.length) throw new FactoryError(`${key}= needs at least one ref`);
          let after;
          if (key === 'parity_refs') after = given;
          else if (key === 'parity_refs+') after = [...before, ...given.filter((r) => !before.includes(r))];
          else {
            const missing = given.filter((r) => !before.includes(r));
            if (missing.length) throw new FactoryError(`${id} has no parity ref ${missing.join(', ')}`);
            after = before.filter((r) => !given.includes(r));
          }
          const added = after.filter((r) => !before.includes(r));
          const removed = before.filter((r) => !after.includes(r));
          if (added.length || removed.length) {
            changes.push(`parity_refs ${[...added.map((r) => `+${r}`), ...removed.map((r) => `-${r}`)].join(' ')} (${before.length} → ${after.length})`);
          }
          e.parity_refs = after;
          break;
        }
        default:
          throw new FactoryError(`cannot set "${key}" on an epic (settable: title goal milestone parity_refs, parity_refs+=, parity_refs-=)`);
      }
    }
  });
  appendEvent(ctx, { actor: by, kind: 'ticket', text: `epic ${id} updated: ${changes.length ? changes.join('; ') : 'no change'}` });
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

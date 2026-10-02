// CEO decisions: creation (with the open-decision budget), answers, advisory defaults, notices.
import {
  appendEvent, listEntities, nextId, nowIso, putEntity, requireEntity, updateEntity, withLock,
} from './store.mjs';
import { FactoryError } from './errors.mjs';
import { createFeedback } from './items.mjs';
import { notify } from './notify.mjs';

export const DECISION_KINDS = ['directional', 'advisory', 'notice'];
const OPTION_ID = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;

function required(value, what) {
  if (typeof value !== 'string' || !value.trim()) throw new FactoryError(`${what} is required`);
  return value.trim();
}

/**
 * Parse a CLI option spec `id|Label|summary[|preview]`.
 * @param {string} spec
 */
export function parseOptionSpec(spec) {
  const [id, label, summary = '', preview = null] = String(spec).split('|').map((s) => s.trim());
  if (!id || !label) throw new FactoryError(`bad option "${spec}" (expected "id|Label|summary")`);
  return { id, label, summary, pros: [], cons: [], preview: preview || null };
}

/**
 * Parse `72h`, `3d` or `90m` into hours.
 * @param {string} text
 */
export function parseDuration(text) {
  const m = /^(\d+(?:\.\d+)?)\s*([hdm])$/i.exec(String(text).trim());
  if (!m) throw new FactoryError(`bad duration "${text}" (use 72h, 3d or 90m)`);
  const n = Number(m[1]);
  return { h: n, d: n * 24, m: n / 60 }[m[2].toLowerCase()];
}

/**
 * Decisions that count against the CEO's budget (`ceo.max_open_decisions`).
 * @param {object[]} decisions
 */
export function openCeoDecisions(decisions) {
  return decisions.filter((d) => d.status === 'pending' && (d.kind === 'directional' || d.kind === 'advisory'));
}

/**
 * Create a decision request. Refuses a request over the open-decision budget unless forced, and
 * attaches the decision to every ticket it blocks.
 * @param {object} ctx
 * @param {object} input kind, title, question, options[], context, multi, recommendation, rationale,
 *   default_option, default_in_hours, blocks[]
 * @param {{by?: string, force?: boolean}} [opts]
 */
export function createDecision(ctx, input, { by = 'factory-director', force = false } = {}) {
  const {
    kind, title, question, context = '', options = [], multi = false, recommendation = null, rationale = '',
    default_option = null, default_in_hours = null, blocks = [],
  } = input;
  if (!DECISION_KINDS.includes(kind)) throw new FactoryError(`kind must be one of ${DECISION_KINDS.join(' ')}`);
  required(title, 'title');
  required(question, 'question');
  const ids = options.map((o) => o.id);
  if (ids.some((id) => !OPTION_ID.test(id))) throw new FactoryError('option ids may contain letters, digits, - and _');
  if (new Set(ids).size !== ids.length) throw new FactoryError('option ids must be unique');
  if (kind !== 'notice' && (options.length < 2 || options.length > 4)) {
    throw new FactoryError(`a ${kind} decision needs 2–4 options (got ${options.length})`);
  }
  if (options.length > 4) throw new FactoryError('at most 4 options');
  if (recommendation && !ids.includes(recommendation)) throw new FactoryError(`recommendation "${recommendation}" is not one of the options`);

  const now = ctx.now();
  let defaultOption = default_option;
  let defaultAt = null;
  if (kind === 'advisory') {
    defaultOption ??= recommendation;
    if (!defaultOption) throw new FactoryError('an advisory decision needs --default (or --recommend, which becomes the default)');
    const hours = default_in_hours ?? ctx.config.ceo?.advisory_default_hours ?? 72;
    defaultAt = new Date(now.getTime() + hours * 3_600_000).toISOString();
  } else if (defaultOption) {
    throw new FactoryError('only advisory decisions have a default');
  }
  if (defaultOption && !ids.includes(defaultOption)) throw new FactoryError(`default "${defaultOption}" is not one of the options`);
  for (const t of blocks) requireEntity(ctx, 'tickets', t, 'ticket');

  const decision = withLock(ctx, () => {
    const open = openCeoDecisions(listEntities(ctx, 'decisions'));
    const max = ctx.config.ceo?.max_open_decisions ?? 3;
    if ((kind === 'directional' || kind === 'advisory') && open.length >= max && !force) {
      throw new FactoryError(`${open.length} CEO decisions are already open (${open.map((d) => d.id).join(', ')}; limit ${max}). Batch this one into an open request, or pass --force.`);
    }
    const d = {
      id: nextId(ctx, 'D'), kind, title: title.trim(), question: question.trim(), context, options, multi: Boolean(multi),
      recommendation, rationale, default_option: defaultOption, default_at: defaultAt, blocks,
      status: 'pending', answer: null, applied: false, created_by: by, created: now.toISOString(), updated: now.toISOString(),
    };
    putEntity(ctx, 'decisions', d);
    for (const t of blocks) {
      updateEntity(ctx, 'tickets', t, (ticket) => {
        if (!ticket.decisions.includes(d.id)) ticket.decisions.push(d.id);
      });
    }
    return d;
  });
  appendEvent(ctx, { actor: by, kind: 'decision', text: `${decision.kind} decision ${decision.id} opened: ${decision.title}` });
  if (kind !== 'notice') notify(ctx, { title: 'activeDIQ needs you', message: decision.title });
  return decision;
}

/**
 * Record the CEO's answer.
 * @param {object} ctx
 * @param {string} id
 * @param {{options: string[], note?: string, via?: 'cli'|'board'}} answer
 */
export function answerDecision(ctx, id, { options, note = '', via = 'cli' }) {
  const decision = updateEntity(ctx, 'decisions', id, (d) => {
    if (d.status !== 'pending') throw new FactoryError(`${id} is already ${d.status}`);
    if (d.kind === 'notice') throw new FactoryError(`${id} is a notice: acknowledge or veto it`);
    const chosen = [...new Set(options ?? [])];
    if (!chosen.length) throw new FactoryError('choose at least one option');
    const unknown = chosen.filter((o) => !d.options.some((x) => x.id === o));
    if (unknown.length) throw new FactoryError(`unknown option ${unknown.join(', ')} (options: ${d.options.map((o) => o.id).join(', ')})`);
    if (!d.multi && chosen.length > 1) throw new FactoryError(`${id} accepts a single option`);
    d.status = 'answered';
    d.answer = { options: chosen, note, ts: nowIso(ctx), via };
    d.applied = false;
  });
  appendEvent(ctx, { actor: 'ceo', kind: 'decision', text: `${id} answered: ${decision.answer.options.join(', ')}${note ? ` — ${note}` : ''}` });
  return decision;
}

/**
 * Mark an answered / defaulted decision as propagated (memory, tickets).
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 */
export function markApplied(ctx, id, by) {
  const decision = updateEntity(ctx, 'decisions', id, (d) => {
    if (d.status !== 'answered' && d.status !== 'defaulted') throw new FactoryError(`${id} is ${d.status}; only answered or defaulted decisions can be applied`);
    d.applied = true;
  });
  appendEvent(ctx, { actor: by, kind: 'decision', text: `${id} applied` });
  return decision;
}

/**
 * Withdraw a pending decision that is no longer needed.
 * @param {object} ctx
 * @param {string} id
 * @param {string} by
 * @param {string} note why
 */
export function withdrawDecision(ctx, id, by, note) {
  required(note, '--note');
  const decision = updateEntity(ctx, 'decisions', id, (d) => {
    if (d.status !== 'pending') throw new FactoryError(`${id} is already ${d.status}`);
    d.status = 'withdrawn';
    d.withdrawn_note = note;
  });
  appendEvent(ctx, { actor: by, kind: 'decision', text: `${id} withdrawn: ${note}` });
  return decision;
}

function resolveNotice(ctx, id, status, note, by) {
  return updateEntity(ctx, 'decisions', id, (d) => {
    if (d.kind !== 'notice') throw new FactoryError(`${id} is a ${d.kind} decision: answer it instead`);
    if (d.status !== 'pending') throw new FactoryError(`${id} is already ${d.status}`);
    d.status = status;
    d.answer = { options: [], note, ts: nowIso(ctx), via: by };
    d.applied = true;
  });
}

/**
 * The CEO acknowledges a factory notice.
 * @param {object} ctx
 * @param {string} id
 * @param {{note?: string, by?: string}} [opts]
 */
export function acknowledgeNotice(ctx, id, { note = '', by = 'board' } = {}) {
  const decision = resolveNotice(ctx, id, 'acknowledged', note, by);
  appendEvent(ctx, { actor: 'ceo', kind: 'decision', text: `${id} acknowledged` });
  return decision;
}

/**
 * The CEO vetoes a factory notice; this files feedback so the next triage reverses the decision.
 * @param {object} ctx
 * @param {string} id
 * @param {{note?: string, by?: string}} [opts]
 */
export function vetoNotice(ctx, id, { note = '', by = 'board' } = {}) {
  const decision = resolveNotice(ctx, id, 'vetoed', note, by);
  createFeedback(ctx, {
    target: `decision:${id}`, sentiment: 'change', by: 'ceo',
    text: note || `I veto "${decision.title}". Please reverse it and tell me what you propose instead.`,
  });
  appendEvent(ctx, { actor: 'ceo', kind: 'decision', text: `${id} vetoed${note ? `: ${note}` : ''}` });
  return decision;
}

/**
 * Apply the default of every advisory decision whose window has passed.
 * @param {object} ctx
 * @returns {string[]} ids defaulted
 */
export function applyAdvisoryDefaults(ctx) {
  const now = ctx.now();
  const defaulted = [];
  for (const d of listEntities(ctx, 'decisions')) {
    if (d.kind !== 'advisory' || d.status !== 'pending' || !d.default_at || Date.parse(d.default_at) > now.getTime()) continue;
    try {
      updateEntity(ctx, 'decisions', d.id, (fresh) => {
        if (fresh.status !== 'pending') return;
        fresh.status = 'defaulted';
        fresh.answer = { options: [fresh.default_option], note: 'Default applied: no answer within the window.', ts: now.toISOString(), via: 'default' };
        fresh.applied = false;
        defaulted.push(fresh.id);
      });
      if (defaulted.includes(d.id)) appendEvent(ctx, { actor: 'dispatcher', kind: 'decision', text: `${d.id} defaulted to "${d.default_option}" (no answer by ${d.default_at})` });
    } catch {
      // a decision deleted mid-scan is not worth failing the tick over
    }
  }
  return defaulted;
}

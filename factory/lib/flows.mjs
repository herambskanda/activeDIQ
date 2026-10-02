// Flow resolution and transitions. Pure: no I/O, no clock. A flow is the ordered list of stages a
// ticket type passes through; the dispatcher claims `ready → in_progress`, workers advance or reject.
import { FactoryError } from './errors.mjs';

export const TICKET_TYPES = ['build', 'bug', 'test', 'chore', 'ops', 'spec', 'design', 'docs', 'video', 'research', 'proposal', 'decision-prep', 'spike', 'meta'];
export const STATUSES = ['backlog', 'ready', 'in_progress', 'review', 'qa', 'done', 'blocked', 'cancelled'];
export const PRIORITIES = ['P0', 'P1', 'P2', 'P3'];
/** Statuses in which a worker session does work (and `advance` / `reject` are legal). */
export const WORK_STAGES = ['in_progress', 'review', 'qa'];
/** The role substituted when a ticket's owner would review their own work. */
export const SUBSTITUTE_REVIEWER = 'factory-director';

const MAX_ALIAS_DEPTH = 5;

/**
 * Resolve a ticket type to its stages, following string aliases.
 * @param {object} config
 * @param {string} type
 * @returns {Array<{status: string, role: string|null, extra: Array<{role: string, tag: string}>}>}
 */
export function resolveFlow(config, type) {
  let flow = config.flows?.[type];
  for (let depth = 0; typeof flow === 'string'; depth++) {
    if (depth >= MAX_ALIAS_DEPTH) throw new FactoryError(`flow alias loop at type "${type}"`);
    flow = config.flows[flow];
  }
  if (!Array.isArray(flow)) throw new FactoryError(`no flow configured for ticket type "${type}"`);
  return flow.map(([status, role = null, ...extras]) => ({
    status,
    role,
    extra: extras.map((spec) => {
      const m = /^\+([^:]+):(.+)$/.exec(spec);
      if (!m) throw new FactoryError(`bad extra-reviewer spec "${spec}" in flow "${type}" (expected "+role:tag")`);
      return { role: m[1], tag: m[2] };
    }),
  }));
}

/**
 * Problems with the configured flows (for `doctor`).
 * @param {object} config
 * @returns {string[]}
 */
export function validateFlows(config) {
  const problems = [];
  for (const type of TICKET_TYPES) {
    try {
      const flow = resolveFlow(config, type);
      if (flow[0]?.status !== 'in_progress') problems.push(`flow "${type}" must start at in_progress`);
      if (flow.at(-1)?.status !== 'done') problems.push(`flow "${type}" must end at done`);
    } catch (err) {
      problems.push(err.message);
    }
  }
  return problems;
}

/**
 * Whether a ticket type produces code (branch + worktree + merge).
 * @param {object} config
 * @param {string} type
 */
export function isCodeType(config, type) {
  return (config.dispatcher?.code_types ?? []).includes(type);
}

/**
 * The ordered roles that work a stage for this ticket: `$owner` expanded, tag-conditional second
 * reviewers included, and an owner who would review their own work replaced by factory-director.
 * @param {{owner: string, tags?: string[]}} ticket
 * @param {{status: string, role: string|null, extra: Array<{role: string, tag: string}>}} stage
 * @returns {string[]}
 */
export function rolesForStage(ticket, stage) {
  if (!stage.role) return [];
  const tags = ticket.tags ?? [];
  const roles = [stage.role, ...stage.extra.filter((e) => tags.includes(e.tag)).map((e) => e.role)]
    .map((role) => (role === '$owner' ? ticket.owner : role))
    .map((role) => (stage.status !== 'in_progress' && role === ticket.owner ? SUBSTITUTE_REVIEWER : role));
  return [...new Set(roles)];
}

function stageFor(config, ticket, status = ticket.status) {
  const flow = resolveFlow(config, ticket.type);
  const index = flow.findIndex((s) => s.status === status);
  if (index < 0) throw new FactoryError(`status "${status}" is not a stage of the ${ticket.type} flow`);
  return { flow, index };
}

/**
 * The role that works a ticket right now: the dispatcher-set `stage_role`, else the first role of
 * the current stage.
 * @param {object} config
 * @param {object} ticket
 * @returns {string|null}
 */
export function currentRole(config, ticket) {
  if (ticket.stage_role) return ticket.stage_role;
  if (ticket.status === 'ready') return ticket.owner;
  try {
    const { flow, index } = stageFor(config, ticket);
    return rolesForStage(ticket, flow[index])[0] ?? null;
  } catch {
    return null;
  }
}

/**
 * Where `advance` takes a ticket: a second reviewer in the same stage, the next stage, or done.
 * @param {object} config
 * @param {object} ticket
 * @returns {{status: string, stage_role: string|null}}
 */
export function nextPosition(config, ticket) {
  if (!WORK_STAGES.includes(ticket.status)) {
    throw new FactoryError(`cannot advance ${ticket.id}: status is "${ticket.status}" (only ${WORK_STAGES.join(', ')} can advance)`);
  }
  const { flow, index } = stageFor(config, ticket);
  const roles = rolesForStage(ticket, flow[index]);
  const at = roles.indexOf(ticket.reassigned_from ?? ticket.stage_role);
  if (at >= 0 && at < roles.length - 1) return { status: ticket.status, stage_role: roles[at + 1] };
  const next = flow[index + 1];
  if (!next || next.status === 'done') return { status: 'done', stage_role: null };
  return { status: next.status, stage_role: rolesForStage(ticket, next)[0] ?? null };
}

/**
 * Where `reject` takes a ticket: back to in_progress with the owner.
 * @param {object} ticket
 * @returns {{status: string, stage_role: string}}
 */
export function rejectPosition(ticket) {
  if (ticket.status !== 'review' && ticket.status !== 'qa') {
    throw new FactoryError(`cannot reject ${ticket.id}: status is "${ticket.status}" (only review and qa can reject)`);
  }
  return { status: 'in_progress', stage_role: ticket.owner };
}

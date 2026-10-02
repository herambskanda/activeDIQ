// The escalation ladder (OPERATING-MODEL §3) for a ticket whose worker made no progress:
// retry → raise effort one rung → reassign the stage to the escalation role → blocked.
import { appendEvent, nowIso, updateEntity } from './store.mjs';
import { blockTicket } from './tickets.mjs';
import { modelFamily, nextEffort } from './policy.mjs';

/**
 * Decide the next step after one more run without progress. Pure.
 * @param {object} ticket
 * @param {{name: string, model?: string|null, effort?: string|null}|null} agent the role currently working the stage
 * @param {object} config
 * @returns {{action: 'retry', attempts: number} | {action: 'raise_effort', effort: string} | {action: 'reassign', role: string} | {action: 'block'}}
 */
export function planNoProgress(ticket, agent, config) {
  const attempts = (ticket.attempts ?? 0) + 1;
  if (attempts < (config.dispatcher.max_retries ?? 2)) return { action: 'retry', attempts };

  const escalationRole = config.models.escalation_roles?.[0] ?? null;
  const onEscalationRole = ticket.stage_role === escalationRole;
  if ((ticket.escalations ?? 0) === 0 && !onEscalationRole && agent) {
    const effort = nextEffort(config, modelFamily(agent.model), ticket.effort_override ?? agent.effort);
    if (effort) return { action: 'raise_effort', effort };
  }
  if (escalationRole && !onEscalationRole) return { action: 'reassign', role: escalationRole };
  return { action: 'block' };
}

/**
 * Record a run that ended without moving the ticket, and escalate when retries are exhausted.
 * Every escalation is an event.
 * @param {object} ctx
 * @param {string} ticketId
 * @param {{name: string, model?: string|null, effort?: string|null}|null} agent
 * @param {string} runId
 * @returns {{action: string}} the plan that was applied
 */
export function applyNoProgress(ctx, ticketId, agent, runId) {
  let plan;
  updateEntity(ctx, 'tickets', ticketId, (t) => {
    plan = planNoProgress(t, agent, ctx.config);
    const ts = nowIso(ctx);
    const note = (text) => t.notes.push({ ts, by: 'dispatcher', text });
    if (plan.action === 'retry') {
      t.attempts = plan.attempts;
      note(`run ${runId} ended without progress (attempt ${plan.attempts}/${ctx.config.dispatcher.max_retries})`);
    } else if (plan.action === 'raise_effort') {
      t.effort_override = plan.effort;
      t.attempts = 0;
      t.escalations = 1;
      note(`escalation: ${t.stage_role} retried without progress; effort raised to ${plan.effort}`);
    } else if (plan.action === 'reassign') {
      t.reassigned_from = t.stage_role;
      t.stage_role = plan.role;
      t.effort_override = null;
      t.attempts = 0;
      t.escalations = 2;
      note(`escalation: stage reassigned from ${t.reassigned_from} to ${plan.role}`);
    }
  });
  if (plan.action === 'block') {
    blockTicket(ctx, ticketId, 'dispatcher', 'retries and escalations exhausted; the director must triage this ticket');
  }
  const text = {
    retry: `${ticketId}: run ${runId} made no progress (attempt ${plan.attempts})`,
    raise_effort: `${ticketId}: escalated, effort raised to ${plan.effort}`,
    reassign: `${ticketId}: escalated, stage reassigned to ${plan.role}`,
    block: `${ticketId}: blocked after exhausting the escalation ladder`,
  }[plan.action];
  appendEvent(ctx, { actor: 'dispatcher', kind: 'dispatcher', ticket: ticketId, run: runId, text });
  return plan;
}

// Model and effort policy (OPERATING-MODEL §3, config.models). Pure.

/**
 * Normalise a model string: contains "opus" → opus, contains "sonnet" → sonnet, else null.
 * @param {string|null|undefined} model
 * @returns {'opus'|'sonnet'|null}
 */
export function modelFamily(model) {
  const m = String(model ?? '').toLowerCase();
  if (m.includes('opus')) return 'opus';
  if (m.includes('sonnet')) return 'sonnet';
  return null;
}

function check(config, role, model, effort, { escalated }) {
  const problems = [];
  const family = modelFamily(model);
  if (!family) return [`model "${model ?? ''}" is neither opus nor sonnet`];
  if (!effort) return [`${family} agent has no effort set`];
  const models = config.models ?? {};
  if (!(models.allowed?.[family] ?? []).includes(effort)) {
    problems.push(`effort "${effort}" is not allowed for ${family} (allowed: ${(models.allowed?.[family] ?? []).join(', ') || 'none'})`);
  } else if (!escalated && (models.escalation_only?.[family] ?? []).includes(effort) && !(models.escalation_roles ?? []).includes(role)) {
    problems.push(`${family} effort "${effort}" is escalation-only; ${role} is not an escalation role`);
  }
  return problems;
}

/**
 * Policy violations of an agent definition as written.
 * @param {object} config
 * @param {{name: string, model?: string, effort?: string}} agent
 * @returns {string[]}
 */
export function checkAgentPolicy(config, agent) {
  return check(config, agent.name, agent.model, agent.effort, { escalated: false });
}

/**
 * Policy violations of a launch: the agent's model with its effort or the ticket's override. An
 * override is itself an escalation, so it is exempt from the escalation-only rule but must still be
 * in `models.allowed`.
 * @param {object} config
 * @param {{name: string, model?: string, effort?: string}} agent
 * @param {string|null} [effortOverride]
 * @returns {string[]}
 */
export function checkLaunchPolicy(config, agent, effortOverride = null) {
  return check(config, agent.name, agent.model, effortOverride ?? agent.effort, { escalated: Boolean(effortOverride) });
}

/**
 * The next rung of the effort ladder for a model family, or null when already at the top (or the
 * current effort is not on the ladder).
 * @param {object} config
 * @param {string|null} family
 * @param {string|null|undefined} current
 * @returns {string|null}
 */
export function nextEffort(config, family, current) {
  const ladder = (family && config.models?.effort_ladder?.[family]) || [];
  const at = ladder.indexOf(current);
  return at >= 0 && at < ladder.length - 1 ? ladder[at + 1] : null;
}

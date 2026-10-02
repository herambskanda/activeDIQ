// Plain, readable terminal output. Colour only on a TTY (and never with NO_COLOR).
const CODES = { bold: '1', dim: '2', red: '31', green: '32', yellow: '33', cyan: '36' };

/**
 * Whether to colour output on a stream.
 * @param {{isTTY?: boolean}} [stream]
 */
export function colorEnabled(stream = process.stdout) {
  return Boolean(stream.isTTY) && !process.env.NO_COLOR;
}

/**
 * Wrap text in an ANSI style when colour is enabled.
 * @param {keyof typeof CODES} style
 * @param {string} text
 * @param {boolean} [enabled]
 */
export function paint(style, text, enabled = colorEnabled()) {
  return enabled ? `\u001b[${CODES[style]}m${text}\u001b[0m` : String(text);
}

/**
 * Align rows into columns (no borders).
 * @param {string[][]} rows
 * @param {string} [indent]
 */
export function table(rows, indent = '  ') {
  if (!rows.length) return '';
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => String(r[i] ?? '').length)));
  return rows.map((r) => indent + r.map((c, i) => (i === r.length - 1 ? String(c ?? '') : String(c ?? '').padEnd(widths[i]))).join('  ').trimEnd()).join('\n');
}

/**
 * Human duration: 4s, 12m 03s, 2h 05m.
 * @param {number} ms
 */
export function duration(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m`;
}

const k = (n) => `${Math.round((n ?? 0) / 1000)}k`;
const short = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));

/**
 * `factory status` as text.
 * @param {ReturnType<typeof import('./status.mjs').buildStatus>} s
 * @param {number} nowMs
 */
export function formatStatus(s, nowMs) {
  const lines = [];
  const state = s.control.paused ? paint('yellow', `PAUSED${s.control.reason ? ` — ${s.control.reason}` : ''}`) : paint('green', 'RUNNING');
  lines.push(`${paint('bold', `${s.product} factory`)} · ${state}`);

  const d = s.dispatcher;
  if (d.alive) {
    lines.push(`dispatcher   alive · heartbeat ${duration(nowMs - Date.parse(d.heartbeat))} ago · pid ${d.pid} · runs today ${d.runs_today.count}/${s.limits.daily_run_cap}`);
  } else {
    lines.push(`dispatcher   ${paint('red', 'not running')}${d.heartbeat ? ` (last heartbeat ${duration(nowMs - Date.parse(d.heartbeat))} ago)` : ''} · runs today ${d.runs_today.count}/${s.limits.daily_run_cap}`);
  }
  if (d.backoff_until) lines.push(`             backing off until ${d.backoff_until}`);
  lines.push(`board        ${s.board ? `${s.board.url} (pid ${s.board.pid})` : paint('dim', 'not running')}`);

  lines.push(`active runs  ${s.active_runs.length ? `(${s.active_runs.length})` : paint('dim', 'none')}`);
  if (s.active_runs.length) {
    lines.push(table(s.active_runs.map((r) => [r.id, r.ticket, r.role, duration(r.elapsed_ms), `ctx ${k(r.context_tokens)}`])));
  }
  lines.push(`tickets      ${Object.entries(s.counts).map(([status, n]) => `${status} ${n}`).join(' · ')}`);

  const needs = [
    ...s.decisions.map((x) => [x.id, x.kind, short(x.title, 70)]),
    ...s.notices.map((x) => [x.id, 'notice', short(x.title, 70)]),
    ...s.actions.map((x) => [x.id, 'action', short(x.title, 70)]),
  ];
  lines.push(`needs you    ${needs.length ? `(${s.decisions.length} decisions · ${s.notices.length} notices · ${s.actions.length} actions)` : paint('dim', 'nothing')}`);
  if (needs.length) lines.push(table(needs));
  lines.push(`digest       ${s.digest.path ?? paint('dim', 'none yet')}`);
  return lines.join('\n');
}

const STATUS_STYLE = { done: 'green', blocked: 'red', cancelled: 'dim', in_progress: 'cyan', review: 'cyan', qa: 'cyan' };

/**
 * One line per ticket.
 * @param {object[]} tickets
 */
export function formatTicketList(tickets) {
  if (!tickets.length) return paint('dim', 'no tickets');
  return table(tickets.map((t) => [t.id, t.priority, paint(STATUS_STYLE[t.status] ?? 'bold', t.status.padEnd(11)), t.type, t.stage_role ?? t.owner, short(t.title, 70)]));
}

/**
 * A ticket in full.
 * @param {object} t
 * @param {object[]} runs runs for this ticket, newest first
 */
export function formatTicket(t, runs = []) {
  const lines = [
    `${paint('bold', t.id)}  ${t.title}`,
    `${t.type} · ${t.priority} · ${paint(STATUS_STYLE[t.status] ?? 'bold', t.status)} · owner ${t.owner}${t.stage_role && t.stage_role !== t.owner ? ` · working: ${t.stage_role}` : ''}`,
  ];
  const meta = [
    t.epic && `epic ${t.epic}`, t.milestone && `milestone ${t.milestone}`,
    t.depends_on?.length && `depends on ${t.depends_on.join(', ')}`, t.decisions?.length && `decisions ${t.decisions.join(', ')}`,
    t.tags?.length && `tags ${t.tags.join(', ')}`, t.parity_refs?.length && `parity ${t.parity_refs.join(', ')}`,
    t.attempts && `attempts ${t.attempts}`, t.effort_override && `effort ${t.effort_override}`,
    t.handoff?.pending && `handoff pending: ${t.handoff.latest}`,
  ].filter(Boolean);
  if (meta.length) lines.push(meta.join(' · '));
  if (t.links?.branch) lines.push(`branch ${t.links.branch}${t.links.worktree ? ` · worktree ${t.links.worktree}` : ''}`);
  if (t.summary) lines.push('', t.summary);
  if (t.body) lines.push('', t.body);
  if (t.acceptance?.length) lines.push('', paint('bold', 'Acceptance'), ...t.acceptance.map((a, i) => `  ${i + 1}. ${a}`));
  if (t.notes?.length) lines.push('', paint('bold', 'Notes'), ...t.notes.slice(-8).map((n) => `  ${n.ts.slice(0, 16)} ${n.by}: ${n.text}`));
  if (runs.length) lines.push('', paint('bold', 'Runs'), table(runs.slice(0, 5).map((r) => [r.id, r.role, r.stage, r.status, `$${(r.cost_usd ?? 0).toFixed(2)}`, r.result_line ?? ''])));
  return lines.join('\n');
}

/**
 * A decision in full.
 * @param {object} d
 */
export function formatDecision(d) {
  const lines = [`${paint('bold', d.id)}  ${d.title}`, `${d.kind} · ${d.status}${d.default_at ? ` · defaults to "${d.default_option}" at ${d.default_at}` : ''}`, '', d.question];
  if (d.context) lines.push('', d.context);
  for (const o of d.options) {
    lines.push('', `  [${o.id}] ${o.label}${d.recommendation === o.id ? paint('green', '  (recommended)') : ''}`);
    if (o.summary) lines.push(`      ${o.summary}`);
    if (o.preview) lines.push(`      preview: ${o.preview}`);
  }
  if (d.rationale) lines.push('', `Why: ${d.rationale}`);
  if (d.blocks?.length) lines.push(`Blocks: ${d.blocks.join(', ')}`);
  if (d.answer) lines.push('', `Answer: ${d.answer.options.join(', ') || '—'}${d.answer.note ? ` — ${d.answer.note}` : ''} (${d.answer.via}, ${d.answer.ts})`);
  return lines.join('\n');
}

/**
 * One line per decision.
 * @param {object[]} decisions
 */
export function formatDecisionList(decisions) {
  if (!decisions.length) return paint('dim', 'no decisions');
  return table(decisions.map((d) => [d.id, d.kind, d.status, short(d.title, 70)]));
}

/**
 * `factory digest` as text.
 * @param {ReturnType<typeof import('./status.mjs').buildDigest>} g
 */
export function formatDigest(g) {
  const list = (items, line) => (items.length ? items.map(line).join('\n') : '  none');
  const t = (x) => `  ${x.id} ${x.priority} ${x.title} (${x.owner})`;
  return [
    paint('bold', `Digest for ${g.date}`),
    `runs today: ${g.runs_today.count} (${g.runs_today.failed} failed) · $${g.runs_today.cost_usd.toFixed(2)}`,
    '', paint('bold', 'Shipped today'), list(g.shipped, (x) => `${t(x)}${x.result ? ` — ${short(x.result, 90)}` : ''}`),
    '', paint('bold', 'In progress'), list(g.in_progress, (x) => `${t(x)} [${x.status}]`),
    '', paint('bold', 'Blocked'), list(g.blocked, (x) => `${t(x)}${x.note ? ` — ${short(x.note, 90)}` : ''}`),
    '', paint('bold', 'At risk'), list(g.at_risk, t),
    '', paint('bold', 'Needs the CEO'),
    list([...g.needs_ceo.decisions, ...g.needs_ceo.actions], (x) => `  ${x.id} ${x.kind ?? 'action'} ${x.title}`),
    `  new feedback: ${g.needs_ceo.feedback_new}`,
  ].join('\n');
}

/**
 * Doctor results, one PASS/WARN/FAIL line each.
 * @param {Array<{level: string, name: string, detail: string}>} checks
 */
export function formatDoctor(checks) {
  const style = { PASS: 'green', WARN: 'yellow', FAIL: 'red' };
  return checks.map((c) => `${paint(style[c.level], c.level)}  ${c.name.padEnd(18)} ${c.detail}`.trimEnd()).join('\n');
}

/**
 * `factory run --dry-run` as text.
 * @param {Awaited<ReturnType<typeof import('./dispatcher.mjs').planDryRun>>} plan
 */
export function formatDryRun(plan) {
  const lines = [];
  lines.push(`checkout: ${plan.shared ? 'shared (no commits yet or isolation none): code tickets run one at a time in the main checkout' : 'worktree per code ticket'}`);
  if (plan.active.length) lines.push(`already running: ${plan.active.map((r) => `${r.ticket} (${r.role})`).join(', ')}`);
  if (plan.defaults.length) lines.push(`advisory defaults due: ${plan.defaults.join(', ')}`);
  if (plan.gate) {
    lines.push(`would launch nothing: ${plan.gate}`);
    return lines.join('\n');
  }
  if (!plan.candidates.length) lines.push('would launch nothing: no free slot or no eligible work');
  for (const c of plan.candidates) {
    const head = `would launch  ${c.ticket ?? '(new meta ticket)'}  ${c.role}  ${c.stage}  [${c.kind}${c.continuation ? ', continuation' : ''}]  ${c.model ?? '?'}·${c.effort ?? '?'}  ${short(c.title, 60)}`;
    lines.push(c.refused.length ? `${paint('red', 'would refuse')}  ${c.ticket ?? '(new meta ticket)'}  ${c.role}: ${c.refused.join('; ')}` : head);
    if (!c.refused.length) lines.push(paint('dim', `              ${c.command.map((a) => (/[\s"'$]/.test(a) ? JSON.stringify(a) : a)).join(' ')}`));
  }
  return lines.join('\n');
}

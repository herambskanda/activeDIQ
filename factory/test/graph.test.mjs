import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { GraphLogReader, buildGraph, windowStart } from '../lib/graph.mjs';
import { appendEvent, putEntity } from '../lib/store.mjs';
import { createTicket } from '../lib/tickets.mjs';
import { createDecision } from '../lib/decisions.mjs';
import { makeFactory, ticketInput, writeAgent } from './helpers.mjs';

const MIN = 60_000;

/** stream-json fixtures */
const usage = (n) => ({ input_tokens: 2, cache_creation_input_tokens: 0, cache_read_input_tokens: n - 2, output_tokens: 5 });
const jl = (...msgs) => `${msgs.map((m) => JSON.stringify(m)).join('\n')}\n`;
const init = (model) => ({ type: 'system', subtype: 'init', model, session_id: 'sess-1' });
const assistant = (ts, content, { parent = null, tokens = 1000, model = 'claude-opus-5-5' } = {}) => ({
  type: 'assistant', parent_tool_use_id: parent, timestamp: new Date(ts).toISOString(),
  message: { model, content, usage: usage(tokens) },
});
const tool = (id, name, input) => ({ type: 'tool_use', id, name, input });
const agentCall = (id, type, description) => tool(id, 'Agent', { subagent_type: type, description, prompt: 'x' });
const toolResult = (ts, id, extra = {}) => ({
  type: 'user', parent_tool_use_id: null, timestamp: new Date(ts).toISOString(),
  message: { content: [{ type: 'tool_result', tool_use_id: id, content: 'ok' }] }, ...extra,
});

function makeRun(f, id, over = {}) {
  const started = over.started ?? new Date(f.clock.ms - 10 * MIN).toISOString();
  const run = {
    id, ticket: null, stage: 'in_progress', role: 'backend-engineer', model: 'sonnet', effort: 'high', pid: 999999,
    session_id: `sess-${id}`, worktree: null, status: 'running', started, ended: null, context_tokens: 0, peak_context_tokens: 0,
    cost_usd: 0, num_turns: 0, result_line: null, last_activity: 'Bash · npm test', continuation: false, snapshot: {}, ...over,
  };
  putEntity(f.ctx, 'runs', run);
  return run;
}

const writeLog = (f, id, text) => fs.appendFileSync(path.join(f.ctx.dir('runs'), `${id}.log`), text);
const writeSession = (f, s) => fs.writeFileSync(path.join(f.ctx.dir('sessions'), `${s.session_id}.json`), JSON.stringify(s));
const node = (g, id) => g.nodes.find((n) => n.id === id);
const edge = (g, kind, from, to) => g.edges.find((e) => e.kind === kind && (!from || e.from === from) && (!to || e.to === to));

test('the log reader reads only appended bytes and survives a torn line', () => {
  const f = makeFactory();
  try {
    const file = path.join(f.ctx.dir('runs'), 'R-1.log');
    const t0 = f.clock.ms;
    const first = jl(init('claude-opus-5-5'), assistant(t0, [agentCall('toolu_a', 'Explore', 'Find things')], { tokens: 5000 }));
    const torn = JSON.stringify(assistant(t0 + 1000, [{ type: 'text', text: 'thinking out loud' }], { tokens: 9000 }));
    fs.writeFileSync(file, first + torn.slice(0, 40));
    const reader = new GraphLogReader();
    let r = reader.read(file);
    assert.equal(r.state.model, 'claude-opus-5-5');
    assert.equal(r.state.context_tokens, 5000);
    assert.equal(r.state.spawns.size, 1);
    const entry = reader.entries.get(file);
    assert.equal(entry.offset, fs.statSync(file).size);

    fs.appendFileSync(file, `${torn.slice(40)}\n{"type":"system","subtype":"thinking_tokens","n":1}\n`);
    const before = entry.offset;
    r = reader.read(file);
    assert.equal(r.state.context_tokens, 9000, 'the completed torn line counts');
    assert.ok(entry.offset > before);
    assert.equal(r.state.turns, 2, 'nothing was parsed twice');

    // no new bytes: same state object, no re-parse
    const sameState = r.state;
    assert.equal(reader.read(file).state, sameState);
    assert.equal(r.state.turns, 2);

    // a replaced (shorter) file starts over
    fs.writeFileSync(file, jl(init('claude-sonnet-5-5')));
    r = reader.read(file);
    assert.equal(r.state.model, 'claude-sonnet-5-5');
    assert.equal(r.state.turns, 0);
    assert.deepEqual(reader.read(path.join(f.ctx.dir('runs'), 'missing.log')).state.spawns.size, 0);
  } finally { f.cleanup(); }
});

test('the scan budget spreads a cold start over several reads', () => {
  const f = makeFactory();
  try {
    const file = path.join(f.ctx.dir('runs'), 'R-1.log');
    fs.writeFileSync(file, jl(init('claude-opus-5-5'), assistant(f.clock.ms, [{ type: 'text', text: 'hi' }], { tokens: 42 })));
    const reader = new GraphLogReader();
    let r = reader.read(file, { budget: { left: 0 } });
    assert.equal(r.complete, false);
    assert.equal(r.state.context_tokens, null);
    r = reader.read(file, { budget: { left: 1e6 } });
    assert.equal(r.complete, true);
    assert.equal(r.state.context_tokens, 42);
  } finally { f.cleanup(); }
});

test('workers: model, effective effort (with mismatch), context state, ticket and subagent attribution', () => {
  const f = makeFactory();
  try {
    writeAgent(path.join(f.root, '.claude', 'agents'), 'Explore', 'sonnet', 'high');
    const ticket = createTicket(f.ctx, ticketInput({ title: 'Filter builder', owner: 'backend-engineer', status: 'ready' }), 'pm');
    const t0 = f.clock.ms - 8 * MIN;
    makeRun(f, 'R-20261002-095000-aaaa', {
      ticket: ticket.id, role: 'backend-engineer', model: 'sonnet', effort: 'high', session_id: 'sess-a', context_tokens: 100000,
      worktree: '/tmp/wt', continuation: true, snapshot: { handoff_latest: '/x/handoffs/T-0001/2026-10-02.md' },
    });
    writeSession(f, { session_id: 'sess-a', kind: 'worker', role: 'backend-engineer', run: 'R-20261002-095000-aaaa', effort: 'xhigh', context_tokens: 100000, budget_tokens: 300000, last_tool: 'Bash' });
    writeLog(f, 'R-20261002-095000-aaaa', jl(
      init('claude-sonnet-5-5'),
      assistant(t0, [agentCall('toolu_sync', 'Explore', 'Where is the filter builder?'), agentCall('toolu_async', 'code-reviewer', 'Review the diff')], { tokens: 216000, model: 'claude-sonnet-5-5' }),
      assistant(t0 + 1000, [tool('tu1', 'Grep', { pattern: 'filter' })], { parent: 'toolu_sync', tokens: 30000, model: 'claude-sonnet-5-5' }),
      assistant(t0 + 2000, [tool('tu2', 'Read', { file_path: '/a/b.ts' })], { parent: 'toolu_sync', tokens: 41000, model: 'claude-sonnet-5-5' }),
      toolResult(t0 + 3000, 'toolu_sync'),
      { type: 'user', parent_tool_use_id: null, timestamp: new Date(t0 + 4000).toISOString(), tool_use_result: { status: 'async_launched', agentId: 'agent-9', resolvedModel: 'claude-sonnet-5-5' }, message: { content: [{ type: 'tool_result', tool_use_id: 'toolu_async', content: 'launched' }] } },
      assistant(t0 + 5000, [tool('tu3', 'Bash', { command: 'git diff' })], { parent: 'toolu_async', tokens: 12000, model: 'claude-sonnet-5-5' }),
      assistant(t0 + 6000, [tool('tu4', 'Edit', { file_path: '/main.ts' })], { tokens: 222000, model: 'claude-sonnet-5-5' }),
    ));

    const g = buildGraph(f.ctx, { window: 'live' });
    const w = node(g, 'run:R-20261002-095000-aaaa');
    assert.equal(w.kind, 'worker');
    assert.equal(w.model, 'sonnet');
    assert.equal(w.model_exact, 'claude-sonnet-5-5');
    assert.equal(w.effort, 'xhigh', 'the session file reports the effective effort');
    assert.equal(w.effort_configured, 'high');
    assert.equal(w.effort_mismatch, true);
    assert.equal(w.policy.ok, true);
    assert.equal(w.context.tokens, 222000, 'subagent usage never counts as the worker context');
    assert.equal(w.context.pct, 74);
    assert.equal(w.context.state, 'checkpoint');
    assert.equal(w.ticket, ticket.id);
    assert.equal(w.ticket_title, 'Filter builder');
    assert.equal(w.group, 'in_progress');
    assert.equal(w.checkout, 'worktree');
    assert.equal(w.continuation, true);
    assert.equal(w.handoff_pending, false);
    assert.equal(w.current_tool, 'Bash · npm test');
    assert.equal(w.subagent_count, 2);
    assert.equal(w.cost_usd, null, 'no cost is invented before the run reports one');
    assert.equal(w.pid_alive, false);
    assert.equal(edge(g, 'launch', 'dispatcher', w.id).label, 'launch · in_progress');
    assert.equal(edge(g, 'launch', 'dispatcher', w.id).active, true);

    const sync = node(g, 'sub:R-20261002-095000-aaaa:toolu_sync');
    assert.equal(sync.label, 'Explore');
    assert.equal(sync.description, 'Where is the filter builder?');
    assert.equal(sync.status, 'finished');
    assert.equal(sync.active, false);
    assert.equal(sync.context.tokens, 41000, 'latest usage among that subagent’s own messages');
    assert.equal(sync.model, 'sonnet');
    assert.equal(sync.effort, 'high');
    assert.equal(sync.builtin, false);
    assert.equal(sync.parent, w.id);
    assert.deepEqual(sync.activity.map((a) => a.text), ['Grep · filter', 'Read · /a/b.ts']);
    assert.equal(edge(g, 'spawn', w.id, sync.id).active, false);
    assert.equal(edge(g, 'spawn', w.id, sync.id).label, 'spawn: Where is the filter builder?');

    const async = node(g, 'sub:R-20261002-095000-aaaa:toolu_async');
    assert.equal(async.status, 'running', 'an async launch is not a completion');
    assert.equal(async.active, true);
    assert.equal(async.current_tool, 'Bash · git diff');
    assert.equal(async.context.tokens, 12000);
    assert.equal(async.builtin, false, 'code-reviewer has an agent file');
    assert.equal(edge(g, 'spawn', w.id, async.id).active, true);

    assert.equal(g.totals.active_workers, 1);
    assert.equal(g.totals.active_subagents, 1);
    assert.equal(g.totals.context_tokens, 222000 + 12000);

    // the notification finishes the async subagent
    writeLog(f, 'R-20261002-095000-aaaa', jl({ type: 'system', subtype: 'task_notification', task_id: 'agent-9', tool_use_id: 'toolu_async', status: 'completed', usage: { total_tokens: 50000 } }));
    assert.equal(node(buildGraph(f.ctx, { window: 'live' }), async.id).status, 'finished');
  } finally { f.cleanup(); }
});

test('a built-in subagent (no agent file) says so; a policy-violating combination is flagged', () => {
  const f = makeFactory();
  try {
    const t0 = f.clock.ms - MIN;
    makeRun(f, 'R-20261002-095100-bbbb', { role: 'qa-verifier', model: 'sonnet', effort: 'medium', session_id: 'sess-b' });
    writeLog(f, 'R-20261002-095100-bbbb', jl(
      init('claude-sonnet-5-5'),
      assistant(t0, [agentCall('toolu_g', 'general-purpose', 'Dig')], { tokens: 1000 }),
      assistant(t0 + 10, [tool('t', 'Bash', { command: 'ls' })], { parent: 'toolu_g', tokens: 500, model: 'claude-sonnet-5-5' }),
    ));
    const g = buildGraph(f.ctx, { window: 'live' });
    const w = node(g, 'run:R-20261002-095100-bbbb');
    assert.equal(w.policy.ok, false);
    assert.match(w.policy.problems[0], /medium/);
    const sub = g.nodes.find((n) => n.kind === 'subagent');
    assert.equal(sub.builtin, true);
    assert.equal(sub.model, 'sonnet');
    assert.equal(sub.model_exact, 'claude-sonnet-5-5');
    assert.equal(sub.effort, null);
  } finally { f.cleanup(); }
});

test('a finished worker with an unfinished subagent shows the subagent as ended, and a handoff run is flagged', () => {
  const f = makeFactory();
  try {
    const t0 = f.clock.ms - 20 * MIN;
    makeRun(f, 'R-20261002-094000-cccc', {
      status: 'handoff', started: new Date(f.clock.ms - 20 * MIN).toISOString(), ended: new Date(f.clock.ms - 5 * MIN).toISOString(), cost_usd: 3.456, num_turns: 40, context_tokens: 80000, peak_context_tokens: 240000,
      result_line: 'RESULT: handoff — half done', last_activity: 'stale',
    });
    writeLog(f, 'R-20261002-094000-cccc', jl(init('claude-sonnet-5-5'), assistant(t0, [agentCall('toolu_x', 'Explore', 'Hanging')], { tokens: 1 })));
    const g = buildGraph(f.ctx, { window: '1h' });
    const w = node(g, 'run:R-20261002-094000-cccc');
    assert.equal(w.active, false);
    assert.equal(w.handoff_pending, true);
    assert.equal(w.cost_usd, 3.46);
    assert.equal(w.context.peak, 240000);
    assert.equal(w.current_tool, null);
    assert.equal(w.elapsed_ms, 15 * MIN);
    const sub = g.nodes.find((n) => n.kind === 'subagent');
    assert.equal(sub.status, 'ended');
    assert.equal(sub.active, false);
    assert.equal(g.totals.cost_usd, 3.46);
    assert.equal(g.totals.active_agents, 0);
  } finally { f.cleanup(); }
});

test('windows keep the runs that overlap them; running runs always stay', () => {
  const f = makeFactory();
  try {
    const at = (minAgo) => new Date(f.clock.ms - minAgo * MIN).toISOString();
    makeRun(f, 'R-20261002-080000-0001', { status: 'done', started: at(130), ended: at(120) }); // 08:00 local clock: 120 min ago
    makeRun(f, 'R-20261002-092000-0002', { status: 'done', started: at(50), ended: at(40) });
    makeRun(f, 'R-20261002-095500-0003', { status: 'done', started: at(9), ended: at(3) });
    makeRun(f, 'R-20261002-090000-0004', { status: 'running', started: at(200) });
    const ids = (w) => buildGraph(f.ctx, { window: w }).nodes.filter((n) => n.kind === 'worker').map((n) => n.run_id).sort();
    assert.deepEqual(ids('live'), ['R-20261002-090000-0004', 'R-20261002-095500-0003']);
    assert.deepEqual(ids('1h'), ['R-20261002-090000-0004', 'R-20261002-092000-0002', 'R-20261002-095500-0003']);
    assert.equal(ids('6h').length, 4);
    assert.equal(ids('bogus').length, 3, 'unknown window falls back to 1h');
    const g = buildGraph(f.ctx, { window: 'today' });
    assert.equal(g.window.name, 'today');
    assert.equal(g.window.since, new Date(2026, 9, 2).toISOString());
    assert.equal(windowStart('6h', new Date(1_000_000_000_000)), 1_000_000_000_000 - 6 * 3_600_000);
  } finally { f.cleanup(); }
});

test('ceo, dispatcher and live directors are always accounted for; stale or ended sessions are not directors', () => {
  const f = makeFactory({ config: (c) => { c.dispatcher.daily_run_cap = 12; } });
  try {
    const ago = (m) => new Date(f.clock.ms - m * MIN).toISOString();
    writeSession(f, { session_id: 'dir-live', kind: 'interactive', role: 'factory-director', effort: 'high', context_tokens: 150000, peak_context_tokens: 160000, budget_tokens: 300000, started: ago(120), updated: ago(1), last_tool: 'Bash · factory status' });
    writeSession(f, { session_id: 'dir-stale', kind: 'interactive', role: 'factory-director', updated: ago(30), started: ago(200) });
    writeSession(f, { session_id: 'dir-ended', kind: 'interactive', role: 'factory-director', updated: ago(1), started: ago(200), ended: true });
    writeSession(f, { session_id: 'wk', kind: 'worker', role: 'backend-engineer', updated: ago(1), started: ago(5) });
    createDecision(f.ctx, { kind: 'directional', title: 'Pick one', question: 'Which?', options: [{ id: 'a', label: 'A', summary: '' }, { id: 'b', label: 'B', summary: '' }] });
    const g = buildGraph(f.ctx, { window: 'live' });
    assert.deepEqual(g.nodes.map((n) => n.kind).sort(), ['ceo', 'director', 'dispatcher']);
    const d = node(g, 'director:dir-live');
    assert.equal(d.effort, 'high');
    assert.equal(d.model, 'opus');
    assert.equal(d.model_source, 'agent definition');
    assert.equal(d.context.pct, 50);
    assert.equal(d.current_tool, 'Bash · factory status');
    assert.equal(node(g, 'ceo').open_decisions[0].title, 'Pick one');
    const disp = node(g, 'dispatcher');
    assert.equal(disp.alive, false, 'no heartbeat yet');
    assert.equal(disp.daily_run_cap, 12);
    assert.equal(disp.paused, false);
    assert.equal(g.totals.active_agents, 1);
    assert.equal(g.totals.active_directors, 1);
  } finally { f.cleanup(); }
});

test('hand-offs, rejections, notes and CEO traffic become aggregated edges between roles', () => {
  const f = makeFactory();
  try {
    const ago = (m) => new Date(f.clock.ms - m * MIN).toISOString();
    writeSession(f, { session_id: 'dir', kind: 'interactive', role: 'factory-director', updated: ago(1), started: ago(100), context_tokens: 1000 });
    const owned = createTicket(f.ctx, ticketInput({ title: 'Owned by dir-eng', owner: 'directory-engineer', status: 'ready' }), 'pm');
    makeRun(f, 'R-20261002-095500-r001', { role: 'backend-engineer', status: 'running' });
    makeRun(f, 'R-20261002-095400-r002', { role: 'code-reviewer', status: 'running', stage: 'review' });
    const ev = (minAgo, actor, kind, ticket, text) => {
      const e = { ts: ago(minAgo), actor, kind, ticket, run: null, text };
      fs.appendFileSync(path.join(f.ctx.dir('events'), `${e.ts.slice(0, 10)}.jsonl`), `${JSON.stringify(e)}\n`);
    };
    fs.mkdirSync(f.ctx.dir('events'), { recursive: true });
    ev(30, 'backend-engineer', 'ticket', 'T-0100', 'T-0100 advanced in_progress → review (code-reviewer): done');
    ev(20, 'backend-engineer', 'ticket', 'T-0101', 'T-0101 advanced in_progress → review (code-reviewer): done');
    ev(10, 'code-reviewer', 'ticket', 'T-0101', 'T-0101 rejected review → in_progress (backend-engineer): fix X');
    ev(9, 'code-reviewer', 'ticket', owned.id, `note on ${owned.id}: heads up`);
    ev(8, 'backend-engineer', 'ticket', 'T-0100', 'T-0100 advanced review → done: merged'); // → done: no recipient role
    ev(7, 'factory-director', 'decision', null, 'directional decision D-0001 opened: Pick one');
    ev(6, 'ceo', 'decision', null, 'D-0001 answered: a — go');
    ev(5, 'dispatcher', 'ticket', 'T-0100', 'T-0100 advanced in_progress → review (code-reviewer): not a role actor');
    ev(500, 'backend-engineer', 'ticket', 'T-0007', 'T-0007 advanced in_progress → review (code-reviewer): out of window');

    const g = buildGraph(f.ctx, { window: '1h' });
    const be = 'run:R-20261002-095500-r001';
    const cr = 'run:R-20261002-095400-r002';
    const adv = edge(g, 'handoff', be, cr);
    assert.equal(adv.count, 2, 'aggregated per role pair, the out-of-window one excluded');
    assert.equal(adv.last_ticket, 'T-0101');
    assert.deepEqual(adv.tickets.sort(), ['T-0100', 'T-0101']);
    assert.equal(adv.label, 'advance ×2 · T-0101');
    const rej = edge(g, 'reject', cr, be);
    assert.equal(rej.count, 1);
    assert.equal(rej.verb, 'reject');
    const note = edge(g, 'note', cr, 'role:directory-engineer');
    assert.equal(note.last_ticket, owned.id);
    assert.ok(node(g, 'role:directory-engineer'), 'a role without a run in the window gets a stub node');
    assert.equal(node(g, 'role:directory-engineer').model, 'sonnet');
    assert.equal(g.edges.filter((e) => e.kind === 'handoff').length, 1, 'no edge for a move to done or by a non-role actor');
    const ask = edge(g, 'ask', 'director:dir', 'ceo');
    assert.equal(ask.verb, 'decision');
    assert.equal(ask.last_ticket, 'D-0001');
    assert.equal(edge(g, 'answer', 'ceo', 'director:dir').verb, 'answer');
    assert.equal(adv.active, false);
    assert.equal(rej.active, false);
  } finally { f.cleanup(); }
});

test('layoutGraph: deterministic columns, no overlap, no director column when none, subagents beside their worker', async () => {
  const { layoutGraph } = await import('../board/public/agents.js');
  const w = (id, group, active = true) => ({ id, kind: 'worker', group, active, run_id: id });
  const g = {
    nodes: [
      { id: 'ceo', kind: 'ceo' }, { id: 'dispatcher', kind: 'dispatcher' },
      w('run:a', 'in_progress'), w('run:b', 'in_progress'), w('run:c', 'review'),
      { id: 'sub:1', kind: 'subagent', parent: 'run:a', started: '2026-10-02T10:00:00Z' },
      { id: 'sub:2', kind: 'subagent', parent: 'run:a', started: '2026-10-02T10:01:00Z' },
    ],
    edges: [],
  };
  const a = layoutGraph(g);
  assert.deepEqual([...a.pos.keys()], [...layoutGraph(g).pos.keys()]);
  assert.ok(!a.columns.some((c) => c.key === 'director'), 'no empty director column');
  assert.deepEqual(a.columns.map((c) => c.key), ['you', 'dispatcher', 'stage:in_progress', 'stage:review', 'sub']);
  const boxes = [...a.pos.values()];
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const p = boxes[i], q = boxes[j];
    const overlap = p.x < q.x + q.w && q.x < p.x + p.w && p.y < q.y + q.h && q.y < p.y + p.h;
    assert.ok(!overlap, `cards ${i} and ${j} overlap`);
  }
  assert.ok(a.pos.get('sub:1').y >= a.pos.get('run:a').y, 'subagents start level with their worker');
});

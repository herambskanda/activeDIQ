// Dispatcher tests. Workers are the fake `claude` in fixtures/ (FACTORY_CLAUDE_BIN), never the real one.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Dispatcher, planDryRun } from '../lib/dispatcher.mjs';
import { buildWorkerArgs, launchWorker, runFiles } from '../lib/launcher.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { createHandoff } from '../lib/handoffs.mjs';
import { createDecision } from '../lib/decisions.mjs';
import { getEntity, listEntities, putEntity, readDispatcherState, readRecentEvents, setControl } from '../lib/store.mjs';
import {
  commitAll, initRepo, makeLiveFactory, readArgsLog, ticketInput, useFakeClaude, waitFor, writeAgent, git,
} from './helpers.mjs';

const texts = (f) => readRecentEvents(f.ctx, 200).map((e) => e.text);
const tickets = (f) => Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));
const runs = (f) => listEntities(f.ctx, 'runs');
const fast = (c) => { c.dispatcher.persist_seconds = 0; c.dispatcher.poll_seconds = 0.05; };

/** Tick until `done()` is true. */
async function drive(f, d, done, what) {
  await waitFor(async () => {
    await d.tick();
    return done();
  }, { timeoutMs: 30000, intervalMs: 60, what });
}

/** Run a body with the fake claude and clean up afterwards, including any workers left running. */
async function withFactory(opts, env, body) {
  const f = makeLiveFactory({ config: (c) => { fast(c); opts?.config?.(c); }, agents: opts?.agents });
  const log = path.join(f.root, 'args.log');
  const restore = useFakeClaude({ FAKE_CLAUDE_ARGS_LOG: log, ...env });
  try {
    await body(f, log);
  } finally {
    restore();
    for (const r of runs(f)) if (r.pid) try { process.kill(r.pid, 'SIGKILL'); } catch { /* already gone */ }
    f.cleanup();
  }
}

test('worker command line: policy-correct flags, always --effort, conditional --mcp-config', () => {
  const f = makeLiveFactory();
  try {
    const base = { config: f.ctx.config, role: 'backend-engineer', prompt: 'do it', ticketId: 'T-0001', root: '/repo' };
    const noEffort = buildWorkerArgs(base);
    assert.ok(!noEffort.includes('--effort'), 'no effort known: nothing passed');
    const plain = buildWorkerArgs({ ...base, agentEffort: 'medium' });
    assert.deepEqual(plain, [
      '-p', 'do it', '--agent', 'backend-engineer', '--effort', 'medium', '--output-format', 'stream-json', '--verbose',
      '--permission-mode', 'auto', '--permission-prompts', 'none', '--autocompact', '300000',
      '--strict-mcp-config', '--name', 'T-0001 · backend-engineer',
    ]);
    assert.ok(!plain.includes('--mcp-config'));
    const escalated = buildWorkerArgs({ ...base, agentEffort: 'medium', effortOverride: 'xhigh' });
    assert.deepEqual(escalated.slice(escalated.indexOf('--effort'), escalated.indexOf('--effort') + 2), ['--effort', 'xhigh']);
    const cfg = { ...f.ctx.config, dispatcher: { ...f.ctx.config.dispatcher, mcp_configs: { 'qa-verifier': 'factory/mcp/qa.json' } } };
    const qa = buildWorkerArgs({ ...base, config: cfg, role: 'qa-verifier', agentEffort: 'high' });
    assert.deepEqual(qa.slice(qa.indexOf('--mcp-config') - 1, qa.indexOf('--mcp-config') + 2), ['--strict-mcp-config', '--mcp-config', '/repo/factory/mcp/qa.json']);
    assert.ok(!buildWorkerArgs({ ...base, config: cfg }).includes('--mcp-config'), 'only roles with a configured file');
  } finally { f.cleanup(); }
});

test('launchWorker captures stdout and stderr, passes the environment, and reports the exit', async () => {
  await withFactory({}, { FAKE_CLAUDE_MODE: 'noop' }, async (f, log) => {
    let exit;
    const { pid } = launchWorker(f.ctx, { runId: 'R-test-1', ticketId: 'T-0001', role: 'backend-engineer', prompt: 'hello', cwd: f.root }, (e) => { exit = e; });
    assert.ok(pid > 0);
    await waitFor(() => exit, { what: 'worker exit' });
    assert.deepEqual([exit.code, exit.signal], [0, null]);
    const stdout = fs.readFileSync(runFiles(f.ctx, 'R-test-1').log, 'utf8');
    assert.match(stdout, /"type":"result"/);
    const [call] = readArgsLog(log);
    assert.deepEqual([call.role, call.ticket, call.run, call.cwd], ['backend-engineer', 'T-0001', 'R-test-1', f.root]);
    assert.equal(call.args[0], '-p');
    assert.equal(call.args[1], 'hello');
  });
});

test('launchWorker throws a clear error when claude cannot be started', () => {
  const f = makeLiveFactory();
  const restore = useFakeClaude({ FACTORY_CLAUDE_BIN: path.join(f.root, 'no-such-claude') });
  try {
    assert.throws(() => launchWorker(f.ctx, { runId: 'R-x', ticketId: 'T-0001', role: 'r', prompt: 'p', cwd: f.root }, () => {}), /could not start/);
  } finally { restore(); f.cleanup(); }
});

test('a worker that advances its ticket: run recorded, ticket moves, daily counter, events', async () => {
  await withFactory({}, {}, async (f, log) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'meta', owner: 'project-manager', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await drive(f, d, () => tickets(f)[t.id].status === 'done' && runs(f).every((r) => r.status !== 'running'), 'the worker to finish');
    await d.tick();
    const [run] = runs(f);
    assert.equal(runs(f).length, 1);
    assert.deepEqual([run.status, run.role, run.stage, run.model, run.effort], ['done', 'project-manager', 'in_progress', 'opus', 'medium']);
    assert.equal(run.exit_code, 0);
    assert.equal(run.result_line, 'RESULT: advanced — fake advance');
    assert.equal(run.cost_usd, 0.07);
    assert.equal(run.peak_context_tokens, 8151);
    assert.match(run.session_id, /^sess-R-/);
    assert.ok(run.ended);
    const [call] = readArgsLog(log);
    assert.equal(call.cwd, f.root, 'no repo: shared checkout');
    assert.ok(call.args.includes('--strict-mcp-config'));
    assert.deepEqual(call.args.slice(call.args.indexOf('--effort'), call.args.indexOf('--effort') + 2), ['--effort', 'medium'], 'frontmatter effort always passed');
    assert.deepEqual(call.args.slice(call.args.indexOf('--agent'), call.args.indexOf('--agent') + 2), ['--agent', 'project-manager']);
    assert.match(call.args[1], /ticket \*\*T-0001/);
    assert.match(call.args[1], /Stage: meta work/);
    assert.equal(readDispatcherState(f.ctx).runs_today.count, 1);
    assert.equal(tickets(f)[t.id].result, 'advance by fake claude');
    assert.ok(texts(f).some((x) => /done: T-0001 as project-manager · 3 turns · \$0\.07 · ctx 8k/.test(x)));
  });
});

test('a ticket runs through every stage with the right role at each stage', async () => {
  await withFactory({}, {}, async (f, log) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await drive(f, d, () => tickets(f)[t.id].status === 'done', 'docs ticket to finish');
    assert.deepEqual(readArgsLog(log).map((c) => c.role), ['docs-writer', 'product-manager']);
    assert.equal(tickets(f)[t.id].result, 'advance by fake claude');
  });
});

test('a rejecting reviewer sends the ticket back to the owner', async () => {
  await withFactory({}, { FAKE_CLAUDE_MODE: 'reject' }, async (f) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    claimTicket(f.ctx, t.id);
    advanceTicket(f.ctx, t.id, 'docs-writer', 'drafted');
    const d = new Dispatcher(f.ctx);
    const review = () => runs(f).find((r) => r.role === 'product-manager');
    await drive(f, d, () => review()?.status === 'done', 'the review to finish');
    const after = tickets(f)[t.id];
    assert.deepEqual([after.status, after.stage_role], ['in_progress', 'docs-writer']);
    assert.ok(after.notes.some((n) => n.text === 'rejected: reject by fake claude'));
    assert.equal(after.attempts, 0, 'a rejection is progress, not a failed attempt');
  });
});

test('a worker that does nothing is retried, then escalated: effort first, then the escalation role', async () => {
  await withFactory({}, { FAKE_CLAUDE_MODE: 'noop' }, async (f, log) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await drive(f, d, () => tickets(f)[t.id].stage_role === 'principal-engineer', 'reassignment to the escalation role');
    await waitFor(() => readArgsLog(log).length >= 4, { what: 'four worker starts' });
    const effort = (c) => (c.args.includes('--effort') ? c.args[c.args.indexOf('--effort') + 1] : null);
    assert.deepEqual(readArgsLog(log).slice(0, 4).map((c) => [c.role, effort(c)]), [
      ['docs-writer', 'high'], ['docs-writer', 'high'], ['docs-writer', 'xhigh'], ['docs-writer', 'xhigh'],
    ]);
    const after = tickets(f)[t.id];
    assert.deepEqual([after.reassigned_from, after.escalations, after.effort_override], ['docs-writer', 2, null]);
    const events = texts(f).join('\n');
    assert.match(events, /escalated, effort raised to xhigh/);
    assert.match(events, /escalated, stage reassigned to principal-engineer/);
  });
});

test('a usage-limit failure backs the whole dispatcher off and does not count against the ticket', async () => {
  await withFactory({}, { FAKE_CLAUDE_MODE: 'ratelimit' }, async (f) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await drive(f, d, () => runs(f).length === 1 && runs(f)[0].status === 'failed', 'rate-limited run');
    const until = readDispatcherState(f.ctx).backoff_until;
    assert.ok(until && Date.parse(until) > Date.now() + 14 * 60_000, `backoff_until=${until}`);
    assert.equal(tickets(f)[t.id].attempts, 0);
    assert.match(texts(f).join('\n'), /usage limit hit, backing off until/);
    await d.tick();
    assert.equal(runs(f).length, 1, 'nothing launches while backing off');
  });
});

function writeSignal(f, signal) {
  const dir = path.join(f.ctx.stateDir, 'signals');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'rate-limit.json'), JSON.stringify(signal));
}

test('a fresh rate-limit signal from the StopFailure hook backs the dispatcher off, and says so once', async () => {
  await withFactory({}, {}, async (f) => {
    createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    writeSignal(f, { ts: new Date().toISOString(), type: 'rate_limit', session: null, role: 'backend-engineer' });
    const d = new Dispatcher(f.ctx);
    await d.tick();
    await d.tick();
    const until = readDispatcherState(f.ctx).backoff_until;
    assert.ok(Date.parse(until) > Date.now() + 14 * 60_000, `backoff_until=${until}`);
    assert.equal(runs(f).length, 0, 'nothing launches while backing off');
    assert.equal(texts(f).filter((x) => /usage limit reported by backend-engineer \(rate_limit\)/.test(x)).length, 1);
  });
});

test('a rate-limit signal older than the backoff window is ignored', async () => {
  await withFactory({}, {}, async (f) => {
    createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    writeSignal(f, { ts: new Date(Date.now() - 3_600_000).toISOString(), type: 'rate_limit', session: null, role: 'ceo' });
    await new Dispatcher(f.ctx).tick();
    assert.equal(readDispatcherState(f.ctx).backoff_until, null);
    assert.equal(runs(f).length, 1);
  });
});

test('a run whose session matches the rate-limit signal is not counted as a failed attempt', async () => {
  await withFactory({}, { FAKE_CLAUDE_MODE: 'hang' }, async (f) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await d.tick();
    await drive(f, d, () => runs(f)[0]?.session_id, 'the session id to be recorded');
    const [run] = runs(f);
    writeSignal(f, { ts: new Date().toISOString(), type: 'rate_limit', session: run.session_id, role: 'docs-writer' });
    process.kill(run.pid, 'SIGKILL');
    await drive(f, d, () => getEntity(f.ctx, 'runs', run.id).status !== 'running', 'the run to be reaped');
    assert.equal(tickets(f)[t.id].attempts, 0);
    assert.match(texts(f).join('\n'), /failed: T-0001 as docs-writer.*usage limit hit, backing off/);
  });
});

test('paused: nothing launches; resuming launches', async () => {
  await withFactory({}, {}, async (f) => {
    createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    setControl(f.ctx, { paused: true, reason: 'test' });
    const d = new Dispatcher(f.ctx);
    await d.tick();
    assert.equal(runs(f).length, 0);
    assert.match(readDispatcherState(f.ctx).last_action, /idle: paused/);
    setControl(f.ctx, { paused: false });
    await d.tick();
    assert.equal(runs(f).length, 1);
  });
});

test('max_parallel and the daily cap are enforced', async () => {
  await withFactory({ config: (c) => { c.dispatcher.max_parallel = 1; c.dispatcher.daily_run_cap = 1; } }, { FAKE_CLAUDE_MODE: 'hang' }, async (f) => {
    for (let i = 0; i < 3; i++) createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await d.tick();
    await d.tick();
    assert.equal(runs(f).length, 1, 'one slot');
    for (const r of runs(f)) process.kill(r.pid, 'SIGKILL');
    await drive(f, d, () => runs(f).every((r) => r.status !== 'running'), 'the hung worker to be reaped');
    await d.tick();
    assert.equal(runs(f).length, 1, 'the daily cap of 1 is reached');
    assert.match(readDispatcherState(f.ctx).last_action, /daily run cap reached/);
  });
});

test('live context usage is persisted while a worker runs', async () => {
  await withFactory({}, { FAKE_CLAUDE_MODE: 'hang' }, async (f) => {
    createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await d.tick();
    await drive(f, d, () => runs(f)[0]?.context_tokens > 0, 'context to be recorded');
    const [run] = runs(f);
    assert.deepEqual([run.status, run.context_tokens, run.peak_context_tokens], ['running', 8151, 8151]);
    assert.match(run.last_activity, /^Bash · ls -la$/);
    assert.match(run.session_id, /^sess-R-/);
  });
});

test('a run past run_timeout_minutes gets SIGTERM, then SIGKILL if it ignores it', async () => {
  const cfg = (c) => { c.dispatcher.run_timeout_minutes = 0.01; c.dispatcher.kill_grace_seconds = 0.3; };
  await withFactory({ config: cfg }, { FAKE_CLAUDE_MODE: 'hang', FAKE_IGNORE_TERM: '1' }, async (f) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await drive(f, d, () => runs(f)[0]?.status === 'killed', 'the timeout kill');
    const [run] = runs(f);
    assert.equal(run.kill_reason, 'timeout');
    const log = texts(f).join('\n');
    assert.match(log, /timeout: sent SIGTERM/);
    assert.match(log, /ignored SIGTERM; sent SIGKILL/);
    assert.equal(tickets(f)[t.id].status, 'in_progress');
  });
});

test('shutdown gives workers their grace, then terminates them; tickets stay in their stage', async () => {
  const cfg = (c) => { c.dispatcher.shutdown_grace_seconds = 0.3; c.dispatcher.kill_grace_seconds = 0.3; };
  await withFactory({ config: cfg }, { FAKE_CLAUDE_MODE: 'hang' }, async (f) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await d.tick();
    await waitFor(() => runs(f)[0]?.pid, { what: 'worker pid' });
    d.stopping = true;
    await d.shutdown();
    const [run] = runs(f);
    assert.deepEqual([run.status, run.kill_reason], ['killed', 'shutdown']);
    const after = tickets(f)[t.id];
    assert.deepEqual([after.status, after.stage_role, after.attempts], ['in_progress', 'docs-writer', 0], 'no escalation for a shutdown');
    assert.match(texts(f).join('\n'), /stopping: giving 1 running worker/);
  });
});

test('a restarted dispatcher adopts workers that are still running, and reaps them when they end', async () => {
  await withFactory({}, { FAKE_CLAUDE_MODE: 'hang' }, async (f) => {
    createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    await new Dispatcher(f.ctx).tick();
    const [started] = runs(f);
    assert.equal(started.status, 'running');

    const second = new Dispatcher(f.ctx);
    await second.tick();
    assert.deepEqual([...second.active.keys()], [started.id]);
    assert.equal(runs(f).length, 1, 'adopted, not relaunched');

    process.kill(started.pid, 'SIGKILL');
    await drive(f, second, () => getEntity(f.ctx, 'runs', started.id).status !== 'running', 'the adopted run to be reaped');
    assert.equal(getEntity(f.ctx, 'runs', started.id).status, 'failed');
  });
});

test('a policy violation or a missing agent refuses the launch once, leaves the ticket ready, and keeps going', async () => {
  await withFactory({}, {}, async (f) => {
    writeAgent(f.ctx.agentsDir, 'docs-writer', 'opus', 'xhigh');
    fs.rmSync(path.join(f.ctx.agentsDir, 'test-engineer.md'));
    const bad = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready', priority: 'P0' }), 'x');
    const missing = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'test-engineer', status: 'ready', priority: 'P1' }), 'x');
    const good = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'backend-engineer', status: 'ready', priority: 'P2' }), 'x');
    const d = new Dispatcher(f.ctx);
    await d.tick();
    await d.tick();
    assert.equal(tickets(f)[bad.id].status, 'ready');
    assert.equal(tickets(f)[missing.id].status, 'ready');
    assert.equal(runs(f).filter((r) => r.ticket === good.id).length, 1);
    const refusals = texts(f).filter((x) => x.startsWith('refused to launch'));
    assert.equal(refusals.length, 2, 'reported once each, not every tick');
    assert.ok(refusals.some((x) => /docs-writer.*escalation-only/.test(x)));
    assert.ok(refusals.some((x) => /no agent definition for "test-engineer"/.test(x)));
  });
});

test('a worker that cannot be spawned backs off without counting an attempt', async () => {
  await withFactory({}, { FACTORY_CLAUDE_BIN: '/nonexistent/claude' }, async (f) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await d.tick();
    const [run] = runs(f);
    assert.equal(run.status, 'failed');
    assert.match(run.error, /could not start/);
    assert.ok(Date.parse(readDispatcherState(f.ctx).backoff_until) > Date.now());
    assert.equal(tickets(f)[t.id].attempts, 0);
    assert.match(texts(f).join('\n'), /could not start.*backing off 5 min/);
  });
});

test('a corrupt state file is reported once and does not stop work', async () => {
  await withFactory({}, {}, async (f) => {
    fs.writeFileSync(path.join(f.ctx.dir('tickets'), 'T-0777.json'), '{"id": "T-0777", ');
    createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await d.tick();
    await d.tick();
    assert.equal(runs(f).length, 1);
    assert.equal(texts(f).filter((x) => /ignoring unreadable state file.*T-0777/.test(x)).length, 1);
  });
});

test('a broken config.json keeps the previous config and says so once', async () => {
  await withFactory({}, {}, async (f) => {
    const d = new Dispatcher(f.ctx);
    fs.writeFileSync(path.join(f.home, 'config.json'), '{ broken');
    await d.tick();
    await d.tick();
    assert.equal(texts(f).filter((x) => /config\.json unreadable, keeping the previous one/.test(x)).length, 1);
    assert.ok(f.ctx.config.dispatcher, 'previous config still in use');
  });
});

test('advisory defaults are applied on the tick', async () => {
  await withFactory({}, {}, async (f) => {
    createDecision(f.ctx, { kind: 'advisory', title: 't', question: 'q', options: [{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }], default_option: 'a', default_in_hours: 0.0001 });
    await new Promise((r) => setTimeout(r, 400));
    await new Dispatcher(f.ctx).tick();
    assert.equal(getEntity(f.ctx, 'decisions', 'D-0001').status, 'defaulted');
  });
});

test('auto-created triage ticket is launched for an answered decision', async () => {
  await withFactory({}, { FAKE_CLAUDE_MODE: 'hang' }, async (f, log) => {
    putEntity(f.ctx, 'decisions', { id: 'D-0001', kind: 'directional', title: 'q', status: 'answered', applied: false, options: [], answer: { options: ['a'] }, created: new Date().toISOString() });
    const d = new Dispatcher(f.ctx);
    await d.tick();
    const meta = Object.values(tickets(f)).filter((t) => t.type === 'meta');
    assert.equal(meta.length, 1);
    assert.deepEqual([meta[0].owner, meta[0].status, meta[0].tags, meta[0].priority], ['factory-director', 'in_progress', ['triage'], 'P0']);
    await waitFor(() => readArgsLog(log).length === 1, { what: 'triage worker' });
    assert.match(readArgsLog(log)[0].args[1], /Stage: triage\. Process exactly these items/);
    await d.tick();
    assert.equal(Object.values(tickets(f)).filter((t) => t.type === 'meta').length, 1, 'never a second open triage');
  });
});

test('a handoff continuation is launched first, with the handoff in the prompt', async () => {
  await withFactory({}, { FAKE_CLAUDE_MODE: 'hang' }, async (f, log) => {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    claimTicket(f.ctx, t.id);
    const file = createHandoff(f.ctx, t.id, 'docs-writer');
    createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready', priority: 'P0' }), 'x');
    const d = new Dispatcher(f.ctx);
    await d.tick();
    await waitFor(() => readArgsLog(log).length >= 1, { what: 'worker start' });
    const first = readArgsLog(log).find((c) => c.ticket === t.id);
    assert.ok(first, 'the continuation ticket launched despite the P0 ready ticket');
    assert.match(first.args[1], /This is a continuation/);
    assert.ok(first.args[1].includes(file));
    assert.equal(runs(f).find((r) => r.ticket === t.id).continuation, true);
  });
});

test('code tickets run in their own worktree, flow to done, and are merged and cleaned up', async () => {
  await withFactory({}, { FAKE_CLAUDE_COMMIT: 'feature.txt', FAKE_CLAUDE_COMMIT_ROLE: 'backend-engineer' }, async (f, log) => {
    initRepo(f.root);
    const t = createTicket(f.ctx, ticketInput({ status: 'ready' }), 'x');
    const d = new Dispatcher(f.ctx);
    await drive(f, d, () => tickets(f)[t.id].status === 'done' && tickets(f)[t.id].links.merged, 'merge');

    const calls = readArgsLog(log);
    assert.deepEqual(calls.map((c) => c.role), ['backend-engineer', 'code-reviewer', 'qa-verifier']);
    const worktree = path.join(f.root, '.worktrees', t.id);
    assert.ok(calls.every((c) => c.cwd === worktree), 'every stage works in the ticket worktree');
    assert.ok(runs(f).every((r) => r.worktree === worktree));

    assert.equal(fs.readFileSync(path.join(f.root, 'feature.txt'), 'utf8'), 'T-0001 by backend-engineer\n');
    assert.match(git(f.root, 'log', '-1', '--format=%s'), /^Merge T-0001: A ticket$/);
    assert.equal(fs.existsSync(worktree), false);
    assert.equal(git(f.root, 'branch', '--list', 'factory/T-0001'), '');
    const after = tickets(f)[t.id];
    assert.deepEqual([after.links.worktree, after.links.branch], [null, 'factory/T-0001']);
    assert.match(after.links.merge_commit, /^[0-9a-f]{40}$/);
    assert.match(texts(f).join('\n'), /T-0001 merged into main/);
  });
});

test('a merge conflict reopens the ticket for its owner and leaves main clean', async () => {
  await withFactory({}, {}, async (f) => {
    initRepo(f.root);
    fs.writeFileSync(path.join(f.root, 'shared.txt'), 'base\n');
    commitAll(f.root, 'base');
    const finish = async (title, text) => {
      const t = createTicket(f.ctx, ticketInput({ title, status: 'ready' }), 'x');
      const wt = await ensureWorktree(f.ctx, t.id);
      fs.writeFileSync(path.join(wt.path, 'shared.txt'), text);
      commitAll(wt.path, `work ${t.id}`);
      claimTicket(f.ctx, t.id);
      for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
      setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
      return t;
    };
    const a = await finish('a', 'from A\n');
    const b = await finish('b', 'from B\n');
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    await d.mergePass();
    const out = tickets(f);
    assert.equal(out[a.id].status, 'done');
    assert.ok(out[a.id].links.merged);
    assert.deepEqual([out[b.id].status, out[b.id].stage_role], ['in_progress', 'backend-engineer']);
    assert.match(out[b.id].notes.at(-1).text, /conflicted/);
    assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '');
    assert.equal(fs.readFileSync(path.join(f.root, 'shared.txt'), 'utf8'), 'from A\n');
  });
});

test('dry run reports gate, candidates, models and commands without changing anything', async () => {
  const f = makeLiveFactory();
  try {
    const t = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready' }), 'x');
    const before = JSON.stringify(getEntity(f.ctx, 'tickets', t.id));
    const plan = await planDryRun(f.ctx);
    assert.equal(plan.gate, null);
    assert.equal(plan.shared, true);
    const [c] = plan.candidates;
    assert.deepEqual([c.ticket, c.role, c.model, c.effort, c.stage, c.refused], [t.id, 'docs-writer', 'sonnet', 'high', 'in_progress', []]);
    assert.equal(c.command[0], 'claude');
    assert.ok(c.command.includes('--strict-mcp-config'));
    assert.equal(JSON.stringify(getEntity(f.ctx, 'tickets', t.id)), before);
    assert.equal(runs(f).length, 0);
  } finally { f.cleanup(); }
});

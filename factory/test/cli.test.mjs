import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { runCli } from '../lib/cli.mjs';
import { getEntity, listEntities, putEntity } from '../lib/store.mjs';
import { claimTicket } from '../lib/tickets.mjs';
import { FACTORY_BIN, git, initRepo, makeLiveFactory, useFakeClaude, waitFor } from './helpers.mjs';

const exec = promisify(execFile);

/** A CLI session against a throw-away factory. */
function session(opts) {
  const f = makeLiveFactory(opts);
  const run = async (args, env = {}) => {
    const out = [];
    const err = [];
    const code = await runCli(args, {
      out: (s) => out.push(s), err: (s) => err.push(s), env: { FACTORY_HOME: f.home, ...env }, cwd: f.root,
    });
    return { code, out: out.join('\n'), err: err.join('\n') };
  };
  const json = async (args, env) => {
    const r = await run([...args, '--json'], env);
    assert.equal(r.code, 0, `${args.join(' ')} → ${r.err}`);
    return JSON.parse(r.out);
  };
  return { ...f, run, json };
}

const listIds = (ctx) => listEntities(ctx, 'tickets').map((t) => t.id).sort().join(',');

const NEW_TICKET = ['ticket', 'new', '--title', 'LDAP filter builder', '--type', 'build', '--owner', 'backend-engineer', '--summary', 'Build it.', '--ac', 'Given a, when b, then c.'];

test('help and usage errors: exit 0 for help, 2 for misuse, 1 for runtime failures', async () => {
  const s = session();
  try {
    for (const args of [[], ['help'], ['--help']]) {
      const r = await s.run(args);
      assert.equal(r.code, 0);
      assert.match(r.out, /usage: factory <command>/);
    }
    const unknown = await s.run(['frobnicate']);
    assert.deepEqual([unknown.code, /unknown command "frobnicate"/.test(unknown.err)], [2, true]);
    assert.equal((await s.run(['ticket', 'frob'])).code, 2);
    assert.equal((await s.run(['ticket'])).code, 2);
    assert.equal((await s.run(['ticket', 'show'])).code, 2, 'an ID is required');
    assert.equal((await s.run(['ticket', 'new', '--title', 'x'])).code, 2, 'missing --type');
    assert.equal((await s.run(['ticket', 'list', '--bogus'])).code, 2, 'unknown flag');
    assert.equal((await s.run(['ticket', 'advance', 'T-0001'])).code, 2, 'missing --note');
    assert.equal((await s.run(['event', '--actor', 'a', '--kind', 'nonsense', 'text'])).code, 2);
    const missing = await s.run(['ticket', 'show', 'T-0404']);
    assert.equal(missing.code, 1);
    assert.match(missing.err, /^error: ticket T-0404 not found/);
  } finally { s.cleanup(); }
});

test('ticket lifecycle through the CLI, with --json', async () => {
  const s = session();
  try {
    const created = await s.json(NEW_TICKET);
    assert.deepEqual([created.id, created.status, created.priority], ['T-0001', 'backlog', 'P2']);
    assert.equal((await s.run(['ticket', 'ready', 'T-0001'])).code, 0);
    assert.equal(getEntity(s.ctx, 'tickets', 'T-0001').status, 'ready');

    const listed = await s.json(['ticket', 'list', '--status', 'ready']);
    assert.deepEqual(listed.map((t) => t.id), ['T-0001']);
    assert.deepEqual(await s.json(['ticket', 'list', '--owner', 'nobody']), []);

    const text = await s.run(['ticket', 'list']);
    assert.match(text.out, /T-0001\s+P2\s+ready\s+build\s+backend-engineer\s+LDAP filter builder/);

    await s.run(['ticket', 'set', 'T-0001', 'priority=P0', 'tags=a,b']);
    const shown = await s.json(['ticket', 'show', 'T-0001']);
    assert.deepEqual([shown.priority, shown.tags, shown.runs], ['P0', ['a', 'b'], []]);
    assert.match((await s.run(['ticket', 'show', 'T-0001'])).out, /LDAP filter builder/);
    assert.equal((await s.run(['ticket', 'set', 'T-0001'])).code, 2, 'nothing to set');
    assert.equal((await s.run(['ticket', 'set', 'T-0001', 'noequals'])).code, 2);

    const noted = await s.run(['ticket', 'note', 'T-0001', '--by', 'qa-verifier', 'looks', 'fine']);
    assert.equal(noted.code, 0);
    assert.equal(getEntity(s.ctx, 'tickets', 'T-0001').notes.at(-1).text, 'looks fine');
  } finally { s.cleanup(); }
});

test('--by falls back to FACTORY_ROLE, as set in a worker session', async () => {
  const s = session();
  try {
    await s.run(NEW_TICKET);
    await s.run(['ticket', 'ready', 'T-0001']);
    claimTicket(s.ctx, 'T-0001');
    assert.equal((await s.run(['ticket', 'advance', 'T-0001', '--note', 'done'])).code, 2, 'no --by and no FACTORY_ROLE');
    const ok = await s.run(['ticket', 'advance', 'T-0001', '--note', 'implemented'], { FACTORY_ROLE: 'backend-engineer' });
    assert.equal(ok.code, 0);
    assert.match(ok.out, /T-0001 advanced: now review \(code-reviewer\)/);
    assert.equal(getEntity(s.ctx, 'tickets', 'T-0001').history.at(-1).by, 'backend-engineer');
  } finally { s.cleanup(); }
});

test('ticket ready refuses an incomplete ticket with exit 1 and a reason', async () => {
  const s = session();
  try {
    await s.run(['ticket', 'new', '--title', 'Bare', '--type', 'build', '--owner', 'backend-engineer']);
    const r = await s.run(['ticket', 'ready', 'T-0001']);
    assert.equal(r.code, 1);
    assert.match(r.err, /missing at least one acceptance criterion, summary/);
    const direct = await s.run(['ticket', 'new', '--title', 'Bare2', '--type', 'build', '--owner', 'x', '--status', 'ready']);
    assert.equal(direct.code, 1);
  } finally { s.cleanup(); }
});

test('decisions through the CLI: options, blocks, limit, answer, applied', async () => {
  const s = session();
  try {
    await s.run(NEW_TICKET);
    const base = ['decision', 'new', '--kind', 'directional', '--title', 'Stack?', '--question', 'Which?', '--option', 'a|Go|fast', '--option', 'b|Rust|safe', '--recommend', 'a'];
    const created = await s.json([...base, '--blocks', 'T-0001']);
    assert.deepEqual([created.id, created.options.map((o) => o.label), created.recommendation], ['D-0001', ['Go', 'Rust'], 'a']);
    assert.deepEqual(getEntity(s.ctx, 'tickets', 'T-0001').decisions, ['D-0001']);

    await s.run([...base, '--title', 'Second']);
    await s.run([...base, '--title', 'Third']);
    const over = await s.run([...base, '--title', 'Fourth']);
    assert.equal(over.code, 1);
    assert.match(over.err, /3 CEO decisions are already open/);
    assert.equal((await s.run([...base, '--title', 'Fourth', '--force'])).code, 0);

    const adv = await s.json(['decision', 'new', '--kind', 'advisory', '--title', 'Tone', '--question', 'q', '--option', 'a|A', '--option', 'b|B', '--default', 'b', '--default-in', '24h', '--force']);
    assert.equal(adv.default_option, 'b');
    assert.equal(Math.round((Date.parse(adv.default_at) - Date.parse(adv.created)) / 3_600_000), 24);
    assert.equal((await s.run([...base, '--default-in', '3 days', '--kind', 'advisory', '--force'])).code, 1, 'bad duration');

    assert.equal((await s.run(['decision', 'answer', 'D-0001', '--option', 'zzz'])).code, 1);
    assert.equal((await s.run(['decision', 'answer', 'D-0001'])).code, 2, '--option is required');
    const answered = await s.json(['decision', 'answer', 'D-0001', '--option', 'a', '--note', 'ship it']);
    assert.deepEqual([answered.status, answered.answer.options, answered.answer.via], ['answered', ['a'], 'cli']);
    assert.equal((await s.json(['decision', 'applied', 'D-0001', '--by', 'factory-director'])).applied, true);
    assert.equal((await s.json(['decision', 'list', '--status', 'answered'])).length, 1);
    assert.match((await s.run(['decision', 'show', 'D-0001'])).out, /Stack\?/);
    assert.equal((await s.run(['decision', 'withdraw', 'D-0002', '--by', 'fd'])).code, 2, '--note is required');
    assert.equal((await s.run(['decision', 'withdraw', 'D-0002', '--by', 'fd', '--note', 'moot'])).code, 0);
  } finally { s.cleanup(); }
});

test('actions, feedback, epics, milestones, events, handoffs', async () => {
  const s = session();
  try {
    assert.equal((await s.json(['action', 'new', '--title', 'Create tenant', '--why', 'needed'])).id, 'A-0001');
    assert.equal((await s.json(['action', 'done', 'A-0001', '--note', 'ok'])).status, 'done');
    assert.equal((await s.run(['action', 'done', 'A-0001'])).code, 1, 'already done');

    const m = await s.json(['milestone', 'new', '--name', 'First demo', '--goal', 'g']);
    assert.equal(m.id, 'M1');
    const e = await s.json(['epic', 'new', '--title', 'Core', '--milestone', 'M1', '--parity', 'ADM-1,ADM-2']);
    assert.deepEqual([e.id, e.milestone, e.parity_refs], ['E-001', 'M1', ['ADM-1', 'ADM-2']]);
    assert.equal((await s.json(['milestone', 'set', 'M1', 'status=active'])).status, 'active');
    assert.equal((await s.run(['milestone', 'set', 'M1', 'status=bogus'])).code, 1);
    assert.match((await s.run(['epic', 'list'])).out, /E-001\s+\S+\s+M1\s+Core/);

    await s.run(NEW_TICKET);
    const fb = await s.json(['feedback', 'new', '--target', 'ticket:T-0001', '--text', 'Rename it', '--sentiment', 'change']);
    assert.deepEqual([fb.id, fb.status], ['F-0001', 'new']);
    assert.equal((await s.run(['feedback', 'new', '--target', 'bogus', '--text', 'x'])).code, 1);
    const triaged = await s.json(['feedback', 'triage', 'F-0001', '--note', 'ticketed', '--tickets', 'T-0001', '--by', 'factory-director']);
    assert.deepEqual([triaged.status, triaged.tickets], ['triaged', ['T-0001']]);
    assert.equal((await s.json(['feedback', 'new', '--target', 'general', '--text', 'ok'])).id, 'F-0002');
    assert.equal((await s.json(['feedback', 'triage', 'F-0002', '--note', 'noted', '--done', '--by', 'fd'])).status, 'done');

    const ev = await s.json(['event', '--actor', 'backend-engineer', '--kind', 'tool', '--ticket', 'T-0001', 'ran', 'the', 'tests']);
    assert.deepEqual([ev.actor, ev.kind, ev.ticket, ev.text], ['backend-engineer', 'tool', 'T-0001', 'ran the tests']);

    const handoff = await s.json(['handoff', 'new', 'T-0001', '--by', 'backend-engineer']);
    assert.ok(fs.existsSync(handoff.path));
    assert.match(fs.readFileSync(handoff.path, 'utf8'), /# Handoff — T-0001: LDAP filter builder/);
    assert.equal((await s.json(['handoff', 'latest', 'T-0001'])).path, handoff.path);
    assert.equal(getEntity(s.ctx, 'tickets', 'T-0001').handoff.pending, true);
    assert.equal((await s.run(['handoff', 'latest', 'T-0002'])).code, 1);
    assert.equal((await s.run(['handoff', 'latest', '../etc'])).code, 1, 'ids are validated');
  } finally { s.cleanup(); }
});

test('pause, resume, status and digest', async () => {
  const s = session();
  try {
    await s.run(NEW_TICKET);
    await s.run(['pause', '--reason', 'demo prep']);
    let status = await s.json(['status']);
    assert.deepEqual([status.control.paused, status.control.reason, status.counts.backlog, status.dispatcher.alive], [true, 'demo prep', 1, false]);
    assert.match((await s.run(['status'])).out, /PAUSED — demo prep/);
    await s.run(['resume']);
    status = await s.json(['status']);
    assert.equal(status.control.paused, false);
    assert.match((await s.run(['status'])).out, /RUNNING/);
    const digest = await s.json(['digest']);
    assert.deepEqual(Object.keys(digest).sort(), ['at_risk', 'blocked', 'date', 'in_progress', 'needs_ceo', 'runs_today', 'shipped']);
    assert.match((await s.run(['digest'])).out, new RegExp(digest.date));
  } finally { s.cleanup(); }
});

test('run --dry-run prints what would launch and changes nothing', async () => {
  const s = session();
  try {
    await s.run(['ticket', 'new', '--title', 'Backlog one', '--type', 'docs', '--owner', 'docs-writer']);
    await s.run(['ticket', 'new', '--title', 'Ready one', '--type', 'docs', '--owner', 'docs-writer', '--summary', 's', '--ac', 'a', '--status', 'ready']);
    const before = JSON.stringify(getEntity(s.ctx, 'tickets', 'T-0002'));
    const r = await s.run(['run', '--dry-run']);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /T-0002/);
    assert.match(r.out, /docs-writer/);
    assert.match(r.out, /sonnet/);
    assert.match(r.out, /--strict-mcp-config/);
    assert.equal(JSON.stringify(getEntity(s.ctx, 'tickets', 'T-0002')), before);
    assert.deepEqual(fs.readdirSync(s.ctx.dir('runs')), []);
    assert.equal(listIds(s.ctx), 'T-0001,T-0002', 'no meta ticket was created');

    const plan = await s.json(['run', '--dry-run']);
    assert.equal(plan.gate, null);
    const byTicket = plan.candidates.find((c) => c.ticket === 'T-0002');
    assert.deepEqual([byTicket.role, byTicket.model, byTicket.effort, byTicket.refused], ['docs-writer', 'sonnet', 'high', []]);
    const grooming = plan.candidates.find((c) => c.creates_meta === 'grooming');
    assert.ok(grooming, 'a short ready queue with a backlog proposes grooming (P1 outranks the P2 ticket)');
    assert.equal(plan.candidates[0], grooming);
    await s.run(['pause']);
    assert.match((await s.run(['run', '--dry-run'])).out, /paused/);
  } finally { s.cleanup(); }
});

test('doctor: FAIL (exit 1) on missing agents, a policy violation or a bad config; PASS on a healthy setup', async () => {
  const restore = useFakeClaude();
  try {
    const healthy = session();
    try {
      initRepo(healthy.root);
      const r = await healthy.run(['doctor']);
      assert.equal(r.code, 0, r.out);
      assert.match(r.out, /PASS\s+agents/);
      assert.match(r.out, /PASS\s+model policy/);
      assert.match(r.out, /PASS\s+git/);
      assert.doesNotMatch(r.out, /FAIL/);
      const checks = await healthy.json(['doctor']);
      assert.ok(checks.every((c) => ['PASS', 'WARN', 'FAIL'].includes(c.level)));
    } finally { healthy.cleanup(); }

    const noAgents = session({ agents: { 'factory-director': ['opus', 'high'] } });
    try {
      initRepo(noAgents.root);
      const r = await noAgents.run(['doctor']);
      assert.equal(r.code, 1);
      assert.match(r.out, /FAIL\s+agents\s+no agent file for: code-reviewer, .*qa-verifier/);
    } finally { noAgents.cleanup(); }

    const violation = session();
    try {
      initRepo(violation.root);
      fs.writeFileSync(path.join(violation.ctx.agentsDir, 'docs-writer.md'), '---\nname: docs-writer\nmodel: haiku\neffort: high\n---\n');
      const r = await violation.run(['doctor']);
      assert.equal(r.code, 1);
      assert.match(r.out, /FAIL\s+model policy\s+docs-writer: model "haiku" is neither opus nor sonnet/);
    } finally { violation.cleanup(); }

    const broken = session();
    try {
      fs.writeFileSync(path.join(broken.home, 'config.json'), '{ nope');
      const r = await broken.run(['doctor']);
      assert.equal(r.code, 1);
      assert.match(r.out, /FAIL\s+config\.json/);
      assert.equal((await broken.run(['status'])).code, 1, 'other commands refuse a broken config');
    } finally { broken.cleanup(); }
  } finally { restore(); }
});

test('doctor warns about duplicate top-level config keys, dangling references and bad state files', async () => {
  const restore = useFakeClaude();
  const s = session();
  try {
    initRepo(s.root);
    const text = fs.readFileSync(path.join(s.home, 'config.json'), 'utf8');
    fs.writeFileSync(path.join(s.home, 'config.json'), text.replace(/\n}\s*$/, ',\n  "ceo": { "max_open_decisions": 9 }\n}'));
    fs.writeFileSync(path.join(s.ctx.dir('tickets'), 'T-0500.json'), '{ torn');
    putEntity(s.ctx, 'tickets', { id: 'T-0600', status: 'ready', owner: 'backend-engineer', depends_on: ['T-0999'], decisions: [], title: 'x' });
    const r = await s.run(['doctor']);
    assert.match(r.out, /WARN\s+config\.json\s+duplicate top-level key\(s\) "ceo"/);
    assert.match(r.out, /WARN\s+state file\s+state\/tickets\/T-0500\.json/);
    assert.match(r.out, /WARN\s+references\s+dangling: T-0600 → T-0999/);
    assert.equal(r.code, 0, 'warnings do not fail doctor');
  } finally { s.cleanup(); restore(); }
});

test('doctor without a git repository or without commits', async () => {
  const restore = useFakeClaude();
  const s = session();
  try {
    let r = await s.run(['doctor']);
    assert.equal(r.code, 1);
    assert.match(r.out, /FAIL\s+git\s+.* is not a git repository/);
    git(s.root, 'init', '-q', '-b', 'main');
    r = await s.run(['doctor']);
    assert.match(r.out, /WARN\s+git commits\s+no commits yet/);
  } finally { s.cleanup(); restore(); }
});

test('bin/factory runs as a process: output, exit codes, FACTORY_HOME', async () => {
  const s = session();
  try {
    const env = { ...process.env, FACTORY_HOME: s.home };
    const ok = await exec(process.execPath, [FACTORY_BIN, 'ticket', 'list', '--json'], { env });
    assert.deepEqual(JSON.parse(ok.stdout), []);
    await assert.rejects(exec(process.execPath, [FACTORY_BIN, 'nonsense'], { env }), (e) => e.code === 2 && /unknown command/.test(e.stderr));
    await assert.rejects(exec(process.execPath, [FACTORY_BIN, 'ticket', 'show', 'T-0001'], { env }), (e) => e.code === 1 && /not found/.test(e.stderr));
    assert.equal(fs.statSync(FACTORY_BIN).mode & 0o111, 0o111, 'bin/factory is executable');
    assert.equal(fs.readFileSync(FACTORY_BIN, 'utf8').split('\n')[0], '#!/usr/bin/env node');
  } finally { s.cleanup(); }
});

test('up refuses a second copy; down stops both processes and cleans up', async () => {
  const s = session({ config: (c) => { c.board.port = 0; } });
  const env = { ...process.env, FACTORY_HOME: s.home };
  const cli = (...args) => exec(process.execPath, [FACTORY_BIN, ...args], { env });
  const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
  let pids = [];
  try {
    const up = await cli('up');
    assert.match(up.stdout, /board\s+http:\/\/127\.0\.0\.1:\d+/);
    const board = JSON.parse(fs.readFileSync(path.join(s.ctx.stateDir, 'board.json'), 'utf8'));
    const dispatcher = JSON.parse(fs.readFileSync(path.join(s.ctx.stateDir, 'dispatcher.json'), 'utf8'));
    pids = [board.pid, dispatcher.pid];
    assert.ok(pids.every(alive));

    const state = await (await fetch(`http://127.0.0.1:${board.port}/api/state`)).json();
    assert.equal(state.dispatcher.alive, true);

    await assert.rejects(cli('up'), (e) => e.code === 1 && /already running/.test(e.stderr));
    assert.ok(pids.every(alive), 'the refused second start leaves the first copy alone');
    const status = JSON.parse((await cli('status', '--json')).stdout);
    assert.deepEqual([status.board.pid, status.dispatcher.alive], [board.pid, true]);

    const down = await cli('down');
    assert.match(down.stdout, /stopping/);
    await waitFor(() => pids.every((p) => !alive(p)), { what: 'both processes to exit' });
    assert.equal(fs.existsSync(path.join(s.ctx.stateDir, 'board.json')), false);
    assert.match((await cli('down')).stdout, /was not running/);
    const events = fs.readdirSync(s.ctx.dir('events')).map((n) => fs.readFileSync(path.join(s.ctx.dir('events'), n), 'utf8')).join('');
    assert.match(events, /dispatcher stopped/);
  } finally {
    for (const p of pids) try { process.kill(p, 'SIGKILL'); } catch { /* already gone */ }
    s.cleanup();
  }
});

test('ticket set decisions, decision ack/veto, and a written handoff outranks an auto-snapshot', async () => {
  const s = session();
  try {
    const t = await s.json(['ticket', 'new', '--title', 'X', '--type', 'spec', '--owner', 'solution-architect', '--summary', 'x', '--ac', 'Given a, when b, then c.']);
    const d = await s.json(['decision', 'new', '--kind', 'directional', '--title', 'Q', '--question', 'Which?', '--option', 'a|A|first', '--option', 'b|B|second', '--recommend', 'a']);
    assert.deepEqual((await s.json(['ticket', 'set', t.id, `decisions=${d.id}`, '--by', 'factory-director'])).decisions, [d.id]);
    assert.equal((await s.run(['ticket', 'set', t.id, 'decisions=D-0999', '--by', 'factory-director'])).code, 1, 'unknown decision');
    const n1 = await s.json(['decision', 'new', '--kind', 'notice', '--title', 'N1', '--question', 'FYI', '--option', 'a|OK|fine']);
    const n2 = await s.json(['decision', 'new', '--kind', 'notice', '--title', 'N2', '--question', 'FYI', '--option', 'a|OK|fine']);
    assert.equal((await s.json(['decision', 'ack', n1.id])).status, 'acknowledged');
    assert.equal((await s.run(['decision', 'veto', n2.id])).code, 2, '--note is required');
    assert.equal((await s.json(['decision', 'veto', n2.id, '--note', 'no'])).status, 'vetoed');
    assert.equal(listEntities(s.ctx, 'feedback').length, 1, 'a veto files feedback');
    const dir = path.join(s.ctx.handoffsDir, t.id);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, '2026-01-01T00-00-00-000Z.md'), 'written');
    fs.writeFileSync(path.join(dir, '2026-01-02T00-00-00Z-auto-snapshot.md'), 'snap');
    assert.match((await s.run(['handoff', 'latest', t.id])).out, /2026-01-01T00-00-00-000Z\.md/);
    fs.rmSync(path.join(dir, '2026-01-01T00-00-00-000Z.md'));
    assert.match((await s.run(['handoff', 'latest', t.id])).out, /auto-snapshot\.md/, 'falls back to the snapshot');
  } finally { s.cleanup(); }
});

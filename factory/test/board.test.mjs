import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { startBoard } from '../board/server.mjs';
import { createTicket } from '../lib/tickets.mjs';
import { createDecision } from '../lib/decisions.mjs';
import { createAction, createEpic, createFeedback, createMilestone } from '../lib/items.mjs';
import { appendEvent, getEntity, listEntities, putEntity, readControl, updateDispatcherState } from '../lib/store.mjs';
import { makeFactory, ticketInput } from './helpers.mjs';

const OPTIONS = [{ id: 'a', label: 'A', summary: '' }, { id: 'b', label: 'B', summary: '' }];

/** Run a body against a board listening on an ephemeral port in a throw-away factory. */
async function withBoard(body, opts) {
  const f = makeFactory(opts);
  const { server, port } = await startBoard(f.ctx, { port: 0 });
  const base = `http://127.0.0.1:${port}`;
  const call = (pathAndQuery, { method = 'GET', headers = {}, body: payload } = {}) => fetch(base + pathAndQuery, {
    method, headers: { ...(payload ? { 'content-type': 'application/json' } : {}), ...headers }, body: payload ? JSON.stringify(payload) : undefined,
  });
  const post = (p, payload = {}, headers = { 'X-Factory-Board': '1' }) => call(p, { method: 'POST', headers, body: payload });
  try {
    await body({ f, base, port, call, post });
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    f.cleanup();
  }
}

function seedLibrary(root) {
  const write = (rel, text) => {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  };
  write('knowledge/product/prd.md', '---\ntitle: The PRD\nupdated: 2026-09-30\n---\n\n# Ignored heading\nbody\n');
  write('knowledge/development/architecture/overview.md', '# Architecture overview\n\ntext\n');
  write('knowledge/misc/untitled-note.md', 'no heading, no frontmatter\n');
  write('knowledge/development/decisions/0001-stack.md', '---\nstatus: draft\n---\n\n# ADR 1\n');
  write('factory/reports/digest-2026-10-01.md', '# Digest 1\n');
  write('factory/reports/digest-2026-10-02.md', '# Digest 2\n');
  write('docs/guide.md', '# Guide\n');
  write('knowledge/clip.html', '<h1>hello</h1>');
  write('knowledge/demo.mp4', '0123456789abcdefghij');
  write('knowledge/run.sh', 'echo no');
  write('src/secret.md', '# not in a library root\n');
  fs.writeFileSync(path.join(root, 'outside.md'), '# outside everything\n');
}

test('GET /api/state returns the whole payload in the documented shape', async () => {
  await withBoard(async ({ f, call }) => {
    seedLibrary(f.root);
    const m = createMilestone(f.ctx, { name: 'First demo' });
    const e = createEpic(f.ctx, { title: 'Directory core', milestone: m.id });
    const t = createTicket(f.ctx, ticketInput({ epic: e.id, milestone: m.id, tags: ['security-sensitive'], status: 'ready' }), 'pm');
    createDecision(f.ctx, { kind: 'directional', title: 'Stack?', question: 'Which stack?', options: OPTIONS, recommendation: 'a', blocks: [t.id] });
    createAction(f.ctx, { title: 'Create the Azure tenant' });
    createFeedback(f.ctx, { target: 'general', text: 'Looks good' });
    updateDispatcherState(f.ctx, { pid: process.pid, heartbeat: new Date().toISOString(), active: ['R-1'] });
    f.ctx.now = () => new Date();

    const res = await call('/api/state');
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /application\/json/);
    const s = await res.json();
    assert.deepEqual(Object.keys(s).sort(), [
      'actions', 'company', 'control', 'decisions', 'digest', 'dispatcher', 'epics', 'events', 'feedback', 'generated',
      'library', 'milestones', 'product', 'runs', 'sessions', 'tickets',
    ]);
    assert.equal(s.product, 'activeDIQ');
    assert.deepEqual(s.control, { paused: false, reason: null, by: null, ts: null });
    assert.equal(s.dispatcher.alive, true);
    assert.deepEqual(s.dispatcher.active, ['R-1']);
    assert.equal(s.milestones[0].id, m.id);
    assert.equal(s.epics[0].id, e.id);

    assert.equal(s.tickets.length, 1);
    assert.deepEqual(Object.keys(s.tickets[0]).sort(), [
      'attempts', 'created', 'decisions', 'depends_on', 'effort_override', 'epic', 'handoff', 'id', 'last_note', 'milestone', 'owner',
      'parity_refs', 'priority', 'stage_role', 'status', 'summary', 'tags', 'title', 'type', 'updated',
    ]);
    assert.equal(s.tickets[0].body, undefined, 'summaries leave out the heavy fields');
    assert.equal(s.tickets[0].history, undefined);
    assert.deepEqual(s.tickets[0].decisions, ['D-0001']);

    assert.equal(s.decisions.length, 1);
    assert.equal(s.decisions[0].question, 'Which stack?', 'decisions are served in full');
    assert.deepEqual(s.decisions[0].options.map((o) => o.id), ['a', 'b']);
    assert.equal(s.actions[0].title, 'Create the Azure tenant');
    assert.equal(s.feedback[0].text, 'Looks good');
    assert.deepEqual(s.runs, { active: [], recent: [] });
    assert.deepEqual(s.sessions, []);
    assert.ok(s.events.length >= 5);
    assert.ok(s.events[0].ts >= s.events.at(-1).ts, 'newest first');
    assert.deepEqual(s.digest, { date: '2026-10-02', path: 'factory/reports/digest-2026-10-02.md' });
  });
});

test('GET /api/state: runs split into active and the 20 most recent finished', async () => {
  await withBoard(async ({ f, call }) => {
    for (let i = 0; i < 25; i++) {
      putEntity(f.ctx, 'runs', { id: `R-20261002-1000${String(i).padStart(2, '0')}-aaaa`, ticket: 'T-0001', status: 'done', role: 'x' });
    }
    putEntity(f.ctx, 'runs', { id: 'R-20261002-110000-bbbb', ticket: 'T-0001', status: 'running', role: 'x' });
    const s = await (await call('/api/state')).json();
    assert.equal(s.runs.active.length, 1);
    assert.equal(s.runs.active[0].id, 'R-20261002-110000-bbbb');
    assert.equal(s.runs.recent.length, 20);
    assert.equal(s.runs.recent[0].id, 'R-20261002-100024-aaaa', 'newest first');
  });
});

test('GET /api/state: only sessions updated in the last 15 minutes are live', async () => {
  await withBoard(async ({ f, call }) => {
    const dir = f.ctx.dir('sessions');
    fs.writeFileSync(path.join(dir, 'fresh.json'), JSON.stringify({ id: 'fresh', role: 'backend-engineer' }));
    fs.writeFileSync(path.join(dir, 'stale.json'), JSON.stringify({ id: 'stale' }));
    fs.writeFileSync(path.join(dir, 'torn.json'), '{"id": ');
    const old = new Date(Date.now() - 20 * 60_000);
    fs.utimesSync(path.join(dir, 'stale.json'), old, old);
    f.ctx.now = () => new Date();
    const s = await (await call('/api/state')).json();
    assert.deepEqual(s.sessions.map((x) => x.id), ['fresh']);
  });
});

test('GET /api/state: events are capped at 150, newest first', async () => {
  await withBoard(async ({ f, call }) => {
    for (let i = 0; i < 170; i++) {
      f.clock.advance(1000);
      appendEvent(f.ctx, { text: `event ${i}` });
    }
    const s = await (await call('/api/state')).json();
    assert.equal(s.events.length, 150);
    assert.equal(s.events[0].text, 'event 169');
    assert.equal(s.events.at(-1).text, 'event 20');
  });
});

test('the library lists markdown with frontmatter titles, heading and mtime fallbacks, grouped by longest prefix', async () => {
  await withBoard(async ({ f, call }) => {
    seedLibrary(f.root);
    const mtime = new Date('2026-08-15T12:00:00Z');
    fs.utimesSync(path.join(f.root, 'knowledge/misc/untitled-note.md'), mtime, mtime);
    const { library } = await (await call('/api/state')).json();
    const byPath = Object.fromEntries(library.map((d) => [d.path, d]));

    assert.deepEqual(byPath['knowledge/product/prd.md'], { path: 'knowledge/product/prd.md', title: 'The PRD', group: 'Product', updated: '2026-09-30' });
    assert.equal(byPath['knowledge/development/architecture/overview.md'].title, 'Architecture overview');
    assert.equal(byPath['knowledge/development/architecture/overview.md'].group, 'Engineering');
    assert.deepEqual([byPath['knowledge/misc/untitled-note.md'].title, byPath['knowledge/misc/untitled-note.md'].group, byPath['knowledge/misc/untitled-note.md'].updated],
      ['untitled-note', 'Other', '2026-08-15']);
    assert.equal(byPath['knowledge/development/decisions/0001-stack.md'].title, 'ADR 1', 'a heading when frontmatter has no title');
    assert.equal(byPath['factory/reports/digest-2026-10-02.md'].group, 'Reports');
    assert.equal(byPath['docs/guide.md'].group, 'Product docs');
    assert.ok(!('src/secret.md' in byPath) && !('outside.md' in byPath), 'only files under the library roots');
    assert.ok(!('knowledge/clip.html' in byPath), 'the library lists markdown');
    const groups = [...new Set(library.map((d) => d.group))];
    assert.equal(groups.at(-1), 'Other', 'ungrouped documents come last');
  });
});

test('the library longest-prefix rule: a nested group wins over its parent', async () => {
  await withBoard(async ({ f, call }) => {
    seedLibrary(f.root);
    const { library } = await (await call('/api/state')).json();
    const group = (suffix) => library.find((d) => d.path.endsWith(suffix)).group;
    assert.equal(group('0001-stack.md'), 'ADRs');
    assert.equal(group('architecture/overview.md'), 'Engineering');
  }, { config: (c) => { c.library.groups['knowledge/development/decisions'] = 'ADRs'; } });
});

test('GET /api/ticket/:id returns the ticket with its runs and handoffs; unknown is 404', async () => {
  await withBoard(async ({ f, call }) => {
    const t = createTicket(f.ctx, ticketInput({ body: 'The body' }), 'pm');
    putEntity(f.ctx, 'runs', { id: 'R-20261002-100000-aaaa', ticket: t.id, status: 'done' });
    putEntity(f.ctx, 'runs', { id: 'R-20261002-100001-bbbb', ticket: 'T-0099', status: 'done' });
    const hdir = path.join(f.ctx.handoffsDir, t.id);
    fs.mkdirSync(hdir, { recursive: true });
    fs.writeFileSync(path.join(hdir, '2026-10-02T10-00-00-000Z.md'), '# handoff');
    const res = await call(`/api/ticket/${t.id}`);
    assert.equal(res.status, 200);
    const d = await res.json();
    assert.equal(d.body, 'The body');
    assert.deepEqual(d.runs.map((r) => r.id), ['R-20261002-100000-aaaa']);
    assert.deepEqual(d.handoffs.map((h) => h.name), ['2026-10-02T10-00-00-000Z.md']);
    assert.equal((await call('/api/ticket/T-0099')).status, 404);
    assert.equal((await call('/api/ticket/..%2Fstate')).status, 400);
  });
});

test('GET /api/run/:id/tail converts stream-json into readable lines', async () => {
  await withBoard(async ({ f, call }) => {
    putEntity(f.ctx, 'runs', { id: 'R-20261002-100000-aaaa', ticket: 'T-0001', status: 'running' });
    const stream = fs.readFileSync(new URL('./fixtures/stream-success.jsonl', import.meta.url), 'utf8');
    fs.writeFileSync(path.join(f.ctx.dir('runs'), 'R-20261002-100000-aaaa.log'), `${stream}{"type":"assistant","message":{"content":[{"type":"text","text":"torn`);
    const res = await call('/api/run/R-20261002-100000-aaaa/tail?lines=3');
    assert.equal(res.status, 200);
    const tail = await res.json();
    assert.equal(tail.status, 'running');
    assert.deepEqual(tail.lines, [
      'assistant: subagent chatter',
      'assistant: All acceptance criteria are met and the tests pass. Done.',
      'result: Implemented the builder. RESULT: advanced — filter builder done, 14 tests',
    ]);
    const all = await (await call('/api/run/R-20261002-100000-aaaa/tail')).json();
    assert.equal(all.lines[0], 'system: session started (claude-sonnet-5-5)');
    assert.equal((await call('/api/run/R-20261002-999999-zzzz/tail')).status, 404);
    putEntity(f.ctx, 'runs', { id: 'R-20261002-100005-cccc', ticket: 'T-0001', status: 'running' });
    assert.deepEqual((await (await call('/api/run/R-20261002-100005-cccc/tail')).json()).lines, [], 'no log yet is an empty tail');
  });
});

test('every POST needs the X-Factory-Board header', async () => {
  await withBoard(async ({ f, post }) => {
    createDecision(f.ctx, { kind: 'directional', title: 'q', question: 'q?', options: OPTIONS });
    for (const headers of [{}, { 'X-Factory-Board': '0' }, { 'X-Factory-Board': 'true' }]) {
      const res = await post('/api/decisions/D-0001/answer', { options: ['a'] }, headers);
      assert.equal(res.status, 403, JSON.stringify(headers));
      assert.match((await res.json()).error, /X-Factory-Board/);
    }
    assert.equal(getEntity(f.ctx, 'decisions', 'D-0001').status, 'pending', 'nothing was written');
    const control = await post('/api/control', { paused: true }, {});
    assert.equal(control.status, 403);
    assert.equal(readControl(f.ctx).paused, false);
    const ok = await post('/api/decisions/D-0001/answer', { options: ['a'], note: 'go' });
    assert.equal(ok.status, 200);
    const d = await ok.json();
    assert.deepEqual([d.status, d.answer.options, d.answer.note, d.answer.via], ['answered', ['a'], 'go', 'board']);
    assert.equal(getEntity(f.ctx, 'decisions', 'D-0001').status, 'answered');
  });
});

test('POST validation errors come back as 4xx JSON, never a crash', async () => {
  await withBoard(async ({ f, post, call, base }) => {
    createDecision(f.ctx, { kind: 'directional', title: 'q', question: 'q?', options: OPTIONS });
    const wrong = await post('/api/decisions/D-0001/answer', { options: ['zzz'] });
    assert.equal(wrong.status, 400);
    assert.match((await wrong.json()).error, /unknown option zzz/);
    assert.equal((await post('/api/decisions/D-0001/answer', {})).status, 400);
    assert.equal((await post('/api/decisions/D-0404/answer', { options: ['a'] })).status, 404);
    assert.equal((await post('/api/nothing', {})).status, 404);
    assert.equal((await post('/api/control', { paused: 'yes' })).status, 400);
    const bad = await fetch(`${base}/api/control`, { method: 'POST', headers: { 'X-Factory-Board': '1', 'content-type': 'application/json' }, body: '{nope' });
    assert.equal(bad.status, 400);
    assert.equal((await call('/api/state', { method: 'DELETE' })).status, 405);
    assert.equal((await call('/api/unknown')).status, 404);
  });
});

test('notice acknowledge / veto, action done, feedback and pause/resume over POST', async () => {
  await withBoard(async ({ f, post }) => {
    createDecision(f.ctx, { kind: 'notice', title: 'We chose X', question: 'FYI', options: [] });
    createDecision(f.ctx, { kind: 'notice', title: 'We chose Y', question: 'FYI', options: [] });
    createAction(f.ctx, { title: 'Create tenant' });

    assert.equal((await (await post('/api/decisions/D-0001/ack', {})).json()).status, 'acknowledged');
    assert.equal((await (await post('/api/decisions/D-0002/veto', { note: 'no' })).json()).status, 'vetoed');
    assert.equal(listEntities(f.ctx, 'feedback').length, 1, 'a veto files feedback');

    const done = await (await post('/api/actions/A-0001/done', { note: 'did it' })).json();
    assert.deepEqual([done.status, done.done_note], ['done', 'did it']);

    const fb = await post('/api/feedback', { target: 'ticket:T-0001', text: 'Hmm', sentiment: 'change' });
    assert.equal(fb.status, 200);
    assert.equal((await post('/api/feedback', { target: 'bogus', text: 'x' })).status, 400);
    assert.equal((await post('/api/feedback', { target: 'general', text: '' })).status, 400);

    await post('/api/control', { paused: true, reason: 'demo' });
    assert.deepEqual([readControl(f.ctx).paused, readControl(f.ctx).reason], [true, 'demo']);
    await post('/api/control', { paused: false });
    assert.equal(readControl(f.ctx).paused, false);
  });
});

test('/api/doc serves markdown from the library roots', async () => {
  await withBoard(async ({ f, call }) => {
    seedLibrary(f.root);
    const res = await call('/api/doc?path=knowledge/product/prd.md');
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/markdown/);
    assert.match(await res.text(), /# Ignored heading/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal((await call('/api/doc?path=knowledge/product/missing.md')).status, 404);
    assert.equal((await call('/api/doc?path=knowledge/clip.html')).status, 415, '/api/doc is markdown only');
    assert.equal((await call('/api/doc')).status, 400);
  });
});

test('/api/doc and /api/file reject traversal, absolute paths and paths outside the roots', async () => {
  await withBoard(async ({ f, call }) => {
    seedLibrary(f.root);
    const sneaky = [
      '../outside.md', 'knowledge/../outside.md', 'knowledge/../../outside.md', 'knowledge/%2e%2e/outside.md',
      '..%2foutside.md', '/etc/passwd', path.join(f.root, 'outside.md'), path.join(f.root, 'knowledge/product/prd.md'),
      'src/secret.md', 'factory/config.json', 'factory/state/counters.json', 'knowledgeX/outside.md', 'knowledge/../src/secret.md',
      'knowledge\\..\\outside.md', 'knowledge/product/prd.md\0.png',
    ];
    for (const endpoint of ['/api/doc', '/api/file']) {
      for (const p of sneaky) {
        const res = await call(`${endpoint}?path=${encodeURIComponent(p)}`);
        assert.ok([400, 403, 404].includes(res.status), `${endpoint} ${JSON.stringify(p)} → ${res.status}`);
        const text = await res.text();
        assert.doesNotMatch(text, /outside everything|not in a library root|root:/, `${endpoint} ${JSON.stringify(p)} leaked content`);
      }
    }
    assert.equal((await call(`/api/file?path=${encodeURIComponent('../outside.md')}`)).status, 403);
    assert.equal((await call(`/api/file?path=${encodeURIComponent('src/secret.md')}`)).status, 403);
    assert.equal((await call('/api/file?path=%2Fetc%2Fpasswd')).status, 400);
  });
});

test('/api/file refuses a symlink that leaves the roots', async (t) => {
  await withBoard(async ({ f, call }) => {
    seedLibrary(f.root);
    const outside = path.join(f.root, 'outside.md');
    try {
      fs.symlinkSync(outside, path.join(f.root, 'knowledge', 'link.md'));
      fs.symlinkSync(path.join(f.root, 'src'), path.join(f.root, 'knowledge', 'linkdir'));
    } catch {
      t.skip('symlinks are not available');
      return;
    }
    assert.equal((await call('/api/file?path=knowledge/link.md')).status, 403);
    assert.equal((await call('/api/doc?path=knowledge/link.md')).status, 403);
    assert.equal((await call('/api/file?path=knowledge/linkdir/secret.md')).status, 403);
    const { library } = await (await call('/api/state')).json();
    assert.ok(library.every((d) => !d.path.includes('link')), 'symlinks are not listed');
  });
});

test('/api/file serves typed assets with a sandbox CSP and byte ranges; refuses unknown types', async () => {
  await withBoard(async ({ f, call }) => {
    seedLibrary(f.root);
    const html = await call('/api/file?path=knowledge/clip.html');
    assert.equal(html.status, 200);
    assert.match(html.headers.get('content-type'), /text\/html/);
    assert.match(html.headers.get('content-security-policy'), /sandbox/);

    const full = await call('/api/file?path=knowledge/demo.mp4');
    assert.equal(full.headers.get('content-type'), 'video/mp4');
    assert.equal(full.headers.get('accept-ranges'), 'bytes');
    assert.equal((await full.text()), '0123456789abcdefghij');

    const part = await call('/api/file?path=knowledge/demo.mp4', { headers: { Range: 'bytes=5-9' } });
    assert.equal(part.status, 206);
    assert.equal(part.headers.get('content-range'), 'bytes 5-9/20');
    assert.equal(await part.text(), '56789');
    const tailRange = await call('/api/file?path=knowledge/demo.mp4', { headers: { Range: 'bytes=-4' } });
    assert.equal(await tailRange.text(), 'ghij');
    const openEnded = await call('/api/file?path=knowledge/demo.mp4', { headers: { Range: 'bytes=15-' } });
    assert.equal(await openEnded.text(), 'fghij');
    assert.equal((await call('/api/file?path=knowledge/demo.mp4', { headers: { Range: 'bytes=50-60' } })).status, 416);

    assert.equal((await call('/api/file?path=knowledge/run.sh')).status, 415);
  });
});

test('static files come from board/public; traversal out of it is refused', async () => {
  await withBoard(async ({ call }) => {
    const index = await call('/');
    assert.equal(index.status, 200);
    assert.match(index.headers.get('content-type'), /text\/html/);
    assert.match(await index.text(), /<html/i);
    for (const file of ['/app.js', '/styles.css', '/tokens.css']) assert.equal((await call(file)).status, 200, file);
    assert.equal((await call('/dev/fixture-state.json')).status, 200);
    for (const bad of ['/../server.mjs', '/%2e%2e/server.mjs', '/..%2fserver.mjs', '/nope.js', '/dev/', '/%00']) {
      const res = await call(bad);
      assert.ok([400, 403, 404].includes(res.status), `${bad} → ${res.status}`);
    }
  });
});

test('requests with a foreign Host header are refused (DNS rebinding)', async () => {
  await withBoard(async ({ port }) => {
    const request = (host) => new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path: '/api/state', headers: { Host: host } }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      });
      req.on('error', reject);
      req.end();
    });
    assert.equal(await request(`127.0.0.1:${port}`), 200);
    assert.equal(await request(`localhost:${port}`), 200);
    assert.equal(await request('evil.example.com'), 403);
    assert.equal(await request(`evil.example.com:${port}`), 403);
  });
});

test('the board binds config.board.host only', async () => {
  const f = makeFactory({ config: (c) => { c.board.host = '127.0.0.1'; } });
  const { server, port } = await startBoard(f.ctx, { port: 0 });
  try {
    assert.equal(server.address().address, '127.0.0.1');
    assert.ok(port > 0);
    const nonLoopback = Object.values(os.networkInterfaces()).flat().find((i) => i && !i.internal && i.family === 'IPv4');
    if (nonLoopback) {
      await assert.rejects(fetch(`http://${nonLoopback.address}:${port}/api/state`, { signal: AbortSignal.timeout(2000) }));
    }
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    f.cleanup();
  }
});

test('a second board on the same port fails to start with a clear error', async () => {
  const f = makeFactory();
  const first = await startBoard(f.ctx, { port: 0 });
  try {
    await assert.rejects(startBoard(f.ctx, { port: first.port }), /EADDRINUSE/);
  } finally {
    first.server.closeAllConnections();
    await new Promise((r) => first.server.close(r));
    f.cleanup();
  }
});

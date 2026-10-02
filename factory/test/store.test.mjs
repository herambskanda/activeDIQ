import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  appendEvent, drainBadFiles, entityPath, getEntity, listEntities, newRunId, nextId, openStore, putEntity,
  readControl, readRecentEvents, resolveHome, setControl, updateDispatcherState, readDispatcherState,
  updateEntity, withLock, writeJsonAtomic, readJson,
} from '../lib/store.mjs';
import { FactoryError } from '../lib/errors.mjs';
import { git, initRepo, makeFactory } from './helpers.mjs';

const run = promisify(execFile);

test('writeJsonAtomic leaves no temp files and replaces content whole', () => {
  const f = makeFactory();
  try {
    const file = path.join(f.ctx.stateDir, 'x.json');
    writeJsonAtomic(file, { a: 1 });
    writeJsonAtomic(file, { a: 2, b: 'é' });
    assert.deepEqual(readJson(file), { a: 2, b: 'é' });
    assert.deepEqual(fs.readdirSync(f.ctx.stateDir).filter((n) => n.includes('.tmp')), []);
  } finally { f.cleanup(); }
});

test('readJson returns null for a missing file and throws on corrupt JSON', () => {
  const f = makeFactory();
  try {
    assert.equal(readJson(path.join(f.ctx.stateDir, 'nope.json')), null);
    const bad = path.join(f.ctx.stateDir, 'bad.json');
    fs.writeFileSync(bad, '{"a":');
    assert.throws(() => readJson(bad));
  } finally { f.cleanup(); }
});

test('ids are sequential, zero-padded per kind, and independent', () => {
  const f = makeFactory();
  try {
    assert.deepEqual(['T', 'T', 'D', 'A', 'F', 'E', 'M', 'M'].map((k) => nextId(f.ctx, k)),
      ['T-0001', 'T-0002', 'D-0001', 'A-0001', 'F-0001', 'E-001', 'M1', 'M2']);
    assert.throws(() => nextId(f.ctx, 'Z'));
  } finally { f.cleanup(); }
});

test('nextId skips ids whose file exists even when counters.json is lost', () => {
  const f = makeFactory();
  try {
    putEntity(f.ctx, 'tickets', { id: 'T-0001', title: 'x' });
    putEntity(f.ctx, 'tickets', { id: 'T-0002', title: 'y' });
    assert.equal(nextId(f.ctx, 'T'), 'T-0003');
    fs.rmSync(path.join(f.ctx.stateDir, 'counters.json'));
    assert.equal(nextId(f.ctx, 'T'), 'T-0003');
  } finally { f.cleanup(); }
});

test('a corrupt counters.json is reported, not silently reset', () => {
  const f = makeFactory();
  try {
    fs.writeFileSync(path.join(f.ctx.stateDir, 'counters.json'), '{nope');
    assert.throws(() => nextId(f.ctx, 'T'), /corrupt/);
  } finally { f.cleanup(); }
});

test('ids are unique across concurrent processes', async () => {
  const f = makeFactory();
  try {
    const script = `
      import { openStore, nextId } from ${JSON.stringify(new URL('../lib/store.mjs', import.meta.url).href)};
      const ctx = openStore(process.argv[1]);
      const ids = []; for (let i = 0; i < 25; i++) ids.push(nextId(ctx, 'T'));
      console.log(ids.join(','));`;
    const outs = await Promise.all(Array.from({ length: 4 }, () => run(process.execPath, ['--input-type=module', '-e', script, f.home])));
    const all = outs.flatMap((o) => o.stdout.trim().split(','));
    assert.equal(all.length, 100);
    assert.equal(new Set(all).size, 100);
    assert.equal(nextId(f.ctx, 'T'), 'T-0101');
  } finally { f.cleanup(); }
});

test('withLock is re-entrant and releases the lock', () => {
  const f = makeFactory();
  try {
    const out = withLock(f.ctx, () => withLock(f.ctx, () => 7));
    assert.equal(out, 7);
    assert.equal(fs.existsSync(path.join(f.ctx.stateDir, '.lock')), false);
    assert.throws(() => withLock(f.ctx, () => { throw new Error('boom'); }), /boom/);
    assert.equal(fs.existsSync(path.join(f.ctx.stateDir, '.lock')), false);
    assert.equal(f.ctx.lockDepth, 0);
  } finally { f.cleanup(); }
});

test('a stale lock (older than 10 s) is broken', () => {
  const f = makeFactory();
  try {
    const lock = path.join(f.ctx.stateDir, '.lock');
    fs.mkdirSync(lock);
    const old = new Date(Date.now() - 60_000);
    fs.utimesSync(lock, old, old);
    assert.equal(withLock(f.ctx, () => 'got it'), 'got it');
    assert.equal(fs.existsSync(lock), false);
    assert.deepEqual(fs.readdirSync(f.ctx.stateDir).filter((n) => n.startsWith('.lock')), []);
  } finally { f.cleanup(); }
});

test('entityPath rejects ids that could escape the directory', () => {
  const f = makeFactory();
  try {
    for (const bad of ['../x', 'a/b', '', '.hidden', 'a\0b', null, 5]) {
      assert.throws(() => entityPath(f.ctx, 'tickets', bad), FactoryError, String(bad));
    }
    assert.equal(path.basename(entityPath(f.ctx, 'tickets', 'T-0001')), 'T-0001.json');
  } finally { f.cleanup(); }
});

test('updateEntity is a locked read-modify-write that stamps updated', () => {
  const f = makeFactory();
  try {
    putEntity(f.ctx, 'tickets', { id: 'T-0001', n: 1, updated: 'then' });
    f.clock.advance(60_000);
    const out = updateEntity(f.ctx, 'tickets', 'T-0001', (t) => { t.n += 1; });
    assert.equal(out.n, 2);
    assert.equal(out.updated, f.ctx.now().toISOString());
    assert.equal(getEntity(f.ctx, 'tickets', 'T-0001').n, 2);
    assert.throws(() => updateEntity(f.ctx, 'tickets', 'T-9999', () => {}), /not found/i);
  } finally { f.cleanup(); }
});

test('a throwing mutate leaves the stored entity untouched', () => {
  const f = makeFactory();
  try {
    putEntity(f.ctx, 'tickets', { id: 'T-0001', n: 1 });
    assert.throws(() => updateEntity(f.ctx, 'tickets', 'T-0001', (t) => { t.n = 99; throw new Error('no'); }));
    assert.equal(getEntity(f.ctx, 'tickets', 'T-0001').n, 1);
  } finally { f.cleanup(); }
});

test('listEntities skips corrupt files and reports each once via drainBadFiles', () => {
  const f = makeFactory();
  try {
    putEntity(f.ctx, 'tickets', { id: 'T-0001' });
    fs.writeFileSync(path.join(f.ctx.dir('tickets'), 'T-0002.json'), '{"id":');
    fs.writeFileSync(path.join(f.ctx.dir('tickets'), 'notes.txt'), 'ignored');
    assert.deepEqual(listEntities(f.ctx, 'tickets').map((t) => t.id), ['T-0001']);
    assert.equal(drainBadFiles(f.ctx).length, 1);
    listEntities(f.ctx, 'tickets');
    assert.equal(drainBadFiles(f.ctx).length, 0, 'reported only once');
  } finally { f.cleanup(); }
});

test('run ids sort by start time', () => {
  const f = makeFactory();
  try {
    const a = newRunId(f.ctx);
    f.clock.advance(1000);
    const b = newRunId(f.ctx);
    assert.match(a, /^R-\d{8}-\d{6}-[0-9a-f]{4}$/);
    assert.ok(a < b);
  } finally { f.cleanup(); }
});

test('events are appended per local day and read back newest first', () => {
  const f = makeFactory();
  try {
    appendEvent(f.ctx, { actor: 'a', kind: 'ticket', ticket: 'T-0001', text: 'one' });
    f.clock.advance(1000);
    appendEvent(f.ctx, { actor: 'b', kind: 'system', text: 'two' });
    f.clock.advance(1000);
    appendEvent(f.ctx, { actor: 'c', kind: 'system', text: 'three' });
    assert.deepEqual(readRecentEvents(f.ctx, 10).map((e) => e.text), ['three', 'two', 'one']);
    assert.deepEqual(readRecentEvents(f.ctx, 2).map((e) => e.text), ['three', 'two']);
  } finally { f.cleanup(); }
});

test('readRecentEvents tolerates a torn final line and spans days', () => {
  const f = makeFactory();
  try {
    appendEvent(f.ctx, { text: 'day one' });
    f.clock.advance(26 * 3_600_000);
    appendEvent(f.ctx, { text: 'day two' });
    const files = fs.readdirSync(f.ctx.dir('events')).sort();
    assert.equal(files.length, 2);
    fs.appendFileSync(path.join(f.ctx.dir('events'), files[1]), '{"ts":"torn');
    assert.deepEqual(readRecentEvents(f.ctx, 10).map((e) => e.text), ['day two', 'day one']);
  } finally { f.cleanup(); }
});

test('control (pause) and dispatcher state round-trip', () => {
  const f = makeFactory();
  try {
    assert.equal(readControl(f.ctx).paused, false);
    setControl(f.ctx, { paused: true, reason: 'demo', by: 'ceo' });
    assert.equal(readControl(f.ctx).paused, true);
    assert.equal(readControl(f.ctx).reason, 'demo');
    setControl(f.ctx, { paused: false });
    assert.equal(readControl(f.ctx).paused, false);
    updateDispatcherState(f.ctx, { pid: 5 });
    updateDispatcherState(f.ctx, (s) => ({ count: (s.count ?? 0) + 1 }));
    assert.deepEqual([readDispatcherState(f.ctx).pid, readDispatcherState(f.ctx).count], [5, 1]);
  } finally { f.cleanup(); }
});

test('resolveHome: FACTORY_HOME wins, then the main checkout of a worktree, then the fallback', () => {
  const f = makeFactory();
  const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'nohome-'));
  try {
    assert.equal(resolveHome({ env: { FACTORY_HOME: f.home }, cwd: '/' }), f.home);
    assert.equal(resolveHome({ env: {}, cwd: elsewhere, fallbackHome: f.home }), f.home);
    assert.throws(() => resolveHome({ env: {}, cwd: elsewhere }), /FACTORY_HOME/);

    initRepo(f.root);
    const inside = path.join(f.root, '.worktrees', 'w');
    git(f.root, 'worktree', 'add', '-q', '-b', 'w', inside);
    assert.equal(resolveHome({ env: {}, cwd: inside }), f.home);
  } finally {
    fs.rmSync(elsewhere, { recursive: true, force: true });
    f.cleanup();
  }
});

test('openStore fails on a bad config, lenient mode reports it instead', () => {
  const f = makeFactory();
  try {
    fs.writeFileSync(path.join(f.home, 'config.json'), '{ nope');
    assert.throws(() => openStore(f.home), /not valid JSON/);
    assert.match(openStore(f.home, { lenient: true }).configError, /not valid JSON/);
  } finally { f.cleanup(); }
});

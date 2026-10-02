// The file-based state store: home resolution, atomic JSON files, the mkdir lock, ids, events,
// control and dispatcher state. Everything else in the runtime reads and writes through here.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { FactoryError, NotFoundError } from './errors.mjs';

/** Event kinds accepted by `factory event`. */
export const EVENT_KINDS = ['ticket', 'decision', 'action', 'feedback', 'run', 'dispatcher', 'session', 'tool', 'memory', 'ceo', 'system'];

const STATE_DIRS = ['tickets', 'epics', 'milestones', 'decisions', 'actions', 'feedback', 'runs', 'sessions', 'events'];
/** counter key → [id prefix, zero-pad width, entity directory] */
const ID_FORMATS = {
  T: ['T-', 4, 'tickets'],
  D: ['D-', 4, 'decisions'],
  A: ['A-', 4, 'actions'],
  F: ['F-', 4, 'feedback'],
  E: ['E-', 3, 'epics'],
  M: ['M', 1, 'milestones'],
};
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const LOCK_STALE_MS = 10_000;
const LOCK_WAIT_MS = 15_000;

/**
 * Locate FACTORY_HOME: `$FACTORY_HOME`, else `factory/` of the main git checkout (so workers in a
 * worktree share one state store), else the supplied fallback (the directory holding `bin/`).
 * @param {{env?: object, cwd?: string, fallbackHome?: string}} [opts]
 * @returns {string} absolute path of the factory directory
 */
export function resolveHome({ env = process.env, cwd = process.cwd(), fallbackHome } = {}) {
  if (env.FACTORY_HOME) return path.resolve(env.FACTORY_HOME);
  try {
    const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000,
    }).trim();
    const candidate = path.join(path.dirname(common), 'factory');
    if (fs.existsSync(path.join(candidate, 'config.json'))) return candidate;
  } catch {
    // not inside a git checkout, or git is missing: fall through
  }
  if (fallbackHome) return path.resolve(fallbackHome);
  throw new FactoryError('cannot locate FACTORY_HOME (set the FACTORY_HOME environment variable)');
}

/**
 * Parse `<home>/config.json`.
 * @param {string} home
 * @returns {object}
 */
export function loadConfig(home) {
  const file = path.join(home, 'config.json');
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new FactoryError(`cannot read ${file}: ${err.code ?? err.message}`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new FactoryError(`${file} is not valid JSON: ${err.message}`);
  }
}

/**
 * Open the store. The returned context is passed to every runtime function.
 * @param {string} home absolute FACTORY_HOME
 * @param {{lenient?: boolean, now?: () => Date}} [opts] lenient: do not throw when config.json is bad (doctor)
 * @returns {object} ctx
 */
export function openStore(home, { lenient = false, now } = {}) {
  const resolved = path.resolve(home);
  const root = path.dirname(resolved);
  const ctx = {
    home: resolved,
    root,
    stateDir: path.join(resolved, 'state'),
    handoffsDir: path.join(resolved, 'handoffs'),
    reportsDir: path.join(resolved, 'reports'),
    templatesDir: path.join(resolved, 'templates'),
    agentsDir: path.join(root, '.claude', 'agents'),
    config: null,
    configError: null,
    now: now ?? (() => new Date()),
    lockDepth: 0,
    badFiles: new Map(),
    reportedBad: new Set(),
    dir(kind) { return path.join(this.stateDir, kind); },
  };
  try {
    ctx.config = loadConfig(resolved);
  } catch (err) {
    if (!lenient) throw err;
    ctx.configError = err.message;
  }
  return ctx;
}

/**
 * Re-read config.json (the dispatcher does this every tick).
 * @param {object} ctx
 * @returns {object} the new config
 */
export function reloadConfig(ctx) {
  ctx.config = loadConfig(ctx.home);
  return ctx.config;
}

/**
 * Create any missing state directories.
 * @param {object} ctx
 * @returns {string[]} directories that were created
 */
export function ensureStateDirs(ctx) {
  const created = [];
  for (const dir of [ctx.stateDir, ...STATE_DIRS.map((d) => ctx.dir(d)), ctx.handoffsDir]) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      created.push(dir);
    }
  }
  return created;
}

// ---------------------------------------------------------------------------------------------
// time

const pad = (n) => String(n).padStart(2, '0');

/**
 * Local calendar date as YYYY-MM-DD.
 * @param {Date} d
 */
export function localDate(d) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/**
 * ISO-8601 UTC timestamp of the store clock.
 * @param {object} ctx
 */
export function nowIso(ctx) {
  return ctx.now().toISOString();
}

/**
 * Block the thread for a short time (lock back-off only).
 * @param {number} ms
 */
export function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Whether a process exists.
 * @param {number|null|undefined} pid
 */
export function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

// ---------------------------------------------------------------------------------------------
// files

/**
 * Read a JSON file. Missing file → null; corrupt file → throws.
 * @param {string} file
 */
export function readJson(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  return JSON.parse(text);
}

/**
 * Write JSON atomically (tmp file + rename).
 * @param {string} file
 * @param {unknown} data
 */
export function writeJsonAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(3).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`);
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

/**
 * Read bytes [start, end) of a file.
 * @param {string} file
 * @param {number} start
 * @param {number} end
 * @returns {Buffer}
 */
export function readRange(file, start, end) {
  const length = Math.max(0, end - start);
  const buf = Buffer.alloc(length);
  const fd = fs.openSync(file, 'r');
  try {
    let got = 0;
    while (got < length) {
      const n = fs.readSync(fd, buf, got, length - got, start + got);
      if (n === 0) break;
      got += n;
    }
    return got === length ? buf : buf.subarray(0, got);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Read the last `maxBytes` of a text file, starting at a line boundary. Missing file → ''.
 * @param {string} file
 * @param {number} [maxBytes]
 */
export function readTail(file, maxBytes = 262144) {
  let size;
  try {
    size = fs.statSync(file).size;
  } catch (err) {
    if (err.code === 'ENOENT') return '';
    throw err;
  }
  const start = Math.max(0, size - maxBytes);
  let text = readRange(file, start, size).toString('utf8');
  if (start > 0) {
    const nl = text.indexOf('\n');
    text = nl >= 0 ? text.slice(nl + 1) : '';
  }
  return text;
}

// ---------------------------------------------------------------------------------------------
// lock

function acquireLock(ctx) {
  const dir = path.join(ctx.stateDir, '.lock');
  fs.mkdirSync(ctx.stateDir, { recursive: true });
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      fs.mkdirSync(dir);
      return dir;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
    try {
      if (Date.now() - fs.statSync(dir).mtimeMs > LOCK_STALE_MS) {
        // Whoever renames the stale lock away wins and deletes it; everybody else just retries.
        const stale = `${dir}.stale.${process.pid}.${crypto.randomBytes(2).toString('hex')}`;
        fs.renameSync(dir, stale);
        fs.rmSync(stale, { recursive: true, force: true });
        continue;
      }
    } catch {
      continue; // the lock vanished between mkdir and stat: retry immediately
    }
    if (Date.now() > deadline) throw new FactoryError(`could not acquire the state lock (${dir})`, 503);
    sleepSync(5 + Math.floor(Math.random() * 15));
  }
}

/**
 * Run a synchronous critical section under the store's mkdir lock (re-entrant within a process;
 * stale after 10 s).
 * @template T
 * @param {object} ctx
 * @param {() => T} fn must not be async
 * @returns {T}
 */
export function withLock(ctx, fn) {
  if (ctx.lockDepth > 0) return fn();
  const dir = acquireLock(ctx);
  ctx.lockDepth = 1;
  try {
    return fn();
  } finally {
    ctx.lockDepth = 0;
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------------------------
// entities

/**
 * Absolute path of an entity file. Ids are validated so callers can pass untrusted input.
 * @param {object} ctx
 * @param {string} kind directory name, e.g. 'tickets'
 * @param {string} id
 */
export function entityPath(ctx, kind, id) {
  if (typeof id !== 'string' || !SAFE_ID.test(id)) throw new FactoryError(`invalid id: ${JSON.stringify(id)}`);
  return path.join(ctx.dir(kind), `${id}.json`);
}

/**
 * Read one entity; null when it does not exist.
 * @param {object} ctx
 * @param {string} kind
 * @param {string} id
 */
export function getEntity(ctx, kind, id) {
  return readJson(entityPath(ctx, kind, id));
}

/**
 * Read one entity or throw NotFoundError.
 * @param {object} ctx
 * @param {string} kind
 * @param {string} id
 * @param {string} [label] noun for the message, e.g. 'ticket'
 */
export function requireEntity(ctx, kind, id, label = kind.replace(/s$/, '')) {
  const entity = getEntity(ctx, kind, id);
  if (!entity) throw new NotFoundError(`${label} ${id} not found`);
  return entity;
}

/**
 * Write one entity atomically.
 * @param {object} ctx
 * @param {string} kind
 * @param {{id: string}} entity
 */
export function putEntity(ctx, kind, entity) {
  writeJsonAtomic(entityPath(ctx, kind, entity.id), entity);
  return entity;
}

/**
 * Read-modify-write one entity under the lock. `mutate` edits in place or returns a replacement;
 * `updated` is stamped automatically.
 * @param {object} ctx
 * @param {string} kind
 * @param {string} id
 * @param {(entity: any) => any} mutate
 */
export function updateEntity(ctx, kind, id, mutate) {
  return withLock(ctx, () => {
    const current = requireEntity(ctx, kind, id);
    const next = mutate(current) ?? current;
    next.updated = nowIso(ctx);
    return putEntity(ctx, kind, next);
  });
}

/**
 * List every entity of a kind, oldest id first. Unreadable files are skipped and remembered in
 * `ctx.badFiles` (see {@link drainBadFiles}) so one corrupt file never takes the factory down.
 * @param {object} ctx
 * @param {string} kind
 * @returns {any[]}
 */
export function listEntities(ctx, kind) {
  const dir = ctx.dir(kind);
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  const out = [];
  for (const name of names.sort()) {
    if (!name.endsWith('.json')) continue;
    const file = path.join(dir, name);
    try {
      const data = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (!data || typeof data !== 'object' || typeof data.id !== 'string') throw new Error('not an entity (no id)');
      out.push(data);
      ctx.badFiles.delete(file);
    } catch (err) {
      if (err.code !== 'ENOENT') ctx.badFiles.set(file, err.message);
    }
  }
  return out;
}

/**
 * The newest runs (run ids sort chronologically), newest first.
 * @param {object} ctx
 * @param {number} limit
 */
export function listRecentRuns(ctx, limit) {
  let names;
  try {
    names = fs.readdirSync(ctx.dir('runs'));
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  const out = [];
  for (const name of names.filter((n) => n.endsWith('.json')).sort().reverse().slice(0, limit)) {
    const file = path.join(ctx.dir('runs'), name);
    try {
      out.push(JSON.parse(fs.readFileSync(file, 'utf8')));
      ctx.badFiles.delete(file);
    } catch (err) {
      if (err.code !== 'ENOENT') ctx.badFiles.set(file, err.message);
    }
  }
  return out;
}

/**
 * Unreadable state files seen since the last call (each reported once until it is fixed and breaks again).
 * @param {object} ctx
 * @returns {Array<[string, string]>} [file, message]
 */
export function drainBadFiles(ctx) {
  const fresh = [];
  for (const [file, message] of ctx.badFiles) {
    if (!ctx.reportedBad.has(file)) {
      ctx.reportedBad.add(file);
      fresh.push([file, message]);
    }
  }
  for (const file of ctx.reportedBad) if (!ctx.badFiles.has(file)) ctx.reportedBad.delete(file);
  return fresh;
}

// ---------------------------------------------------------------------------------------------
// ids

/**
 * Allocate the next id for a counter key (T D A F E M) under the lock. Never returns an id whose
 * file already exists, even if counters.json was lost.
 * @param {object} ctx
 * @param {'T'|'D'|'A'|'F'|'E'|'M'} key
 */
export function nextId(ctx, key) {
  const format = ID_FORMATS[key];
  if (!format) throw new Error(`unknown counter key: ${key}`);
  const [prefix, width, kind] = format;
  return withLock(ctx, () => {
    const file = path.join(ctx.stateDir, 'counters.json');
    let counters;
    try {
      counters = readJson(file) ?? {};
    } catch (err) {
      throw new FactoryError(`${file} is corrupt (${err.message}); fix or delete it`);
    }
    let n = counters[key] ?? 0;
    let id;
    do {
      n += 1;
      id = prefix + String(n).padStart(width, '0');
    } while (fs.existsSync(entityPath(ctx, kind, id)));
    counters[key] = n;
    writeJsonAtomic(file, counters);
    return id;
  });
}

/**
 * A fresh run id: `R-YYYYMMDD-HHMMSS-xxxx` (UTC), sortable by start time.
 * @param {object} ctx
 */
export function newRunId(ctx) {
  const stamp = ctx.now().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
  return `R-${stamp}-${crypto.randomBytes(2).toString('hex')}`;
}

// ---------------------------------------------------------------------------------------------
// events

/**
 * Append an activity event to today's feed. Best effort: a full disk must not break the operation
 * that is being logged.
 * @param {object} ctx
 * @param {{actor?: string, kind?: string, ticket?: string|null, run?: string|null, text?: string}} event
 * @returns {object} the event written
 */
export function appendEvent(ctx, { actor = 'system', kind = 'system', ticket = null, run = null, text = '' }) {
  const now = ctx.now();
  const event = { ts: now.toISOString(), actor, kind, ticket, run, text };
  try {
    fs.mkdirSync(ctx.dir('events'), { recursive: true });
    fs.appendFileSync(path.join(ctx.dir('events'), `${localDate(now)}.jsonl`), `${JSON.stringify(event)}\n`);
  } catch {
    // advisory only
  }
  return event;
}

/**
 * The newest events, newest first.
 * @param {object} ctx
 * @param {number} limit
 */
export function readRecentEvents(ctx, limit) {
  let names;
  try {
    names = fs.readdirSync(ctx.dir('events')).filter((n) => n.endsWith('.jsonl')).sort().reverse();
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    const lines = readTail(path.join(ctx.dir('events'), name), 1_048_576).split('\n');
    for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
      if (!lines[i]) continue;
      try {
        out.push(JSON.parse(lines[i]));
      } catch {
        // skip a torn line
      }
    }
    if (out.length >= limit) break;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// control and dispatcher state

/**
 * The pause switch.
 * @param {object} ctx
 * @returns {{paused: boolean, reason: string|null, by: string|null, ts: string|null}}
 */
export function readControl(ctx) {
  let data = null;
  try {
    data = readJson(path.join(ctx.stateDir, 'control.json'));
  } catch {
    // a corrupt control file reads as "running" rather than wedging the factory
  }
  return { paused: false, reason: null, by: null, ts: null, ...(data ?? {}) };
}

/**
 * Pause or resume the factory.
 * @param {object} ctx
 * @param {{paused: boolean, reason?: string|null, by?: string}} change
 */
export function setControl(ctx, { paused, reason = null, by = 'cli' }) {
  const control = { paused: Boolean(paused), reason: paused ? reason : null, by, ts: nowIso(ctx) };
  writeJsonAtomic(path.join(ctx.stateDir, 'control.json'), control);
  appendEvent(ctx, {
    actor: by, kind: 'dispatcher',
    text: paused ? `factory paused${reason ? `: ${reason}` : ''}` : 'factory resumed',
  });
  return control;
}

/**
 * The rate-limit signal the StopFailure hook leaves in `state/signals/rate-limit.json` when any
 * session (a worker, or the CEO's own) is stopped by an API usage limit.
 * @param {object} ctx
 * @returns {{ts: string, type: string, session: string|null, role: string|null}|null} null when absent or unreadable
 */
export function readRateLimitSignal(ctx) {
  try {
    const signal = readJson(path.join(ctx.stateDir, 'signals', 'rate-limit.json'));
    return signal && Number.isFinite(Date.parse(signal.ts)) ? signal : null;
  } catch {
    return null;
  }
}

/**
 * Dispatcher bookkeeping (`state/dispatcher.json`).
 * @param {object} ctx
 */
export function readDispatcherState(ctx) {
  let data = null;
  try {
    data = readJson(path.join(ctx.stateDir, 'dispatcher.json'));
  } catch {
    // treated as empty; the next write replaces it
  }
  return { pid: null, started: null, heartbeat: null, active: [], last_action: null, backoff_until: null, runs_today: { date: null, count: 0 }, ...(data ?? {}) };
}

/**
 * Merge a patch (or the result of a function) into dispatcher.json.
 * @param {object} ctx
 * @param {object|((state: object) => object)} patch
 */
export function updateDispatcherState(ctx, patch) {
  return withLock(ctx, () => {
    const current = readDispatcherState(ctx);
    const next = { ...current, ...(typeof patch === 'function' ? patch(current) : patch) };
    writeJsonAtomic(path.join(ctx.stateDir, 'dispatcher.json'), next);
    return next;
  });
}

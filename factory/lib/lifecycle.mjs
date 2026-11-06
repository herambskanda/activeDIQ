// `factory up` / `factory down`: start and stop the board and the dispatcher as detached processes.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { ensureStateDirs, pidAlive, readJson, sleepSync } from './store.mjs';
import { FactoryError } from './errors.mjs';

const START_WAIT_MS = 6000;

const stateFile = (ctx, name) => path.join(ctx.stateDir, name);

function recordedPid(ctx, name) {
  try {
    const pid = readJson(stateFile(ctx, name))?.pid;
    return pidAlive(pid) ? pid : null;
  } catch {
    return null;
  }
}

/**
 * Start `bin/factory <args>` detached with stdout/stderr appended to state/<logName>.
 * @param {object} ctx
 * @param {string} binPath
 * @param {string|string[]} args
 * @param {string} logName
 * @param {Record<string, string>} [env] extra environment
 * @returns {number} the child's pid
 */
export function spawnDetached(ctx, binPath, args, logName, env = {}) {
  const fd = fs.openSync(stateFile(ctx, logName), 'a');
  try {
    const child = spawn(process.execPath, [binPath, ...[args].flat()], {
      cwd: ctx.root, detached: true, stdio: ['ignore', fd, fd],
      env: { ...process.env, ...env, FACTORY_HOME: ctx.home },
    });
    child.on('error', () => {});
    child.unref();
    return child.pid;
  } finally {
    fs.closeSync(fd);
  }
}

function waitFor(ctx, file, pid) {
  const deadline = Date.now() + START_WAIT_MS;
  while (Date.now() < deadline) {
    try {
      const data = readJson(stateFile(ctx, file));
      if (data?.pid === pid) return data;
    } catch {
      // being written
    }
    if (!pidAlive(pid)) return null;
    sleepSync(100);
  }
  return null;
}

/**
 * Start the board and the dispatcher, each detached with stdout/stderr in state/*.log.
 * Refuses to start a second copy of either.
 * @param {object} ctx
 * @param {string} binPath absolute path of bin/factory
 * @returns {{board: {pid: number, url: string}, dispatcher: {pid: number}}}
 */
export function up(ctx, binPath) {
  ensureStateDirs(ctx);
  const running = [['board', 'board.json'], ['dispatcher', 'dispatcher.json']]
    .map(([name, file]) => [name, recordedPid(ctx, file)])
    .filter(([, pid]) => pid);
  if (running.length) {
    throw new FactoryError(`already running: ${running.map(([n, p]) => `${n} (pid ${p})`).join(', ')}. Use "factory down" first.`);
  }
  const boardPid = spawnDetached(ctx, binPath, 'board', 'board.log');
  const dispatcherPid = spawnDetached(ctx, binPath, 'run', 'dispatcher.log');
  const board = waitFor(ctx, 'board.json', boardPid);
  const dispatcher = waitFor(ctx, 'dispatcher.json', dispatcherPid);
  if (!board) throw new FactoryError(`the board did not start; see ${stateFile(ctx, 'board.log')}`);
  if (!dispatcher) throw new FactoryError(`the dispatcher did not start; see ${stateFile(ctx, 'dispatcher.log')}`);
  return { board: { pid: boardPid, url: `http://${ctx.config.board.host}:${board.port}` }, dispatcher: { pid: dispatcherPid } };
}

/**
 * SIGTERM the board and the dispatcher. The dispatcher gives running workers time to finish.
 * @param {object} ctx
 * @returns {{board: number|null, dispatcher: number|null}} pids signalled (null: was not running)
 */
export function down(ctx) {
  const result = { board: null, dispatcher: null };
  for (const [name, file] of [['board', 'board.json'], ['dispatcher', 'dispatcher.json']]) {
    const pid = recordedPid(ctx, file);
    if (pid) {
      process.kill(pid, 'SIGTERM');
      result[name] = pid;
    }
  }
  return result;
}

const delay = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

async function waitUntil(fn, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = fn();
    if (value) return value;
    if (Date.now() >= deadline) return null;
    await delay(50);
  }
}

/**
 * Restart the board on the new code: SIGTERM the running one (it holds no workers and no state), wait
 * for its port to free up, start a detached replacement on the same port. Nothing running → nothing
 * started (`factory up` starts one).
 * @param {object} ctx
 * @param {string} binPath absolute path of bin/factory
 * @returns {Promise<{old: number, pid: number, port: number}|null>} null when no board was running
 */
export async function restartBoard(ctx, binPath) {
  const old = recordedPid(ctx, 'board.json');
  if (!old) return null;
  const port = readJson(stateFile(ctx, 'board.json'))?.port;
  process.kill(old, 'SIGTERM');
  if (!(await waitUntil(() => !pidAlive(old), 5000))) {
    try { process.kill(old, 'SIGKILL'); } catch { /* gone */ }
    await waitUntil(() => !pidAlive(old), 2000);
  }
  const pid = spawnDetached(ctx, binPath, port ? ['board', '--port', String(port)] : ['board'], 'board.log');
  const started = await waitUntil(() => {
    try { return readJson(stateFile(ctx, 'board.json'))?.pid === pid; } catch { return false; }
  }, START_WAIT_MS);
  if (!started) throw new FactoryError(`the board did not restart; see ${stateFile(ctx, 'board.log')}`);
  return { old, pid, port };
}

/**
 * `factory restart`: reload the dispatcher and the board on the code now on disk, keeping workers.
 * The dispatcher gets SIGUSR2 and does what it does when factory code lands on main (abort a merge
 * gate in flight, start a successor that adopts the running workers, restart the board, exit).
 * A dispatcher from before T-1336 has no SIGUSR2 handler and dies from the signal; its workers are
 * unaffected, so a replacement is started the same way `up` would.
 * @param {object} ctx
 * @param {string} binPath absolute path of bin/factory
 * @param {{timeoutMs?: number}} [opts]
 * @returns {Promise<{dispatcher: {old: number, pid: number}|null, board: {pid: number, port: number}|null, legacy: boolean}>}
 */
export async function restart(ctx, binPath, { timeoutMs = 120_000 } = {}) {
  ensureStateDirs(ctx);
  const old = recordedPid(ctx, 'dispatcher.json');
  if (!old) return { dispatcher: null, board: await restartBoard(ctx, binPath), legacy: false };
  const successor = () => {
    let s = null;
    try { s = readJson(stateFile(ctx, 'dispatcher.json')); } catch { /* being written */ }
    return s?.pid && s.pid !== old && pidAlive(s.pid) ? s : null;
  };
  process.kill(old, 'SIGUSR2');
  let next = await waitUntil(successor, 8000); // a reload with nothing in flight takes well under this
  let legacy = false;
  if (!next && !pidAlive(old)) { // killed by the signal: it predates the handler
    legacy = true;
    const pid = spawnDetached(ctx, binPath, ['run'], 'dispatcher.log');
    next = waitFor(ctx, 'dispatcher.json', pid);
    if (!next) throw new FactoryError(`the dispatcher did not start; see ${stateFile(ctx, 'dispatcher.log')}`);
  } else if (!next) {
    next = await waitUntil(successor, timeoutMs - 8000); // aborting a merge gate takes a while
    if (!next) throw new FactoryError(`the dispatcher (pid ${old}) did not hand over within ${Math.round(timeoutMs / 1000)} s; see ${stateFile(ctx, 'dispatcher.log')}`);
  }
  // The dispatcher restarts the board itself when it reloads (before it exits); a legacy one could not.
  let board = null;
  if (legacy) board = await restartBoard(ctx, binPath);
  else {
    try {
      const b = readJson(stateFile(ctx, 'board.json'));
      if (b?.pid && pidAlive(b.pid)) board = { pid: b.pid, port: b.port };
    } catch { /* being written */ }
  }
  return { dispatcher: { old, pid: next.pid }, board, legacy };
}

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

function spawnDetached(ctx, binPath, command, logName) {
  const fd = fs.openSync(stateFile(ctx, logName), 'a');
  try {
    const child = spawn(process.execPath, [binPath, command], {
      cwd: ctx.root, detached: true, stdio: ['ignore', fd, fd],
      env: { ...process.env, FACTORY_HOME: ctx.home },
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

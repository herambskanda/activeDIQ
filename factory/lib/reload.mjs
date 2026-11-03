// Self-reload (T-1336): the dispatcher and the board are long-lived node processes that load factory/
// code once. When factory code lands on main they must pick it up WITHOUT touching running workers
// (workers are detached and the next dispatcher adopts them). This module holds the pieces: has factory
// code changed between two commits, stop stale pre-merge gate children, hand over to a successor.
import fs from 'node:fs';
import path from 'node:path';
import { git } from './git.mjs';
import { pidAlive, readDispatcherState, readJson } from './store.mjs';
import { scratchRoot } from './premerge.mjs';
import { spawnDetached } from './lifecycle.mjs';

/** Directories under factory/ whose code a running process has loaded. */
export const RELOAD_DIRS = ['lib', 'bin', 'board'];

const delay = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

/** @param {string|null|undefined} sha */
export const shortSha = (sha) => (sha ? sha.slice(0, 12) : 'unknown');

/**
 * The commit the main branch points at, or null when it cannot be read (no repo, no commits).
 * @param {object} ctx
 * @returns {Promise<string|null>}
 */
export async function mainSha(ctx) {
  const r = await git(ctx.root, ['rev-parse', '--verify', '-q', `${ctx.config.dispatcher.main_branch}^{commit}`]);
  return r.code === 0 ? r.stdout.trim() : null;
}

/**
 * Whether the diff between two commits touches factory code (lib, bin or board).
 * @param {object} ctx
 * @param {string} from
 * @param {string} to
 * @returns {Promise<{changed: boolean, files: string[]}>} throws when git cannot compare the commits
 */
export async function factoryChange(ctx, from, to) {
  const rel = path.relative(ctx.root, ctx.home).split(path.sep).join('/');
  const specs = RELOAD_DIRS.map((d) => `${rel ? `${rel}/` : ''}${d}`);
  const r = await git(ctx.root, ['diff', '--name-only', from, to, '--', ...specs]);
  if (r.code !== 0) throw new Error(`git diff ${shortSha(from)}..${shortSha(to)} failed: ${r.stderr.trim()}`);
  const files = r.stdout.split('\n').filter(Boolean);
  return { changed: files.length > 0, files };
}

/**
 * Stop processes left running under the pre-merge scratch root (`worktree_root/.premerge`): a gate's
 * `make` that outlived the process that started it. Only called when no gate of this process is in
 * flight, so anything found there is stale. Linux only (reads /proc); elsewhere it finds nothing.
 * SIGTERM to the process group (gate commands run as group leaders), SIGKILL after `graceMs`.
 * @param {object} ctx
 * @param {{graceMs?: number}} [opts]
 * @returns {Promise<number[]>} pids found
 */
export async function stopStaleGateChildren(ctx, { graceMs = 3000 } = {}) {
  const scratch = scratchRoot(ctx);
  let names;
  try {
    names = fs.readdirSync('/proc');
  } catch {
    return [];
  }
  const found = [];
  for (const name of names) {
    if (!/^\d+$/.test(name) || Number(name) === process.pid) continue;
    try {
      const cwd = fs.readlinkSync(`/proc/${name}/cwd`);
      if (cwd === scratch || cwd.startsWith(scratch + path.sep)) found.push(Number(name));
    } catch {
      // gone, or not ours to inspect
    }
  }
  const send = (pid, signal) => {
    try { process.kill(-pid, signal); return; } catch { /* not a group leader */ }
    try { process.kill(pid, signal); } catch { /* already gone */ }
  };
  for (const pid of found) send(pid, 'SIGTERM');
  const deadline = Date.now() + graceMs;
  while (found.some((pid) => pidAlive(pid)) && Date.now() < deadline) await delay(50);
  for (const pid of found) if (pidAlive(pid)) send(pid, 'SIGKILL');
  return found;
}

/**
 * Start the replacement dispatcher, detached. `FACTORY_REPLACES` tells it to announce itself and then
 * wait for this process to exit before taking over (see `Dispatcher#awaitPredecessor`).
 * @param {object} ctx
 * @param {string} binPath bin/factory
 * @returns {number} the successor's pid
 */
export function spawnSuccessor(ctx, binPath) {
  return spawnDetached(ctx, binPath, ['run'], 'dispatcher.log', { FACTORY_REPLACES: String(process.pid) });
}

/**
 * Wait until the successor has loaded the new code and said so (`successor_ready` in dispatcher.json).
 * @param {object} ctx
 * @param {number} pid
 * @param {{timeoutMs?: number}} [opts]
 * @returns {Promise<boolean>} false when it died or never announced itself
 */
export async function awaitSuccessor(ctx, pid, { timeoutMs = 20_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (readDispatcherState(ctx).successor_ready === pid && pidAlive(pid)) return true;
    if (!pidAlive(pid)) return false;
    await delay(50);
  }
  return false;
}

/**
 * Successor side: announce readiness, then wait for the process it replaces to be gone.
 * @param {number} predecessor
 * @param {(patch: object) => void} announce writes `successor_ready` into dispatcher.json
 * @param {{timeoutMs?: number}} [opts]
 * @returns {Promise<boolean>} whether the predecessor is gone
 */
export async function awaitPredecessor(predecessor, announce, { timeoutMs = 60_000 } = {}) {
  announce({ successor_ready: process.pid });
  const deadline = Date.now() + timeoutMs;
  while (pidAlive(predecessor) && Date.now() < deadline) await delay(50);
  return !pidAlive(predecessor);
}

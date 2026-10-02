// Spawning headless Claude Code workers. The command line is the one in README "Worker launch".
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { FactoryError } from './errors.mjs';

/**
 * The claude executable (override with FACTORY_CLAUDE_BIN, e.g. for tests).
 * @param {NodeJS.ProcessEnv} [env]
 */
export function claudeBinary(env = process.env) {
  return env.FACTORY_CLAUDE_BIN || 'claude';
}

/**
 * Where a run's raw stdout / stderr go.
 * @param {object} ctx
 * @param {string} runId
 */
export function runFiles(ctx, runId) {
  const base = path.join(ctx.dir('runs'), runId);
  return { log: `${base}.log`, err: `${base}.err` };
}

/**
 * Argument vector for `claude`. Always `--strict-mcp-config`; `--mcp-config` only when the role has
 * one in `dispatcher.mcp_configs`; `--effort` always: the escalation
 * override if any, else the agent's frontmatter effort (user-level modelSettings would otherwise win).
 * @param {object} p
 * @param {object} p.config
 * @param {string} p.role
 * @param {string} p.prompt
 * @param {string} p.ticketId
 * @param {string|null} [p.effortOverride]
 * @param {string|null} [p.agentEffort] the agent's frontmatter effort
 * @param {string} [p.root] repo root, to resolve a relative mcp config path
 * @returns {string[]}
 */
export function buildWorkerArgs({ config, role, prompt, ticketId, effortOverride = null, agentEffort = null, root = process.cwd() }) {
  const d = config.dispatcher;
  const args = ['-p', prompt, '--agent', role];
  const effort = effortOverride ?? agentEffort;
  if (effort) args.push('--effort', effort);
  args.push(
    '--output-format', 'stream-json', '--verbose',
    '--permission-mode', d.permission_mode, '--permission-prompts', 'none',
    '--autocompact', String(config.context.budget_tokens),
    '--strict-mcp-config',
  );
  const mcp = d.mcp_configs?.[role];
  if (mcp) args.push('--mcp-config', path.resolve(root, mcp));
  args.push('--name', `${ticketId} · ${role}`);
  return args;
}

/**
 * Start a worker. stdout goes to `state/runs/<id>.log`, stderr to `<id>.err`; the child is not
 * piped, so it survives a dispatcher restart and can be adopted by the next one.
 * @param {object} ctx
 * @param {object} spec runId, ticketId, role, prompt, cwd, effortOverride, agentEffort
 * @param {(exit: {code: number|null, signal: string|null, error?: string}) => void} onExit
 * @returns {{child: import('node:child_process').ChildProcess, pid: number}}
 */
export function launchWorker(ctx, { runId, ticketId, role, prompt, cwd, effortOverride = null, agentEffort = null }, onExit) {
  const files = runFiles(ctx, runId);
  fs.mkdirSync(path.dirname(files.log), { recursive: true });
  const out = fs.openSync(files.log, 'a');
  const err = fs.openSync(files.err, 'a');
  const args = buildWorkerArgs({ config: ctx.config, role, prompt, ticketId, effortOverride, agentEffort, root: ctx.root });
  let child;
  try {
    child = spawn(claudeBinary(), args, {
      cwd,
      stdio: ['ignore', out, err],
      env: {
        ...process.env,
        FACTORY_HOME: ctx.home,
        FACTORY_TICKET: ticketId,
        FACTORY_RUN_ID: runId,
        FACTORY_ROLE: role,
        FACTORY_CONTEXT_BUDGET: String(ctx.config.context.budget_tokens),
      },
    });
  } finally {
    fs.closeSync(out);
    fs.closeSync(err);
  }
  let settled = false;
  const settle = (exit) => {
    if (settled) return;
    settled = true;
    onExit(exit);
  };
  child.on('error', (e) => settle({ code: null, signal: null, error: e.message }));
  child.on('exit', (code, signal) => settle({ code, signal }));
  if (!child.pid) {
    // spawn failed (ENOENT, bad cwd…): the 'error' event arrives later and must not reach the caller
    child.removeAllListeners();
    child.on('error', () => {});
    throw new FactoryError(`could not start "${claudeBinary()}" in ${cwd} (is claude on PATH?)`);
  }
  child.unref();
  return { child, pid: child.pid };
}

/**
 * Send a signal to a worker process; false when it is already gone.
 * @param {number} pid
 * @param {NodeJS.Signals} signal
 */
export function signalPid(pid, signal) {
  try {
    process.kill(pid, signal);
    return true;
  } catch {
    return false;
  }
}

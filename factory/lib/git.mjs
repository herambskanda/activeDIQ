// Thin git wrappers. Arguments are always an array (never a shell string); a non-zero exit is a
// result, not an exception, so callers can branch on it.
import { execFile } from 'node:child_process';

const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' };

/**
 * Run git asynchronously.
 * @param {string} cwd
 * @param {string[]} args
 * @param {{timeoutMs?: number}} [opts]
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
export function git(cwd, args, { timeoutMs = 60_000 } = {}) {
  return new Promise((resolve) => {
    execFile('git', args, { cwd, env: GIT_ENV, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (!err) return resolve({ code: 0, stdout, stderr });
      resolve({ code: typeof err.code === 'number' ? err.code : -1, stdout: stdout ?? '', stderr: stderr || err.message });
    });
  });
}

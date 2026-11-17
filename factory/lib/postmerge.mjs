// Post-merge verification (T-2xxx, step 2 of the merge-queue throughput fix). Once `ci-fast` became
// the blocking pre-merge gate, the full `ci-full` suite moved here: it runs on `main` itself, after
// merges land, in a scratch worktree so it never touches the shared checkout. It reports only a
// finding `ci-full` did not already have the last time this ran — never a block, never a revert. The
// dispatcher decides when to call it (cooldown, "has main moved") and what to do with a report
// (an event, nothing else); this module only runs the command and does the finding diff.
import fs from 'node:fs';
import path from 'node:path';
import { FactoryError } from './errors.mjs';
import {
  addDetached, assertTreeIntact, dropWorktree, extractFindings, gateDir, newFindings, readLog, runLogged, runTag, scratchRoot,
} from './premerge.mjs';

export const POST_MERGE_VERIFY_DEFAULTS = Object.freeze({
  enabled: false,
  argv: ['make', '-k', 'ci-full'],
  timeout_minutes: 150,
  // How long to wait after one verify run ends before the next one may start, even if main moved
  // again in the meantime — a merge burst should not queue up a verify run per merge.
  cooldown_minutes: 15,
  // A finding `main` did not have before is a regression nobody owns until someone is told. When on, the
  // dispatcher also opens one P0 ticket for it (never more than one open at a time); the board event
  // is posted either way. Off = the original notice-only behaviour.
  raise_ticket: false,
});

/**
 * The effective settings (config.json `dispatcher.post_merge_verify` over the defaults).
 * @param {object} config
 */
export function postMergeVerifySettings(config) {
  const s = { ...POST_MERGE_VERIFY_DEFAULTS, ...(config.dispatcher?.post_merge_verify ?? {}) };
  if (!Array.isArray(s.argv) || !s.argv.length || s.argv.some((a) => typeof a !== 'string')) {
    throw new FactoryError('dispatcher.post_merge_verify.argv must be a non-empty array of strings');
  }
  if (typeof s.timeout_minutes !== 'number' || !(s.timeout_minutes > 0)) {
    throw new FactoryError('dispatcher.post_merge_verify.timeout_minutes must be a positive number');
  }
  if (!Number.isInteger(s.cooldown_minutes) || s.cooldown_minutes < 0) {
    throw new FactoryError('dispatcher.post_merge_verify.cooldown_minutes must be a whole number of at least 0');
  }
  if (typeof s.raise_ticket !== 'boolean') {
    throw new FactoryError('dispatcher.post_merge_verify.raise_ticket must be true or false');
  }
  return s;
}

function knownFile(ctx) { return path.join(gateDir(ctx), 'postmerge-known.json'); }

/**
 * The sha and findings `runPostMergeVerify` last recorded, or null before it has ever run.
 * @param {object} ctx
 * @returns {{sha: string, findings: Map<string, number>}|null}
 */
export function readKnownFindings(ctx) {
  try {
    const raw = JSON.parse(fs.readFileSync(knownFile(ctx), 'utf8'));
    return { sha: raw.sha, findings: new Map(raw.findings) };
  } catch {
    return null;
  }
}

function writeKnownFindings(ctx, sha, findings) {
  const dir = gateDir(ctx);
  fs.mkdirSync(dir, { recursive: true });
  const file = knownFile(ctx);
  const tmp = `${file}.${runTag()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ sha, findings: [...findings] }));
  fs.renameSync(tmp, file);
}

/**
 * Run `ci-full` on `mainSha` in a scratch worktree and report the findings it did not have the last
 * time this ran (whatever sha that was). Always records this run's findings as the new "known" set
 * once it finishes, whether or not anything new showed up — so a reported finding is reported once,
 * not every run until someone fixes it, and a fix is not specially announced either: this is a
 * notice board, not a dashboard.
 *
 * Throws only when the run itself could not produce a verdict (timeout, stop, worktree failure); the
 * caller should treat that as "try again next time", the same as the pre-merge gate does.
 * @param {object} ctx
 * @param {object} settings
 * @param {string} mainSha
 * @param {{signal?: AbortSignal}} [opts]
 * @returns {Promise<{sha: string, previousSha: string|null, code: number, newFindings: string[], log: string}>}
 */
export async function runPostMergeVerify(ctx, settings, mainSha, { signal } = {}) {
  const run = runTag();
  const dir = path.join(scratchRoot(ctx), `verify-${mainSha.slice(0, 12)}-${run}`);
  const log = path.join(gateDir(ctx), `verify-${mainSha.slice(0, 12)}-${run}.log`);
  const identity = await addDetached(ctx, dir, mainSha);
  try {
    const ran = await runLogged(settings.argv, dir, log, { timeoutMs: settings.timeout_minutes * 60_000, signal });
    if (ran.aborted) throw new FactoryError(`post-merge verify: the run on ${mainSha.slice(0, 12)} was stopped (${log})`);
    if (ran.timedOut) throw new FactoryError(`post-merge verify: ${settings.argv.join(' ')} on ${mainSha.slice(0, 12)} timed out after ${settings.timeout_minutes} minutes (${log})`);
    assertTreeIntact(dir, identity, log);
    const head = extractFindings(readLog(log), [fs.realpathSync(dir), dir]);
    const known = readKnownFindings(ctx);
    const fresh = known ? newFindings(known.findings, head).map((f) => f.key) : [];
    writeKnownFindings(ctx, mainSha, head);
    return { sha: mainSha, previousSha: known?.sha ?? null, code: ran.code, newFindings: fresh, log };
  } finally {
    await dropWorktree(ctx, dir);
  }
}

// The pre-merge gate (T-0941). Before the dispatcher merges a finished ticket it builds the merge
// result in a throw-away worktree and runs the configured CI command (`make -k ci`) there.
//
//  - Green: merge.
//  - Red while `main` is green: refuse; every finding is new.
//  - Red while `main` is red too: run the same command on `main` (cached per main commit) and
//    refuse only if the merge result has a finding `main` does not have. Findings are compared as a
//    multiset keyed by a position-independent text, so an old finding that moves a line does not
//    count and a new one in a red job cannot hide behind the old ones.
//
// Nothing here edits the repository's checks; it only reads their output. Every subprocess runs
// from an argument array, never a shell.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { git } from './git.mjs';
import { FactoryError } from './errors.mjs';
import { branchName } from './worktree.mjs';

const ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;
const MAX_LOG_BYTES = 256 * 1024 * 1024;

export const PRE_MERGE_DEFAULTS = Object.freeze({
  enabled: false,
  argv: ['make', '-k', 'ci'],
  timeout_minutes: 120,
  // T-1067: a cheap check that runs on the merge result BEFORE the full command. Each branch passes
  // the migration-numbering test on its own; two parallel branches that both add 00NN only collide
  // once merged, and a red `main` can hide that failure from the ratchet. `null` = off.
  // { dir: 'migrations', argv: ['go', 'test', …], timeout_seconds: 120 }
  numbering: null,
});

/**
 * The effective gate settings (config.json `dispatcher.pre_merge` over the defaults).
 * @param {object} config
 */
export function preMergeSettings(config) {
  const s = { ...PRE_MERGE_DEFAULTS, ...(config.dispatcher?.pre_merge ?? {}) };
  if (!Array.isArray(s.argv) || !s.argv.length || s.argv.some((a) => typeof a !== 'string')) {
    throw new FactoryError('dispatcher.pre_merge.argv must be a non-empty array of strings');
  }
  const n = s.numbering;
  if (n !== null && n !== undefined) {
    if (typeof n.dir !== 'string' || !n.dir || !Array.isArray(n.argv) || !n.argv.length || n.argv.some((a) => typeof a !== 'string')) {
      throw new FactoryError('dispatcher.pre_merge.numbering needs a "dir" string and a non-empty "argv" array of strings');
    }
    s.numbering = { timeout_seconds: 120, ...n };
  }
  return s;
}

// ---- findings ----------------------------------------------------------------------------

const stripTimes = (s) => s.replace(/\(\d+(?:\.\d+)?s\)/g, '').replace(/\b\d+(?:\.\d+)?(?:ms|s)\b/g, '').replace(/\s+/g, ' ').trim();

/**
 * Turn one output line into a finding key, or null when the line is not a finding. A key never
 * contains a line or column number, a duration or the worktree path.
 * @param {string} raw
 * @param {string[]} [roots] directories to replace with `<root>`
 * @returns {string|null}
 */
export function findingKey(raw, roots = []) {
  let line = raw.replace(ANSI, '').replace(/\r$/, '');
  for (const root of roots) line = line.split(root).join('<root>');
  line = line.trim();
  if (!line) return null;

  // A failed make target: `make: *** [tools/ci/ci.mk:42: fitness-profiles] Error 1`.
  const mk = /^make(?:\[\d+\])?: \*\*\* \[(?:[^\]]*?:\d+: )?([^\]\s]+)\]/.exec(line);
  if (mk) return `FAILED ${mk[1]}`;
  if (/^make(?:\[\d+\])?: /.test(line)) return null;

  // A positioned finding: `path/file.go:12:3: message` (Go, vet, fitness checks, test log lines).
  const pos = /^([\w@.+~/<>-]+\.[A-Za-z][\w]*):\d+(?::\d+)?:\s*(.*)$/.exec(line);
  if (pos) return `${pos[1]}: ${stripTimes(pos[2])}`;

  const failTest = /^--- FAIL: (\S+)/.exec(line);
  if (failTest) return `FAIL ${failTest[1]}`;
  const failPkg = /^FAIL\s+(\S+)/.exec(line);
  if (failPkg) return `FAIL ${failPkg[1]}`;

  // Position-free fitness findings: the ADR checks end their rule with "fitness function)".
  if (/fitness function\)/.test(line)) return stripTemp(stripTimes(line));
  // `fitness-xyz: FAIL: …` / `fitness-xyz: [P1] …` but not a pass line, a progress line or a count summary.
  if (/^fitness-[\w-]+:/.test(line)) {
    if (FITNESS_QUIET.some((re) => re.test(line))) return null;
    return stripTemp(stripTimes(line));
  }

  // A rule tag followed by a colon: `<where> <check> [<rule>]: <message>` (fleetca, reports, keycustody,
  // the bound-test failures; `<where>` is path:line) and `<check> <where> [<rule>]: <message>` (audit,
  // tenancy, domainkeys; `<where>` is a table, a role or a path). Only the line numbers come out.
  const tagged = /^(\S.*?) (\[[^\]]+\]): (\S.*)$/.exec(line);
  if (tagged) return stripTemp(`${tagged[1].replace(/(\.[A-Za-z]\w*):\d+(?::\d+)?(?=\s|$)/g, '$1')} ${tagged[2]}: ${stripTimes(tagged[3])}`);

  // A finding on a whole file or object, no line: `docs/x.md: message`, `go.mod: F4 (ADR-0001 rule 4): …`,
  // `attr.sid: FF-SP6 [pslit] …`, `<scenario>/<case>: message`. The subject must look like a path or a
  // dotted name, so `go: downloading …` and `Error: …` are not findings.
  const bare = /^((?=[^\s:]*(?:\/|\.[A-Za-z]))[\w@.+~/<>-]+): (\S.*)$/.exec(line);
  if (bare) return stripTemp(`${bare[1]}: ${stripTimes(bare[2])}`);
  return null;
}

// Progress and summary lines of the fitness tools; the same on `main` and the branch unless the change
// activates a check, which must not read as a new finding.
const FITNESS_QUIET = [
  /:\s*ok\b/,
  /\bok \(/,
  /^fitness-[\w-]+:\s+activation table \(/,
  /\b\d+ (?:violation|problem|record)/,
  /^fitness-[\w-]+:\s+(?:inactive|pending)\b/,
  /^fitness-[\w-]+:\s+PostgreSQL \d+/,
  /\b\d+ of \d+ checks active\b/,
  /\bAG1-AG8 (?:in)?active\b/,
];

// Scratch directories differ on every run.
const stripTemp = (s) => s.replace(/\/tmp\/[\w.-]+/g, '<tmp>');

/**
 * Count the findings in a CI log.
 * @param {string} text
 * @param {string[]} [roots]
 * @returns {Map<string, number>}
 */
export function extractFindings(text, roots = []) {
  const found = new Map();
  const add = (key) => { if (key !== null) found.set(key, (found.get(key) ?? 0) + 1); };
  let block = null; // the id of a `<id> … : FAIL` header whose indented lines are its violations
  for (const raw of text.split('\n')) {
    const line = raw.replace(ANSI, '').replace(/\r$/, '');
    if (block !== null) {
      if (/^\s{2,}\S/.test(line)) {
        let body = line.trim().replace(/^[-*]\s+/, '');
        for (const root of roots) body = body.split(root).join('<root>');
        add(stripTemp(`FAIL ${block}: ${stripTimes(body)}`));
        continue;
      }
      block = null;
    }
    const header = FAIL_BLOCK.map((re) => re.exec(line.trim())).find(Boolean);
    if (header && !/^\s/.test(line)) { block = header[1]; continue; }
    add(findingKey(raw, roots));
  }
  return found;
}

// A result that lists its violations indented under a heading: agent-host prints
// `A4  <what>: FAIL` and host prints `FAIL   <case>`, each then one indented line per violation.
const FAIL_BLOCK = [/^(\S+)\s+.*: FAIL$/, /^FAIL\s+(\S+)$/];

/**
 * The findings in `head` that `base` does not account for (multiset difference).
 * @param {Map<string, number>} base
 * @param {Map<string, number>} head
 * @returns {{key: string, extra: number, known: number}[]} sorted by key; `known` is how many copies the base already has
 */
export function newFindings(base, head) {
  const out = [];
  for (const [key, count] of head) {
    const known = base.get(key) ?? 0;
    const extra = count - known;
    if (extra > 0) out.push({ key, extra, known });
  }
  return out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

// ---- running the command -------------------------------------------------------------------

/**
 * Run argv in cwd, both streams to `logFile`. Kills the whole process group on timeout or abort.
 * @returns {Promise<{code: number, timedOut: boolean, aborted: boolean}>}
 */
export function runLogged(argv, cwd, logFile, { timeoutMs, signal, env = process.env } = {}) {
  fs.mkdirSync(path.dirname(logFile), { recursive: true });
  const fd = fs.openSync(logFile, 'w');
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(argv[0], argv.slice(1), { cwd, env: { ...env, CI: '1' }, stdio: ['ignore', fd, fd], detached: true });
    } catch (err) {
      fs.closeSync(fd);
      reject(new FactoryError(`could not start ${argv[0]}: ${err.message}`));
      return;
    }
    let timedOut = false;
    let aborted = false;
    const killGroup = (sig) => { try { process.kill(-child.pid, sig); } catch { /* already gone */ } };
    const stop = () => { killGroup('SIGTERM'); setTimeout(() => killGroup('SIGKILL'), 15_000).unref(); };
    const timer = timeoutMs ? setTimeout(() => { timedOut = true; stop(); }, timeoutMs) : null;
    const onAbort = () => { aborted = true; stop(); };
    signal?.addEventListener('abort', onAbort, { once: true });
    child.on('error', (err) => {
      clearTimeout(timer); signal?.removeEventListener('abort', onAbort); fs.closeSync(fd);
      reject(new FactoryError(`could not start ${argv[0]}: ${err.message}`));
    });
    child.on('close', (code) => {
      clearTimeout(timer); signal?.removeEventListener('abort', onAbort); fs.closeSync(fd);
      resolve({ code: code ?? -1, timedOut, aborted });
    });
  });
}

function readLog(file) {
  const size = fs.statSync(file).size;
  if (size <= MAX_LOG_BYTES) return fs.readFileSync(file, 'utf8');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(MAX_LOG_BYTES);
    fs.readSync(fd, buf, 0, MAX_LOG_BYTES, size - MAX_LOG_BYTES);
    return buf.toString('utf8');
  } finally { fs.closeSync(fd); }
}

function gateDir(ctx) { return path.join(ctx.stateDir, 'premerge'); }
function scratchRoot(ctx) { return path.resolve(ctx.root, ctx.config.dispatcher.worktree_root, '.premerge'); }

async function addDetached(ctx, dir, ref) {
  fs.rmSync(dir, { recursive: true, force: true });
  await git(ctx.root, ['worktree', 'prune']);
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  const added = await git(ctx.root, ['worktree', 'add', '--detach', dir, ref]);
  if (added.code !== 0) throw new FactoryError(`pre-merge: git worktree add failed: ${added.stderr.trim()}`);
}

async function dropWorktree(ctx, dir) {
  await git(ctx.root, ['worktree', 'remove', '--force', dir]);
  fs.rmSync(dir, { recursive: true, force: true });
  await git(ctx.root, ['worktree', 'prune']);
}

/**
 * The findings (and exit code) of the gate command on `main`, cached per commit and argv.
 * @returns {Promise<{code: number, findings: Map<string, number>, log: string, cached: boolean}>}
 */
async function baseline(ctx, settings, mainSha, { signal }) {
  const tag = crypto.createHash('sha256').update(JSON.stringify(settings.argv)).digest('hex').slice(0, 10);
  const cache = path.join(gateDir(ctx), `baseline-${mainSha.slice(0, 12)}-${tag}.json`);
  try {
    const hit = JSON.parse(fs.readFileSync(cache, 'utf8'));
    return { code: hit.code, findings: new Map(hit.findings), log: hit.log, cached: true };
  } catch { /* no usable cache */ }
  const dir = path.join(scratchRoot(ctx), `base-${mainSha.slice(0, 12)}`);
  const log = path.join(gateDir(ctx), `baseline-${mainSha.slice(0, 12)}-${tag}.log`);
  await addDetached(ctx, dir, mainSha);
  try {
    const ran = await runLogged(settings.argv, dir, log, { timeoutMs: settings.timeout_minutes * 60_000, signal });
    if (ran.timedOut || ran.aborted) throw new FactoryError(`pre-merge: the baseline run on main ${ran.timedOut ? 'timed out' : 'was stopped'} (${log})`);
    const findings = extractFindings(readLog(log), [fs.realpathSync(dir), dir]);
    fs.writeFileSync(cache, JSON.stringify({ code: ran.code, findings: [...findings], log }));
    return { code: ran.code, findings, log, cached: false };
  } finally {
    await dropWorktree(ctx, dir);
  }
}

// ---- migration numbering (T-1067) -----------------------------------------------------------------

const NUMBERED = /^(\d+)(_.+)$/;

/**
 * Which migrations the branch added with a number `main` already uses, and the free number each
 * should take. Pure: `mainNames` are the file names on main, `addedNames` the ones the branch added.
 * @param {string[]} mainNames
 * @param {string[]} addedNames
 * @returns {{from: string, to: string}[]}
 */
export function planRenumber(mainNames, addedNames) {
  const num = (n) => { const m = NUMBERED.exec(n); return m ? { n: Number(m[1]), width: m[1].length, rest: m[2] } : null; };
  const used = new Set();
  let max = 0;
  for (const name of mainNames) { const p = num(name); if (p) { used.add(p.n); max = Math.max(max, p.n); } }
  const parsed = addedNames.map((name) => ({ name, p: num(name) })).filter((x) => x.p).sort((a, b) => a.p.n - b.p.n || (a.name < b.name ? -1 : 1));
  const out = [];
  const taken = new Set(used);
  for (const { name, p } of parsed) {
    if (!taken.has(p.n)) { taken.add(p.n); max = Math.max(max, p.n); continue; }
    max += 1;
    taken.add(max);
    out.push({ from: name, to: `${String(max).padStart(p.width, '0')}${p.rest}` });
  }
  return out;
}

/**
 * Run the numbering check on the merge result in `dir`. Returns a `blocked` verdict when it fails
 * (naming the number to renumber to), or null when it passes. A check that cannot run throws.
 */
async function checkMigrationNumbering(ctx, settings, dir, mainSha, ticket, { signal }) {
  const cfg = settings.numbering;
  const log = path.join(gateDir(ctx), `${ticket.id}-${mainSha.slice(0, 12)}-numbering.log`);
  const started = Date.now();
  const ran = await runLogged(cfg.argv, dir, log, { timeoutMs: cfg.timeout_seconds * 1000, signal });
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  if (ran.timedOut) throw new FactoryError(`pre-merge: the migration-numbering check on ${ticket.id} timed out after ${cfg.timeout_seconds} s (${log})`);
  if (ran.aborted) throw new FactoryError(`pre-merge: the run for ${ticket.id} was stopped (${log})`);
  if (ran.code === 0) { fs.appendFileSync(log, `\n# migration-numbering check passed in ${seconds} s\n`); return { seconds: Number(seconds) }; }

  const names = async (ref) => (await git(dir, ['ls-tree', '--name-only', ref, `${cfg.dir}/`])).stdout.split('\n').map((l) => path.basename(l.trim())).filter((n) => n.endsWith('.sql'));
  const added = (await git(dir, ['diff', '--name-only', '--diff-filter=A', mainSha, 'HEAD', '--', `${cfg.dir}/`])).stdout
    .split('\n').map((l) => path.basename(l.trim())).filter((n) => n.endsWith('.sql'));
  const plan = planRenumber(await names(mainSha), added);
  const findings = plan.map((r) => `renumber ${cfg.dir}/${r.from} to ${r.to}`);
  const branch = branchName(ticket.id);
  return {
    refused: true, status: 'blocked', mode: 'migration-numbering', findings, renumber: plan, log, seconds,
    summary: plan.length
      ? `${branch} adds migration number(s) that ${ctx.config.dispatcher.main_branch} already uses (or that now leave a gap): ${plan.map((r) => `${r.from} → ${r.to}`).join(', ')}`
      : `the migration-numbering check fails on the merge of ${branch} into ${ctx.config.dispatcher.main_branch} but the branch adds no clashing file; read the log (a gap or a changed file name?)`,
  };
}

/**
 * Run the gate for a finished ticket.
 *
 * Statuses: `pass` (merge may proceed), `blocked` (the branch adds a finding or breaks a green
 * job; `findings` names them), `conflict` (main moved and the branch no longer merges cleanly).
 * Anything that stops the gate from judging (a timeout, a worktree failure, a stop request)
 * throws, so the merge is never allowed by accident.
 *
 * @param {object} ctx
 * @param {{id: string, title: string}} ticket
 * @param {{signal?: AbortSignal, argv?: string[]}} [opts] `argv` overrides the configured command (dry runs)
 * @returns {Promise<{status: 'pass'|'blocked'|'conflict', mode?: string, findings: string[], summary: string, log?: string, baseLog?: string}>}
 */
export async function runPreMergeGate(ctx, ticket, { signal, argv } = {}) {
  const settings = preMergeSettings(ctx.config);
  if (argv) settings.argv = argv;
  const main = ctx.config.dispatcher.main_branch;
  const mainSha = (await git(ctx.root, ['rev-parse', '--verify', '-q', `refs/heads/${main}`])).stdout.trim();
  if (!mainSha) throw new FactoryError(`pre-merge: branch "${main}" not found`);
  const branch = branchName(ticket.id);
  if ((await git(ctx.root, ['rev-parse', '--verify', '-q', `refs/heads/${branch}`])).code !== 0) {
    throw new FactoryError(`pre-merge: branch "${branch}" not found`);
  }
  const dir = path.join(scratchRoot(ctx), `cand-${ticket.id}`);
  const log = path.join(gateDir(ctx), `${ticket.id}-${mainSha.slice(0, 12)}.log`);
  await addDetached(ctx, dir, mainSha);
  try {
    const merged = await git(dir, ['merge', '--no-ff', '--no-edit', '-m', `Merge ${ticket.id}: ${ticket.title}`, branch]);
    if (merged.code !== 0) {
      const detail = (merged.stdout + merged.stderr).trim().split('\n').slice(0, 6).join(' | ');
      await git(dir, ['merge', '--abort']);
      return { status: 'conflict', findings: [], summary: detail };
    }
    let numberingSeconds = null;
    if (settings.numbering) {
      const checked = await checkMigrationNumbering(ctx, settings, dir, mainSha, ticket, { signal });
      if (checked.refused) { const { refused, ...verdict } = checked; return verdict; }
      numberingSeconds = checked.seconds;
    }
    const withTiming = (text) => (numberingSeconds === null ? text : `${text}; migration numbering checked in ${numberingSeconds} s`);
    const ran = await runLogged(settings.argv, dir, log, { timeoutMs: settings.timeout_minutes * 60_000, signal });
    if (ran.timedOut) throw new FactoryError(`pre-merge: ${settings.argv.join(' ')} on ${ticket.id} timed out after ${settings.timeout_minutes} minutes (${log})`);
    if (ran.aborted) throw new FactoryError(`pre-merge: the run for ${ticket.id} was stopped (${log})`);
    if (ran.code === 0) return { status: 'pass', mode: 'green', findings: [], summary: withTiming(`${settings.argv.join(' ')} passed on the merge result`), log };

    const head = extractFindings(readLog(log), [fs.realpathSync(dir), dir]);
    const base = await baseline(ctx, settings, mainSha, { signal });
    const fresh = newFindings(base.code === 0 ? new Map() : base.findings, head);
    const total = (m) => [...m.values()].reduce((a, b) => a + b, 0);
    const lines = fresh.map((f) => (f.known ? `${f.key}  (${f.extra} more than the ${f.known} on ${main})` : f.extra > 1 ? `${f.key}  (${f.extra} times)` : f.key));
    if (base.code === 0) {
      return {
        status: 'blocked', mode: 'main-green', findings: lines, log, baseLog: base.log,
        summary: `${main} is green and ${settings.argv.join(' ')} fails on the merge result${lines.length ? '' : ' with no recognisable finding line; read the log'}`,
      };
    }
    if (!head.size) {
      return {
        status: 'blocked', mode: 'unrecognised', findings: [], log, baseLog: base.log,
        summary: `${settings.argv.join(' ')} fails on the merge result and the log has no recognisable finding line, so it cannot be compared with the red ${main}; read the log`,
      };
    }
    if (fresh.length) {
      return {
        status: 'blocked', mode: 'new-findings', findings: lines, log, baseLog: base.log,
        summary: `${main} is red (${total(base.findings)} known findings) and the merge result adds ${lines.length} that ${main} does not have`,
      };
    }
    return {
      status: 'pass', mode: 'ratchet', findings: [], log, baseLog: base.log,
      summary: withTiming(`${main} is red (${total(base.findings)} known findings); the merge result adds none (${total(head)} findings, all already on ${main})`),
    };
  } finally {
    await dropWorktree(ctx, dir);
  }
}

/**
 * Text for the reopen note: what to fix and where the logs are.
 * @param {Awaited<ReturnType<typeof runPreMergeGate>>} gate
 * @param {string} main
 */
export function blockedNote(gate, main) {
  if (gate.mode === 'migration-numbering') {
    const moves = (gate.renumber ?? []).map((r) => `git mv migrations/${r.from} migrations/${r.to}`);
    return [
      `the pre-merge gate refused the merge: ${gate.summary}.`,
      moves.length ? `Renumber to ${gate.renumber.map((r) => r.to.split('_')[0]).join(', ')}: ${moves.join(' ; ')}. Then fix every reference to the old number (tests, comments, docs, ticket notes) and re-run go test ./migrations/ -run TestMigrationNumbersAreUniqueAndContiguous.` : null,
      `Merge ${main} into the branch first so you see the numbers it uses now; if ${main} moves again before you advance, the gate will name the next free number again.`,
      `Log: ${gate.log}.`,
    ].filter(Boolean).join(' ');
  }
  const shown = gate.findings.slice(0, 25);
  const more = gate.findings.length - shown.length;
  return [
    `the pre-merge gate refused the merge: ${gate.summary}.`,
    shown.length ? `New findings (key = check and message, positions removed):\n${shown.map((l) => `  - ${l}`).join('\n')}${more > 0 ? `\n  … and ${more} more` : ''}` : null,
    `Logs: ${gate.log}${gate.baseLog ? ` · ${main}: ${gate.baseLog}` : ''}.`,
    `Fix the cause in the code (never weaken, skip or edit the check to get green), merge ${main} into the branch, run the failing job locally, and advance again.`,
  ].filter(Boolean).join(' ');
}

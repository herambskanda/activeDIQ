// ADR-0012 fitness function `fitness-merge-order` (T-1707).
//   M5  history invariant: no `Merge T-x:` commit on first-parent main precedes the landing of a dependency.
//   M1-M4  bound tests: named node tests that must exist, run and pass once the stacking code (T-1706) has landed.
// A part whose subject has not landed is reported pending, which is not a pass; a landed part that is
// missing, failed or skipped fails the build.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';

/**
 * Grandfathering: history up to and including this first-parent commit (main when ADR-0012 was ratified)
 * predates the rule. It holds real violations (dependents merged before their dependency, and ticket
 * numbers that were reused), so M5 judges only the Merge commits after it. A deviation from the ADR's
 * "list in the script": one boundary instead of a list, so the rule also covers future commits by default.
 */
export const GRANDFATHER_UNTIL = '6cb96d24d8d21c7bb211c6b296ad777fb9a02a44';

/** The bound tests: id -> test file and the title prefix every subtest of that part carries. */
export const BOUND = Object.freeze([
  { id: 'M1', file: 'factory/test/stacking.test.mjs', prefix: 'M1' },
  { id: 'M2', file: 'factory/test/stacking.test.mjs', prefix: 'M2' },
  { id: 'M3', file: 'factory/test/stacking.test.mjs', prefix: 'M3' },
  { id: 'M4', file: 'factory/test/premerge.test.mjs', prefix: 'M4' },
]);

const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 256 << 20 }).trim();
const gitOk = (cwd, args) => spawnSync('git', args, { cwd, stdio: 'ignore' }).status === 0;

/** Dependencies per ticket from `<stateDir>/tickets/*.json`; null when the state is absent. */
export function loadDependencies(stateDir) {
  const dir = path.join(stateDir, 'tickets');
  if (!fs.existsSync(dir)) return null;
  const deps = new Map();
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.json')) continue;
    const t = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    deps.set(t.id, Array.isArray(t.depends_on) ? t.depends_on : []);
  }
  return deps;
}

/**
 * M5. Walk `git log --first-parent <main>` oldest first and check every `Merge T-x:` commit: each
 * dependency D of T-x needs (a) a `Merge D:` commit earlier on the line, or (b) no `factory/D` branch
 * (spec/docs/no-diff tickets), or (c) D's branch tip an ancestor of the commit main had just before
 * T-x's merge (hand merge or fast-forward). Using the first parent rather than the merge commit itself
 * is deliberate: a stacked T-x contains D's commits, so "ancestor of the merge" would pass a dependent
 * that landed before its dependency.
 * @returns {{violations: {id: string, dep: string, sha: string}[], checked: number}}
 */
export function checkHistory({ repo, main = 'main', deps, grandfatherUntil = GRANDFATHER_UNTIL }) {
  const log = git(repo, ['log', '--first-parent', '--reverse', '--format=%H%x09%P%x09%s', main]);
  const merges = new Map(); // ticket id -> index on the first-parent line
  const rows = [];
  log.split('\n').filter(Boolean).forEach((line, i) => {
    const [sha, parents, subject] = line.split('\t');
    const m = /^Merge (T-\d+):/.exec(subject ?? '');
    if (m && !merges.has(m[1])) merges.set(m[1], i);
    rows.push({ sha, parent: parents.split(' ')[0], id: m?.[1] });
  });
  const violations = [];
  let checked = 0;
  const boundary = rows.findIndex((r) => r.sha === grandfatherUntil);
  rows.forEach((row, i) => {
    if (!row.id || merges.get(row.id) !== i || i <= boundary) return;
    checked++;
    for (const dep of deps.get(row.id) ?? []) {
      if (merges.has(dep) && merges.get(dep) < i) continue; // (a)
      const tip = spawnSync('git', ['rev-parse', '-q', '--verify', `refs/heads/factory/${dep}^{commit}`], { cwd: repo, encoding: 'utf8' });
      if (tip.status !== 0) { if (!merges.has(dep)) continue; } // (b) no branch and no merge commit: spec/docs/no-diff
      else if (row.parent && gitOk(repo, ['merge-base', '--is-ancestor', tip.stdout.trim(), row.parent])) continue; // (c)
      violations.push({ id: row.id, dep, sha: row.sha });
    }
  });
  return { violations, checked };
}

/** True once the stacking implementation (T-1706) is in factory/lib. */
export function stackingLanded(repo) {
  const dir = path.join(repo, 'factory', 'lib');
  return fs.readdirSync(dir).some((f) => f.endsWith('.mjs') && f !== 'fitness-merge-order.mjs' && fs.readFileSync(path.join(dir, f), 'utf8').includes('max_depth'));
}

/** A nested `node --test` must not inherit the parent runner's context, or it reports into the parent. */
const childEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'NODE_TEST_CONTEXT'));

/** M1-M4: run each bound test file once and judge every part by its subtests' TAP lines. */
export function checkBound(repo, landed) {
  const results = [];
  const byFile = new Map();
  for (const b of BOUND) byFile.set(b.file, [...(byFile.get(b.file) ?? []), b]);
  for (const [file, parts] of byFile) {
    const abs = path.join(repo, file);
    const run = fs.existsSync(abs)
      ? spawnSync(process.execPath, ['--test', '--test-reporter=tap', abs], { cwd: repo, encoding: 'utf8', maxBuffer: 256 << 20, env: childEnv() })
      : null;
    const lines = run ? run.stdout.split('\n') : [];
    for (const p of parts) {
      const own = lines.filter((l) => new RegExp(`^\\s*(not ok|ok) \\d+ - ${p.prefix}\\b`).test(l));
      const failed = own.filter((l) => /^\s*not ok/.test(l) || /# (SKIP|TODO)/i.test(l));
      if (own.length && !failed.length) results.push({ id: p.id, state: 'pass', note: `${own.length} subtest(s)` });
      else if (own.length) results.push({ id: p.id, state: 'fail', note: `failed or skipped: ${failed.join(' | ').trim()}` });
      else results.push({ id: p.id, state: landed ? 'fail' : 'pending', note: `no ${p.prefix} subtest in ${file}${landed ? ' (stacking has landed: it must exist)' : ' (T-1706 has not landed)'}` });
    }
  }
  return results;
}

/** Where the factory state lives: $FACTORY_STATE_DIR, this tree, or the primary checkout of the repository. */
export function findStateDir(repo) {
  const candidates = [process.env.FACTORY_STATE_DIR, path.join(repo, 'factory', 'state'),
    path.join(path.dirname(path.resolve(repo, git(repo, ['rev-parse', '--git-common-dir']))), 'factory', 'state')];
  return candidates.find((c) => c && fs.existsSync(path.join(c, 'tickets'))) ?? null;
}

export function run(repo, { out = console.log, main = 'main' } = {}) {
  let failed = false;
  const landed = stackingLanded(repo);
  for (const r of checkBound(repo, landed)) {
    out(`${r.id}: ${r.state}${r.state === 'pending' ? ' (pending, not a pass)' : ''} - ${r.note}`);
    if (r.state === 'fail') failed = true;
  }
  const stateDir = findStateDir(repo);
  const deps = stateDir && loadDependencies(stateDir);
  if (!deps) out('M5: inactive (no factory/state/tickets here: set FACTORY_STATE_DIR) - not a pass');
  else {
    const { violations, checked } = checkHistory({ repo, main, deps });
    for (const v of violations) { out(`M5: FAIL ${v.id} (${v.sha.slice(0, 9)}) merged before its dependency ${v.dep} reached main`); failed = true; }
    if (!violations.length) out(`M5: pass - ${checked} Merge commit(s) on first-parent ${main}`);
  }
  return failed ? 1 : 0;
}

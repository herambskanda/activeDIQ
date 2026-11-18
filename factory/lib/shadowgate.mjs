// The shadow gate (plan step 4, "tiered gate"). A second, faster merge check that runs BESIDE the
// real pre-merge gate and decides nothing: after the real gate has judged a ticket, this module
// replays the same merge (same `main`, same branch head) in its own scratch worktree, runs the
// cheap checks that every ticket gets plus only the tests the change can affect, times every step
// and writes one record per ticket to `state/shadow/results.jsonl`. The dispatcher never reads a
// record to merge, refuse or reopen anything. After a week of records `summarizeShadow` answers the
// one question that matters before the real gate is replaced: did the fast checks ever pass a
// ticket the full gate refused (a "miss")?
//
//  Tier 1  every ticket           lint, generated-code freshness, API lint, architecture rules
//                                 (`fitness`), secrets scan
//  Tier 2  only what changed      Go tests for the changed packages and every package that imports
//                                 them; web lint/tests/Playwright when web/ changed; vuln scan when
//                                 dependencies changed; workflow check when CI files changed
//  Tier 3  on a schedule          the full `make ci-full` on main — already `post_merge_verify`
//
// Every subprocess runs from an argument array, never a shell.
import fs from 'node:fs';
import path from 'node:path';
import { FactoryError } from './errors.mjs';
import { git } from './git.mjs';
import { branchName } from './worktree.mjs';
import {
  addDetached, assertTreeIntact, dropWorktree, extractFindings, gateDir, readLog, runLogged, runTag, scratchRoot,
} from './premerge.mjs';

/** Placeholder in a step's argv that expands to the affected Go packages. */
export const GO_PACKAGES = '{go_packages}';

export const SHADOW_GATE_DEFAULTS = Object.freeze({
  enabled: false,
  step_timeout_minutes: 60,
  steps: Object.freeze([
    // Tier 1: every ticket.
    { tier: 1, name: 'lint-go', when: 'always', argv: ['make', 'lint-go'] },
    { tier: 1, name: 'gen-check', when: 'always', argv: ['make', '-k', 'gen-check', 'gen-modules-check', 'gen-api-check'] },
    { tier: 1, name: 'lint-api', when: 'always', argv: ['make', 'lint-api'] },
    { tier: 1, name: 'fitness', when: 'always', argv: ['make', '-k', 'fitness'] },
    { tier: 1, name: 'secrets-scan', when: 'always', argv: ['make', 'secrets-scan'] },
    // Tier 2: only what the change can affect.
    { tier: 2, name: 'go-test', when: 'go', argv: ['go', 'test', '-count=1', '-p', '3', '-timeout', '30m', GO_PACKAGES] },
    { tier: 2, name: 'lint-web', when: 'web', argv: ['make', 'lint-web'] },
    { tier: 2, name: 'test-web', when: 'web', argv: ['make', 'test-web'] },
    { tier: 2, name: 'e2e', when: 'web', argv: ['npm', '--prefix', 'web', 'run', 'e2e'] },
    { tier: 2, name: 'vuln-scan', when: 'deps', argv: ['make', 'vuln-scan'] },
    { tier: 2, name: 'workflows-check', when: 'workflows', argv: ['make', 'workflows-check'] },
  ]),
});

const WHEN = new Set(['always', 'go', 'web', 'deps', 'workflows']);

/**
 * The effective settings (config.json `dispatcher.shadow_gate` over the defaults).
 * @param {object} config
 */
export function shadowGateSettings(config) {
  const s = { ...SHADOW_GATE_DEFAULTS, ...(config.dispatcher?.shadow_gate ?? {}) };
  if (typeof s.step_timeout_minutes !== 'number' || !(s.step_timeout_minutes > 0)) {
    throw new FactoryError('dispatcher.shadow_gate.step_timeout_minutes must be a positive number');
  }
  if (!Array.isArray(s.steps) || !s.steps.length) throw new FactoryError('dispatcher.shadow_gate.steps must be a non-empty array');
  const names = new Set();
  for (const step of s.steps) {
    if (!step || typeof step.name !== 'string' || !/^[\w.-]+$/.test(step.name)) throw new FactoryError('every dispatcher.shadow_gate step needs a "name" (letters, digits, . _ -)');
    if (names.has(step.name)) throw new FactoryError(`dispatcher.shadow_gate has two steps named "${step.name}"`);
    names.add(step.name);
    if (!Array.isArray(step.argv) || !step.argv.length || step.argv.some((a) => typeof a !== 'string')) throw new FactoryError(`dispatcher.shadow_gate step "${step.name}" needs a non-empty "argv" array of strings`);
    if (!WHEN.has(step.when)) throw new FactoryError(`dispatcher.shadow_gate step "${step.name}": "when" must be one of ${[...WHEN].join(', ')}`);
    if (![1, 2].includes(step.tier)) throw new FactoryError(`dispatcher.shadow_gate step "${step.name}": "tier" must be 1 or 2`);
  }
  return s;
}

// ---- what did the change touch? ---------------------------------------------------------------------

// Paths that cannot change what a Go test or a build sees: prose, the knowledge base, agent memory,
// the factory's own runtime and prototypes (the same roots the baseline cache already trusts).
const NO_CODE_ROOTS = ['knowledge/', '.claude/', 'factory/', 'garage/', 'docs/'];
// Paths that can change every package: dependencies, the build files and the CI scripts.
const WIDE = [/^go\.(mod|sum|work)$/, /^Makefile$/, /\.mk$/, /^tools\/ci\//, /^\.golangci/, /^\.github\//];
const DEPS = [/^go\.(mod|sum)$/, /^web\/package(-lock)?\.json$/, /^tools\/ci\/vuln-allow\.json$/, /^tools\/vulntools\//];
const WORKFLOWS = [/^\.github\//, /^tools\/ci\/workflows-check/];

const isProse = (p) => p.endsWith('.md') || p === 'LICENSE';
const matches = (list, p) => list.some((re) => re.test(p));

/**
 * Classify the changed paths of one merge.
 * @param {string[]} changed repo-relative paths
 * @returns {{go: boolean, web: boolean, deps: boolean, workflows: boolean, wide: boolean, goFiles: string[]}}
 *   `go`: some Go package must be tested; `wide`: so must all of them (the change reaches every package
 *   or no package owns it, so the safe answer is the whole tree); `goFiles`: the changed paths that
 *   some package may own.
 */
export function classifyChange(changed) {
  const out = { go: false, web: false, deps: false, workflows: false, wide: false, goFiles: [] };
  for (const p of changed) {
    if (p.startsWith('web/')) { out.web = true; if (matches(DEPS, p)) out.deps = true; continue; }
    if (matches(DEPS, p)) out.deps = true;
    if (matches(WORKFLOWS, p)) out.workflows = true;
    if (NO_CODE_ROOTS.some((r) => p.startsWith(r)) || isProse(p)) continue;
    out.go = true;
    if (matches(WIDE, p)) out.wide = true; else out.goFiles.push(p);
  }
  return out;
}

/**
 * The Go packages a change can affect: every package that owns a changed file, plus every package
 * that imports one of them directly, in a test or an external test, or through other packages.
 * A changed file no package owns (an OpenAPI file, a proto, packaging) cannot be traced, so the
 * answer is `null`, meaning "all of them".
 *
 * @param {string[]} goFiles changed paths from {@link classifyChange}
 * @param {{path: string, dir: string, imports: string[]}[]} pkgs the module's packages (`dir` repo-relative, '' = root)
 * @returns {string[]|null} import paths, sorted; `null` = test everything
 */
export function affectedGoPackages(goFiles, pkgs) {
  const byDir = new Map(pkgs.map((p) => [p.dir, p]));
  const changedPkgs = new Set();
  for (const file of goFiles) {
    let dir = path.posix.dirname(file);
    if (dir === '.') dir = '';
    let owner = null;
    for (;;) {
      if (byDir.has(dir)) { owner = byDir.get(dir); break; }
      if (!dir) break;
      dir = path.posix.dirname(dir);
      if (dir === '.') dir = '';
    }
    if (!owner) return null;
    // A non-Go file in a package directory (testdata, SQL, golden files) still belongs to that package.
    changedPkgs.add(owner.path);
  }
  const importers = new Map();
  for (const p of pkgs) for (const imp of p.imports) {
    if (!importers.has(imp)) importers.set(imp, []);
    importers.get(imp).push(p.path);
  }
  const seen = new Set(changedPkgs);
  const queue = [...changedPkgs];
  while (queue.length) {
    for (const up of importers.get(queue.pop()) ?? []) if (!seen.has(up)) { seen.add(up); queue.push(up); }
  }
  return [...seen].sort();
}

/** Parse `go list -f '{{.ImportPath}}|{{.Dir}}|{{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}'`. */
export function parseGoList(text, root) {
  const rootReal = root.replace(/\/+$/, '');
  return text.split('\n').filter(Boolean).map((line) => {
    const [pkg, dir, imps] = line.split('|');
    const rel = path.posix.relative(rootReal, dir);
    return { path: pkg, dir: rel === '.' ? '' : rel, imports: [...new Set((imps ?? '').split(/\s+/).filter(Boolean))] };
  });
}

/**
 * Decide which steps a change needs.
 * @param {object[]} steps configured steps
 * @param {ReturnType<typeof classifyChange>} cls
 * @param {string[]|null} goPackages affected packages, `null` = all
 * @returns {{step: object, argv: string[]|null, reason: string}[]} `argv: null` = skipped, `reason` says why
 */
export function planSteps(steps, cls, goPackages) {
  return steps.map((step) => {
    const run = step.when === 'always' || cls[step.when === 'go' ? 'go' : step.when];
    if (!run) return { step, argv: null, reason: `no ${step.when} change` };
    if (!step.argv.includes(GO_PACKAGES)) return { step, argv: step.argv, reason: step.when === 'always' ? 'every ticket' : `${step.when} changed` };
    const pkgs = cls.wide || goPackages === null ? ['./...'] : goPackages;
    if (!pkgs.length) return { step, argv: null, reason: 'no Go package affected' };
    return {
      step, argv: step.argv.flatMap((a) => (a === GO_PACKAGES ? pkgs : [a])),
      reason: pkgs[0] === './...' ? 'whole module (the change reaches every package)' : `${pkgs.length} affected package(s)`,
    };
  });
}

// ---- comparing with the real gate ----------------------------------------------------------------

/**
 * How the shadow verdict relates to the real gate's.
 *   agree        both passed, or both refused and the shadow found every finding the real gate did
 *   MISS         the real gate refused and the shadow passed or missed a finding: the dangerous case
 *   false-alarm  the shadow failed and the real gate passed on a green main
 *   inconclusive the shadow failed, the real gate passed but `main` was red (findings already on main
 *                are not new), so this says nothing either way
 *   n/a          the real gate did not judge the code (conflict, numbering refusal, no recognisable finding)
 * @param {{status: string, mode?: string, findings?: string[]}} old verdict of the real gate
 * @param {{ok: boolean, findings: string[]}} shadow
 */
export function compareVerdicts(old, shadow) {
  if (old.status === 'pass') {
    if (shadow.ok) return { agreement: 'agree', caught: null };
    return { agreement: old.mode === 'ratchet' ? 'inconclusive' : 'false-alarm', caught: null };
  }
  if (old.status !== 'blocked' || !old.log || !old.findings?.length || old.mode === 'unrecognised') return { agreement: 'n/a', caught: null };
  const have = new Set(shadow.findings);
  const strip = (f) => f.replace(/\s+\(\d+ (?:times|more than the \d+ on \S+)\)$/, '');
  const caught = old.findings.filter((f) => have.has(strip(f))).length;
  return { agreement: caught === old.findings.length && !shadow.ok ? 'agree' : 'MISS', caught: `${caught}/${old.findings.length}` };
}

// ---- running it ---------------------------------------------------------------------------------

export function shadowDir(ctx) { return path.join(ctx.stateDir, 'shadow'); }
export function resultsFile(ctx) { return path.join(shadowDir(ctx), 'results.jsonl'); }

export function readShadowResults(ctx) {
  let text;
  try { text = fs.readFileSync(resultsFile(ctx), 'utf8'); } catch { return []; }
  return text.split('\n').filter(Boolean).flatMap((l) => { try { return [JSON.parse(l)]; } catch { return []; } });
}

function appendResult(ctx, record) {
  fs.mkdirSync(shadowDir(ctx), { recursive: true });
  fs.appendFileSync(resultsFile(ctx), `${JSON.stringify(record)}\n`);
}

async function changedFiles(dir, base) {
  const diff = await git(dir, ['diff', '--name-only', '-z', base, 'HEAD']);
  if (diff.code !== 0) throw new FactoryError(`shadow gate: git diff failed: ${diff.stderr.trim()}`);
  return diff.stdout.split('\0').filter(Boolean);
}

async function goPackages(dir, log, timeoutMs, signal) {
  const listFile = `${log}.golist`;
  const fmt = '{{.ImportPath}}|{{.Dir}}|{{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}';
  try {
    const ran = await runLogged(['go', 'list', '-e', '-f', fmt, './...'], dir, listFile, { timeoutMs, signal });
    if (ran.code !== 0) return null; // cannot trace imports: test everything
    return parseGoList(fs.readFileSync(listFile, 'utf8'), fs.realpathSync(dir));
  } catch {
    return null; // no Go toolchain here: the safe answer is the whole module
  }
}

/**
 * Replay one ticket's merge and run the tiered checks. Never throws for a failing check; throws only
 * when it could not even set up (no branch, worktree failure) or was aborted, and the caller logs that.
 * One record is appended to `results.jsonl` either way.
 *
 * @param {object} ctx
 * @param {{id: string, title: string}} ticket
 * @param {{mainSha: string, branchSha?: string, verdict: object, signal?: AbortSignal}} opts the `main`
 *   commit and ticket head the real gate judged, and its verdict
 */
export async function runShadowGate(ctx, ticket, { mainSha, branchSha, verdict, signal }) {
  const settings = shadowGateSettings(ctx.config);
  const started = Date.now();
  const run = runTag();
  const dir = path.join(scratchRoot(ctx), `shadow-${ticket.id}-${run}`);
  const logDir = path.join(shadowDir(ctx), 'logs', `${ticket.id}-${mainSha.slice(0, 12)}-${run}`);
  const record = {
    at: new Date().toISOString(), ticket: ticket.id, mainSha, old: { status: verdict.status, mode: verdict.mode ?? null, findings: verdict.findings ?? [] },
  };
  const identity = await addDetached(ctx, dir, mainSha);
  try {
    const head = branchSha ?? branchName(ticket.id);
    const merged = await git(dir, ['merge', '--no-ff', '--no-edit', '-m', `Merge ${ticket.id}: ${ticket.title}`, head]);
    if (merged.code !== 0) {
      await git(dir, ['merge', '--abort']);
      const rec = { ...record, status: 'error', error: 'the merge conflicts with main', agreement: 'n/a', steps: [], seconds: Math.round((Date.now() - started) / 1000) };
      appendResult(ctx, rec);
      return rec;
    }
    const changed = await changedFiles(dir, mainSha);
    const cls = classifyChange(changed);
    let pkgs = null;
    if (cls.go && !cls.wide) {
      const listed = await goPackages(dir, path.join(logDir, 'plan'), 5 * 60_000, signal);
      pkgs = listed ? affectedGoPackages(cls.goFiles, listed) : null;
    }
    const plan = planSteps(settings.steps, cls, pkgs);
    record.changedFiles = changed.length;
    record.affectedPackages = cls.wide || pkgs === null ? 'all' : pkgs.length;
    record.steps = [];
    const findings = new Set();
    let ok = true;
    for (const { step, argv, reason } of plan) {
      if (!argv) { record.steps.push({ name: step.name, tier: step.tier, skipped: true, reason }); continue; }
      const log = path.join(logDir, `${step.name}.log`);
      const t0 = Date.now();
      const ran = await runLogged(argv, dir, log, { timeoutMs: settings.step_timeout_minutes * 60_000, signal });
      if (ran.aborted) throw new FactoryError(`shadow gate: ${step.name} on ${ticket.id} was stopped`);
      assertTreeIntact(dir, identity, log);
      const found = ran.code === 0 ? new Map() : extractFindings(readLog(log), [fs.realpathSync(dir), dir]);
      for (const k of found.keys()) findings.add(k);
      if (ran.code !== 0 || ran.timedOut) ok = false;
      record.steps.push({ name: step.name, tier: step.tier, code: ran.code, timedOut: ran.timedOut, seconds: Math.round((Date.now() - t0) / 1000), reason, log, findings: found.size });
    }
    record.status = ok ? 'pass' : 'fail';
    record.findings = [...findings];
    record.seconds = Math.round((Date.now() - started) / 1000);
    Object.assign(record, compareVerdicts({ ...verdict, findings: verdict.findings }, { ok, findings: record.findings }));
    appendResult(ctx, record);
    return record;
  } finally {
    await dropWorktree(ctx, dir);
  }
}

/** Record that a ticket was judged by the real gate but the shadow could not run (busy, error). */
export function recordShadowSkip(ctx, ticket, reason, verdict) {
  appendResult(ctx, { at: new Date().toISOString(), ticket: ticket.id, status: 'skipped', error: reason, agreement: 'n/a', old: { status: verdict.status, mode: verdict.mode ?? null }, steps: [] });
}

/**
 * The week-end report: agreement counts, every miss, and measured time per step against the real gate.
 * @param {object[]} records from {@link readShadowResults}
 */
export function summarizeShadow(records) {
  const judged = records.filter((r) => r.status === 'pass' || r.status === 'fail');
  const count = (k) => judged.filter((r) => r.agreement === k).length;
  const secs = judged.map((r) => r.seconds).sort((a, b) => a - b);
  const pct = (p) => (secs.length ? secs[Math.min(secs.length - 1, Math.floor(p * secs.length))] : null);
  const stepTime = new Map();
  for (const r of judged) for (const s of r.steps ?? []) {
    if (s.skipped) continue;
    const e = stepTime.get(s.name) ?? { name: s.name, tier: s.tier, runs: 0, total: 0, fails: 0 };
    e.runs += 1; e.total += s.seconds; if (s.code !== 0) e.fails += 1;
    stepTime.set(s.name, e);
  }
  return {
    tickets: records.length, judged: judged.length, skipped: records.length - judged.length,
    agree: count('agree'), misses: judged.filter((r) => r.agreement === 'MISS'),
    falseAlarms: count('false-alarm'), inconclusive: count('inconclusive'), notComparable: count('n/a'),
    seconds: { median: pct(0.5), p90: pct(0.9), mean: secs.length ? Math.round(secs.reduce((a, b) => a + b, 0) / secs.length) : null },
    steps: [...stepTime.values()].map((e) => ({ ...e, mean: Math.round(e.total / e.runs) })).sort((a, b) => b.total - a.total),
  };
}

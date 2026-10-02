// Shared test helpers. Every test builds a throw-away factory in a temp dir: the real
// factory/state is never touched.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ensureStateDirs, openStore } from '../lib/store.mjs';

export const REAL_FACTORY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const FIXTURES = path.join(REAL_FACTORY, 'test', 'fixtures');
export const FAKE_CLAUDE = path.join(FIXTURES, 'fake-claude');
export const FACTORY_BIN = path.join(REAL_FACTORY, 'bin', 'factory');

/**
 * The model/effort policy every fixture factory runs under: a deliberately multi-rung policy
 * (escalation-only rungs above the everyday ones) so the ladder, the escalation-only rule and
 * override semantics are exercised whatever the live `factory/config.json` allows. The live policy
 * is pinned separately in policy.test.mjs.
 */
export const TEST_MODELS = Object.freeze({
  allowed: { opus: ['medium', 'high', 'xhigh', 'max'], sonnet: ['high', 'xhigh'] },
  escalation_only: { opus: ['xhigh', 'max'] },
  escalation_roles: ['principal-engineer'],
  effort_ladder: { sonnet: ['high', 'xhigh'], opus: ['medium', 'high', 'xhigh'] },
});

/** role → [model, effort] for the fixture agents; the defaults mirror the live roster (all high). */
export const AGENTS = {
  'factory-director': ['opus', 'high'],
  'project-manager': ['opus', 'high'],
  'product-manager': ['opus', 'high'],
  'solution-architect': ['opus', 'high'],
  'security-architect': ['opus', 'high'],
  'principal-engineer': ['opus', 'high'],
  'backend-engineer': ['sonnet', 'high'],
  'directory-engineer': ['sonnet', 'high'],
  'code-reviewer': ['sonnet', 'high'],
  'qa-verifier': ['sonnet', 'high'],
  'docs-writer': ['sonnet', 'high'],
  'test-engineer': ['sonnet', 'high'],
};

export function writeAgent(agentsDir, name, model, effort, extra = '') {
  fs.mkdirSync(agentsDir, { recursive: true });
  const effortLine = effort ? `effort: ${effort}\n` : '';
  fs.writeFileSync(path.join(agentsDir, `${name}.md`), `---\nname: ${name}\ndescription: >\n  Fixture agent ${name}.\n  Second line.\nmodel: ${model}\n${effortLine}${extra}---\n\nYou are ${name}.\n`);
}

/**
 * Build a temp factory: <root>/factory (FACTORY_HOME) with the real config (with the TEST_MODELS policy swapped in) and templates,
 * fixture agents in <root>/.claude/agents, and a controllable clock.
 * @param {{config?: (c: object) => void, agents?: Record<string, [string, string]>}} [opts]
 */
export function makeFactory({ config, agents = AGENTS } = {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'factory-test-')));
  const home = path.join(root, 'factory');
  fs.mkdirSync(home, { recursive: true });
  fs.cpSync(path.join(REAL_FACTORY, 'templates'), path.join(home, 'templates'), { recursive: true });
  const cfg = JSON.parse(fs.readFileSync(path.join(REAL_FACTORY, 'config.json'), 'utf8'));
  cfg.models = structuredClone(TEST_MODELS);
  cfg.ceo.notify.macos = false;
  cfg.dispatcher.worktree_root = '.worktrees';
  cfg.dispatcher.min_free_disk_gb = 0; // the host's free disk must not gate fixture launches
  config?.(cfg);
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify(cfg, null, 2));
  for (const [name, [model, effort]] of Object.entries(agents)) writeAgent(path.join(root, '.claude', 'agents'), name, model, effort);

  const ctx = openStore(home);
  ensureStateDirs(ctx);
  const clock = { ms: new Date(2026, 9, 2, 10, 0, 0).getTime() }; // local 10:00, before the digest hour
  ctx.now = () => new Date(clock.ms);
  clock.advance = (ms) => { clock.ms += ms; };
  clock.set = (iso) => { clock.ms = Date.parse(iso); };
  return { root, home, ctx, clock, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

/** Same as makeFactory, with the real wall clock (for tests that spawn processes). */
export function makeLiveFactory(opts) {
  const f = makeFactory(opts);
  f.ctx.now = () => new Date();
  return f;
}

export function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

/** Make <root> a git repo on main with one commit (so worktrees are possible). */
export function initRepo(root) {
  git(root, 'init', '-q', '-b', 'main');
  git(root, 'config', 'user.name', 'Test');
  git(root, 'config', 'user.email', 'test@example.com');
  fs.writeFileSync(path.join(root, 'README.md'), '# test\n');
  fs.writeFileSync(path.join(root, '.gitignore'), 'factory/state/\nfactory/handoffs/\n.worktrees/\n');
  git(root, 'add', '-A');
  git(root, 'commit', '-q', '-m', 'initial');
}

/** Commit everything in a working directory. */
export function commitAll(cwd, message) {
  git(cwd, 'add', '-A');
  git(cwd, '-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-q', '-m', message);
}

export async function waitFor(fn, { timeoutMs = 15000, intervalMs = 50, what = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

export function ticketInput(overrides = {}) {
  return {
    title: 'A ticket', type: 'build', owner: 'backend-engineer', priority: 'P2',
    summary: 'Do the thing.', acceptance: ['Given a, when b, then c.'], ...overrides,
  };
}

/**
 * Point the launcher at the fake claude for the duration of a test.
 * @param {Record<string, string>} [extra] FAKE_CLAUDE_* settings
 * @returns {() => void} restore the environment
 */
export function useFakeClaude(extra = {}) {
  const set = { FACTORY_CLAUDE_BIN: FAKE_CLAUDE, FAKE_CLAUDE_FACTORY_BIN: FACTORY_BIN, ...extra };
  const before = Object.fromEntries(Object.keys(set).map((k) => [k, process.env[k]]));
  Object.assign(process.env, set);
  return () => {
    for (const [k, v] of Object.entries(before)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
}

/** The argument-log lines the fake claude wrote, parsed. */
export function readArgsLog(file) {
  try {
    return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

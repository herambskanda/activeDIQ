// Shared helpers for factory hooks. Standard library only; every helper fails soft.
// Hooks must be fast and must never break a session: on any internal error they exit 0.

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

/** Read and parse the hook payload from stdin. Returns {} on any problem. */
export function readInput() {
  try {
    const raw = fs.readFileSync(0, 'utf8');
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

/** Run fn; on any exception exit 0 silently so the session is never disturbed. */
export function safely(fn) {
  try {
    fn();
  } catch (err) {
    if (process.env.FACTORY_HOOK_DEBUG) process.stderr.write(`[factory hook] ${err?.stack || err}\n`);
    process.exit(0);
  }
}

/** Emit a JSON object on stdout (the hook's structured output). */
export function emit(obj) {
  process.stdout.write(JSON.stringify(obj));
}

/** Inject text into the model's context for the given event. */
export function addContext(eventName, text) {
  emit({ hookSpecificOutput: { hookEventName: eventName, additionalContext: text } });
}

const projectDir = () => process.env.CLAUDE_PROJECT_DIR || process.cwd();

/**
 * Resolve the factory home exactly like the CLI: $FACTORY_HOME, else the main checkout of the
 * git repository (so worktrees share one state store), else <project>/factory.
 */
export function factoryHome() {
  if (process.env.FACTORY_HOME) return process.env.FACTORY_HOME;
  try {
    const common = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
      cwd: projectDir(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 1500,
    }).trim();
    const candidate = path.join(path.dirname(common), 'factory');
    if (fs.existsSync(path.join(candidate, 'config.json'))) return candidate;
  } catch { /* not a git repo */ }
  return path.join(projectDir(), 'factory');
}

/** Repository root of the main checkout (parent of the factory home). */
export const repoRoot = () => path.dirname(factoryHome());

let cachedConfig;
/** factory/config.json, or sane defaults. */
export function loadConfig() {
  if (cachedConfig) return cachedConfig;
  try {
    cachedConfig = JSON.parse(fs.readFileSync(path.join(factoryHome(), 'config.json'), 'utf8'));
  } catch {
    cachedConfig = {};
  }
  return cachedConfig;
}

export const stateDir = (...parts) => path.join(factoryHome(), 'state', ...parts);

export function readJson(file, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

/** Atomic JSON write (tmp + rename). Creates parent directories. */
export function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, file);
}

/** Append one event to the factory activity feed. */
export function appendEvent({ actor, kind, ticket = null, run = null, text }) {
  const ts = new Date().toISOString();
  const file = stateDir('events', `${ts.slice(0, 10)}.jsonl`);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, JSON.stringify({ ts, actor, kind, ticket, run, text }) + '\n');
}

/** Context about who is running: worker (dispatched) or interactive session. */
export function who(input = {}) {
  const ticket = process.env.FACTORY_TICKET || null;
  return {
    ticket,
    run: process.env.FACTORY_RUN_ID || null,
    role: process.env.FACTORY_ROLE || input.agent_type || 'interactive',
    kind: ticket ? 'worker' : 'interactive',
    isSubagent: Boolean(input.agent_id),
  };
}

/** Context budget settings: env override, then config, then the 300k default. */
export function budget() {
  const ctx = loadConfig().context || {};
  const tokens = Number(process.env.FACTORY_CONTEXT_BUDGET) || ctx.budget_tokens || 300000;
  return {
    tokens,
    warn: (ctx.warn_pct ?? 70) / 100,
    checkpoint: (ctx.checkpoint_pct ?? 85) / 100,
    critical: (ctx.critical_pct ?? 95) / 100,
  };
}

/**
 * Transcript to measure: the subagent's own transcript when the call comes from a subagent
 * (verified layout: <dir>/<session_id>/subagents/agent-<agent_id>.jsonl), else the session's.
 */
export function transcriptFor(input) {
  if (!input.transcript_path) return null;
  if (input.agent_id && input.session_id) {
    const sub = path.join(path.dirname(input.transcript_path), input.session_id, 'subagents', `agent-${input.agent_id}.jsonl`);
    if (fs.existsSync(sub)) return sub;
  }
  return input.transcript_path;
}

/** Read up to `max` bytes from the end of a file as lines (first partial line dropped). */
export function tailLines(file, max = 512 * 1024) {
  try {
    const { size } = fs.statSync(file);
    const start = Math.max(0, size - max);
    const fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    fs.closeSync(fd);
    const lines = buf.toString('utf8').split('\n');
    if (start > 0) lines.shift();
    return lines.filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Current context size in tokens, from the latest assistant message's usage:
 * input + cache_creation + cache_read + output. Returns null when unknown.
 */
export function contextTokens(transcript) {
  if (!transcript) return null;
  for (const max of [512 * 1024, 4 * 1024 * 1024]) {
    const lines = tailLines(transcript, max);
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i];
      if (!line.includes('"usage"') || !line.includes('"assistant"')) continue;
      try {
        const entry = JSON.parse(line);
        const u = entry?.message?.usage;
        if (entry.type === 'assistant' && u) {
          return (u.input_tokens || 0) + (u.cache_creation_input_tokens || 0) +
            (u.cache_read_input_tokens || 0) + (u.output_tokens || 0);
        }
      } catch { /* partial or odd line */ }
    }
  }
  return null;
}

/** Small per-session scratch state for hooks (not part of the factory database). */
export function guardStatePath(key) {
  return path.join(os.tmpdir(), 'activediq-factory-guard', `${key.replace(/[^A-Za-z0-9_.-]/g, '_')}.json`);
}

/** macOS notification; no-op elsewhere or when disabled in config. */
export function notify(title, message) {
  if (process.platform !== 'darwin') return;
  if (loadConfig().ceo?.notify?.macos === false) return;
  try {
    const esc = (s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').slice(0, 200);
    execFileSync('osascript', ['-e', `display notification "${esc(message)}" with title "${esc(title)}"`], {
      stdio: 'ignore', timeout: 2000,
    });
  } catch { /* ignore */ }
}

export const short = (s, n = 100) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};

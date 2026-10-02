#!/usr/bin/env node
// PreToolUse guard: blocks destructive or policy-violating actions before they run.
// Blocking = exit code 2 with the reason on stderr (shown to the model, which adapts).
// High-precision rules only: a guard that cries wolf gets routed around.

import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { readInput, safely, who, repoRoot, appendEvent, short, readJson, stateDir, loadConfig } from './_common.mjs';

const SECRET_PATTERNS = [
  [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/, 'a private key'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'an AWS access key id'],
  [/\bgh[pousr]_[A-Za-z0-9]{36,}\b/, 'a GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{50,}\b/, 'a GitHub fine-grained token'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, 'a Slack token'],
  [/\bsk-ant-[A-Za-z0-9_-]{20,}\b/, 'an Anthropic API key'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/, 'a Google API key'],
];

const VERIFIER_WRITE_ALLOW = {
  'code-reviewer': ['.claude/agent-memory/code-reviewer/', 'knowledge/memory/'],
  'qa-verifier': ['.claude/agent-memory/qa-verifier/', 'knowledge/memory/', 'factory/demos/evidence/'],
};

safely(() => {
  const input = readInput();
  const me = who(input);
  const tool = input.tool_name || '';
  const t = input.tool_input || {};
  const reason = tool === 'Bash' ? checkBash(String(t.command || ''), me, input)
    : /^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool) ? checkWrite(t, me, input)
      : null;
  if (!reason) return;
  try {
    appendEvent({ actor: me.role, kind: 'system', ticket: me.ticket, run: me.run, text: `guard blocked ${tool}: ${short(reason, 120)}` });
  } catch { /* feed is best effort */ }
  process.stderr.write(`Blocked by factory guard: ${reason}`);
  process.exit(2);
});


/** @returns {string|null} reason to block */
function checkBash(cmd, me, input) {
  const c = cmd.replace(/\s+/g, ' ');

  // Catastrophic deletes: root, home, parent-of-repo.
  if (/\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(--\s+)?("|')?(\/|~|\$HOME|\/Users\/?[^/\s]*|\.\.)(\/)?("|')?(\s|$|\*)/.test(c)) {
    return 'refusing a recursive delete of a root, home or parent directory. Delete specific paths inside the repository instead.';
  }
  // Force pushes rewrite shared history.
  if (/\bgit\s+push\b.*(\s--force\b|\s-f\b|\s--force-with-lease\b|\s\+\S)/.test(c)) {
    return 'never force-push. If history must change, raise it with the factory-director.';
  }
  // Workers never push: merging is the dispatcher's job; publishing is a CEO-level act.
  if (me.kind === 'worker' && /\bgit\s+push\b/.test(c)) {
    return 'workers do not push. Commit on your ticket branch; the dispatcher merges after QA.';
  }
  // Code tickets commit only on their ticket branch. Non-code tickets (specs, docs, research)
  // work in the main checkout and commit their own files there, so code worktrees can see them.
  if (me.kind === 'worker' && /\bgit\s+commit\b/.test(c) && isCodeTicket(me.ticket)) {
    try {
      const branch = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
        cwd: input.cwd || process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 1500,
      }).trim();
      if (branch === 'main' || branch === 'master') {
        return `you are on ${branch}. Workers commit only on their ticket branch (factory/${me.ticket}).`;
      }
    } catch { /* not a repo: let git report it */ }
  }
  // Piping remote scripts into a shell is a supply-chain risk.
  if (/\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b/.test(c) || /\b(ba|z)?sh\s+<\(\s*(curl|wget)\b/.test(c)) {
    return 'do not pipe downloaded scripts into a shell. Download, inspect, and pin a version instead.';
  }
  // Credential stores.
  if (/(~|\$HOME|\/Users\/[^/\s]+)\/\.(ssh|aws|gnupg)\b/.test(c) && /\b(cat|less|more|head|tail|cp|scp|base64|xxd|strings)\b/.test(c)) {
    return 'reading credential stores (~/.ssh, ~/.aws, ~/.gnupg) is not allowed.';
  }
  // Factory state is a database: only the CLI writes it. (Reading it is fine.)
  const intoState = [
    /(>>?|\btee\b(\s+-a)?)\s*["']?[^\s;&|]*factory\/state(\/|\s|$)/, // redirect or tee into it
    /\bsed\s+(-[a-zA-Z]*i[a-zA-Z]*|--in-place)\b[^;&|]*factory\/state\//, // in-place edit
    /\b(rm|mv)\b[^;&|]*factory\/state(\/|\s|$)/, // remove or move
    /\bcp\b[^;&|]*\s["']?[^\s;&|]*factory\/state\/[^\s;&|]*["']?\s*($|[;&|])/, // copy into it
  ];
  if (intoState.some((re) => re.test(c))) {
    return 'factory/state is the factory database — change it only through factory/bin/factory.';
  }
  return null;
}

/** @returns {string|null} reason to block */
function checkWrite(t, me, input) {
  const file = t.file_path || t.notebook_path || '';
  if (!file) return null;
  const abs = path.resolve(input.cwd || process.cwd(), file);
  const root = repoRoot();
  const rel = path.relative(root, abs);

  if (rel.startsWith('factory/state/') || rel === 'factory/state') {
    return 'factory/state is the factory database — change it only through factory/bin/factory.';
  }
  if (/(^|\/)\.env(\.[^/]*)?$/.test(abs) && !/\.env\.example$/.test(abs)) {
    return 'do not write .env files; document variables in .env.example instead.';
  }
  // Workers stay inside their checkout (main or their worktree) and the system temp dir.
  if (me.kind === 'worker') {
    const cwd = input.cwd || process.cwd();
    const inside = (base) => !path.relative(base, abs).startsWith('..') && !path.isAbsolute(path.relative(base, abs));
    const tmpOk = /^\/(private\/)?(tmp|var\/folders)\//.test(abs);
    if (!inside(cwd) && !inside(root) && !tmpOk) {
      return `workers may only write inside the repository or their worktree (attempted ${abs}).`;
    }
  }
  // Verifier roles never modify product code: only their memory, shared memory and QA evidence.
  const role = input.agent_id ? input.agent_type : (process.env.FACTORY_ROLE || input.agent_type);
  if (VERIFIER_WRITE_ALLOW[role]) {
    const relToCwd = path.relative(input.cwd || process.cwd(), abs);
    const ok = VERIFIER_WRITE_ALLOW[role].some((p) => rel.startsWith(p) || relToCwd.startsWith(p))
      || /^\/(private\/)?(tmp|var\/folders)\//.test(abs);
    if (!ok) return `${role} does not modify product files. Record findings in the ticket (reject with notes) or file a ticket; you may write only to ${VERIFIER_WRITE_ALLOW[role].join(', ')}.`;
  }
  const content = [t.content, t.new_string, ...(Array.isArray(t.edits) ? t.edits.map((e) => e.new_string) : [])]
    .filter((s) => typeof s === 'string').join('\n');
  for (const [re, what] of SECRET_PATTERNS) {
    if (re.test(content)) return `the content looks like ${what}. Secrets never go into files in the repository.`;
  }
  return null;
}

/** True when the ticket's type is code-bearing (config.dispatcher.code_types). Unknown → true. */
function isCodeTicket(id) {
  const t = readJson(stateDir('tickets', `${id}.json`), null);
  if (!t) return true;
  const codeTypes = loadConfig().dispatcher?.code_types || ['build', 'bug', 'test', 'chore', 'ops'];
  return codeTypes.includes(t.type);
}

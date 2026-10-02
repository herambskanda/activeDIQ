#!/usr/bin/env node
// SessionStart: register the session for the board and inject a compact factory brief.
// Workers get their ticket and latest handoff; the CEO's session gets what needs the CEO.
// After a compaction, the latest handoff/snapshot is re-injected so work continues cleanly.

import fs from 'node:fs';
import path from 'node:path';
import {
  readInput, safely, addContext, who, budget, readJson, writeJson, stateDir, factoryHome, loadConfig, short,
} from './_common.mjs';

const MAX_HANDOFF_CHARS = 8000;

safely(() => {
  const input = readInput();
  const me = who(input);
  if (me.isSubagent) return;
  const source = input.source || 'startup';
  const b = budget();

  if (input.session_id) {
    const sfile = stateDir('sessions', `${input.session_id}.json`);
    const prev = readJson(sfile, {});
    writeJson(sfile, {
      ...prev,
      session_id: input.session_id,
      kind: me.kind,
      role: me.role,
      ticket: me.ticket,
      run: me.run,
      cwd: input.cwd || null,
      budget_tokens: b.tokens,
      started: prev.started || new Date().toISOString(),
      updated: new Date().toISOString(),
      last_source: source,
      ended: false,
    });
  }

  const lines = [];
  if (me.kind === 'worker') {
    const t = readJson(stateDir('tickets', `${me.ticket}.json`), null);
    lines.push(`FACTORY: you are ${me.role} on ${me.ticket}${t ? ` — "${short(t.title, 90)}" (${t.type}, stage ${t.status})` : ''}.`);
    lines.push(`Context budget ${Math.round(b.tokens / 1000)}k tokens; warnings arrive at ${pctOf(b.warn)}/${pctOf(b.checkpoint)}/${pctOf(b.critical)}%. Follow the factory-protocol skill.`);
    lines.push(...handoffLines(me.ticket, source === 'compact' || Boolean(t?.handoff?.pending)));
  } else {
    lines.push(...ceoBrief());
    if (source === 'compact' && input.session_id) lines.push(...handoffLines(`session-${input.session_id}`, true));
  }
  if (lines.length) addContext('SessionStart', lines.join('\n'));
});

function pctOf(x) { return Math.round(x * 100); }

/**
 * Handoff context for a ticket id or "session-<id>" key. A written handoff outranks the
 * mechanical PreCompact snapshot; when `inline`, the best one is injected in full.
 */
function handoffLines(key, inline) {
  const dir = path.join(factoryHome(), 'handoffs', key);
  let files = [];
  try {
    files = fs.readdirSync(dir).filter((f) => f.endsWith('.md')).sort();
  } catch {
    return [];
  }
  const written = files.filter((f) => !f.includes('auto-snapshot')).pop();
  const snapshot = files.filter((f) => f.includes('auto-snapshot')).pop();
  const rel = (f) => path.relative(path.dirname(factoryHome()), path.join(dir, f));
  const best = written || snapshot;
  if (!best) return [];
  const out = [];
  if (inline) out.push(`Latest ${written ? 'handoff' : 'auto-snapshot'} (${rel(best)}):\n${readCapped(path.join(dir, best))}`);
  else out.push(`Latest ${written ? 'handoff' : 'auto-snapshot'} on this ticket: ${rel(best)}`);
  if (written && snapshot && snapshot > written) out.push(`A newer mechanical snapshot also exists: ${rel(snapshot)}`);
  return out;
}

function readCapped(file) {
  try {
    const s = fs.readFileSync(file, 'utf8');
    return s.length > MAX_HANDOFF_CHARS ? `${s.slice(0, MAX_HANDOFF_CHARS)}\n…(truncated — read the file for the rest)` : s;
  } catch {
    return '(unreadable)';
  }
}

/** What the CEO's interactive session should know at a glance. */
function ceoBrief() {
  const cfg = loadConfig();
  const list = (kind) => {
    try {
      return fs.readdirSync(stateDir(kind)).filter((f) => f.endsWith('.json'))
        .map((f) => readJson(stateDir(kind, f), null)).filter(Boolean);
    } catch {
      return [];
    }
  };
  const decisions = list('decisions').filter((d) => d.status === 'pending');
  const actions = list('actions').filter((a) => a.status === 'open');
  const runs = list('runs').filter((r) => r.status === 'running');
  const control = readJson(stateDir('control.json'), {});
  const disp = readJson(stateDir('dispatcher.json'), null);
  const alive = disp?.heartbeat && Date.now() - Date.parse(disp.heartbeat) < 60_000;
  const state = !alive ? 'not running' : control.paused ? 'paused' : 'running';
  const out = [`FACTORY STATUS (for the factory-director): dispatcher ${state}; ${runs.length} worker(s) active; board http://${cfg.board?.host || '127.0.0.1'}:${cfg.board?.port || 4747} (start with /factory-up).`];
  if (decisions.length) {
    out.push(`${decisions.length} CEO decision(s) pending: ${decisions.slice(0, 5).map((d) => `${d.id} ${short(d.title, 60)} [${d.kind}]`).join('; ')}. Offer /decide when relevant — do not nag.`);
  }
  if (actions.length) out.push(`${actions.length} open CEO action item(s): ${actions.slice(0, 3).map((a) => `${a.id} ${short(a.title, 60)}`).join('; ')}.`);
  return out;
}

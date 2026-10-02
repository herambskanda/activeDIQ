#!/usr/bin/env node
// PostToolUse: (1) context-budget guard (the 300k rule), (2) live session usage for the board,
// (3) notable activity to the event feed, (4) memory-file budget warnings.
// One process per tool call, so everything lives in this single, fast script.

import fs from 'node:fs';
import path from 'node:path';
import {
  readInput, safely, addContext, who, budget, transcriptFor, contextTokens, guardStatePath,
  readJson, writeJson, stateDir, appendEvent, loadConfig, repoRoot, short,
} from './_common.mjs';

const REMIND_EVERY = 8; // tool calls between repeated checkpoint reminders

safely(() => {
  const input = readInput();
  const me = who(input);
  const messages = [];

  // ---- 1. Context guard -------------------------------------------------------------------
  const tokens = contextTokens(transcriptFor(input));
  const b = budget();
  let pct = null;
  if (tokens != null) {
    pct = tokens / b.tokens;
    const key = `${input.session_id || 'nosession'}__${input.agent_id || 'main'}`;
    const gfile = guardStatePath(key);
    const g = readJson(gfile, { warned: false, checkpointed: false, sinceCheckpoint: 0 });
    const k = Math.round(tokens / 1000);
    const cap = Math.round(b.tokens / 1000);
    const p = Math.round(pct * 100);

    if (pct >= b.critical) {
      messages.push(me.isSubagent
        ? `CONTEXT BUDGET — CRITICAL (subagent, ${k}k/${cap}k). Stop now and return your findings to the caller in a few lines.`
        : me.kind === 'worker'
          ? `CONTEXT BUDGET — CRITICAL (${p}%, ${k}k/${cap}k). Start nothing new. Immediately: \`factory/bin/factory handoff new ${me.ticket} --by ${me.role}\`, fill every section, note the ticket, and end with "RESULT: handoff — <summary>".`
          : `CONTEXT BUDGET — CRITICAL (${p}%, ${k}k/${cap}k). Stop starting new work. Tell the CEO in one line, run the handoff skill (/handoff) now, then suggest /clear and /pickup.`);
      g.checkpointed = true;
      g.warned = true;
    } else if (pct >= b.checkpoint) {
      g.sinceCheckpoint = (g.sinceCheckpoint || 0) + 1;
      if (!g.checkpointed || g.sinceCheckpoint >= REMIND_EVERY) {
        g.checkpointed = true;
        g.sinceCheckpoint = 0;
        messages.push(me.isSubagent
          ? `CONTEXT BUDGET (subagent, ${k}k/${cap}k). Stop exploring; return your findings to the caller now, concisely.`
          : me.kind === 'worker'
            ? `CONTEXT BUDGET — CHECKPOINT (${p}%, ${k}k/${cap}k). Finish only the current atomic step — do not start new subtasks. Then: 1) \`factory/bin/factory handoff new ${me.ticket} --by ${me.role}\` and fill every section of the file it prints; 2) \`factory/bin/factory ticket note ${me.ticket} --by ${me.role} "checkpoint: handoff written"\`; 3) end your turn with "RESULT: handoff — <summary>". A fresh session continues from your handoff.`
            : `CONTEXT BUDGET — CHECKPOINT (${p}%, ${k}k/${cap}k). At the next natural stopping point: tell the CEO in one line, run the handoff skill (/handoff), then suggest /clear followed by /pickup.`);
      }
      g.warned = true;
    } else if (pct >= b.warn && !g.warned) {
      g.warned = true;
      messages.push(`CONTEXT BUDGET — ADVISORY (${p}%, ${k}k/${cap}k). Plan to reach a clean checkpoint soon; avoid reading large files whole — use the Explore agent for searches.`);
    }
    writeJson(gfile, g);
  }

  // ---- 2. Live session usage for the board (main sessions only, throttled) -----------------
  if (!me.isSubagent && input.session_id) {
    const sfile = stateDir('sessions', `${input.session_id}.json`);
    const prev = readJson(sfile, null);
    const now = Date.now();
    // First tool call of a session (SessionStart wrote the file without usage) always records.
    const stale = !prev || !prev.last_tool || now - Date.parse(prev.updated || 0) > 10_000;
    if (stale || (tokens != null && prev && Math.abs((prev.context_tokens || 0) - tokens) > 20_000)) {
      writeJson(sfile, {
        ...(prev || {}),
        session_id: input.session_id,
        kind: me.kind,
        role: me.role,
        ticket: me.ticket,
        run: me.run,
        cwd: input.cwd || null,
        effort: input.effort?.level || prev?.effort || null,
        context_tokens: tokens ?? prev?.context_tokens ?? null,
        peak_context_tokens: Math.max(tokens || 0, prev?.peak_context_tokens || 0),
        budget_tokens: b.tokens,
        last_tool: `${input.tool_name || '?'} · ${short(describe(input), 80)}`,
        started: prev?.started || new Date(now).toISOString(),
        updated: new Date(now).toISOString(),
        ended: false,
      });
    }
  }

  // ---- 3. Notable activity → event feed ----------------------------------------------------
  const activity = notable(input);
  if (activity && !me.isSubagent) {
    const dfile = guardStatePath(`act__${input.session_id}__${activity.key}`);
    const last = readJson(dfile, null);
    if (!last || Date.now() - last.ts > 5 * 60_000) {
      appendEvent({ actor: me.role, kind: activity.kind, ticket: me.ticket, run: me.run, text: activity.text });
      writeJson(dfile, { ts: Date.now() });
    }
  }

  // ---- 4. Memory budgets --------------------------------------------------------------------
  const file = input.tool_input?.file_path;
  if (file && /^(Write|Edit|MultiEdit)$/.test(input.tool_name || '')) {
    const rel = path.relative(repoRoot(), path.resolve(input.cwd || repoRoot(), file));
    const memDir = (loadConfig().memory?.dir || 'knowledge/memory') + '/';
    let limit = null;
    if (rel.startsWith(memDir) && !rel.startsWith(memDir + 'archive/') && rel.endsWith('.md')) {
      limit = loadConfig().memory?.max_lines_per_file || 120;
    } else if (/^\.claude\/agent-memory\/[^/]+\/MEMORY\.md$/.test(rel)) {
      limit = 60;
    }
    if (limit) {
      try {
        const lines = fs.readFileSync(path.resolve(input.cwd || repoRoot(), file), 'utf8').split('\n').length;
        if (lines > limit) {
          messages.push(`MEMORY BUDGET: ${rel} is ${lines} lines (budget ${limit}). Compress it now per the memory skill — merge, generalise, or archive older entries — before adding more.`);
        }
      } catch { /* file may be gone */ }
    }
  }

  if (messages.length) addContext('PostToolUse', messages.join('\n\n'));
});

/** One-line description of a tool call for the board. */
function describe(input) {
  const t = input.tool_input || {};
  return t.command || t.file_path || t.pattern || t.description || t.url || t.query || '';
}

/** Activity worth showing the CEO: knowledge/docs/report edits, commits, merges. */
function notable(input) {
  const t = input.tool_input || {};
  if (/^(Write|Edit|MultiEdit)$/.test(input.tool_name || '') && t.file_path) {
    const rel = path.relative(repoRoot(), path.resolve(input.cwd || repoRoot(), t.file_path));
    if (/^(knowledge|docs|factory\/reports|factory\/demos)\//.test(rel) && !rel.startsWith('knowledge/memory/archive/')) {
      return { key: rel, kind: 'doc', text: `updated ${rel}` };
    }
    return null;
  }
  if (input.tool_name === 'Bash' && typeof t.command === 'string') {
    const m = t.command.match(/git\s+commit\b[^\n]*?-m\s+(["'])([\s\S]*?)\1/);
    if (m) return { key: `commit:${m[2].slice(0, 40)}`, kind: 'tool', text: `committed: ${short(m[2], 90)}` };
  }
  return null;
}

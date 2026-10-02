#!/usr/bin/env node
// PreCompact: before the context is compacted, write a mechanical snapshot next to the
// handoffs so nothing load-bearing is lost. SessionStart(compact) re-injects the latest handoff.

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  readInput, safely, who, readJson, stateDir, factoryHome, tailLines, appendEvent, short,
} from './_common.mjs';

safely(() => {
  const input = readInput();
  const me = who(input);
  if (me.isSubagent) return;
  const key = me.ticket || (input.session_id ? `session-${input.session_id}` : null);
  if (!key) return;

  const ts = new Date().toISOString();
  const dir = path.join(factoryHome(), 'handoffs', key);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${ts.replace(/[:.]/g, '-')}-auto-snapshot.md`);

  const ticket = me.ticket ? readJson(stateDir('tickets', `${me.ticket}.json`), null) : null;
  const git = (args) => {
    try {
      return execFileSync('git', args, { cwd: input.cwd || process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 }).trim();
    } catch {
      return '(unavailable)';
    }
  };

  const touched = new Set();
  const commands = [];
  for (const line of tailLines(input.transcript_path, 2 * 1024 * 1024)) {
    if (!line.includes('"tool_use"')) continue;
    try {
      const entry = JSON.parse(line);
      for (const c of entry?.message?.content || []) {
        if (c.type !== 'tool_use') continue;
        if (c.input?.file_path && /^(Write|Edit|MultiEdit)$/.test(c.name)) touched.add(c.input.file_path);
        if (c.name === 'Bash' && c.input?.command) commands.push(short(c.input.command, 140));
      }
    } catch { /* skip */ }
  }

  const doc = [
    '---',
    `kind: auto-snapshot`,
    `trigger: ${input.trigger || 'unknown'}`,
    `session: ${input.session_id || 'unknown'}`,
    `role: ${me.role}`,
    `created: ${ts}`,
    '---',
    '',
    `# Auto-snapshot before compaction — ${key}`,
    '',
    'Mechanical state captured by the PreCompact hook. A written handoff, if one exists, is more',
    'authoritative than this file.',
    '',
    ticket ? `## Ticket\n${ticket.id} — ${ticket.title}\nstatus: ${ticket.status} · owner: ${ticket.owner} · stage role: ${ticket.stage_role || '-'}\n\n${ticket.summary || ''}` : '## Ticket\nnone (interactive session)',
    '',
    '## Recent ticket notes',
    ...((ticket?.notes || []).slice(-5).map((n) => `- ${n.ts} ${n.by}: ${short(n.text, 200)}`)),
    '',
    '## Git',
    `branch: ${git(['rev-parse', '--abbrev-ref', 'HEAD'])}`,
    '```',
    git(['status', '--porcelain']).split('\n').slice(0, 40).join('\n'),
    '```',
    '```',
    git(['diff', '--stat']).split('\n').slice(-25).join('\n'),
    '```',
    '',
    '## Files written or edited in this session (most recent last)',
    ...[...touched].slice(-25).map((f) => `- ${f}`),
    '',
    '## Recent shell commands',
    ...commands.slice(-15).map((c) => `- \`${c.replace(/`/g, "'")}\``),
    '',
  ].join('\n');

  fs.writeFileSync(file, doc);
  appendEvent({ actor: me.role, kind: 'session', ticket: me.ticket, run: me.run, text: `context compacted (${input.trigger || 'auto'}); snapshot saved` });
});

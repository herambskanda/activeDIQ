// Handoff files: factory/handoffs/<ticket-or-session-id>/<timestamp>.md, rendered from the template.
import fs from 'node:fs';
import path from 'node:path';
import { appendEvent, getEntity, nowIso, requireEntity, updateEntity } from './store.mjs';
import { render } from './render.mjs';
import { FactoryError } from './errors.mjs';

/**
 * Every handoff file for an id (ticket or session), oldest first, as absolute paths.
 * @param {object} ctx
 * @param {string} id
 * @returns {string[]}
 */
export function listHandoffs(ctx, id) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(id)) throw new FactoryError(`invalid id: ${JSON.stringify(id)}`);
  const dir = path.join(ctx.handoffsDir, id);
  try {
    return fs.readdirSync(dir).filter((n) => n.endsWith('.md')).sort().map((n) => path.join(dir, n));
  } catch {
    return [];
  }
}

/**
 * The newest handoff for an id, or null. A written handoff outranks the PreCompact hook's mechanical
 * `*-auto-snapshot.md`; a snapshot is returned only when no written handoff exists.
 * @param {object} ctx
 * @param {string} id
 */
export function latestHandoff(ctx, id) {
  const all = listHandoffs(ctx, id);
  return all.filter((f) => !f.endsWith('-auto-snapshot.md')).at(-1) ?? all.at(-1) ?? null;
}

/**
 * Create a handoff skeleton for a ticket and flag the ticket as having a pending continuation.
 * @param {object} ctx
 * @param {string} ticketId
 * @param {string} by role writing the handoff
 * @returns {string} absolute path of the new file
 */
export function createHandoff(ctx, ticketId, by) {
  const ticket = requireEntity(ctx, 'tickets', ticketId, 'ticket');
  const runId = process.env.FACTORY_RUN_ID;
  const run = runId ? getEntity(ctx, 'runs', runId) : null;
  const ts = nowIso(ctx);
  const template = fs.readFileSync(path.join(ctx.templatesDir, 'handoff.md'), 'utf8');
  const body = render(template, {
    ticket_id: ticket.id, ticket_title: ticket.title, role: by, ts,
    session_id: run?.session_id ?? process.env.CLAUDE_SESSION_ID ?? 'unknown',
    context_tokens: run?.context_tokens ?? 0,
  });

  const dir = path.join(ctx.handoffsDir, ticketId);
  fs.mkdirSync(dir, { recursive: true });
  const stem = ts.replace(/[:.]/g, '-');
  let file = path.join(dir, `${stem}.md`);
  for (let n = 2; ; n++) {
    try {
      fs.writeFileSync(file, body, { flag: 'wx' });
      break;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      file = path.join(dir, `${stem}-${n}.md`);
    }
  }
  updateEntity(ctx, 'tickets', ticketId, (t) => {
    t.handoff = { pending: true, latest: file };
  });
  appendEvent(ctx, { actor: by, kind: 'ticket', ticket: ticketId, text: `handoff written for ${ticketId}: ${path.basename(file)}` });
  return file;
}

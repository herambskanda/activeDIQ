#!/usr/bin/env node
// SessionEnd / StopFailure: keep the board's session list honest and tell the dispatcher about
// rate limits so it backs off instead of burning retries.

import { readInput, safely, who, readJson, writeJson, stateDir, appendEvent, short } from './_common.mjs';

safely(() => {
  const input = readInput();
  const me = who(input);
  const event = input.hook_event_name;

  if (event === 'SessionEnd' && input.session_id) {
    const sfile = stateDir('sessions', `${input.session_id}.json`);
    const s = readJson(sfile, null);
    if (s) writeJson(sfile, { ...s, ended: true, end_reason: input.reason || null, updated: new Date().toISOString() });
    return;
  }

  if (event === 'StopFailure') {
    const type = input.error_type || input.error?.type || input.matcher || 'unknown';
    if (/rate|overload|quota/i.test(String(type))) {
      writeJson(stateDir('signals', 'rate-limit.json'), { ts: new Date().toISOString(), type, session: input.session_id || null, role: me.role });
    }
    appendEvent({ actor: me.role, kind: 'system', ticket: me.ticket, run: me.run, text: `session stopped by an API error: ${short(type, 60)}` });
  }
});

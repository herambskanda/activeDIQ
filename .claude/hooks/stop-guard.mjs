#!/usr/bin/env node
// Stop: a dispatched worker may not end its session without recording an outcome on its
// ticket (advance / reject / block / note + handoff). Interactive sessions are never blocked.

import { readInput, safely, emit, who, readJson, writeJson, stateDir } from './_common.mjs';

safely(() => {
  const input = readInput();
  const me = who(input);

  if (input.session_id) {
    const sfile = stateDir('sessions', `${input.session_id}.json`);
    const s = readJson(sfile, null);
    if (s) writeJson(sfile, { ...s, updated: new Date().toISOString(), last_stop: new Date().toISOString() });
  }

  if (me.kind !== 'worker' || me.isSubagent) return;
  if (input.stop_hook_active) return; // already reminded once; never loop

  const ticket = readJson(stateDir('tickets', `${me.ticket}.json`), null);
  if (!ticket) return;

  const run = me.run ? readJson(stateDir('runs', `${me.run}.json`), null) : null;
  const session = input.session_id ? readJson(stateDir('sessions', `${input.session_id}.json`), null) : null;
  const since = Date.parse(run?.started || session?.started || 0) || 0;

  const touched = [...(ticket.history || []), ...(ticket.notes || [])]
    .some((e) => Date.parse(e.ts || 0) >= since);
  if (touched || ticket.handoff?.pending) return;

  emit({
    decision: 'block',
    reason: `Before stopping, record the outcome on ${me.ticket}: \`factory/bin/factory ticket advance|reject|block ${me.ticket} --by ${me.role} --note "…"\` — or, if you are mid-task, write a handoff (\`factory/bin/factory handoff new ${me.ticket} --by ${me.role}\`) and note the ticket. Then end with the RESULT line.`,
  });
});

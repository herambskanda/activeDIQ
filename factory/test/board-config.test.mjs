import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { startBoard } from '../board/server.mjs';
import { makeFactory } from './helpers.mjs';

test('the board follows config.json edits without a restart (run cap on the Agents graph)', async () => {
  const f = makeFactory();
  const { server, port } = await startBoard(f.ctx, { port: 0 });
  const cap = async () => (await (await fetch(`http://127.0.0.1:${port}/api/graph`)).json());
  const findCap = (g) => JSON.stringify(g).match(/"daily_run_cap":(\d+)/)?.[1];
  try {
    const file = path.join(f.ctx.home, 'config.json');
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    const before = findCap(await cap());
    assert.equal(before, String(cfg.dispatcher.daily_run_cap));

    cfg.dispatcher.daily_run_cap = 777;
    fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    const t = new Date(Date.now() + 2000);
    fs.utimesSync(file, t, t); // guarantee a new mtime on coarse-clock filesystems
    assert.equal(findCap(await cap()), '777');

    fs.writeFileSync(file, '{ not json');
    fs.utimesSync(file, new Date(Date.now() + 4000), new Date(Date.now() + 4000));
    assert.equal(findCap(await cap()), '777', 'an unreadable config keeps the previous one');
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    f.cleanup();
  }
});

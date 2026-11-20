// Per-step times of a gate run, from the log and the `<log>.timing` note the gate writes next to it.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { formatStepTable, locateSteps, msAtOffset, parsePlan, parseTiming, stepTable } from '../lib/gatetiming.mjs';
import { runLogged } from '../lib/premerge.mjs';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'gate-timing');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'gatetiming-'));

test('parseTiming reads the header and samples, and tells a side-by-side (-O) run from a serial one', () => {
  const t = parseTiming('# start 1700000000000\n# argv make -k ci\n0\t0\n2000\t100\n4000\t900\n');
  assert.deepEqual([t.argv, t.sync, t.samples.length], ['make -k ci', false, 3]);
  assert.equal(parseTiming('# argv make -k -j2 -O ci\n0\t0\n').sync, true);
  assert.equal(parseTiming('# argv make -kO ci\n0\t0\n').sync, true);
  assert.equal(parseTiming('# argv make -k -j2 --output-sync=target ci\n0\t0\n').sync, true);
  assert.equal(parseTiming('# argv make -k -j2 ci\n0\t0\n').sync, false, '-j alone does not hold output back');
  assert.equal(parseTiming('garbage\n\n# x\n').samples.length, 0, 'junk lines are ignored');
});

test('msAtOffset is when the log first held more than that many bytes; past the end it is the last sample', () => {
  const s = [{ ms: 0, bytes: 0 }, { ms: 2000, bytes: 100 }, { ms: 4000, bytes: 900 }];
  assert.deepEqual([0, 99, 100, 899, 900, 5000].map((o) => msAtOffset(s, o)), [2000, 2000, 4000, 4000, 4000, 4000]);
  assert.equal(msAtOffset([], 10), 0);
});

test('parsePlan keeps real commands once, in order, and drops make lines, echo and comments', () => {
  const plan = ['go vet ./...', '# a comment', 'make[1]: Entering directory', 'echo "hello"', '', 'go vet ./...', '  npm ci --prefix web  ', 'make: Nothing to be done'].join('\n');
  assert.deepEqual(parsePlan(plan), ['go vet ./...', 'npm ci --prefix web']);
});

test('locateSteps gives byte offsets (even after multi-byte text), finds a command on the first line, and counts silent ones', () => {
  const log = Buffer.from('go vet ./...\nok\nnaïve café ✓ output\nnpm ci --prefix web\nadded 3 packages\n', 'utf8');
  const { found, missing } = locateSteps(log, ['npm ci --prefix web', 'go vet ./...', 'tools/ci/never-echoed.sh']);
  assert.deepEqual(found.map((f) => f.command), ['go vet ./...', 'npm ci --prefix web'], 'sorted by position in the log');
  assert.equal(found[0].offset, 0);
  assert.equal(log.subarray(found[1].offset).toString('utf8').startsWith('npm ci --prefix web\n'), true, 'the offset is a real byte offset');
  assert.equal(missing, 1);
  assert.equal(locateSteps(Buffer.from('xgo vet ./...\n'), ['go vet ./...']).found.length, 0, 'only a whole line counts');
});

test('stepTable: a serial run times each step to the next one; a side-by-side run gives the gap between finishes', () => {
  const samples = [{ ms: 0, bytes: 0 }, { ms: 60_000, bytes: 50 }, { ms: 360_000, bytes: 200 }, { ms: 420_000, bytes: 300 }];
  const steps = [{ command: 'a', offset: 0 }, { command: 'b', offset: 60 }, { command: 'c', offset: 250 }];
  const serial = stepTable({ argv: 'make -k ci', samples, sync: false }, steps);
  assert.deepEqual(serial.rows.map((r) => [r.command, r.atMs, r.ms]), [['a', 60_000, 300_000], ['b', 360_000, 60_000], ['c', 420_000, 0]]);
  assert.equal(serial.totalMs, 420_000);
  const sync = stepTable({ argv: 'make -k -j2 -O ci', samples, sync: true }, steps);
  assert.deepEqual(sync.rows.map((r) => r.ms), [60_000, 300_000, 60_000], 'gap since the previous step finished');
  const text = formatStepTable(serial, 2, 2);
  assert.match(text, /serial run/);
  assert.match(text, /2 not echoed/);
  assert.match(text, /top 2 by time taken:\n\s+5\.0 min\s+a/, 'the slowest step comes first');
  assert.match(formatStepTable(sync), /side-by-side run \(-O\).*FINISHED/);
});

test('runLogged with timing leaves a note that grows with the log; the table reads real step times from it', async () => {
  const dir = tmp();
  try {
    const script = "process.stdout.write('step-one\\n');setTimeout(()=>{process.stdout.write('step-two\\n');setTimeout(()=>process.stdout.write('step-three\\n'),1200)},1200)";
    const log = path.join(dir, 'run.log');
    const r = await runLogged(['node', '-e', script], dir, log, { timing: true, timingEveryMs: 100 });
    assert.equal(r.code, 0);
    const note = fs.readFileSync(`${log}.timing`, 'utf8');
    assert.match(note, /^# start \d+\n# argv node -e /);
    const t = parseTiming(note);
    assert.ok(t.samples.length >= 3, `expected 3+ samples, got ${t.samples.length}`);
    assert.ok(t.samples.every((s, i) => i === 0 || (s.ms >= t.samples[i - 1].ms && s.bytes >= t.samples[i - 1].bytes)), 'time and size only grow');
    assert.equal(t.samples.at(-1).bytes, fs.statSync(log).size, 'the last sample is the final size');
    const steps = locateSteps(fs.readFileSync(log), ['step-one', 'step-two', 'step-three']).found;
    const rows = stepTable(t, steps).rows;
    assert.equal(rows.length, 3);
    for (const row of rows.slice(0, 2)) assert.ok(row.ms >= 900 && row.ms <= 1700, `a 1.2 s step read as ${row.ms} ms`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('without the timing option no note is written, and a note that cannot be written never fails the run', async () => {
  const dir = tmp();
  try {
    const plain = path.join(dir, 'plain.log');
    assert.equal((await runLogged(['node', '-e', "console.log('x')"], dir, plain)).code, 0);
    assert.equal(fs.existsSync(`${plain}.timing`), false);
    const blocked = path.join(dir, 'blocked.log');
    fs.mkdirSync(`${blocked}.timing`); // a directory where the note should go: writing it throws
    const r = await runLogged(['node', '-e', "console.log('still runs')"], dir, blocked, { timing: true });
    assert.equal(r.code, 0);
    assert.match(fs.readFileSync(blocked, 'utf8'), /still runs/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('gate-timing: no argument is a usage error, a run without a note says so, and a real note gives a table', () => {
  assert.equal(spawnSync('node', [BIN], { encoding: 'utf8' }).status, 2);
  const dir = tmp();
  try {
    const log = path.join(dir, 'old.log');
    fs.writeFileSync(log, 'go vet ./...\n');
    const old = spawnSync('node', [BIN, log], { encoding: 'utf8' });
    assert.equal(old.status, 1);
    assert.match(old.stderr, /no .*\.timing/);
    const repo = path.join(dir, 'repo');
    fs.mkdirSync(repo);
    fs.writeFileSync(path.join(repo, 'Makefile'), 'ci:\n\tgo vet ./...\n\tnpm ci --prefix web\n');
    fs.writeFileSync(log, 'go vet ./...\nok\nnpm ci --prefix web\nadded\n');
    fs.writeFileSync(`${log}.timing`, '# start 1\n# argv make -k ci\n0\t0\n2000\t14\n62000\t40\n');
    const out = execFileSync('node', [BIN, log, '--repo', repo], { encoding: 'utf8' });
    assert.match(out, /2 steps found/);
    assert.match(out, /go vet \.\/\.\.\./);
    assert.match(out, /1\.0 min\s+go vet|1\.0\s+go vet/, 'the first step took the minute until the second began');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

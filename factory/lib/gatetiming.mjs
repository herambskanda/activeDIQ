// Per-step times of a gate run, read back from the log and its `<log>.timing` note (see
// `startLogTiming` in premerge.mjs). The gate log itself has no timestamps, so before this nobody could say
// which of the ~60 commands of `make ci` takes the 75 minutes.
//
// How: the note says when the log reached each size. `make` prints every command it runs on a line of its
// own, so the byte position of that line, looked up in the note, is the time the command started
// (serial run) or finished (`-O`: make holds each target's output until the target is done).
import fs from 'node:fs';

/** @param {string} text a `<log>.timing` file */
export function parseTiming(text) {
  const samples = [];
  let argv = '';
  for (const line of text.split('\n')) {
    if (line.startsWith('# argv ')) { argv = line.slice(7); continue; }
    if (!line || line.startsWith('#')) continue;
    const [ms, bytes] = line.split('\t').map(Number);
    if (Number.isFinite(ms) && Number.isFinite(bytes)) samples.push({ ms, bytes });
  }
  return { argv, samples, sync: /(^|\s)(-O\S*|--output-sync\S*)(\s|$)/.test(argv) || /(^|\s)-\w*O\w*(\s|$)/.test(argv) };
}

/** Milliseconds since the run started at which the log first held more than `offset` bytes (2 s resolution). */
export function msAtOffset(samples, offset) {
  for (const s of samples) if (s.bytes > offset) return s.ms;
  return samples.length ? samples[samples.length - 1].ms : 0;
}

/**
 * The commands `make -n` printed, in order, without the lines that are not a step (make's own, comments).
 * @param {string} makeDryRun output of `make -n -k ci`
 */
export function parsePlan(makeDryRun) {
  const seen = new Set();
  const out = [];
  for (const raw of makeDryRun.split('\n')) {
    const cmd = raw.trim();
    if (!cmd || cmd.startsWith('#') || /^make(\[\d+\])?:/.test(cmd) || /^echo /.test(cmd) || seen.has(cmd)) continue;
    seen.add(cmd);
    out.push(cmd);
  }
  return out;
}

/**
 * Where each planned command appears in the log: the byte offset of the first line that is exactly the command.
 * `@`-silenced commands are never echoed, so they are not found and are counted in `missing`.
 * @param {Buffer} log
 * @param {string[]} commands
 */
export function locateSteps(log, commands) {
  const text = log.toString('latin1'); // 1 char = 1 byte, so string indexes are byte offsets
  const found = [];
  let missing = 0;
  for (const command of commands) {
    const c = Buffer.from(command, 'utf8').toString('latin1');
    let at = text.startsWith(`${c}\n`) ? 0 : text.indexOf(`\n${c}\n`);
    if (at > 0) at += 1;
    if (at < 0) { missing++; continue; }
    found.push({ command, offset: at });
  }
  return { found: found.sort((a, b) => a.offset - b.offset), missing };
}

/**
 * @param {{argv: string, samples: {ms: number, bytes: number}[], sync: boolean}} timing
 * @param {{command: string, offset: number}[]} steps in log order
 * @returns {{mode: 'serial'|'sync', totalMs: number, rows: {command: string, atMs: number, ms: number}[]}}
 *   `ms` is the step's own time in a serial run; in a sync (`-O`) run it is the time since the previous step finished,
 *   which is the best a log can say when steps overlap.
 */
export function stepTable(timing, steps) {
  const total = timing.samples.length ? timing.samples[timing.samples.length - 1].ms : 0;
  const at = steps.map((s) => ({ command: s.command, atMs: msAtOffset(timing.samples, s.offset) }));
  const rows = at.map((s, i) => {
    if (timing.sync) return { ...s, ms: s.atMs - (i ? at[i - 1].atMs : 0) };
    return { ...s, ms: (i + 1 < at.length ? at[i + 1].atMs : total) - s.atMs };
  });
  return { mode: timing.sync ? 'sync' : 'serial', totalMs: total, rows };
}

const min = (ms) => (ms / 60000).toFixed(1).padStart(5);

/** The table and the top five, as text. */
export function formatStepTable(table, missing = 0, top = 5) {
  const lines = [];
  lines.push(table.mode === 'serial'
    ? `serial run: each row is the time from that command's first output to the next command's (minutes)`
    : `side-by-side run (-O): make holds a target's output until it is done, so "at" is when each step FINISHED and "gap" the time since the previous one finished (minutes)`);
  lines.push(`run total ${min(table.totalMs).trim()} min, ${table.rows.length} steps found${missing ? `, ${missing} not echoed in the log (silent make lines)` : ''}`);
  lines.push('');
  lines.push(`  ${table.mode === 'serial' ? 'start' : '   at'}  ${table.mode === 'serial' ? ' took' : '  gap'}  step`);
  for (const r of table.rows) lines.push(`  ${min(r.atMs)}  ${min(r.ms)}  ${r.command.slice(0, 110)}`);
  lines.push('');
  lines.push(`top ${top} by ${table.mode === 'serial' ? 'time taken' : 'gap'}:`);
  for (const r of [...table.rows].sort((a, b) => b.ms - a.ms).slice(0, top)) lines.push(`  ${min(r.ms)} min  ${r.command.slice(0, 110)}`);
  return lines.join('\n');
}

/** Read a gate log and its note from disk. */
export function readRun(logFile) {
  const timing = parseTiming(fs.readFileSync(`${logFile}.timing`, 'utf8'));
  return { log: fs.readFileSync(logFile), timing };
}

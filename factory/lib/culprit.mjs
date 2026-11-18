// Culprit finder for a refused merge train (merge plan step 4.1).
//
// A train of N tickets was gated together and the gate refused it with findings that `main` does not
// have. Instead of halving the train and gating both halves (slow when many tickets fail), map each new
// finding to the one ticket that changed the file or Go package it names, drop that ticket and gate the
// rest once. The rule is deliberately strict: a finding is blamed on a ticket only when exactly one member
// of the train touched the file (or the package directory) the finding names. Anything else (a finding that
// names no file, or a file two members touched, or a failing package no member touched) means "cannot
// tell": the caller falls back to halving, which always finds the culprit. A wrong blame therefore costs
// at most one extra run; it never merges anything untested, because the kept tickets are gated again.
//
// Two grades of blame. A finding at a file or directory one member changed (a lint, architecture or
// static rule) is CERTAIN: that ticket is refused at once. A failing Go package or test is only LIKELY: the
// member that changed the package may not be the one that broke it (the other may have changed an API it
// uses), so that ticket is gated alone afterwards and gets its own verdict. An innocent ticket never takes
// a strike from a guess.

const MODULE = 'github.com/skenzeriq/activediq/';
const AGGREGATE = /^FAILED [\w.-]+$/; // `make` target roll-ups, a consequence of the specific findings
const PKG_FAIL = /^FAIL (\S+\/\S+)$/; // `go test` package roll-up: FAIL github.com/.../internal/foo
const TEST_FAIL = /^FAIL \S/; // FAIL TestName, FAIL lock stuck…: explained by a package roll-up when one exists
const LOCATED = /^((?:[\w.@+-]+\/)*[\w.@+-]+)(?::\d+)?: /; // path[:line]: message   (file or directory)
const RULE_AT = /^((?:[\w.@+-]+\/)+[\w.@+-]+\.\w+) [A-Z][\w-]* \[[^\]]*\]: /; // lab/e2e/x.sh FF-KEY-3 [rule]: message
const TEST_AT = /^\.\/((?:[\w.@+-]+\/)*[\w.@+-]+) Test\w+/; // ./internal/compose/server TestName FF-KEY-3 [test-failed]
const SUFFIX = /\s{2}\((?:\d+ times|\d+ more than the \d+ on [^)]*)\)$/; // "  (3 times)" added by the gate

/** @param {string} line one finding line as the gate prints it @returns {string} */
export function bareFinding(line) {
  return line.replace(SUFFIX, '').trim();
}

/**
 * What a finding names.
 * @param {string} raw
 * @returns {{kind: 'aggregate'|'package'|'test'|'path'|'other', path?: string}}
 */
export function classifyFinding(raw) {
  const f = bareFinding(raw);
  if (AGGREGATE.test(f)) return { kind: 'aggregate' };
  const pkg = PKG_FAIL.exec(f);
  if (pkg) return { kind: 'package', path: pkg[1].startsWith(MODULE) ? pkg[1].slice(MODULE.length) : pkg[1] };
  if (TEST_FAIL.test(f)) return { kind: 'test' };
  const rule = RULE_AT.exec(f);
  if (rule) return { kind: 'path', path: rule[1] };
  const test = TEST_AT.exec(f);
  if (test) return { kind: 'package', path: test[1] };
  const at = LOCATED.exec(f);
  if (at && (at[1].includes('/') || /\.\w+$/.test(at[1]))) return { kind: 'path', path: at[1] };
  return { kind: 'other' };
}

/** The members whose changed files are `path` itself or lie under the directory `path`. */
function ownersOf(path, members) {
  return members.filter((m) => m.files.some((f) => f === path || f.startsWith(`${path}/`)));
}

/**
 * Blame each new finding on the one train member that changed what it names.
 * @param {string[]} findings the gate's new-finding lines
 * @param {{id: string, files: string[]}[]} members every ticket of the refused train, with the repo-relative
 *   files its branch changes against `main`
 * @returns {{certain: Map<string, string[]>, likely: Map<string, string[]>, unmapped: string[], ignored: number}}
 *   `certain` / `likely`: ticket id -> its findings. `unmapped` are the findings nobody can be blamed for; when
 *   any exist the split must not be trusted.
 */
export function blameFindings(findings, members) {
  const kinds = findings.map((raw) => ({ raw: bareFinding(raw), ...classifyFinding(raw) }));
  const hasPackage = kinds.some((k) => k.kind === 'package');
  const certain = new Map();
  const likely = new Map();
  const unmapped = [];
  let ignored = 0;
  const add = (map, id, f) => map.set(id, [...(map.get(id) ?? []), f]);
  for (const k of kinds) {
    if (k.kind === 'aggregate' || (k.kind === 'test' && hasPackage)) { ignored += 1; continue; }
    const owners = k.kind === 'package' || k.kind === 'path' ? ownersOf(k.path, members) : [];
    if (owners.length !== 1) { unmapped.push(k.raw); continue; }
    add(k.kind === 'path' ? certain : likely, owners[0].id, k.raw);
  }
  for (const id of certain.keys()) likely.delete(id); // a ticket with a certain finding is simply refused
  return { certain, likely, unmapped, ignored };
}

/**
 * The plan for a refused train, or null to halve it.
 * @param {string[]} findings
 * @param {{id: string, files: string[]}[]} members in queue order
 * @returns {null | {drop: Map<string, string[]>, suspect: Map<string, string[]>, keep: string[], ignored: number}}
 *   `drop`: refuse these now (certain). `suspect`: gate each alone afterwards (likely). `keep`: gate together again.
 */
export function planDrop(findings, members) {
  if (members.length < 2 || !findings.length) return null;
  const { certain, likely, unmapped, ignored } = blameFindings(findings, members);
  if (unmapped.length || (!certain.size && !likely.size)) return null;
  const out = new Set([...certain.keys(), ...likely.keys()]);
  return { drop: certain, suspect: likely, keep: members.map((m) => m.id).filter((id) => !out.has(id)), ignored };
}

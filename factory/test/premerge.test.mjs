// The pre-merge gate (T-0941): a branch that adds a finding cannot merge while main is red for
// older ones, a branch that adds none can, and nothing merges when the gate cannot judge.
// The "CI" in the fixture repo is check.mjs: it prints one fitness-style finding per line of
// violations.txt (file|line|message) and one failed make target per line of targets.txt, to stderr,
// and exits 1 when it printed anything — the shape of `make -k ci` over fitness-profiles.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { blockedNote, extractFindings, findingKey, newFindings, runPreMergeGate } from '../lib/premerge.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { listEntities, readRecentEvents } from '../lib/store.mjs';
import { commitAll, git, initRepo, makeFactory, ticketInput } from './helpers.mjs';

const CHECK = `import fs from 'node:fs';
const read = (f) => (fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split('\\n').filter(Boolean) : []);
let bad = 0;
for (const l of read('violations.txt')) {
  const [file, line, msg] = l.split('|');
  console.error(\`\${file}:\${line}: P1 (ADR-0002 fitness function): \${msg}\`);
  bad++;
}
for (const l of read('raw.txt')) { console.error(l); bad++; }
for (const t of read('targets.txt')) { console.error(\`make: *** [tools/ci/ci.mk:7: \${t}] Error 1\`); bad++; }
console.log('ok  \\tsome/package\\t0.123s');
process.exit(bad ? 1 : 0);
`;

const V = (file, line, msg) => `${file}|${line}|${msg}`;
const OLD1 = V('internal/a/x.go', 10, 'identifier "OnPremisesSID" names a deployment profile');
const OLD2 = V('internal/b/y.go', 20, 'os.Getenv reads an environment variable whose name is not a constant');
const NEW1 = V('internal/c/z.go', 5, 'identifier "CloudThing" names a deployment profile');

function setup({ gate = {}, main = [] } = {}) {
  const f = makeFactory({ config: (c) => { c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'check.mjs'], timeout_minutes: 5, ...gate }; } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'check.mjs'), CHECK);
  fs.writeFileSync(path.join(f.root, 'violations.txt'), main.length ? `${main.join('\n')}\n` : '');
  commitAll(f.root, 'ci fixture');
  return f;
}

/** A ticket branch that rewrites violations.txt; returns the ticket. */
async function branchWith(f, id, violations, extra = {}) {
  const wt = await ensureWorktree(f.ctx, id);
  fs.writeFileSync(path.join(wt.path, 'violations.txt'), violations.length ? `${violations.join('\n')}\n` : '');
  fs.writeFileSync(path.join(wt.path, `work-${id}.txt`), 'work\n');
  for (const [file, text] of Object.entries(extra)) fs.writeFileSync(path.join(wt.path, file), text);
  commitAll(wt.path, `work ${id}`);
  return { id, title: `work ${id}`, wt };
}

// ---- finding keys ------------------------------------------------------------------------

test('finding keys drop positions, durations and the worktree path, and ignore pass lines', () => {
  const root = '/srv/wt/cand-T-1';
  const key = (l) => findingKey(l, [root]);
  assert.equal(key(`${root}/internal/a/x.go:10: P1 (ADR-0002 fitness function): bad`), '<root>/internal/a/x.go: P1 (ADR-0002 fitness function): bad');
  assert.equal(key('internal/a/x.go:10:3: P1 (ADR-0002 fitness function): bad'), key('internal/a/x.go:99:1: P1 (ADR-0002 fitness function): bad'));
  assert.equal(key('activation table P2: ACT (ADR-0002 fitness function): packaging/windows exists'), 'activation table P2: ACT (ADR-0002 fitness function): packaging/windows exists');
  assert.equal(key('make: *** [tools/ci/ci.mk:42: fitness-profiles] Error 1'), 'FAILED fitness-profiles');
  assert.equal(key('make[1]: *** [Makefile:3: sub] Error 2'), 'FAILED sub');
  assert.equal(key('--- FAIL: TestThing (0.12s)'), 'FAIL TestThing');
  assert.equal(key('FAIL\tgithub.com/x/y\t1.234s'), 'FAIL github.com/x/y');
  assert.equal(key('\x1b[31m  foo_test.go:12: got 1 want 2\x1b[0m'), 'foo_test.go: got 1 want 2');
  assert.equal(key('fitness-sso: FAIL: record O-4 missing'), 'fitness-sso: FAIL: record O-4 missing');
  for (const quiet of ['', 'ok  \tgithub.com/x/y\t0.4s', 'fitness-profiles: ok (P1,P4)', 'fitness-profiles: 93 violation(s); rules: adr', 'make: Target ci not remade because of errors.', 'go: downloading x v1', 'P3  ACTIVE, FAILING  EXISTS: internal/connector/ad']) {
    assert.equal(key(quiet), null, JSON.stringify(quiet));
  }
});

test('newFindings is a multiset difference', () => {
  const base = extractFindings('a.go:1: m\na.go:2: m\nb.go:3: n\n');
  assert.deepEqual(newFindings(base, extractFindings('a.go:9: m\na.go:8: m\nb.go:1: n\n')), []);
  assert.deepEqual(newFindings(base, extractFindings('a.go:9: m\na.go:8: m\na.go:7: m\nb.go:1: n\nc.go:1: o\n')), [
    { key: 'a.go: m', extra: 1, known: 2 }, { key: 'c.go: o', extra: 1, known: 0 },
  ]);
});

// ---- the gate ----------------------------------------------------------------------------

test('main red for known findings: a branch that adds one is refused naming it', async () => {
  const f = setup({ main: [OLD1, OLD2] });
  try {
    const t = await branchWith(f, 'T-0001', [OLD1, OLD2, NEW1]);
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'blocked');
    assert.equal(v.mode, 'new-findings');
    assert.deepEqual(v.findings, ['internal/c/z.go: P1 (ADR-0002 fitness function): identifier "CloudThing" names a deployment profile']);
    assert.match(blockedNote(v, 'main'), /CloudThing/);
    assert.ok(fs.existsSync(v.log) && fs.existsSync(v.baseLog));
    assert.equal(git(f.root, 'worktree', 'list').split('\n').length, 2, 'gate worktrees are removed (main + T-0001)');
  } finally { f.cleanup(); }
});

test('main red: a branch that adds none passes, even when the old findings move lines', async () => {
  const f = setup({ main: [OLD1, OLD2] });
  try {
    const moved = [V('internal/a/x.go', 11, 'identifier "OnPremisesSID" names a deployment profile'), OLD2.replace('|20|', '|44|')];
    const t = await branchWith(f, 'T-0001', moved);
    const v = await runPreMergeGate(f.ctx, t);
    assert.deepEqual([v.status, v.mode, v.findings], ['pass', 'ratchet', []]);
    const fewer = await runPreMergeGate(f.ctx, await branchWith(f, 'T-0002', [OLD1]));
    assert.equal(fewer.status, 'pass', 'fixing an old finding is fine');
  } finally { f.cleanup(); }
});

test('a second copy of a known finding counts as new', async () => {
  const f = setup({ main: [OLD1] });
  try {
    const t = await branchWith(f, 'T-0001', [OLD1, V('internal/a/x.go', 30, 'identifier "OnPremisesSID" names a deployment profile')]);
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'blocked');
    assert.match(v.findings[0], /\(1 more than the 1 on main\)/);
  } finally { f.cleanup(); }
});

test('main green: a branch that adds a finding is refused; a clean one passes untouched', async () => {
  const f = setup();
  try {
    const bad = await runPreMergeGate(f.ctx, await branchWith(f, 'T-0001', [NEW1]));
    assert.deepEqual([bad.status, bad.mode], ['blocked', 'main-green']);
    assert.match(bad.findings.join('\n'), /CloudThing/);
    const good = await runPreMergeGate(f.ctx, await branchWith(f, 'T-0002', []));
    assert.deepEqual([good.status, good.mode], ['pass', 'green']);
  } finally { f.cleanup(); }
});

test('a job that was green on main and is now red is refused even with no finding line', async () => {
  const f = setup({ main: [OLD1] });
  try {
    const t = await branchWith(f, 'T-0001', [OLD1], { 'targets.txt': 'lint-go\n' });
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'blocked');
    assert.deepEqual(v.findings, ['FAILED lint-go']);
  } finally { f.cleanup(); }
});

test('a red run with nothing recognisable is refused rather than compared', async () => {
  const f = setup({ main: [OLD1], gate: { argv: ['node', '-e', 'console.error("boom"); process.exit(3)'] } });
  try {
    const v = await runPreMergeGate(f.ctx, await branchWith(f, 'T-0001', [OLD1]));
    assert.deepEqual([v.status, v.mode], ['blocked', 'unrecognised']);
  } finally { f.cleanup(); }
});

test('the baseline run is cached per main commit', async () => {
  const f = setup({ main: [OLD1] });
  try {
    await runPreMergeGate(f.ctx, await branchWith(f, 'T-0001', [OLD1, NEW1]));
    const dir = path.join(f.ctx.stateDir, 'premerge');
    const cached = fs.readdirSync(dir).filter((n) => /^baseline-.*\.json$/.test(n));
    assert.equal(cached.length, 1);
    const logMtime = fs.statSync(path.join(dir, cached[0].replace('.json', '.log'))).mtimeMs;
    await runPreMergeGate(f.ctx, await branchWith(f, 'T-0002', [OLD1, NEW1]));
    assert.equal(fs.statSync(path.join(dir, cached[0].replace('.json', '.log'))).mtimeMs, logMtime, 'not re-run');
  } finally { f.cleanup(); }
});

test('a timeout throws: the gate never passes a branch it could not judge', async () => {
  const f = setup({ gate: { argv: ['node', '-e', 'setTimeout(() => {}, 60000)'], timeout_minutes: 0.005 } });
  try {
    const t = await branchWith(f, 'T-0001', []);
    await assert.rejects(runPreMergeGate(f.ctx, t), /timed out/);
    assert.equal(git(f.root, 'worktree', 'list').split('\n').length, 2, 'scratch worktree removed after the timeout');
  } finally { f.cleanup(); }
});

test('a branch that no longer merges cleanly is reported as a conflict', async () => {
  const f = setup();
  try {
    const t = await branchWith(f, 'T-0001', [], { 'shared.txt': 'from branch\n' });
    fs.writeFileSync(path.join(f.root, 'shared.txt'), 'from main\n');
    commitAll(f.root, 'main moves');
    assert.equal((await runPreMergeGate(f.ctx, t)).status, 'conflict');
  } finally { f.cleanup(); }
});

// ---- in the dispatcher ---------------------------------------------------------------------

async function finished(f, title, violations) {
  const t = createTicket(f.ctx, ticketInput({ title, status: 'ready' }), 'x');
  const wt = await ensureWorktree(f.ctx, t.id);
  fs.writeFileSync(path.join(wt.path, 'violations.txt'), violations.length ? `${violations.join('\n')}\n` : '');
  fs.writeFileSync(path.join(wt.path, `work-${t.id}.txt`), 'work\n');
  commitAll(wt.path, `work ${t.id}`);
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  return t;
}

test('the dispatcher reopens a ticket the gate refuses, leaves main alone, and merges one it passes', async () => {
  const f = setup({ main: [OLD1] });
  try {
    const bad = await finished(f, 'adds one', [OLD1, NEW1]);
    const ok = await finished(f, 'adds none', [OLD1]);
    const mainBefore = git(f.root, 'rev-parse', 'main');
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    await d.mergePass();
    await d.gateIdle();
    let out = Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));
    assert.deepEqual([out[bad.id].status, out[bad.id].stage_role], ['in_progress', 'backend-engineer']);
    assert.match(out[bad.id].notes.at(-1).text, /pre-merge gate refused the merge[\s\S]*CloudThing/);
    assert.equal(git(f.root, 'rev-parse', 'main'), mainBefore, 'nothing merged');
    assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '');
    await d.mergePass();
    await d.gateIdle();
    out = Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));
    assert.ok(out[ok.id].links.merged, 'the clean ticket merged');
    assert.match(readRecentEvents(f.ctx, 50).map((e) => e.text).join('\n'), /pre-merge gate passed \(ratchet\)/);
    assert.notEqual(git(f.root, 'rev-parse', 'main'), mainBefore);
  } finally { f.cleanup(); }
});

test('when the gate cannot judge, the ticket stays done, unmerged, and is retried only later', async () => {
  const f = setup({ gate: { argv: ['node', '-e', 'setTimeout(() => {}, 60000)'], timeout_minutes: 0.005 } });
  try {
    const t = await finished(f, 'slow', []);
    const mainBefore = git(f.root, 'rev-parse', 'main');
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    await d.mergePass();
    await d.gateIdle();
    const cur = listEntities(f.ctx, 'tickets').find((x) => x.id === t.id);
    assert.equal(cur.status, 'done');
    assert.equal(cur.links.merged, undefined);
    assert.equal(git(f.root, 'rev-parse', 'main'), mainBefore);
    await d.mergePass();
    assert.equal(d.gateRun, null, 'backing off: not retried at once');
  } finally { f.cleanup(); }
});


// ---- one fixture per violation shape (T-0973) --------------------------------------------------
// Every job in `make fitness` prints violations in the shape its Go type formats them (the Sprintf
// in tools/fitness/<job>). A shape findingKey does not recognise is red on main yet lets a new
// violation through, so each job has a sample line, copied from that format, and the table below
// must name every job of the target. `moved` is the same finding after a line moved; `other` is a
// different violation of the same job.
const JOBS = {
  'fitness-modules': {
    line: 'internal/compose/server/catalogue.go:7: [blueprint §2.5] internal/compose/server imports internal/modules/reports; only the generated modules.gen.go may name a module',
    moved: 'internal/compose/server/catalogue.go:9: [blueprint §2.5] internal/compose/server imports internal/modules/reports; only the generated modules.gen.go may name a module',
    other: 'internal/compose/server/catalogue.go:8: [blueprint §2.5] internal/compose/server imports internal/modules/directory; only the generated modules.gen.go may name a module',
  },
  'fitness-sso': {
    line: 'fitness-sso: FAIL: internal/platform/authn/sso/saml/x.go:12 imports github.com/crewjam/saml outside authn/sso/saml',
    moved: 'fitness-sso: FAIL: internal/platform/authn/sso/saml/x.go:12 imports github.com/crewjam/saml outside authn/sso/saml',
    other: 'fitness-sso: FAIL: go.mod: goxmldsig is below the v1.6.0 floor',
  },
  'fitness-stack': {
    line: 'go.mod: F4 (ADR-0001 rule 4): golang.org/x/text has no row in the licence register',
    moved: 'go.mod: F4 (ADR-0001 rule 4): golang.org/x/text has no row in the licence register',
    other: 'internal/platform/kekopen: F2 (ADR-0001 rule 2): platform adapter names a vendor',
  },
  'fitness-tenancy': {
    line: 'T2 public.widgets [rls-enabled]: tenant table has row level security disabled',
    moved: 'T2 public.widgets [rls-enabled]: tenant table has row level security disabled',
    other: 'T1 owner role [migrations-apply]: does not apply on an empty database as the migration role: boom',
  },
  'fitness-domain-keys': {
    line: 'X3 public.directory_user [dn-key]: table is keyed on a distinguished name',
    moved: 'X3 public.directory_user [dn-key]: table is keyed on a distinguished name',
    other: 'X5 public.audit_event [no-update]: an UPDATE grant exists on an append-only table',
  },
  'fitness-profiles': {
    line: 'internal/directory/inventory/objects.go:157: P1 (ADR-0002 fitness function): identifier "OnPremisesSyncRead" names a deployment profile ("onprem"); name the capability or the setting, never the profile (ADR-0002 rule 1)',
    moved: 'internal/directory/inventory/objects.go:200: P1 (ADR-0002 fitness function): identifier "OnPremisesSyncRead" names a deployment profile ("onprem"); name the capability or the setting, never the profile (ADR-0002 rule 1)',
    other: 'activation table P3: ACT (ADR-0002 fitness function): internal/connector/ad exists, the connector conformance check is deferred past its expiry',
  },
  'fitness-proto': {
    line: 'proto/skenzeriq/agent/v1/agent.proto:14:3: [AG4] field "blob" is bytes; policy data is typed',
    moved: 'proto/skenzeriq/agent/v1/agent.proto:20:3: [AG4] field "blob" is bytes; policy data is typed',
    other: 'proto/skenzeriq/agent/v1/agent.proto:30:3: [AG5] field "any" is google.protobuf.Any',
  },
  'fitness-safeprim': {
    line: 'internal/platform/jobs/queue.go:146: FF-SP2 [sqlconst] SQL argument of Exec is not a constant or reportsql.CompiledSQL',
    moved: 'internal/platform/jobs/queue.go:151: FF-SP2 [sqlconst] SQL argument of Exec is not a constant or reportsql.CompiledSQL',
    other: 'internal/platform/jobs/queue.go:200: FF-SP2 [dnstring] distinguished name built with fmt.Sprintf',
  },
  'fitness-corpus': {
    line: 'internal/directory/ldap/corpus/ldapfilter.jsonl: FF-SP4 [min-hostile]: unit p1.filter has 3 records with "hostile": true, needs 10',
    moved: 'internal/directory/ldap/corpus/ldapfilter.jsonl: FF-SP4 [min-hostile]: unit p1.filter has 3 records with "hostile": true, needs 10',
    other: 'internal/directory/ldap/corpus/ldapfilter.jsonl: FF-SP4 [retired]: retired record p1.filter/r7 needs supersededBy and reason',
  },
  'fitness-oracles': {
    line: 'attr.sid: FF-SP6 [pslit] record r12 rejected by the PowerShell parser: Unexpected token',
    moved: 'attr.sid: FF-SP6 [pslit] record r12 rejected by the PowerShell parser: Unexpected token',
    other: 'p1.filter: FF-SP6 [ldapfilter] record r3 does not parse',
  },
  'fitness-api': {
    line: 'web/src/api/open-enum.test.ts: [ADR-0004 A5] only the generated files and client.ts live in web/src/api (ADR-0004 rule 12); a hand-written client file is a private endpoint caller',
    moved: 'web/src/api/open-enum.test.ts: [ADR-0004 A5] only the generated files and client.ts live in web/src/api (ADR-0004 rule 12); a hand-written client file is a private endpoint caller',
    other: 'internal/platform/report/cell.go:5: [ADR-0004 A7] imports encoding/json (v1): product code uses encoding/json/v2',
  },
  'fitness-operation': {
    line: 'internal/platform/operation/step.go:40: O1 [rule 2] step escapes the operation kernel',
    moved: 'internal/platform/operation/step.go:44: O1 [rule 2] step escapes the operation kernel',
    other: 'internal/platform/operation/queue.go:9: O4 [rule 3] SQL is not constant',
  },
  'fitness-audit': {
    line: 'A1 audit_head [genesis-trigger]: audit_head has no genesis trigger',
    moved: 'A1 audit_head [genesis-trigger]: audit_head has no genesis trigger',
    other: 'A2 internal/platform/audit/chain_test.go [test-missing]: no test TestChainDetectsReorder',
  },
  'fitness-objectid': {
    line: 'internal/directory/x/y.go:12:9: conversion to authz.ObjectID is forbidden',
    moved: 'internal/directory/x/y.go:30:9: conversion to authz.ObjectID is forbidden',
    other: 'internal/directory/x/z.go:3:2: conversion to authz.ObjectID is forbidden',
  },
  'fitness-grantbootstrap': {
    line: 'internal/modules/rbac/grant.go:55:4: reference to GrantBootstrap',
    moved: 'internal/modules/rbac/grant.go:70:4: reference to GrantBootstrap',
    other: 'internal/modules/rbac/grant.go:80:4: string mentions GrantBootstrap (reflection or code generation)',
  },
  'fitness-disclosure': {
    line: '.well-known/security.txt:7: Expires 2026-11-01T00:00:00Z is less than 30 days away; renew it (new Expires under a year ahead)',
    moved: '.well-known/security.txt:9: Expires 2026-11-01T00:00:00Z is less than 30 days away; renew it (new Expires under a year ahead)',
    other: 'SECURITY.md: missing (vulnerability disclosure policy): open SECURITY.md: no such file',
  },
  'fitness-packaging': {
    line: 'packaging/linux-oci/prepare-tls-dir.sh: directory is not mode 0700 afterwards',
    moved: 'packaging/linux-oci/prepare-tls-dir.sh: directory is not mode 0700 afterwards',
    other: 'packaging/linux-oci/compose.yml: the server must run as a numeric non-root user: "uid:gid"',
  },
  'fitness-host': {
    line: 'fitness-host: FAIL HOST-IDENT: service account is root',
    moved: 'fitness-host: FAIL HOST-IDENT: service account is root',
    other: 'fitness-host: FAIL HOST-NO-DUMPS: core dumps are not disabled',
  },
  'fitness-agent-host': {
    line: 'fitness-agent-host: A4: agent closure imports github.com/skenzeriq/activediq/internal/compose/tunnelbind, which is not on the allowlist tools/fitness/agenthost/closure-allow.txt (GOOS=windows)',
    moved: 'fitness-agent-host: A4: agent closure imports github.com/skenzeriq/activediq/internal/compose/tunnelbind, which is not on the allowlist tools/fitness/agenthost/closure-allow.txt (GOOS=windows)',
    other: 'fitness-agent-host: R3: agent module internal/modules/x imports os/exec',
  },
  'fitness-built-msi': {
    line: 'fitness-built-msi: dist/activeDIQ-agent.msi: ServiceInstall runs as LocalSystem',
    moved: 'fitness-built-msi: dist/activeDIQ-agent.msi: ServiceInstall runs as LocalSystem',
    other: 'fitness-built-msi: dist/activeDIQ-agent.msi: CustomAction runs a script',
  },
  'fitness-update': {
    line: 'tampered-artefact/online: accepted a bad update; want refusal "hash-mismatch"',
    moved: 'tampered-artefact/online: accepted a bad update; want refusal "hash-mismatch"',
    other: 'rollback/online: accepted a bad update; want refusal "rollback"',
  },
  'fitness-update-offline': {
    line: 'tampered-artefact/offline: accepted a bad update; want refusal "hash-mismatch"',
    moved: 'tampered-artefact/offline: accepted a bad update; want refusal "hash-mismatch"',
    other: 'fitness-update-offline: FAIL: the container reached the network under --network none',
  },
  'fitness-keys': {
    line: 'internal/platform/keys/keys.go:88 FF-KEY-2 [owner]: tenant_keys is touched outside internal/platform/keys',
    moved: 'internal/platform/keys/keys.go:91 FF-KEY-2 [owner]: tenant_keys is touched outside internal/platform/keys',
    other: 'internal/compose/server/kek.go:12 FF-KEY-3 [kek-config]: KEK config is read outside the composition root',
  },
  'fitness-fleet-ca-scope': {
    line: 'internal/platform/fleetca/sign.go:30 FCS-1 [key-use]: the server CA key is unsealed outside SignServerLeaf',
    moved: 'internal/platform/fleetca/sign.go:34 FCS-1 [key-use]: the server CA key is unsealed outside SignServerLeaf',
    other: 'migrations/0090.sql:4 FCS-5 [tenant-id]: fleet_server_ca is installation scope: no tenant_id column',
  },
  'fitness-reports': {
    line: 'internal/modules/reports/run/x.go:20 RP2 [readscope]: ReadScope.Terms is called outside authz and reportsql',
    moved: 'internal/modules/reports/run/x.go:25 RP2 [readscope]: ReadScope.Terms is called outside authz and reportsql',
    other: 'internal/platform/report/library/LOCK RP7 [append-only]: library/LOCK lost an entry against main',
  },
};

const fitnessTargets = () => {
  const mk = fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../tools/ci/ci.mk'), 'utf8');
  const m = /^fitness:\s*(.*?)\s*##/m.exec(mk);
  assert.ok(m, 'tools/ci/ci.mk defines the fitness target');
  // The recipe also runs fitness-modules; the others are prerequisites.
  return new Set([...m[1].split(/\s+/).filter(Boolean), 'fitness-modules']);
};

test('every job in make fitness has a violation fixture, so none is red on main but unratcheted', () => {
  const targets = fitnessTargets();
  const have = new Set(Object.keys(JOBS));
  assert.deepEqual([...targets].filter((t) => !have.has(t)).sort(), [], 'a fitness job has no fixture: add its violation line to JOBS in factory/test/premerge.test.mjs, and make findingKey recognise the shape');
  assert.deepEqual([...have].filter((t) => !targets.has(t)).sort(), [], 'a fixture names a job that is not in make fitness: delete it');
});

for (const [job, s] of Object.entries(JOBS)) {
  test(`${job}: a violation is a finding, a moved one is the same finding, another one is new`, () => {
    const key = findingKey(s.line);
    assert.ok(key, `findingKey does not recognise ${job}'s violation line: ${s.line}`);
    assert.equal(findingKey(s.moved), key, 'a line number is not part of the finding');
    assert.ok(findingKey(s.other), `findingKey does not recognise ${job}'s other line: ${s.other}`);
    assert.notEqual(findingKey(s.other), key);
    // The job's summary and progress lines are not findings.
    const name = job.replace(/^fitness-/, '');
    for (const quiet of [`fitness-${name}: 3 violation(s); rules: x`, `fitness-${name}: ok (X1)`, `fitness-${name}: FAIL: 2 problem(s)`]) {
      assert.equal(findingKey(quiet), null, quiet);
    }
    const base = extractFindings(`${s.line}\nmake: *** [tools/ci/ci.mk:9: ${job}] Error 1\n`);
    assert.deepEqual(newFindings(base, extractFindings(`${s.moved}\nmake: *** [tools/ci/ci.mk:9: ${job}] Error 1\n`)), []);
    assert.deepEqual(newFindings(base, extractFindings(`${s.line}\n${s.other}\nmake: *** [tools/ci/ci.mk:9: ${job}] Error 1\n`)).map((f) => f.key), [findingKey(s.other)]);
  });
}

test('through the gate, one violation added to any job shape is refused naming it, and moved ones pass', async () => {
  // One run per distinct way of writing a finding: the key of each job's line with the job's own words removed.
  const shapes = new Map();
  for (const [job, s] of Object.entries(JOBS)) {
    const shape = s.line.replace(/[A-Za-z0-9_.\/-]+/g, 'w').replace(/w( w)+/g, 'w').slice(0, 40);
    if (!shapes.has(shape)) shapes.set(shape, { job, ...s });
  }
  assert.ok(shapes.size >= 6, `expected several distinct shapes, got ${shapes.size}`);
  const f = setup({});
  try {
    let n = 0;
    for (const { job, line, moved, other } of shapes.values()) {
      n += 1;
      fs.writeFileSync(path.join(f.root, 'raw.txt'), `${line}\n`);
      commitAll(f.root, `main is red in ${job}`);
      const refused = await branchWith(f, `T-9${n}01`, [], { 'raw.txt': `${line}\n${other}\n` });
      const v = await runPreMergeGate(f.ctx, refused);
      assert.deepEqual([v.status, v.mode, v.findings], ['blocked', 'new-findings', [findingKey(other)]], job);
      assert.match(blockedNote(v, 'main'), new RegExp(other.split(/\s/)[0].replace(/[^\w]/g, '.').slice(0, 12)), job);
      const same = await branchWith(f, `T-9${n}02`, [], { 'raw.txt': `${moved}\n` });
      const p = await runPreMergeGate(f.ctx, same);
      assert.deepEqual([p.status, p.mode], ['pass', 'ratchet'], job);
    }
  } finally { f.cleanup(); }
});

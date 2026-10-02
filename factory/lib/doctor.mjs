// `factory doctor`: validate config, state, agents, model policy, claude and git.
import fs from 'node:fs';
import path from 'node:path';
import { ensureStateDirs, listEntities, openStore } from './store.mjs';
import { validateFlows, resolveFlow, TICKET_TYPES } from './flows.mjs';
import { loadAgents } from './agents.mjs';
import { checkAgentPolicy } from './policy.mjs';
import { claudeBinary } from './launcher.mjs';
import { git } from './git.mjs';
import { isOpen } from './tickets.mjs';

const REQUIRED_SECTIONS = ['board', 'dispatcher', 'context', 'models', 'ceo', 'flows', 'library'];
/** Roles the dispatcher itself assigns work to. */
const IMPLICIT_ROLES = ['factory-director', 'project-manager'];

function onPath(binary) {
  const candidates = path.isAbsolute(binary) || binary.includes(path.sep)
    ? [binary]
    : (process.env.PATH ?? '').split(path.delimiter).filter(Boolean).map((dir) => path.join(dir, binary));
  for (const file of candidates) {
    try {
      fs.accessSync(file, fs.constants.X_OK);
      if (fs.statSync(file).isFile()) return file;
    } catch {
      // keep looking
    }
  }
  return null;
}

/**
 * Top-level keys that appear more than once in a JSON document (JSON.parse silently keeps the last).
 * @param {string} text
 * @returns {string[]}
 */
export function duplicateTopLevelKeys(text) {
  const seen = new Set();
  const dupes = new Set();
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      let k = j + 1;
      while (/\s/.test(text[k] ?? '')) k++;
      if (depth === 1 && text[k] === ':') {
        const key = JSON.parse(text.slice(i, j + 1));
        if (seen.has(key)) dupes.add(key);
        seen.add(key);
      }
      i = j;
    } else if (c === '{' || c === '[') {
      depth++;
    } else if (c === '}' || c === ']') {
      depth--;
    }
  }
  return [...dupes];
}

/**
 * Run every check.
 * @param {string} home FACTORY_HOME
 * @returns {Promise<{checks: Array<{level: 'PASS'|'WARN'|'FAIL', name: string, detail: string}>, failed: boolean}>}
 */
export async function runDoctor(home) {
  const checks = [];
  const add = (level, name, detail = '') => checks.push({ level, name, detail });
  const finish = () => ({ checks, failed: checks.some((c) => c.level === 'FAIL') });

  add(Number(process.versions.node.split('.')[0]) >= 20 ? 'PASS' : 'FAIL', 'node', `v${process.versions.node} (need ≥ 20)`);

  const ctx = openStore(home, { lenient: true });
  if (ctx.configError) {
    add('FAIL', 'config.json', ctx.configError);
    return finish();
  }
  const { config } = ctx;
  const missing = REQUIRED_SECTIONS.filter((k) => !config[k]);
  if (missing.length) {
    add('FAIL', 'config.json', `missing section(s): ${missing.join(', ')}`);
    return finish();
  }
  add('PASS', 'config.json', 'parses');
  const dupes = duplicateTopLevelKeys(fs.readFileSync(path.join(home, 'config.json'), 'utf8'));
  if (dupes.length) add('WARN', 'config.json', `duplicate top-level key(s) ${dupes.map((k) => `"${k}"`).join(', ')}: only the last value is used, the earlier one is silently lost`);

  const flowProblems = validateFlows(config);
  if (flowProblems.length) flowProblems.forEach((p) => add('FAIL', 'flows', p));
  else add('PASS', 'flows', `${TICKET_TYPES.length} ticket types resolve`);

  const created = ensureStateDirs(ctx);
  add('PASS', 'state directories', created.length ? `created ${created.length} missing` : 'all present');

  const kinds = ['tickets', 'epics', 'milestones', 'decisions', 'actions', 'feedback', 'runs'];
  const data = Object.fromEntries(kinds.map((k) => [k, listEntities(ctx, k)]));
  if (ctx.badFiles.size) {
    for (const [file, msg] of ctx.badFiles) add('WARN', 'state file', `${path.relative(home, file)}: ${msg}`);
  } else {
    add('PASS', 'state files', 'all readable');
  }

  // agents
  const agents = loadAgents(ctx);
  if (!agents.size) add('FAIL', 'agents', `no agent definitions in ${ctx.agentsDir}`);
  const needed = new Set([...IMPLICIT_ROLES, ...(config.models.escalation_roles ?? [])]);
  for (const type of TICKET_TYPES) {
    try {
      for (const stage of resolveFlow(config, type)) {
        if (stage.role && stage.role !== '$owner') needed.add(stage.role);
        stage.extra.forEach((e) => needed.add(e.role));
      }
    } catch {
      // already reported under "flows"
    }
  }
  for (const t of data.tickets.filter(isOpen)) needed.add(t.owner);
  const absent = [...needed].filter((r) => !agents.has(r)).sort();
  if (agents.size) {
    if (absent.length) add('FAIL', 'agents', `no agent file for: ${absent.join(', ')}`);
    else add('PASS', 'agents', `${agents.size} defined; every flow role and ticket owner has one`);
  }
  const violations = [...agents.values()].flatMap((a) => checkAgentPolicy(config, a).map((v) => `${a.name}: ${v}`));
  if (agents.size) {
    if (violations.length) violations.forEach((v) => add('FAIL', 'model policy', v));
    else add('PASS', 'model policy', 'every agent complies');
  }

  // references
  const ids = Object.fromEntries(kinds.map((k) => [k, new Set(data[k].map((e) => e.id))]));
  const dangling = data.tickets.filter(isOpen).flatMap((t) => [
    ...(t.depends_on ?? []).filter((d) => !ids.tickets.has(d)).map((d) => `${t.id} → ${d}`),
    ...(t.decisions ?? []).filter((d) => !ids.decisions.has(d)).map((d) => `${t.id} → ${d}`),
    ...(t.epic && !ids.epics.has(t.epic) ? [`${t.id} → ${t.epic}`] : []),
  ]);
  if (dangling.length) add('WARN', 'references', `dangling: ${dangling.join(', ')}`);

  // claude
  const bin = claudeBinary();
  const found = onPath(bin);
  if (found) add('PASS', 'claude', found);
  else add('FAIL', 'claude', `"${bin}" not found on PATH`);

  // git
  const inside = await git(ctx.root, ['rev-parse', '--is-inside-work-tree']);
  if (inside.code !== 0) {
    add('FAIL', 'git', `${ctx.root} is not a git repository`);
  } else {
    add('PASS', 'git', 'repository present');
    const main = config.dispatcher.main_branch;
    const head = await git(ctx.root, ['rev-parse', '--verify', '-q', 'HEAD']);
    if (head.code !== 0) {
      const current = (await git(ctx.root, ['symbolic-ref', '--short', '-q', 'HEAD'])).stdout.trim();
      add('WARN', 'git commits', 'no commits yet: workers run in the main checkout and max_parallel is 1 for code tickets');
      add(current === main ? 'PASS' : 'WARN', 'git branch', `unborn branch "${current}"${current === main ? '' : `, config expects "${main}"`}`);
    } else {
      add('PASS', 'git commits', 'repository has commits');
      const has = (await git(ctx.root, ['show-ref', '--verify', '--quiet', `refs/heads/${main}`])).code === 0;
      add(has ? 'PASS' : 'FAIL', 'git branch', has ? `main branch "${main}" exists` : `main branch "${main}" does not exist`);
    }
    const email = await git(ctx.root, ['config', 'user.email']);
    const name = await git(ctx.root, ['config', 'user.name']);
    if (email.code !== 0 || name.code !== 0) add('WARN', 'git identity', 'user.name / user.email are not set: merges and worker commits will fail');
  }
  return finish();
}

// The `factory` command line. Output goes through `io` so tests can capture it.
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { FactoryError, UsageError } from './errors.mjs';
import {
  EVENT_KINDS, appendEvent, ensureStateDirs, listEntities, listRecentRuns, openStore, requireEntity, resolveHome, setControl,
} from './store.mjs';
import {
  addNote, advanceTicket, blockTicket, cancelTicket, createTicket, markReady, rejectTicket, setTicketFields, unblockTicket,
} from './tickets.mjs';
import {
  acknowledgeNotice, answerDecision, createDecision, markApplied, parseDuration, parseOptionSpec, vetoNotice, withdrawDecision,
} from './decisions.mjs';
import {
  completeAction, createAction, createEpic, createFeedback, createMilestone, listItems, setEpic, setMilestone, sortById, triageFeedback,
} from './items.mjs';
import { createHandoff, latestHandoff } from './handoffs.mjs';
import { Dispatcher, planDryRun } from './dispatcher.mjs';
import { runDoctor } from './doctor.mjs';
import { buildDigest, buildStatus } from './status.mjs';
import { down, up } from './lifecycle.mjs';
import {
  formatDecision, formatDecisionList, formatDigest, formatDoctor, formatDryRun, formatStatus, formatTicket, formatTicketList, table,
} from './format.mjs';

const LIB_DIR = path.dirname(fileURLToPath(import.meta.url));
const FALLBACK_HOME = path.resolve(LIB_DIR, '..');
const BIN_PATH = path.join(FALLBACK_HOME, 'bin', 'factory');

const USAGE = `usage: factory <command>

  up | down | status [--json] | pause [--reason R] | resume | doctor
  board [--port N]                  run the board in the foreground
  run [--once] [--dry-run]          run the dispatcher in the foreground

  ticket new --title T --type TYPE --owner ROLE [--priority P2] [--epic E] [--milestone M]
             [--depends T-1,T-2] [--decisions D-1] [--tags a,b] [--parity ADM-1] [--summary S]
             [--body-file F] [--ac "…"]... [--status backlog|ready]
  ticket list [--status S] [--owner R] [--epic E] | show ID | ready ID | note ID --by ROLE "text"
  ticket advance|reject|block|unblock|cancel ID --by ROLE --note "…"
  ticket set ID field=value …       priority owner epic milestone effort_override tags depends_on decisions

  decision new --kind K --title T --question Q --option "a|Label|summary"... [--recommend a]
               [--rationale R] [--context-file F] [--default a --default-in 72h] [--blocks T-1] [--multi] [--force]
  decision list [--status S] | show ID | answer ID --option a[,b] [--note N] | applied ID --by ROLE
  decision withdraw ID --by ROLE --note N
  decision ack ID [--note N] | veto ID --note N      (notices only)
  action new --title T --detail D --why W | list | done ID [--note N]
  feedback new --target X --text T [--sentiment love|ok|change] | list | triage ID --note N [--tickets T-1] [--done]
  epic new --title T [--goal G] [--milestone M] [--parity A,B] | list | show ID
  epic set ID field=value …         title goal milestone parity_refs=A,B | parity_refs+=C | parity_refs-=A
  milestone new --name N [--goal G] [--target D] | list | show ID | set ID status=…
  handoff new ID --by ROLE | latest ID
  event --actor A --kind K [--ticket T] "text"
  digest [--json]

Add --json for machine-readable output. FACTORY_HOME overrides home discovery.`;

const csv = (s) => (s ? s.split(',').map((x) => x.trim()).filter(Boolean) : []);

function need(values, ...names) {
  for (const n of names) if (values[n] === undefined || values[n] === '') throw new UsageError(`--${n} is required`);
}

function who(values, env) {
  const by = values.by ?? env.FACTORY_ROLE;
  if (!by) throw new UsageError('--by ROLE is required (or set FACTORY_ROLE)');
  return by;
}

function assignments(pairs) {
  const out = {};
  for (const pair of pairs) {
    const at = pair.indexOf('=');
    if (at < 1) throw new UsageError(`expected field=value, got "${pair}"`);
    out[pair.slice(0, at)] = pair.slice(at + 1);
  }
  if (!Object.keys(out).length) throw new UsageError('nothing to set (expected field=value …)');
  return out;
}

const str = { type: 'string' };
const bool = { type: 'boolean' };
const many = { type: 'string', multiple: true };

/**
 * Command table: `options` (util.parseArgs) and `run`, which may return an exit code. `standalone`
 * commands get `home` but no opened store (doctor must work when config.json is broken).
 * `c` = { home, ctx, values, pos, out, env, print(data, textFn) }.
 */
const COMMANDS = {
  up: { options: {}, run: (c) => {
    const started = up(c.ctx, BIN_PATH);
    c.out(`board       ${started.board.url}  (pid ${started.board.pid})\ndispatcher  pid ${started.dispatcher.pid}\nlogs        ${c.ctx.stateDir}/{board,dispatcher}.log`);
  } },
  down: { options: {}, run: (c) => {
    const stopped = down(c.ctx);
    c.out(`board       ${stopped.board ? `stopping (pid ${stopped.board})` : 'was not running'}`);
    c.out(`dispatcher  ${stopped.dispatcher ? `stopping (pid ${stopped.dispatcher}); running workers get up to 2 minutes to finish` : 'was not running'}`);
  } },
  status: { options: {}, run: (c) => {
    const status = buildStatus(c.ctx);
    c.print(status, () => formatStatus(status, c.ctx.now().getTime()));
  } },
  pause: { options: { reason: str, by: str }, run: (c) => {
    setControl(c.ctx, { paused: true, reason: c.values.reason ?? null, by: c.values.by ?? 'cli' });
    c.out('paused: running workers will finish, nothing new launches');
  } },
  resume: { options: { by: str }, run: (c) => {
    setControl(c.ctx, { paused: false, by: c.values.by ?? 'cli' });
    c.out('resumed');
  } },
  doctor: { options: {}, standalone: true, run: async (c) => {
    const { checks, failed } = await runDoctor(c.home);
    c.print(checks, () => formatDoctor(checks));
    return failed ? 1 : 0;
  } },
  board: { options: { port: str }, run: async (c) => {
    const { runBoard } = await import('../board/server.mjs');
    const port = c.values.port === undefined ? undefined : Number(c.values.port);
    if (port !== undefined && !(Number.isInteger(port) && port >= 0 && port < 65536)) throw new UsageError('--port must be 0–65535');
    await runBoard(c.ctx, { port });
  } },
  run: { options: { once: bool, 'dry-run': bool }, run: async (c) => {
    if (c.values['dry-run']) {
      const plan = await planDryRun(c.ctx);
      return c.print(plan, () => formatDryRun(plan));
    }
    await new Dispatcher(c.ctx).run({ once: c.values.once });
    return undefined;
  } },

  'ticket new': { options: { title: str, type: str, owner: str, priority: str, epic: str, milestone: str, depends: str, decisions: str, tags: str, parity: str, summary: str, 'body-file': str, ac: many, status: str, by: str }, run: (c) => {
    need(c.values, 'title', 'type', 'owner');
    const v = c.values;
    const ticket = createTicket(c.ctx, {
      title: v.title, type: v.type, owner: v.owner, priority: v.priority, epic: v.epic ?? null, milestone: v.milestone ?? null,
      depends_on: csv(v.depends), decisions: csv(v.decisions), tags: csv(v.tags), parity_refs: csv(v.parity),
      summary: v.summary ?? '', body: v['body-file'] ? fs.readFileSync(v['body-file'], 'utf8') : '', acceptance: v.ac ?? [], status: v.status,
    }, v.by ?? c.env.FACTORY_ROLE ?? 'cli');
    c.print(ticket, () => `${ticket.id} created (${ticket.status})`);
  } },
  'ticket list': { options: { status: str, owner: str, epic: str }, run: (c) => {
    const { status, owner, epic } = c.values;
    const tickets = sortById(listEntities(c.ctx, 'tickets'))
      .filter((t) => (!status || t.status === status) && (!owner || t.owner === owner) && (!epic || t.epic === epic));
    c.print(tickets, () => formatTicketList(tickets));
  } },
  'ticket show': { options: {}, run: (c) => {
    const ticket = requireEntity(c.ctx, 'tickets', c.pos[0], 'ticket');
    const runs = listRecentRuns(c.ctx, 500).filter((r) => r.ticket === ticket.id);
    c.print({ ...ticket, runs }, () => formatTicket(ticket, runs));
  } },
  'ticket ready': { options: { by: str }, run: (c) => {
    const t = markReady(c.ctx, c.pos[0], c.values.by ?? c.env.FACTORY_ROLE ?? 'cli');
    c.print(t, () => `${t.id} is ready`);
  } },
  'ticket note': { options: { by: str }, run: (c) => {
    const t = addNote(c.ctx, c.pos[0], who(c.values, c.env), c.pos.slice(1).join(' '));
    c.print(t, () => `noted ${t.id}`);
  } },
  'ticket advance': { options: { by: str, note: str }, run: (c) => transitionCommand(c, advanceTicket, 'advanced') },
  'ticket reject': { options: { by: str, note: str }, run: (c) => transitionCommand(c, rejectTicket, 'rejected') },
  'ticket block': { options: { by: str, note: str }, run: (c) => transitionCommand(c, blockTicket, 'blocked') },
  'ticket unblock': { options: { by: str, note: str }, run: (c) => transitionCommand(c, unblockTicket, 'unblocked') },
  'ticket cancel': { options: { by: str, note: str }, run: (c) => transitionCommand(c, cancelTicket, 'cancelled') },
  'ticket set': { options: { by: str }, run: (c) => {
    const t = setTicketFields(c.ctx, c.pos[0], assignments(c.pos.slice(1)), c.values.by ?? c.env.FACTORY_ROLE ?? 'cli');
    c.print(t, () => `updated ${t.id}`);
  } },

  'decision new': { options: { kind: str, title: str, question: str, 'context-file': str, option: many, recommend: str, rationale: str, default: str, 'default-in': str, blocks: str, multi: bool, force: bool, by: str }, run: (c) => {
    need(c.values, 'kind', 'title', 'question');
    const v = c.values;
    const decision = createDecision(c.ctx, {
      kind: v.kind, title: v.title, question: v.question, context: v['context-file'] ? fs.readFileSync(v['context-file'], 'utf8') : '',
      options: (v.option ?? []).map(parseOptionSpec), multi: v.multi, recommendation: v.recommend ?? null, rationale: v.rationale ?? '',
      default_option: v.default ?? null, default_in_hours: v['default-in'] ? parseDuration(v['default-in']) : null, blocks: csv(v.blocks),
    }, { by: v.by ?? c.env.FACTORY_ROLE ?? 'factory-director', force: v.force });
    c.print(decision, () => `${decision.id} opened (${decision.kind})`);
  } },
  'decision list': { options: { status: str }, run: (c) => {
    const list = sortById(listEntities(c.ctx, 'decisions')).filter((d) => !c.values.status || d.status === c.values.status);
    c.print(list, () => formatDecisionList(list));
  } },
  'decision show': { options: {}, run: (c) => {
    const d = requireEntity(c.ctx, 'decisions', c.pos[0], 'decision');
    c.print(d, () => formatDecision(d));
  } },
  'decision answer': { options: { option: str, note: str, via: str }, run: (c) => {
    need(c.values, 'option');
    if (c.values.via && !['cli', 'board'].includes(c.values.via)) throw new UsageError('--via must be cli or board');
    const d = answerDecision(c.ctx, c.pos[0], { options: csv(c.values.option), note: c.values.note ?? '', via: c.values.via ?? 'cli' });
    c.print(d, () => `${d.id} answered: ${d.answer.options.join(', ')}`);
  } },
  'decision applied': { options: { by: str }, run: (c) => {
    const d = markApplied(c.ctx, c.pos[0], who(c.values, c.env));
    c.print(d, () => `${d.id} marked applied`);
  } },
  'decision ack': { options: { note: str }, run: (c) => {
    const d = acknowledgeNotice(c.ctx, c.pos[0], { note: c.values.note ?? '', by: 'cli' });
    c.print(d, () => `${d.id} acknowledged`);
  } },
  'decision veto': { options: { note: str }, run: (c) => {
    need(c.values, 'note');
    const d = vetoNotice(c.ctx, c.pos[0], { note: c.values.note, by: 'cli' });
    c.print(d, () => `${d.id} vetoed; feedback filed for triage`);
  } },
  'decision withdraw': { options: { by: str, note: str }, run: (c) => {
    need(c.values, 'note');
    const d = withdrawDecision(c.ctx, c.pos[0], who(c.values, c.env), c.values.note);
    c.print(d, () => `${d.id} withdrawn`);
  } },

  'action new': { options: { title: str, detail: str, why: str, by: str }, run: (c) => {
    need(c.values, 'title');
    const a = createAction(c.ctx, { title: c.values.title, detail: c.values.detail ?? '', why: c.values.why ?? '', by: c.values.by ?? c.env.FACTORY_ROLE ?? 'factory-director' });
    c.print(a, () => `${a.id} opened`);
  } },
  'action list': { options: {}, run: (c) => {
    const list = listItems(c.ctx, 'actions');
    c.print(list, () => (list.length ? table(list.map((a) => [a.id, a.status, a.title])) : 'no actions'));
  } },
  'action done': { options: { note: str }, run: (c) => {
    const a = completeAction(c.ctx, c.pos[0], { note: c.values.note ?? '', by: 'cli' });
    c.print(a, () => `${a.id} done`);
  } },

  'feedback new': { options: { target: str, text: str, sentiment: str }, run: (c) => {
    need(c.values, 'target', 'text');
    const f = createFeedback(c.ctx, { target: c.values.target, text: c.values.text, sentiment: c.values.sentiment ?? null, by: 'cli' });
    c.print(f, () => `${f.id} recorded`);
  } },
  'feedback list': { options: {}, run: (c) => {
    const list = listItems(c.ctx, 'feedback');
    c.print(list, () => (list.length ? table(list.map((f) => [f.id, f.status, f.target, f.text.slice(0, 80)])) : 'no feedback'));
  } },
  'feedback triage': { options: { note: str, tickets: str, done: bool, by: str }, run: (c) => {
    need(c.values, 'note');
    const f = triageFeedback(c.ctx, c.pos[0], { note: c.values.note, tickets: csv(c.values.tickets), done: c.values.done, by: c.values.by ?? c.env.FACTORY_ROLE ?? 'factory-director' });
    c.print(f, () => `${f.id} ${f.status}`);
  } },

  'epic new': { options: { title: str, goal: str, milestone: str, parity: str, by: str }, run: (c) => {
    need(c.values, 'title');
    const e = createEpic(c.ctx, { title: c.values.title, goal: c.values.goal ?? '', milestone: c.values.milestone ?? null, parity_refs: csv(c.values.parity), by: c.values.by ?? c.env.FACTORY_ROLE ?? 'project-manager' });
    c.print(e, () => `${e.id} created`);
  } },
  'epic list': { options: {}, run: (c) => {
    const list = listItems(c.ctx, 'epics');
    c.print(list, () => (list.length ? table(list.map((e) => [e.id, e.status, e.milestone ?? '-', e.title])) : 'no epics'));
  } },
  'epic show': { options: {}, run: (c) => c.print(requireEntity(c.ctx, 'epics', c.pos[0], 'epic'), (e) => JSON.stringify(e, null, 2)) },
  'epic set': { options: { by: str }, run: (c) => {
    const e = setEpic(c.ctx, c.pos[0], assignments(c.pos.slice(1)), c.values.by ?? c.env.FACTORY_ROLE ?? 'cli');
    c.print(e, () => `updated ${e.id}`);
  } },

  'milestone new': { options: { name: str, goal: str, target: str, by: str }, run: (c) => {
    need(c.values, 'name');
    const m = createMilestone(c.ctx, { name: c.values.name, goal: c.values.goal ?? '', target: c.values.target ?? null, by: c.values.by ?? c.env.FACTORY_ROLE ?? 'project-manager' });
    c.print(m, () => `${m.id} created`);
  } },
  'milestone list': { options: {}, run: (c) => {
    const list = listItems(c.ctx, 'milestones');
    c.print(list, () => (list.length ? table(list.map((m) => [m.id, m.status, m.name])) : 'no milestones'));
  } },
  'milestone show': { options: {}, run: (c) => c.print(requireEntity(c.ctx, 'milestones', c.pos[0], 'milestone'), (m) => JSON.stringify(m, null, 2)) },
  'milestone set': { options: { by: str }, run: (c) => {
    const m = setMilestone(c.ctx, c.pos[0], assignments(c.pos.slice(1)), c.values.by ?? c.env.FACTORY_ROLE ?? 'factory-director');
    c.print(m, () => `updated ${m.id}`);
  } },

  'handoff new': { options: { by: str }, run: (c) => {
    const file = createHandoff(c.ctx, c.pos[0], who(c.values, c.env));
    c.print({ path: file }, () => file);
  } },
  'handoff latest': { options: {}, run: (c) => {
    const file = latestHandoff(c.ctx, c.pos[0]);
    if (!file) throw new FactoryError(`no handoff for ${c.pos[0]}`);
    c.print({ path: file }, () => file);
  } },

  event: { options: { actor: str, kind: str, ticket: str }, run: (c) => {
    need(c.values, 'actor', 'kind');
    if (!EVENT_KINDS.includes(c.values.kind)) throw new UsageError(`--kind must be one of ${EVENT_KINDS.join(' ')}`);
    if (!c.pos.length) throw new UsageError('event text is required');
    const e = appendEvent(c.ctx, { actor: c.values.actor, kind: c.values.kind, ticket: c.values.ticket ?? null, text: c.pos.join(' ') });
    c.print(e, () => 'event recorded');
  } },
  digest: { options: {}, run: (c) => {
    const digest = buildDigest(c.ctx);
    c.print(digest, () => formatDigest(digest));
  } },
};

function transitionCommand(c, fn, past) {
  need(c.values, 'note');
  const t = fn(c.ctx, c.pos[0], who(c.values, c.env), c.values.note);
  c.print(t, () => `${t.id} ${past}: now ${t.status}${t.stage_role ? ` (${t.stage_role})` : ''}`);
}

const SUBCOMMAND_GROUPS = new Set(['ticket', 'decision', 'action', 'feedback', 'epic', 'milestone', 'handoff']);
/** Commands whose first positional argument is an entity id. */
const NEEDS_ID = /^(ticket (show|ready|note|advance|reject|block|unblock|cancel|set)|decision (show|answer|applied|withdraw|ack|veto)|action done|feedback triage|epic (show|set)|milestone (show|set)|handoff (new|latest))$/;

function lookup(argv) {
  if (!argv.length || argv[0] === 'help' || argv[0] === '--help' || argv[0] === '-h') return { help: true };
  const name = SUBCOMMAND_GROUPS.has(argv[0]) ? `${argv[0]} ${argv[1] ?? ''}`.trim() : argv[0];
  const command = COMMANDS[name];
  if (!command) throw new UsageError(SUBCOMMAND_GROUPS.has(argv[0]) ? `unknown ${argv[0]} subcommand "${argv[1] ?? ''}"` : `unknown command "${argv[0]}"`);
  return { name, command, rest: argv.slice(SUBCOMMAND_GROUPS.has(argv[0]) ? 2 : 1) };
}

/**
 * Run the CLI.
 * @param {string[]} argv arguments after the program name
 * @param {{out?: (s: string) => void, err?: (s: string) => void, env?: NodeJS.ProcessEnv, cwd?: string}} [io]
 * @returns {Promise<number>} exit code (0 ok, 1 failure, 2 usage)
 */
export async function runCli(argv, io = {}) {
  const out = io.out ?? ((s) => process.stdout.write(`${s}\n`));
  const err = io.err ?? ((s) => process.stderr.write(`${s}\n`));
  const env = io.env ?? process.env;
  try {
    const found = lookup(argv);
    if (found.help) {
      out(USAGE);
      return 0;
    }
    let parsed;
    try {
      parsed = parseArgs({ args: found.rest, options: { ...found.command.options, json: bool }, allowPositionals: true, strict: true });
    } catch (e) {
      throw new UsageError(e.message);
    }
    const { values, positionals } = parsed;
    if (NEEDS_ID.test(found.name) && !positionals.length) throw new UsageError(`${found.name}: an ID is required`);

    const home = resolveHome({ env, cwd: io.cwd ?? process.cwd(), fallbackHome: FALLBACK_HOME });
    const context = {
      home, values, pos: positionals, out, env,
      print: (data, text) => {
        out(values.json ? JSON.stringify(data, null, 2) : text(data));
      },
    };
    if (!found.command.standalone) {
      context.ctx = openStore(home);
      ensureStateDirs(context.ctx);
    }
    const code = await found.command.run(context);
    return Number.isInteger(code) ? code : 0;
  } catch (e) {
    if (e instanceof UsageError) {
      err(`usage error: ${e.message}\n(run "factory help" for the command list)`);
      return 2;
    }
    err(`error: ${e instanceof FactoryError ? e.message : (process.env.FACTORY_DEBUG ? e.stack : e.message)}`);
    return 1;
  }
}

/**
 * Entry point used by bin/factory.
 * @param {string[]} argv
 */
export async function main(argv) {
  process.exitCode = await runCli(argv);
}

// The dispatcher: a deterministic loop that reaps finished workers, applies advisory defaults,
// merges finished code tickets and launches new workers into free slots. It never calls a model and
// never crashes on one bad file or one failed worker: every step is guarded and reported once.
import fs from 'node:fs';
import {
  appendEvent, drainBadFiles, getEntity, listEntities, listRecentRuns, localDate, newRunId, nowIso,
  pidAlive, putEntity, readControl, readDispatcherState, readRange, readRateLimitSignal, readTail, reloadConfig,
  updateDispatcherState, updateEntity,
} from './store.mjs';
import { FactoryError } from './errors.mjs';
import { loadAgents } from './agents.mjs';
import { checkLaunchPolicy } from './policy.mjs';
import { isCodeType } from './flows.mjs';
import { LogScanner, detectRateLimit, resultKeyword } from './runlog.mjs';
import { claimTicket, createTicket, blockTicket, reopenTicket, setTicketLinks } from './tickets.mjs';
import { applyAdvisoryDefaults } from './decisions.mjs';
import { applyNoProgress } from './escalation.mjs';
import { buildPrompt } from './prompt.mjs';
import { buildWorkerArgs, launchWorker, runFiles, signalPid } from './launcher.mjs';
import {
  branchName, cleanupWorktree, ensureWorktree, mergeTicket, repoState, usesSharedCheckout,
} from './worktree.mjs';
import { candidateKey, launchGate, selectCandidates } from './candidates.mjs';
import { setting } from './settings.mjs';

export { selectCandidates, launchGate } from './candidates.mjs';

/**
 * Free bytes available to an unprivileged user on the volume holding `dir`, or null if unknown.
 * Workers fill the disk (build caches, swap); the launch gate stops new runs below
 * `dispatcher.min_free_disk_gb` instead of letting the dispatcher die on ENOSPC.
 * @param {string} dir
 * @returns {number|null}
 */
export function diskFreeBytes(dir) {
  try {
    const st = fs.statfsSync(dir);
    return st.bavail * st.bsize;
  } catch {
    return null;
  }
}

const READ_CHUNK = 4 * 1024 * 1024;
const NO_PID_GRACE_MS = 30_000;

/**
 * Snapshot of everything `selectCandidates` needs.
 * @param {object} ctx
 */
export function loadState(ctx) {
  return {
    tickets: listEntities(ctx, 'tickets'),
    decisions: listEntities(ctx, 'decisions'),
    feedback: listEntities(ctx, 'feedback'),
    runs: listRecentRuns(ctx, 200),
    control: readControl(ctx),
    dispatcher: readDispatcherState(ctx),
  };
}

function madeProgress(snapshot, ticket) {
  return ticket.status !== snapshot.status
    || (ticket.stage_role ?? null) !== (snapshot.stage_role ?? null)
    || (ticket.handoff?.latest ?? null) !== (snapshot.handoff_latest ?? null);
}

const kTokens = (n) => `${Math.round((n ?? 0) / 1000)}k`;

/** The dispatcher. Create one per process; call {@link Dispatcher#run}. */
export class Dispatcher {
  /**
   * @param {object} ctx
   * @param {{spawnWorker?: typeof launchWorker}} [opts] spawnWorker is injectable for tests
   */
  constructor(ctx, { spawnWorker = launchWorker } = {}) {
    this.ctx = ctx;
    this.spawnWorker = spawnWorker;
    this.active = new Map(); // runId → run record (running)
    this.children = new Map(); // runId → { child, exit } for workers this process started
    this.tails = new Map(); // runId → { scanner, offset, dirty, persistedAt }
    this.killing = new Map(); // runId → { reason, at, killed }
    this.reported = new Map(); // dedupe key → last text
    this.shared = true;
    this.adopted = false;
    this.daemon = false;
    this.ticking = false;
    this.stopping = false;
    this.forceStop = false;
    this.requestTick = false;
    this.lastTick = 0;
    this.lastHeartbeat = 0;
    this.wake = null;
  }

  // ---- bookkeeping ------------------------------------------------------------------------

  #nowMs() {
    return this.ctx.now().getTime();
  }

  /** Log an event once per distinct text per key; a success on the key re-arms it. */
  report(key, text) {
    if (this.reported.get(key) === text) return;
    this.reported.set(key, text);
    appendEvent(this.ctx, { actor: 'dispatcher', kind: 'dispatcher', text });
  }

  async guard(key, fn) {
    try {
      const value = await fn();
      this.reported.delete(key);
      return value;
    } catch (err) {
      this.report(key, `${key} failed: ${err.message}`);
      return undefined;
    }
  }

  heartbeat() {
    this.lastHeartbeat = this.#nowMs();
    updateDispatcherState(this.ctx, { pid: process.pid, heartbeat: nowIso(this.ctx), active: [...this.active.keys()] });
  }

  #lastAction(text) {
    updateDispatcherState(this.ctx, { last_action: `${nowIso(this.ctx)} ${text}` });
  }

  // ---- the tick ---------------------------------------------------------------------------

  /** One full pass: heartbeat, reap, defaults, merge, launch. Never throws. */
  async tick() {
    if (this.ticking) return;
    this.ticking = true;
    try {
      this.lastTick = this.#nowMs();
      this.requestTick = false;
      try {
        reloadConfig(this.ctx);
        this.reported.delete('config');
      } catch (err) {
        this.report('config', `config.json unreadable, keeping the previous one: ${err.message}`);
      }
      if (!this.adopted) this.adopt();
      if (this.daemon) this.heartbeat();
      await this.guard('poll', () => this.poll());
      await this.guard('rate-limit signal', async () => this.applyRateLimitSignal());
      for (const [file, message] of drainBadFiles(this.ctx)) {
        appendEvent(this.ctx, { actor: 'dispatcher', kind: 'dispatcher', text: `ignoring unreadable state file ${file}: ${message}` });
      }
      await this.guard('advisory defaults', async () => applyAdvisoryDefaults(this.ctx));
      await this.guard('repository check', async () => {
        this.shared = usesSharedCheckout(this.ctx, await repoState(this.ctx));
      });
      if (!this.stopping) await this.guard('merge', () => this.mergePass());
      if (!this.stopping) await this.guard('launch', () => this.fill());
      if (this.daemon) this.heartbeat();
    } finally {
      this.ticking = false;
    }
  }

  /** Take over runs a previous dispatcher left running. */
  adopt() {
    this.adopted = true;
    for (const run of listRecentRuns(this.ctx, 200)) {
      if (run.status === 'running' && !this.active.has(run.id)) this.active.set(run.id, run);
    }
  }

  /**
   * Back off when the StopFailure hook reports a usage limit (the limit is account-wide, so a hit
   * in any session counts). A signal older than the backoff window is ignored.
   */
  applyRateLimitSignal() {
    const { ctx } = this;
    const signal = readRateLimitSignal(ctx);
    if (!signal) return;
    const until = Date.parse(signal.ts) + ctx.config.dispatcher.rate_limit_backoff_minutes * 60_000;
    if (until <= this.#nowMs()) return;
    const current = readDispatcherState(ctx).backoff_until;
    if (current && Date.parse(current) >= until) return;
    const iso = new Date(until).toISOString();
    updateDispatcherState(ctx, { backoff_until: iso });
    appendEvent(ctx, { actor: 'dispatcher', kind: 'dispatcher', text: `usage limit reported by ${signal.role ?? 'a session'} (${signal.type}); backing off until ${iso}` });
  }

  // ---- watching workers -------------------------------------------------------------------

  /** Tail logs, enforce time limits, reap finished runs. */
  async poll() {
    let reaped = 0;
    for (const run of [...this.active.values()]) {
      try {
        const tail = this.readLog(run.id);
        const exit = this.exitOf(run);
        if (exit) {
          await this.reap(run, exit);
          reaped += 1;
        } else {
          this.persistLive(run, tail);
          this.enforceLimits(run);
        }
      } catch (err) {
        this.report(`run ${run.id}`, `run ${run.id}: ${err.message}`);
      }
    }
    if (reaped) this.requestTick = true;
  }

  /** Read new log bytes into the run's scanner. */
  readLog(runId) {
    let tail = this.tails.get(runId);
    if (!tail) {
      tail = { scanner: new LogScanner(), offset: 0, dirty: false, persistedAt: 0 };
      this.tails.set(runId, tail);
    }
    const file = runFiles(this.ctx, runId).log;
    let size;
    try {
      size = fs.statSync(file).size;
    } catch {
      return tail;
    }
    while (tail.offset < size) {
      const buf = readRange(file, tail.offset, Math.min(size, tail.offset + READ_CHUNK));
      if (!buf.length) break;
      tail.offset += buf.length;
      if (tail.scanner.push(buf)) tail.dirty = true;
    }
    return tail;
  }

  /** Persist context usage and activity to the run record, at most every `persist_seconds`. */
  persistLive(run, tail) {
    if (!tail.dirty || this.#nowMs() - tail.persistedAt < setting(this.ctx.config, 'persist_seconds') * 1000) return;
    const s = tail.scanner.state;
    const updated = updateEntity(this.ctx, 'runs', run.id, (r) => {
      r.context_tokens = s.context_tokens;
      r.peak_context_tokens = Math.max(r.peak_context_tokens ?? 0, s.peak_context_tokens);
      r.last_activity = s.last_activity ?? r.last_activity;
      r.session_id = s.session_id ?? r.session_id;
    });
    this.active.set(run.id, updated);
    tail.dirty = false;
    tail.persistedAt = this.#nowMs();
  }

  /** null while the worker runs; otherwise how it ended. */
  exitOf(run) {
    const child = this.children.get(run.id);
    if (child) return child.exit;
    if (run.pid) return pidAlive(run.pid) ? null : { code: null, signal: null };
    return this.#nowMs() - Date.parse(run.started) > NO_PID_GRACE_MS ? { code: null, signal: null, error: 'no pid was recorded' } : null;
  }

  enforceLimits(run) {
    const kill = this.killing.get(run.id);
    if (!kill) {
      if (this.#nowMs() - Date.parse(run.started) > this.ctx.config.dispatcher.run_timeout_minutes * 60_000) this.terminate(run, 'timeout');
    } else if (!kill.killed && this.#nowMs() - kill.at > setting(this.ctx.config, 'kill_grace_seconds') * 1000) {
      kill.killed = true;
      if (run.pid) signalPid(run.pid, 'SIGKILL');
      appendEvent(this.ctx, { actor: 'dispatcher', kind: 'run', ticket: run.ticket, run: run.id, text: `${run.id} ignored SIGTERM; sent SIGKILL` });
    }
  }

  /** SIGTERM a worker; SIGKILL follows after `kill_grace_seconds` if it is still there. */
  terminate(run, reason) {
    if (this.killing.has(run.id)) return;
    this.killing.set(run.id, { reason, at: this.#nowMs(), killed: false });
    if (run.pid) signalPid(run.pid, 'SIGTERM');
    appendEvent(this.ctx, { actor: 'dispatcher', kind: 'run', ticket: run.ticket, run: run.id, text: `${run.id} (${run.ticket}, ${run.role}) ${reason}: sent SIGTERM` });
  }

  /** Finalise a finished run and apply its consequences to the ticket. */
  async reap(run, exit) {
    const { ctx } = this;
    const tail = this.readLog(run.id);
    tail.scanner.flush();
    const s = tail.scanner.state;
    const result = s.result;
    const stderr = readTail(runFiles(ctx, run.id).err, 8192);
    const kill = this.killing.get(run.id);
    const keyword = resultKeyword(result?.result_line);
    const signal = readRateLimitSignal(ctx);
    const sessionId = result?.session_id ?? s.session_id ?? run.session_id;
    const rateLimited = !kill && (detectRateLimit({ result, stderr }) || Boolean(signal?.session && signal.session === sessionId));

    let status = 'failed';
    if (kill) status = 'killed';
    else if (result && !result.is_error && keyword !== 'failed') status = keyword === 'handoff' ? 'handoff' : 'done';

    updateEntity(ctx, 'runs', run.id, (r) => {
      Object.assign(r, {
        status, ended: nowIso(ctx), exit_code: exit.code,
        context_tokens: s.context_tokens, peak_context_tokens: Math.max(r.peak_context_tokens ?? 0, s.peak_context_tokens),
        last_activity: s.last_activity ?? r.last_activity, session_id: result?.session_id ?? s.session_id ?? r.session_id,
        cost_usd: result?.total_cost_usd ?? r.cost_usd, num_turns: result?.num_turns ?? r.num_turns,
        result_line: result?.result_line ?? null, kill_reason: kill?.reason ?? null,
        error: exit.error ?? (status === 'failed' ? (stderr.trim().split('\n').at(-1) || result?.result?.slice(0, 200) || 'worker ended without a result') : null),
      });
    });
    this.active.delete(run.id);
    this.children.delete(run.id);
    this.tails.delete(run.id);
    this.killing.delete(run.id);

    const ticket = getEntity(ctx, 'tickets', run.ticket);
    let consequence = '';
    if (rateLimited) {
      const until = new Date(this.#nowMs() + ctx.config.dispatcher.rate_limit_backoff_minutes * 60_000).toISOString();
      updateDispatcherState(ctx, { backoff_until: until });
      consequence = `; usage limit hit, backing off until ${until}`;
    } else if (ticket && kill?.reason !== 'shutdown' && run.snapshot && !madeProgress(run.snapshot, ticket)) {
      const agent = loadAgents(ctx).get(ticket.stage_role ?? run.role) ?? null;
      consequence = `; no progress → ${applyNoProgress(ctx, ticket.id, agent, run.id).action}`;
    }
    appendEvent(ctx, {
      actor: 'dispatcher', kind: 'run', ticket: run.ticket, run: run.id,
      text: `${run.id} ${status}: ${run.ticket} as ${run.role} · ${s.result?.num_turns ?? 0} turns · $${(result?.total_cost_usd ?? 0).toFixed(2)} · ctx ${kTokens(s.peak_context_tokens)}${result?.result_line ? ` — ${result.result_line}` : ''}${consequence}`,
    });
  }

  // ---- merging ----------------------------------------------------------------------------

  /** Merge every finished code ticket that still has a worktree. */
  async mergePass() {
    if (this.shared) return;
    const finished = listEntities(this.ctx, 'tickets')
      .filter((t) => t.status === 'done' && t.links?.worktree && isCodeType(this.ctx.config, t.type));
    for (const ticket of finished) {
      if (this.stopping) return;
      await this.guard(`merge ${ticket.id}`, () => this.mergeOne(ticket));
    }
  }

  async mergeOne(ticket) {
    const { ctx } = this;
    const merged = await mergeTicket(ctx, ticket);
    if (merged.status === 'merged') {
      const problems = await cleanupWorktree(ctx, ticket.id);
      setTicketLinks(ctx, ticket.id, { worktree: null, merged: nowIso(ctx), merge_commit: merged.commit });
      appendEvent(ctx, { actor: 'dispatcher', kind: 'ticket', ticket: ticket.id, text: `${ticket.id} merged into ${ctx.config.dispatcher.main_branch} (${merged.commit.slice(0, 8)})${problems.length ? `; cleanup: ${problems.join('; ')}` : ''}` });
    } else if (merged.status === 'conflict') {
      reopenTicket(ctx, ticket.id, 'dispatcher', `merging ${branchName(ticket.id)} into ${ctx.config.dispatcher.main_branch} conflicted (${merged.detail}). Merge ${ctx.config.dispatcher.main_branch} into the branch, resolve the conflicts, re-run the tests and advance again.`);
    } else {
      throw new FactoryError(`merging ${ticket.id} failed: ${merged.detail}`);
    }
  }

  // ---- launching --------------------------------------------------------------------------

  /** Fill free slots until the candidates run out or nothing more can be launched. */
  async fill() {
    const { ctx } = this;
    const skip = new Set();
    for (let round = 0; round < 10 && !this.stopping; round++) {
      const state = { ...loadState(ctx), sharedCheckout: this.shared, skip, disk_free_bytes: diskFreeBytes(ctx.root) };
      const now = ctx.now();
      const gate = launchGate(state, now, ctx.config);
      if (gate) return this.#lastAction(`idle: ${gate}`);
      const picks = selectCandidates(state, now, ctx.config);
      if (!picks.length) return this.#lastAction('idle: nothing to launch');
      let refused = false;
      for (const candidate of picks) {
        const key = candidateKey(candidate);
        try {
          if ((await this.launchCandidate(candidate)) !== 'launched') {
            skip.add(key);
            refused = true;
          }
          this.reported.delete(`launch ${key}`);
        } catch (err) {
          skip.add(key);
          refused = true;
          this.report(`launch ${key}`, `could not launch ${key}: ${err.message}`);
        }
      }
      if (!refused) return undefined;
    }
    return undefined;
  }

  /** Create the ticket for an auto-generated meta candidate. */
  materialize(spec) {
    const { ctx } = this;
    const ticket = createTicket(ctx, {
      title: spec.title, type: 'meta', owner: spec.owner, priority: spec.priority, summary: spec.summary,
      body: spec.body, acceptance: spec.acceptance, tags: spec.tags, status: 'ready', meta: spec.meta,
    }, 'dispatcher');
    for (const id of spec.meta.blocked ?? []) {
      updateEntity(ctx, 'tickets', id, (t) => { t.triaged_at = nowIso(ctx); });
    }
    return ticket;
  }

  /**
   * Validate, claim, prepare the worktree, record the run and start the worker.
   * @returns {Promise<'launched'|'refused'|'blocked'|'failed'>}
   */
  async launchCandidate(candidate) {
    const { ctx } = this;
    const { config } = ctx;
    const role = candidate.role;
    const label = candidate.ticket?.id ?? candidate.create.title;
    const agent = loadAgents(ctx).get(role);
    const override = candidate.ticket?.effort_override ?? null;
    const problems = agent ? checkLaunchPolicy(config, agent, override) : [`there is no agent definition for "${role}"`];
    if (problems.length) {
      this.report(`refuse ${role}`, `refused to launch ${role} for ${label}: ${problems.join('; ')}`);
      return 'refused';
    }

    let ticket = candidate.create ? this.materialize(candidate.create) : candidate.ticket;
    if (ticket.status === 'ready') ticket = claimTicket(ctx, ticket.id);

    const isolated = isCodeType(config, ticket.type) && !this.shared;
    let cwd = ctx.root;
    if (isolated) {
      try {
        const worktree = await ensureWorktree(ctx, ticket.id);
        cwd = worktree.path;
        ticket = setTicketLinks(ctx, ticket.id, { branch: worktree.branch, worktree: worktree.path });
      } catch (err) {
        blockTicket(ctx, ticket.id, 'dispatcher', `worktree setup failed: ${err.message}`);
        return 'blocked';
      }
    }

    const continuation = Boolean(ticket.handoff?.pending);
    const prompt = buildPrompt(ctx, { ticket, role, stage: ticket.status, continuation, isolated });
    const runId = newRunId(ctx);
    const run = {
      id: runId, ticket: ticket.id, stage: ticket.status, role, model: agent.model, effort: override ?? agent.effort,
      pid: null, session_id: null, worktree: isolated ? cwd : null, status: 'running', started: nowIso(ctx), ended: null,
      exit_code: null, context_tokens: 0, peak_context_tokens: 0, cost_usd: 0, num_turns: 0, result_line: null,
      last_activity: null, log: `state/runs/${runId}.log`, continuation,
      snapshot: { status: ticket.status, stage_role: ticket.stage_role ?? null, handoff_latest: ticket.handoff?.latest ?? null },
    };
    putEntity(ctx, 'runs', run);

    let started;
    try {
      started = this.spawnWorker(ctx, { runId, ticketId: ticket.id, role, prompt, cwd, effortOverride: override, agentEffort: agent.effort }, (exit) => {
        const entry = this.children.get(runId);
        if (entry) entry.exit = exit;
      });
    } catch (err) {
      updateEntity(ctx, 'runs', runId, (r) => Object.assign(r, { status: 'failed', ended: nowIso(ctx), error: err.message }));
      const minutes = setting(config, 'launch_failure_backoff_minutes');
      updateDispatcherState(ctx, { backoff_until: new Date(this.#nowMs() + minutes * 60_000).toISOString() });
      this.report('spawn', `${err.message}; backing off ${minutes} min`);
      return 'failed';
    }
    this.reported.delete('spawn');
    this.children.set(runId, { child: started.child, exit: null });
    const live = updateEntity(ctx, 'runs', runId, (r) => { r.pid = started.pid; });
    this.active.set(runId, live);

    const today = localDate(ctx.now());
    updateDispatcherState(ctx, (s) => ({
      runs_today: { date: today, count: (s.runs_today?.date === today ? s.runs_today.count : 0) + 1 },
      active: [...this.active.keys()],
      last_action: `${nowIso(ctx)} launched ${runId} (${ticket.id} · ${role})`,
    }));
    appendEvent(ctx, { actor: 'dispatcher', kind: 'run', ticket: ticket.id, run: runId, text: `launched ${runId}: ${ticket.id} "${ticket.title}" as ${role} (${run.model} · ${run.effort})${continuation ? ' [continuation]' : ''}` });
    return 'launched';
  }

  // ---- lifecycle --------------------------------------------------------------------------

  /** Ask the loop to stop; a second call skips the grace period. */
  stop() {
    if (this.stopping) this.forceStop = true;
    this.stopping = true;
    this.wake?.();
  }

  sleep(ms) {
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        this.wake = null;
        resolve();
      };
      const timer = setTimeout(done, ms);
      this.wake = done;
    });
  }

  /**
   * Run the dispatcher.
   * @param {{once?: boolean}} [opts] once: a single tick, then return (workers keep running and are adopted later)
   */
  async run({ once = false } = {}) {
    const { ctx } = this;
    if (once) return this.tick();

    const existing = readDispatcherState(ctx);
    if (pidAlive(existing.pid) && existing.pid !== process.pid) throw new FactoryError(`a dispatcher is already running (pid ${existing.pid})`);
    this.daemon = true;
    updateDispatcherState(ctx, { pid: process.pid, started: nowIso(ctx), heartbeat: nowIso(ctx), stopped: null });
    appendEvent(ctx, { actor: 'dispatcher', kind: 'dispatcher', text: `dispatcher started (pid ${process.pid})` });
    const onSignal = () => this.stop();
    process.on('SIGTERM', onSignal);
    process.on('SIGINT', onSignal);
    try {
      while (!this.stopping) {
        if (this.requestTick || this.#nowMs() - this.lastTick >= ctx.config.dispatcher.tick_seconds * 1000) {
          await this.tick();
        } else {
          await this.guard('poll', () => this.poll());
          if (this.#nowMs() - this.lastHeartbeat >= 10_000) this.heartbeat();
        }
        if (!this.stopping) await this.sleep(setting(ctx.config, 'poll_seconds') * 1000);
      }
      await this.shutdown();
    } finally {
      process.off('SIGTERM', onSignal);
      process.off('SIGINT', onSignal);
      updateDispatcherState(ctx, { pid: null, stopped: nowIso(ctx), active: [...this.active.keys()] });
      appendEvent(ctx, { actor: 'dispatcher', kind: 'dispatcher', text: 'dispatcher stopped' });
    }
    return undefined;
  }

  /** Let running workers finish, then terminate the rest; their tickets stay where they are. */
  async shutdown() {
    const { config } = this.ctx;
    const grace = setting(config, 'shutdown_grace_seconds') * 1000;
    const killGrace = setting(config, 'kill_grace_seconds') * 1000;
    appendEvent(this.ctx, { actor: 'dispatcher', kind: 'dispatcher', text: `stopping: giving ${this.active.size} running worker(s) up to ${setting(config, 'shutdown_grace_seconds')} s to finish` });

    const graceEnds = this.#nowMs() + grace;
    while (this.active.size && this.#nowMs() < graceEnds && !this.forceStop) {
      await this.guard('poll', () => this.poll());
      if (this.active.size) await this.sleep(Math.min(1000, Math.max(10, graceEnds - this.#nowMs())));
    }
    for (const run of [...this.active.values()]) this.terminate(run, 'shutdown');
    const killEnds = this.#nowMs() + killGrace + 2000;
    while (this.active.size && this.#nowMs() < killEnds) {
      await this.guard('poll', () => this.poll());
      if (this.active.size) await this.sleep(Math.min(500, Math.max(10, killEnds - this.#nowMs())));
    }
    for (const run of [...this.active.values()]) await this.reap(run, { code: null, signal: 'SIGKILL' });
  }
}

/**
 * What `factory run --dry-run` reports: the launch gate, advisory defaults that are due, and for
 * each candidate the role, model, effort, policy verdict and the command that would run. Reads
 * state, changes nothing.
 * @param {object} ctx
 */
export async function planDryRun(ctx) {
  const repo = await repoState(ctx);
  const shared = usesSharedCheckout(ctx, repo);
  const state = { ...loadState(ctx), sharedCheckout: shared, disk_free_bytes: diskFreeBytes(ctx.root) };
  const now = ctx.now();
  const gate = launchGate(state, now, ctx.config);
  const agents = loadAgents(ctx);
  const picks = gate ? [] : selectCandidates(state, now, ctx.config);
  const defaults = state.decisions
    .filter((d) => d.kind === 'advisory' && d.status === 'pending' && d.default_at && Date.parse(d.default_at) <= now.getTime())
    .map((d) => d.id);

  return {
    gate, shared, repo, defaults,
    active: state.runs.filter((r) => r.status === 'running').map((r) => ({ run: r.id, ticket: r.ticket, role: r.role })),
    candidates: picks.map((c) => {
      const agent = agents.get(c.role) ?? null;
      const ticket = c.ticket ?? { id: '(new)', title: c.create.title, type: 'meta', priority: c.create.priority, meta: c.create.meta, handoff: {} };
      const override = ticket.effort_override ?? null;
      const problems = agent ? checkLaunchPolicy(ctx.config, agent, override) : [`there is no agent definition for "${c.role}"`];
      const isolated = isCodeType(ctx.config, ticket.type) && !shared;
      const prompt = buildPrompt(ctx, { ticket, role: c.role, stage: c.stage, continuation: c.continuation, isolated });
      return {
        kind: c.kind, ticket: c.ticket?.id ?? null, title: ticket.title, role: c.role, stage: c.stage,
        model: agent?.model ?? null, effort: override ?? agent?.effort ?? null, continuation: c.continuation,
        creates_meta: c.create ? c.create.kind : null, isolated, refused: problems,
        command: ['claude', ...buildWorkerArgs({ config: ctx.config, role: c.role, prompt: `<prompt: ${prompt.length} chars>`, ticketId: ticket.id, effortOverride: override, agentEffort: agent?.effort ?? null, root: ctx.root })],
      };
    }),
  };
}

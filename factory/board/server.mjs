// The Factory Board: static UI from board/public/ plus the JSON API from README "Board".
// Node http only. Reads state on every request; writes go through the same lib/ functions as the CLI.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import {
  appendEvent, listEntities, listRecentRuns, pidAlive, readControl, readJson, readRecentEvents, readTail,
  requireEntity, setControl, writeJsonAtomic,
} from '../lib/store.mjs';
import { FactoryError, NotFoundError } from '../lib/errors.mjs';
import { acknowledgeNotice, answerDecision, vetoNotice } from '../lib/decisions.mjs';
import { completeAction, createFeedback, sortById } from '../lib/items.mjs';
import { summarizeTicket } from '../lib/tickets.mjs';
import { dispatcherInfo, latestDigest } from '../lib/status.mjs';
import { listHandoffs } from '../lib/handoffs.mjs';
import { FILE_TYPES, createLibraryLister, resolveLibraryPath } from '../lib/library.mjs';
import { readableLines } from '../lib/runlog.mjs';

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');
const MAX_BODY_BYTES = 1024 * 1024;
const SESSION_WINDOW_MS = 15 * 60_000;
const WILDCARD_HOSTS = ['0.0.0.0', '::'];

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
}

function sendText(res, status, text, type) {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(text);
}

/** Only the board's own host names may be used, which defeats DNS-rebinding reads from other sites. */
function hostAllowed(header, boundHost) {
  if (!header || WILDCARD_HOSTS.includes(boundHost)) return true;
  const host = header.startsWith('[') ? header.slice(1, header.indexOf(']')) : header.split(':')[0];
  return [boundHost, '127.0.0.1', 'localhost', '::1'].includes(host);
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new FactoryError('request body too large', 413);
    chunks.push(chunk);
  }
  if (!size) return {};
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('not an object');
    return body;
  } catch {
    throw new FactoryError('request body must be a JSON object');
  }
}

function liveSessions(ctx, now) {
  const dir = ctx.dir('sessions');
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith('.json'));
  } catch {
    return [];
  }
  const out = [];
  for (const name of names.sort()) {
    const file = path.join(dir, name);
    try {
      if (now.getTime() - fs.statSync(file).mtimeMs > SESSION_WINDOW_MS) continue;
      out.push(JSON.parse(fs.readFileSync(file, 'utf8')));
    } catch {
      // a half-written or deleted session file is not worth a failed request
    }
  }
  return out;
}

function buildState(ctx, listLibrary) {
  const now = ctx.now();
  const runs = listRecentRuns(ctx, 100);
  return {
    generated: now.toISOString(),
    product: ctx.config.product,
    company: ctx.config.company,
    control: readControl(ctx),
    dispatcher: dispatcherInfo(ctx),
    milestones: sortById(listEntities(ctx, 'milestones')),
    epics: sortById(listEntities(ctx, 'epics')),
    tickets: sortById(listEntities(ctx, 'tickets')).map(summarizeTicket),
    decisions: sortById(listEntities(ctx, 'decisions')),
    actions: sortById(listEntities(ctx, 'actions')),
    feedback: sortById(listEntities(ctx, 'feedback')),
    runs: {
      active: runs.filter((r) => r.status === 'running'),
      recent: runs.filter((r) => r.status !== 'running').slice(0, 20),
    },
    sessions: liveSessions(ctx, now),
    events: readRecentEvents(ctx, 150),
    library: listLibrary(),
    digest: latestDigest(ctx),
  };
}

function ticketDetail(ctx, id) {
  const ticket = requireEntity(ctx, 'tickets', id, 'ticket');
  return {
    ...ticket,
    runs: listRecentRuns(ctx, 500).filter((r) => r.ticket === id),
    handoffs: listHandoffs(ctx, id).map((file) => ({ name: path.basename(file), path: file })),
  };
}

function runTail(ctx, id, linesParam) {
  const run = requireEntity(ctx, 'runs', id, 'run');
  const lines = Math.min(500, Math.max(1, Number.parseInt(linesParam ?? '80', 10) || 80));
  return { id, status: run.status, lines: readableLines(readTail(path.join(ctx.dir('runs'), `${id}.log`), 512 * 1024), lines) };
}

function decode(text) {
  try {
    return decodeURIComponent(text);
  } catch {
    throw new FactoryError('malformed URL');
  }
}

function serveStatic(res, urlPath) {
  const rel = urlPath === '/' ? 'index.html' : decode(urlPath).replace(/^\/+/, '');
  const file = path.resolve(PUBLIC_DIR, rel);
  const type = FILE_TYPES[path.extname(file).toLowerCase()];
  if (!type || (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep))) throw new NotFoundError('not found');
  let body;
  try {
    body = fs.readFileSync(file);
  } catch {
    throw new NotFoundError('not found');
  }
  res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
}

function serveLibraryFile(req, res, ctx, relPath, { markdownOnly }) {
  const real = resolveLibraryPath(ctx, relPath);
  const ext = path.extname(real).toLowerCase();
  const type = FILE_TYPES[ext];
  if (!type || (markdownOnly && ext !== '.md' && ext !== '.markdown')) throw new FactoryError(`unsupported file type "${ext}"`, 415);
  const size = fs.statSync(real).size;
  // Preview pages run in an opaque origin: they cannot reach the board API.
  const headers = { 'Content-Type': type, 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': 'sandbox allow-scripts', 'Accept-Ranges': 'bytes' };

  const range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range ?? '');
  if (range && (range[1] || range[2])) {
    const start = range[1] ? Number(range[1]) : Math.max(0, size - Number(range[2]));
    const end = range[1] && range[2] ? Math.min(Number(range[2]), size - 1) : size - 1;
    if (start > end || start >= size) {
      res.writeHead(416, { 'Content-Range': `bytes */${size}` });
      res.end();
      return;
    }
    res.writeHead(206, { ...headers, 'Content-Range': `bytes ${start}-${end}/${size}`, 'Content-Length': end - start + 1 });
    fs.createReadStream(real, { start, end }).on('error', () => res.destroy()).pipe(res);
    return;
  }
  res.writeHead(200, { ...headers, 'Content-Length': size });
  fs.createReadStream(real).on('error', () => res.destroy()).pipe(res);
}

async function handlePost(ctx, pathname, body) {
  let m;
  if ((m = /^\/api\/decisions\/([^/]+)\/answer$/.exec(pathname))) {
    return answerDecision(ctx, m[1], { options: body.options, note: body.note ?? '', via: 'board' });
  }
  if ((m = /^\/api\/decisions\/([^/]+)\/ack$/.exec(pathname))) return acknowledgeNotice(ctx, m[1], { note: body.note ?? '' });
  if ((m = /^\/api\/decisions\/([^/]+)\/veto$/.exec(pathname))) return vetoNotice(ctx, m[1], { note: body.note ?? '' });
  if ((m = /^\/api\/actions\/([^/]+)\/done$/.exec(pathname))) return completeAction(ctx, m[1], { note: body.note ?? '', by: 'ceo' });
  if (pathname === '/api/feedback') {
    return createFeedback(ctx, { target: body.target, text: body.text, sentiment: body.sentiment ?? null, by: 'ceo' });
  }
  if (pathname === '/api/control') {
    if (typeof body.paused !== 'boolean') throw new FactoryError('"paused" must be true or false');
    return setControl(ctx, { paused: body.paused, reason: body.reason ?? null, by: 'ceo' });
  }
  throw new NotFoundError('not found');
}

/**
 * Build the board's HTTP server (not yet listening).
 * @param {object} ctx
 * @returns {http.Server}
 */
export function createBoardServer(ctx) {
  const listLibrary = createLibraryLister(ctx);
  return http.createServer(async (req, res) => {
    try {
      if (!hostAllowed(req.headers.host, ctx.config.board.host)) throw new FactoryError('unexpected Host header', 403);
      const url = new URL(req.url, 'http://board.local');
      const { pathname } = url;

      if (req.method === 'POST') {
        if (req.headers['x-factory-board'] !== '1') throw new FactoryError('missing X-Factory-Board header', 403);
        return sendJson(res, 200, await handlePost(ctx, pathname, await readBody(req)));
      }
      if (req.method !== 'GET') throw new FactoryError('method not allowed', 405);

      let m;
      if (pathname === '/api/state') return sendJson(res, 200, buildState(ctx, listLibrary));
      if ((m = /^\/api\/ticket\/([^/]+)$/.exec(pathname))) return sendJson(res, 200, ticketDetail(ctx, decode(m[1])));
      if ((m = /^\/api\/run\/([^/]+)\/tail$/.exec(pathname))) return sendJson(res, 200, runTail(ctx, decode(m[1]), url.searchParams.get('lines')));
      if (pathname === '/api/doc') return serveLibraryFile(req, res, ctx, url.searchParams.get('path'), { markdownOnly: true });
      if (pathname === '/api/file') return serveLibraryFile(req, res, ctx, url.searchParams.get('path'), { markdownOnly: false });
      if (pathname.startsWith('/api/')) throw new NotFoundError('not found');
      return serveStatic(res, pathname);
    } catch (err) {
      if (res.headersSent) return res.destroy();
      if (err instanceof FactoryError) return sendJson(res, err.status, { error: err.message });
      process.stderr.write(`board: ${req.method} ${req.url}: ${err.stack ?? err}\n`);
      return sendJson(res, 500, { error: 'internal error' });
    }
  });
}

/**
 * Start listening. Port 0 picks a free port (tests).
 * @param {object} ctx
 * @param {{port?: number}} [opts]
 * @returns {Promise<{server: http.Server, port: number}>}
 */
export async function startBoard(ctx, { port = ctx.config.board.port } = {}) {
  const server = createBoardServer(ctx);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, ctx.config.board.host, resolve);
  });
  return { server, port: server.address().port };
}

/**
 * Run the board in the foreground until SIGTERM / SIGINT, recording board.json while it runs.
 * @param {object} ctx
 * @param {{port?: number}} [opts]
 */
export async function runBoard(ctx, { port } = {}) {
  const file = path.join(ctx.stateDir, 'board.json');
  const existing = readJson(file);
  if (existing && pidAlive(existing.pid) && existing.pid !== process.pid) {
    throw new FactoryError(`a board is already running (pid ${existing.pid}, port ${existing.port})`);
  }
  let started;
  try {
    started = await startBoard(ctx, { port });
  } catch (err) {
    throw new FactoryError(err.code === 'EADDRINUSE' ? `port ${port ?? ctx.config.board.port} is in use` : `cannot start the board: ${err.message}`);
  }
  writeJsonAtomic(file, { pid: process.pid, port: started.port, started: ctx.now().toISOString() });
  appendEvent(ctx, { actor: 'board', kind: 'system', text: `board listening on http://${ctx.config.board.host}:${started.port}` });
  process.stdout.write(`board listening on http://${ctx.config.board.host}:${started.port}\n`);

  await new Promise((resolve) => {
    const stop = () => {
      started.server.close(() => resolve());
      started.server.closeAllConnections();
    };
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
  });
  fs.rmSync(file, { force: true });
}

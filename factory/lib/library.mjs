// The Library: markdown under config.library.roots, listed with titles for the board, and the
// path checks that keep /api/doc and /api/file inside those roots.
import fs from 'node:fs';
import path from 'node:path';
import { FactoryError, NotFoundError } from './errors.mjs';
import { parseFrontmatter } from './frontmatter.mjs';

const HEAD_BYTES = 16 * 1024;

/** Content types the board serves from the library roots (anything else is refused). */
export const FILE_TYPES = {
  '.md': 'text/markdown; charset=utf-8', '.markdown': 'text/markdown; charset=utf-8',
  '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.vtt': 'text/vtt; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.pdf': 'application/pdf',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime',
  '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.wav': 'audio/wav',
};

const within = (root, file) => file === root || file.startsWith(root + path.sep);

function lexicalRoots(ctx) {
  return (ctx.config.library?.roots ?? []).map((r) => path.resolve(ctx.root, r));
}

function realRoots(ctx) {
  return lexicalRoots(ctx).flatMap((r) => {
    try {
      return [fs.realpathSync(r)];
    } catch {
      return []; // a root that does not exist yet (docs/) is simply empty
    }
  });
}

/**
 * Resolve a repo-relative path to a real file under the library roots. Rejects absolute paths,
 * `..` traversal and symlinks that leave the roots. Outside paths are refused before the
 * filesystem is consulted, so existence outside the roots is never revealed.
 * @param {object} ctx
 * @param {unknown} rel
 * @returns {string} real path
 */
export function resolveLibraryPath(ctx, rel) {
  if (typeof rel !== 'string' || !rel.trim()) throw new FactoryError('path is required');
  if (rel.includes('\0')) throw new FactoryError('invalid path');
  if (path.isAbsolute(rel)) throw new FactoryError('path must be relative to the repository root');
  const lexical = path.resolve(ctx.root, rel);
  if (!lexicalRoots(ctx).some((r) => within(r, lexical))) throw new FactoryError('path is outside the library roots', 403);
  let real;
  try {
    real = fs.realpathSync(lexical);
  } catch {
    throw new NotFoundError('file not found');
  }
  if (!realRoots(ctx).some((r) => within(r, real))) throw new FactoryError('path is outside the library roots', 403);
  if (!fs.statSync(real).isFile()) throw new NotFoundError('not a file');
  return real;
}

function describe(file, stat) {
  const fd = fs.openSync(file, 'r');
  let head;
  try {
    const buf = Buffer.alloc(Math.min(stat.size, HEAD_BYTES));
    fs.readSync(fd, buf, 0, buf.length, 0);
    head = buf.toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
  const { data, body } = parseFrontmatter(head);
  const heading = /^#\s+(.+)$/m.exec(body);
  return {
    title: data.title || heading?.[1].trim() || path.basename(file, path.extname(file)),
    updated: data.updated || new Date(stat.mtimeMs).toISOString().slice(0, 10),
  };
}

function* markdownFiles(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* markdownFiles(full);
    else if (entry.isFile() && entry.name.endsWith('.md')) yield full;
  }
}

/**
 * A library lister that re-reads only files whose mtime or size changed.
 * @param {object} ctx
 * @returns {() => Array<{path: string, title: string, group: string, updated: string}>}
 */
export function createLibraryLister(ctx) {
  const cache = new Map(); // file → { mtimeMs, size, title, updated }
  return function list() {
    const groups = Object.entries(ctx.config.library?.groups ?? {}).sort((a, b) => b[0].length - a[0].length);
    const groupOrder = Object.values(ctx.config.library?.groups ?? {});
    const seen = new Set();
    const out = [];
    for (const root of lexicalRoots(ctx)) {
      for (const file of markdownFiles(root)) {
        if (seen.has(file)) continue;
        seen.add(file);
        let stat;
        try {
          stat = fs.statSync(file);
        } catch {
          continue;
        }
        let info = cache.get(file);
        if (!info || info.mtimeMs !== stat.mtimeMs || info.size !== stat.size) {
          try {
            info = { mtimeMs: stat.mtimeMs, size: stat.size, ...describe(file, stat) };
          } catch {
            continue;
          }
          cache.set(file, info);
        }
        const rel = path.relative(ctx.root, file).split(path.sep).join('/');
        const group = groups.find(([prefix]) => rel === prefix || rel.startsWith(`${prefix}/`))?.[1] ?? 'Other';
        out.push({ path: rel, title: info.title, group, updated: info.updated });
      }
    }
    for (const file of cache.keys()) if (!seen.has(file)) cache.delete(file);
    const rank = (g) => (groupOrder.includes(g) ? groupOrder.indexOf(g) : groupOrder.length);
    return out.sort((a, b) => rank(a.group) - rank(b.group) || a.path.localeCompare(b.path));
  };
}

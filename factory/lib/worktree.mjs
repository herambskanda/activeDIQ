// Git worktrees and merging for code-bearing tickets. Every git call is an argument array.
import fs from 'node:fs';
import path from 'node:path';
import { git } from './git.mjs';
import { FactoryError } from './errors.mjs';

/**
 * Branch name for a ticket.
 * @param {string} ticketId
 */
export function branchName(ticketId) {
  return `factory/${ticketId}`;
}

/**
 * Where a ticket's worktree lives (`dispatcher.worktree_root` is relative to the main checkout).
 * @param {object} ctx
 * @param {string} ticketId
 */
export function worktreePath(ctx, ticketId) {
  return path.resolve(ctx.root, ctx.config.dispatcher.worktree_root, ticketId);
}

/**
 * Inspect the main checkout.
 * @param {object} ctx
 * @returns {Promise<{isRepo: boolean, hasCommits: boolean, branch: string|null}>}
 */
export async function repoState(ctx) {
  const inside = await git(ctx.root, ['rev-parse', '--is-inside-work-tree']);
  if (inside.code !== 0) return { isRepo: false, hasCommits: false, branch: null };
  const head = await git(ctx.root, ['rev-parse', '--verify', '-q', 'HEAD']);
  const branch = await git(ctx.root, ['symbolic-ref', '--short', '-q', 'HEAD']);
  return { isRepo: true, hasCommits: head.code === 0, branch: branch.code === 0 ? branch.stdout.trim() : null };
}

/**
 * Whether workers must share the main checkout (no commits yet, or isolation is "none").
 * @param {object} ctx
 * @param {{hasCommits: boolean}} repo
 */
export function usesSharedCheckout(ctx, repo) {
  return ctx.config.dispatcher.isolation === 'none' || !repo.hasCommits;
}

async function registeredWorktrees(ctx) {
  const list = await git(ctx.root, ['worktree', 'list', '--porcelain']);
  return new Set(list.stdout.split('\n').filter((l) => l.startsWith('worktree ')).map((l) => l.slice(9)));
}

/**
 * Create the ticket's worktree on branch `factory/<id>` from the main branch, or reuse the existing one.
 * @param {object} ctx
 * @param {string} ticketId
 * @returns {Promise<{path: string, branch: string, created: boolean}>}
 */
export async function ensureWorktree(ctx, ticketId) {
  const dir = worktreePath(ctx, ticketId);
  const branch = branchName(ticketId);
  if (fs.existsSync(dir)) {
    if ((await registeredWorktrees(ctx)).has(fs.realpathSync(dir))) return { path: dir, branch, created: false };
    throw new FactoryError(`${dir} exists but is not a git worktree`);
  }
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  await git(ctx.root, ['worktree', 'prune']);
  const exists = (await git(ctx.root, ['show-ref', '--verify', '--quiet', `refs/heads/${branch}`])).code === 0;
  const args = exists
    ? ['worktree', 'add', dir, branch]
    : ['worktree', 'add', '-b', branch, dir, ctx.config.dispatcher.main_branch];
  const added = await git(ctx.root, args);
  if (added.code !== 0) throw new FactoryError(`git worktree add failed: ${added.stderr.trim()}`);
  return { path: dir, branch, created: true };
}

/**
 * Merge a finished ticket's branch into the main branch of the main checkout with `--no-ff`.
 * A conflict is aborted cleanly and reported as such.
 * @param {object} ctx
 * @param {{id: string, title: string}} ticket
 * @returns {Promise<{status: 'merged'|'conflict'|'error', detail: string, commit?: string}>}
 */
export async function mergeTicket(ctx, ticket) {
  const main = ctx.config.dispatcher.main_branch;
  const current = await git(ctx.root, ['symbolic-ref', '--short', '-q', 'HEAD']);
  if (current.stdout.trim() !== main) {
    return { status: 'error', detail: `the main checkout is on "${current.stdout.trim() || 'a detached HEAD'}", not "${main}"` };
  }
  const merged = await git(ctx.root, ['merge', '--no-ff', '--no-edit', '-m', `Merge ${ticket.id}: ${ticket.title}`, branchName(ticket.id)]);
  if (merged.code === 0) {
    const head = await git(ctx.root, ['rev-parse', 'HEAD']);
    return { status: 'merged', detail: merged.stdout.trim().split('\n')[0], commit: head.stdout.trim() };
  }
  if ((await git(ctx.root, ['rev-parse', '-q', '--verify', 'MERGE_HEAD'])).code === 0) {
    await git(ctx.root, ['merge', '--abort']);
    return { status: 'conflict', detail: (merged.stdout + merged.stderr).trim().split('\n').slice(0, 6).join(' | ') };
  }
  return { status: 'error', detail: (merged.stderr || merged.stdout).trim().split('\n')[0] };
}

/**
 * Remove a merged ticket's worktree and delete its branch.
 * @param {object} ctx
 * @param {string} ticketId
 * @returns {Promise<string[]>} problems encountered (empty on a clean removal)
 */
export async function cleanupWorktree(ctx, ticketId) {
  const problems = [];
  const dir = worktreePath(ctx, ticketId);
  if (fs.existsSync(dir)) {
    const removed = await git(ctx.root, ['worktree', 'remove', '--force', dir]);
    if (removed.code !== 0) problems.push(`worktree remove: ${removed.stderr.trim()}`);
  }
  await git(ctx.root, ['worktree', 'prune']);
  const deleted = await git(ctx.root, ['branch', '-d', branchName(ticketId)]);
  if (deleted.code !== 0) problems.push(`branch delete: ${deleted.stderr.trim()}`);
  return problems;
}

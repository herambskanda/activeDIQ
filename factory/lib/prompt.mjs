// The worker prompt: templates/worker-prompt.md plus stage-specific instructions.
import fs from 'node:fs';
import path from 'node:path';
import { render } from './render.mjs';
import { isCodeType, resolveFlow, rolesForStage } from './flows.mjs';
import { branchName } from './worktree.mjs';

const list = (ids) => (ids?.length ? ids.join(', ') : 'none');

function metaInstructions(ticket) {
  const meta = ticket.meta ?? {};
  switch (meta.kind) {
    case 'triage':
      return [
        'Stage: triage. Process exactly these items, then advance this ticket:',
        `- Decisions answered or defaulted but not yet applied: ${list(meta.decisions)}. For each: read it (\`factory/bin/factory decision show <id>\`), propagate the answer (CEO preferences and decisions log in knowledge/memory, affected tickets, specs), then run \`factory/bin/factory decision applied <id> --by ${ticket.owner}\`.`,
        `- New CEO feedback: ${list(meta.feedback)}. For each: decide what it means, create tickets or memory entries as needed, then run \`factory/bin/factory feedback triage <id> --note "…" [--tickets T-…]\`.`,
        `- Blocked tickets: ${list(meta.blocked)}. For each: read the block note and decide to unblock (\`ticket unblock\`), re-scope, escalate to the CEO through the ceo-decisions skill, or cancel.`,
        'Never ask the CEO about implementation details; decide them and record the decision.',
      ].join('\n');
    case 'grooming':
      return [
        'Stage: grooming. Use the ticket-craft skill.',
        `The ready queue is short (${meta.ready ?? 0} ready, minimum ${meta.min_ready ?? 0}). Backlog tickets to groom: ${list(meta.backlog)}.`,
        'Refine the best candidates until each meets the Definition of Ready (single outcome, Given/When/Then acceptance, owner, dependencies, links to spec or ADR), then run `factory/bin/factory ticket ready <id>`. Split anything too large for one session. Create new tickets for gaps you find.',
      ].join('\n');
    case 'digest':
      return [
        'Stage: daily digest. Use the status-digest skill.',
        `Write factory/reports/digest-${meta.date}.md. Start from \`factory/bin/factory digest\`; report facts only and never invent progress.`,
      ].join('\n');
    default:
      return 'Stage: meta work. Do what the ticket body asks, then advance.';
  }
}

/**
 * Stage-specific instructions for the worker.
 * @param {object} p
 * @param {object} p.config
 * @param {object} p.ticket
 * @param {string} p.stage in_progress | review | qa
 * @param {string} p.role the role being launched
 * @param {boolean} p.isolated whether the worker has its own worktree
 * @returns {string}
 */
export function stageInstructions({ config, ticket, stage, role, isolated }) {
  if (ticket.type === 'meta') return metaInstructions(ticket);
  const code = isCodeType(config, ticket.type);
  const branch = branchName(ticket.id);

  if (stage === 'in_progress') {
    if (!code) {
      return 'Stage: produce the deliverable. The ticket body and links.spec give the path it goes to. Follow the knowledge-base conventions in knowledge/README.md (frontmatter, status ladder, inline source URLs, [UNVERIFIED] tags). If earlier notes record a rejection, address it first. When the deliverable is complete, commit only the files you produced, by explicit path (`git add <path>…`, never `git add -A` or `git add .` — other workers share this checkout), then advance with a note naming every file you produced.';
    }
    const where = isolated
      ? `Implement on branch \`${branch}\` in this worktree (your working directory).`
      : 'This repository runs without branch isolation: work in the main checkout and commit to the current branch.';
    return `Stage: implement. ${where} Write tests and run them until they pass. Update the docs and the architecture map (knowledge/development/architecture/) if the structure changed, and delete code this change supersedes. Commit with conventional commits (feat:, fix:, test:, chore:…). If earlier notes record a review or QA rejection or a merge conflict, fix that first (for a conflict, merge main into the branch, resolve, and re-run the tests). Then advance.`;
  }

  if (stage === 'review') {
    if (!code) {
      return 'Stage: review. Review the deliverable against the ticket\'s acceptance criteria. Advance if it meets them; otherwise reject with notes that say, per problem, where it is (path and section) and what must change.';
    }
    const reviewers = rolesForStage(ticket, resolveFlow(config, ticket.type).find((s) => s.status === 'review'));
    const second = reviewers.indexOf(role) > 0
      ? ' You are the second reviewer of a security-sensitive ticket: the first review passed, so concentrate on the threat model, trust boundaries, input handling and secrets.'
      : '';
    return `Stage: review. Review the diff of branch \`${branch}\` against main (\`git diff main...${branch}\`) with the review-checklist skill.${second} Advance if it meets the bar; otherwise reject with notes that cite file:line and say exactly what must change.`;
  }

  return 'Stage: QA. Verify every acceptance criterion with evidence (test output, screenshots) using the qa-verification skill, and click every control on a changed screen. Advance if all pass; otherwise reject, listing each failing criterion with its evidence. File separate tickets for unrelated findings.';
}

/**
 * Render the worker prompt for a launch.
 * @param {object} ctx
 * @param {object} p
 * @param {object} p.ticket
 * @param {string} p.role
 * @param {string} p.stage
 * @param {boolean} p.continuation
 * @param {boolean} p.isolated
 * @returns {string}
 */
export function buildPrompt(ctx, { ticket, role, stage, continuation, isolated }) {
  const template = fs.readFileSync(path.join(ctx.templatesDir, 'worker-prompt.md'), 'utf8');
  return render(template, {
    role, stage,
    ticket_id: ticket.id, ticket_title: ticket.title, ticket_type: ticket.type, ticket_priority: ticket.priority,
    continuation, handoff_path: ticket.handoff?.latest ?? '',
    stage_instructions: stageInstructions({ config: ctx.config, ticket, stage, role, isolated }),
  });
}

// Agent definitions: `<main checkout>/.claude/agents/*.md` frontmatter.
import fs from 'node:fs';
import path from 'node:path';
import { parseFrontmatter } from './frontmatter.mjs';

/**
 * Parse one agent file.
 * @param {string} file
 * @returns {{name: string, model: string|null, effort: string|null, description: string, file: string}}
 */
export function parseAgentFile(file) {
  const { data } = parseFrontmatter(fs.readFileSync(file, 'utf8'));
  return {
    name: data.name || path.basename(file, '.md'),
    model: data.model || null,
    effort: data.effort || null,
    description: data.description || '',
    file,
  };
}

/**
 * Every agent definition, keyed by name. Unreadable files are skipped.
 * @param {object} ctx
 * @returns {Map<string, ReturnType<typeof parseAgentFile>>}
 */
export function loadAgents(ctx) {
  const agents = new Map();
  let names = [];
  try {
    names = fs.readdirSync(ctx.agentsDir).filter((n) => n.endsWith('.md')).sort();
  } catch {
    return agents;
  }
  for (const name of names) {
    try {
      const agent = parseAgentFile(path.join(ctx.agentsDir, name));
      agents.set(agent.name, agent);
    } catch {
      // one bad agent file must not hide the others; doctor reports missing agents
    }
  }
  return agents;
}

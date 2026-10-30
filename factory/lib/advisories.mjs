// Security-disclosure intake (runbook security-disclosure §1): poll the repository's private GitHub
// security advisories and open one embargoed security-architect ticket per new report, so the
// 3-business-day acknowledgement target does not depend on the CEO forwarding email.
//
// Rules this module enforces:
//  - Fail loudly. A caller without the security-manager/admin role gets an empty list from GitHub
//    for `state=triage` (not an error), which would look like "no reports". So access is proven
//    first, and every non-success path throws.
//  - The ticket carries no vulnerability details: neutral title, body = the advisory link only.
//  - Exactly one ticket per advisory, deduplicated on `meta.ghsa_id` across every ticket status.
//  - No credentials here: the transport is the `gh` CLI's own login; nothing is read from or written to config.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { FactoryError } from './errors.mjs';
import { appendEvent, listEntities } from './store.mjs';
import { createTicket } from './tickets.mjs';

const exec = promisify(execFile);

export const DEFAULT_REPO = 'herambskanda/activeDIQ';
/** Collaborator role names that can read draft/triage advisories. [UNVERIFIED] exact spelling GitHub returns for the security-manager role — a mismatch fails loudly, never silently. */
export const ADVISORY_ROLES = ['admin', 'security_manager', 'security-manager'];
const GHSA = /^GHSA(-[2-9cfghjmpqrvwx]{4}){3}$/;
const URL_OK = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/security\/advisories\/GHSA(-[2-9cfghjmpqrvwx]{4}){3}$/;

/** Default transport: `gh api` (argv array, no shell). Throws with GitHub's message on any failure. */
export async function ghApi(endpoint) {
  try {
    const { stdout } = await exec('gh', ['api', '--paginate', '--slurp', endpoint], { maxBuffer: 32 * 1024 * 1024, timeout: 60_000 });
    const pages = JSON.parse(stdout);
    return Array.isArray(pages) && pages.every(Array.isArray) ? pages.flat() : pages;
  } catch (err) {
    throw new FactoryError(`GitHub API ${endpoint} failed: ${(err.stderr || err.message || '').toString().trim().split('\n')[0]}`);
  }
}

/**
 * Poll once.
 * @param {object} ctx factory context
 * @param {{repo?: string, api?: (endpoint: string) => Promise<any>}} [opts]
 * @returns {Promise<{checked: number, created: string[], known: number}>}
 */
export async function pollAdvisories(ctx, { repo = DEFAULT_REPO, api = ghApi } = {}) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new FactoryError(`invalid repository "${repo}"`);

  const me = await api('user');
  if (!me?.login) throw new FactoryError('GitHub did not identify the caller — is `gh auth login` done for the factory account?');
  const perm = await api(`repos/${repo}/collaborators/${me.login}/permission`);
  const role = perm?.role_name ?? perm?.permission;
  if (!ADVISORY_ROLES.includes(role)) {
    throw new FactoryError(`${me.login} has role "${role ?? 'none'}" on ${repo}; reading private advisories needs the security-manager role (CEO action, T-0260). Refusing to report zero.`);
  }

  const advisories = await api(`repos/${repo}/security-advisories?state=triage&per_page=100`);
  if (!Array.isArray(advisories)) throw new FactoryError('unexpected response listing security advisories; refusing to report zero');

  const known = new Set(listEntities(ctx, 'tickets').map((t) => t.meta?.ghsa_id).filter(Boolean));
  const created = [];
  for (const adv of advisories) {
    if (!GHSA.test(adv?.ghsa_id ?? '') || !URL_OK.test(adv?.html_url ?? '')) {
      throw new FactoryError('an advisory in the response has an unexpected id or link; refusing to continue');
    }
    if (known.has(adv.ghsa_id)) continue;
    const ticket = createTicket(ctx, {
      title: `Private security report ${adv.ghsa_id}`,
      type: 'bug', owner: 'security-architect', priority: 'P1', status: 'ready',
      tags: ['security-sensitive', 'embargoed'],
      summary: 'Acknowledge within 3 business days and triage per the security-disclosure runbook.',
      body: `${adv.html_url}\n`,
      acceptance: ['Given the linked private report, when triage ends, then the reporter has been acknowledged and a severity decided, with no details written to this ticket.'],
      meta: { kind: 'security-intake', ghsa_id: adv.ghsa_id },
    }, 'security-intake');
    known.add(adv.ghsa_id);
    created.push(ticket.id);
  }
  appendEvent(ctx, { actor: 'security-intake', kind: 'system', text: `advisory poll: ${advisories.length} in triage, ${created.length} new` });
  return { checked: advisories.length, created, known: advisories.length - created.length };
}

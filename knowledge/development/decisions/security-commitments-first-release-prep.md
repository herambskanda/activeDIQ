---
title: External security commitments for the first customer release — decision prep
date: 2026-10-23
updated: 2026-10-23
status: draft
owner: security-architect
kind: decision-prep
ticket: T-0079
---

# External security commitments for the first customer release

Source of the obligation: threat model §16.2 (`../architecture/threat-model.md`), row "External security
commitments". These leave the building, so they are the CEO's. Buyer expectation: ME-SEC §4.4
([`manageengine-ad-customer-voice-and-security.md`](../../business/market-research/manageengine-ad-customer-voice-and-security.md))
lists "same-day advisories with CVSS that matches the CNA record" and "independent pentest attestation"
as what any Tier-0 vendor will be asked for. ME-SEC §4.3 is the benchmark we are measured against:
median 60 days from fix to NVD publication, 68% over 30 days, vendor "High" against CNA 9.8 for
CVE-2026-74849.

## Facts that shape the options

- The repository is already public (decisions-log 2026-10-09, D-0018). A researcher can find a bug today.
  A missing `SECURITY.md` means they open a public issue or tell nobody. So **the intake half is needed now**,
  not at first release.
- A `SECURITY.md` plus a monitored mailbox or GitHub private reporting costs nothing in cash.
  GitHub's private vulnerability reporting is free on public repositories
  ([GitHub Docs](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository)).
  The owner switched it on for this repository (D-0006 option a). On 2026-10-29
  `gh api repos/herambskanda/activeDIQ/private-vulnerability-reporting` returned `{"enabled":true}` (T-0265).
- `security.txt` ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)) requires `Contact` and `Expires`.
  An expired file is treated as stale, so it needs an annual renewal job (devops).
- Becoming our own CNA needs a public disclosure policy and a public point of contact, plus the CVE
  Terms of Use ([OpenSSF CNA guide](https://github.com/ossf/wg-vulnerability-disclosures/blob/main/docs/guides/becoming-a-cna-as-an-open-source-org-or-project.md);
  [CNA Rules](https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v3.0.pdf), the search showed v3.0,
  2020; check the current version before applying). Zoho is its own CNA (ME-SEC §4.3), which is how
  it controls the CVSS in the record. Being a CNA is the only way to make advisory and CVE record
  say the same thing on the same day. Timeline and fees to onboard: `[UNVERIFIED]`, to be confirmed
  with the CVE Program before we commit to a date.
- Penetration test pricing (vendor blogs, rough): about $5,000–$15,000 for a small single application,
  commonly up to $30,000 for SaaS or web with APIs, SSO and admin roles; three to four days is a typical
  minimum; around $2,000 is usually a scan with a cover page
  ([Blaze](https://www.blazeinfosec.com/post/how-much-does-penetration-testing-cost/),
  [Startup Defense](https://www.startupdefense.io/blog/penetration-testing-cost),
  [Cyphere](https://thecyphere.com/blog/penetration-testing-cost/)). Our scope is larger than a typical
  web app (server, DC agent, SSPR portal, Entra connector, update channel), so the realistic first
  quote is above this range `[UNVERIFIED: no quote yet]`.
- We cannot test ourselves into an attestation. The value is an independent party; a self-attested
  letter is a worse signal than none.

## Decision 1 — disclosure and advisory commitment (files as one question)

SECURITY.md, the report address and the policy are the same promise as the advisory SLA: what we
say to a researcher is what we later say to a customer. One question: **how strong a promise do we
publish?**

| Option | What we publish | Cost | Honest downside |
| --- | --- | --- | --- |
| **a. Own CNA, same-day advisory** (recommended) | `SECURITY.md`, `security.txt`, private report channel, acknowledgement in 3 business days, triage in 7, fix targets by severity (critical 14 days, high 30), advisory published **the day the fix ships** with the CVE we assign and a CVSS we publish once, in both places. Safe-harbour for good-faith research. SBOM published per release | No cash. Staff time to run the process; CNA onboarding effort (weeks) | Public deadlines we can miss. A missed 14-day target is visible. Needs one named on-call owner |
| **b. Same-day advisory, CVE via a third party** | Same policy, but CVE IDs come from GitHub's CNA or MITRE after the fix | No cash | CVSS in the record is set by someone else, so it can differ from our advisory, which is the exact ManageEngine complaint (ME-SEC §4.3). Slower IDs |
| **c. Intake only, no deadlines** | `SECURITY.md` with a mailbox and "we will respond", advisories "when a fix is released" | No cash, least staff time | No answer to the buyer question in ME-SEC §4.4. Reads as ManageEngine-like ("median 60 days") to a security reviewer |
| **d. Add a paid bug bounty** | Option a plus rewards via a platform | Platform fee plus rewards, `[UNVERIFIED]` typically five figures a year | Premature before there is a customer base; triage load before we have a security team |

Recommendation: **a**, because our selling point is that the security posture is real (ME-SEC §4.3 is
the weakness we exploit) and it costs time, not money. Do the intake part (`SECURITY.md`,
`security.txt`) immediately under every option, as the repo is public.

Reversibility: published deadlines are hard to withdraw without looking worse. A softer starting
point (deadlines as "targets", tightening after two releases) is a cheap hedge that lives inside
option a. Moving from b to a later is easy; from a to c is a reputational step back.

Blocks: first customer release; the `SECURITY.md` and advisory-template tickets filed after the answer
(security-architect and docs-writer) and the CNA application.

## Decision 2 — independent penetration test attestation

One question: **do we commission an independent pentest before the first customer release, and
publish the result?**

| Option | What we get | Cost | Honest downside |
| --- | --- | --- | --- |
| **a. Independent pentest before release, summary letter to customers under NDA** (recommended) | Third-party attestation for buyer security questionnaires; findings fixed before customers install | Estimate $15,000–$40,000 for server, SSPR portal, DC agent and connector scope `[UNVERIFIED: our estimate from the ranges above; needs 2–3 quotes]` | Fixed money before revenue. A report against a moving codebase ages quickly, so scope it at release candidate |
| **b. Narrow pentest: server, API and SSPR portal only** | The internet-facing and pre-auth surface (the ME-SEC §4.3 recurring components) | Roughly $8,000–$20,000 `[UNVERIFIED]` | DC-side code and update channel untested. Say so honestly in the letter |
| **c. Defer: first release is design-partner only, pentest before general availability** | Money spent once, on the real GA build | No cash now | Early customers install an untested Tier-0 product. Needs a written risk acceptance in their contract |
| **d. Publish the full report** | Maximum trust | Same as a, plus findings are public | Unfixed findings are exposed. Rarely done; the repo is already source-available so we can offer the report to anyone under NDA instead |

Recommendation: **a** with the answer conditional on 2–3 quotes. Failing that, **b** is the
acceptable floor. Rationale: ME-SEC §4.4 lists attestation as an expected item, and the DC agent
and update channel are the components whose compromise takes a domain (threat model TM-X8).

Reversibility: cheap to change before booking; once booked it is a deposit. Engagement lead time is
typically weeks `[UNVERIFIED]`, so book against the release date, which is itself an external date
(CEO).

Blocks: first customer release gate; an engineering freeze at the release candidate.

## What does not need the CEO

Timing of the internal fix process, the advisory template, SBOM format, the `security.txt` renewal job
and who answers the mailbox are factory decisions and follow whichever option is chosen.

## Follow-ups after the answers

- security-architect: `SECURITY.md`, advisory template, severity-to-deadline table, safe-harbour wording.
- devops-engineer: `security.txt` with `Expires` renewal job; SBOM and signed-release publication.
- docs-writer: customer-facing security page.
- service-manager: wording of the pentest letter and customer NDA.

---
title: "Runbook: vulnerability handling, severity-to-deadline table and advisories"
date: 2026-10-23
updated: 2026-10-23
status: draft
owner: security-architect
ticket: T-0260
decisions: [D-0004]
---

# Runbook: vulnerability handling and advisories

The public promise is `SECURITY.md` (T-0258). This runbook is how the factory keeps it. CEO choice
D-0004 (a): our own CVE Numbering Authority (CNA), the advisory on the day the fix ships, one CVSS
score everywhere, deadlines published as **targets**. Decision prep:
`../decisions/security-commitments-first-release-prep.md`. Why it matters: ManageEngine's median gap
from fix to NVD publication is 60 days, and the vendor's label "High" sat against its own CNA's 9.8
(ME-SEC §4.3, [`manageengine-ad-customer-voice-and-security.md`](../../business/market-research/manageengine-ad-customer-voice-and-security.md)).
The CNA application is in `cna-application.md`. The gate is `make fitness-disclosure`.

## 1. Owners

| Role | Who | Does |
| --- | --- | --- |
| **Security on-call owner** (named owner, D-0004) | **security-architect** | Acknowledges, triages, scores, owns the clock and every message to the reporter, writes the advisory. Every report is a P0 or P1 ticket owned by security-architect until triage, then by the module's engineer for the fix |
| **Accountable human and CNA administrative contact** | **the CEO** | The only person with repository admin rights: receives GitHub's private-report notifications, publishes the advisory, is the CNA contact (CNA Rules 3.2.2 needs a named person with email and phone). Actions in §8 |
| Second scorer | code-reviewer (principal-engineer if the score is disputed) | Confirms the CVSS vector before anything is published (§3.2) |
| Fix owner | the module's engineer | Fixes on an `embargoed` ticket (§6) |

Reports reach the factory through GitHub private vulnerability reporting, and through the public
`Security contact request` issue fallback in `SECURITY.md`. Until the factory account can read draft
advisories (§8, A-2) and T-0270 polls them, the CEO forwards each report by filing a factory ticket. The ticket gets a
neutral title, the tags `security-sensitive,embargoed`, and only the advisory link, never the details.

## 2. The clock

Day 0 is the day the report arrives. Business days are Monday to Friday.

| Step | Target | Evidence |
| --- | --- | --- |
| Acknowledge | 3 business days | Comment on the private advisory |
| Triage: confirm or decline, CVSS vector, severity, CVE requested | 7 days | Vector in the advisory draft; ticket note |
| Fix released | By severity, from triage (§3) | Release, `fix_shipped` |
| Advisory published | **The fix day** | `published` = `fix_shipped` (gate) |
| CVE record published | **The fix day**, minutes after the advisory | `datePublished` on the same UTC day (gate). CNA Rules 4.5.1.3/4.5.1.4 require it within 24 h (SHOULD) and 72 h (MUST) of disclosing the ID |
| Credit and closure | Fix day | Reporter told, audit copy committed |

**Missing a target.** Tell the reporter **before** it passes, with the reason and a new date, and
note it on the ticket. The advisory then states `target_met: false` and says by how much we missed and
why. The gate recomputes `target_met` from the dates, so a missed target cannot be published as met.

## 3. Severity-to-deadline table

### 3.1 The table

One score: **CVSS v3.1 base** ([specification](https://www.first.org/cvss/v3.1/specification-document)).
Severity is its qualitative rating (§5 of the specification), and we publish no other label.

| Severity | CVSS v3.1 base | Fix target from triage | Published in `SECURITY.md` | Release vehicle |
| --- | --- | --- | --- | --- |
| Critical | 9.0–10.0 | **14 days** | yes | Out-of-band patch release, through the update channel |
| High | 7.0–8.9 | **30 days** | yes | Patch release |
| Medium | 4.0–6.9 | 90 days (internal) | "a scheduled release; we tell you which one" | Next scheduled release within 90 days |
| Low | 0.1–3.9 | 180 days (internal) | as medium | Next scheduled release within 180 days |

These are targets, published as targets (D-0004 reversibility note). Tighten them only by amending
`SECURITY.md`, this table and `fixTargetDays` in `tools/fitness/disclosure/cvss.go` together.

**Override, clock only, never the score.** If a vulnerability is exploited in the wild, or publicly
disclosed before the fix, it runs on the critical clock whatever its score, and the advisory says
so. The score stays the honest base score.

### 3.2 Scoring rules for a Tier-0 product

- **Score the base, once.** Score at triage. The second scorer confirms the vector before the
  advisory is published. After publication the score changes only to correct an error. A correction
  updates both the advisory and the record the same day (CNA Rules 4.5.3.2) and adds a changelog line
  to the advisory.
- **Scope.** The vulnerable component is activeDIQ. If exploitation lets an attacker act in Active
  Directory or Entra ID with activeDIQ's delegated rights, the impacted component is under a different
  security authority, so the vector is **`S:C`**, and C, I and A are scored for the directory. Most
  privilege-boundary bugs in a Tier-0 tool are `S:C`. Do not under-score them by scoring only our own
  database.
- **DC-side code** (DC agent, password filter): a crash that stops LSASS or the logon path is
  `A:H` against the domain controller.
- **No vendor discount.** We never lower a score for a "rare configuration" or "requires an admin
  account". Those facts go into the vector (`AC`, `PR`) and the advisory text.

## 4. CVE assignment

This section is the public CVE-assignment guidance that CNA Rules 3.2.6.1 requires. `SECURITY.md`
carries its short form.

- One CVE ID per independently fixable vulnerability (CNA Rules 4.2), including in end-of-life
  versions. We never issue a separate ID for an EOL copy of the same flaw (4.2.17.8).
- **Request the ID at triage, not on fix day.** Until we are a CNA, use **Request CVE** on the draft
  GitHub advisory. GitHub is a CNA, and its review typically takes up to 72 hours
  ([GitHub docs](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/publishing-a-repository-security-advisory)).
  It takes the CVSS 3.1 or 4.0 score the maintainer sets
  ([changelog](https://github.blog/changelog/2024-09-13-github-security-advisories-support-cvss-4-0)),
  so set the 3.1 vector, which keeps one score. Once we are a CNA (`cna-application.md`), reserve the
  ID through CVE Services at triage instead.
- **Order on fix day:** release, then the advisory, then the record. A CVE record must never be the
  first public disclosure (CNA Rules 5.3.1), and the ID must not appear in public before its record
  exists.
- **The record carries no credit in its description** (5.2.4). Credit goes in the advisory and in the
  record's `credits` element.
- **Requesting a CVE ID is never conditional** on accepting our embargo or safe-harbour terms
  (CNA Rules 3.2.4.2).
- Example and test IDs use the `CVE-1900-` prefix (5.4). The gate rejects them in published
  advisories.

## 5. Fix day: writing and publishing the advisory

1. The fix is released (signed, through the update channel).
2. Copy `security/advisories/TEMPLATE/` to `security/advisories/<CVE-ID>/`. Fill every `{{…}}`
   in `advisory.md` and `record.json`, delete the instruction comment, and run
   `make fitness-disclosure` until it passes. The gate checks:
   - the same CVE ID in the directory, the advisory, the advisory text and the record;
   - one CVSS v3.1 vector whose computed score equals the published score, and a severity equal to
     that score's rating;
   - no second CVSS version in the record;
   - `published` = `fix_shipped`, and the record's `datePublished` on that UTC day;
   - an honest `target_met`;
   - CWE, an affected product, the advisory as a public reference, no self-reference and no credit in
     the description.
3. Paste everything below the front matter of `advisory.md` into the GitHub advisory, enter the same
   vector in its CVSS field, and publish it (CEO, until §8 A-2 is done).
4. Publish the record. With our own CNA, submit `record.json` through CVE Services
   ([Vulnogram](https://vulnogram.github.io/) accepts it). With GitHub's CNA, GitHub publishes it.
   Then replace `record.json` with the record as published (`https://cveawg.mitre.org/api/cve/<CVE-ID>`)
   and re-run the gate, so that the gate compares what actually went out.
5. Tell the reporter, then commit the audit copy on the same day:
   `docs(security): advisory <CVE-ID>`.

The file `security/advisories/` is the audit copy. The distribution point (CNA Rules 4.5.2.2) is the
repository's Security Advisories page,
<https://github.com/herambskanda/activeDIQ/security/advisories>.

## 6. Embargo: keeping an unfixed vulnerability private

The repository is public. Anything pushed to `main` is disclosure.

- Fix tickets carry the tag `embargoed`, a neutral title and summary, and only the advisory link.
- The fix is built in the advisory's temporary private fork, or on the local ticket branch. Commit
  messages stay neutral until fix day.
- **An `embargoed` ticket is not merged to `main` before fix day.** Until the dispatcher enforces
  this (T-0269), the reviewer and QA stages must check the tag before advancing.
- Reporter embargo: until the fix ships, or 90 days from the report, whichever is first (`SECURITY.md`).
  Exploitation in the wild ends the embargo: ship the fix or a mitigation on the critical clock.

## 7. Records and review

- Every report has a ticket. Declined reports get a written reason sent to the reporter.
- Each quarter, security-architect reports target performance (reported to triaged, triaged to fixed,
  fix to advisory) in the weekly review. Every miss is recorded in `knowledge/memory/lessons.md`.
- Yearly: renew `security.txt` (the gate forces it), re-read the CNA Rules, and rotate the CVE
  Services credentials (OpenSSF guide, `cna-application.md`).

## 8. CEO actions this runbook depends on

Filed on the Factory Board as actions (T-0260):

- **A-1** Turn on GitHub private vulnerability reporting. On 2026-10-23 it was **off**
  (`gh api repos/herambskanda/activeDIQ/private-vulnerability-reporting` → `{"enabled":false}`), while
  `SECURITY.md` already points researchers to it. The public-issue fallback works until then.
- **A-2** Give the factory account the repository *security manager* role, so it can read draft
  advisories and request CVEs. Without it, the CEO forwards every report and publishes every advisory.
- **A-3** Submit the CNA application (`cna-application.md` §5).

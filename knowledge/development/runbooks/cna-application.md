---
title: "CNA application: activeDIQ (skenzeriq) as a CVE Numbering Authority"
date: 2026-10-23
updated: 2026-10-23
status: draft
owner: security-architect
ticket: T-0260
decisions: [D-0004]
---

# CNA application

CEO choice D-0004 (a): we assign our own CVE IDs, so that the advisory and the CVE record carry the
same score on the same day. Zoho does this for ManageEngine as its own CNA, and still published a
vendor "High" against its CNA's 9.8 (ME-SEC §4.3,
[`manageengine-ad-customer-voice-and-security.md`](../../business/market-research/manageengine-ad-customer-voice-and-security.md)).
Being a CNA is necessary but not sufficient; the process in `security-disclosure.md` and its gate do
the rest.

**Status: ready to submit, except the fields only the CEO can provide (§5).** Until onboarding is
complete, CVE IDs come from GitHub's CNA (`security-disclosure.md` §4).

## 1. Rules version checked

- **CNA Operational Rules 4.2.0**: approved 2026-08-20, effective 2026-08-25. Text read from
  [CVEProject/cve-documents `CNA_Rules.md`](https://github.com/CVEProject/cve-documents/blob/master/CNA_Rules.md)
  on 2026-10-23; PDF at [cve.org](https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.2.0.pdf).
  This supersedes the v3.0 (2020) that the decision prep cited.
- A CVE Program post reports **v4.2.6 in effect from 2026-10-20**. It clarifies 4.1 (vulnerability
  determination at Supplier CNAs), 4.2.6 and 4.2.11 (separate IDs)
  ([CVE Program on Medium](https://medium.com/@cve_program/cna-rules-v4-2-6-now-in-effect-24dbf31dacf3)).
  `[UNVERIFIED: the page returned 403; seen in search results only. The repository's master branch still shows 4.2.0, and a cna_rules_4.3.0 branch exists.]`
  None of the reported changes affects anything below. **Re-read the rules page
  ([cve.org CNA Rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules)) on the day of submission.**

## 2. What the rules require, and where we meet it

| Requirement (CNA Rules 4.2.0) | Where we meet it | State |
| --- | --- | --- |
| Scope Definition, approved by the Root before authorisation (3.1.1) | §4 below | Drafted |
| Administrative POC: named people with email **and** phone, at least two recommended, kept private (3.2.2) | CEO (§5) | **CEO** |
| Public POC, published in the List of Partners (3.2.3) | GitHub private vulnerability reporting, plus a public mailbox (§5, A-3b) | **CEO**: reporting is switched off today (A-1) |
| A way to request a CVE ID that is not encumbered by restrictive terms (3.2.4.2) | `SECURITY.md` says a CVE request is never conditional on our embargo or safe-harbour terms | Done (T-0260) |
| Expected response times documented (3.2.4.3) | `SECURITY.md` "What we commit to" | Done (T-0258) |
| Follow the CNA Discussion mailing list (3.2.4.5) | The administrative POC subscribes | **CEO** at onboarding |
| Published guidance on how we assign IDs and publish records (3.2.6.1) | `SECURITY.md` "CVE IDs and scores"; `security-disclosure.md` §4 | Done (T-0260) |
| URL of the disclosure policy (3.2.6.2) | <https://github.com/herambskanda/activeDIQ/blob/main/SECURITY.md> | Done |
| Record within 72 h of disclosing an ID, 24 h recommended (4.5.1.3, 4.5.1.4) | Same day; the gate checks it | Done (`fitness-disclosure`) |
| A public advisory distribution point, no login, no restrictive terms (4.5.2.2, 4.5.2.4) | <https://github.com/herambskanda/activeDIQ/security/advisories> | Done (nothing published yet) |
| Advisory must not contradict the record (4.5.2.3) | One CVE ID and one CVSS vector, compared by the gate | Done |
| Record content: product, an affected version, CWE, English description, public reference, no self-reference (5.1–5.3) | `security/advisories/TEMPLATE/record.json` and the gate | Done |
| Agree to the CVE [Terms of Use](https://www.cve.org/Legal/TermsOfUse) | Legal acceptance | **CEO** |

## 3. Process and timeline

These steps follow the [OpenSSF guide](https://github.com/ossf/wg-vulnerability-disclosures/blob/main/docs/guides/becoming-a-cna-as-an-open-source-org-or-project.md).
It is written for open-source projects, but its steps are the CVE Program's own. There is no fee and no contract
([CVE Program blog, 2019](https://www.cve.org/Resources/Media/Archives/OldWebsite/blog/August292019_Become_a_CNA_to_Assign_Your_Own_CVE_IDs.html);
`[UNVERIFIED: 2019 post; confirm still true at first contact]`).

1. Submit the [CVE Program request form](https://cveform.mitre.org/) and choose the option to ask about
   becoming a CNA. The program replies with an onboarding form.
2. Complete the onboarding form with the answers in §4, and give three dates for the onboarding call.
3. Watch the CNA onboarding and CVE Services training videos
   ([CNA onboarding resources](https://www.cve.org/ResourcesSupport/Resources#cnaOnboarding)).
   security-architect watches them and summarises them for the CEO.
4. Attend the onboarding call: about an hour, with every contact present.
5. Complete the practice exercises. security-architect drafts them from `record.json` in
   [Vulnogram](https://vulnogram.github.io/), and the CEO submits them.
6. Get announced in the List of Partners.

**Timeline:** at least about four weeks from first contact, with at least three weeks before the
first call (OpenSSF guide). Count it as **4–8 weeks** `[UNVERIFIED: upper bound is our buffer]`.
Start now, so that we are a CNA before the first customer release.

## 4. Form answers, ready to paste

| Field | Answer |
| --- | --- |
| Organisation full name | **CEO to confirm**: the legal entity name of skenzeriq |
| Short name (becomes `assignerShortName`) | `skenzeriq` |
| Country | **CEO to confirm** |
| Industry (GICS) | 451030 Software (OpenSSF guide) |
| CNA role and type | CNA; Vendor |
| Root | **MITRE TL-Root**. activeDIQ is a commercial product under the Business Source License (`LICENSE`), not open source, so Red Hat's open-source Root is not the natural fit. The OpenSSF guide says MITRE TL-Root may be selected when undecided |
| Scope Definition | "All skenzeriq products, including activeDIQ, in supported and end-of-life versions." This is the broad Supplier form of CNA Rules 3.1.3; EOL is covered as 3.1.11 allows |
| Vulnerability disclosure policy URL | <https://github.com/herambskanda/activeDIQ/blob/main/SECURITY.md> |
| Advisory location URL | <https://github.com/herambskanda/activeDIQ/security/advisories> |
| Public contact | <https://github.com/herambskanda/activeDIQ/security/advisories/new>, and the public mailbox from A-3b once it exists |
| Administrative contacts (private) | **CEO**: at least two named people, each with a personal email address and a phone number |
| CVE requests in flight | None |
| Estimated CVEs per year | 0–10 for the first year |

## 5. CEO-only steps (Factory Board actions)

These leave the building or bind the company, so they are the CEO's. Everything else is done.

- **A-1 Switch on private vulnerability reporting** (repository Settings → Security → Private
  vulnerability reporting). It is **off** today, although `SECURITY.md` points to it. This step is
  needed now, regardless of the CNA.
- **A-2 Give the factory account the security manager role** on the repository, so it can read draft
  advisories and request CVEs (`security-disclosure.md` §1).
- **A-3 CNA submission:**
  - (a) Name the administrative contacts.
  - (b) Decide whether to open a public security mailbox on the company domain. CVE requesters
    without a GitHub account need one, and it may cost money.
  - (c) Confirm the legal name and country.
  - (d) Accept the CVE Terms of Use.
  - (e) Submit the request form (§3 step 1), attend the call and submit the exercises that
    security-architect prepares.

When A-3 is done, record the CNA status in `knowledge/memory/decisions-log.md`. Then switch
`security-disclosure.md` §4 and the `SECURITY.md` "CVE IDs and scores" section from GitHub's CNA to
our own, in one change.

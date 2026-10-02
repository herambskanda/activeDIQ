---
title: "Open Source Licence Register — activeDIQ"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: heramb
---

# Open Source Licence Register

> **Purpose.** One place that answers: which outside code do we use, how much, under what licence,
> and does it need a conversation before we ship? activeDIQ ships **on-prem**, which is
> *distribution* — the act that triggers copyleft obligations.
>
> **Not legal advice.** Engineering triage to decide what needs a lawyer. Anything embedded gets a
> real legal review before we ship it. Adapted from `../UEM/knowledge/business/licensing/`.
>
> **Rule:** every new dependency gets a row here *before* it is adopted (CLAUDE.md rule 9).

---

## 1. The three ways we can use someone's project

The licence only matters for some of these. Getting this distinction right saves a lot of
unnecessary negotiation.

| Mode | What it means | Licence needed? |
| --- | --- | --- |
| **Inspiration** | We read their code and docs, learn the design, then write our own | **No.** Ideas and architecture are not copyrightable. Only the actual code is. This is always free. |
| **Separate process** | We ship their program unmodified next to ours and talk over an API or network | **Usually no derivative work** ("mere aggregation"). The escape hatch closes if we modify them. |
| **Embedded** | We copy their code, link their library, or build it into our binary | **Yes.** This is where copyleft and proprietary terms bite. |

**Most of what we want is inspiration.** Studying how other tools model delegation or audit
events costs nothing and needs nobody's permission. We only need a conversation when we want the
actual code inside our product.

---

## 2. The question that decides whether negotiation is even possible

**Can they legally grant us a licence?**

- **Yes — single owner or CLA.** If one company owns the code, or every contributor signed a
  Contributor Licence Agreement handing rights to the project, then one party can say yes. These
  are worth approaching.
- **No — diffuse copyright.** If a project has many outside contributors and no CLA, nobody owns
  all of it. The maintainers cannot relicense it even if they want to, because they do not hold
  the rights to other people's contributions. Approaching them is wasted effort.


---

## 3. Register

Status key: **Clear** = no action needed. **Talk** = worth a conversation. **Check** = needs legal
review or more research. **Candidate** = under consideration, not adopted (adoption needs the ADR
that chooses the stack).

| Project | Licence | Use | Mode | Ships to customers? | Status |
| --- | --- | --- | --- | --- | --- |
| Node.js (factory runtime) | MIT | Internal tooling only | Separate process | No | **Clear** |
| go-ldap/ldap | MIT | LDAP client (if Go is chosen) | Embedded | Yes | **Candidate** |
| jcmturner/gokrb5 | Apache-2.0 | Kerberos client (if Go is chosen) | Embedded | Yes | **Candidate** |
| microsoftgraph/msgraph-sdk-go | MIT | Entra ID / M365 (if Go is chosen) | Embedded | Yes | **Candidate** |
| React | MIT | Web UI (if chosen) | Embedded | Yes | **Candidate** |
| PostgreSQL | PostgreSQL Licence | Product database (if chosen) | Separate process | Yes | **Candidate** |
| Samba 4 (AD DC) | GPL-3.0 | Test lab only (Docker) — never shipped | Separate process | No | **Clear** for testing; **Check** before any shipping use |
| Playwright | Apache-2.0 | E2E tests, QA screenshots, demo recording | Dev tooling | No | **Candidate** |
| FFmpeg | LGPL-2.1+ (GPL with some options) | Demo/tutorial video editing | Dev tooling | No | **Clear** for internal use |

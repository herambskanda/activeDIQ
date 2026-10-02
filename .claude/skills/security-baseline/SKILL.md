---
name: security-baseline
description: Secure-development baseline for a Tier-0 AD product — when security-architect review is mandatory, safe primitives, secrets, service accounts, transport, console auth, RBAC, tamper-evident audit, supply chain, updates. Use for security work.
---

# Security baseline

activeDIQ holds rights to reset passwords, change group membership and read secrets in the
customer's domain. It is **Tier 0**: compromising it compromises the forest. Customers switch
from ManageEngine partly because of its security record — exploited pre-auth bugs in
ADSelfService Plus (CVE-2021-40539, REST API authentication bypass → RCE, exploited in the wild:
https://nvd.nist.gov/vuln/detail/CVE-2021-40539, https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a)
and an outdated third-party SAML library across many products (CVE-2022-47966:
https://nvd.nist.gov/vuln/detail/CVE-2022-47966). Full record and customer voice:
`knowledge/business/market-research/manageengine-ad-customer-voice-and-security.md` (draft).
We cannot afford one of those. Owner: `security-architect`.

Bug classes the competitor shipped repeatedly — design them out, don't patch them later (research doc §4.1):
- **Embedded browser on the logon screen** → SYSTEM code execution (CVE-2020-11552, CVE-2026-74849).
  Our credential provider renders no web content; it talks to the server over a narrow typed API.
- **Unauthenticated agent / REST API routes** (CVE-2021-40539, CVE-2026-6516, CVE-2026-75791). Every
  route is authenticated by default; anonymous routes are an explicit, reviewed allow-list.
- **Predictable SSO or session tickets** → account takeover (CVE-2026-11374). Tokens come only from a
  CSPRNG with ≥128 bits, are bound to the audience, and expire.
- **Stale third-party libraries** in auth paths (CVE-2022-47966, xmlsec 1.4.1). SBOM plus dependency
  scanning gate every release.
- **Default credentials and plain HTTP on first run** (ADManager Plus admin/admin over HTTP). We use
  TLS from first boot and a one-time setup secret — never a default password.

Area checklists (auth, self-service portal, DC-resident code, updates): `reference/checklists.md`.

## 1. When `security-architect` review is mandatory

Tag the ticket `security-sensitive` (the dispatcher then adds `security-architect` as a second
reviewer) when it touches any of:

| Trigger | Examples |
| --- | --- |
| Authentication and sessions | console login, SSO/SAML/OIDC, MFA, API tokens, self-service enrolment and identity verification |
| Authorisation | RBAC, delegation scopes, approval workflows, anything deciding "may this caller do this" |
| AD/Entra writes | password set, unlock, membership, UAC flags, ACLs, delegation, deletes, bulk jobs |
| Credentials and secrets | service-account and Graph credentials, LAPS/BitLocker retrieval, key storage, tokens |
| DC-resident or host code | DC agent, password filter (LSASS), credential provider, installers, services |
| Network listeners | any new port, endpoint without auth, webhook receiver or sender (SSRF) |
| Crypto | any use of crypto primitives, signing, TLS configuration, random tokens |
| Untrusted input parsing | CSV/LDIF import, admin-supplied LDAP filters, file uploads, XML/SAML, event-log parsing |
| Safe primitives | the filter/DN/attribute builders, SQL layer, PowerShell invocation, SD model |
| Audit trail | anything that writes, stores, exports or could suppress audit events |

Unsure? Tag it. A missed tag is a review finding; an extra review costs one session.

## 2. Safe primitives (CLAUDE.md rule 5)

Never build security-relevant strings by formatting or concatenation (PatchIQ §11 #1, #10).

| Value | Only via |
| --- | --- |
| LDAP filter, DN, attribute encodings | `ldapfilter`, `dn`, `attr` packages (`ad-engineering` §1) |
| SQL | parameterised queries / generated code; tenant context via `set_config($1, true)` |
| Shell / PowerShell | argument arrays, never a shell; PowerShell runs fixed scripts with bound parameters, data as JSON on stdin |
| Security descriptors | typed SD model (owner, DACL entries with SID, access mask, object-type GUID, flags) → binary; never hand-edited SDDL strings |
| HTML | the framework's auto-escaping; no `dangerouslySetInnerHTML`; CSP without `unsafe-inline` |
| JWT / SAML | vetted library, algorithm pinned, issuer/audience/expiry checked; never hand-assembled claims |

Enforcement: types that make the unsafe call unrepresentable, lint/import rules, fuzz tests.

## 3. Secrets

- Never in the repo, config files, logs, error messages, URLs, audit `detail` fields, crash dumps
  or telemetry. `.env*` is gitignored; gitleaks runs pre-commit and in CI; the guard hook blocks
  secret-shaped writes — if it blocks you, it is right.
- At rest: OS key store (DPAPI on Windows, keychain/kernel keyring on Linux) or Vault, with an
  envelope key; our database stores ciphertext only. Encryption keys never sit beside the data.
- In code: a `Secret` type (redacted string/JSON forms, zeroed after use where the runtime allows).
- Rotation: every credential we hold can be rotated without downtime; we surface age and expiry.
- LAPS passwords, BitLocker keys and similar are retrieved on demand, never cached, every read audited.

## 4. AD service accounts and Graph apps

- **Never Domain Admin, Enterprise Admin or equivalent.** The installer and docs specify exact
  delegated rights per feature, scoped to OUs; a feature that needs more says so in its spec and
  gets `security-architect` sign-off.
- Prefer gMSA on Windows hosts; Kerberos over simple bind; separate accounts for read/sync and
  for writes where the customer wants it. Never store a customer's personal admin credentials.
- Health check reports rights that are **excessive** as well as missing.
- Graph: certificate credentials, least-privilege application permissions (`ad-engineering` §5),
  no `Directory.ReadWrite.All` without sign-off.

## 5. Transport

TLS 1.2+ everywhere (1.3 preferred), modern cipher suites, HSTS on the console. LDAPS or StartTLS
with certificate verification; LDAP signing and channel binding supported and tested; Kerberos
for DC binds where possible. No plaintext protocol is enabled by default. Agent ↔ server traffic
mutually authenticated (mTLS or signed tokens bound to the agent identity).

## 6. Console authentication and sessions

- SSO (SAML 2.0/OIDC) and MFA for every console user; local accounts only for break-glass, with
  MFA. AD credential login (if offered) uses Kerberos/LDAPS bind with the empty-password guard.
- Sessions: `HttpOnly`, `Secure`, `SameSite=Strict` cookies, CSRF tokens on mutations, idle and
  absolute timeouts, re-authentication for privileged actions (e.g. reading LAPS, changing RBAC).
- Login and self-service endpoints: rate limits, generic errors (no account enumeration), and they
  must never be the way an attacker locks AD accounts (`ad-engineering` gotchas #31–32).

## 7. RBAC, delegation and audit invariants

- **Deny by default** at the router: every route declares its permission; a route without one
  fails startup (the ADSelfService CVE-2021-40539 class). Unauthenticated routes are an explicit,
  reviewed allow-list.
- Effective permission = role ∩ delegation scope (domains/OUs/object types) ∩ token scope —
  checked against the **target object**, server-side, for every item in a bulk job.
- No role can grant more than its granter holds. Changes to roles and scopes are themselves
  privileged, audited, and optionally require approval.
- Our service account's power is not the user's power: authorise the human first, then act.
- **Audit**: every privileged action — success, failure and denial — records actor, on-behalf-of,
  source, target (GUID + DN), before/after (secrets redacted), result and correlation IDs; it is
  written in the same transaction as the action. The audit store is append-only for the
  application role (no UPDATE/DELETE grants), **hash-chained** with periodic signed checkpoints so
  tampering is detectable, exportable to SIEM (syslog/CEF), and its own retention and access are
  audited.

## 8. Supply chain and build

- SBOM (CycloneDX) per release; dependency and vulnerability scanning (`govulncheck`,
  `osv-scanner`, npm audit) gating CI on high/critical with a reachable path.
- Licence register before any new dependency (`engineering-standards` §3).
- Builds from CI only, reproducible where feasible; artefacts signed — Authenticode for Windows
  binaries and MSIs, signatures for containers and update bundles; CI actions pinned by SHA;
  signing keys in an HSM or cloud KMS, never on a developer machine or in the repo.

## 9. Updates

Update bundles are signed and verified **before** anything is unpacked; downgrade (rollback)
protection; staged rollout for DC-resident components, with a tested uninstall path; no update
channel that can run arbitrary code without signature verification; air-gapped customers use the
same signed bundle via a different transport.

## 10. Vulnerability handling

- Internally: any suspected vulnerability → P0/P1 `bug` tagged `security-sensitive`, details kept
  out of public text until fixed. CVSS-scored by `security-architect`.
- Externally: `SECURITY.md`, a disclosure address, response SLAs, coordinated disclosure and CVE
  assignment are **commitments that leave the building** → CEO decision before first customer
  release (`ceo-decisions`). Draft them; do not publish them.

## 11. Reviewer's minimum (security-architect)

- [ ] Threat model updated for new trust boundaries, listeners or privileges (STRIDE per data flow).
- [ ] Safe primitives used; no raw construction; fuzz tests for new parsers.
- [ ] Authorisation on the target object; deny-by-default holds; bulk items checked individually.
- [ ] No secret in code, logs, errors, audit or fixtures; rotation path exists.
- [ ] Audit events complete for every new privileged action, including failures and denials.
- [ ] Rights required from AD/Entra are minimal and documented.
- [ ] The relevant area checklist in `reference/checklists.md` passes.

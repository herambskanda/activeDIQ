# Security checklists by area

Use the section that matches the change. Each item is a yes/no question; a "no" is a finding.

## A. Self-service portal (the ADSelfService Plus attack surface)

ADSelfService Plus is often exposed to the internet and was exploited pre-auth
(CVE-2021-40539: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a). Assume ours
will be exposed too.

- [ ] Every unauthenticated endpoint is on the reviewed allow-list; everything else denies by default.
- [ ] Identity verification is multi-factor; enrolment requires an already-authenticated session.
- [ ] Responses do not reveal whether an account exists (same body, status and timing class).
- [ ] Per-account and per-IP rate limits; our own failure counter stops below the domain lockout
      threshold, so the portal cannot be used to lock users out.
- [ ] Security answers and OTP secrets are stored hashed/encrypted; OTPs single-use, short-lived.
- [ ] Resets send the password-policy-hints control (history enforced) and run over LDAPS.
- [ ] No feature executes admin-configured scripts or commands with input from the portal.
- [ ] The portal component can run separated from the admin console (own process/host), with no
      admin APIs reachable from it.

## B. Console authentication and RBAC

- [ ] SSO + MFA; break-glass local account has MFA and alerts on use.
- [ ] Session cookie flags, CSRF, idle/absolute timeout, re-auth for privileged actions.
- [ ] Route registry fails startup on a route without a permission.
- [ ] Scope checks run per target object; tests cover a user just outside the delegated OU.
- [ ] Privilege-changing actions (roles, scopes, tokens) are audited and cannot self-escalate.

## C. Directory writes

- [ ] Inputs validated, values encoded via `attr` codecs, DNs via `dn`, filters via `ldapfilter`.
- [ ] Dry run available and exact; destructive actions confirmed in the UI with the impact count.
- [ ] Protected objects (AdminSDHolder, accidental-deletion protection, privileged groups) handled
      explicitly — warn, never silently override.
- [ ] Writes to privileged groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators,
      Account/Server/Backup Operators, DnsAdmins, Group Policy Creator Owners) require a dedicated
      permission and are flagged in audit.
- [ ] Per-item audit with before/after; secrets redacted.

## D. DC-resident and host code (windows-engineer)

- [ ] Password filter: no blocking I/O in LSASS callbacks; bounded memory; fails **open or closed
      as the spec decides, explicitly**; cannot crash LSASS (a crash reboots the DC).
- [ ] Credential provider: no network call on the logon UI thread; works offline with a clear
      message; cannot block normal logon if our service is down.
- [ ] Services run as least-privileged virtual accounts or gMSA, not LocalSystem unless justified.
- [ ] Binaries and MSI Authenticode-signed; install and uninstall tested on a DC in the Windows lab.
- [ ] Agent ↔ server channel mutually authenticated; the agent accepts commands only from its server.

## E. Parsing untrusted input (CSV, LDIF, XML/SAML, event logs, filters)

- [ ] Size and row limits; streaming parsers for large files; no XML external entities.
- [ ] CSV export neutralises formula injection (`=`, `+`, `-`, `@` leading cells).
- [ ] Admin-supplied LDAP filters parsed to an AST and validated, never passed through as text.
- [ ] Fuzz test for the parser in CI.

## F. Webhooks and outbound calls

- [ ] Signed (Standard Webhooks); secrets rotatable; payloads without secrets.
- [ ] SSRF protection: no loopback, link-local, metadata or internal ranges unless allow-listed.
- [ ] Timeouts, retries with backoff, no redirects followed to disallowed hosts.

## G. Updates and release

- [ ] Signature verified before unpacking; version monotonic (no downgrade).
- [ ] SBOM generated; scanners clean or every finding triaged with a ticket.
- [ ] Rollback/uninstall path tested for DC-resident components.

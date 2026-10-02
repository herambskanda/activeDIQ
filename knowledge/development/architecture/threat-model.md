---
title: "Threat model v0 — activeDIQ security architecture"
date: 2026-10-02
updated: 2026-10-02
status: review
owner: heramb
author: security-architect
ticket: T-0007
binding_sources: ADR-0001 (ratified), ADR-0002 (ratified), blueprint v0 (review), safe-primitives.md (review)
sources_last_checked: 2026-10-02
---

# Threat model v0 — activeDIQ security architecture

activeDIQ holds delegated write authority over a customer's Active Directory and Entra ID. This
document says what an attacker gains by compromising it, where the trust boundaries are, which
control stops each threat, and which test proves the control. It also fixes the service-account
model: the minimum AD rights and Graph permissions per feature family, and the Tier-0 object set.

Short names used throughout:

| Name | Document |
| --- | --- |
| ADR-0001 | [`../decisions/0001-technology-stack.md`](../decisions/0001-technology-stack.md) (ratified) |
| ADR-0002 | [`../decisions/0002-deployment-model.md`](../decisions/0002-deployment-model.md) (ratified) |
| BP | [`blueprint.md`](blueprint.md) — architecture blueprint v0 (review) |
| SP | [`safe-primitives.md`](safe-primitives.md) — safe-primitives spec (review) |
| FEAS | [`build-feasibility/ad-technical-feasibility.md`](build-feasibility/ad-technical-feasibility.md) |
| DM | [`../domain/domain-model.md`](../domain/domain-model.md) — entity and invariant IDs (`DM-16.I8`) |
| ME-SEC | [`../../business/market-research/manageengine-ad-customer-voice-and-security.md`](../../business/market-research/manageengine-ad-customer-voice-and-security.md) — the competitor's security record. CVE IDs in this file are cited from ME-SEC §4.1–4.4, never from memory |
| SB | `.claude/skills/security-baseline/SKILL.md` and its `reference/checklists.md` (checklists A–G) |

---

## 0. How to use this document

**What is binding.** The ratified ADRs bind this document, as they bind the blueprint. Where this
file and a ratified ADR disagree, the ADR wins and this file is the bug. Inside those limits, the
items marked **DECISION** (IDs `TM-D*`) are security-architect decisions. A spec, ADR or ticket may
not contradict one without a recorded security-architect review that changes this file first.
Everything else is design direction for the spec that owns the feature.

**IDs.** Everything carries an ID so tickets and reviews can cite it ("violates TM-TB3-T2").

| Prefix | Meaning | Section |
| --- | --- | --- |
| `TM-O*` | security objective | §1 |
| `TM-A*` | asset | §2 |
| `TM-X*` | attacker | §3 |
| `TB*` | trust boundary | §4 |
| `TM-TBn-Tk` | threat k on boundary n (STRIDE row) | §5 |
| `TM-D*` | decision taken in this document | §6–§13 |
| `TM-F-*` | proof (test or fitness function) this document demands | §15 |
| `TM-R*` | residual risk | §16 |
| `TM-Q*` | open item | §17 |

**Notation.** `[OPEN → T-xxxx / spec]` means the item is decided there, under the constraint
written next to it. `[M3]` / `[M4]` marks a later milestone; it is drawn now so v1 code does not
block it. `[UNVERIFIED]` marks an external claim not yet confirmed; `[LAB]` marks a behaviour that
needs the Windows or Samba lab. Proof names that exist already: `FF-SP1`–`FF-SP9` (SP §8, tickets
T-0033/T-0034), `fitness-tenancy` T1–T5 (ADR-0002, T-0036), `fitness-profiles` P1–P7 (ADR-0002,
T-0038), the API fitness of T-0046 and the operation/audit fitness of T-0047.

**Who updates it.** Any ticket that adds a trust boundary, listener, process, privilege, credential,
anonymous route or outbound destination type updates this file in the same change (§14). A ticket
that does not is a review reject. security-architect owns the file; the owning engineer writes the
change, security-architect reviews it.

**Relation to ADRs.** This is a living spec, not an ADR. Decisions here that would be expensive to
reverse and that cross several modules (e.g. TM-D2, TM-D6) may later be lifted into an ADR with a
fitness function. Until then the proof table (§15) is their enforcement.

---

## 1. Security objectives

**What an attacker gains.** A management tool for AD is the shortest path to a domain. When the
competitor's self-service product was exploited through CVE-2021-40539, CISA's remediation for a
compromise that reached NTDS.dit was **domain-wide password resets plus a double Kerberos TGT
(krbtgt) reset** ([AA21-259A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a);
ME-SEC §4.2). Attackers injected KdcSponge into LSASS on DCs to harvest credentials (ME-SEC §4.2,
Unit 42). Horizon3 found "highly privileged" AD credentials in another of the competitor's
product databases (ME-SEC §4.4). The buyer's inference is ours too: **a compromise of activeDIQ must
be scoped as an AD incident** (ME-SEC §4.4). The objectives below exist so that, in a default
install, it is not a *forest* incident.

| ID | Objective | Holds when | Where | Main proofs |
| --- | --- | --- | --- | --- |
| TM-O1 | **A compromise of the management plane never yields Tier 0.** | All four conditions of ADR-0002 rule 9 hold: (1) the connector's AD identity holds delegated rights only, with no write or control right on any `tier0` object or DC; (2) the Entra app holds no permission to manage privileged roles; (3) the server never runs on a DC; (4) control-plane components never share a process with a management-plane role and accept only signed, typed, allow-listed messages | §6, §12 | TM-F-RIGHTS, TM-F-T0GUARD, P1, TM-F-HOST |
| TM-O2 | **No anonymous path reaches a privileged operation.** | Deny-by-default router; the anonymous routes equal a reviewed allow-list; every RPC except `Enroll` requires a client certificate | §7, §8 | TM-F-ANON, TM-F-FLEET, T-0046 API fitness |
| TM-O3 | **Directory credentials exist only inside the connector.** | Only `internal/connector/` names, unseals or uses them; no API response, log, error or audit record carries one | §6.1, §9 | P3, FF-SP1/SP2, TM-F-SECRETOUT |
| TM-O4 | **Tenants are isolated.** | Tenant comes only from an authenticated principal; RLS + FORCE; sealed values bound to their tenant and row | §9, §13 | T1–T5, P4, TM-F-SEAL |
| TM-O5 | **Every change activeDIQ makes is attributable and tamper-evident.** | Same-transaction audit of success, failure and denial; append-only; hash-chained per tenant; checkpoints anchored outside the host | §11 | TM-F-AUDIT, T-0047 fitness |
| TM-O6 | **Only skenzeriq-signed code runs.** | Every artefact and update is signed in CI and verified before unpack; the server can push to agents only release-signed artefacts | §10 | TM-F-UPDATE, P5 |
| TM-O7 | **DC-resident code cannot take down a DC or run server-supplied code.** | Closed command set; policy is data; no network I/O in LSASS; fail mode decided explicitly | §12 | TM-F-AGENTCMD, T-0040, T-0024 |
| TM-O8 | **Internet exposure happens only through `edge`, which is assumed compromised.** | The server is never published; edge holds no directory credential, tenant key or database; the tunnel lands on a router that mounts only the self-service routes | §8 | TM-F-EDGE, P1 |

---

## 2. Assets

Tier is the Enterprise Access Model plane the asset belongs to when activeDIQ is deployed as
designed (FEAS §2.1;
[Enterprise Access Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)).
"Mgmt" is the management plane. An asset marked *Tier 0 if mis-delegated* becomes Tier 0 the moment
a customer grants more than §6.3 allows.

| ID | Asset | Where it lives | Tier | What compromise gives the attacker |
| --- | --- | --- | --- | --- |
| TM-A1 | **Directory write authority** — the connector identity's delegated rights | AD ACLs on delegated OUs; the Entra app's granted permissions | Mgmt; Tier 0 if mis-delegated | Reset, unlock, modify, move or delete every in-scope object; change group membership (and so access to everything those groups guard). With any right on a `tier0` object: the forest |
| TM-A2 | **Directory credentials** — gMSA (no stored secret), AES keytab, AD password fallback, Entra certificate private key | gMSA: KDS-derived, host-bound; keytab: file on the connector host; password fallback and Entra key: sealed in PostgreSQL (embedded) or on the remote connector host (TM-D8) | Mgmt | Everything in TM-A1, from anywhere the attacker can reach a DC or Graph, without passing our RBAC or audit |
| TM-A3 | **KEK and per-tenant DEKs** | KEK: profile key provider (DPAPI-NG/TPM, TPM2/KMS/Vault/passphrase, KMS); DEKs: wrapped in PostgreSQL (DM-02), plaintext in memory only | Mgmt | Opens every sealed value: Entra keys, password fallbacks, MFA seeds, integration credentials |
| TM-A4 | **Console sessions, API tokens, MFA enrolments** | Session and token hashes in PostgreSQL (DM-31, DM-32); seeds sealed (DM-37) | Mgmt | Act as a technician or administrator within their RBAC; with an admin's: change RBAC itself |
| TM-A5 | **Audit-trail integrity** | Append-only tenant table, hash chain, checkpoints (DM-80, DM-81); SIEM copy | Mgmt | Hide what was done; frame a technician; defeat the evidence auditors ask for |
| TM-A6 | **Inventory** — PII and the reconnaissance map (memberships, `tier0` set, delegations, stale and privileged accounts, last logons) | PostgreSQL, blobs, exports | Mgmt | Privacy breach; a ready-made attack-path map of the forest |
| TM-A7 | **Secrets in transit** — new passwords, OTP codes, LAPS passwords, BitLocker keys being revealed | Request bodies, connector memory, TLS/LDAPS buffers; never stored (SP §3.7) | Mgmt (LAPS on servers: the server's tier) | Account takeover of the reset user; local admin on the LAPS-managed machine |
| TM-A8 | **Release-signing keys and the update channel** | skenzeriq CI and HSM/KMS (T-0027); public keys pinned in every install | skenzeriq supply chain | Code execution in every customer, including on DCs [M3] — the SolarWinds pattern ([AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)) |
| TM-A9 | **DC-resident code** [M3/M4] — `cmd/agent` + `addc`, `native/passfilt` in LSASS, `native/credprov` in LogonUI | DCs; endpoints | Tier 0 (DCs); endpoint tier (credprov) | Code on a DC is the forest; a crash in LSASS reboots the DC (SB checklist D) |
| TM-A10 | **Agent-policy signing key** [M3] | Management plane, sealed under the tenant DEK (BP §12) | Mgmt, bounded by TM-D14 | Sign policies DC agents accept; bounded to policy *data* within schema (§12) |
| TM-A11 | **Fleet enrollment CA key and enrollment tokens** | Server (sealed); tokens hashed (DM-12.I2) | Mgmt | Mint connector/agent identities for a tenant; impersonate a connector to receive operations |
| TM-A12 | **End-user verification and SSPR enrolment data** — v1 TOTP seeds (FD-05, DM-37); [M4] SSPR factors | Sealed in PostgreSQL | Mgmt | Pass caller verification (ENH-09) or SSPR as the victim → password reset → account takeover |
| TM-A13 | **Platform configuration** — hostname bindings (DM-04), IdP metadata and signing certificates, trust anchors (DC CAs, fleet CA), listen addresses, update ring | Config file and platform tables | Mgmt | Re-point SSO to an attacker IdP; accept a rogue DC certificate; expose a listener |

---

## 3. Attackers

| ID | Attacker | Position and capabilities | Typical goal | Boundaries |
| --- | --- | --- | --- | --- |
| TM-X1 | **Internet, unauthenticated** | Reaches whatever is published: `edge` [M4], and the server only if the customer publishes it against our guidance | Pre-auth RCE or auth bypass (the CVE-2021-40539 class, ME-SEC §4.1) | TB11, TB1, TB10 |
| TM-X2 | **LAN, unauthenticated** | On the network path: MITM, NTLM relay, authentication coercion, rogue DHCP/DNS, spoofed DCs or RADIUS clients | Capture or relay our service identity; downgrade transport; forge RADIUS answers | TB1, TB3, TB6, TB12, TB19 |
| TM-X3 | **Low-privilege AD user** | Writes the attributes the estate lets users write on their own object (by default part of the Personal-Information property set `[UNVERIFIED — lab]`); can create computer accounts while `ms-DS-MachineAccountQuota` allows `[UNVERIFIED — estate]`; can trigger failed logons | Stored XSS or CSV formula injection in admin views and exports; a UNC `homeDirectory`/`profilePath` that coerces our identity; lock other users out through our flows | TB1, TB3, TB15 |
| TM-X4 | **Malicious or compromised technician** | Valid console account with a role and a delegation scope | Escape the scope; escalate their own RBAC; harvest LAPS/BitLocker secrets; act without trace | TB1, TB2 |
| TM-X5 | **Compromised activeDIQ administrator** (`tenant-owner`) | Full tenant-scope RBAC through the API | Use activeDIQ to reach Tier 0. **Goal of this model: they still cannot** (TM-O1) | TB1, TB2, TB3, TB7 |
| TM-X6 | **Code execution on the server host** (or a host administrator) | Process memory, config, keytab, KEK provider access as the service | Directory credentials, DEKs, audit tampering | TB4, TB5, TB16 |
| TM-X7 | **SaaS cell insider or cell compromise** [SaaS] | skenzeriq operations access or code execution in the cell | Every tenant's Entra certificate and data | TB17, TB5, TB7 |
| TM-X8 | **Supply chain** — a dependency, CI, a signing key, the update channel | Code into our build or our updates | Code execution in every customer, the SolarWinds pattern ([AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)): a malicious DLL entered the build and was signed with the vendor's own code-signing certificate | TB10, TB14, TB16 |
| TM-X9 | **Rogue enrolled connector or agent host** | Owns a host with a valid fleet certificate | Read or influence another tenant; feed false data; receive secrets | TB6, TB12 |
| TM-X10 | **Compromised edge** [M4] | Full control of the `edge` process and its host | Pivot inward through the tunnel; read SSPR traffic | TB11 |
| TM-X11 | **Another tenant** [SaaS] | A valid tenant of the same cell | Cross-tenant read, write or credential use | TB17, TB4, TB6 |
| TM-X12 | **Compromised integration peer** — IdP, HR source, ITSM, SIEM, SMTP/SMS gateway, [M4] RADIUS client (VPN concentrator or other NAS, often internet-facing) | Controls a system we trust for input or send data to; a RADIUS client holds a valid shared secret | Forge sign-ins (IdP); drive provisioning (HR); create requests (ITSM); read what we send; guess passwords and OTPs through RADIUS | TB8, TB9, TB19 |
| TM-X13 | **Compromised or hostile migration source** — a ManageEngine server, its database, or an export file handed to us | Controls the bytes our importers parse and the results our comparator reads | Code execution through a parser or an imported script; escalation through imported roles; false parity results | TB18 |

---

## 4. System model and trust boundaries

### 4.1 Self-hosted (`windows`, `linux-oci`)

Same roles and binaries in both profiles; only adapters differ (BP §3.3). Numbers in brackets are
the trust boundaries of §4.3.

```
 Admins / technicians        Scripts, ITSM, [M3] PowerShell/MCP     End users: v1 TOTP enrolment page;
   (browser)  [TB1]               [TB2]                              [M4] SSPR, credprov [TB13]
        | HTTPS                     | HTTPS + API token                   | internet: only via edge
        v                           v                                     v
+--------------------- customer server host (never a DC) [TB16] ----+   +--- DMZ host -----------+
|  cmd/server (Windows service under gMSA / non-root container)      |   | cmd/edge [M4] alone    |
|   apihost: console/API listener   fleet gRPC listener [TB6/TB12]   |<==| [TB11] no creds, no DB |
|   [M4] edge tunnel client [TB11]: dials OUT ---------------------->|==>| L7 TLS, schema checks  |
|   [M4] radius UDP listener <-- customer NAS / VPN [TB19]           |
|   modules -> platform kernel (authn, authz, audit, keys, jobs)     |   +------------------------+
|   migration importer, scanner, comparator <-- ADMP source [TB18]   |
|   embedded connector: provider/ad, provider/entra, custody         |
|   sidecars [M3] over stdio [TB14]                                  |
+----+-------------+---------------+-------------+------------+------+
     |             |               |             |            |
 [TB3] LDAPS /  [TB7] HTTPS    [TB4] SQL     [TB5] key     [TB9] SMTP, SMS, SIEM, ITSM, HR/DB,
 Kerberos+CBT;  Graph + token  + blob        provider      [M3] webhooks; [TB8] IdP (SAML/OIDC)
 SMB (ADM-023)  endpoint         |             |           [TB15] exports, backups, SIEM stream
     v             v             v             v           [TB10] update courier (online/offline)
+-----------+  +----------+  +-----------+  +-----------------------+
| Domain    |  | Entra ID |  | PostgreSQL|  | DPAPI-NG / TPM / TPM2 |
| controllers| | / Graph  |  | + blob fs |  | KMS / Vault / passphr.|
| [M3] agent |  +----------+  +-----------+  +-----------------------+
|  --fleet--> server [TB12]; [M4] passfilt --pipe--> agent [TB12]
+-----------+
 Optional remote cmd/connector (other forest, DMZ, branch, redundancy) dials OUT to fleet [TB6]
 [M3] File servers: cmd/agent + fileserver module dials OUT to fleet [TB12]
```

### 4.2 SaaS (designed, CI-only; not shipped in v1)

```
+--------------------------- skenzeriq cell (per region) [TB17] -------------------------+
|  N x cmd/server (stateless) + embedded connector: provider/entra ONLY (P1)             |
|  KMS (per-tenant DEK wrap, tenant encryption context) [TB5]   managed PostgreSQL [TB4] |
|  edge (ours) [TB11]                                                                    |
+------------^------------------------------------------------^--------------------------+
             | mTLS, dialled OUT by the customer [TB6/TB12]    | HTTPS Graph [TB7]
+------------+---------------- customer site ---------------+  +-----------------+
| cmd/connector (provider/ad), gMSA or keytab; AD creds      |  | Entra ID / Graph|
|   stay here; computes tier0 locally (TM-D2)                |  +-----------------+
| [M3] cmd/agent on DCs                                      |
+------------------------------------------------------------+
```

### 4.3 Trust boundaries

| TB | Boundary | Crosses | Protocol and authentication | Milestone |
| --- | --- | --- | --- | --- |
| TB1 | Browser ↔ server | Technicians, admins; end users on the v1 TOTP enrolment page (DM-04 hostname binding) | HTTPS (TLS from first boot); SSO/OIDC/SAML + MFA; `__Host-` session cookie | v1 |
| TB2 | API / automation clients ↔ server | Scripts, ITSM inbound, [M3] PowerShell module, MCP | HTTPS; API token (ADM-141) | v1 (+M3) |
| TB3 | Connector ↔ DC | LDAP reads/writes, password sets, SMB for home folders (ADM-023), later MS-RPC | LDAPS or StartTLS with verification; SASL GSSAPI (Kerberos) + signing + channel binding; Kerberos-only SMB | v1 |
| TB4 | Server ↔ PostgreSQL and blob store | All state | pgx over TLS; runtime role ≠ owner; RLS; tenant-prefixed blob keys | v1 |
| TB5 | Server ↔ key provider | KEK unwrap of DEKs | OS API (DPAPI-NG, TPM), KMS/Vault over TLS, passphrase keystore | v1 |
| TB6 | Remote connector ↔ server `fleet` | Connector operations multiplexed over a connector-initiated stream; enrollment | gRPC over mTLS dialled out by the connector; tenant + component in certificate SAN; single-use enrollment token | v1 |
| TB7 | Connector ↔ Graph and the Entra token endpoint | Entra reads/writes | HTTPS; app-only certificate credential (client assertion) | v1 |
| TB8 | Server ↔ customer IdP | Console SSO | SAML 2.0 or OIDC; signed assertions/ID tokens | v1 |
| TB9 | Server → outbound integrations | SMTP, SMS, SIEM, ITSM (both directions), HR/DB sources, [M3] webhooks | TLS; sealed per-integration credentials; SSRF guard | v1 (+M3) |
| TB10 | Update channel | Release manifests and artefacts, online courier and offline bundle | TUF-style signed metadata; Authenticode, container signatures | v1 |
| TB11 | Internet ↔ edge, and server → edge tunnel | SSPR end-user flows | Public TLS at edge; mTLS tunnel dialled out by the server | M4 |
| TB12 | DC agent and file-server agent ↔ `fleet`; passfilt ↔ agent | Event collection, policy, password checks; file-server ACL reads and writes (`fileserver` module) | mTLS dial-out (agent); local named pipe ACL'd to the agent's service SID (passfilt) | M3 / M4 |
| TB13 | Credential provider (LogonUI) ↔ SSPR API | Forgot-password at the logon screen | Pinned TLS, through edge or direct | M4 |
| TB14 | Sidecars ↔ launcher | `sidecars/exchange`, `sidecars/gpmc` | stdio typed messages, constant argv (FF-SP8/SP9) | M3 / FD-04 |
| TB15 | Data leaving | Exports, scheduled report delivery, audit export, DB backups (ADM-158), SIEM stream | Encoders (T-0029); delivery via TB9; backup files on the host | v1 |
| TB16 | Host and installer | MSI/OCI install, service identity, file ACLs on config, keytab and keys; host admins | OS ACLs; Authenticode; container user | v1 |
| TB17 | SaaS cell | Tenant ↔ tenant; operations staff ↔ tenant data; cell ↔ on-site connector | RLS, KMS policy, break-glass access, fleet mTLS | SaaS (not v1) |
| TB18 | ManageEngine source ↔ `migration` (importers, discovery scanner, parallel-run comparator) | ADMP export files and, second, a read-only ADMP database or API read; AD reads for discovery | Uploaded files over TB1; DB/API over TLS through the egress client with a sealed read-only credential, Kerberos-only for Windows authentication | M2 (ENH-02, E2.11) |
| TB19 | RADIUS clients (VPN, NAS) ↔ `radius` | Network-access authentication: password and OTP checks | UDP RADIUS with a per-client shared secret and mandatory `Message-Authenticator`; RADIUS/TLS preferred | M4 |

**Not modelled in v0.** `fpolicy` [M5] (BP §3.1; NetApp FPolicy for NAS auditing) and `t0-connector` [post-v1, FD-11]. Each is out of scope for this version. Specifying either is an RT-6 trigger (§14): it adds its boundary, STRIDE table and §8.1 line before build.

---
## 5. STRIDE per trust boundary

One table per boundary. **STRIDE**: S spoofing · T tampering · R repudiation · I information
disclosure · D denial of service · E elevation of privilege. Each row names the attacker (§3), the
asset (§2), the control, the proof that must exist (§15) and what is left over. A control without a
proof is direction, not a control; the proof table says which ticket builds each one.

### 5.1 TB1 — Browser ↔ server (console; v1 end-user TOTP enrolment page)

| ID | STRIDE | Threat (attacker → asset) | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB1-T1 | S | X1/X4 phish or stuff console credentials → A4 | SSO (OIDC preferred, SAML) and MFA for every console user; WebAuthn/passkeys preferred, TOTP allowed; local accounts only for break-glass, always MFA, alert on use (§7) | TM-F-SSO, TM-F-SESSION | Real-time phishing proxies beat TOTP; WebAuthn resists them |
| TM-TB1-T2 | S | X2 signs in with a default account or sniffs first-run HTTP (the competitor shipped `admin`/`admin`, ME-SEC §4.1 Rapid7 note) → A4 | TLS from first boot with a per-install generated certificate whose fingerprint is shown; one-time setup secret; no default account (DM-30.I3, ADM-145) | TM-F-HOST | Admin ignores the fingerprint on first connect |
| TM-TB1-T3 | T | X1 forges a state-changing request from another site (CSRF) → A1 | `SameSite=Strict` cookie, CSRF token on every mutation, strict `application/json` only | TM-F-SESSION | — |
| TM-TB1-T4 | T/E | X3 writes script into an attribute they control; an admin views it (stored XSS) → admin session | Framework auto-escaping; no `dangerouslySetInnerHTML` (FF-SP3, ESLint `react/no-danger`); CSP without `unsafe-inline`; output encoders (T-0029) | FF-SP3, T-0029 encoder corpus | Low |
| TM-TB1-T5 | R | X4 denies having made a change → A5 | Audit in the same transaction: actor, session, factor, client IP, operation ID (§11) | TM-F-AUDIT | — |
| TM-TB1-T6 | I | X1/X3 steals a session token (script, logs, URL) → A4 | `__Host-` cookie, `HttpOnly`, `Secure`; tokens never in URLs; session ID stored hashed (DM-31); HSTS | TM-F-SESSION | — |
| TM-TB1-T7 | I | X4 reads a secret from an API response (the CVE-2022-24978 pattern, ME-SEC §4.1) → A2, A7 | Secret fields write-only in the OpenAPI schema; response linter; LAPS/BitLocker only through the reveal endpoint with step-up (§7) | TM-F-SECRETOUT | — |
| TM-TB1-T8 | I | X4 sees objects outside their scope in search, reports or counts → A6 | RBAC trimming in queries; counts and pages after authorisation (SP LF-39); report compiler injects scope (BP §10) | TM-F-AUTHZ, FF-SP4 | — |
| TM-TB1-T9 | D | X3 locks AD users out through AD-identity sign-in or the enrolment page | Our per-account failure counter stops below the domain lockout threshold; per-IP limits; generic errors (SB §6) | TM-F-ABUSE | Domain threshold 0 or very low: we refuse AD sign-in rather than risk lockouts |
| TM-TB1-T10 | D | X4 exhausts the server with huge bodies or bulk jobs | Body-size caps, per-principal rate limits, job quotas, per-DC concurrency | T-0046 API fitness (limits declared per operation) `[OPEN → T-0046]` | — |
| TM-TB1-T11 | E | X4 grants themself a stronger role (the CVE-2024-24409 class, ME-SEC §4.1; DM-36.I1) → A1 | No-escalation rule: a grantor must hold every privilege of the role over the whole scope; role and scope changes need step-up and are audited | TM-F-AUTHZ | — |
| TM-TB1-T12 | E | X4 acts on an object just outside their OU, or moves it between check and write → A1 | Authorisation on the **target**, server-side, per bulk item; Plan re-reads the live parent chain (BP §11, DM-35.I2) | TM-F-AUTHZ | — |
| TM-TB1-T13 | S | X3 enrols a TOTP factor for a victim on the v1 enrolment page, then passes caller verification (ENH-09) and gets the victim's password reset → A12, A1 | Enrolment requires the end user's own AD authentication (connector `VerifyUser` or SPNEGO); re-enrolment requires the existing factor or a technician-verified reset; every enrolment notifies contact data already held and is audited `[OPEN → ENH-09 spec]` with this constraint | TM-F-ABUSE | An attacker who already has the user's password can enrol first; the notice shortens the window |

### 5.2 TB2 — API and automation clients ↔ server

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB2-T1 | S | X1 guesses or X4 steals an API token → A4 | CSPRNG ≥ 128 bits; prefix `adq_` so secret scanners find leaks; stored hashed; expiry mandatory; scoped; shown once; owner and `last_used` recorded (DM-32, ADM-141) | TM-F-SESSION | Token leaked in a script repository is valid until expiry or revocation |
| TM-TB2-T2 | S/E | X1 reaches an operation without authentication (CVE-2021-40539, CVE-2026-75791 class, ME-SEC §4.1, §4.3 "REST API authentication") | Deny-by-default router; every operation declares `x-permission`; a route without one fails startup; anonymous routes = reviewed allow-list (§7.6) | TM-F-ANON, T-0046 API fitness | — |
| TM-TB2-T3 | T | X4 smuggles fields (mass assignment) or a tenant ID | Strict JSON, unknown fields rejected; generated handlers; no `tenant_id` in any tenant-scope operation (ADR-0002 T5) | T-0046, T5 | — |
| TM-TB2-T4 | T | X4 injects LDAP/SQL/PowerShell through API input → A1 | Safe primitives only (SP P1–P5) | FF-SP1–SP9 | — |
| TM-TB2-T5 | R | Script actions cannot be traced to a person | Token has an owner; audit actor chain records principal + token + automation policy (DM-80) | TM-F-AUDIT | — |
| TM-TB2-T6 | I | Token in a URL, query string or log line | `Authorization` header only; query-string credentials rejected; log redaction | TM-F-SECRETOUT | — |
| TM-TB2-T7 | D | X4 floods the API or the DCs through automation | Per-token rate limits; bulk caps; per-DC concurrency | T-0046 `[OPEN → T-0046]` | — |
| TM-TB2-T8 | E | A token outlives or exceeds its owner's authority | Effective = owner's current authority ∩ token subset; a disabled owner kills the token (DM-32.I1) | TM-F-AUTHZ | Within sync freshness for directory-group-based roles (DM-36.I2) |
| TM-TB2-T9 | E | X12 (ITSM) creates a direct directory write | An inbound ticket creates only a Request, which goes through approval (DM-85.I1); writes only via `Action.Apply` | T-0047 operation fitness | — |
| TM-TB2-T10 | E | [M3] PowerShell module or MCP server adds a second auth path | They are clients of the same OpenAPI operations with the same token model; no private endpoint `[OPEN → M3 specs]` | TM-F-ANON (route set unchanged) | — |

### 5.3 TB3 — Connector ↔ domain controllers

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB3-T1 | S | X2 impersonates a DC (DNS spoofing, rogue host) → A7 passwords sent to it | LDAPS/StartTLS with chain verified to configured trust anchors and hostname = the DC's `InventoryHost` FQDN; no downgrade, ever (SP §5.6, PW-18); Kerberos mutual authentication | FF-SP4 (PW-10, PW-17, PW-18) | — |
| TM-TB3-T2 | S/E | X3 plants `\\attacker\share` in `homeDirectory`/`profilePath`/`gPCFileSysPath`; X2 coerces and relays our identity (CVE-2022-29457, CVE-2025-11670 class, ME-SEC §4.1) → A1 | Kerberos-only outbound (TM-D10); connection targets only from `InventoryHost` (SP §6.3); LDAP signing + channel binding | TM-F-NTLM, FF-SP4 (PROC-14, PROC-17) | — |
| TM-TB3-T3 | T | X2 alters LDAP traffic in flight | TLS; SASL signing; channel-binding token on every SASL bind over TLS (FEAS §2.4) | T-0023 acceptance (binds succeed with signing + CBT "Always"; no events 2887, 3039, 3074/3075) | — |
| TM-TB3-T4 | T/E | X4 widens a search or write with filter or DN injection → A1, A6 | Filter AST and DN builder (SP P1, P2); base = delegation root `GUIDRef`; escape controls only in named operations (SP §3.6) | FF-SP1–SP6 | — |
| TM-TB3-T5 | R | AD's own logs show the connector, not the technician (ADM-134) | Our audit records technician + factor + operation ID; [M3] DC events correlated to the operation (TM-D6) | TM-F-AUDIT; [M3] correlation test in T-0040 | Native AD logs alone do not name the technician (§6.7) |
| TM-TB3-T6 | I | Secret attributes (LAPS, BitLocker, `unicodePwd`, …) reach inventory, search or reports → A7 | `SecretAttrs` computed from schema + static list; stripped before leaving the connector; `ReadSecret` only, never cached (SP §3.7) | FF-SP4 (LF-22, LF-34, LF-35, LF-37, LF-38) | — |
| TM-TB3-T7 | I | A password crosses an unencrypted connection → A7 | `SecureConn` required by `unicodePwd.Replace/Change`; fail before send (SP §5.6) | FF-SP4 (PW-10) | — |
| TM-TB3-T8 | D | Our traffic locks accounts or overloads DCs | Paged reads; per-DC concurrency; change feed instead of full scans; our lockout counter (TM-TB1-T9) | TM-F-ABUSE; performance budgets (engineering-standards §7) | — |
| TM-TB3-T9 | D/I | A referral or partial page is shown as a complete result | Referrals are errors, never chased (SP LF-32) | FF-SP4 | — |
| TM-TB3-T10 | E | X5 or a compromised server asks the connector to write a `tier0` object → forest | Tier-0 guard twice: Action Plan against a live re-read, **and** inside the connector, which computes `tier0` for its own forest and refuses `Apply` (TM-D2) | TM-F-T0GUARD | — |
| TM-TB3-T11 | E | The customer delegates too much (Domain Admin, GenericAll on the domain) → activeDIQ becomes Tier 0 | Onboarding refuses to activate; explicit, audited override with a permanent banner; health check reports excessive and missing rights (TM-D1, §6.5) | TM-F-RIGHTS | Customer overrides; then O1 no longer holds and the product says so |
| TM-TB3-T12 | T | Home-folder creation (ADM-023) writes a bad ACL or dials an attacker host | File server must be an `InventoryHost`; ACLs via the typed security-descriptor primitive (T-0028); Kerberos-only SMB | T-0028 golden tests, FF-SP4 (PROC-14) | — |

### 5.4 TB4 — Server ↔ PostgreSQL and blob store

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB4-T1 | S | X2 impersonates a remote PostgreSQL | A DSN to a non-loopback host requires TLS with full verification; configuration refuses weaker modes | TM-F-HOST | — |
| TM-TB4-T2 | T | SQL injection (the competitor's report-SQLi cluster, ME-SEC §4.3) → A6, A5 | sqlc only; `reportsql` is the only dynamic SQL, identifiers from a pre-quoted registry (BP §10, SP P5) | FF-SP1, FF-SP2 (`sqlconst`), FF-SP3, FF-SP7 | — |
| TM-TB4-T3 | T | Application code edits or deletes audit rows → A5 | Runtime role has INSERT only on audit tables (no UPDATE, DELETE, TRUNCATE) | TM-F-AUDIT, T3 | — |
| TM-TB4-T4 | R | A database administrator rewrites rows directly | Hash chain + signed checkpoints anchored outside the host (§11) | TM-F-AUDIT | Unanchored tail (§11) |
| TM-TB4-T5 | I | X11 reads another tenant's rows (RLS bypass) → A6 | "Where tenancy lives" rules: RLS + FORCE, composite FKs, tenant-led unique indexes, no `SECURITY DEFINER`, `security_invoker` views | T1–T5 | — |
| TM-TB4-T6 | I | X6 steals a dump or backup → A2, A12 | Only ciphertext of secrets in the database; KEK never in the database; AEAD with associated data (TM-D7) | TM-F-SEAL | PII in inventory is readable (TM-TB15-T4) |
| TM-TB4-T7 | T | X6 with DB write copies a sealed Entra key from tenant A's row into tenant B's → B's jobs sign as A | Associated data binds tenant, table, row, column and key version (TM-D7) | TM-F-SEAL | — |
| TM-TB4-T8 | I | Blob objects read across tenants | Keys prefixed by tenant through `platform/blob` only | Blob isolation probe `[OPEN → T-0036 adds it to T4]` | — |
| TM-TB4-T9 | D | Database unavailable mid-operation | Writes fail closed: no directory write without its audit row in the same transaction (§11); leases expire | T-0047 operation fitness | Availability |
| TM-TB4-T10 | E | The runtime role owns objects or has `BYPASSRLS` | Separate owner role for migrations | T3, FF-SP7 | — |

### 5.5 TB5 — Server ↔ key provider

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB5-T1 | S | Another local process asks the provider to unwrap the KEK → A3 | DPAPI-NG descriptor bound to the service identity (gMSA SID) `[UNVERIFIED — Windows lab]`; KMS/Vault policy grants unwrap only to the workload identity; TPM2 sealed to the service | TM-F-HOST | A host administrator can always run as the service (TM-R4) |
| TM-TB5-T2 | T | An attacker substitutes the KEK or a wrapped DEK | Wrapped DEKs are authenticated (AEAD); `kek_ref` pinned per DEK version (DM-02) | TM-F-SEAL | — |
| TM-TB5-T3 | R | KEK use leaves no trace | KMS profiles: the provider's audit log (e.g. CloudTrail) records every unwrap; all profiles: DEK unwrap count metric per tenant | §13; metric test in `keys` | Local providers (DPAPI-NG, TPM) give no independent log |
| TM-TB5-T4 | I | Passphrase or KEK material written beside the data | Passphrase keystore unlocks from operator input or the OS secret store, never from the config file or database | TM-F-HOST | — |
| TM-TB5-T5 | D | Provider unavailable or TPM cleared → nothing can be unsealed | Fail closed (no directory operations); documented KEK recovery path `[OPEN → E2.12 PRD]` | P2 boot test (missing provider = clear error, no plaintext fallback) | Availability; lost KEK means re-entering credentials |
| TM-TB5-T6 | E | Code outside the connector unseals a directory credential | Only `credential/sealed` under the connector root unseals directory credentials | P3 | — |

### 5.6 TB6 — Remote connector ↔ server `fleet`

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB6-T1 | S | X9 enrols a rogue connector with a stolen or guessed token → A11 | Enrollment token single-use, short-lived, stored hashed, rate-limited, issued only by a permission holder after step-up (DM-12.I2, §7.4) | TM-F-FLEET | Token stolen inside its lifetime and used first |
| TM-TB6-T2 | S | X2 impersonates the server to a connector | The connector pins the installation CA from its enrollment bundle and verifies the server certificate | TM-F-FLEET | — |
| TM-TB6-T3 | T | A message body names another tenant | Tenant only from the certificate SAN, never the message (ADR-0002) | P4 | — |
| TM-TB6-T4 | T/E | A compromised server sends hostile operations to an on-site connector | Typed contract only, no query or script verb (ADR-0002 rule 3); connector-side tier-0 guard (TM-D2) | P3, TM-F-T0GUARD | A compromised server can still do what the delegated rights allow (TM-R1) |
| TM-TB6-T5 | R | A connector acts with no server-side record | Every `Apply` carries the operation ID and acting principal; connector logs them locally; server audit (§11) | TM-F-AUDIT | — |
| TM-TB6-T6 | I | Secrets pushed over fleet to a remote host | Nothing secret is ever pushed; remote credentials are created on the host (TM-D8); the fleet contract has no secret-bearing message type except `SetPassword`/`ReadSecret` payloads of an operation | TM-F-FLEET (contract lint) | — |
| TM-TB6-T7 | D | Flood in either direction | Per-component stream limits and backpressure `[OPEN → connector spec]` | Conformance suite (P3) | — |
| TM-TB6-T8 | E | A connector certificate reaches non-fleet APIs | The fleet listener mounts only fleet services; console/API routes are not on it; every RPC except `Enroll` requires a client certificate | TM-F-FLEET, TM-F-PORTS | — |
| TM-TB6-T9 | E | A revoked connector keeps working | Revocation is checked on every stream (re)establishment and kills open streams (DM-12 lifecycle) | TM-F-FLEET | — |

### 5.7 TB7 — Connector ↔ Graph and the Entra token endpoint

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB7-T1 | S | X6 steals the Entra certificate key and signs in as the app from anywhere → A2 | Key generated by activeDIQ; sealed under the DEK with associated data (TM-D7); on a remote host generated there, non-exportable where possible (TM-D8); expiry and rotation surfaced (DM-11) | TM-F-SEAL | Theft while unsealed in memory; customer may restrict the app's sign-in locations in Entra `[OPEN → ADM-159 spec]` |
| TM-TB7-T2 | T | X2 intercepts Graph traffic | System trust store; TLS verification bypasses banned | FF-SP2 | — |
| TM-TB7-T3 | E | The app is consented with more than it needs (`Directory.ReadWrite.All`, `RoleManagement.*`) → Entra Tier 0 | Allow list + deny list (§6.6); onboarding reads the service principal's granted app roles and refuses or flags extras | TM-F-RIGHTS (Entra half) | Customer consents extras and overrides (as TM-D1) |
| TM-TB7-T4 | E | X5 uses the app to touch privileged Entra users or role-assignable groups | The app holds **no Entra directory role**; Graph's own protections apply (§6.6); our guard treats privileged-role holders as `tier0` | TM-F-T0GUARD (Entra half) | — |
| TM-TB7-T5 | R | Entra audit shows only the app | Our audit names the technician; operation ID in our record | TM-F-AUDIT | As TM-TB3-T5 |
| TM-TB7-T6 | D | Graph throttling stalls jobs | Honour `Retry-After`, backoff, per-tenant concurrency | P3 conformance (fake Graph) | — |
| TM-TB7-T7 | S | [SaaS] a job of tenant A authenticates with tenant B's certificate | Unseal only inside the tenant's own `WithTenantTx` | P4 | — |
| TM-TB7-T8 | S/E | An Entra admin stamps an AD admin's `objectGUID` as `onPremisesImmutableId` on a cloud-only user, signs in by SSO and inherits that admin's AD-side grants (forged anchor) → A1 | Only `matched` correlations authorise; the gate needs `onPremisesSyncEnabled = true` (read-only in Graph) and the SID to equal `objectSid` (DM-20.I4 a–e; TM-D17) | TM-F-HYBRID | — |
| TM-TB7-T9 | S/E | Takeover through hard or soft match: a pre-created cloud user is taken over when its target enters sync scope, and keeps the attacker's sign-in methods → A1 | (f): both tenant blocking flags, attested by a Global Administrator and watched in the directory audit; eligibility only goes down (g); `tenant-owner` and RBAC administration never cross a correlation (h) (TM-D17) | TM-F-HYBRID | Takeovers before install or in the install-time population (TM-R11) |
| TM-TB7-T10 | T/E | After an SOA transfer (`isCloudManaged`) the on-premises attributes, the SID included, become admin-writable → a forged match | Gate (b) and (a); the object is once-cloud-managed, so it needs re-confirmation (g) | TM-F-HYBRID | — |
| TM-TB7-T11 | E | A technician resets the AD password of a synced user who holds an Entra role, and password hash sync hands over that role | C16: an AD object correlated to an Entra `tier0` principal is `tier0`, whatever the correlation state; ENH-08 reports synced role holders | TM-F-T0GUARD, TM-F-HYBRID | — |
| TM-TB7-T12 | E | Whoever controls the sync client, the tenant sync features or SOA transfer passes every check | Tier 0 by designation (§6.4, E4); activeDIQ holds no permission for any of them (§6.6 deny list) | TM-F-RIGHTS (deny list) | **Accepted** (TM-R11): outside what the gate can defend |
| TM-TB7-T13 | S/E | A correctly `matched` correlation is used by whoever can sign in as the synced technician in Entra (TAP, method reset, federation) | See TM-TB8-T8 (TM-D19) | TM-F-HYBRID | TM-R12 |

### 5.8 TB8 — Server ↔ customer IdP

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB8-T1 | S | X1 forges a SAML assertion through signature wrapping or a stale XML-DSig library (CVE-2022-47966, ME-SEC §4.1, §4.3) | OIDC preferred; SAML in one package with a vetted, maintained library (licence register first), algorithm pinned, signed assertion required, wrapping fuzz corpus; Go `encoding/xml` has no external entities (the XXE lesson of CVE-2022-28219, ME-SEC §4.1) | TM-F-SSO | Library zero-day; SBOM + scanning shorten the window |
| TM-TB8-T2 | S | Replay of a captured assertion or ID token | `InResponseTo`/`state`, `nonce`, PKCE; one-time assertion-ID cache; audience, issuer, expiry and clock-skew checks | TM-F-SSO | — |
| TM-TB8-T3 | T | X5 or X6 swaps IdP metadata or signing certificate → A13 | Changes need step-up, are audited, alert all `tenant-owner` accounts | TM-F-SESSION (step-up list), TM-F-AUDIT | — |
| TM-TB8-T4 | R | SSO sign-ins not attributable | Audit records issuer, subject, session and factors claimed | TM-F-AUDIT | — |
| TM-TB8-T5 | I | Raw assertions or tokens in logs | Never logged; only issuer + subject | TM-F-SECRETOUT | — |
| TM-TB8-T6 | D | IdP outage locks every admin out | Break-glass local accounts with MFA and alert on use (ADM-142) | TM-F-SESSION | — |
| TM-TB8-T7 | E | IdP group claims grant roles; a compromised IdP (X12) signs anyone in | Claim-to-role mappings are explicit tenant configuration, audited; `tenant-owner` never granted by a claim alone `[OPEN → ADM-143 spec]` | TM-F-AUTHZ | A compromised IdP gets console access within RBAC — still not Tier 0 (TM-O1) |
| TM-TB8-T8 | S/E | An Entra role that controls the **authentication plane** signs in as a synced technician bound by `oid` or `onprem_sid` and inherits the AD-side group grants of a legitimately `matched` correlation (DM-20.I6): a Privileged Authentication Administrator or Authentication Administrator issues a TAP or resets methods; an Authentication Policy Administrator lets TAPs be used; a Hybrid Identity Administrator federates the domain. Also the history case: an object taken over while the takeover flags were off keeps the attacker's methods | The Entra sign-in alone never carries AD-side authority: correlation-derived AD grants need an activeDIQ-held authority factor enrolled with an AD-plane proof (TM-D19, §6.9); console-backing objects are escalation objects | TM-F-HYBRID (TM-D19 cases) | Someone who controls both planes at enrolment (TM-R12) |

### 5.9 TB9 — Server → outbound integrations (SMTP, SMS, SIEM, ITSM, HR/DB, [M3] webhooks)

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB9-T1 | I/E | X5 points an integration URL at loopback, link-local, a cloud metadata endpoint or an internal service (SSRF) | One egress client for every integration: resolve, then refuse loopback, link-local, metadata and private ranges unless the installation operator allow-lists them; connect to the resolved IP (no DNS rebinding); no redirect to a disallowed host (SB checklist F) | TM-F-EGRESS | Allow-listed internal ranges remain reachable by design |
| TM-TB9-T2 | I | Our identity authenticates to an attacker-chosen HTTP endpoint (NTLM via HTTP) | No HTTP client does integrated Windows authentication (TM-D10) | TM-F-NTLM | — |
| TM-TB9-T3 | S | X12 spoofs an HR feed or ITSM callback | Inbound ITSM authenticated by API token or signature and only creates Requests (DM-85.I1); HR/DB pulled by us over verified TLS | TM-F-EGRESS, T-0047 | — |
| TM-TB9-T4 | T | X12 (HR) drives mass leaver actions | Lifecycle policies run through Plan, approvals and per-run change-volume limits `[OPEN → E2.9 lifecycle spec]` | T-0047 operation fitness | A believable HR change still flows if within limits |
| TM-TB9-T5 | I | Integration credentials returned or logged | Sealed, write-only, never returned (DM-82.I1, DM-63, DM-85) | TM-F-SECRETOUT, TM-F-SEAL | — |
| TM-TB9-T6 | I | A new password travels in a notification | Default: no password in any notification; any "deliver initial password" feature needs its own security review `[OPEN → E2.5 helpdesk spec]` | TM-F-SECRETOUT | OTP codes are sent by design (they are the factor) |
| TM-TB9-T7 | R | Deliveries cannot be proven | Delivery outcome recorded and audited (BP §14 flow 4) | TM-F-AUDIT | — |
| TM-TB9-T8 | D | A slow peer ties up workers | Timeouts, bounded retries with backoff, per-destination concurrency | TM-F-EGRESS | — |
| TM-TB9-T9 | T | [M3] webhook receivers spoofed or payloads altered | Standard Webhooks signatures, rotatable secrets, payloads without secrets (SB checklist F) | TM-F-EGRESS | — |
| TM-TB9-T10 | S | SIM swap or mailbox takeover intercepts an OTP | TOTP preferred over SMS/email; factor recorded in the audit event (DM-38.I4) | TM-F-AUDIT | Residual for SMS/email factors |

### 5.10 TB10 — Update channel (online courier, offline bundle)

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB10-T1 | S/T | X8 serves a malicious update from a compromised mirror or CDN → every customer | TUF-style signed metadata verified **before** unpacking; Authenticode and container signatures; one verifier for both couriers (§10) | TM-F-UPDATE, P5 | — |
| TM-TB10-T2 | T | Rollback to a vulnerable signed version | Monotonic version persisted per install | TM-F-UPDATE | — |
| TM-TB10-T3 | T | Freeze: stale metadata hides a security release | Timestamp role with short expiry | TM-F-UPDATE | — |
| TM-TB10-T4 | E | X8 steals a signing key | Offline root with threshold signatures; targets key in HSM/KMS (T-0027); key rotation through root | TM-F-UPDATE (key-rotation case) | A build-system compromise signs legitimately (SolarWinds, [AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)); provenance and reproducible builds reduce it (TM-R6) |
| TM-TB10-T5 | E | A compromised server pushes its own code to agents | Agents accept only artefacts signed by the release root, never server-signed code (TM-D12) | TM-F-UPDATE | — |
| TM-TB10-T6 | D | A bad update breaks the fleet or DCs | Rings, windows, pinning; health check and automatic rollback; DC components never auto-update without explicit approval by default | P2 upgrade tests; ENH-07 spec | — |
| TM-TB10-T7 | R | Nobody knows who applied what | Platform audit events for stage, apply, rollback | TM-F-AUDIT | — |
| TM-TB10-T8 | I | Update checks leak installation data | No mandatory egress (P6); the courier sends only what the ENH-07 spec lists `[OPEN → ENH-07 spec]` | P6 | — |
| TM-TB10-T9 | E | The OCI apply path gets Docker-socket access | Forbidden (BP §14 flow 6) `[OPEN → ENH-07 spec]` | ENH-07 spec test | — |

### 5.11 TB11 — Internet ↔ edge, and server → edge tunnel [M4]

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB11-T1 | S | X1 enumerates accounts by response or timing | Same body, status and timing class whether or not the account exists (SB checklist A) | TM-F-ABUSE | — |
| TM-TB11-T2 | S | X1 brute-forces OTPs (the CVE-2022-36413 class, ME-SEC §4.1) | Per-account attempt limits enforced **server-side**; OTP single-use and short-lived | TM-F-ABUSE | — |
| TM-TB11-T3 | E | X10 pivots from edge to admin APIs | The tunnel lands on a separate router instance that mounts only the SSPR route group; admin and API routes are not mounted there (structural, not path filtering) (TM-D11) | TM-F-EDGE | — |
| TM-TB11-T4 | I | X10 reads SSPR plaintext (new passwords, OTPs) while edge is compromised | MFA; short OTP lifetime; immutable signed edge image | TM-F-EDGE | **Accepted** (TM-R5): an L7 edge sees SSPR plaintext |
| TM-TB11-T5 | T | X10 alters requests or lies about client IPs | Schema validation at edge and server; per-account limits authoritative on the server; edge-reported IP advisory only | TM-F-EDGE, TM-F-ABUSE | — |
| TM-TB11-T6 | D | Lockout campaign or flood through the portal | Server counter below the domain lockout threshold; CAPTCHA fallback; edge rate limits (advisory) | TM-F-ABUSE | Volumetric DDoS needs the customer's front door |
| TM-TB11-T7 | S | A fake edge or a fake server on the tunnel | mTLS both ways, both pinned to the installation CA; the server dials out | TM-F-EDGE | — |
| TM-TB11-T8 | R | SSPR actions unattributable | Audit with factors, user, advisory source IP | TM-F-AUDIT | — |
| TM-TB11-T9 | E | Pre-auth bug in edge request parsing | Edge holds nothing worth stealing (no directory credential, tenant key or database); memory-safe Go; fuzzed decoders | TM-F-EDGE, FF-SP5 | — |

### 5.12 TB12 — DC agent and file-server agent ↔ `fleet` [M3]; password filter ↔ agent [M4]

Rows T1–T9 cover the `addc` module on DCs and the password filter. Rows T10–T15 cover the
`fileserver` module on file servers (BP §5.5, §13). A compromised server can send commands to
both kinds of agent, so both command sets are closed (TM-D13).

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB12-T1 | S | X9 enrols a rogue agent or clones an agent identity | As TB6: single-use token, certificate per DC, tenant + component in SAN | TM-F-FLEET | — |
| TM-TB12-T2 | S | A rogue server commands an agent | The agent pins the installation CA and accepts commands only from its server (SB checklist D) | TM-F-FLEET | — |
| TM-TB12-T3 | E | A compromised server runs code on a DC through the agent → forest | Closed command set with no code execution, no file write outside the data directory, no service/registry configuration, no update outside the release-signed channel (TM-D13) | TM-F-AGENTCMD, TM-F-UPDATE | — |
| TM-TB12-T4 | T | A compromised server signs a malicious policy (the policy key lives in the management plane, BP §12) | Policy is **data within schema bounds** (TM-D14) | TM-F-AGENTCMD | **Accepted** (TM-R7): weaker or stricter password checks; event collection stopped |
| TM-TB12-T5 | S | Another process on the DC connects to the filter's pipe | Pipe ACL'd to the agent's service SID; each end checks the peer (BP §13) | T-0024 spike test | — |
| TM-TB12-T6 | D | The filter crashes or blocks LSASS → DC reboot | No network I/O in LSASS; bounded memory; no blocking calls; fail mode decided explicitly (CEO, §12) | T-0024 fault injection | Until the CEO decides the fail mode, M4 build cannot start |
| TM-TB12-T7 | I | Candidate passwords cross the pipe or persist | If the IPC carries them: zeroed at both ends, never logged, never leave the DC unless a later password-sync feature is reviewed `[OPEN → T-0024 + T-0040]` | T-0024 | — |
| TM-TB12-T8 | R | A compromised agent forges DC events | Per-DC agent identity; event records keep the agent identity; cross-check with DC replication metadata (BP §9) | T-0040 | A compromised DC can lie; it is already Tier 0 |
| TM-TB12-T9 | D | The agent starves the DC | CPU, memory and queue bounds; subscription throttles | T-0040 | — |
| TM-TB12-T10 | E | A compromised server makes file-server agents write hostile ACLs, write files or run code | Closed `fileserver` command set (TM-D13): read an ACL, apply an ACL built only by the typed security-descriptor primitive (T-0028), create a folder (ADM-023), collect file-access events. No exec, no file content write, no delete, no service or registry change | TM-F-AGENTCMD | Within the configured roots, a compromised server can still set any ACL the primitive can express (TM-R1 analogue) |
| TM-TB12-T11 | E | The server widens the agent's reach to `C:\`, another share or a system path | The **root allow-list is local**: set on the file server at install by its administrator, in a config file ACL'd to administrators. The server can narrow it and never widen it. Policy cannot name roots | TM-F-AGENTCMD | Host administrator sets a broad root (TM-R4) |
| TM-TB12-T12 | T/E | Path escape from a root: `..`, junctions, symbolic links, 8.3 short names, `\\?\` device paths, alternate data streams | Paths are canonicalised before the root check; reparse points are not followed (opened as the link, not the target); device, UNC and stream syntax refused | TM-F-AGENTCMD (escape corpus) | — |
| TM-TB12-T13 | E | The file-server agent becomes Tier 0, or holds host-wide rights | The `fileserver` module refuses to start on a DC. `SYSVOL`, `NETLOGON` and any DC share can never be a root: writing them plants scripts or policy that every DC and client runs. The agent runs as a virtual service account or gMSA with Modify + WRITE_DAC on its roots only, never LocalSystem and never holding SeBackupPrivilege, SeRestorePrivilege or SeTakeOwnershipPrivilege (each bypasses every ACL on the host). Its tier is the file server's tier (Tier 1). Final identity in the M3 `fileserver` spec | TM-F-AGENTCMD, TM-F-HOST | — |
| TM-TB12-T14 | R | ACL changes cannot be attributed or undone | Each command carries the operation ID and acting principal; the agent records the before and after security descriptors, so the change is audited and undoable (ENH-04) | TM-F-AUDIT | — |
| TM-TB12-T15 | I | File-access events and ACL reads expose who can read what | Stored as inventory under RBAC trimming (TM-TB1-T8); per-agent identity in every record | TM-F-AUTHZ | — |

### 5.13 TB13 — Credential provider (LogonUI) ↔ SSPR API [M4]

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB13-T1 | E | Kiosk breakout from an embedded browser on the logon screen to SYSTEM (CVE-2020-11552, CVE-2026-74849; ME-SEC §4.1, §4.3 "logon-screen client") | No web content at all; native fields only; no file dialogs, help links or printing (FEAS §2.6) | TM-F-CREDPROV | — |
| TM-TB13-T2 | S | X2 impersonates the SSPR server to the logon screen | Pinned TLS (BP §13) | TM-F-CREDPROV | — |
| TM-TB13-T3 | D | Our service is down and users cannot log on | The provider never blocks normal logon; works offline with a clear message; no network call on the UI thread (SB checklist D) | TM-F-CREDPROV | — |
| TM-TB13-T4 | T | A malformed response crashes LogonUI | Tier N (Rust) parser, fuzzed; bounded messages | FF-SP5 | — |
| TM-TB13-T5 | I | Account enumeration from the logon screen | The same SSPR rules as TB11 | TM-F-ABUSE | — |
| TM-TB13-T6 | R | Resets from endpoints unattributable | Audit with device identity and factors | TM-F-AUDIT | — |

### 5.14 TB14 — Sidecars ↔ launcher [M3 / FD-04]

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB14-T1 | T/E | PowerShell injection through data (the CVE-2022-28810 custom-script class, ME-SEC §4.1) | Typed `psx` operations: `AddCommand`/`AddParameter` only, constant argv, data as JSON on stdin; no custom-script feature (SP §6.1) | FF-SP8, FF-SP9 | — |
| TM-TB14-T2 | E | Code loaded into the sidecar through the environment | Never-inherit list (`DOTNET_STARTUP_HOOKS`, profiler variables, `PSModulePath`, `LD_PRELOAD`, …) (SP §6.3) | FF-SP4 (PROC-15) | — |
| TM-TB14-T3 | S | The sidecar binary is replaced on disk | Absolute path fixed at install, under an ACL'd install directory; Authenticode-signed | TM-F-HOST | Host administrator (TM-R4) |
| TM-TB14-T4 | I | Secrets in argv or environment | stdin only; `SecureString` as a type boundary (SP §5.6) | FF-SP4 (PROC-13), FF-SP9 (PSX-18) | — |
| TM-TB14-T5 | D | A hung sidecar | Timeout and output cap per operation | FF-SP8 | — |
| TM-TB14-T6 | E | A sidecar opens a listener | Sidecars never listen (BP §5.5) | TM-F-PORTS | — |

### 5.15 TB15 — Data leaving: exports, scheduled delivery, audit export, backups, SIEM

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB15-T1 | T | X3 plants a formula (`=`, `+`, `-`, `@`, tab, CR, LF, full-width variants) in an attribute; an admin opens the CSV/XLSX | Export encoders neutralise formula-leading cells (T-0029) | T-0029 encoder corpus | — |
| TM-TB15-T2 | I | A scheduled report delivers data beyond what its owner may see | Compiled with the **owner's** scope at run time; a disabled owner stops the schedule | TM-F-AUTHZ | Recipients outside activeDIQ see what the owner could see |
| TM-TB15-T3 | I | Exports contain secret attributes | `SecretAttrs` never stored, so never exportable (SP LF-38) | FF-SP4 | — |
| TM-TB15-T4 | I | X6 steals a database backup (ADM-158) | Secrets are ciphertext only; backup files ACL'd to the service; backup encryption `[OPEN → E2.12 PRD]` | TM-F-HOST | The PII in inventory is readable (TM-R8) |
| TM-TB15-T5 | T | An audit export is edited before an auditor sees it | Export carries the chain and signed checkpoints; offline verifier (§11) | TM-F-AUDIT | — |
| TM-TB15-T6 | R | Bulk data leaves with no record | Every export, download and delivery audited with actor and row count | TM-F-AUDIT | — |
| TM-TB15-T7 | I | The SIEM stream travels in clear | TLS syslog or HTTPS by default; plain UDP syslog only with an explicit operator opt-in and a warning | TM-F-EGRESS | Customer opts in |
| TM-TB15-T8 | D | Huge exports exhaust the server | Streaming encoders, row caps, asynchronous jobs | T-0029 | — |

### 5.16 TB16 — Host and installer

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB16-T1 | E | The server is installed on a DC → management plane on Tier 0 | Installer refuses a DC (ADR-0002 rule 9) | TM-F-HOST | — |
| TM-TB16-T2 | E | The service runs as LocalSystem or root | gMSA on Windows; non-root container on Linux | TM-F-HOST | — |
| TM-TB16-T3 | I | Other local users read config, keytab or keystore → A2, A3 | File ACLs: service identity and administrators only; keytab mounted read-only, mode 0400 | TM-F-HOST | — |
| TM-TB16-T4 | T | DLL planting or binary replacement in the install directory | Install directory ACL; Authenticode; absolute paths, never `PATH` (SP §6.3) | TM-F-HOST | — |
| TM-TB16-T5 | E | A host administrator acts as the service | Stated: **host administrators are at the tier of the service** (TM-R4); docs require the host to be managed as a Tier-1 server | — (documentation) | Accepted |
| TM-TB16-T6 | I | Secrets in crash dumps, core files or the pagefile | No `pprof`; `GOTRACEBACK` never `crash`; `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`; no WER LocalDumps (SP §5.6, §9 below) | FF-SP2, TM-F-HOST | Pagefile and hibernation file (TM-R9) |
| TM-TB16-T7 | S | Someone races the operator to first-run setup | One-time setup secret written only where the installing administrator can read it; expires; consumed on first use | TM-F-HOST | — |
| TM-TB16-T8 | R | Install and uninstall leave no trace | Installer logs to the OS event log; first start writes a platform audit event | TM-F-AUDIT | — |
| TM-TB16-T9 | I | Uninstall leaves delegated rights in AD | Hardening module emits a "remove delegation" plan `[OPEN → ENH-08 spec]` | ENH-08 spec test | Customer does not apply it |
| TM-TB16-T10 | E | An unexpected listener is exposed (debug port, sidecar, metrics without auth) | The listening sockets of a booted install equal the declared list (§8) | TM-F-PORTS | — |

### 5.17 TB17 — SaaS cell (designed, not shipped)

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB17-T1 | I | X11 reads another tenant's data | RLS from migration 1 (T1–T5); tenant from principal only | T1–T5, P4 | — |
| TM-TB17-T2 | S | Tenant A's connector certificate used against B | Tenant from certificate SAN | P4 | — |
| TM-TB17-T3 | I | X7 (operations staff) reads tenant data or unseals certificates | No standing unseal; break-glass access is approved, time-bound and audited; KMS policy grants decrypt only to the cell workload identity (§13) | SaaS launch revision `[OPEN → E5.6]` | Insider with cell code execution (TM-R10) |
| TM-TB17-T4 | E | A compromised cell orders `tier0` writes through an on-site connector | Connector-side tier-0 guard (TM-D2) | TM-F-T0GUARD | — |
| TM-TB17-T5 | E | A compromised cell uses every tenant's Entra certificate | One certificate per tenant; KMS encryption context per tenant; KMS audit log; permission limits (§6.6); a regulated tenant binds Entra on-site (ADR-0002 amendment path) | §13 | **Accepted for design** (TM-R10) |
| TM-TB17-T6 | R | Unwraps are not independently recorded | KMS audit log (e.g. CloudTrail) is an independent record of every unwrap | §13 | — |
| TM-TB17-T7 | D | A noisy neighbour starves other tenants | Per-tenant quotas `[OPEN → E5.6]` | — | — |
| TM-TB17-T8 | I | Logs, metrics or caches mix tenants | Tenant ID on every log line and metric; caches keyed by tenant (ADR-0002) | P4 (extended to logs and caches) `[OPEN → T-0038]` | — |

### 5.18 TB18 — ManageEngine source ↔ migration importer, discovery scanner, parallel-run comparator [M2]

`migration` (BP §5.4; E2.11; ENH-02) imports ADMP configuration. The first route is the export
files the customer hands over: report exports in CSV, XLSX or HTML, plus ADMP-format bulk CSV. The
second route is a read-only read of the ADMP database or API
([migration playbook](../../business/service/manageengine-migration-playbook.md) §4.1, §8 MIG-01–03,
MIG-10, MIG-14, MIG-16). The discovery scanner (MIG-01) reads AD through the connector. The
comparator (MIG-10) diffs activeDIQ dry-run results against ADMP's. **The source is untrusted.** A
ManageEngine server may itself be compromised (TM-X13; ME-SEC §4.1). Export files carry attribute
values that any user can write on their own object (TM-X3).

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB18-T1 | T/E | X13 or X4 supplies a hostile file: XML external entities, an XLSX or ZIP with `..`/absolute entry names or links, a decompression bomb, oversized rows or cells | Every importer is an RT-13 parser. It enforces limits on file size, decompressed size, rows, cell length and nesting. Archive entries are read in memory or in a per-job temporary directory; absolute, `..` and link entries are rejected. Go `encoding/xml` has no external entities, and no other XML library is allowed in importers. Each format has a fuzz target (FF-SP5). Imported strings stay data and are re-encoded on output (T-0029) | TM-F-MIGRATE, FF-SP5 | — |
| TM-TB18-T2 | E | Imported roles, delegations, approvers or automation grants escalate someone, the importer included (the CVE-2024-24409 class, ME-SEC §4.1) | TM-D21: imports land as **proposals**, never live. Each is applied as an Action (T-0047) by an actor who holds every privilege of every imported grant over its whole scope (DM-36.I1), with step-up (§7.4). `tenant-owner`, and permissions that administer RBAC, delegation scopes or connections, are never imported. A scope or target that resolves to a `tier0` object (§6.4) is dropped and reported as "not supported". Grants to shared technician logins wait for MIG-16 to map them to named people | TM-F-MIGRATE, TM-F-AUTHZ | — |
| TM-TB18-T3 | E | Script-bearing ADMP content imported as executable: custom scripts, custom naming functions, script-backed automations. This is the class of CVE-2022-28810 (custom script, KEV) and CVE-2025-10020 (ADMP Custom Script command injection) (ME-SEC §4.1) | Never imported as executable. Script bodies appear only as escaped text in the fidelity report (MIG-03), classified `manual`. activeDIQ has no custom-script feature (SP §6.1). Custom-report LDAP filters are parsed by the filter AST (SP P1), or classified `not supported`. Raw SQL is never executed (SP P5). Naming macros parse into a typed rule; an unknown macro is `not supported` | TM-F-MIGRATE, FF-SP1 | — |
| TM-TB18-T4 | I | ADMP's own stored AD credentials or technician passwords are read or imported. Horizon3 found "highly privileged" AD credentials in a competitor product's database (ME-SEC §4.4) | Adapters read an **allow-list** of tables and columns per ADMP build. A CI-checked deny list covers every credential, key and password table or column. A database dump or backup is read as a stream, only allow-listed tables are extracted, and the upload is deleted when the job ends; it never enters the blob store. Technicians are re-created by invitation or SSO, never with imported passwords | TM-F-MIGRATE | ADMP's service account keeps its rights until the customer removes it (playbook phase 6) |
| TM-TB18-T5 | I | The credential for the ADMP database or API leaks; that database holds ADMP's AD credentials | Sealed per-integration credential (TM-D7), write-only, never returned (TM-TB9-T5). Read-only by contract: a read-only database login or a read-only technician token, read-only transactions, no write statement in adapter code (FF-SP7 scope). Windows authentication to SQL Server is Kerberos only (TM-D10). The credential is deleted when the migration project closes | TM-F-MIGRATE, TM-F-SECRETOUT | The customer grants a login that can write; the adapter still never writes |
| TM-TB18-T6 | S/I | A scanner or comparator target is used for SSRF or NTLM coercion | ManageEngine servers are registered explicitly. They are reached only through the egress client (TM-TB9-T1); AD only through the connector and `InventoryHost`. Kerberos only, no NTLM (TM-D10) | TM-F-EGRESS, TM-F-NTLM | — |
| TM-TB18-T7 | E | Parallel run executes imported automations for real (a leaver deleted twice; MIG-14) | Comparator runs are Plan-only operations with no Apply path. activeDIQ refuses to run a job whose owner is ManageEngine (MIG-14). Switching ownership is an audited Action with step-up | TM-F-MIGRATE, T-0047 operation fitness | — |
| TM-TB18-T8 | T | X13 feeds false results so the comparator reports parity | Comparator output is advisory and never triggers a write. The fidelity report shows the source of each row | — | A wrong parity sign-off; the customer's review is the control |
| TM-TB18-T9 | S/I | An imported scheduled report or notification delivers to an attacker-chosen recipient (MIG-06) | Imported schedules land disabled, with recipients shown for review. Recipients outside the tenant's allowed domains are flagged. Delivery runs with the owner's scope (TM-TB15-T2) | TM-F-MIGRATE | — |
| TM-TB18-T10 | I | Discovery output (privileged accounts, delegations) becomes a reconnaissance map (A6) | The scanner needs its own permission and uses only R1 read rights (§6.3). Its output is inventory under RBAC trimming; exports go through the TB15 encoders and are audited | TM-F-AUTHZ | — |
| TM-TB18-T11 | R | Import runs cannot be traced | Every run is audited: actor, source kind and SHA-256, ADMP build, item counts per classification. Every applied proposal is its own audited Action (§11) | TM-F-AUDIT | — |
| TM-TB18-T12 | D | A huge export or database stalls the server | Streaming parsers, job quotas, per-job time and memory caps | TM-F-MIGRATE | — |

**DECISION TM-D21 — migration imports are proposals, never code, never credentials.** The rows
above are binding on the E2.11 tickets. An import never writes live configuration, never imports
an executable artefact, never reads a credential, and never grants authority its applier does not
hold. A new source product (ADAP in M3, ADSSP in M4) is an RT-18 trigger (§14).

### 5.19 TB19 — RADIUS clients ↔ `radius` [M4]

ADR-0002 rule 2 lets `radius` share the `server` process, and so the process that holds directory
credentials. It also hands this document the job of bounding it. RADIUS clients are VPN
concentrators and network devices. Internet-facing VPN appliances are a common way in, so a
**compromised client that holds a valid shared secret** is in scope (TM-X12), not only a spoofed
one (TM-X2).

| ID | STRIDE | Threat | Control | Proof | Residual |
| --- | --- | --- | --- | --- | --- |
| TM-TB19-T1 | S | X2 sends requests as an unknown or spoofed NAS | Registered client addresses with a distinct secret per client. A request from a client without a secret "MUST be silently discarded" ([RFC 2865 §2](https://www.rfc-editor.org/rfc/rfc2865)), before any attribute is parsed. Secrets are generated by activeDIQ with 32 random bytes; RFC 2865 §3 prefers "at least 16 octets". Sealed (TM-D7), shown once | TM-F-RADIUS | Source addresses on UDP can be spoofed; the secret is the real check |
| TM-TB19-T2 | S/T | Blast-RADIUS: an on-path attacker forges an Access-Accept with an MD5 chosen-prefix collision (CVE-2024-3596, [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-3596)) | `Message-Authenticator` required in every request and response and verified before anything else is acted on ([blastradius.fail](https://www.blastradius.fail/)). It is sent first in our responses. Clients that cannot send it are refused | TM-F-RADIUS | — |
| TM-TB19-T3 | S/D | A compromised client (X12) guesses passwords and OTPs, or locks users out | The same server-side counter as TM-TB1-T9: it stops below the domain lockout threshold; OTPs are single-use; one generic Access-Reject | TM-F-ABUSE, TM-F-RADIUS | Guessing below the threshold, spread over time |
| TM-TB19-T4 | I | PAP exposure: the password is hidden by an MD5 of "the shared secret followed by the Request Authenticator" XOR the password ([RFC 2865 §5.2](https://www.rfc-editor.org/rfc/rfc2865)), so a leaked or weak secret plus captured traffic reveals passwords | High-entropy per-client secrets (T1); RADIUS/TLS ([RFC 6614](https://www.rfc-editor.org/rfc/rfc6614)) preferred where clients support it; internal networks only; attribute values never logged | TM-F-RADIUS, TM-F-SECRETOUT | **Accepted** (TM-R13): PAP over UDP for clients without RADIUS/TLS |
| TM-TB19-T5 | I/E | MS-CHAPv2: a captured exchange lets an attacker "obtain user credentials" ([Advisory 2743314](https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2743314)), and verifying it needs the user's NT hash ([RFC 2759](https://www.rfc-editor.org/rfc/rfc2759)), which activeDIQ never holds (no Get-Changes-All, §6.3 R2) | MS-CHAPv2 is not offered in M4. A Netlogon pass-through design would add a new right on TB3 and needs its own review (RT-4) | TM-F-RADIUS (no MS-CHAP attributes accepted) | — |
| TM-TB19-T6 | D | A UDP flood, or reflection through our replies | Per-client and global rate limits. A bounded queue and a worker pool separate from the console and API pools, so a flood cannot starve them. Unregistered sources get no reply, so no amplification. Per-DC concurrency for the checks behind it | TM-F-RADIUS | Volumetric floods need the network's controls |
| TM-TB19-T7 | R | Network-access decisions cannot be traced | Every Access-Request outcome is audited: client, user, factor, result and reason, never a secret | TM-F-AUDIT | — |
| TM-TB19-T8 | E | A pre-auth parser bug inside the credential-holding process | TM-D20: Go only, no `unsafe` or cgo in the `radius` package (lint). The decoder is fuzzed (FF-SP5) and bounded by the RFC 2865 packet length (20 to 4096 octets), with an attribute allow-list. `radius` reaches the connector only through the `VerifyUser` and OTP-check interfaces, never credentials or `store` directly (import rule). No EAP method in M4 | TM-F-RADIUS, FF-SP5 | — |
| TM-TB19-T9 | E | RADIUS success becomes console or API access | `radius` exposes no console or API capability; an Access-Accept grants network access only | TM-F-ANON (route set unchanged) | — |

**DECISION TM-D20 — `radius` may share `cmd/server` only under TM-TB19-T8.** Sharing the process
is acceptable because the decoder is small, memory-safe and fuzzed, and because the flood
isolation of T6 keeps it from starving the console. Any of the following moves `radius` into its own
`cmd/radius` process, which BP §3.1 already defines; ADR-0002 rule 2 then needs the amendment the
M4 RADIUS spec proposes:
- an EAP method;
- a TLS stack other than Go's;
- a fuzz or flood budget the shared process cannot meet.

---

## 6. Service-account model and least privilege

### 6.1 Identities

| Identity | Profile / where | What it is | Holds |
| --- | --- | --- | --- |
| Connector AD identity | `windows`: **gMSA** (no stored secret). `linux-oci`: dedicated account with an **AES-only keytab** (`msDS-SupportedEncryptionTypes` 0x18, FEAS §2.4); gMSA retrieval on Linux is `[LAB]` | The only directory identity (ADR-0002 rule 3) | Exactly the rights of §6.3 for the enabled features |
| gMSA retrieval list | `msDS-GroupMSAMembership` (PrincipalsAllowedToRetrieveManagedPassword) | Who may read `msDS-ManagedPassword` | Exactly the connector host computer account(s); the password is returned only over a sealed connection ([msDS-ManagedPassword](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-managedpassword)) |
| Entra app | The customer's **own** app registration, one per Entra tenant; certificate credential | App-only Graph access (ADR-0002 rule 3) | §6.6 permissions; **no Entra directory role**; **no owners** |
| PostgreSQL roles | Owner role (migrations) ≠ runtime role (ADR-0002 rule 4) | Data access | Runtime: no ownership, no `BYPASSRLS`, no `TRUNCATE`, INSERT-only on audit (§11) |
| Server process | `windows`: the gMSA (embedded transport); `linux-oci`: non-root container, keytab mounted read-only | Runs `server` + embedded `connector` | Host-level only what the service needs (TM-F-HOST) |
| Sidecars [M3] | Inherit the launcher's identity | Typed operations | No credentials of their own |
| DC agent [M3] | A virtual service account in Event Log Readers preferred over LocalSystem ([WEF Appendix D](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection); FEAS §2.3) | Event collection, filter IPC | Final choice in T-0040 |
| Edge [M4] | Own host | Public front | **No directory identity** |

### 6.2 Never Domain Admin — DECISIONS TM-D1 and TM-D2

**TM-D1 — onboarding refuses an over-privileged identity.** A connection does not become `active`
(DM-10 lifecycle) while its connector identity is, transitively, a member of any group in the
Tier-0 set (§6.4), or holds any write or control right on a `tier0` object (§6.5). The installation
operator may override with an explicit, audited, platform-scope acknowledgement (step-up, §7.4).
An override shows a permanent "activeDIQ is Tier 0 in this forest" banner and health status. The
health check reports **excessive and missing** rights on every run (SB §4).

**TM-D2 — v1 never writes a `tier0` object, whatever the rights** (DM-16.I8, DM-35.I5, FD-11). The
check runs twice:
1. in Action **Plan**, against a live re-read of the target and its group memberships;
2. **independently in the connector**, which computes `tier0` for its own forest and refuses
   `Apply` on a `tier0` target even when the server asks. This is defence in depth for a
   compromised server, and matters most for remote and SaaS connectors (TB6, TB17).

**Proof TM-F-T0GUARD.** Both transports: a hand-crafted `Apply` on a `tier0` user, group, DC, GPO
and the AdminSDHolder object is refused by the connector with the server-side guard disabled; an
object that became `tier0` after the last sync (added to Domain Admins) is refused at Plan and at
the connector; Entra: a write to a privileged-role holder or a role-assignable group is refused
before Graph is called.

### 6.3 Minimum AD rights per feature family

Source for this table: ad-expert consult for T-0007 (schema pages and MS-ADTS; GUIDs verified
against the AD schema; behaviour "doc-only" unless marked). Abbreviations: RP read property, WP
write property, CA control access (extended right or confidential read), CC/DC create/delete child,
SW validated write. GUIDs shortened with "…" are taken **from the forest's schema at run time**
(`schemaIDGUID`, `rightsGuid`) by the hardening module, never hard-coded.

| # | Feature family (parity) | Minimum rights | Scope | Pitfalls |
| --- | --- | --- | --- | --- |
| R1 | Inventory, reporting, exact last logon (ADM-084), nested membership | Authenticated read for most attributes; read of `tokenGroupsGlobalAndUniversal` through membership of **Windows Authorization Access Group** (S-1-5-32-560) | Domains | `lastLogon` is per-DC and not replicated: query every DC or label `lastLogonTimestamp` (lags by `msDS-LogonTimeSyncInterval`, default 14 days) |
| R2 | Change tracking (DirSync) | **None extra:** `LDAP_DIRSYNC_OBJECT_SECURITY` (0x1) returns only what the identity can already read | NC roots | Plain **DS-Replication-Get-Changes** (`1131f6aa-…`) via DirSync **bypasses object and attribute ACLs and reads confidential attributes** (not hashes) — Tier-0-adjacent; **not used in v1**. **Get-Changes-All** (`1131f6ad-…`) is DCSync — forbidden |
| R3 | User create, delete, modify (ADM-008…024) | CC/DC for class `user` on target OUs; **per-attribute WP**, inheritedObjectType `user` | Target OUs | **Never the User-Account-Restrictions property set** (`4c164200-20c0-11d0-a768-00aa006e0529`): from WS2012 it includes `msDS-AllowedToActOnBehalfOfOtherIdentity`, i.e. RBCD configuration → takeover ([property set](https://learn.microsoft.com/en-us/windows/win32/adschema/r-user-account-restrictions)) |
| R4 | Enable/disable, expiry, unlock, must-change | WP `userAccountControl`, `accountExpires`, `lockoutTime` (unlock = 0), `pwdLastSet` (0 / -1) | `user`, delegated OUs | Not covered by Reset-Password; write to the PDC emulator; displayed state from `msDS-User-Account-Control-Computed` |
| R5 | Password reset (ADM-136) | **Reset-Password** extended right (CA, `00299570-246d-11d0-a768-00aa006e0529`), inheritedObjectType `user` | `user`, delegated OUs | Send `LDAP_SERVER_POLICY_HINTS_OID` (`1.2.840.113556.1.4.2239`, flag 0x1) so history and minimum age apply; it needs no extra right (doc-only `[UNVERIFIED — lab]`). `unicodePwd` over LDAPS only (SP §5.6) |
| R6 | Group management | CC/DC class `group`; WP `member` | Delegated groups/OUs | Protected groups reset their ACL hourly (SDProp), so delegation there does not stick — and they are `tier0` anyway |
| R7 | Computers: create, reset (ADM-057) | CC/DC class `computer` (**object-specific**, never "Create all child objects"); Reset-Password for machine reset; WP on benign attributes only | Delegated computer OUs | **Never delegate:** `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD), `msDS-KeyCredentialLink` (shadow credentials), `servicePrincipalName` and Validated-SPN, `dNSHostName` and Validated-DNS-Host-Name, the `userAccountControl` delegation bits (TRUSTED_FOR_DELEGATION also needs SeEnableDelegationPrivilege on DCs — never requested). On WS2025, "Create all child objects" or "Create msDS-DelegatedManagedServiceAccount" on an OU is the **BadSuccessor** dMSA escalation ([Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)) |
| R8 | Contacts and OUs; move; rename | CC/DC class `contact` / `organizationalUnit`; move = DC on source + CC on target + WP RDN/`name` | Parent containers | **Withhold Delete-Tree** (0x40, control `1.2.840.113556.1.4.805`): it deletes a subtree ignoring child protections, including accidental-deletion deny ACEs. Delete non-empty OUs by recursion so each child is access-checked |
| R9 | Recycle Bin restore (ADM-038) | **Reanimate-Tombstones** (`45ec5156-db7e-47bb-b53f-dbeb2d03c40f`) on the NC root + WP on mandatory attributes and RDN + CC of the class on the target container | Reanimate is **NC-root-wide** (cannot be scoped); effective restore bounded by CC on target OUs | **Tier-0-adjacent: JIT only**, never standing (FEAS §2.3 `adq-restore`). Works only for objects deleted after the delegation was set. Samba deleted-object behaviour can false-pass (before the [CVE-2018-14628](https://www.samba.org/samba/security/CVE-2018-14628.html) fix, tombstones were readable over LDAP): **Windows lab required**. **Finding the object:** by default "only the System account and members of the Administrators group can view" `CN=Deleted Objects`, and letting anyone else list it needs a Domain Admin to take ownership of the container and grant List + Read Property ([KB 892806](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/non-administrators-view-deleted-object-container)). v1 restore requests **no list right**: it addresses the object by the `objectGUID` inventory recorded before deletion (`<GUID=…>` DN with the Show-Deleted control). Whether a DC resolves that GUID for an identity without list rights on the container is `[UNVERIFIED — lab]` (T-0051, T-0060). If it does not, the container change is needed; it stays JIT like Reanimate and needs a security-architect review (TM-Q27) |
| R10 | LAPS read (ADM-060) | Legacy: CA on `ms-Mcs-AdmPwd` + read expiration. Windows LAPS: RP + CA on `msLAPS-Password` / `msLAPS-EncryptedPassword` (confidential), via `Set-LapsADReadPasswordPermission` per OU ([LAPS technical reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)) | Computer OUs, **excluding the Domain Controllers OU** | `msLAPS-EncryptedDSRMPassword` on DC objects is the DSRM password = Tier 0. The connector is **never** a member of the decryptor principal of a policy covering DCs, and never through Domain Admins (the default decryptor). A dedicated decryptor group for non-DC policies is the security-architect reading, `[UNVERIFIED — lab]`, `[OPEN → ADM-060 spec]` |
| R11 | BitLocker key read | CA on child `msFVE-RecoveryInformation` objects (keys are confidential, `searchFlags` 0x298, SP §3.7) | Computer OUs | Granted on the whole recovery object |
| R12 | Home and profile folders (ADM-023) | AD: WP `homeDirectory`, `homeDrive`, `profilePath`. File server: "Create Folders / Append Data" + Read on the share root; the **user** owns their folder with Modify | File server (an `InventoryHost`) + user attributes | No standing Full Control over all home folders; implementation with windows-engineer |
| R13 | Hardening wizard (ENH-08) | **None standing** (TM-D3) | — | — |

**Default posture.** Per-attribute WP, never property sets that over-grant. No GenericAll,
GenericWrite, WRITE_DAC, WRITE_OWNER or Delete-Tree anywhere. No Get-Changes or Get-Changes-All.
LAPS and BitLocker off by default and never on DCs. **A feature that is off has its rights not
granted**; the hardening wizard (ENH-08) generates exactly these delegations for the enabled
features. A new right is a §14 trigger (RT-4).

**TM-D3 — the wizard never holds WRITE_DAC.** Applying delegations needs WRITE_DAC on the target
OUs. The connector therefore never holds it. The wizard emits a reviewed **delegation plan** built
with the typed security-descriptor primitive (T-0028), which a customer administrator applies with
their own credential in a one-time elevated session. `[OPEN → ENH-08 spec]` under this constraint.

### 6.4 The Tier-0 object set (`tier0`, answers DM Q1) — DECISION TM-D4

`tier0` = the **computed set** ∪ **customer-designated additions**. The computed set is recomputed
on every sync and on every schema or ACL refresh. Computed entries cannot be un-designated.
Membership is computed **transitively**, never trusted from `adminCount`: SDProp sets it up to 60
minutes after the fact and never clears it when a principal leaves
([Appendix C](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)).

Computed, per forest and domain (ad-expert consult; Microsoft tier model; SpecterOps
[TierZeroTable](https://github.com/SpecterOps/TierZeroTable)):

| # | Members of `tier0` |
| --- | --- |
| C1 | Protected groups (Appendix C): Account Operators, Administrator, Administrators, Backup Operators, Domain Admins, Domain Controllers, Enterprise Admins, Enterprise Key Admins, Key Admins, Krbtgt, Print Operators, Read-only Domain Controllers, Replicator, Schema Admins, Server Operators |
| C2 | Transitive members of C1 groups (computed by walking `member`, including primary-group edges) |
| C3 | `CN=AdminSDHolder,CN=System,<domain>` |
| C4 | `krbtgt` and every RODC `krbtgt_NNNNN` (`msDS-SecondaryKrbTgtNumber` set) |
| C5 | DC computer objects: `userAccountControl` SERVER_TRUST_ACCOUNT 0x2000 or PARTIAL_SECRETS_ACCOUNT 0x4000000, corroborated by `nTDSDSA` / `msDS-isRODC` |
| C6 | The Domain Controllers OU, and every OU or container whose subtree holds a DC computer object (DCs moved out of the default OU) |
| C7 | Naming-context heads: domain, Configuration, Schema |
| C8 | Sensitive `CN=System` objects, including the **KDS root key container** — its keys let an attacker "generate the password for all the associated gMSAs offline", and they do not rotate ([Golden gMSA](https://www.semperis.com/blog/golden-gmsa-attack/)) |
| C9 | GPOs whose links reach a DC or a C1–C4 account, with reach as DM-23.I5 defines it: the SOM's whole subtree, enforced links passing block inheritance, loopback. This includes every GPO linked to the domain head, to a C6 OU, or to a C15 site. **DM-23.I5 confirmed:** a `gPLink`/`gPOptions` write on the domain head, a C6 OU or a C15 site is a Tier-0 write |
| C10 | PKI in the Configuration NC: enterprise CA objects (`pKIEnrollmentService`), root/AIA CA objects, the NTAuth store, certificate templates |
| C11 | Principals holding Get-Changes **and** Get-Changes-All on a domain root (DCSync), found from the domain-root DACL |
| C12 | Delegation-risk principals: unconstrained delegation, `msDS-AllowedToDelegateTo` to a DC service, or listed in a DC's `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| C13 | Default-privileged groups treated as Tier 0: DnsAdmins, Cert Publishers, Exchange Trusted Subsystem / Exchange Windows Permissions (if present). **Group Policy Creator Owners is sensitive, not Tier 0** (it edits only GPOs it created) |
| C14 | `AZUREADSSOACC$` (Seamless SSO) computer account |
| C15 | Site objects (`CN=Sites,CN=Configuration`) that hold a DC's server object |
| C16 | **Hybrid:** AD objects with **any** correlation (`candidate`, `matched` or `broken`, DM-20) to an Entra `tier0` principal (E1–E5 below). A password reset in AD reaches Entra through password hash sync or pass-through authentication. Microsoft: "Ensure that changes to these accounts can't affect the integrity of your cloud environment" ([protect M365](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks)) |

**Customer-designated** (not derivable from LDAP): Entra Connect servers — Microsoft: "must be
treated as a Tier 0 component"
([Entra Connect prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites));
their AD connector accounts fall out of C11 when password hash sync is on. Also Cloud Sync agent
hosts (security-architect decision: an agent can write every in-scope object, as a Connect server
can), AD CS and AD FS hosts, PAM servers, and hypervisor, backup and EDR hosts with DC-level
control. Onboarding proposes candidates and the customer confirms them. Designations are audited
and need step-up.

**Entra `tier0`** (refines DM-35.I5). The guard of TM-D2 refuses every write to:

| # | Members of Entra `tier0` | Why |
| --- | --- | --- |
| E1 | Holders of **any** Entra directory role, active or PIM-eligible, at any scope — not only the roles labelled PRIVILEGED | Graph already refuses app-only sensitive actions on admin-role holders (§6.6), so the wider set costs no function. Labels change over time. Reading eligibility through `RoleManagement.Read.Directory` is `[UNVERIFIED — lab G6]` |
| E2 | Role-assignable groups (`isAssignableToRole`), their members and their owners | Membership is role assignment ([groups-concept](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept)) |
| E3 | Owners of app registrations or service principals that hold a directory role or a §6.6 deny-list permission | An owner can add a credential (`addKey`) and act as the app (§6.6) |
| E4 | The hybrid control set: holders of Hybrid Identity Administrator and Hybrid Administrator (sync features, SOA transfer, [user SOA](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure)); Directory Synchronization Accounts; the sync clients' service principals | Whoever controls sync passes every correlation check (DM-20.I6; §6.8) |
| E5 | Entra objects with **any** correlation to an AD `tier0` object (C1–C16) | Writes on the cloud side (password writeback) can reach AD `[UNVERIFIED — lab]`; fail closed |

Customer-designated Entra additions: emergency-access (break-glass) accounts, and the groups that
Conditional Access policies exclude. **Protection is wider than authority:** for `tier0`, any
correlation counts, even `candidate`; for authority, only `matched` counts (§6.8).

### 6.5 Verification at onboarding and on every health check

Run as the connector identity, no Domain Admin needed:
1. **Group membership.** Read the identity's `tokenGroups` (base scope) and intersect with the
   SIDs of C1, C13 and customer-designated groups.
2. **Constructed effective-rights attributes, read as the connector on each `tier0` object:**
   `allowedAttributesEffective` (attributes with WP), `allowedChildClassesEffective` (classes with
   CC) and `sDRightsEffective` (OWNER/DACL/SACL write bits)
   ([allowedAttributesEffective](https://learn.microsoft.com/en-us/windows/win32/adschema/a-allowedattributeseffective),
   [sDRightsEffective](https://learn.microsoft.com/en-us/windows/win32/adschema/a-sdrightseffective)).
   Any non-empty result refuses activation (TM-D1).
3. **DACL evaluation for what step 2 cannot see:** extended rights, confidential read and
   validated writes. Read `nTSecurityDescriptor` with the SD-flags control (`…801`) set to
   DACL (+owner/group) only — never request the SACL, which fails for a non-admin — and match the
   identity's SIDs against CA/SW ACEs. READ_CONTROL is available to authenticated users on almost
   all objects by default.
4. **Excessive rights in managed OUs.** Compare the identity's ACEs per OU with the §6.3 mask of
   the enabled features; flag GenericAll, GenericWrite, WRITE_DAC, WRITE_OWNER and any WP on the
   R3/R7 never-delegate list. `allowedAttributesEffective` on a sample user per OU is a cheap
   positive check.
5. **Delegation configuration of the identity itself:** no `msDS-AllowedToDelegateTo`, neither
   TRUSTED_FOR_DELEGATION nor TRUSTED_TO_AUTH_FOR_DELEGATION, and absent from every DC's RBCD
   attribute (§6.7).

**Samba.** The three constructed attributes are implemented in Samba's ACL module with the same
semantics (confirmed in Samba source by the ad-expert consult), so the CI check is meaningful.
Runtime confirmation on the Samba lab is still `[LAB]`; Recycle Bin and deleted-object checks are
**Windows-lab only**. The Windows lab is the oracle.

**Proof TM-F-RIGHTS.** Lab: an identity in Domain Admins, one in Account Operators, one with
GenericAll on the Domain Controllers OU, one with WP on a C1 group's `member`, one with
Reset-Password inherited onto AdminSDHolder-protected users, one with constrained delegation to
`ldap/<DC>` — each refused activation; a correctly delegated identity passes; the health check
lists both excessive and missing rights. Entra half: §6.6.

### 6.6 Entra ID / Graph permissions for v1 — DECISION TM-D5

Source: Graph least-privilege research for T-0007 (Microsoft Learn pages, 2026-10-02). Scope: ADM-159,
160, 161, 162, 164, 169, ADM-009 (bulk), I360-003 (delta). The app is the customer's own
registration with a certificate; it holds **no Entra directory role**.

**Allow list** (grant only the rows whose feature is enabled):

| Feature | Graph call | Application permission |
| --- | --- | --- |
| ADM-159 tenant and domains | `GET /organization` | `Organization.Read.All` ([ref](https://learn.microsoft.com/en-us/graph/api/organization-get?view=graph-rest-1.0)) |
| ADM-161 read SKUs | `GET /subscribedSkus` | `LicenseAssignment.Read.All` ([ref](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0)); `Organization.Read.All` also covers it |
| ADM-161 user and group licences | `POST /users/{id}/assignLicense`, `POST /groups/{id}/assignLicense` | `LicenseAssignment.ReadWrite.All` ([user](https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0), [group](https://learn.microsoft.com/en-us/graph/api/group-assignlicense?view=graph-rest-1.0)) |
| ADM-160, ADM-009 create users | `POST /users` | `User.Create` ([ref](https://learn.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0)) |
| ADM-162 update properties, UPN | `PATCH /users/{id}` | `User.ReadUpdate.All` ([ref](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0)); UPN coverage `[UNVERIFIED — lab]` |
| ADM-162 reset password | `PATCH /users/{id}` `passwordProfile` | `User-PasswordProfile.ReadWrite.All` (same page); whether app-only also needs User Administrator is **contradictory on Microsoft's page** `[UNVERIFIED — lab]` (see below) |
| ADM-162 block / unblock | `PATCH` `accountEnabled` | `User.EnableDisableAccount.All` + `User.Read.All` (same page) |
| ADM-162 hard delete, restore | `/directory/deletedItems/{id}` | `User.DeleteRestore.All` ([delete](https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-delete?view=graph-rest-1.0), [restore](https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-restore?view=graph-rest-1.0)) |
| ADM-162 soft delete; set/remove manager | `DELETE /users/{id}`; `/manager/$ref` | `User.ReadWrite.All` is the only documented permission ([delete](https://learn.microsoft.com/en-us/graph/api/user-delete?view=graph-rest-1.0), [manager](https://learn.microsoft.com/en-us/graph/api/user-post-manager?view=graph-rest-1.0)) — **conditional**: granted only when these features are enabled; whether `User.DeleteRestore.All` suffices for soft delete is `[UNVERIFIED — lab]` |
| ADM-162 revoke sessions | `POST /users/{id}/revokeSignInSessions` | `User.RevokeSessions.All` ([ref](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0)) |
| ADM-160 invite guests | `POST /invitations` | `User.Invite.All` ([ref](https://learn.microsoft.com/en-us/graph/api/invitation-post?view=graph-rest-1.0)) |
| ADM-164 create groups | `POST /groups` | `Group.Create` ([ref](https://learn.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0)) |
| ADM-164 update, delete, owners | `PATCH`/`DELETE /groups/{id}`, `owners/$ref` | `Group.ReadWrite.All` in practice ([update](https://learn.microsoft.com/en-us/graph/api/group-update?view=graph-rest-1.0)); it also reads M365 group conversations — accepted, feature-gated |
| ADM-164 membership | `members/$ref` | `GroupMember.ReadWrite.All` ([ref](https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0)) |
| ADM-169 hybrid view; I360-003 user delta | `GET /users`, `/users/delta` | `User.Read.All` ([delta](https://learn.microsoft.com/en-us/graph/api/user-delta?view=graph-rest-1.0)) |
| I360-003 group delta | `GET /groups/delta` | `GroupMember.Read.All` (the page's `Group-NestingSupport.ReadWrite.All` looks like a documentation artefact) ([ref](https://learn.microsoft.com/en-us/graph/api/group-delta?view=graph-rest-1.0)) |
| Last sign-in reports | `signInActivity` | `AuditLog.Read.All` + `User.Read.All`; Entra ID P1/P2 ([ref](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0)) |
| Admin pre-flight (tier-0 guard) | memberOf, role assignments | `Directory.Read.All`, `RoleManagement.Read.Directory` — reading roles is not managing them |
| Hybrid-trust monitor (§6.8, §6.9) | `GET /auditLogs/directoryAudits` | `AuditLog.Read.All` — **optional, recommended** whenever a HybridLink exists. Without it the attestation's age is the only demotion trigger and connection health says change monitoring is off (DM-10.I7(d)). The last-sign-in row grants the same permission |
| Hybrid-trust attestation (§6.8) — **delegated, not app-only** | `GET /directory/onPremisesSynchronization` | Delegated `OnPremDirectorySynchronization.Read.All`, used inside a Global Administrator's interactive sign-in. Application permission is "Not supported" and "Global Administrator is the only role supported" ([ref](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-get?view=graph-rest-1.0)) |

Distribution and mail-enabled security groups are read-only in Graph (Exchange only)
([groups overview](https://learn.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)).

**Deny list** (onboarding refuses activation if any is granted; override as TM-D1):
`Directory.ReadWrite.All`; `RoleManagement.ReadWrite.Directory`;
`RoleAssignmentSchedule.ReadWrite.Directory`, `RoleEligibilitySchedule.ReadWrite.Directory`;
`PrivilegedAccess.ReadWrite.*` and the PIM schedule write permissions; `Application.ReadWrite.All`;
`Application.ReadWrite.OwnedBy`; `AppRoleAssignment.ReadWrite.All` (it can grant itself
`RoleManagement.ReadWrite.Directory` — Microsoft's caution: "grant additional privileges to
itself"); `DelegatedPermissionGrant.ReadWrite.All`; `EntitlementManagement.ReadWrite.All`;
`UserAuthenticationMethod.ReadWrite.All`; `Policy.ReadWrite.*`; `Domain.ReadWrite.All`;
`AdministrativeUnit.ReadWrite.All`; `User-OnPremisesSyncBehavior.ReadWrite.All` and its group and
contact counterparts (SOA transfer), `OnPremDirectorySynchronization.ReadWrite.All` (tenant sync
features, §6.8), `Synchronization.ReadWrite.All`; `User-Phone.ReadWrite.All`, `User-Mail.ReadWrite.All`,
`User.ManageIdentities.All` (SSPR contact data and sign-in identities)
([permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference),
[overview](https://learn.microsoft.com/en-us/graph/permissions-overview)).

**Graph's own protections, because the app holds no role.** With application permissions alone the
app cannot change sensitive properties of, delete, or restore users who hold an admin role, or who
own or are members of role-assignable groups
([user-update](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0),
[users](https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-perform-sensitive-actions)).
Role-assignable group membership needs `RoleManagement.ReadWrite.Directory`; "`Group.ReadWrite.All`
won't work" ([groups-concept](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept)).
Objects in a restricted management administrative unit (RMAU) are protected from **every**
property write, not only sensitive ones: "Applications can't modify objects in restricted
management administrative units by default", and "If you assign Microsoft Graph application
permissions to the application, those permissions won't apply because it's restricted". Only an
Entra role scoped to the RMAU lifts it. Microsoft lists as blocked: modifying any Entra property,
deleting, updating a password, and changing an RMAU group's owners or members
([RMAU](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management)).
Our guard (TM-D2) still refuses all writes to role holders and role-assignable groups.

**If password reset needs a role** (lab test G1 below proves it does): v1 does **not** give the app
User Administrator (a PRIVILEGED-labelled role,
[roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)).
Entra password reset is then withheld until a security-architect review of the AU-scoped fallback
(a role scoped to an administrative unit cannot reset users who hold other roles,
[AU roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-assign-roles))
`[OPEN → ADM-162 spec + lab]`.

**Gaps the protections do not cover** (and our guard must): non-admin **owners of app
registrations** can add credentials to their apps
([addKey](https://learn.microsoft.com/en-us/graph/api/application-addkey?view=graph-rest-1.0)), so
resetting such an owner takes over the app; security groups that grant access (not
role-assignable) are writable with `GroupMember.ReadWrite.All` (Microsoft's control is the RMAU);
PIM-eligible-only admins may not count as admins `[UNVERIFIED — lab]`. The Entra `tier0` set
(§6.4 E1–E5) covers all three: PIM-eligible holders, the owners of privileged apps, and
role-granting groups (§7.7).

**A stolen certificate can add a new credential.** `addKey` takes a proof signed by an existing
certificate, and "an application doesn't need any specific permission to roll its own keys"
([addKey](https://learn.microsoft.com/en-us/graph/api/application-addkey?view=graph-rest-1.0));
`removeKey` uses the same proof, so a thief can also lock us out. Withholding `Application.ReadWrite.*`
does **not** prevent this. Mitigations, documented for the customer at onboarding: the app has
**no owners**; Conditional Access for workload identities restricts token issuance to the
activeDIQ host's egress addresses (needs Workload ID Premium,
[CA for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity));
app-management policies (`asymmetricKeyLifetime`, beta `trustedCertificateAuthority`) — whether they
bind `addKey` is `[UNVERIFIED — lab]`, and their licence requirement is `[UNVERIFIED]`; alert on
"Update application – Certificates and secrets management" in the Entra audit log. activeDIQ itself
compares the app's key credentials with the thumbprint it holds on every health check and flags
any extra key.

**Verification (Entra half of TM-F-RIGHTS).** Onboarding and health check read the service
principal's own `appRoleAssignments` and directory-role memberships, refuse on any deny-list
permission or any role, flag permissions beyond the enabled features' rows, and flag extra key
credentials and owners. Lab tests to clear the `[UNVERIFIED]` items: G1 password reset with
`User-PasswordProfile.ReadWrite.All` and no role; G2 soft delete with `User.DeleteRestore.All`;
G3 UPN change with `User.ReadUpdate.All`; G4 `revokeSignInSessions` against an admin with no role;
G5 `Group.ReadWrite.All` adding an owner to a role-assignable group; G6 PIM-eligible-only admins,
and reading eligibility with `RoleManagement.Read.Directory`; G7 app-management policies and
`addKey`; G8 the directory-audit activities that record a change to the tenant sync features and
an SOA transfer, which the §6.8 monitor keys on; G9 whether an Entra-side reset with password
writeback reaches an AD account in a protected group (E5); G10 the directory-audit activities that
record a TAP being created, authentication methods being reset or registered by another actor, and a
domain's authentication changing to federated (TM-D19 rule 4).

**The customer's independent record.** Service-principal sign-in logs ("can't be changed or
deleted"), Entra audit logs filtered by our appId, and Graph activity logs (P1/P2, if routed to a
workspace) show what our app did, independently of our audit
([SP sign-ins](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-service-principal-sign-ins),
[Graph activity logs](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)).

### 6.7 ADM-134 per-technician attribution — DECISION TM-D6

**(a) Prohibited: Kerberos constrained delegation with protocol transition** (S4U2Self +
S4U2Proxy) from the connector to `ldap/<DC>`. S4U2Self lets the connector obtain a ticket for any
user not marked sensitive or in Protected Users — **including Domain Admins** — and the service
name in the resulting ticket is not integrity-protected, so a ticket for `ldap/DC` can be
retargeted to other services on the DC (ad-expert consult §E).
Configuring it also needs SeEnableDelegationPrivilege. activeDIQ would be Tier 0 by construction
(FEAS §2.1's test). **RBCD on DC objects is prohibited too:** writing a DC object is itself Tier 0,
and under RBCD "S4U2Proxy … works when provided with a non-forwardable TGS by design", so protocol
transition is effectively always available
([Wagging the Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)). §6.5 step 5
checks that neither is configured.

**(b) Not in v1: per-session technician credentials** (the technician's AD password turned into a
TGT held in connector memory). Reasons: a compromised server would harvest every technician's
password at sign-in — the credential-harvesting pattern of the attacks on the competitor (KdcSponge,
Wdigest; ME-SEC §4.2); Tier-0 technicians would expose Tier-0 credentials on a management host,
breaking the clean-source principle; it breaks stateless nodes (ADR-0002 rule 6); in SaaS the
password would transit the cell. If ever offered: opt-in, never for `tier0` technicians, TGT
retained and never the password, connector memory only, bound to the session, with its own
security review.

**(c) v1 mechanism.** Our tamper-evident audit records technician, factor and operation ID for
every write (§11). AD shows the connector identity. **[M3]** the `addc` event pipeline correlates
DC events (5136, 4738, 4728, …) to the operation by objectGUID + attribute + originating DC + time +
subject = connector, so every native AD event of ours is attributed to a technician in reports
and in the SIEM export. Optional coarse attribution inside AD: one connector identity per role
family (for example help desk vs provisioning) is allowed by this model; feasibility per platform
is `[UNVERIFIED]` and the ADM-134 spec decides.

**Note for the product-manager.** ADM-134's "attribution visible in AD's own logs" leapfrog is
delivered through (c) and the M3 correlation, not through AD-native subject fields.

### 6.8 Cross-directory authority (hybrid correlation) — DECISION TM-D17

**The path.** A correlation (DM-20) between an AD object and an Entra object carries authority in
three places: SSO binding (DM-30.I5), AD scope reaching Entra objects (`include_correlated`,
DM-35.I6) and directory-group grants (DM-36.I2). Each is a bridge between two administrative
domains. A **forged anchor** would let an Entra administrator cross that bridge.
Certain privileged roles can write `onPremisesImmutableId` on cloud-only users
([user](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)), and an AD
admin's `objectGUID` is readable by any domain user. If a correlation matched on that value, a
cloud-only identity would sign in through SSO and inherit an AD admin's activeDIQ grants (DM §12
S1). **Takeover through hard or soft match** gives the same result without forging anything. An
attacker pre-creates a cloud user carrying a target's anchor or UPN. When the target enters sync
scope, the sync client takes that object over, every attribute check passes, and the sign-in
methods the attacker registered stay. Microsoft's own hardening guidance says to disable both soft
matching and hard-match takeover
([Entra Connect prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)).

**TM-D17 — DM-20.I4 (a)–(e) are confirmed, (f) is kept, and the gate is tightened:**
1. **(f) stays strict.** Both `blockCloudObjectTakeoverThroughHardMatchEnabled` **and**
   `blockSoftMatchEnabled` must be true. The architect's soft-match extension is kept, not relaxed:
   soft match produces the same takeover, and Microsoft recommends blocking it. Failing (f) does not
   stop the product. Roles are then granted to console accounts directly, or through IdP claims
   (TM-TB8-T7), instead of through correlation.
2. **(f) is attested, because it cannot be read app-only (confirms DM-10.I7).**
   `GET /directory/onPremisesSynchronization` supports only delegated permissions, and only for
   Global Administrator (§6.6).
   - **Start.** An account holding `connections.takeover.attest` over the Entra connection's
     `entra_tenant` scope starts an attestation, with step-up (§7.4).
   - **Read.** A Global Administrator of that tenant signs in through authorization code + PKCE.
     The flow requests only delegated `OnPremDirectorySynchronization.Read.All`, with no
     `offline_access`. The server makes the one read itself and rejects a token whose `tid` is not
     the connection's tenant. It records both values, the attester's object ID and the time in the
     audit, then **discards the token**.
   - **State.** `takeover_protection` is `attested` only while three things hold: both values were
     `true`; `attested_at` is younger than `attestation_max_age`; and no demotion signal (rule 3)
     has arrived since. `attestation_max_age` is **90 days by default and at most**; a tenant may
     shorten it. Otherwise the state is `unattested`, `open` or `stale`, and every correlation in
     the tenant is `candidate` with reason `tenant_takeover_open`. This is DM-10.I7's vocabulary.
   - **Link confirmation is a separate act.** Confirming or declaring a HybridLink needs
     `connections.hybrid_link.confirm` over both sides (DM-21.I2).

   **Why 90 days, not 30.** The first draft said 30; this revision settles on 90, which matches
   DM-10.I7(c) and notice D-0009. The age only bounds a flag flip that the monitor missed. Only E4
   roles can flip the flags, and they are Tier 0 by designation. Rule 4 (g) independently refuses
   any correlation whose Entra object our sync ever saw cloud-only or cloud-managed. That catches a
   takeover of any object activeDIQ observed before the takeover, whatever the attestation's age.
   Connection health warns 14 days before expiry (DM-10.I7(c)).
3. **Change monitor (optional, recommended).** With `AuditLog.Read.All` (§6.6), the app-only
   identity polls the Entra directory audit for sync-feature changes and SOA transfers. A
   sync-feature change makes the state `stale` at once (DM-10.I7(d)). Activity names are
   `[UNVERIFIED — lab G8]`. Without the permission, or until the lab confirms the names, age is the
   only trigger, and connection health says change monitoring is off. Microsoft's SOA rollback
   procedure turns hard-match blocking **off** and back on
   ([user SOA](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure)),
   so a legitimate flip does happen; with the monitor it is caught.
4. **(g) Eligibility only goes down.** A correlation whose Entra object our sync has *ever*
   observed as cloud-only (`onPremisesSyncEnabled` not `true`) or cloud-managed (`isCloudManaged`)
   cannot become `matched` again by itself. Neither can a correlation that first became eligible
   **after** the tenant's first `attested` state, while the state was `open` or `stale`. Either
   becomes `matched` only when a `tenant-owner` re-confirms it with step-up (§7.4), and that
   confirmation is audited. This catches a takeover our sync observed, even if both flags are on
   again by the time anyone looks. It also catches one that slipped in while an attestation had
   lapsed.
   - **The install-time population.** Some correlations are already eligible when the tenant
     first reaches `attested`. They formed while the tenant was `unattested`, or `open` because
     the first read found a flag off; both flags default to `false`, so that path is common. These
     correlations become `matched` on that first attestation, unless the first sentence of this
     rule applies to them. Until then they are `candidate` like every other correlation (rule 2),
     so none of them carries authority before it. A new hybrid tenant can hold thousands of them,
     and a review one by one would become a rubber stamp. Takeovers among them that our sync never
     observed are TM-R11. TM-D19 rule 2 still denies them AD-side authority without an AD-plane
     proof.
5. **(h) Some authority never crosses a correlation.** It never carries `tenant-owner` or any
   permission that administers RBAC, delegation scopes or connections. Those are assigned only to
   the console account itself (DM-30). It never reaches a `tier0` object on either side (TM-D2,
   C16, E5).

Rules 4 (g) and 5 (h) are this document's tightening of DM-20.I4. T-0061 carries them, and
TM-D19, into the domain model.

**Residuals, confirmed as Tier 0 (closes the sync-plane part of DM-20.I6).** Control of the sync client — the Entra
Connect server, a Cloud Sync agent host, or the Directory Synchronization Accounts role — makes
(a)–(e) pass. So does changing the tenant's sync features or transferring SOA (Hybrid
Administrator). The gate cannot defend against these. They are in `tier0` (customer-designated
hosts, E4), activeDIQ never holds a permission that does any of them (deny list, §6.6), and
TM-R11 records the rest. Takeovers that happened **before** activeDIQ was installed are invisible to
rule 4 (TM-R11). So are takeovers in the install-time population that our sync never saw
cloud-only (rule 4, second bullet). TM-D19 rule 2 still denies both AD-side authority without an
AD-plane proof. The
authentication-plane part of DM-20.I6 is §6.9.

**Synced administrators.** An AD account that holds an Entra role is in AD `tier0` through C16. A
help-desk password reset therefore cannot become a Global Administrator takeover through password
hash sync. Microsoft's guidance is that no on-premises account should hold such a role ("Use
cloud-only accounts for Microsoft Entra ID and Microsoft 365 privileged roles",
[protect M365](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks)).
The hardening report (ENH-08) lists every synced role holder as a finding.

**Proof TM-F-HYBRID.** CI with a fake Graph, plus Samba. None of these grants authority:
- `onPremisesImmutableId` forged on a cloud-only user → `candidate`;
- `isCloudManaged` set, or the SID differs → `candidate`;
- the attestation is missing, expired or voided by a monitored feature change → all `candidate`;
- an object once seen cloud-only that is now synced → `candidate` until re-confirmed with step-up;
- a correlation present before the tenant's first attestation, through `unattested` and then
  `open` → `matched` when the first `attested` state lands, with no re-confirmation; if its Entra
  object was once seen cloud-only → still `candidate`;
- a correlation that first appears while the state is `stale` or `open` after an earlier
  attestation → still `candidate` after the re-attestation, until a `tenant-owner` re-confirms it
  with step-up;
- an attestation flow that stores a token, or asks for any scope beyond the one listed → the test fails;
- a role granted to an AD group never carries `tenant-owner` across a correlation;
- the TM-D19 cases listed in §6.9.

Every refusal is audited with its reason. Protection side: an AD user with a `candidate`
correlation to an Entra Global Administrator is refused a password reset (C16). An Entra object
correlated to a Domain Admin is refused a write (E5).

### 6.9 The authentication-plane residual — DECISION TM-D19

**The path (closes the authentication-plane and history parts of DM-20.I6).** A `matched`
correlation is legitimate. Even so, whoever can sign in to Entra as the synced technician inherits
the AD-side group grants that reach an `sso` account through it (DM-30.I5, DM-36.I2):
- **TAP and method resets.** Privileged Authentication Administrators "can create, delete, and view
  a TAP for admins and members". Authentication Administrators can do the same "for members" —
  and activeDIQ technicians are usually members, not Entra admins. Authentication Policy
  Administrators decide who may sign in with one
  ([TAP](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)).
  The same page says users "can sign in with a TAP to onboard other passwordless authentication
  methods". So a TAP holder can register a passkey, and then satisfies even a phishing-resistant
  authentication strength.
- **Federation.** The Hybrid Identity Administrator role manages "federation settings"
  ([roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)),
  and the identity provider of a federated domain signs in that domain's users.
- **History.** An object taken over while the takeover flags were off keeps the sign-in methods the
  attacker registered on it (DM-20.I6).

None of these roles is Tier 0 for AD. Without a control, an Entra help-desk role becomes AD-side
authority through activeDIQ.

**TM-D19 — the Entra authentication plane alone never carries AD-side authority.**
1. **Authority factor.** An `sso` account uses AD-side grants that reach it through a correlation
   only in a session that has also verified an **activeDIQ-held WebAuthn credential** of that
   account (DM-37, `webauthn`). This covers DM-36.I2 group grants through an `oid` or `onprem_sid`
   binding. The factor is checked at first use in the session and again at every §7.4 step-up.
   Without it the session keeps Entra-side grants and grants made to the account itself. This is
   the same degraded mode as an unattested tenant, so nothing breaks. `directory` accounts already
   use an activeDIQ-held factor, so the two kinds of account become symmetric.
2. **Enrolment is anchored outside Entra.** The authority factor can be enrolled in one of two
   ways:
   - in a ceremony that also proves the correlated AD account (connector `VerifyUser` or SPNEGO,
     BP §11);
   - after a `tenant-owner`'s approval with step-up.

   Every enrolment is audited and notifies the account and every `tenant-owner`. No Entra role can
   enrol, reset or remove the factor. A reset is a `tenant-owner` action with step-up, and it is
   audited.
3. **AD-plane alternative.** Where the PRD offers SPNEGO sign-in, a session that authenticated the
   correlated AD account by Kerberos satisfies rule 1 without the factor. This is zero-touch on a
   domain-joined admin workstation `[OPEN → ADM-143 spec]`.
4. **Signals, alert only.** With `AuditLog.Read.All`, the TM-D17 monitor also watches the bound
   Entra objects of technicians that hold correlation-derived grants. It raises an alert to every
   `tenant-owner` when one of these is detected: a TAP created, methods reset or registered by
   another actor, or the user's domain switching to federated. Activity names are
   `[UNVERIFIED — lab G10]`. Rule 1 is the control; these signals only shorten detection.
5. **Console-backing objects are escalation objects** (the account analogue of TM-D18). The
   following objects back a console account:
   - the AD object of a `directory` account;
   - the object an `sso` account is bound to;
   - any object correlated to either.

   Through activeDIQ, these changes to such an object need an actor who holds every privilege the
   backed account holds (DM-36.I1): resetting its password, unlocking or enabling it, changing its
   UPN or sign-in name, and moving it. Otherwise the change is refused. The Entra app never writes
   authentication methods (§6.6 deny list).
6. **These roles are not added to E4.** With rules 1 and 2 they reach no AD-side authority through
   activeDIQ. They stay in E1, where every role holder is write-protected.
   - **Recommended customer hardening** (setup guide and a health hint): put hybrid technicians'
     Entra accounts in a restricted management administrative unit. That blocks tenant-scope
     administrators, Global Administrator included, from updating their passwords or properties.
     It needs Entra ID P1 for each AU administrator
     ([RMAU](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management)).
   - **Consequence, intended.** The same page, under Programmability: "If you assign Microsoft
     Graph application permissions to the application, those permissions won't apply". So
     activeDIQ cannot write those technicians' Entra accounts at all: no property, no password, no
     deletion. That is intended. It fits rule 5, under which a console-backing object is already an
     escalation object, and the only lever that would lift it is an Entra role scoped to the RMAU,
     which TM-D5 never grants the app. The RMAU's scoped administrators manage those accounts in
     Entra; activeDIQ shows them as protected (a health hint, not a failure).

**Alternatives rejected.**
- **An authentication strength, or an `acr` / authentication-context claim.** A TAP lets its holder
  register a passkey, which then satisfies the requirement.
- **Refusing TAP sign-ins by `amr`.** Whether a TAP sign-in is distinguishable in the ID token is
  `[UNVERIFIED]`, and the passkey registered with the TAP is not distinguishable.
- **Adding the roles to Tier 0.** A designation does not stop anyone from acting in Entra.

**Residual (TM-R12).** Someone who controls both planes at enrolment can enrol an authority factor.
That means holding the AD password (or a `tenant-owner` approval) and the Entra sign-in. An
attacker with both is, in effect, that technician. The history residual reduces to this case: an
object taken over before install still needs an AD-plane proof at enrolment.

**Customer-visible.** Hybrid SSO technicians enrol one activeDIQ passkey once, proving their AD
password. They touch it once per session before AD-side group authority applies. This is a notice
for the CEO (factory-director files it), like D-0009.

**TM-F-HYBRID cases for TM-D19.** CI, with a fake IdP and Samba:
- an `oid`-bound account with a `matched` correlation and an AD group grant, signed in through
  Entra only, holds no AD-side grant until its authority factor verifies;
- an enrolment with neither an AD-plane proof nor an owner approval is refused;
- a simulated Entra-side method reset leaves the activeDIQ factor untouched;
- a technician resetting, through activeDIQ, the AD password of a console account that holds more
  privileges than they do is refused (rule 5).

---

## 7. Console authentication, sessions and RBAC

Builds on BP §11 and SB §6–§7. Owner: backend-engineer (`platform/authn`, `platform/authz`);
security-architect reviews every change here.

### 7.1 Principals

| Principal | Authenticates with | Tenant from | Notes |
| --- | --- | --- | --- |
| Console user (technician, administrator, requester) — DM-30 | SSO (OIDC or SAML) + MFA; break-glass local account + MFA; optionally AD identity through the connector | The session (DM-31) | MFA for every console user |
| API token — DM-32 | Bearer token in the `Authorization` header | The token's owner | Owner ∩ token subset |
| Remote connector, agent [M3] — DM-12 | mTLS client certificate | Certificate SAN | Never a console or API principal |
| Anonymous end-user flow — DM-04 | Inside the flow (AD sign-in for TOTP enrolment; factors for SSPR [M4]) | Hostname binding | Only anonymous-flow capabilities, never console or API (DM-04.I2) |

### 7.2 Sign-in

- **SSO first.** OIDC is preferred. SAML is supported through one package with a vetted, maintained
  library (licence-register row first), the algorithm pinned, signed assertions required, and a
  signature-wrapping fuzz corpus. The lesson is the competitor's pre-auth RCE through an outdated
  XML-DSig library in SAML handling, CVE-2022-47966 (ME-SEC §4.1, §4.3 "third-party components").
- **MFA for every console user.** WebAuthn/passkeys are preferred; TOTP is allowed. MFA claims from
  the IdP are accepted only when the tenant configures that IdP as MFA-asserting `[OPEN → ADM-143
  spec]`. Local accounts exist only for break-glass, always require MFA (DM-30.I1, ADM-142), and
  every use raises an alert to all `tenant-owner` accounts. AD-side grants that reach an `sso`
  account through a correlation also need the activeDIQ-held authority factor (TM-D19).
- **First run.** TLS from first boot with a per-install generated certificate; its fingerprint is
  shown by the installer. The first account is created with a one-time setup secret. There is never
  a default credential (DM-30.I3, ADM-145).
- **AD-identity sign-in** (if the PRD offers it) goes only through the connector's `VerifyUser` or
  SPNEGO acceptor, never an LDAP bind from platform code (BP §11). The empty-password guard applies
  (an empty password is an anonymous bind that "succeeds"; SP PW-08). Our per-account failure
  counter stops below the domain's lockout threshold, so sign-in cannot be used to lock users out.

### 7.3 Sessions

| Property | Rule |
| --- | --- |
| Storage | Server-side in PostgreSQL (DM-31), so any node serves it (ADR-0002 rule 6); the ID is stored hashed |
| Cookie | `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, no `Domain` attribute |
| CSRF | Token on every mutation; JSON-only request bodies |
| Timeouts | Idle and absolute, tenant-configurable within platform bounds; concurrent-session limit (ADM-145) |
| Revocation | On account disable (DM-31.I2), on role change of the account, on password/MFA reset, and on demand |
| Transport | HSTS on the console; no plaintext listener |

### 7.4 Step-up re-authentication — DECISION TM-D16 (part 1)

These operations require a fresh MFA within a short window, whatever the session age:

| Operation | Why |
| --- | --- |
| LAPS / BitLocker reveal (named secret ops, SP §3.7) | Direct credential disclosure (A7) |
| RBAC changes: roles, assignments, delegation scopes | Escalation path (TM-TB1-T11) |
| API token creation | Creates a standing credential |
| Connector enrollment token creation | Creates a fleet identity (A11) |
| Directory credential or connection changes (DM-10, DM-11) | Re-points or replaces A2 |
| IdP configuration and claim mappings | Re-points sign-in (TM-TB8-T3) |
| Audit export, retention or SIEM-sink changes | Evidence integrity (A5) |
| Break-glass account use | Always alerts |
| The Tier-0 override acknowledgement (TM-D1) | Changes the product's tier |
| HybridLink confirmation (`connections.hybrid_link.confirm`); starting an attestation (`connections.takeover.attest`); re-confirming a correlation (TM-D17) | Opens a cross-directory authority path |
| Approving, enrolling or resetting an authority factor (TM-D19) | Gates AD-side authority reached through Entra sign-in |
| Designating or un-designating `tier0` objects (§6.4) | Widens or narrows the guard |

**Secret-reveal harvesting.** A technician (X4) may reveal secrets one by one within scope. Each
reveal is audited; reveals per technician are rate-limited, and a burst above a tenant threshold
alerts `tenant-owner` accounts `[OPEN → E2.5 helpdesk spec]` for the default numbers.

### 7.5 API tokens

CSPRNG with at least 128 bits of entropy; prefixed `adq_` so secret scanners can find leaked
tokens; stored hashed; scoped (permission subset and scope narrowing); expiry mandatory; shown once;
owner and last use recorded (DM-32, ADM-141). Sent only in the `Authorization` header.

### 7.6 Deny by default and the anonymous allow-list — DECISION TM-D16 (part 2)

Every OpenAPI operation declares exactly one `x-permission` (DM-33.I1). A route without one fails
startup (the CVE-2021-40539 class; ME-SEC §4.1). The routes reachable without a console session or
API token are exactly these:

| # | Route group | Listener | Gate |
| --- | --- | --- | --- |
| AN-1 | Health (liveness and readiness; status only, no version or configuration detail) | Console/API | None |
| AN-2 | Static assets of the embedded web UI | Console/API | None |
| AN-3 | SSO callbacks (OIDC redirect, SAML ACS) and SSO start | Console/API | Signed IdP response (§7.2) |
| AN-4 | First-run setup | Console/API | One-time setup secret; gone after first use |
| AN-5 | v1 end-user TOTP enrolment page (FD-05, DM-04) | Console/API, by hostname binding | End user's own AD authentication inside the flow (TM-TB1-T13) |
| AN-6 | Fleet `Enroll` RPC | Fleet gRPC | Single-use, short-lived, rate-limited token |
| AN-7 [M4] | SSPR flows | Edge tunnel router, or console/API listener by hostname binding | Factors inside the flow |

**Proof TM-F-ANON.** The set of routes the built router serves without authentication equals a
reviewed allow-list file kept in the API contract tree, with `security-architect` as its CODEOWNER.
Any difference fails CI. This is part of T-0046's API fitness. Adding a row to the table above is a
§14 trigger.

### 7.7 Authorisation

- **Effective permission = role ∩ delegation scope ∩ token scope**, checked on the **target object**,
  server-side, for every item of a bulk job; Plan re-reads the live parent chain from the DC, so a
  moved object cannot escape between check and write (BP §11, DM-35.I2).
- **No escalation.** No role can grant more than its grantor holds (DM-36.I1).
- **Tiered model.** No role touches a `tier0` object in v1 (DM-16.I8, DM-35.I5). This is enforced
  by the authorisation layer **and** by the guards of TM-D2; no permission or scope can lift it.
- **Privileged groups that are not `tier0`.** Writes to the groups SB checklist C names are refused
  in v1 when the group is in `tier0` (§6.4 puts most of them there). Any that a forest does not
  classify as `tier0` (and any group a customer designates "sensitive") need a dedicated permission
  and are flagged in audit; the permission name belongs to the delegation spec.
- **Our service account's power is not the user's power.** Authorise the human first, then act
  (SB §7).
- **DECISION TM-D18 — groups that grant activeDIQ roles are escalation objects** (answers the
  DM-36.I2 referral). An AD group grants nothing, and the health check flags it, while its DACL
  lets a broad principal change its membership. Broad principals are Everyone, Anonymous Logon,
  Authenticated Users, Domain Users, Domain Computers and Users. The ACEs that count are the
  Self-Membership validated write (`bf9679c0-0de6-11d0-a285-00aa003049e2`,
  [Self-Membership](https://learn.microsoft.com/en-us/windows/win32/adschema/r-self-membership)),
  WP `member`, GenericWrite, GenericAll, WRITE_DAC and WRITE_OWNER. This is the AD analogue of
  DM-36.I2's "a Public Entra group grants nothing". The role page lists a granting group's owners
  and managers (Entra owners; AD `managedBy` holding WP `member`) as people who can grant that
  role. Microsoft likewise says to "consider owners of groups used for access as privileged
  identities"
  ([protect M365](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks)).
  The no-escalation rule covers membership: changing the membership of a role-granting group
  through activeDIQ requires the actor to hold every privilege that group grants (DM-36.I1).

**Proof TM-F-AUTHZ.** Lab tests: a technician acts on a user just outside the delegated OU
(refused); an object moved out of scope between Plan and Apply (refused); a bulk job with one
out-of-scope item (that item refused, others reported per row); a grant of a role the grantor does
not fully hold (refused); a token whose owner was disabled (dead); a scheduled report whose owner
lost scope (delivers only the new scope or stops); a role-granting AD group whose DACL gives Domain
Users Self-Membership (grants nothing, flagged); a technician adding themselves to a role-granting
group whose privileges they do not hold (refused).

**Proof TM-F-SESSION.** Cookie attributes; CSRF rejection; idle and absolute expiry; revocation on
disable; every operation in the §7.4 list refuses without fresh MFA; API token entropy, prefix,
hashing and mandatory expiry; break-glass use raises the alert.

**Proof TM-F-SSO.** SAML: the signature-wrapping corpus, unsigned assertions, wrong audience,
expired, replayed assertion ID, algorithm substitution, XML external entities — all refused. OIDC:
`alg: none`, wrong `iss`/`aud`, missing `nonce`/`state`, missing PKCE — all refused.

---

## 8. Bounding the management-plane process's public surface

ADR-0002 rule 2 serves the public API, the IdP endpoints and `radius` from the management-plane
process and hands this document the job of bounding them.

**Reference deployment.** The server is never published to the internet. CISA advised keeping the
competitor's self-service product off the internet after CVE-2021-40539 (ME-SEC §4.2,
[AA21-259A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a)). The console
listener supports a source-CIDR allow-list (ADM-145). Internet-facing self-service goes through
`edge` only (TM-O8).

### 8.1 Listeners

| # | Listener | Who connects | Authentication | Exposure |
| --- | --- | --- | --- | --- |
| L1 | HTTPS console + public API | Browsers, scripts, ITSM | Session or API token; anonymous only for §7.6 AN-1 to AN-5, AN-7 | Internal network; source-CIDR allow-list |
| L2 | Fleet gRPC | Remote connectors, [M3] agents | Client certificate required for every RPC except `Enroll` (token-gated, single-use, short-lived, rate-limited) | Internal network, or reachable by on-site connectors (SaaS) |
| L3 [M4] | RADIUS (UDP) | Customer NAS / VPN devices | Per-client shared secret; `Message-Authenticator` required in every request and response; bounded by §5.19 (TB19) and TM-D20 | Internal networks only |
| — | Edge tunnel [M4] | — | Not a listener: the server dials **out** to edge | — |
| — | Bundled PostgreSQL | The server | Loopback only by default; TLS + SCRAM and a host allow-list when nodes are added | Not exposed |

L3 is UDP only. RADIUS over TLS (RadSec, TM-Q18) runs "over TCP", by default on "TCP/2083"
([RFC 6614](https://www.rfc-editor.org/rfc/rfc6614)), so it would be a **second listener**. If the
M4 RADIUS spec adopts it, it gets its own L-row through an RT-6 review (§14) before it ships, and
TM-F-PORTS checks it like any other row.

Through M4, no other listener exists: no debug or profiling port (FF-SP2 bans `pprof`), no
sidecar port, no unauthenticated metrics. **Proof TM-F-PORTS:** on a booted install of each
profile, the listening sockets equal this table; an extra socket fails the boot smoke test (P2).

Two later modules in BP §3.1 are **out of scope for v0** and are an RT-6 trigger (§14) when specced:
- `fpolicy` [M5]: an ONTAP FPolicy external server, which accepts connections from the storage
  system, so it adds a listener `[UNVERIFIED]`;
- `t0-connector` [post-v1]: a new connector boundary.

**RADIUS [M4].** RFC 2865 RADIUS is "susceptible to forgery attacks by a local attacker who can
modify any valid Response … using a chosen-prefix collision attack against MD5 Response
Authenticator signature" (CVE-2024-3596, Blast-RADIUS;
[NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-3596)). The researchers'
mitigation is to "mandate that clients and servers always send and require `Message-Authenticator`
attributes for all requests and responses" ([blastradius.fail](https://www.blastradius.fail/)). Our
listener requires it, uses a distinct secret per client, accepts only registered client addresses,
and is never exposed beyond internal networks. The full STRIDE table is §5.19 (TB19). Sharing the
`server` process is bounded by **TM-D20**: an EAP method, a non-Go TLS stack or a missed fuzz or
flood budget moves `radius` into `cmd/radius` (TM-Q26). RADIUS over TLS is preferred where
clients support it (TM-Q18).

**IdP endpoints [M4].** If activeDIQ acts as an IdP for end users on the internet, those endpoints
are served only through `edge`.

### 8.2 The edge tunnel — DECISION TM-D11

```
 internet --TLS--> edge (DMZ / our cloud)  <==== mTLS tunnel, dialled OUT by the server ====  server
                   - public TLS key                                                       |
                   - tunnel client identity                                    separate router instance:
                   - no directory credential,                                  mounts ONLY the SSPR
                     no tenant key, no database                                route group (AN-7)
```

- The server dials **out** to edge over mTLS; both sides are pinned to the installation CA
  (BP §3.1). No inbound firewall hole into the AD network.
- The tunnel lands on a **separate router instance** that mounts only the SSPR route group. Admin
  and API routes are not mounted there at all. Isolation is structural, never path filtering.
- Edge holds only its public TLS key and its tunnel identity. It holds no directory credential,
  tenant key or database (ADR-0002 rule 2: "assumed compromised").
- **Abuse controls are server-side.** Per-account limits on the server are authoritative. Per-IP
  limits and the client IP reported by edge are advisory, because a compromised edge can lie.
- **Residual, stated honestly (TM-R5).** An L7 edge terminates TLS, so while compromised it sees
  SSPR plaintext: new passwords and OTPs. MFA, short OTP lifetimes and an immutable signed edge
  image bound it. The alternative, L4 passthrough, removes that exposure but makes the server parse
  internet TLS and HTTP directly. `[OPEN → M4 SSPR spec]`; the security preference is L7 with
  schema validation at both ends.

**Proof TM-F-EDGE [M4].** Through the tunnel, every admin and API path returns not-found from the
router (it is not mounted); a tunnel peer without the installation CA's certificate is refused in
both directions; the edge image contains no directory-credential, `store` or `keys` code (P1 binary
hygiene); request decoders are fuzzed (FF-SP5).

---

## 9. Secrets handling

### 9.1 Inventory

| Secret | Where | Protected by | Who may use it | Rotation | On compromise |
| --- | --- | --- | --- | --- | --- |
| KEK | Key provider: DPAPI-NG/TPM (`windows`); TPM2, KMS, Vault or passphrase keystore (`linux-oci`); KMS (`saas`) | OS / KMS policy bound to the service identity | `platform/keys` only | Operator-initiated; re-wraps DEKs only | Rotate KEK **and** all DEKs (TM-D15); rotate every sealed credential |
| DEK versions (DM-02) | PostgreSQL, wrapped | KEK; plaintext in memory only (DM-02.I3) | `keys`, inside the tenant's `WithTenantTx` | Yearly, on suspicion, on demand (TM-D15) | Rotate DEK; rotate the credentials it sealed |
| gMSA password | Not stored by us; computed by DCs from KDS keys | AD: only authorised hosts retrieve it | The connector's process identity | Automatic, by AD | §6.1 |
| Keytab | File on the connector host (Linux) | File ACL 0400, read-only mount | Connector only | Host CLI re-key (new key version) | Reset the account's keys; revoke |
| AD password fallback | Sealed in PostgreSQL (embedded) or by the host key provider (remote, TM-D8) | DEK + associated data (TM-D7) | Connector only | Customer-driven; age surfaced, alert on age | Reset the AD password |
| Entra certificate private key | Sealed in PostgreSQL (embedded); generated on the host, non-exportable where possible (remote, TM-D8) | DEK + associated data; or host key store | Connector only | Before `not_after`: new key, upload public cert, remove old | Remove the credential from the app registration |
| Fleet CA key | Server, sealed | DEK (per-tenant issuing CA preferred in SaaS) `[OPEN → connector spec]` | `fleet` only | CA rollover with overlap | Re-enroll every component |
| Enrollment tokens | Hashed (DM-12) | Single use, short life | Issuer (step-up) | n/a | Revoke the token or the component |
| API tokens | Hashed (DM-32) | — | Owner | Mandatory expiry | Revoke |
| Session IDs | Hashed (DM-31) | — | — | Idle/absolute expiry | Revoke sessions |
| MFA seeds; WebAuthn credentials | Seeds sealed (DM-37); WebAuthn stores public keys only | DEK + associated data | `authn` | Re-enrolment | Revoke and re-enrol |
| SMTP / SMS / ITSM / SIEM / HR credentials | Sealed (DM-82, DM-85, DM-63) | DEK + associated data | `notify`, `itsm`, `lifecycle` | In the UI; never returned | Rotate at the peer |
| Audit checkpoint signing key | Sealed | DEK; public key exported with checkpoints | `audit` | Rotation recorded in the chain `[mechanics → T-0047]` | Re-anchor; earlier anchored checkpoints stay valid |
| Edge tunnel key [M4] | Edge host | Host ACL | Edge | Certificate rollover | Revoke the tunnel certificate at the server |
| Agent-policy signing key [M3] | Sealed (BP §12) | DEK | Policy signer in the management plane | `[OPEN → T-0040]` | Bounded by TM-D14: policy is data |
| Release-signing keys | **skenzeriq only**: offline root, HSM/KMS (T-0027) | HSM/KMS | CI release job | TUF root rotation | §10 |
| First-run setup secret | Installer output | OS ACL | Installing administrator | One use | Reinstall |

Customer installs hold **public keys only** for release signing: the pinned TUF root.

### 9.2 Key hierarchy and sealing — DECISION TM-D7

```
KEK (profile adapter: DPAPI-NG/TPM | TPM2/KMS/Vault/passphrase | KMS)
  └── per-tenant DEK, versions v1..vn  (wrapped; KMS profiles: tenant ID as encryption context)
        └── sealed values: Entra key, AD password fallback, MFA seeds, integration credentials,
            audit checkpoint key, agent-policy key, fleet CA key
```

**Seal = AEAD with associated data** that binds `(tenant_id, owning table, row id, column, key
version)`. A sealed blob copied into another tenant's row, another row of the same tenant, or
another column fails to open. An attacker with database write access therefore cannot swap Entra
certificates between tenants or credentials between connections. In KMS profiles the DEK wrap uses
the tenant ID as encryption context, so a wrapped DEK moved between tenants fails to unwrap.

**Proof TM-F-SEAL.** Copy a sealed value to another tenant's row, another row and another column:
each open fails with a typed error and no plaintext; a DEK wrapped for tenant A fails to unwrap as
B (KMS profile, fake KMS); tampering with one byte fails.

### 9.3 DEK rotation — DECISION TM-D15 (answers DM Q2)

1. Create DEK version *n+1* as `active`; version *n* becomes `retired` (decrypt-only) in the same
   transaction (DM-02.I1).
2. A background re-seal job runs per tenant in `WithTenantTx` batches: open with the recorded
   version (DM-02.I2), seal with *n+1*, write. Idempotent; resumable after a crash.
3. When no sealed value references version *n*, it is shredded (DM-02.I4).
4. Triggers: yearly; on suspected compromise; on demand by the installation operator or
   `tenant-owner`. Every step is audited.
5. **KEK rotation** re-wraps the DEK versions only; sealed values are untouched.

A suspected compromise of a DEK also means the **credentials it sealed** must be rotated at their
source; re-sealing alone does not help if the plaintext was read.

### 9.4 Remote connector credentials — DECISION TM-D8 (closes BP §7.3 OPEN)

**Credentials exist only where they are used.**
- A remote connector's Entra key is generated **on its own host**: non-exportable in CNG or the TPM
  where available, otherwise a 0600 file. The administrator uploads only the public certificate.
- An AD password fallback on a remote host is sealed by that host's key provider.
- **Nothing secret is ever pushed over fleet.** Rotation is a host-side CLI action at installation
  operator scope.
- The server keeps public metadata only (DM-11 `connector_local`).

### 9.5 Secret memory policy (SP §5.6 hand-off)

We zero only buffers we own. The copies we cannot zero, stated per tier:

| Tier | Copies we cannot zero | Mitigations |
| --- | --- | --- |
| Go (server, connector, edge, agent) | `net/http`/`bufio` request buffers and `crypto/tls` record buffers; go-asn1-ber packets of the modify request; stack growth copies; `append` growth; GC frees without zeroing (SP §5.6) | One short path (decode → encode → send → `Destroy`), pre-sized buffers; `Secret` type; no `pprof` (FF-SP2); `GOTRACEBACK` never `crash`; `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` on Linux; no WER LocalDumps on Windows |
| .NET sidecars (tier X) | Anything that becomes a `System.String`; GC relocation of unpinned buffers | Secrets arrive on stdin into a pinned `char[]` → `SecureString` → zero the array. `SecureString` is **a type boundary, not a protection** (Microsoft recommends against it for new code; SP §5.6) |
| Rust (tier N: passfilt, credprov) | Copies LSASS or LogonUI make themselves | `zeroize` + `SecureZeroMemory` on everything we own (licence-register row first) |
| Browser (tier W) | Immutable JavaScript strings | Password inputs only; never in storage; page cleared after submit |
| OS | Swap/pagefile, hibernation file | Host disk encryption recommended in the install guide |

**`runtime/secret` — DECISION TM-D9.** We do not depend on it. It exists only with
`GOEXPERIMENT=runtimesecret`, is outside the Go 1 compatibility promise, and protects only on
linux/amd64 and linux/arm64; elsewhere `Do` simply runs the function
([runtime/secret](https://pkg.go.dev/runtime/secret), checked at go1.27.1; SP §5.6). It may be enabled on
`linux-oci` as defence in depth after a spike, through ADR-0001's toolchain manifest. It is never
claimed as a control.

### 9.6 Outbound authentication — DECISION TM-D10 (SP §6.3 hand-off)

- **Service processes use Kerberos only and refuse NTLM.** On Windows, SSPI is called through
  Negotiate with the package list `"!ntlm"`
  ([SEC_WINNT_AUTH_IDENTITY_EXW](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_exw));
  without it, Negotiate falls back to NTLM
  ([Microsoft Kerberos](https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-kerberos)).
  The krb5 adapter on Linux has no NTLM. SMB (go-smb2) is a Kerberos-only initiator. No HTTP
  client performs integrated Windows authentication.
- **Connection targets come only from `InventoryHost`** — never from `homeDirectory`, `profilePath`,
  `dNSHostName`, `gPCFileSysPath` or API input (SP §6.3).
- The install guide recommends "Network security: Restrict NTLM: Outgoing NTLM traffic to remote
  servers" = **Deny all** on the activeDIQ host
  ([policy setting](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers)).

**Proof TM-F-NTLM.** In the Windows lab with NTLM blocked domain-wide, the full provider
conformance suite passes. A user whose `homeDirectory` is a UNC path to a lab listener produces **no**
outbound authentication attempt from the activeDIQ host during sync, report runs and home-folder
operations (the listener sees nothing).

### 9.7 Redaction

The `Secret` type renders `[REDACTED]`, refuses JSON and protobuf marshalling, and has no string
conversion (SP §5.6). Secret fields are **write-only** in the API schema, and a response linter
fails any response schema that can carry one — the lesson of CVE-2022-24978, a password field in a
JSON response (ME-SEC §4.1; FEAS §2.2).

**Proof TM-F-SECRETOUT.** A canary secret used through every secret-bearing flow (password set,
LAPS reveal, credential upload, integration credential) never appears in logs, error bodies, audit
details, API responses, metrics or exports (grep of every sink after the test run); the OpenAPI
linter rejects a response schema with a secret-typed field; credentials in query strings are
refused.

---
## 10. Update integrity — DECISION TM-D12

Automatic updates (ENH-07, ADM-209; BP §14 flow 6) are a **code-execution channel from skenzeriq
into every customer**, and from M3 onto DCs. The SolarWinds compromise shipped a malicious DLL that
was "signed by the legitimate SolarWinds code signing certificate"
([AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)). We therefore
follow The Update Framework's role separation
([TUF specification](https://theupdateframework.github.io/specification/latest/)):

| Role | Key custody | Purpose |
| --- | --- | --- |
| Root | Offline, threshold signatures (k of n) | Delegates and rotates every other key; pinned in every install |
| Targets | HSM or cloud KMS (money → CEO through T-0027) | Signs the release manifest: hashes and lengths of every artefact |
| Snapshot | Online, short expiry | Consistent view of all metadata |
| Timestamp | Online, very short expiry | Freshness; defeats freeze attacks |

Rules:
1. **Verify before unpack.** Metadata and artefact hashes are checked before anything is
   extracted or executed (SB §9).
2. **Rollback protection.** The highest version seen is persisted; older metadata or artefacts are
   refused.
3. **Freeze protection.** Expired timestamp or snapshot metadata is refused.
4. **One verifier** for the online courier and the offline bundle (ADR-0002 rule 7, P5).
5. **CI-only builds**, SBOM (CycloneDX) and build provenance per release; Authenticode for Windows
   binaries and MSIs; signatures for OCI images (SB §8).
6. **Customer control.** Ring, window and pinning are platform settings. DC-resident components
   never auto-update without explicit customer approval by default, and each keeps a tested
   rollback (SB checklist G).
7. **The server never signs code.** It can push to agents and connectors only artefacts signed by
   the release root. An agent refuses anything else.

**Proof TM-F-UPDATE** (extends P5). Rejected: a tampered artefact; a tampered manifest; metadata
signed by a revoked key; an older version (rollback); expired timestamp metadata (freeze); an
artefact signed only by the server's own key. Accepted: a root key rotation signed by the old root
threshold. Same results through the online courier and the offline bundle.

---

## 11. Audit tamper-evidence (co-decided with T-0047)

This section states the **required guarantees**. T-0047 decides the mechanics (chain format,
checkpoint cadence, signer).

| # | Guarantee |
| --- | --- |
| AG-1 | Written **in the same transaction** as the action it records. No action commits without its event |
| AG-2 | Success, failure **and denial** are recorded (SB §7) |
| AG-3 | Each event carries actor, on-behalf-of chain (token, automation policy, approvals), verification factor, source (client IP, component), target GUID + DN at the time, before/after with secrets redacted, outcome, correlation and operation IDs (DM-80) |
| AG-4 | The runtime role has **INSERT only** on audit tables: no UPDATE, DELETE or TRUNCATE. Retention purges run as a separate maintenance path under the owner role and delete only below a checkpoint (DM-80.I2) |
| AG-5 | **One hash chain per tenant**, gapless `seq` (DM-80.I1) |
| AG-6 | **Periodic signed checkpoints** (DM-81) whose hashes are **also streamed to the SIEM sink and included in every export** — external anchoring |
| AG-7 | An **offline verifier** checks an export without access to the installation |
| AG-8 | Audit reads, exports, retention changes and SIEM-sink changes are themselves audited (and need step-up, §7.4) |
| AG-9 | Events never carry a `Secret` (DM-80.I4) |

**Honest limit.** An attacker with root on the host (X6) can stop recording, forge **new** records,
and rewrite the **unanchored tail** since the last checkpoint that left the host. They cannot
rewrite history before the last externally anchored checkpoint without detection. [M3] DC events
(5136, 4738, 4728, …) collected by the `addc` agent give an independent "who" for every native
change, including ours (BP §9).

**Proof TM-F-AUDIT.** Catalog check: the runtime role holds no UPDATE/DELETE/TRUNCATE on audit
tables (with T3). Chain test: edit, delete or reorder one event → the verifier fails at that `seq`.
Anchor test: a checkpoint hash appears in the SIEM stream and in the export; rewriting events
before it is detected by the offline verifier. Coverage: every Action kind emits success, failure
and denial events (T-0047 operation fitness).

---

## 12. Control plane and DC-resident code [M3/M4]

Hand-off to T-0040 (agent host and `addc`), the M3 `fileserver` spec, T-0024 (password filter)
and T-0025 (credential provider). These constraints are binding on those tickets.

- **DECISION TM-D13 — agent command sets are closed (`addc`, `fileserver`).** Neither contains
  code execution, a file write outside the agent's data directory, a service or registry
  configuration change, or an update outside the release-signed channel (§10). Agents are
  outbound-only mTLS with no listener; the tenant is in the certificate SAN; they accept commands
  only from their server (SB checklist D).
  - `addc`: event collection and password-policy enforcement only (TM-TB12-T1…T9).
  - `fileserver` [M3]: read an ACL, apply an ACL built by the typed security-descriptor primitive
    (T-0028), create a folder, collect file-access events — only under a **root allow-list that is
    local to the file server** and that the server can narrow but never widen. Paths are
    canonicalised and reparse points are not followed. The module refuses to run on a DC, never
    accepts `SYSVOL`/`NETLOGON` as a root, and never runs holding SeBackupPrivilege,
    SeRestorePrivilege or SeTakeOwnershipPrivilege (TM-TB12-T10…T13).
- **DECISION TM-D14 — agent policy is data within schema bounds.** The agent-policy signing key lives in the
  management plane (BP §12), so a compromised server can sign policies. Policy is therefore typed
  data with bounds enforced by the agent (for example password-rule lengths and lists), never code,
  paths or commands. **Residual (TM-R7):** the worst a malicious policy can do is weaken or tighten
  password checks, or stop event collection.
- **Password filter (`native/passfilt`, LSASS).** No network I/O in LSASS; bounded memory; no
  blocking calls; it cannot crash LSASS (a crash reboots the DC). **Fail-open vs fail-closed is a
  customer-affecting risk acceptance → CEO decision (`ceo-decisions`) before the M4 build starts,
  not now** (§16.2).
- **Credential provider (`native/credprov`, LogonUI).** No web content of any kind; pinned TLS;
  works offline; can never block normal logon. This designs out the competitor's recurring
  "logon-screen client" class (ME-SEC §4.3: CVE-2020-11552, CVE-2026-74849).
- **DC agent identity.** A virtual service account in Event Log Readers is preferred over
  LocalSystem (FEAS §2.3; SB checklist D); final choice in T-0040 (§6.1).

**Proof TM-F-AGENTCMD.** The `activediq.addc.v1` and `activediq.fileserver.v1` contract lints
fail on any verb in a denied category (exec, arbitrary file write, delete, service/registry change,
update); fuzzed policies outside the schema bounds are rejected by the agent; an in-bounds hostile
policy changes only password-rule outcomes. For `fileserver`, the agent refuses: a denied verb sent
by a test server; a path outside its local roots; a junction, symbolic-link, `..`, 8.3, device-path
or stream escape (escape corpus); a `SYSVOL` or `NETLOGON` root; starting on a DC; starting while
its token holds SeBackupPrivilege. Owner: T-0040 (`addc`) and the M3 `fileserver` spec.

**Proof TM-F-CREDPROV.** The credential-provider binary imports no web-rendering or shell-dialog
component (import scan); logon works with the server unreachable; a server with an unpinned
certificate is refused. Owner: T-0025.

---

## 13. SaaS cell (designed, not shipped; launch needs a revision of this model, E5.6)

- Per-tenant Entra certificates sealed under KMS-wrapped DEKs, with the tenant ID as KMS
  encryption context (TM-D7).
- The KMS key policy grants decrypt only to the cell workload identity. The KMS audit log (for
  example CloudTrail) is an independent record of every unwrap.
- Unseal happens only inside that tenant's `WithTenantTx`. P4 runs the cross-tenant probes.
- Operations access is break-glass only: approved, time-bound, audited, with no standing unseal.
- **AD credentials never enter the cell** (ADR-0002 rule 3; P1).
- The connector-side tier-0 guard (TM-D2) bounds what a compromised cell can make an on-site
  connector do.
- A regulated tenant can bind Entra to its on-site connector (ADR-0002 amendment path).

**Residual (TM-R10).** A compromise of the cell's workload identity can unwrap every tenant's DEK
while it lasts; §6.6's permission limits bound what each Entra certificate can do.

---
## 14. Security review triggers for tickets

A ticket that matches any row is tagged `security-sensitive`, so security-architect reviews it
after code-reviewer (SB §1). **A ticket that adds a boundary, listener, process, privilege,
credential, anonymous route or outbound destination type without updating this file in the same
change is a review reject.**

| # | Trigger | Reviewer checks | Update in this file |
| --- | --- | --- | --- |
| RT-1 | Authentication, sessions, MFA, SSO, API tokens, enrolment (SB §1) | §7 rules; TM-F-SESSION / TM-F-SSO cases added | §7, TB1/TB2/TB8 rows |
| RT-2 | Authorisation: RBAC, scopes, approvals (SB §1) | Target-object check, per-item, no escalation | §7.7, TM-F-AUTHZ cases |
| RT-3 | AD or Entra writes (SB §1) | Rights stay within §6.3/§6.6; tier-0 guard covers it; audit events | §6.3 or §6.6 row |
| RT-4 | **New AD right or Graph permission** | Minimal; feature-gated; onboarding check knows it | §6.3 / §6.6 (row + reason) |
| RT-5 | **Change to the `tier0` definition or to the correlation gate** (AD, Entra or hybrid) | Computed set only grows; designation rules hold; authority still needs `matched` (TM-D17) | §6.4, §6.8 |
| RT-6 | **New trust boundary, listener, port or process** (including `fpolicy` [M5] and `t0-connector` [post-v1] when specced, §8.1) | STRIDE rows; TM-F-PORTS list | §4, §5, §8.1 |
| RT-7 | **New anonymous route** | Gate inside the flow; abuse controls | §7.6 table + allow-list file |
| RT-8 | **New named secret op or escape control** (SP §3.6, §3.7) | Own capability, audit kind, step-up | §7.4, TB3 rows |
| RT-9 | **New credential type or key** | Custody, sealing with associated data, rotation, on-compromise | §9.1 |
| RT-10 | Anything in the update or release path | §10 rules; TM-F-UPDATE cases | §10 |
| RT-11 | Anything that writes, exports, retains or could suppress audit | AG-1…AG-9 | §11 |
| RT-12 | DC-resident or host code (agent, filter, credential provider, installers, services) | §12; SB checklist D; line-by-line review | §12, TB12/TB13/TB16 |
| RT-13 | **New parser of untrusted input** (CSV, LDIF, XML/SAML, event logs, admin filters, uploads) | Limits, fuzz target (FF-SP5), no external entities | TB rows of the boundary it sits on |
| RT-14 | **New outbound destination type** (SSRF) | One egress client; TM-F-EGRESS cases | TB9 |
| RT-15 | **New dependency in an auth, crypto or parsing path** | Licence register, maintenance, SBOM | §5 row of that boundary if it changes a control |
| RT-16 | Any use of crypto primitives, signing, TLS configuration, random tokens | Vetted library, CSPRNG, no verification bypass (FF-SP2) | §9 |
| RT-17 | Safe-primitive packages (filter, DN, codecs, SQL layer, `psx`/`proc`, SD model) | SP rules; corpus records added | — (SP owns) |
| RT-18 | **Importing another product's configuration or data** (migration adapters; a new source product such as ADAP or ADSSP) | TM-D21: proposals only, no executable content, credential deny list, applier holds every imported privilege; TM-F-MIGRATE cases added | §5.18 (TB18) |

---

## 15. Proofs summary

Existing proofs this document relies on: FF-SP1–SP9 (T-0033, T-0034), `fitness-tenancy` T1–T5
(T-0036), `fitness-profiles` P1–P7 (T-0038), API fitness (T-0046), operation and audit fitness
(T-0047), T-0023 CBT acceptance, T-0028 SD golden tests, T-0029 encoder corpus. New proofs:

| Proof | What it proves (fails when …) | Kind | Owner ticket | Threats |
| --- | --- | --- | --- | --- |
| TM-F-RIGHTS | An over-privileged AD identity (Tier-0 group member, or any write/control right on a `tier0` object) or an Entra app with a denied permission is **refused activation**; a correctly delegated one passes; extras and missing rights are both reported (§6.5, §6.6) | Windows lab (oracle) + Samba where supported; fake Graph | T-0053 (directory-engineer) | TB3-T11, TB7-T3 |
| TM-F-T0GUARD | The connector refuses `Apply` on a `tier0` target even when the server asks; Plan refuses too; Entra `tier0` (E1–E5) is refused, as are AD objects correlated to it (C16) (§6.2) | Lab, both transports | T-0053 (directory-engineer) | TB3-T10, TB6-T4, TB7-T4, TB7-T11, TB17-T4 |
| TM-F-HYBRID | A forged, SOA-transferred, SID-mismatched, unattested or once-cloud-only correlation authorises anything; a correlation first eligible during a post-attestation `open`/`stale` lapse becomes `matched` without re-confirmation; an install-time correlation (present before the first attestation, not once cloud-only) fails to become `matched` on that attestation; `tenant-owner` crosses a correlation; the attestation flow keeps a token (§6.8). TM-D19 (§6.9): an Entra-only session holds a correlation-derived AD grant; an authority factor enrols without AD-plane proof or owner approval; an Entra-side method reset touches the activeDIQ factor; a less-privileged technician resets a console-backing object | CI, fake Graph + fake IdP + Samba | T-0054 (directory-engineer, with `authz`) | TB7-T8 to T13, TB8-T8 |
| TM-F-ANON | Anonymous routes of the built router ≠ the reviewed allow-list (§7.6) | CI | T-0046 API fitness | TB2-T2, TB2-T10 |
| TM-F-FLEET | Any RPC but `Enroll` succeeds without a client certificate; an enrollment token works twice or after expiry; a connector accepts an unpinned server; a revoked component keeps a stream; the fleet contract gains a secret-bearing message type outside operation payloads | CI (P3 harness) | T-0055 (backend-engineer) | TB6, TB12-T1/T2 |
| TM-F-NTLM | Any outbound NTLM attempt from the activeDIQ host, with NTLM blocked domain-wide or a planted UNC `homeDirectory` (§9.6) | Windows lab | T-0054 (directory-engineer) | TB3-T2, TB9-T2 |
| TM-F-SEAL | A sealed value opens after being moved to another tenant, row or column; a DEK unwraps under another tenant's context (§9.2) | CI | T-0055 (backend-engineer) | TB4-T6/T7, TB5-T2, TB7-T1 |
| TM-F-AUDIT | Runtime role can UPDATE/DELETE/TRUNCATE audit; an edited, deleted or reordered event verifies; a checkpoint is not anchored in SIEM and export (§11) | CI + catalog | T-0047 fitness | TB1-T5, TB4-T3/T4, TB15-T5 |
| TM-F-UPDATE | A tampered, rolled-back, frozen, revoked-key or server-signed update is accepted, on either courier (§10) | CI, extends P5 | ENH-07 spec (T-0031 plan) + T-0038 | TB10 |
| TM-F-AUTHZ | Scope escape, move-between-check-and-write, bulk item out of scope, self-escalation, dead-owner token or a report beyond its owner's scope succeeds (§7.7) | CI + Samba lab | T-0056 (backend-engineer) | TB1-T8/T11/T12, TB2-T8, TB15-T2 |
| TM-F-SESSION | Cookie, CSRF, timeout, revocation, step-up or token rules of §7.3–§7.5 do not hold | CI | T-0056 (backend-engineer) | TB1, TB2-T1, TB8-T3/T6 |
| TM-F-SSO | A forged, wrapped, replayed or mis-addressed SAML/OIDC response is accepted (§7.7) | CI fuzz corpus | T-0056 (backend-engineer), with ADM-143 spec | TB8 |
| TM-F-SECRETOUT | A canary secret appears in any log, error, audit detail, response, metric or export; a response schema carries a secret field (§9.7) | CI | T-0033/T-0034 (FF-SP extension) + T-0046 linter | TB1-T7, TB2-T6, TB8-T5, TB9-T5/T6 |
| TM-F-EGRESS | An integration reaches loopback, link-local, metadata or private ranges without an allow-list entry; a redirect escapes; DNS rebinding works; TLS is unverified; webhooks are unsigned | CI | T-0055 (backend-engineer) | TB9, TB15-T7 |
| TM-F-ABUSE | Responses differ for existing vs non-existing accounts (body, status, timing class); our counter lets the domain lockout threshold be reached; an OTP works twice or late; enrolment proceeds without the user's own authentication | CI + Samba lab | T-0056 (backend-engineer); ENH-09 spec; M4 SSPR spec | TB1-T9/T13, TB3-T8, TB11, TB13-T5 |
| TM-F-HOST | Installer runs on a DC; service runs as LocalSystem/root; config, keytab or keystore readable by others; a default credential or plaintext listener exists at first run; setup secret reusable; dumps enabled; a remote DB DSN without full TLS verification is accepted | Windows lab + OCI CI, extends P2 | devops-engineer (packaging), T-0038 | TB1-T2, TB4-T1, TB5, TB14-T3, TB16 |
| TM-F-PORTS | A booted install listens on anything not in §8.1 | CI, extends P2 | T-0038 | TB6-T8, TB14-T6, TB16-T10 |
| TM-F-EDGE [M4] | An admin/API route is reachable through the tunnel; an unpinned tunnel peer is accepted; edge links credential or store code (§8.2) | CI | M4 SSPR spec | TB11 |
| TM-F-AGENTCMD [M3] | The `addc` or `fileserver` contract carries a denied verb; an out-of-bounds policy is accepted; the `fileserver` agent acts outside its local roots, follows a junction or link escape, accepts a `SYSVOL`/`NETLOGON` root, starts on a DC or starts holding SeBackupPrivilege (§12) | CI + Windows lab | T-0040 (`addc`); M3 `fileserver` spec | TB12-T3/T4, TB12-T10 to T13 |
| TM-F-MIGRATE [M2] | A hostile-file corpus (XXE, archive `..`/absolute/link entries, decompression bomb, oversized cells) gets through; an import goes live without being a proposal; a proposal is applied by an actor lacking a privilege of an imported grant; `tenant-owner` or a `tier0` scope is imported; script content is importable as executable; an adapter selects a deny-listed credential table or column; an uploaded dump persists after the job; a comparator run reaches Apply; a job owned by ManageEngine runs (§5.18) | CI fuzz corpus + Samba lab | E2.11 migration spec (backend-engineer), planned in T-0031 | TB18 |
| TM-F-RADIUS [M4] | An unregistered client gets a reply; a request without `Message-Authenticator` is accepted; MS-CHAP attributes are accepted; a flood starves console latency; an `unsafe` or cgo import appears in `radius`; the decoder has no fuzz target (§5.19) | CI + load test | M4 RADIUS spec | TB19 |
| TM-F-CREDPROV [M4] | The credential provider imports web or shell-dialog components; blocks logon offline; accepts an unpinned server (§12) | Windows lab | T-0025 | TB13 |

The proofs that no earlier ticket owned are filed as T-0053 to T-0056. The Entra lab claims are T-0057
(G1–G10). TM-F-MIGRATE and TM-F-RADIUS belong to the specs of their milestones (M2, M4) and are
carried by those tickets. Until a proof runs in CI or the lab, its control is direction, not a
control.

---

## 16. Residual risks and decisions owed to the CEO

### 16.1 Residual risk register

| ID | Residual risk | Why it remains | Owner | Revisit when |
| --- | --- | --- | --- | --- |
| TM-R1 | A compromised server or administrator can do everything the delegated rights allow: reset any in-scope password, change any in-scope membership | That is the product's job; §6.3 keeps the rights minimal and §6.4 keeps Tier 0 out | security-architect | Any new right (RT-4) |
| TM-R2 | A customer overrides the Tier-0 refusal (TM-D1); activeDIQ is then Tier 0 in that forest | Customer choice; the product says so permanently | product-manager (onboarding UX) | If overrides become common: pull `t0-connector` (FD-11) forward |
| TM-R3 | AD's native logs show the connector, not the technician, until the M3 correlation | Delegation alternatives are worse (§6.7) | product-manager (ADM-134 spec) | M3 `addc` pipeline |
| TM-R4 | Host administrators of the server or connector host are at the tier of the service | A process cannot defend against its own host's administrators | security-architect (install guide) | New host roles |
| TM-R5 | An L7 edge sees SSPR plaintext while compromised | L4 passthrough moves internet parsing into the server | security-architect | M4 SSPR spec |
| TM-R6 | A build-system compromise produces legitimately signed releases | Signatures prove origin, not intent (AA20-352A) | devops-engineer | T-0027; provenance and reproducible builds |
| TM-R7 | A compromised server can sign in-bounds agent policy | Policy key lives in the management plane (BP §12) | windows-engineer | T-0040 |
| TM-R8 | A stolen database or backup exposes inventory PII | Inventory is not encrypted per field | backend-engineer | E2.12 PRD (backup encryption) |
| TM-R9 | Secret copies we cannot zero (runtime buffers, pagefile, hibernation) | Language runtimes and OS (§9.5) | security-architect | `runtime/secret` graduates; Go adds Windows support |
| TM-R10 | A SaaS cell workload-identity compromise unwraps every tenant's DEK while it lasts | Shared cell by design (ADR-0002) | security-architect | SaaS launch revision (E5.6) |
| TM-R11 | Hybrid: whoever controls the sync client, the tenant sync features or SOA transfer can make a correlation `matched`. Takeovers that happened before install go unseen, and so do takeovers in the install-time population (correlations eligible before the tenant's first `attested` state, including an `open` window before it) that our sync never saw cloud-only (TM-D17 rule 4); TM-D19 rule 2 still withholds AD-side authority from them. Between monitor polls a flag flip is undetected; without the optional monitor, it is undetected until the attestation ages out (≤ 90 days) | The correlation gate trusts the sync client by construction (DM-20.I6) | security-architect | Lab G8; if Graph adds app-only read of sync features |
| TM-R12 | Someone who controls both planes at enrolment (the AD password or a `tenant-owner` approval, plus the Entra sign-in) can enrol a TM-D19 authority factor | Such an attacker is, in effect, the technician; the history residual reduces to this case (§6.9) | security-architect | ADM-143 spec (SPNEGO); lab G10 |
| TM-R13 | RADIUS PAP over UDP for clients without RADIUS/TLS: a leaked or weak shared secret plus captured traffic reveals passwords | Many NAS devices support only UDP; activeDIQ-generated 32-byte secrets and internal-only exposure narrow it (TM-TB19-T4) | security-architect | M4 RADIUS spec (TM-Q18) |

### 16.2 Decisions owed to the CEO (not asked now)

Each goes through the `ceo-decisions` skill in business terms when its trigger arrives.

| Decision | Why it is the CEO's | Must be decided before |
| --- | --- | --- |
| Password-filter fail mode: fail-open (passwords allowed if our check cannot run) or fail-closed (password changes refused) | Customer-affecting risk acceptance | The M4 password-filter build (T-0024 follow-up) |
| Code-signing certificates and HSM/KMS for release keys | Money | Signing work in T-0027 |
| External security commitments: `SECURITY.md`, disclosure address and policy, advisory SLA (same-day advisories with CVSS matching the CNA record), independent pentest attestation | They leave the building (SB §10); ME-SEC §4.4 lists what buyers will ask for | First customer release (prepared in T-0059) |

---
## 17. Open items

| ID | Item | Constraint set here | Decided in |
| --- | --- | --- | --- |
| TM-Q1 | Enrolment integrity of the v1 end-user TOTP page | User's own AD authentication; notice to existing contact data (TM-TB1-T13) | ENH-09 spec |
| TM-Q2 | Rate limits and size caps per operation | Declared per operation in the contract | T-0046 |
| TM-Q3 | IdP claim-to-role mapping; MFA claims from the IdP | `tenant-owner` never from a claim alone | ADM-143 spec |
| TM-Q4 | Secret-reveal thresholds and alerts | Per-technician rate limit + burst alert | E2.5 helpdesk spec |
| TM-Q5 | Password in notifications | Off by default; own review | E2.5 helpdesk spec |
| TM-Q6 | Change-volume limits for HR-driven lifecycle | Through Plan and approvals | E2.9 lifecycle spec |
| TM-Q7 | KEK recovery path; backup encryption; bundled DB backup | No plaintext fallback | E2.12 PRD |
| TM-Q8 | Fleet stream limits; per-tenant issuing CA in SaaS | No secret pushed over fleet (TM-D8) | Connector spec |
| TM-Q9 | Blob isolation probe | Tenant-prefixed keys only | T-0036 (adds it to T4) |
| TM-Q10 | Log/metric/cache tenant isolation probe | Tenant ID on every line | T-0038 (extends P4) |
| TM-Q11 | Update protocol details; courier telemetry; OCI apply without Docker socket | §10 rules | ENH-07 spec (T-0031) |
| TM-Q12 | Hardening wizard delegation plan; "remove delegation" plan on uninstall | Never holds WRITE_DAC (TM-D3) | ENH-08 spec |
| TM-Q13 | LAPS decryptor group for non-DC policies | Never DCs, never via Domain Admins (§6.3 R10) | ADM-060 spec + Windows lab |
| TM-Q14 | Entra password reset if a role is required | No directory role in v1 (TM-D5) | ADM-162 spec + lab G1–G9 |
| TM-Q15 | Restricting where the Entra app may sign in | Customer option, documented | ADM-159 spec |
| TM-Q16 | Per-role-family connector identities for coarse AD attribution | Allowed by TM-D6(c) | ADM-134 spec |
| TM-Q17 | L7 vs L4 edge | Security preference: L7 + schema validation both ends | M4 SSPR spec |
| TM-Q18 | RADIUS over TLS | `Message-Authenticator` mandatory regardless | M4 RADIUS spec |
| TM-Q19 | Password-filter IPC content; agent-policy key rotation | §12; TM-D13, TM-D14 | T-0024 + T-0040 |
| TM-Q20 | Password-filter fail mode | CEO decision (§16.2) | ceo-decisions, before the M4 build |
| TM-Q21 | SaaS quotas, operations break-glass, launch revision of this model | §13 | E5.6 |
| TM-Q22 | Feed the ad-expert corrections back into FEAS §2.3 (Get-Changes over-reads; property-set over-grant; Delete-Tree; Reanimate JIT; LAPS/DSRM; GPCO not Tier 0) | §6.3, §6.4 | T-0060 (ad-expert) |
| TM-Q23 | Windows-lab confirmation of every `[UNVERIFIED — lab]` / `[LAB]` item here | — | T-0051 (lab confirmation) |
| TM-Q24 | Hybrid-trust attestation UX, monitor poll interval, directory-audit activity names | Delegated, single scope, token discarded, at most 90 days; an open tenant is reason `tenant_takeover_open` (TM-D17, DM-10.I7) | Hybrid/ADM-169 spec + lab G8, G10; DM alignment T-0061 |
| TM-Q25 | The `sidecars/exchange` leg to Exchange [M3] (TB14 covers only launcher ↔ sidecar) | **Exchange Online:** app-only through `Exchange.ManageAsApp`, authorised by a **custom Exchange role group assigned to the service principal, with a write scope** — never an Entra directory role, which TM-D5 forbids ("Option 2: Assign custom role groups to the application using service principals", [EXO app-only](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2)). The page says the custom group lets you "use a Write scope to limit which recipients can be modified". EXO app-only needs "an exportable and available private key (.pfx)" from a CSP provider ("CNG certificates aren't supported"), so TM-D8's "non-exportable" cannot hold for it: a separate certificate, ideally a separate app registration, never the Graph credential. **On-premises Exchange:** the connector identity is never in Organization Management, nor in Exchange Windows Permissions or Exchange Trusted Subsystem (both C13); a scoped management role assignment instead. PowerShell only through `psx` (SP) | M3 Exchange spec |
| TM-Q26 | Whether `radius` runs in `cmd/server` or `cmd/radius` | TM-D20 triggers: an EAP method, a non-Go TLS stack or a missed fuzz or flood budget forces `cmd/radius` and an ADR-0002 amendment | M4 RADIUS spec |
| TM-Q27 | Whether restore (§6.3 R9) needs to list `CN=Deleted Objects` or can address the tombstone by the GUID inventory holds | Never take ownership of the container by default; `[UNVERIFIED — lab]` | T-0051 lab; T-0060 FEAS correction |
| TM-Q28 | Migration database-adapter mode (customer dump vs live read-only connection) and the ADMP table allow-list per build | TM-D21; TM-TB18-T4/T5: allow-list plus CI deny list, read-only, sealed credential, upload deleted at job end | E2.11 migration spec + lab |

---

## 18. Sources

Internal: ADR-0001, ADR-0002, BP, SP, FEAS, DM, ME-SEC, SB (table at the top); the ad-expert consult
and the Graph least-privilege research for T-0007 (consult answers to security-architect,
2026-10-02, whose claims are carried above with their sources and tags).

External, in order of first use:

 1. https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-259a
 2. https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model
 3. https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
 4. https://www.rfc-editor.org/rfc/rfc2865
 5. https://nvd.nist.gov/vuln/detail/CVE-2024-3596
 6. https://www.blastradius.fail/
 7. https://www.rfc-editor.org/rfc/rfc6614
 8. https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2743314
 9. https://www.rfc-editor.org/rfc/rfc2759
10. https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-managedpassword
11. https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection
12. https://learn.microsoft.com/en-us/windows/win32/adschema/r-user-account-restrictions
13. https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory
14. https://www.samba.org/samba/security/CVE-2018-14628.html
15. https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/non-administrators-view-deleted-object-container
16. https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference
17. https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
18. https://github.com/SpecterOps/TierZeroTable
19. https://www.semperis.com/blog/golden-gmsa-attack/
20. https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks
21. https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites
22. https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept
23. https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure
24. https://learn.microsoft.com/en-us/windows/win32/adschema/a-allowedattributeseffective
25. https://learn.microsoft.com/en-us/windows/win32/adschema/a-sdrightseffective
26. https://learn.microsoft.com/en-us/graph/api/organization-get?view=graph-rest-1.0
27. https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0
28. https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0
29. https://learn.microsoft.com/en-us/graph/api/group-assignlicense?view=graph-rest-1.0
30. https://learn.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0
31. https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0
32. https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-delete?view=graph-rest-1.0
33. https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-restore?view=graph-rest-1.0
34. https://learn.microsoft.com/en-us/graph/api/user-delete?view=graph-rest-1.0
35. https://learn.microsoft.com/en-us/graph/api/user-post-manager?view=graph-rest-1.0
36. https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0
37. https://learn.microsoft.com/en-us/graph/api/invitation-post?view=graph-rest-1.0
38. https://learn.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0
39. https://learn.microsoft.com/en-us/graph/api/group-update?view=graph-rest-1.0
40. https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0
41. https://learn.microsoft.com/en-us/graph/api/user-delta?view=graph-rest-1.0
42. https://learn.microsoft.com/en-us/graph/api/group-delta?view=graph-rest-1.0
43. https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0
44. https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-get?view=graph-rest-1.0
45. https://learn.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0
46. https://learn.microsoft.com/en-us/graph/permissions-reference
47. https://learn.microsoft.com/en-us/graph/permissions-overview
48. https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-perform-sensitive-actions
49. https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management
50. https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
51. https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-assign-roles
52. https://learn.microsoft.com/en-us/graph/api/application-addkey?view=graph-rest-1.0
53. https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity
54. https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-service-principal-sign-ins
55. https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview
56. https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
57. https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0
58. https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass
59. https://learn.microsoft.com/en-us/windows/win32/adschema/r-self-membership
60. https://pkg.go.dev/runtime/secret
61. https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_exw
62. https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-kerberos
63. https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers
64. https://theupdateframework.github.io/specification/latest/
65. https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2

## Changelog

- 2026-10-02 · v0.2 (T-0007 review round 2). TM-D17 rule 4 (g) corrected: only a correlation that first became eligible **after** the tenant's first `attested` state, while the state was `open` or `stale`, needs a `tenant-owner` re-confirmation. The install-time population (correlations eligible before the first attested state, through `unattested` or `open`) becomes `matched` on that attestation, under TM-R11 and with TM-D19 rule 2 as the AD-side control. Two TM-F-HYBRID cases added (§6.8, §15). The TB7-T9 residual and TM-R11 extended to match. §6.6: RMAU members are protected from every property write (verbatim quotes). §6.9 rule 6: the RMAU Programmability consequence is stated as intended. §4.1 diagram: `radius` is on its own line. §8.1: RadSec (TCP) would be a new L-row through RT-6.
- 2026-10-02 · v0.1 (T-0007 rework after the solution-architect review). New boundaries TB18 (ManageEngine source ↔ migration importer, scanner, comparator; TM-D21) and TB19 (RADIUS; TM-D20, co-location bounded). `fileserver` agent rows TM-TB12-T10…T15 and TM-D13 extended to it; `fpolicy` and `t0-connector` out of scope with an RT-6 trigger. Authentication-plane residual closed by TM-D19 (activeDIQ-held authority factor anchored in the AD plane; TM-TB8-T8, TM-R12). TM-D17 aligned to DM-10.I7 and D-0009: 90 days, optional monitor, DM vocabulary and permissions, T-0061. §6.3 R9 Deleted Objects finding (TM-Q27). §6.4 C rows reordered. New proofs TM-F-MIGRATE and TM-F-RADIUS; RT-18; TM-R13; TM-Q25 (Exchange leg) to TM-Q28. §18 regenerated (65 URLs).
- 2026-10-02 · v0 (T-0007). 17 trust boundaries with STRIDE tables; minimum AD rights R1–R13 and Graph allow and deny lists; the `tier0` set for AD (C1–C16) and Entra (E1–E5), answering DM Q1 and confirming DM-23.I5; the hybrid correlation gate (TM-D17), which confirms DM-20.I4 and tightens it, with (f) attested because Graph has no app-only read; role-granting groups as escalation objects (TM-D18, the DM-36.I2 referral); decisions TM-D1–D18; follow-up tickets T-0053–T-0060. Status `review`.

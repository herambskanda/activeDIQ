---
title: "ADR-0009: Platform scope is a separate principal kind (the installation operator); permissions declare a scope class"
date: 2026-10-29
updated: 2026-10-29
status: proposed
owner: security-architect
kind: technical
ticket: T-0794
fitness: fitness-platform-scope (`make fitness-platform-scope`; a build ticket adds it to `make ci`, so not yet `accepted`)
---

# ADR-0009: Platform scope is a separate principal kind (the installation operator); permissions declare a scope class

**Status:** proposed. Ratified by factory-director after solution-architect review; `accepted` when `fitness-platform-scope` runs green in CI. **Kind:** technical (no CEO fork: it changes no price, packaging or platform strategy; SaaS shape is a constraint recorded here, decided at SaaS launch). **Ticket:** T-0794. Builds on T-0250, ADR-0002 "Configuration scope", threat model TM-D1, §7.4 (step-up, TM-D16), AN-8 (break-glass), TM-D19 (authority factor), ADR-0008 (installation scope).

## Context

T-0250 made `connections.tier0_override.acknowledge` platform-only and fail-closed: `authz.Role.has` returns false for it, and `rbac` refuses any role that lists it (`platformOnlyErr`). That closed the hole (a tenant role could otherwise acknowledge that activeDIQ is Tier 0). It also means **nobody can hold the permission today**, and TM-D1 says the *installation operator* may. Three gaps:

1. No principal exists at platform scope. Every account is tenant-scoped (`tenant_id`, RLS); `authz_assignments` is a tenant table.
2. `authz.platformOnly` is a hand-kept `[]Permission`. The permission is also named in `connections.Tier0OverridePermission`. Two lists that must agree are the PatchIQ drift pattern (postmortem §11).
3. ADR-0002 says the installation operator is the customer when self-hosted and skenzeriq operations in SaaS. Those are very different trust positions and the spec must not paper over that.

## Decision

### 1. Scope class is declared per permission, in the catalogue

Every permission in the catalogue carries a **scope class**, an enum with no default:

| Class | Meaning | Who can hold it |
| --- | --- | --- |
| `tenant` | Exercised inside one tenant | Tenant roles, delegation scopes (today's behaviour) |
| `platform` | Changes the installation, or the tenant's *tier of risk*; not delegable | Only a **platform assignment** (§2) |

- The declaration lives beside the permission in the operation catalogue (`operation.Descriptor` gains `ScopeClass`; the Action definition is the single source of the permission name). A descriptor with no class is a **build error** (zero value is invalid, not `tenant`).
- `authz.platformOnly` is **deleted**. `authz.IsPlatformOnly` stays as the API, reading a set the catalogue registers at process start (`authz.RegisterScopeClass`, called from the catalogue package's init, never from request input). An unregistered permission is treated as `platform` (fail closed) in `Role.has` and in `rbac`'s grant path, so a typo or a late registration denies rather than grants.
- `connections.Tier0OverridePermission` stays a constant (callers need it), but the **drift guard** (fitness item 1) fails the build unless the catalogue declares it `platform` and the descriptor built from it uses that constant. Adding a `platform` permission without a test row in the guard also fails.
- `rbac.platformOnlyErr` and migration 0043's role-permission allow-list keep refusing `platform` permissions at tenant scope; the allow-list is generated from the catalogue's `tenant` set, not hand-edited.

### 2. The platform assignment: a separate principal kind, never a role

An **installation operator** is a row in a global table `platform_operators` (tablekind `Global`, registered in the exemption registry; no `tenant_id`, no RLS, runtime role has SELECT only, writes go through a dedicated `WithPlatform` site with a reason). It is **not** an `authz_assignments` row and **not** a Role, because the kernel's scopes are delegation scopes over directory objects and platform scope is not one (T-0250's reasoning stands).

- A separate **account**, with its own credentials, never an assignment on a tenant account. A human who is both tenant-owner and operator (self-hosted, the usual case) has two accounts and two sessions. A session is either a tenant session or a platform session, never both; there is no "elevate this session".
- The kernel gains `PlatformPrincipal` (ID, disabled, `AuthorityFactor`) and `Evaluator.CheckPlatform(p, permission)`. It allows only a `platform`-class permission, only to an enabled operator, only with a current step-up. A `tenant`-class permission asked of `CheckPlatform` is denied (an operator is not a tenant administrator and holds no tenant data rights by being an operator).
- `Role.TenantOwner` still does **not** imply any `platform` permission. Correlation-derived (hybrid) grants never reach a platform permission (TM-D17 (h) extended: `platform` class is excluded from derivation).
- A platform permission acts on a tenant only through an explicit **tenant binding** in the request (the Action's tenant is a typed input, resolved and verified to exist), executed in that tenant's `WithTenant` transaction so RLS, the tenant audit chain and the tenant DEK apply as usual. The operator never gets a cross-tenant read: the grant is the permission on that one Action, nothing more.

### 3. How it differs from TenantOwner

| | TenantOwner | Installation operator |
| --- | --- | --- |
| Scope | One tenant (all of it, subject to correlation limits) | The installation: settings, and `platform`-class Actions |
| Store | `authz_assignments` (tenant table) | `platform_operators` (global) |
| Holds | Every `tenant` permission (DM-34.I1) | Only `platform` permissions; **no** tenant permission, no directory write, no data read |
| Sign-in | SSO + MFA, or tenant break-glass | Local credential + phishing-resistant factor; never SSO from a tenant IdP (a tenant IdP admin must not mint an operator) |
| Created by | Another tenant-owner, step-up | Installer (first), then another operator with step-up (§4) |
| Can be last-removed | No (DM-30.I4) | No: at least one enabled operator, plus a recovery path (§4) |

### 4. Provisioning

**First operator (self-hosted).** The installer's first-run claim (`setup`, AN-4: one 256-bit secret, single atomic claim, 1 h TTL) creates the **first installation operator and the first tenant-owner as two separate steps of one wizard**, each enrolling its own factor. Claiming setup is the *only* path that creates an operator without an existing operator. The claim is audited to the platform chain (§6). No default account exists. The operator account must enrol a WebAuthn/passkey authenticator at creation; a TOTP-only operator is refused (the factor policy document sets the tenant-side policy; for platform scope the floor is fixed, not configurable, because there is no tenant to configure it).

**More operators.** An operator creates another: an Action, step-up, and a **second operator's approval when two or more operators exist** (four-eyes; with one operator the step-up alone applies, and the console says so). New operators enrol their factor in-person-equivalent: single-use, 15-minute enrolment token shown once, hashed at rest, bound to the account being created.

**Break-glass / recovery.** Losing every operator must not need a database edit. Recovery is a **host-local verb**, `activediq-admin operator recover`, which requires an OS identity that can read the installation secret directory (the same ACL as the setup secret) and prints a one-time enrolment token for a **new** operator, 15-minute TTL, and invalidates all existing operator sessions. It never resets an existing operator's factor and never reveals a credential. Use is audited (written to the platform chain and the OS event log), raises the highest alert class (like AN-8 break-glass), and appears as a banner until an operator acknowledges it. Host access is already inside the Tier-0 trust boundary (host compromise is TM-R-class residual, not a new exposure), so the verb does not widen it. It does not exist in the SaaS profile.

**Not provisioned by:** environment variables, config files, tenant APIs, SCIM, imports (TM-D21 never imports operators), or the public tenant API.

### 5. Authentication of a platform session

1. Password (argon2id) + WebAuthn user-verifying assertion for sign-in. No password-only session, no TOTP, no SSO, no remember-me.
2. **Every `platform` Action requires fresh step-up**: `StepUp: true` is mandatory for the class (the catalogue build check fails a `platform` descriptor with `StepUp == false`). Window: platform floor, **max 5 minutes, fixed**, not tenant-configurable (`StepUpBounds` is a tenant setting; platform sessions ignore it).
3. Platform sessions are shorter (idle 15 min, absolute 8 h), bound to the client (token binding as for tenant sessions), and are never accepted on an end-user or tenant-IdP hostname (AN-5/AN-7 refusal as for AN-8).
4. Sign-in throttled, never locked (AN-8 rule 3): a hard lockout would let an attacker lock the operator out.
5. API: operators use the console; **API tokens are not issuable to operators**. Platform Actions are not reachable with an API token (the token path denies `platform` class), so a leaked token can never change the installation's tier.

### 6. Audit

- A **platform audit chain** (installation-scope, hash-chained like the tenant chain, ADR-0005) records every operator sign-in, step-up, failed attempt, operator creation/removal, recovery verb use, and every `platform` Action with the operator ID, tenant binding, input digest, and plan hash. It is exportable by an operator and verifiable offline, and its checkpoints are signed under the installation key (T-0715).
- A `platform` Action that touches a tenant **also writes to that tenant's chain** (the existing `connection.tier0_override.acknowledged`), with the actor recorded as `platform_operator:<id>`, so the tenant's auditors see it without access to the platform chain. Neither write may succeed without the other (same transaction where both are in one database; otherwise the tenant write commits first and a missing platform entry is a health alarm).
- Operator removal, recovery use, and any `platform` Action alert every enabled tenant-owner of the affected tenant (self-hosted: the customer's own owner sees it).

### 7. SaaS: the operator is skenzeriq, not the customer

In SaaS the installation operator is skenzeriq operations. The customer's risk acceptance ("activeDIQ will be Tier 0 in this forest") is **the customer's to make, not ours**, so a platform assignment alone must never be enough to acknowledge it. Binding constraints for the SaaS revision (TM-TB17, `[OPEN → E5.6]`):

1. Operator accounts are federated to skenzeriq's workforce IdP with phishing-resistant MFA; the local-credential path and `recover` verb are disabled in the profile (composition root, not a runtime conditional in domain code, ADR-0002 rule 1).
2. No standing operator access to a tenant: a tenant binding is an approved, time-bound, audited grant (TM-TB17-T3 break-glass). 
3. `connections.tier0_override.acknowledge` additionally needs a **tenant-owner co-signature** with step-up on that tenant (the operator requests, the owner confirms), both recorded. This is a second declared attribute on the permission (`RequiresTenantConsent`), enforced by the runner, inert for self-hosted where operator and owner are the same customer. The self-hosted build ships the attribute and its check now (so SaaS does not need a catalogue rewrite) and tests it with a fake second party.
4. skenzeriq operators never hold the permission to read tenant data or unseal tenant keys by being operators.

## Threats (STRIDE, trust boundary: console ↔ server, platform scope)

| ID | STRIDE | Threat | Mitigation | Test | Residual |
| --- | --- | --- | --- | --- | --- |
| PS-1 | E | Tenant role/owner/delegation obtains a `platform` permission by listing it, by TenantOwner, by a hybrid derivation, or via a migrated/imported role | Fail-closed scope class; `Role.has` denies; `rbac` refuses at write; derivation excludes the class; the DB allow-list is generated from `tenant` set | Existing T-0250 tests plus table test over every registered `platform` permission × (role listing, owner, derived grant, import, API token) | — |
| PS-2 | E | Unregistered or misdeclared permission treated as `tenant` | Zero value invalid; unregistered = `platform` for grant purposes; build fails on missing class | Catalogue build check; unit test that an unregistered name is denied everywhere | — |
| PS-3 | S | Phished operator credential | WebAuthn mandatory, no TOTP/SSO/remember-me, step-up ≤ 5 min per Action | Sign-in refuses password-only and TOTP-only operators; step-up age 5 min + 1 s denies | A compromised authenticator plus password |
| PS-4 | S | Tenant IdP admin mints an operator | Operators are never SSO-derived, never importable; creation is only setup claim or operator Action | No code path from `sso` to `platform_operators` (static fitness); import rejects operator rows | — |
| PS-5 | E | Operator pivots to tenant data/administration | Operator holds no `tenant` permission; `CheckPlatform` denies `tenant` class; tenant binding opens one Action | `CheckPlatform(tenant perm)` denied; RLS test: operator session reads zero tenant rows outside the bound Action | An operator with host/DB access is already Tier 0 (TM-R) |
| PS-6 | E | Leaked API token changes the installation | `platform` Actions unreachable by token; operators get no tokens | Token with every permission string cannot run a `platform` Action | — |
| PS-7 | R | Operator denies an override, or an override is made without trace | Platform chain + tenant chain, both in transaction, signed checkpoints, tenant-owner alert | Override produces both records; deleting one is detected by chain verification | An operator with DB write can truncate a chain tail until the next checkpoint (as tenant chain) |
| PS-8 | T | Recovery verb abused to plant an operator | Host ACL, 15-min single-use token, kills sessions, loud alert, audited, banner until acknowledged | Verb refuses without ACL; token single-use; sessions invalidated; audit + alert emitted | Host admin is Tier 0 already |
| PS-9 | D | Last operator removed or locked; attacker locks the operator out | Last-operator refusal (mirrors DM-30.I4); throttle never lock; host recovery verb | Revoking the last operator returns `ErrLastOperator`; 100 bad sign-ins don't lock | — |
| PS-10 | E | Operator abuses SaaS access to accept a customer's Tier-0 risk | `RequiresTenantConsent`; no standing access | Runner denies the action without a tenant-owner co-signature when the profile requires it | Collusion of an operator and a customer owner is the customer's own act |
| PS-11 | I | Platform chain or audit export leaks tenant secrets | Chain stores digests and IDs only, never inputs' secret values; export is operator-only | Audit-content test as for the tenant chain | — |
| PS-12 | T | Scope class edited by a module or at runtime | Registration is init-time only, from the catalogue package; modules extend only via extension points (ADR-0003) and cannot register `platform` | Fitness: no `RegisterScopeClass` outside the catalogue package; a module descriptor declaring `platform` fails the module contract check | — |

## Fitness function `fitness-platform-scope`

Fails the build when:

1. **Drift guard (unit, runs in `go test`):** the set `{p : catalogue ScopeClass(p) == platform}` equals the set `authz.IsPlatformOnly` accepts; it contains `connections.Tier0OverridePermission`; and each constant used in a `platform` descriptor is in that set. Deleting `platformOnly` makes the "hand-kept list" form unrepresentable; the guard also greps that no `[]authz.Permission` literal in `internal/platform/authz` contains a permission string.
2. A descriptor has no scope class, or a `platform` descriptor has `StepUp == false` or is not `Irreversible`/audited (AuditKind empty).
3. Any `platform` permission appears in `BuiltInRoles`, the migration 0043 allow-list, or an import mapping.
4. `CheckPlatform` allows a `tenant` permission, or `Evaluator.Check` (the tenant path) allows a `platform` permission, for any principal (table test over the full catalogue × principal kinds, incl. TenantOwner, derived grant, token).
5. Static: `platform_operators` has no `tenant_id`, runtime role has no INSERT/UPDATE/DELETE on it outside the registered `WithPlatform` site; no import of `authn/sso` from the operator package.
6. Platform sign-in succeeds with a TOTP-only or password-only operator; step-up older than 5 minutes is accepted; an operator token is issued (each is a negative test).
7. The recovery verb works without the host ACL, issues a reusable token, or leaves existing operator sessions valid.
8. An override via the console writes only one of the two audit records.
9. `RequiresTenantConsent` is declared on the override and the runner executes it without co-signature when the profile requires consent (test with fake profile).

## Consequences

- Positive: the override becomes usable with a clear, narrow, auditable principal; one declaration site for scope; SaaS does not need a catalogue rewrite; TenantOwner stays tenant-bound.
- Cost: a second account type, a platform audit chain, a platform session type, and a recovery verb. Each is small, but together they are a real slice of work (see build tickets).
- Residual (not mitigable): anyone with host or database write access is already Tier 0 for the installation; the ADR states that rather than claiming otherwise.

## Out of scope

Platform settings UI beyond the operator surface; the SaaS workforce IdP federation (SaaS launch revision); hardware-backed operator keys (HSM is a CEO money decision, not needed here).

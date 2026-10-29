---
title: fleet.v1 contract
status: draft
date: 2026-10-22
updated: 2026-10-29
owner: api-engineer
author: api-engineer
ticket: T-0152
---

# `activediq.fleet.v1`: the fleet gateway contract

Source: `proto/activediq/fleet/v1/fleet.proto`. Generated Go: `internal/proto/activediq/fleet/v1`
(`make gen-proto`; `make gen-check` fails on drift). If the proto and this file disagree, the proto wins.
Threat model: §5.6 (TB6), TM-F-FLEET. Blueprint: `fleet` row (§5.1), §7.2.

## Shape

| RPC | Kind | Client certificate | Purpose |
| --- | --- | --- | --- |
| `Enroll` | unary | not required (the only RPC that works without one) | `EnrollRequest{enrollment_token, csr_der, component_version}` → `EnrollResponse{leaf_certificate_der, ca_bundle_pem, endpoints, leaf_not_after}` |
| `Tunnel` | bidirectional, component-initiated | required | `TunnelFrame` both ways: `open{method, timeout_ms}`, `data{payload}`, `half_close`, `close{status_code, status_message}`, `cancel`, `credit{messages}` |

The service has no other RPC (TM-TB6-T8). The server mounts it alone on the fleet listener.

## Rules (enforced by `fitness-proto` F1 to F11)

- **RPC types are pinned** (F1, T-0185). `Tunnel` takes and returns `TunnelFrame` and nothing else; `EnrollRequest` (which carries the single-use token) is the input or output of no RPC but `Enroll`. The proto tree must define `activediq.fleet.v1` at all (F11), so deleting `fleet.proto` fails the gate instead of making every rule vacuous.
- **No tenant in any message** (TM-TB6-T3, ADR-0002). Tenant and component come from the leaf
  certificate SAN, which the server sets from the enrollment token, not from the CSR.
- **No secret-bearing message** (TM-TB6-T6). A field whose name contains password, secret,
  credential, passphrase, key or token fails CI, with two exceptions that are not field names of
  this kind: the single-use `EnrollRequest.enrollment_token`, and the operation bytes in
  `CallData.payload`, which fleet never reads. The private key is generated on the host; the CSR
  carries only the public key, so `EnrollResponse` has no private-key field (AC 3).
- **Imported types cannot smuggle fields** (F2, F3, F6). The check walks every Enroll and Tunnel
  input and output transitively; fleet messages may reference only messages of
  `activediq.fleet.v1` and `google.protobuf.Timestamp`. The Enroll RPC's output (resolved from the RPC, not by name) and everything under it is an
  exact allowlist of field names and types (F4: `leaf_certificate_der`, `ca_bundle_pem`,
  `endpoints` of `Endpoint{host, port}`, `leaf_not_after`); any addition fails CI and needs
  security review. Map fields are refused everywhere (F7): they are an unchecked side channel. Only the exact package `activediq.fleet.v1` is
  treated as fleet. Every RPC input and output type is a fleet-package message (F6), and the
  token exception is keyed on the full name on the Enroll input only (F3).
- **No extension side channel** (F8). Fleet files are `syntax = "proto3"` (no editions, proto2,
  extension ranges or groups) and no file may extend a fleet message.
- **Tunnel dispatch (TM-TB6-T8).** The gateway dispatches only methods of the contract bound to
  the authenticated component, in the allowed direction; anything else closes the call
  `PERMISSION_DENIED` and is never handed to a non-fleet server. A frame on a call id the sender
  did not open, of the wrong parity, or reuse of an open id is a protocol error that closes the
  tunnel. `CallClose.status_message` from a component is untrusted: length-bounded, never rendered
  or logged raw. Enforcement tests: TM-F-FLEET (T-0069).
- **Gateway notes.** Validate that `ca_bundle_pem` holds only CERTIFICATE blocks; never log
  `enrollment_token` or the CSR; bound `component_version` length.
- **The CA bundle** `ca_bundle_pem` is what the component pins to verify the server (TM-TB6-T2).
- **Contract-agnostic.** `CallOpen.method` is the full gRPC method of the bound contract
  (for example `/activediq.connector.v1.Connector/Describe`); payloads are the bound contract's
  serialised messages. Call ids: odd = server-opened, even = component-opened.
- **Flow control** (TM-TB6-T7, T-0288): `FlowCredit` grants the peer N more `CallData` messages on a call
  (`call_id` 0: on the whole tunnel). Each side starts with the same fixed window, so there is no
  handshake: 16 messages per call (`DefaultCallWindow`), 64 per tunnel (`DefaultTunnelWindow`), plus
  256 concurrent calls and 4 MiB per message. Credit is granted back only when the local handler has
  consumed a message (batched at half a window). A call that ends with messages still buffered returns
  them to the tunnel window only when they are released: discarded at once if nobody will read them
  (local cancel or close, peer cancel), or as the reader consumes them (peer close of a call we opened;
  the reader abandoning the call discards the rest). Pending credit is retried by the writer after
  each frame it sends. Data beyond either window, or a grant of 0 or one that would lift the sender above
  its window, is a protocol violation (`data_exceeds_credit`, `credit_invalid`): the tunnel closes and
  is audited, so the read loop never waits on a slow handler. A sender with no credit blocks (until
  credit, the call's context, the call's end or the tunnel's end). Worst case buffered per tunnel is
  64 x 4 MiB; one slow call can hold tunnel credit and so slows its siblings (accepted).
- The connector contract's rule P4 (no bidirectional streams) does not apply to this package:
  `Tunnel` is the transport the connector contract rides on, not an operation of it.
  P4, P5, P6 and P8 apply to operation contracts only; fleet has F1 to F11 instead.

## Placement (blueprint §2 rule 1)

The generated stubs live in `internal/proto/activediq/fleet/v1`. `internal/platform/` must not import
`internal/proto/activediq/…`, and `fitness-modules` enforces that. The platform `fleet` package is the gateway
(T-0125's gateway ticket) and will implement the `Fleet` service from outside the platform root, or
declare its own transport-level types; that wiring, and where the `Enroll` handler is registered, is
the gateway ticket's decision. This ticket adds only the contract. Nothing under `internal/platform`
imports the generated package.

## Compatibility

New package, additive. Within `v1` only additive changes (new fields, new frame body kinds that
old peers ignore); a removed or renumbered field needs `fleet.v2`.

## Enrollment tokens and the Component store (T-0153)

`internal/platform/fleet/fleetsql` is the server-only SQL of DM-12 (migration `0007_fleet_components`).
`cmd/connector` and `cmd/agent` cannot link it: it imports `platform/store`, which rule 7 bans for both.

- **Issue** (`Enrollment.Issue`) needs `fleet.enrollment.issue` and a fresh step-up, both checked before
  any write. It creates a `pending` Component and one token, stores only the SHA-256, and returns the
  plaintext once. Lifetime defaults to 1 h, at most 24 h (a database CHECK too).
- **Token form** `enr1.<tenant uuid>.<256-bit secret>`. The tenant is routing: `Redeem` opens that tenant's
  transaction, so the Enroll handler never takes a tenant from a message. Possession is proved by the secret.
- **Redeem** (`Enrollment.Redeem`) is one compare-and-set `UPDATE … WHERE used_at IS NULL AND expires_at > now()`
  against a still-`pending` Component. Unknown, malformed, used, expired and removed all return
  `ErrTokenInvalid`. A source that has spent its failed-redeem budget (`FailureLimiter`: `Admit` reserves a try atomically with the check and `Succeeded` refunds it, so overlapping attempts are metered; default 5 then one
  per 30 s, per /32 or /64; `ip:port` accepted, an unreadable source is refused as `ErrNotConfigured`, never pooled) is refused with `ErrRateLimited` before the token is looked at.
  Residual (per-node limiter, same follow-up as the shared-store variant): when `MaxSources` is full new
  sources share one overflow bucket, so an attacker with many IPv6 /64s can throttle new legitimate sources.
- Not here: the Enroll handler, the CA, the listener, the `pending → enrolled` write (it needs the
  certificate serial), revocation, and the audited Operation around Issue.

## Enroll handler and the installation CA (T-0155)

Core: `fleetsql.Enroller` (`fleet/fleetsql/enroll.go`, `ca.go`; migration `0010_fleet_ca`). Adapter:
`internal/compose/server/fleetenroll.go` turns `fleetv1.Enroll` into `Enroller` calls, because the platform
root never imports generated protos. The listener that mounts it is T-0156.

- **One transaction.** Redeem (token CAS), CA load, leaf signing, `pending → enrolled` with `cert_serial`, and
  the audit event commit together. A failure after redemption (CA unusable, key provider down) rolls the token
  back, so a server fault does not burn it (the answer to the T-0153 review's obligation 2). A bad CSR is
  checked before redemption and is its own answer (`ErrCSR`), never a token oracle.
- **SAN.** Exactly two URIs, `urn:activediq:tenant:<uuid>` and `urn:activediq:component:<kind>:<uuid>`
  (`fleet.URIs`, read back by `fleet.IdentityOf`, which refuses any extra name). The values come from the
  token's own row; `EnrollRequest` carries no tenant or component and the CSR's subject and SAN are ignored.
  The `<kind>` is a closed vocabulary: `connector`, `addc`, `fileserver` (`fleet.ValidKind`, `identity.go`). It
  selects the `fleet.Binding`, so one module's certificate reaches only its own contract; any other kind, including
  the bare legacy `agent`, is `ErrIdentity`. A new module adds its kind in `identity.go`, the `components.kind`
  CHECK and its Binding together. Empty subject, ClientAuth only, 90-day default lifetime, clamped to the CA's.
- **CA.** One per tenant (`fleet_ca`), ECDSA P-384, created on first need or by `InitTenant`. The private key
  is PKCS#8 sealed with `keys.Seal` under the tenant DEK, bound to tenant, table, row, column and version
  (TM-A11, AC4); no column holds it in clear and nothing logs it. Per-tenant, not installation-wide, because
  `platform/keys` has only tenant DEKs; a shared CA would need an installation-scope DEK (follow-up).
- **Bundle (TM-D24 D2).** Built from parsed certificates, re-encoded as header-free `CERTIFICATE` blocks; stored
  bytes never pass through. Every stored row must be a DER CA certificate (no PEM, no trailing bytes,
  `IsCA`, `KeyUsageCertSign`), at most 8 rows and 64 KiB, SPKI hash matching, and the active CA present.
  Otherwise `Enroll` returns the generic `ErrTokenInvalid`, and an `Alerter` raises `fleet.ca.material_invalid`
  (plus `fleet.ca.suspected_key_exposure` when a private-key marker is seen).
- **Pin.** `Enroller.CAPin` returns `sha256:<hex>` of the CA SPKI for the enrolment material (D1).
- **Rotation (DM-12.I3).** `Enroller.Rotate(leaf, csr)` takes the verified leaf, reads the identity from it and
  requires that one of the named tenant's own CAs (active or retired) signed it (a verified chain only proves
  some tenant's CA did; per-tenant CA isolation depends on this check); it requires an `enrolled` or `active` component of the same kind whose current `cert_serial` equals the
  certificate's. The row, and so the identity, is kept; only the serial changes, so a superseded certificate
  cannot rotate again. The adapter uses the verified chain only, never `PeerCertificates`.
- **Source address** is `peer.Addr` from the transport, never a header (T-0153 obligation 3).
- Not here: the listener and mTLS interceptor (T-0156), revocation (T-0157), the issuing handler with its audited Operation and principal-derived tenant (T-0153
  obligations 1 and 4).

## CA key rollover (T-0563, TM-D29)

Decision: replacing the fleet CA key is **a new `fleet_ca` row, never an in-place change**, and the **old key is erased when its row retires**. Components **pin the CA by certificate** (SPKI hash), not by row, position or "the latest". This closes the TM-D29 "Fleet CA key" row ([threat-model §9.2.1](threat-model.md)).

1. **New row.** Rollover generates a new ECDSA P-384 key and CA certificate and inserts a new row (new `id`, new `spki_sha256`). The key is sealed with the row id in the AAD (`keys.Seal`, TM-A11), so a blob from another row cannot be replayed into it. Nothing updates `cert_der`, `spki_sha256`, `sealed_key` or `key_version` of an existing row (the `fleet_ca_guard` trigger already refuses it). The new row becomes `active` and the previous `active` row becomes `retired` **in the same transaction** (the partial unique index `fleet_ca_one_active` stays satisfied).
2. **Old key erased.** The `active → retired` transition sets `sealed_key` to NULL in that same transaction. A `retired` row holds only the public certificate. Migration (follow-up): `sealed_key` becomes nullable, with `CHECK (state = 'active' OR sealed_key IS NULL)` and `CHECK (state <> 'active' OR sealed_key IS NOT NULL)`; `fleet_ca_guard` allows `sealed_key` to change only on `active → retired`, and only to NULL. `retired` stays terminal (the trigger already refuses leaving it). Replaying the saved blob into the retired row fails at the CHECK; making the row `active` again fails at the trigger; both hold against the application role (TM-D29 controls 1 + 2). Signing (`Enroller`, `Rotate`) loads only the `active` row, so no path needs a retired key. Cryptographic erasure alone (DEK shredding, TM-D15) is not the control: the DEK is shared by the tenant's other values.
3. **Retired certificates stay as trust anchors.** The retired row's `cert_der` remains in `TenantCAs` and the bundle, so leaves it signed keep verifying until they expire (90 days at most, clamped to the CA's `not_after`). A retired row is removed from the bundle only when no unexpired, non-superseded leaf chains to it, or at once on the compromise path below. Bundle limits are unchanged (at most 8 rows, 64 KiB).
4. **Clients pin by certificate.** `ca-pin.txt` is the SHA-256 of the SPKI of a CA certificate, and `dial.ParseBundle` accepts a bundle only if it contains a certificate with that SPKI (D3). The pin identifies a key, so it never "follows" the active row. After a rollover the old pin still validates every certificate chaining to the old CA. A component adopts the new CA only from a bundle delivered over a connection it already verified against its pinned CA (a leaf `Rotate`/`Enroll` answer carrying `ca_bundle_pem`), and only if the new CA certificate is **cross-signed by the old CA key** at rollover (the one use of the old key, before step 2 erases it; the cross-certificate is public and stored with the new row). The client then pins both SPKIs, and drops the old pin when the old CA leaves the bundle.
5. **Planned versus compromise.** *Planned* (expiry approaching, yearly): steps 1 to 4, no re-enrolment; the cross-signature carries the fleet over. *Suspected key exposure* (`fleet.ca.suspected_key_exposure`, TM-D24): a cross-signature from a possibly stolen key proves nothing, so the old row is retired and erased **and removed from the bundle and `TenantCAs` at once**, which makes the gateway refuse every leaf it signed (TM-Q8); every component re-enrols with a new single-use token against the new pin, which an admin reads from the console out of band. This is a deliberate availability cost and is audited as one operation.
6. **Authorisation and audit.** Rollover is an admin Action behind a fresh step-up and its own permission (`fleet.ca.rotate`), one transaction, with an audit event `fleet.ca.rotated` naming old and new SPKI hashes and the path (planned or compromise). The key itself never appears in any event or log.
7. **Fitness (TM-F-SEAL, extended).** (a) After rollover the old row has `sealed_key IS NULL`, and writing the saved old blob back as the application role is refused by the CHECK. (b) Setting the old row `active`, or changing any column of a retired row, is refused by the trigger. (c) Two concurrent rollovers leave exactly one `active` row. (d) A component with the old pin accepts the new CA only with a valid cross-signature and refuses a bundle without its pinned SPKI. (e) On the compromise path a leaf signed by the old CA gets `Unauthenticated` at once.

Wire shape: no change to `fleet.v1`. `EnrollResponse.ca_bundle_pem` already carries the CA certificates, F4's allowlist is untouched, and the cross-certificate travels as one more `CERTIFICATE` block in the bundle. Follow-ups: migration and `Enroller.RotateCA`, `dial` pin-set handling, the fitness tests above.

## Gateway client-CA pool: the cross-tenant read of `fleet_ca` (T-0712)

**Problem.** The gateway's `serverTLS` needs one `ClientCAs` pool holding every tenant's CA certificates (`clientCAs func() *x509.CertPool`, read per handshake), so a leaf from a forged or unknown CA is refused in memory before any identity or database work. `fleet_ca` is a Tenant table under `FORCE` RLS; `WithPlatform` reads it as empty and reaches only registered-global tables. BYPASSRLS is excluded ([ADR-0002](../decisions/0002-deployment-model.md) rule 4).

**Decision (option b, hardened): a registered `SECURITY DEFINER` reader owned by a dedicated, column-limited role.**

1. **Role.** `activediq_catrust`: `NOLOGIN NOSUPERUSER NOBYPASSRLS`, owns nothing but the one function, created by the installer beside `activediq_owner` and `activediq_app` (the owner has no CREATEROLE, migration `0001`). Migration `0055_fleet_ca_trust` (T-0733) fails loudly if it is missing, as `0001` does for the other two. **Migration prerequisites (security review MF2):** (i) the installer makes `activediq_owner` a member of `activediq_catrust` (`ALTER FUNCTION ... OWNER TO` needs it); (ii) the migration runs `GRANT USAGE ON SCHEMA public TO activediq_catrust` (it must resolve the table and function); (iii) PostgreSQL 15+ gives `public` no `CREATE` for ordinary roles and the new owner needs `CREATE` on the schema to receive ownership, so the migration does `GRANT CREATE ON SCHEMA public TO activediq_catrust`, creates the function as `activediq_owner`, runs `ALTER FUNCTION ... OWNER TO activediq_catrust`, then `REVOKE CREATE ON SCHEMA public FROM activediq_catrust`, all in the same migration. (iv) `activediq_app` must not be a member of `activediq_catrust` (it holds `EXECUTE` only); the `0001` `roleRisk` guard is extended to refuse that membership. The installer spec lists exactly these memberships and no others.
2. **Privileges, enforced by the database.** `GRANT SELECT (tenant_id, id, state, cert_der, spki_sha256, not_after) ON public.fleet_ca TO activediq_catrust`. No grant on `sealed_key`, `key_version`, `created_at`; no INSERT, UPDATE, DELETE. One added permissive policy `fleet_ca_trust_read ON public.fleet_ca FOR SELECT TO activediq_catrust USING (state IN ('active','retired'))`. `fleet_ca_tenant` is untouched, so the runtime role still reads `fleet_ca` as empty under `WithPlatform` and the tenancy probe stays true.
3. **Function.** `public.fleet_ca_trust_anchors() RETURNS TABLE (tenant_id uuid, spki_sha256 bytea, cert_der bytea, not_after timestamptz)`, `LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp` (plpgsql, not sql: a SQL function cannot `RAISE`; security review MF1), owned by `activediq_catrust`, `REVOKE ALL FROM PUBLIC`, `EXECUTE` to `activediq_app` only. The body begins `IF NULLIF(current_setting('app.tenant_id', true), '') IS NOT NULL THEN RAISE EXCEPTION ... USING ERRCODE = '42501'; END IF;` then `RETURN QUERY SELECT ... WHERE state IN ('active','retired') AND not_after > now()`. This is the inverse of the guard in `audit_wipe_retired_key` (migration `0020`), so a tenant transaction can never call it and only a platform-scope transaction can. The return type has no key column; the role has no privilege on one. A bug in the function body therefore cannot reach `sealed_key` (the privilege error is the control, not review).
4. **One call site.** `internal/platform/fleet/fleetsql` `TrustAnchors.Load` calls it under `store.WithPlatform(ctx, "fleet: load every tenant's CA certificates for the gateway client-CA pool")`. It is registered in `exempt/registry.json`: one `securityDefiner` entry (`public.fleet_ca_trust_anchors()`) and one `platformPaths` entry (`withPlatform: true`, `mintsTenantID: true`, because `Load` parses tenant ids out of the rows it reads). The reader returns `[]Anchor{Tenant tenant.ID; Cert *x509.Certificate}`, parsed with `parseStoredCert` (strict: DER, `IsCA`, `KeyUsageCertSign`, no PEM, no private-key marker); a row that fails does not enter the pool, raises `fleet.ca.material_invalid` and the refresh keeps the previous pool for the other tenants (a single bad tenant must not take the fleet down, unlike the per-tenant bundle, which fails whole).
5. **What does not change.** `fleet_ca` stays `Kind: Tenant`. No new table, no `tablekind` change, no domain-model kind change, so `fitness-domain-keys` REG (kind vs heading vs exemption registry) is unchanged. X1 gets one sentence (below); X4 is unaffected (`sealed_key` is not selectable on this path).

**Options considered**

| Option | Verdict | Why |
| --- | --- | --- |
| (a) Registered-global `fleet_ca_trust` table kept beside `fleet_ca` | Rejected | A global table is readable by every tenant transaction (no RLS), so tenant code or an injected query reads the whole install's CA list and tenant ids; the registry already carries that caveat for `jobs`. It is a second copy that can drift from `fleet_ca`, and a removed CA lingering in it is a trust failure. Keeping it honest needs definer triggers and revoked write grants: the machinery of (b) plus a table. It also needs a new `P` entity in the domain model. |
| (b) `SECURITY DEFINER` function | **Chosen**, with the dedicated role | No copy, nothing to drift, no new kind. A plain owner-owned definer does not work: the owner is bound by `FORCE` RLS and holds every column, so `sealed_key` would be unreachable only by code review. The dedicated role makes it unreachable by privilege. |
| (c) `tablekind`/registry extension (a "platform-readable tenant table") | Rejected | RLS is row-level: a platform-scope policy for the runtime role exposes every column including `sealed_key`, and breaks the invariant that every `T` table reads empty under `WithPlatform`, which `fitness-tenancy` probes. It would need a column-level mechanism that is (b) again. |
| (d) No pool: `RequestClientCert` + `VerifyPeerCertificate` verifying against `TenantCAs(SAN tenant)` | Rejected as the primary design | It removes the cross-tenant read, but it moves a database read before authentication: any unauthenticated peer can force one per handshake by naming a tenant. The pool rejects forged chains in memory. Kept as the fallback if the pool cannot meet the scale budget below. |
| BYPASSRLS on any role | Excluded | ADR-0002 rule 4 and the `roleRisk` startup guard. |

**The pool is a first gate, not the authority.** After the handshake the interceptor still runs `TenantCAs(ctx, id.Tenant)` (a live per-tenant read) and requires the leaf to be signed by *that tenant's own* CA (TM-Q8), on every RPC. A tenant-A CA in the pool therefore can never authenticate a leaf whose SAN names tenant B. That per-tenant check is not optional and not cacheable beyond the DB read; removing it is a ticket-level regression (fitness F-POOL-3).

**Freshness.**
- `PoolProvider.Pool()` returns an immutable `*x509.CertPool` swapped atomically; it never blocks a handshake on the database.
- Refresh every **10 s** per gateway node, jitter only downward (interval uniform in 8 to 10 s, so it never exceeds 10 s), query timeout 5 s, plus an immediate `Invalidate()` when the same process commits a rollover, withdrawal or tenant provision.
- **Bound.** A CA that is withdrawn (below) leaves the pool of every node within **15 s** of the commit (10 s maximum interval + 5 s query timeout; a refresh whose query started before the commit is the worst case). A new tenant's CA enters within the same bound; an `Enroll` needs no pool, so first enrolment is unaffected, and a new component's first mTLS connect can retry (the dial layer retries with the same pin, no fallback).
- **Fail closed.** If no refresh has succeeded for **60 s**, `Pool()` returns an empty pool: client certificates are refused until the database answers. Enroll is unaffected (no client certificate). Staleness is a metric and an alert.
- Whatever the pool says, the per-RPC `TenantCAs` check refuses a withdrawn CA's leaf on **every new RPC at once**; the 15 s bound limits only how long a stale pool could complete a handshake that the first RPC then refuses.
- **Open streams (security review MF3).** The per-RPC check does not cover a stream already open: today the stream recheck (`gateway.go` ~287 to 295) calls `Components.Usable` only. Required changes, carried into T-0714: (i) the process that commits a withdrawal calls `Gateway.CloseTenant(tenant)` (cancels every registered stream of that tenant, as `CloseComponent` does for one component) in the same step as `Invalidate()`; (ii) every stream's `Config.Recheck` tick (default 5 s) also re-runs the per-tenant CA check (`TenantCAs` for the stream's tenant, leaf signed by one of them), so on every other node a leaf from a withdrawn CA loses its stream within one Recheck (**5 s** plus the lookup timeout; the lookup is a live read, independent of the pool). A lookup failure on recheck keeps the stream until the next tick but fails closed after the same 60 s staleness rule as the pool. The compromise-path bound is therefore: new RPCs at once, open streams 5 s plus lookup timeout (10 s worst case), new handshakes 15 s.

**Removal needs a state.** Today `fleet_ca` has `active` and `retired`, `DELETE` is revoked, and step 3 and 5 of "CA key rollover" speak of "removed from the bundle" with no representation. Decision: add terminal state **`withdrawn`** (the `state` CHECK extended). `fleet_ca_guard` becomes an **explicit allow-list of state transitions** (security review MF4): `active → retired` (existing; sets `sealed_key` NULL), `retired → withdrawn`, `active → withdrawn` (compromise path; also sets `sealed_key` NULL). Everything else, including `withdrawn → anything` and `retired → active`, raises `AD403`; `cert_der`, `spki_sha256`, `tenant_id` and `id` stay immutable. A `BEFORE` row trigger cannot enforce "the same transaction inserts the replacement" (and `fleet_ca_one_active` allows the replacement only after the old active row has left `active`), so the guarantee that a tenant is never left without an active CA is a **`DEFERRABLE INITIALLY DEFERRED` constraint trigger** on `fleet_ca` that, at commit, requires every tenant touched by a transition to `withdrawn` to have exactly one `active` row, else `AD403`. The compromise-path order inside one transaction is: `active → withdrawn`, then insert the new `active` row. `TenantCAs`, the bundle and `fleet_ca_trust_anchors()` take `active` and `retired` only. `withdrawn` rows keep `cert_der` for audit. Folded into the T-0563 migration ticket's `sealed_key` change (T-0733 owns the DDL).

**Data exposure of the new path.** It returns public certificates plus the `tenant_id` that owns each; a platform-scope caller learns the tenant list. That is the same knowledge the platform already has (`tenants` is global; `Claim` sees every tenant's jobs). All CA subjects are the constant `activeDIQ fleet CA` (no tenant data), so the TLS `certificate_authorities` list Go sends to a client reveals nothing per tenant; fitness F-POOL-6 pins that. Scale: identical subjects force Go to try candidate issuers by key id first; chain building cost with thousands of CAs is [UNVERIFIED] and gets a benchmark gate (F-POOL-7) before SaaS use; failing it triggers option (d).

**Fitness functions (T-0714 adds them; the ADR is `accepted` when green in CI).**
- F-POOL-1 `fitness-tenancy` registry: exactly one `securityDefiner` entry for `fleet_ca_trust_anchors` and one `WithPlatform` site naming it; the function is named in SQL nowhere else (`global-table-sql`-style scan).
- F-POOL-2 catalog (real PostgreSQL 16 and 18): `activediq_catrust` is `NOBYPASSRLS`, `NOLOGIN`; holds no privilege on `fleet_ca.sealed_key`, `key_version`, `created_at` and no write privilege on any table; has no `CREATE` on any schema; owns exactly one object (the function); its memberships (and members) equal the installer spec (`activediq_owner` is a member; `activediq_app` is not); the function's result columns equal the four above; `activediq_app` has no BYPASSRLS membership (existing `roleRisk` unchanged, extended per point 1 (iv)).
- F-POOL-3 behaviour: with tenants A and B seeded, the pool holds both tenants' active and retired CAs and nothing else; it excludes `withdrawn` rows and rows past `not_after`; a leaf signed by A's CA but with B's SAN is refused by the interceptor; a `withdrawn` CA's leaf is refused at once on a new RPC and absent from the pool after one refresh; one tenant with an unparseable row leaves every other tenant in the pool.
- F-POOL-4 the function called inside `WithTenant` fails `42501`; the runtime role `SELECT sealed_key FROM fleet_ca` under `WithPlatform` returns zero rows and under any context cannot read other tenants' rows (existing probe); as `activediq_catrust` (test-only `SET ROLE`), `SELECT sealed_key FROM fleet_ca` fails with a privilege error (`42501` permission denied, not an empty result) while `SELECT cert_der` works. The catalog also asserts `pg_proc`: `prosecdef`, `proconfig = {search_path=pg_catalog,pg_temp}`, `proowner = activediq_catrust`, and `proacl` grants `EXECUTE` to `activediq_app` and the owner only, never `PUBLIC`.
- F-POOL-5 freshness: injected clock; the withdrawn CA is out within 15 s; no successful refresh for 60 s yields an empty pool; the pool recovers on the next successful refresh without a restart.
- F-POOL-6 every generated CA subject equals the constant; no tenant id in any CA certificate field.
- F-POOL-7 handshake benchmark at 1,000 tenants (8,000 CAs worst case) within the budget set in T-0714.
- **Implementation (T-0714).** `gateway.PoolProvider` (`gateway/pool.go`; `Pool()`, `Refresh`, `Invalidate`, `Run`, `Staleness`) takes a loader; `fleetsql.TrustAnchors.Certificates` is that loader. `Gateway.CloseTenant` and the stream re-check (`Config.Recheck`, `Config.CAStale` default 60 s) are in `gateway.go`. **Benchmark finding (F-POOL-7):** passing the pool as `tls.Config.ClientCAs` cannot work at scale. Go announces every CA subject in the CertificateRequest and the `certificate_authorities` extension has a 16-bit length, so about a thousand same-subject CAs (even one per tenant at 1,000 tenants) fail every handshake with EOF. Fallback (d) was not needed: `serverTLS` leaves `ClientCAs` unset, requests (does not require) a client certificate, and verifies the chain against the pool in `VerifyConnection`; `verifiedCreds` copies the chain it built into `TLSInfo.VerifiedChains`, which `authenticate` and the enrol handler read. The forged-chain refusal is still in memory before any database work. Budget: median client dial plus call under 50 ms against 1,000 tenants x 8 CAs (measured about 32 ms); `TestPoolHandshakeAtScale`.
- F-POOL-8 open streams: a tenant's streams are cancelled by `CloseTenant` on withdrawal in the committing process, and on a second gateway node (separate process, shared database) a stream whose leaf is from the withdrawn CA ends within `Recheck` + lookup timeout; streams of tenant B are untouched.
- F-POOL-9 transitions: a table-driven test over every (from, to) pair of states proves only `active→retired`, `retired→withdrawn`, `active→withdrawn` succeed; `withdrawn→*` and `retired→active` raise `AD403` (TM-D29); `cert_der` update refused; `active→withdrawn` committed without a replacement `active` row is refused at commit, and with the replacement inserted in the same transaction succeeds.

Threat-model links: TM-A11 (key never leaves the sealed column; unreachable here by privilege), TM-D24 rule D (strict parse), TM-D29 (`withdrawn` is terminal), TM-Q8 (per-tenant issuer check retained). Reviewed by security-architect on T-0712.

## Component side: `fleet/dial` (T-0158)

- **Enrol.** `dial.Enroll(ctx, Material{Address, Token, Pin}, dir, Exchange)`. The pin is mandatory (D1).
  First the server's *presented* chain is read by a handshake against an empty, non-nil pool (it fails by
  design, sends no application data, and yields `tls.CertificateVerificationError.UnverifiedCertificates`);
  the cert with the pinned SPKI becomes the only root of the real connection, on which the token is sent.
  No `InsecureSkipVerify`, no verify callback. **Obligation on the gateway (T-0156):** the Enroll listener
  must include the installation CA in its presented chain, or enrolment is refused (`ErrUntrustedServer`).
- **Bundle (D3).** `dial.ParseBundle`: CERTIFICATE blocks only, no headers, whitespace-only around, 1 to 8
  CAs, at most 64 KiB, one matching the pin; `AppendCertsFromPEM` never touches raw bytes. The result is a
  `Bundle{Roots, ClientCAs}` (ADR-0008 decision 5): **Roots** are exactly the certificates matching the pin and
  must have the server-root shape (`IsCA`, `MaxPathLen 0`, `KeyUsageCertSign`); **ClientCAs** are all others
  (the tenant's client CAs and cross-certificates) and never become a TLS root.
- **Leaf.** Must carry our public key, verify for ClientAuth to a **ClientCA** of the bundle (never to the pinned
  server CA), and have a component identity.
- **Repin (ADR-0008 obligation 5).** `dial.Repin(ctx, dir, newPin, audit)` / `agentsetup repin <pin>`: the new
  pin arrives out of band; the new root is taken from a configured endpoint's chain (SPKI match + full
  verification), key and leaf are untouched, and the state is rewritten in three loadable steps (bundle with
  both roots, new pin, bundle without the old root). One audit event per use (Application log 4102/4103).
- **Persistence.** `ca-bundle.pem`, `ca-pin.txt`, `endpoints.txt`, `key.pem` (0600, PKCS#8), `leaf.pem`
  in a 0700 directory, each by temp+rename, leaf last; `Load` re-validates everything. Nothing is written on
  any failure. On non-unix hosts the package fails closed (no state written or read) until the owner-only DACL lands in T-0291. Load returns ErrExpired for an expired leaf or CA.
- **Dial-out.** `dial.DialOut(addr, state)` uses `Credentials`: TLS 1.3, roots exactly `State.Roots` (the pinned server CA); a leaf signed by a tenant CA is refused as a server.
  Nothing retries or falls back; retry policy is the caller's and must reuse the same pin.
- **Seam.** `dial` imports no generated proto; the role package supplies `Exchange` (fleetv1 Enroll call).

## Gateway transport and per-RPC authentication (T-0156)

`internal/platform/fleet/gateway/gateway.go (package gateway; moved out of the agent closure by T-0688 ruling 3, with hub.go)`. Contract-agnostic (no generated-stub import): the composer
mounts the `Fleet` service on the server `Gateway.NewServer` builds and states every method's auth class.

- **Listener**: `NewServer` builds its own TLS (no caller `tls.Config`; the gateway's credentials and interceptors are applied after caller options so they cannot be replaced): TLS 1.3 with `VerifyClientCertIfGiven` (Enroll must work without a
  certificate), client CA pool read per handshake.
- **Interceptors** (unary + stream) run before any handler. `ClassPublic` is accepted for `EnrollMethod`
  only (`NewGateway` rejects any other). Every other method needs a verified chain, a leaf inside its
  validity (gateway clock) with clientAuth EKU, and a SAN of exactly one tenant + one component.
- **Tenant bound to issuer** (TM-Q8): the pool holds every tenant's CA, so the leaf must also be signed
  by a CA of the tenant named in its SAN (`TenantCAs`, implemented by `fleetsql.Enroller.TenantCAs`). A
  lookup failure refuses (`Unavailable`); it never admits.
- **Identity** is put in the context (`fleet.IdentityFrom`); handlers never read tenant from a message.
- **Deny by default**: `NewServer` fails if a registered method has no explicit class, or a service is
  outside `activediq.fleet.v1.` (no console or API routes). `Routes(srv)` lists the mounted surface.

## Revocation (T-0157, TM-TB6-T9)

- **Refused at establishment, every RPC**: after the certificate checks, the interceptor asks
  `Config.Components` (`ComponentStatus.Usable`, implemented by `fleetsql.Lifecycle`) whether the
  component is `enrolled` or `active`. A revoked (or removed, or unknown) component with a still-valid
  certificate gets `Unauthenticated`; a lookup failure gets `Unavailable`. `Components` is required.
- **Superseded certificate refused (T-0292, TM-TB6-T14)**: establishment calls `ComponentStatus.Current`,
  which is `Usable` plus "presented serial == `components.cert_serial`". After `Rotate` the old leaf gets
  `Unauthenticated` until it expires. The open-stream re-check calls `Usable`, which ignores the serial,
  so a rotation does not drop the stream it was made on.
- **Superseded certificate is a theft signal (T-0300)**: when a CA-verified, unexpired leaf is not
  `Current` but the component is still `Usable`, the gateway calls the optional `Config.Superseded`
  (`fleet.SupersededReporter`, implemented by `fleetsql.SupersededReporter`): a fleet alert plus an audit
  event naming the component, the presented serial and the current serial. At most once per component per
  `Config.SupersededWindow` (default 10 min). The refusal stays `Unauthenticated`; a reporter error is
  logged. The response is Revoke.
- **Open streams are closed**: authenticated streams are registered by (tenant, component).
  `Gateway.CloseComponent` cancels them at once. The interceptor runs the handler on its own goroutine
  and returns `Unauthenticated` as soon as the stream is revoked, so grpc ends the transport stream and
  a handler blocked in `RecvMsg`/`SendMsg` is unblocked and exits whether or not it watches its context;
  each stream also re-checks `Usable` every `Config.Recheck` (default 5 s), which bounds the lifetime
  of a stream whose component was revoked through another server instance. A failed re-check leaves the
  stream open (a database blip must not drop the fleet); new RPCs are refused meanwhile.
- **Revoke**: `fleetsql.Lifecycle.Revoke` checks `fleet.component.revoke` server-side, moves
  enrolled/active to revoked, appends `fleet.component.revoked` (actor = the human or token principal,
  target = component GUID, cert serial) in the same transaction, then calls `StreamCloser`. Revoking an
  unused enrollment token is T-0153's.
- **Not yet wired**: the composer must pass the same `Lifecycle` as `Config.Components` and `Streams`
  (the gateway), and expose Revoke on the API; both belong to the compose/API tickets.

## Tunnel multiplexer (T-0209, TM-D24 A, B, C)

`internal/platform/fleet/{mux,calls,contract,hub,frame,statustext}.go`. Contract-agnostic and free of
the generated stubs: the compose adapter that serves `Fleet.Tunnel` translates `fleetv1.TunnelFrame` to
`fleet.Frame` and supplies a `Transport`. One `Mux` is one tunnel instance; `Role` selects the parity
(server odd, component even), so `fleet/dial` (T-0158) reuses it with `RoleComponent` and the rules exist once.

- **A. Dispatch.** `Bindings` maps the SAN kind to a `Binding{Contract, Serve}` (`Bindings.For`; an
  unbound kind has no tunnel). `NewContract` builds two exact-match allow-sets from generated service
  descriptors (server to component, component to server). There is no normalisation. A component open
  of anything outside its set (another contract, a server-only method, health, reflection, channelz,
  case, slash or suffix variants, empty) gets one fixed `PERMISSION_DENIED` ("method not available") and
  no handler runs; a name over 256 bytes or not UTF-8 is a protocol error (B5) and closes the tunnel.
  Component-opened calls go to a per-tunnel `registrar` that refuses (and fails `NewMux` on) any method
  outside the contract; it is never a `grpc.Server`. Calls this side opens are checked against its own
  set before anything is sent.
- **B. Call identity.** State is `Mux.calls`, keyed by call id inside the tunnel instance, and dies with
  it. Each side's open ids have its parity and strictly increase; ids are spent even when refused. The
  per-role, per-state table is in `Mux.handle`. `call_id` 0 carries `credit` only. A frame for a call this
  side cancelled or closed (still in the tombstone window, 1024 ended calls; a tombstone holds only the id and how the call ended, never its inbox) is dropped; a second `CallData` from the peer on a unary call is a `forbidden` violation, so it is never buffered; any other
  violation closes the tunnel and calls `Reporter.ProtocolError(identity, Violation)`, a fixed
  vocabulary with no peer text. Ending a tunnel (`Mux.fail`) fails every pending call `UNAVAILABLE`
  as a `CallError` with `OutcomeUnknown(err) == true`; `Hub` never moves a call, and a new tunnel of
  the same component closes the old one. Open calls per direction are bounded (`MaxCalls`, default 256;
  a peer open beyond it gets `RESOURCE_EXHAUSTED`).
- **C. Status text.** The peer's `status_code` goes through `NormalizeCode` (0 to 16, else `UNKNOWN`).
  The error a caller gets carries `FixedText(code)`; the component's text is `SanitizeStatusText`-ed
  (at most 1 KiB, invalid UTF-8 replaced, controls, bidi, line separators, backslash and HTML
  metacharacters as `\uXXXX`) and reachable only through `ComponentReported(err)`, for a typed
  `component_reported` field. It is logged only as the structured `component_reported` attribute and is
  never in an error string or an audit summary. What the server sends is `FixedText(code)`.
- **Late frames.** A frame for an id this side certainly used (its own below `nextID`, the peer's at or
  below the highest open seen) that has aged out of the tombstone window is dropped like a tombstone's;
  its data is returned to the tunnel window. A peer id it skipped is indistinguishable, so it is also dropped.
- **Compose adapter (T-0287).** `internal/compose/server/fleettunnel.go`: `ServeTunnel(TunnelDeps, stream)`
  translates `TunnelFrame` to `fleet.Frame`, resolves `Bindings.For(identity)` (only `connector` is bound,
  server opens every `Connector` method), builds a server-role `Mux`, `Hub.Attach`es it and runs
  `Mux.Run(stream.Context())` on the gateway's derived context, so `CloseComponent` or the re-check fails
  the Mux and the Hub refuses the component. `fleetsql.TunnelReporter` implements `Reporter` over the audit
  port: `fleet.tunnel.protocol_error`, outcome denied, reason and `violation` detail = the fixed violation,
  target = the component GUID, no peer text. The peer's `CallClose` text stays a structured log attribute
  (`component_reported`); the `Reporter` interface carries none, so no audit consumer exists for it yet.
  `server.NewFleetService(enroller, TunnelDeps)` builds the `Fleet` service (Enroll + Tunnel) the gateway mounts.
  Proof: `compose/fleetproof/tunnel_test.go` serves that real service under the real gateway with the real
  `TunnelReporter` over a seeded database: revoke, pending call outcome unknown, hub refuses, sibling
  unaffected; a violation lands as an audit event targeting the component.
- **Not here.** Building the gateway, Hub and listener in `server.Run` (no fleet listener is composed yet); the `fleet/dial` wiring.

---
title: fleet.v1 contract
status: draft
date: 2026-10-22
updated: 2026-10-22
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
- **Flow control** (TM-TB6-T7): `FlowCredit` grants the peer N more `CallData` messages on a call
  (`call_id` 0: on the whole tunnel). Numeric limits are the gateway's, in T-0069's ticket.
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

`internal/platform/fleet/fleetsql` is the server-only SQL of DM-12 (migration `0006_fleet_components`).
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

Core: `fleetsql.Enroller` (`fleet/fleetsql/enroll.go`, `ca.go`; migration `0008_fleet_ca`). Adapter:
`internal/compose/server/fleetenroll.go` turns `fleetv1.Enroll` into `Enroller` calls, because the platform
root never imports generated protos. The listener that mounts it is T-0156.

- **One transaction.** Redeem (token CAS), CA load, leaf signing, `pending → enrolled` with `cert_serial`, and
  the audit event commit together. A failure after redemption (CA unusable, key provider down) rolls the token
  back, so a server fault does not burn it (the answer to the T-0153 review's obligation 2). A bad CSR is
  checked before redemption and is its own answer (`ErrCSR`), never a token oracle.
- **SAN.** Exactly two URIs, `urn:activediq:tenant:<uuid>` and `urn:activediq:component:<kind>:<uuid>`
  (`fleet.URIs`, read back by `fleet.IdentityOf`, which refuses any extra name). The values come from the
  token's own row; `EnrollRequest` carries no tenant or component and the CSR's subject and SAN are ignored.
  Empty subject, ClientAuth only, 90-day default lifetime, clamped to the CA's.
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

## Component side: `fleet/dial` (T-0158)

- **Enrol.** `dial.Enroll(ctx, Material{Address, Token, Pin}, dir, Exchange)`. The pin is mandatory (D1).
  First the server's *presented* chain is read by a handshake against an empty, non-nil pool (it fails by
  design, sends no application data, and yields `tls.CertificateVerificationError.UnverifiedCertificates`);
  the cert with the pinned SPKI becomes the only root of the real connection, on which the token is sent.
  No `InsecureSkipVerify`, no verify callback. **Obligation on the gateway (T-0156):** the Enroll listener
  must include the installation CA in its presented chain, or enrolment is refused (`ErrUntrustedServer`).
- **Bundle (D3).** `dial.ParseBundle`: CERTIFICATE blocks only, no headers, whitespace-only around, 1 to 8
  CAs, at most 64 KiB, one matching the pin; `AppendCertsFromPEM` never touches raw bytes.
- **Leaf.** Must carry our public key, verify to the bundle for client auth, and have a component identity.
- **Persistence.** `ca-bundle.pem`, `ca-pin.txt`, `endpoints.txt`, `key.pem` (0600, PKCS#8), `leaf.pem`
  in a 0700 directory, each by temp+rename, leaf last; `Load` re-validates everything. Nothing is written on
  any failure. On non-unix hosts the package fails closed (no state written or read) until the owner-only DACL lands in T-0291. Load returns ErrExpired for an expired leaf or CA.
- **Dial-out.** `dial.DialOut(addr, state)` uses `Credentials`: TLS 1.3, roots exactly the pinned CAs.
  Nothing retries or falls back; retry policy is the caller's and must reuse the same pin.
- **Seam.** `dial` imports no generated proto; the role package supplies `Exchange` (fleetv1 Enroll call).

## Gateway transport and per-RPC authentication (T-0156)

`internal/platform/fleet/gateway.go`. Contract-agnostic (no generated-stub import): the composer
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
- **Not here.** Credit accounting and the numeric flow-control limits (TM-TB6-T7); the compose adapter
  that serves `Fleet.Tunnel`, the audit `Reporter` and the connector `Bindings`; the `fleet/dial` wiring.

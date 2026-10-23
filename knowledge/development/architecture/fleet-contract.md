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

## Rules (enforced by `fitness-proto` F1 to F8)

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
  P4, P5, P6 and P8 apply to operation contracts only; fleet has F1 to F8 instead.

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
  `ErrTokenInvalid`. A source that has spent its failed-redeem budget (`FailureLimiter`, default 5 then one
  per 30 s, per /32 or /64) is refused with `ErrRateLimited` before the token is looked at.
- Not here: the Enroll handler, the CA, the listener, the `pending → enrolled` write (it needs the
  certificate serial), revocation, and the audited Operation around Issue.

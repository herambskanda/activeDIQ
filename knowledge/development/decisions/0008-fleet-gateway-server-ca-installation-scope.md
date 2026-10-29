---
title: "ADR-0008: The fleet gateway is authenticated by one installation-scope server CA; component identities stay under per-tenant CAs"
date: 2026-10-29
updated: 2026-10-29
status: proposed
owner: solution-architect
kind: technical
ticket: T-0713
fitness: fitness-fleet-ca-scope (to be built, follow-up filed; not yet in CI)
---

# ADR-0008: The fleet gateway is authenticated by one installation-scope server CA; component identities stay under per-tenant CAs

**Status:** proposed. Ratified by factory-director after security-architect review; `accepted` when `fitness-fleet-ca-scope` runs green in CI. **Kind:** technical (no CEO fork: nothing here changes who can buy, cost or platform strategy; ADR-0002's "self-hosted first, SaaS-ready" is the constraint). **Ticket:** T-0713. Builds on [fleet-contract](../architecture/fleet-contract.md), TM-D24 (§9.8), TM-D29 (§9.2.1), TM-A11.

## Context

`fleet/dial` pins the CA by SPKI (`sha256:<hex>`, TM-D24 D1) and takes the root **from the chain the server presents**: it reads `UnverifiedCertificates` from a handshake against an empty pool and uses only the certificate whose SPKI matches the pin as the root (fleet-contract, "Component side"). So the gateway must present a chain `Certificate[] = leaf + CA`, and the CA in it must be the one the component pinned.

Today the only CA is per tenant (`fleet_ca`, sealed under the tenant DEK, `Enroller.CAPin` per tenant), and that CA signs **ClientAuth** component leaves only. Nothing signs a **ServerAuth** leaf; the listener is unwired (T-0156 built the gateway, composition is T-0716/T-0717). One TLS listener serves every tenant, and it can present only one chain per handshake. Before a component enrols it has no certificate, so the server cannot tell which tenant is calling except by SNI or listener. A gateway chain terminating in tenant A's CA fails A's pin for tenant B's components. That is the gap.

Facts the choice must respect:

- TM-Q8 / `TenantCAs`: the gateway client-pool holds every tenant's CA and then requires the leaf to be signed by a CA **of the tenant named in its SAN**. Per-tenant CA isolation is a live control; a single client-signing CA removes it.
- TM-A11: the CA key can mint identities. Its blast radius is the thing to minimise.
- `platform/keys` has tenant DEKs only; an installation-scope DEK is T-0715 (supersedes T-0253).
- Self-hosted, single tenant is first; SaaS (many tenants, one fleet endpoint) must not need a rewrite.

## Decision

We split the two jobs the one CA was doing.

1. **Installation server CA** (`fleet_server_ca`, new, installation scope, no `tenant_id`). ECDSA P-384, `IsCA`, `MaxPathLen 0`, `KeyUsageCertSign` only, 10-year lifetime like the tenant CA. Its private key is PKCS#8 sealed with `keys.Seal` under the **installation DEK** (T-0715), AAD = table, row, column, key version (no tenant id). It signs **ServerAuth leaves only**. It is never added to the gateway's client-verification pool, so it can never validate a component identity.
2. **Per-tenant client CAs** stay exactly as built (`fleet_ca`): ClientAuth leaves, tenant DEK, `TenantCAs` issuer binding, `Rotate` check. They are no longer the component's pin.
3. **The pin is the server CA's SPKI.** One value for the whole installation (`Enroller.ServerPin`; `CAPin` is renamed, see below). The enrolment material is `{address, token, pin}`, the same shape as today; every tenant's material carries the same pin. The pin is not secret.
4. **Presented chain:** `tls.Certificate.Certificate = [leaf DER, server CA DER]` and nothing else. Never a tenant CA (it would disclose which tenants exist and is not needed).
5. **`EnrollResponse.ca_bundle_pem`** carries, in at most 8 certificates and 64 KiB: the server CA (matches the pin) and the **requesting tenant's** client CA(s) (active, retired, and the TM-D29 cross-certificate). `dial.ParseBundle` still demands one block matching the pin. Change in `dial`: the dial-out **roots are exactly the certificates matching a pinned SPKI** (the server CA set), and the tenant client CA certificates are used **only** to check that our issued leaf verifies for ClientAuth (today's "leaf must verify to the bundle"). A tenant CA is never a TLS root for dialling the server.
6. **Server leaf.** Generated in-process by the gateway (ECDSA P-256, key held in memory only, never persisted, never in a log); signed by the server CA key unsealed inside the Enroller method. EKU `ServerAuth` only; KeyUsage `digitalSignature`; `IsCA` false; empty subject; no URI SANs (no tenant or component identity in it); SAN = exactly the DNS names and IPs of the configured fleet endpoint(s) (the `endpoints.txt` set that components dial; no wildcard). **Lifetime 30 days**, clamped to the CA's `not_after`. **Renewal** in the process at two-thirds of life (day 20) and on restart, hot-swapped through `tls.Config.GetCertificate` with no listener restart; a failed renewal raises an installation alert and the current leaf keeps serving until expiry. Each node mints its own leaf from the same CA; all verify to the same pin.
7. **`Enroller.SignServerLeaf(ctx, names)`** (new; the only way a ServerAuth leaf is made) must verify, and fail closed with a typed error and no key material in the message, that:
   - names are not caller free-form: they are checked against the configured fleet endpoint set; each is a syntactically valid DNS name (no wildcard, no trailing dot oddities, ≤ 253 bytes) or an IP; at most 8; none empty;
   - the public key is the one the method generated itself, P-256; it never accepts a CSR or a key from a network request;
   - the server CA row is `active`, the unsealed key's public half equals the row's SPKI, and the certificate chain is valid and not within the renewal-forbidden window of its own `not_after` (a CA near expiry alerts first);
   - the template has ServerAuth EKU only (no ClientAuth, no any-EKU), `IsCA` false, `BasicConstraintsValid`, a random 128-bit serial, `NotAfter ≤ min(now+30d, CA.NotAfter)`;
   - the produced leaf parses back, verifies to the CA with `ExtKeyUsageServerAuth` for every requested name, and its public key matches; only then is the `tls.Certificate` returned;
   - the unexported signer stays unexported; no exported method returns the key or signs arbitrary input. It is not reachable from any RPC and takes no principal, so no network request can ask for a certificate. It is called by the composer at start and by the renewal timer. Each issuance appends audit `fleet.server_cert.issued` (names, serial, not_after, CA SPKI).
8. **Rollover of the server CA** follows fleet-contract "CA key rollover" unchanged in mechanism (new row, old key erased on retire, `sealed_key` CHECKs, cross-signature carried in the bundle, `fleet.ca.rotate` with step-up), at installation scope: permission and audit are platform-level, not tenant-level. *Planned*: all components in all tenants adopt the new CA over their already-verified connection, no re-enrolment. *Compromise*: the old server CA is removed at once; because it never could mint identities, **client leaves remain valid**, but every component must obtain the new pin, which means re-enrolment or an out-of-band re-pin (a deliberate, audited cost, larger than a per-tenant event). Rollover of a **tenant client CA** no longer touches any component pin: the component's pin (server CA) is unchanged and the gateway simply adds the new tenant CA to `TenantCAs`; the cross-signature requirement for tenant CAs falls away, replaced by the existing overlap while old-signed leaves live.
9. **ClientCAs pool design does not change.** The pool still holds every tenant's CA (read per handshake) and `TenantCAs` still binds issuer to the SAN's tenant. New fitness rule: the server CA is provably absent from that pool, and a ClientAuth leaf signed by it is refused.

SaaS note: the same shape lets an operator supply a publicly trusted or enterprise chain for the fleet endpoint instead of the built-in server CA (the pin is then that chain's CA SPKI); that is an extension of item 1, not built now.

## Alternatives considered

| Alternative | What it would buy us | Why not |
| --- | --- | --- |
| **(a) One installation-scope CA** signing both server and client leaves; one pin, one chain | Simplest: one CA, one pin, one chain; fewest moving parts for a single-tenant install | One key mints identities for **every tenant**: blast radius of TM-A11 becomes the installation; `TenantCAs` issuer-binding (TM-Q8) and the `Rotate` per-tenant check become meaningless, because every leaf chains to the one CA; tenant deletion cannot shred the tenant's CA; SaaS would need rework to get back to per-tenant isolation. Needs the installation DEK anyway. |
| **(b) Per-tenant CAs, a server leaf per tenant, chosen by SNI or listener** | Keeps every CA per tenant; each pin is tenant-specific; no installation DEK | Before enrolment a component must already name its tenant in TLS (SNI or a tenant port), so enrolment material needs tenant-specific hostnames or ports: wildcard DNS and certs or a port per tenant, an operational burden and a reachability/tenant-enumeration oracle (the server's answer to an SNI reveals tenant existence); the same CA would sign ServerAuth and ClientAuth so a tenant CA leak also impersonates the gateway; N chains to renew; cannot present a chain for an unknown SNI. Self-hosted single tenant pays complexity it does not need. Compatible later (the leaf names are parameters), so not foreclosed. |
| **(c) Keep per-tenant CAs, add one installation server CA that every tenant's pin references** (chosen) | Single pin and chain for the whole installation; client identity isolation untouched; compromise of the server CA cannot mint identities; tenant CA rollover is invisible to components | Two CA kinds instead of one; needs the installation DEK (T-0715 stays); a server CA compromise needs installation-wide re-pin; `dial` must stop treating the pinned root as the client-leaf verifier. |
| Pin the server **leaf** SPKI, no server CA | No CA to protect, no chain | Leaf renews every 30 days so the pin would change; breaks D1 (pin identifies a CA the bundle must contain) and every renewal needs a re-pin. |
| Self-signed gateway cert generated per node | No installation DEK | No shared pin across nodes, no rotation story, equals pinning the leaf. |

## Consequences

**Positive.** One pin and one chain serve every tenant, so SaaS and self-hosted use the same wiring. Tenant isolation is not weakened: no new identity-minting key exists. Blast radius: a server CA compromise yields impersonation of the gateway (token capture at enrolment, MITM of the tunnel) but not forged component identities; a tenant client CA compromise yields identities for one tenant only. Tenant CA rollover and deletion stay tenant-local. The ClientCAs design and `TenantCAs` are untouched.

**Negative.** Two CA kinds to document and audit. A server-CA compromise is an installation-wide re-pin event. Enrolment material for all tenants is one pin: an admin of tenant A who sees the pin learns nothing secret, but a mis-issued pin is installation-wide. `dial` and the bundle semantics change (roots vs. client-leaf check). Requires T-0715 (installation DEK), so that ticket is **kept**, rescoped to the server CA key only.

**Migration.** No installation has deployed fleet components (the listener is not wired; T-0156 is unmounted, T-0657 never ran), so no component holds a tenant-CA pin. `fleet_ca` rows are unchanged and keep their meaning as client CAs; no data is rewritten. Add the `fleet_server_ca` migration (installation scope, registered in the exemption registry as an installation table; `sealed_key` CHECKs as for `fleet_ca`). `Enroller.CAPin` becomes `Enroller.ServerPin` and the enrolment material and console show it; tests that read the tenant pin change. If a pre-release test install did enrol against a tenant pin, it re-enrols (documented in the migration ticket).

**Security review.** To be recorded on the ticket by `security-architect` (key custody, blast radius of one CA versus many, TM-A11, TM-D24, TM-D29). Threat-model rows to add: TM-TB6-T15 (server CA compromise: gateway impersonation, installation-wide re-pin) and an update to the §9.1 "Fleet CA key" row to list both CAs.

**Follow-on work.**

- T-0715: rescope to installation DEK sealing the **server CA** key only (AC unchanged; add that `fleet_server_ca` is its first consumer).
- T-0716/T-0717: T-0717 AC2–AC4 updated to `SignServerLeaf`, the 30-day/day-20 renewal and chain `[leaf, server CA]`; pin is `ServerPin`.
- New build tickets: `fleet_server_ca` migration + `Enroller` server CA create/load/`SignServerLeaf`/`ServerPin`; `dial` roots-vs-client-CA split; server-CA rollover (`RotateServerCA`, installation permission); `fitness-fleet-ca-scope`.
- Threat-model and fleet-contract text updates (fleet-contract CA bullet is amended with this ADR).

## Security-review obligations (security-architect, approve with obligations, T-0713)

The review accepts the split and states the cost plainly: **the server-side blast radius is now installation-wide.** A server CA compromise plus a network position captures and redeems enrolment tokens first (yielding a tenant identity), reads tunnel plaintext, and can send server→component commands to every tenant's agents unless commands are separately signed (as ADR-0007 does for policy; the follow-up must confirm this for each contract). These bind the follow-up tickets and amend the Decision:

1. **EKU on the server CA:** `ExtKeyUsage = ServerAuth` on the CA certificate, so Go's EKU chaining refuses ClientAuth even if it reached a client pool. Fitness item 3 is defence in depth.
2. **Key custody (T-0715):** the installation KEK is not stored beside the database; the installation DEK has a distinct key purpose and AAD so it cannot open tenant values; the CA key is unsealed only inside the signing call, zeroised straight after, never cached; every unseal is audited. Prefer minting from a management-role process over every edge-facing node; if every node mints, the DB grant on `fleet_server_ca` is SELECT-only, the node-count residual is documented, and issuance is capped per node per hour.
3. **`SignServerLeaf` additions:** refuse issuance inside 90 days of CA expiry and alert at 1 year (this defines the "renewal-forbidden window"); `NotBefore` backdated at most 5 minutes; signature algorithm pinned to ECDSA-SHA384; AKI and SKI set; the endpoint set comes only from installation config changed by step-up and audit; names lowercased and IDNA-normalised; loopback, link-local and unspecified IPs refused.
4. **Rollover chain gap:** because the old key is erased on retire, a component that has not adopted the new CA cannot validate `[leaf, newCA]`. During the bounded overlap the gateway presents `[leaf, newCA, cross(newCA by oldCA)]`; fitness item 6 is relaxed for that window only. The overlap length and the offline-component path are fixed in the rollover ticket.
5. **Compromise re-pin:** a local `agentsetup repin` verb keeps the component identity and takes a new pin out of band, so a server-CA compromise does not force token re-enrolment (this replaces "re-enrolment" in Decision 8 as the preferred path). Its use is audited.
6. **Dial:** hostname/IP verification against the dialled address stays mandatory; the pinned root must satisfy `IsCA`, `MaxPathLen 0`, `KeyUsageCertSign`; a tenant CA in the bundle never joins `RootCAs`; test that a leaf signed by a tenant CA and presented as the server is refused.
7. **Retire the server CA row** with the same `sealed_key` CHECK and trigger as `fleet_ca`, with the TM-D29 (a) and (b) rollback tests at installation scope.

Threat-model rows to add (filed as a ticket): TM-TB6-T15 server CA compromise (token capture, command injection); T16 key use without key theft (compromised node abuses `SignServerLeaf`: allow-list, audit, rate cap); T17 tampering with the endpoint set or pin material; T18 chain/EKU confusion (server CA in a client pool, tenant CA as dial root); §9.1 "Fleet CA key" lists both CAs; §9.2.1 gains a "Fleet server CA key" row; TM-D24 rule D says "server CA" and TM-F-FLEET (D) gains a two-tenant same-pin case; TM-A11 splits into client-CA and server-CA keys.

## Fitness function

`fitness-fleet-ca-scope` (build ticket; runs in `make ci`), failing the build when:

1. any code path signs with the server CA key other than `SignServerLeaf` (static: the unexported signer's callers, as for `fleet_ca`);
2. `SignServerLeaf` output is not ServerAuth-only, is a CA, has a URI SAN, a wildcard, a lifetime over 30 days or over the CA's `not_after`, or accepts a caller key/CSR (table tests, including rejection of each);
3. the server CA appears in the gateway client pool or `TenantCAs`, or a ClientAuth leaf signed by it is accepted (integration);
4. a tenant CA certificate is used as a TLS root by `dial.DialOut`/`Enroll`, or the enrolment material for two tenants carries different pins (integration, two tenants, one listener, one presented chain);
5. `fleet_server_ca` has a `tenant_id` column or `sealed_key` in clear, or `fleet_ca` rows are reachable under the installation DEK (schema and `keys` AAD tests);
6. the presented `Certificate[]` has any length other than 2 (leaf, server CA).

Until it is green in CI this ADR stays `proposed`/`ratified`, never `accepted`.

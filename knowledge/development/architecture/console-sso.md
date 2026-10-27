---
title: "Console SSO (ADM-143): OIDC and SAML verifier contract, MFA-asserting IdPs, forced SSO, SPNEGO"
date: 2026-10-23
updated: 2026-10-23
status: review
owner: heramb
author: solution-architect
ticket: T-0191
parity: ADM-143, ADM-142
binding_sources: ADR-0001, ADR-0002, ADR-0003, ADR-0004, ADR-0005 (all ratified); threat-model.md (review) §5.8, §6.9, §7; domain-model.md DM-30, DM-31, DM-36, DM-37
sources_last_checked: 2026-10-23
---

# Console SSO: verifier contract and sign-in decisions

This spec closes the items the threat model and the domain model left `[OPEN → ADM-143 spec]`:

| Open item | Where | Closed by |
| --- | --- | --- |
| OIDC and SAML verifier checks, library, algorithm pins | TM §7.2, TM-TB8-T1/T2, TM-F-SSO | §3, §4, §5 |
| IdP marked MFA-asserting | TM §7.2, AN-10, TM-Q3 | §6 (SSO-D4) |
| Claim-to-role mapping; `tenant-owner` never from a claim alone | TM-TB8-T7, TM-Q3 | §7 (SSO-D5) |
| Anchor-claim binding | DM-30.I5 | §7.2 (restates I5 as checks) |
| SPNEGO offered in v1, and TM-D19 rule 3 / DM-30.I6 Kerberos alternative | TM §7.6 AN-9, TM-D19 rule 3, DM-30.I6 | §9 (SSO-D7) |
| Forced SSO ("Force SAML login" in ADManager Plus) | ADM-143 | §8 (SSO-D6) |
| Fuzz corpus for TM-F-SSO | TM §15 | §10 |

Short names are as in the threat model (TM, DM, BP, ADR-nnnn). The checks are numbered: `OIDC-n`,
`SAML-n`, `SSO-n` (shared), `MFA-n`, `MAP-n`, `FSSO-n`, `NEG-n`. A test cites the number it proves
(`TestSAML_RefusesXSW3 // SAML-6`). Decisions are `SSO-Dn`. This document binds the build tickets
T-0201 (OIDC verifier), T-0202 (SAML verifier), T-0203 (AN-3 routes), T-0206 (AN-9) and the proof
T-0073 (TM-F-SSO). Where it disagrees with the threat model, the threat model wins until
security-architect amends one of them.

---

## 1. What ADM-143 has to replace

ADManager Plus offers SAML SSO for the console with Okta, OneLogin, Ping Identity, AD FS, Entra ID
or a custom IdP; an option to force SAML login; and NTLMv2 SSO, for which the customer downloads
the Jespa JAR and copies it into the product's `lib` folder
([SSO help](https://www.manageengine.com/products/ad-manager/help/admin-settings/single-sign-on-authentication.html),
summarised in `knowledge/business/market-research/manageengine-admanager-plus.md` §2.5). The
competitor's SAML path is also where CVE-2022-47966 lived: pre-authentication RCE through an
outdated XML-DSig library, exploitable wherever SAML SSO had ever been configured (ME-SEC §4.1).

activeDIQ v1 offers: **OIDC** (preferred), **SAML 2.0** (SP-initiated, HTTP-POST), a **forced-SSO**
setting, and **Kerberos sign-in by SPNEGO** in place of NTLMv2 SSO. What we deliberately do not offer
in v1 is in §11.

## 2. Platform matrix

| Capability | `windows` | `linux-oci` | `saas` (designed) | Note |
| --- | --- | --- | --- | --- |
| OIDC verifier | in `platform/authn/sso/oidc` | same | same | Pure Go; no profile difference |
| SAML verifier | in `platform/authn/sso/saml` | same | same | Pure Go; no profile difference |
| Replay cache, SSO transactions | PostgreSQL | PostgreSQL | PostgreSQL | Shared by every node (ADR-0002 rule 6) |
| SPNEGO acceptor (AN-9) | SSPI in the embedded connector (gMSA) | krb5 keytab in the embedded connector | on-site remote connector | BP §4 matrix. NEG-9 gates each adapter on its lab cases |

There is no asymmetry between profiles. The only host dependency is SPNEGO's need for a Kerberos
service key, which lives with the connector on every profile (ADR-0002 rule 3).

---

## 3. Shape: one verifier contract, two implementations (SSO-D1)

The two protocols share one shape (parameterise, don't clone). `platform/authn/sso` owns it:

```go
// internal/platform/authn/sso
type Protocol string // "oidc" | "saml"

// Verifier is implemented once per protocol. Start and Complete are the only entry points;
// nothing else in the product parses an IdP response.
type Verifier interface {
    // Start builds the redirect to the IdP and the server-side Transaction it must come back to.
    Start(ctx context.Context, t tenant.ID, idp IdP, intent Intent) (redirect *url.URL, tx Transaction, err error)
    // Complete verifies a callback against exactly one consumed Transaction. It returns a
    // Verified only when every check of §4 (OIDC) or §5 (SAML) holds; otherwise a Refusal with
    // one reason code. It never returns partial claims.
    Complete(ctx context.Context, t tenant.ID, idp IdP, tx Transaction, cb Callback) (Verified, error)
}

// Verified is protocol-neutral. The callback handler (T-0203) sees only this.
type Verified struct {
    Issuer      string        // exact configured issuer / entityID
    Subject     string        // OIDC sub, or SAML persistent NameID / configured subject attribute
    Anchor      *Anchor       // oid+tid, or onprem_sid, when the IdP config names one (§7.2)
    AuthTime    time.Time     // OIDC auth_time / SAML AuthnInstant
    MFAAsserted bool          // §6, false unless the IdP is MFA-asserting AND the response proves it
    Methods     []string      // amr / AuthnContextClassRef values, for audit (TM-TB8-T4)
    GroupClaims []string      // only the claim the mapping names (§7.1); IDs, not names
    SessionCap  time.Time     // SAML SessionNotOnOrAfter, zero if absent
    ResponseID  string        // assertion ID / ID-token jti-or-hash, for the audit record only
}
```

- **SSO-D1.** Every IdP response is parsed in exactly two packages: `platform/authn/sso/oidc` (JOSE)
  and `platform/authn/sso/saml` (XML-DSig). No other package imports the libraries of §3.1, and no
  package under `platform/authn` imports `encoding/xml` except `sso/saml`. FIT-SSO-1 enforces it.
- **Intent** is `signin` or `stepup` (§6.3). A `stepup` transaction is bound to the session that
  started it and forces re-authentication at the IdP (`prompt=login` and `max_age=0`;
  SAML `ForceAuthn="true"`).
- **Transaction** is a server-side record (DM-39.I4): CSPRNG handle of 128 bits or more, stored
  hashed; IdP ID; intent; OIDC `state`, `nonce`, PKCE verifier; SAML AuthnRequest `ID`; the
  return path; created-at. It lives at most 5 minutes and is consumed by the first `Complete`
  call, whatever the outcome.
- **Browser binding.** The handle travels in a cookie `__Host-adq-sso` (`HttpOnly`, `Secure`,
  `Path=/`, no `Domain`). Its `SameSite` is `Lax` for OIDC (the callback is a top-level GET) and
  `None` for SAML (the ACS is a cross-site POST, which a `Lax` or `Strict` cookie does not reach).
  The cookie authorises nothing except one `Complete`; the session cookie stays `SameSite=Strict`
  (TM §7.3).
- **Hand-off to the console.** A session cookie set on the response to a cross-site request is
  not sent with the redirect that follows, because the chain started cross-site. So the callback
  answers with a small same-origin page that navigates to the stored return path (a
  `<meta http-equiv="refresh">`, no inline script, CSP unchanged). That navigation is same-site, so
  the `Strict` cookie is sent `[UNVERIFIED — browser lab, T-0203 proves it in Playwright]`.
- **Return path.** Only a relative console route that matches the console's route table; never an
  absolute URL, never `//`, never taken from `RelayState` or a query parameter at callback time.
  It is stored in the Transaction at Start.
- **Refusals.** Every refusal shows one generic page ("Sign-in failed. Try again or contact your
  administrator.") with a correlation ID. The reason code goes to audit and the server log, with
  issuer and subject only if they came from a verified signature (TM-TB8-T5). The raw response,
  token or assertion is never logged or stored.

### 3.1 Libraries (SSO-D2)

| Role | Choice (pin) | Licence | Why | Register |
| --- | --- | --- | --- | --- |
| OIDC client | `github.com/coreos/go-oidc/v3` v3.21.0 (2026-09-01) | Apache-2.0 | Discovery, JWKS cache, `IDTokenVerifier` with an algorithm allow-list; the de-facto Go RP library | row added (Candidate) |
| JOSE | `github.com/go-jose/go-jose/v4` v4.1.6 (2026-10-14) | Apache-2.0 | go-oidc's JWS layer. v4.0.5 fixed memory exhaustion on compact-JWS parsing, CVE-2025-27144 ([GitLab MR](https://gitlab.com/gitlab-org/gitlab-runner/-/merge_requests/5403)); a 2026 JWE DoS is CVE-2026-34986 ([RHSA](https://www.tenable.com/plugins/nessus/342241)). We never parse JWE (OIDC-9) | row added (Candidate) |
| OAuth 2.0 code exchange | `golang.org/x/oauth2` v0.37.0 | BSD-3-Clause | go-oidc's dependency; PKCE helpers | row added (Candidate) |
| SAML SP | `github.com/russellhaering/gosaml2` v0.12.0 (2026-08-05) | Apache-2.0 | SP-only (no IdP code to ship), actively patched in 2026: v0.11.0 rejects unsigned LogoutRequests and verifies assertion signatures inside signed Responses; v0.12.0 adds a `MaximumXMLTokens` limit, default 50,000 ([releases](https://github.com/russellhaering/gosaml2/releases)) | row added (Candidate) |
| XML-DSig | `github.com/russellhaering/goxmldsig` v1.6.1 (2026-08-04) | Apache-2.0 | gosaml2's signature layer. **Floor v1.6.0**: ≤ v1.5.0 has CVE-2026-33487, a reference-loop bug that lets a second Reference swap signed content ([GHSA-479m-364c-43vc](https://github.com/advisories/GHSA-479m-364c-43vc)) | row added (Candidate) |
| XML tree, round-trip guard | `github.com/beevik/etree` (BSD-2-Clause), `github.com/mattermost/xml-roundtrip-validator` v0.1.0 (Apache-2.0), `github.com/jonboulle/clockwork` (Apache-2.0) | as stated | Transitive closure of gosaml2. The round-trip validator refuses XML whose `encoding/xml` re-encoding differs from the input, the namespace-confusion class of CVE-2020-29509 | row added (Candidate) |

**Rejected candidates.**

- **`github.com/crewjam/saml`** (BSD-2-Clause). It ships both SP and IdP code, its last tag is
  v0.5.1 of 2025-04-14 (module proxy), and its history includes two signature bypasses,
  CVE-2020-27846 and CVE-2022-41912 (multiple Assertion elements accepted;
  [GHSA-j2jp-wvqg-wc2g](https://osv.dev/vulnerability/GHSA-j2jp-wvqg-wc2g)). It also sits on
  goxmldsig, so it adds surface without removing any.
- **Our own XML-DSig on `encoding/xml`.** Canonicalisation and reference processing are where
  every SAML bypass lives; owning them is the competitor's mistake in a different form.
- **A brokering IdP as a sidecar** (Keycloak, SimpleSAMLphp, Dex). A second runtime and a stateful
  service break ADR-0001 rule 3 and multiply what an on-prem install must patch.
- **OIDC only, no SAML.** Removes XML-DSig entirely, but drops a parity row: AD FS and many
  on-prem estates configure SAML first. SAML stays, fenced by §5 and FIT-SSO-1.

**Patch policy.** goxmldsig and gosaml2 between them had security releases every year from 2020 to 2023,
and again in 2026. `govulncheck` in `make ci` (T-0010) fails on a known vulnerability; security-architect
owns the floor versions above, and a new advisory on either is a P1 bug against `sso/saml`. The
residual is a library zero-day (TM-TB8-T1); §5 checks that do not depend on the library (SAML-3,
SAML-4, SAML-6) narrow it.

---

## 4. OIDC checks (T-0201)

Configuration fixes, per IdP: `issuer`, `client_id`, client authentication, the one signing
algorithm, and the redirect URI `https://<console-host>/auth/sso/{idpId}/callback`.

| # | Check | Refusal reason |
| --- | --- | --- |
| OIDC-1 | Authorization code flow only: `response_type=code`, `response_mode=query`. Any `id_token` or `token` in the authorization response is refused | `oidc.flow` |
| OIDC-2 | **PKCE `S256`** on every request: a 32-byte CSPRNG verifier per Transaction. `plain` is never sent. An IdP whose discovery document lacks `S256` in `code_challenge_methods_supported` cannot be saved (config-time refusal) | `oidc.pkce` |
| OIDC-3 | **`state`**: 128-bit CSPRNG, stored in the Transaction, compared in constant time, single use; a callback without `state`, or with a `state` from another browser's Transaction, is refused before the code is exchanged | `oidc.state` |
| OIDC-4 | **Mix-up defence**: one redirect URI per IdP (the `{idpId}` path), and the callback's `idpId` must equal the Transaction's. When discovery advertises `authorization_response_iss_parameter_supported`, the `iss` response parameter must equal the configured issuer ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)) | `oidc.mixup` |
| OIDC-5 | **Code exchange** over TLS to the discovered `token_endpoint` (HTTPS only, egress rules of TM-D10). Client authentication `private_key_jwt` preferred, `client_secret_basic` allowed; the secret or key is sealed under the tenant data key (TM-D7). The response body is capped at 64 KiB | `oidc.token` |
| OIDC-6 | **Token shape** before any parsing: the ID token is a compact JWS with exactly two dots and at most 32 KiB (the CVE-2025-27144 pre-check). A JWE ID token is refused | `oidc.shape` |
| OIDC-7 | **Algorithm pin**: the header `alg` equals the IdP's configured algorithm, chosen at setup from `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`. `none` and every `HS*` are refused at config time and at verify time (alg-confusion). The key's `kty` must match the algorithm; RSA keys are at least 2048 bits | `oidc.alg` |
| OIDC-8 | **Key source**: only the `jwks_uri` of the pinned discovery document. `jku`, `x5u`, `jwk` and `x5c` headers are ignored as key sources; a `crit` header is refused. The JWS `kid` must name a key in the cached set; an unknown `kid` triggers at most one JWKS refresh per IdP per minute, then refusal | `oidc.key` |
| OIDC-9 | **Signature** verified before any claim is read (go-oidc ≥ 3.15 does this; [release](https://dependabot.ecosyste.ms/hosts/GitHub/repositories/coder%2Fcoder/issues/19156)) | `oidc.signature` |
| OIDC-10 | **`iss`** equals the configured issuer as an exact string. For Entra the issuer is the single-tenant `https://login.microsoftonline.com/{tid}/v2.0`; the multi-tenant `common` / `organizations` templates cannot be configured, and `tid` must equal the configured tenant ID ([ID token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)) | `oidc.iss` |
| OIDC-11 | **`aud`** contains `client_id` and no other value; if `azp` is present it equals `client_id` ([OIDC Core §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)) | `oidc.aud` |
| OIDC-12 | **`nonce`** present and equal (constant time) to the Transaction's | `oidc.nonce` |
| OIDC-13 | **Time**: `exp` after now − skew; `nbf`, if present, before now + skew; `iat` not after now + skew and not before now − 10 min. Skew is 120 s, fixed | `oidc.time` |
| OIDC-14 | **`sub`** present, non-empty, at most 255 bytes. The account key is (`iss`, `sub`) | `oidc.sub` |
| OIDC-15 | **Step-up freshness**: for `intent=stepup`, `auth_time` is present and within 120 s of now | `oidc.stale` |
| OIDC-16 | **Claims come from the ID token only.** The UserInfo endpoint is not called and the access token is not used, so `at_hash` is not needed; group overage (`_claim_names`, `hasgroups`) yields no group claims and an audit warning, never a Graph call from `authn` (§7.1) | `oidc.claims` |
| OIDC-17 | **Discovery is pinned at setup.** Its `issuer` must equal the configured issuer, every endpoint is HTTPS, and changes to issuer, client, algorithm or endpoints are an IdP configuration change: step-up, audited, all `tenant-owner` accounts alerted (TM-TB8-T3, TM §7.4). Only the JWKS refreshes on its own | `oidc.config` |

**Implementation note (T-0201).** `sso/oidc` verifies the ID token with go-jose directly and does not import
go-oidc. go-oidc's `IDTokenVerifier` returns unstructured errors (no stable reason per check), applies a
fixed 5-minute `nbf` leeway against OIDC-13's 120 s, and its `RemoteKeySet` refreshes without OIDC-8's
one-per-minute bound; the checks it would have done (signature first, `iss`, `aud`, `exp`) are the
package's own and each has a `TestOIDC_Refuses*` test. go-oidc is therefore not in `go.mod`; its register
row stays Candidate and is unused. Discovery is fetched once at setup (`oidc.Discover`) and pinned
(`sso.OIDCConfig.Discovery`); `oidc.ValidateConfig` runs at setup and again on every `Start` and `Complete`.
Transaction persistence and consume-first (SSO-1), IdP lookup (SSO-2), account lookup (SSO-3) and audit
(SSO-4) belong to the callback handler, T-0203.

## 5. SAML checks (T-0202)

Configuration fixes, per IdP: IdP `entityID`, one or two signing certificates (two only during a
rollover), the IdP SSO URL (HTTP-Redirect binding for our AuthnRequest), the one signature algorithm,
the subject source (§7.2), and our SP `entityID` and ACS URL
`https://<console-host>/auth/sso/{idpId}/callback`. Metadata may be imported to fill these in;
the stored values, not a metadata URL, are what verification uses.

| # | Check | Refusal reason |
| --- | --- | --- |
| SAML-1 | **Binding**: the ACS accepts HTTP-POST only (`SAMLResponse` form field, base64, no DEFLATE). Request body at most 256 KiB; decoded document at most 192 KiB; at most 50,000 XML tokens (gosaml2 `MaximumXMLTokens`) and nesting depth 64 | `saml.binding` |
| SAML-2 | **XML hygiene**: UTF-8 only; any `<!DOCTYPE>` is refused (so no entities, internal or external); the round-trip validator must pass; no processing instructions other than the XML declaration | `saml.xml` |
| SAML-3 | **Structure**, checked by our code on the parsed tree, independent of the library: the root is one `samlp:Response`; it contains **exactly one** `saml:Assertion` as a direct child and no `saml:Assertion` anywhere else (not in `Extensions`, `Advice`, `Status` or a nested element); no `EncryptedAssertion`; every `ID` attribute in the document is unique | `saml.structure` |
| SAML-4 | **Signed assertion required**: the Assertion carries a `ds:Signature` as its child, with exactly **one** `Reference` whose `URI` is `#` + that Assertion's `ID`. A Response-level signature, if present, is verified too (under the same rules), but never replaces the Assertion signature. An empty `URI` (whole document) is refused | `saml.unsigned` |
| SAML-5 | **Trust source**: the signature verifies under one of the configured certificates only. `KeyInfo` in the message is never a trust source; if it carries a certificate that is not configured, the response is refused rather than ignored, so a misconfiguration is visible | `saml.key` |
| SAML-6 | **Consume only what was verified**: claims are read from the element the library returns as verified, never re-read from the raw document by path. The verified Assertion's `ID` must equal the one SAML-3 found. This, with SAML-3 and SAML-4, defeats the eight signature-wrapping classes XSW1–XSW8 ([Somorovsky et al., USENIX Security 2012](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky)) | `saml.wrapped` |
| SAML-7 | **Algorithm pin**: `SignatureMethod` equals the IdP's configured algorithm, from `rsa-sha256`, `rsa-sha384`, `rsa-sha512`, `ecdsa-sha256`, `ecdsa-sha384` (xmldsig-more URIs). `DigestMethod` is SHA-256, SHA-384 or SHA-512. SHA-1, DSA and every HMAC are refused. RSA keys at least 2048 bits. Checked on the verified `SignedInfo`; if goxmldsig exposes an allow-list option it is used as well `[UNVERIFIED — T-0202 confirms the API]` | `saml.alg` |
| SAML-8 | **Transforms** allow-list: `enveloped-signature` then exclusive C14N **without comments** (`http://www.w3.org/2001/10/xml-exc-c14n#`). XPath, XSLT, inclusive C14N and the `#WithComments` variants are refused (the comment-in-NameID class, CVE-2017-11427 and siblings) | `saml.transform` |
| SAML-9 | **Status** is `urn:oasis:names:tc:SAML:2.0:status:Success` | `saml.status` |
| SAML-10 | **Issuer**: the Assertion's `Issuer` (and the Response's, if present) equals the configured IdP `entityID` exactly. An assertion from IdP A posted to IdP B's ACS is refused here | `saml.issuer` |
| SAML-11 | **Destination** on the Response is present and equals our ACS URL for this `idpId` exactly | `saml.destination` |
| SAML-12 | **Bearer confirmation**: at least one `SubjectConfirmation` with method `urn:oasis:names:tc:SAML:2.0:cm:bearer` whose `SubjectConfirmationData` has `Recipient` = our ACS URL, `InResponseTo` = the Transaction's AuthnRequest `ID`, and `NotOnOrAfter` after now − skew. Holder-of-key and sender-vouches alone are refused | `saml.recipient` |
| SAML-13 | **SP-initiated only**: `InResponseTo` names an AuthnRequest this server issued, in the Transaction carried by this browser's `__Host-adq-sso` cookie, not yet consumed, not older than 5 minutes. Unsolicited (IdP-initiated) responses are refused (§11) | `saml.inresponseto` |
| SAML-14 | **Audience**: every `AudienceRestriction` in `Conditions` contains our SP `entityID` (each one restricts; [SAML Core §2.5.1.4](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)). No `AudienceRestriction` at all is refused | `saml.audience` |
| SAML-15 | **Time**: `Conditions` `NotBefore` before now + skew and `NotOnOrAfter` after now − skew; Assertion `IssueInstant` not older than 5 minutes + skew. Skew is 120 s | `saml.time` |
| SAML-16 | **Replay cache**: the (IdP, Assertion `ID`) pair is inserted into DM-39.I5 in the same transaction that consumes the Transaction; a duplicate key refuses. The row lives until `NotOnOrAfter` + skew. Shared by every node through PostgreSQL | `saml.replay` |
| SAML-17 | **AuthnStatement** present; `AuthnInstant` gives `AuthTime`; for `intent=stepup` it is within 120 s of now; `SessionNotOnOrAfter`, if present, caps the session's absolute expiry | `saml.authn` |
| SAML-18 | **Subject**: the account subject comes from the configured source (§7.2). A `transient` NameID, or an `emailAddress`-format NameID, cannot be the subject source and is refused at config and at verify | `saml.subject` |
| SAML-19 | **No SAML logout in v1**: the ACS and every other route refuse `LogoutRequest` and `LogoutResponse` documents (§11). Our sign-out ends our session only | `saml.logout` |

## 6. Shared checks and MFA-asserting IdPs (SSO-D3, SSO-D4)

| # | Check |
| --- | --- |
| SSO-1 | `Complete` consumes the Transaction first (delete-returning), so a second callback with the same cookie finds nothing, whatever the first outcome |
| SSO-2 | The `idpId` in the path names an enabled IdP of the tenant the hostname binds (DM-04); the IdP lookup runs inside that tenant's transaction (ADR-0002 rule 5). A disabled IdP refuses at Start and at Complete |
| SSO-3 | The account is found by (`issuer`, `subject`) of a `sso` account (DM-30). A disabled, deleted or `accountExpires`-expired account (DM-30.I2) is refused with the same page as any other refusal |
| SSO-4 | Audit records `auth.sso.succeeded` / `auth.sso.refused` with IdP ID, issuer, subject (verified only), reason code, `MFAAsserted`, methods and the session or pending-sign-in ID (TM-TB8-T4). No token or assertion bytes |
| SSO-5 | Rate class `auth` (TM-D22) on Start and callback, per source IP |

### 6.1 How an IdP is marked MFA-asserting (SSO-D4)

**Decision.** MFA-asserting is a per-IdP setting with a **per-response proof**, never an attestation
alone. An IdP is MFA-asserting when its configuration has `mfa.mode = claim` and an evidence rule;
the default is `mfa.mode = off`.

| # | Rule |
| --- | --- |
| MFA-1 | **OIDC evidence**: the ID token's `amr` array contains at least one configured value. The default set is `{"mfa"}` ([RFC 8176](https://www.rfc-editor.org/rfc/rfc8176)); the administrator may add `hwk`, `otp`, `fpt`, `face`, `sc`. `pwd`, `kba`, `sms`, `tel` and `user` cannot be added, because each names one factor at most. `acr` is recorded but is not evidence on its own, because its values are IdP-defined |
| MFA-2 | **SAML evidence**: the verified Assertion's `AuthnContextClassRef`, or a named attribute, contains a configured value. Presets: Entra ID and AD FS, attribute `http://schemas.microsoft.com/claims/authnmethodsreferences` containing `http://schemas.microsoft.com/claims/multipleauthn` `[UNVERIFIED — lab G9]`; others are configured by the administrator, and the setup screen shows the last verified response's values so the rule is chosen from evidence |
| MFA-3 | `Verified.MFAAsserted` is true only when `mfa.mode = claim` **and** the response carries the evidence. With the mode on and the evidence absent, sign-in proceeds as non-MFA (a pending sign-in, AN-10) and audit records `sso.mfa_evidence_absent`; it is never a silent session |
| MFA-4 | Switching `mfa.mode` on, or changing the evidence rule, is an IdP configuration change: step-up, audited, every `tenant-owner` alerted (TM-TB8-T3) |
| MFA-5 | **What MFA-asserting buys**: an account whose sign-in has `MFAAsserted` gets a session directly from AN-3, **unless** the account holds `tenant-owner` or any `control_plane` permission (DM-33.I3; both are held only by assignment to the account itself, DM-36.I4); such an account always completes AN-10 with an activeDIQ-held factor. A compromised IdP (TM-X12) then reaches console access within RBAC but never the control plane (TM-TB8-T7, TM-O1) |
| MFA-6 | MFA-asserting never satisfies the TM-D19 authority factor (DM-30.I6). Correlation-derived grants still need the activeDIQ-held WebAuthn factor or a Kerberos sign-in (§9) |

**Why not an attestation ("our Conditional Access policy enforces MFA for this app").** It cannot
be checked per sign-in, so a policy change in the IdP silently removes MFA from a Tier-1 console
and TM §7.1 "MFA for every console user" would rest on configuration we never see. **Consequence
for Entra OIDC**: Microsoft's ID-token claims reference lists no `amr` claim
([ID token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)),
so an Entra OIDC IdP likely cannot be MFA-asserting `[UNVERIFIED — lab G9]`. Its users pass AN-10
with their passkey, one touch per sign-in. Entra over SAML can be MFA-asserting if MFA-2's preset
holds in the lab.

### 6.2 First factor enrolment for SSO accounts

An `sso` account that must pass AN-10 and has no factor yet enrols its first one inside the
pending sign-in, once, while the account is `invited` (DM-30 lifecycle). The enrolment is audited
and notifies every `tenant-owner`. Any later enrolment or reset is a `tenant-owner` action with
step-up (DM-37). The residual is an IdP compromised before the user's first sign-in; it is the
same as TM-R12 and is reported with it.

### 6.3 Step-up for SSO accounts (TM §7.4)

An `sso` session steps up with its activeDIQ-held factor. If the account has none and its IdP is
MFA-asserting, step-up is an `intent=stepup` round trip to the IdP (OIDC-15, SAML-17) whose response
must carry MFA evidence (MFA-3). For a session with correlation-derived grants, the authority factor
is verified at every step-up as TM-D19 rule 1 says; the IdP round trip does not replace it.

---

## 7. Claims: roles, admission and anchors (SSO-D5)

### 7.1 Claim-to-role mapping

| # | Rule |
| --- | --- |
| MAP-1 | A mapping is explicit tenant configuration on the IdP: one named claim (OIDC claim name, SAML attribute name), a value, and a role. Values are matched as exact strings. For Entra the value must be a group object ID (GUID); display names are never matched |
| MAP-2 | A mapping cannot target `tenant-owner` or a role that contains any `control_plane` permission (DM-33.I3). The save is refused, and roles that later gain such a permission drop their claim mappings with an audit event. This is the same limit DM-36.I2 sets for correlation-derived grants |
| MAP-3 | Claim-derived roles are computed at each sign-in from the verified claims, held on the session (DM-31 `methods` records `claim:<idpId>`), and never written as a DM-36 assignment. They end with the session, so removing a user from the IdP group takes effect at the next sign-in or session expiry |
| MAP-4 | Creating, changing or deleting a mapping is an IdP configuration change: step-up, audited, every `tenant-owner` alerted |
| MAP-5 | Group overage (OIDC-16; Entra's SAML limit is 150 groups) yields no claim-derived roles and an audit warning. Entra customers are pointed to bound-account group grants (DM-36.I2 through DM-30.I5), which read inventory and have no overage |

### 7.2 Admission and the anchor binding

- **Admission.** An `sso` account is created at first sign-in only if the tenant's IdP has
  `admission = mapped` and at least one MAP rule matches, or if an administrator invited it
  (the invitation names the IdP and either the expected subject or the directory object the
  anchor must resolve to). Otherwise the sign-in is refused with reason `sso.not_admitted`. A
  system-created account has `created_by = system` (ADR-0005 sock-puppet rule).
- **Subject source.** OIDC: `sub`. SAML: a `persistent` NameID (default) or a named attribute the
  administrator declares immutable (preset for Entra:
  `http://schemas.microsoft.com/identity/claims/objectidentifier`). SAML-18 refuses transient
  and email-format NameIDs.
- **Anchor binding (DM-30.I5, restated as checks for T-0203).** The IdP configuration names at most
  one anchor claim: `oid` with `tid` equal to an Entra connection's tenant, or `onprem_sid`. UPN,
  email, name and immutable-ID claims are not selectable. The binding is made once through
  `authn.DirectoryAnchors.Resolve` and stored as the GUID; a later sign-in whose anchor resolves to
  a different object is refused (`sso.anchor_changed`) and audited, never rebound silently.

---

## 8. Forced SSO (SSO-D6)

ADManager Plus calls it "Force SAML login". activeDIQ has a tenant setting `signin.mode`:

| # | Rule |
| --- | --- |
| FSSO-1 | `choice` (default): the sign-in page lists the enabled IdPs and, if offered, "Sign in with Windows" (AN-9). The break-glass form (AN-8) is behind a "Break-glass sign-in" link |
| FSSO-2 | `forced`: the sign-in page immediately starts the one designated method, an IdP or AN-9. No list is shown |
| FSSO-3 | Forced SSO **never disables AN-8**. Break-glass stays reachable at `/signin/break-glass` (not linked from the page), with all of TM §7.6 rules 2–4. Switching AN-8 off is the separate rule-4 switch |
| FSSO-4 | Turning `forced` on is refused unless the acting `tenant-owner` signed in through the designated method within the current session. That proves it works before everyone is sent to it |
| FSSO-5 | Changing `signin.mode` or the designated method is step-up, audited, and alerts every `tenant-owner` |
| FSSO-6 | When the designated IdP is disabled or its configuration fails validation, the page falls back to `choice` and shows a banner to signed-in owners; it never shows a dead button |

## 9. SPNEGO in v1 (SSO-D7)

**Decision: offered in v1, Kerberos only.** ADM-143 is a v1 P1 parity row
(`knowledge/business/competitive-analysis/feature-parity-matrix.md`) and its ManageEngine content
includes integrated Windows sign-in (NTLMv2 through a customer-supplied JAR, §1). Offering the
Kerberos equivalent is how we build that row, not a change of scope, so it is not a CEO question.
Leaving NTLM out is a security decision (TM §7.6 rule 5: NTLM is relayable, TM-X2); it is
customer-visible, so it goes out as a `notice`.

The route, gate and rules are TM §7.6 AN-9 and rules 2, 5, 6 and 7, unchanged. This spec adds:

| # | Rule |
| --- | --- |
| NEG-1 | AN-9 is off until an administrator enables it and supplies the `HTTP/<console FQDN>` service principal registration (installer or administrator step; activeDIQ never writes `servicePrincipalName`) |
| NEG-2 | The client principal maps through the PAC logon-info user SID, verified by the acceptor with the service key, resolved once to an objectGUID through inventory. It maps to exactly one console account: the `directory` account with that GUID, or the `sso` account whose bound object is, or has a `matched` correlation to, that GUID. Zero or more than one gives the generic failure, and audit records `negotiate.unmapped` or `negotiate.ambiguous` |
| NEG-3 | A successful AN-9 is a first factor only; AN-10 always follows (rule 7) |
| NEG-4 | **TM-D19 rule 3 / DM-30.I6 apply in v1.** A session whose first factor was a Kerberos sign-in of the correlated AD account sets `authority_factor_at` (DM-31.I3), so a hybrid technician on a domain-joined workstation needs no separate authority-factor touch |
| NEG-5 | The browser offers Negotiate only to hosts in its intranet zone or policy allow-list (customer GPO, setup guide). A browser that answers `401 Negotiate` with nothing, or with NTLM only, gets the sign-in page, not an error loop |
| NEG-6 | Replay: the acceptor refuses a replayed AP-REQ (SSPI's replay detection on `windows`; on `linux-oci` the krb5 adapter's replay cache `[UNVERIFIED — lab]`) |
| NEG-7 | Channel binding to the TLS session is requested where the browser offers it; its absence is not a refusal in v1, because browser support varies `[UNVERIFIED — lab]` |
| NEG-8 | The Negotiate header cap (64 KiB, 431) and the FF-SP5 fuzz target of rule 6 stand |
| NEG-9 | **Gate per adapter.** AN-9 is enabled on a profile only when its lab cases pass (NEG-6 replay, rule 5 NTLM refusal, NEG-2 mapping). If the krb5 adapter cannot refuse replays, `linux-oci` serves AN-9 through a Windows-hosted remote connector, never through a profile conditional (BP §4) |

When T-0206 lands, AN-9's `GET /auth/negotiate` enters `api/openapi/policy.yaml` `nonApiRoutes`
(TM §7.6, "Which rows are in policy.yaml today").

---

## 10. TM-F-SSO corpus (T-0073, with T-0201 and T-0202)

### 10.1 Format and harness

- **Home**: `internal/platform/authn/sso/testdata/corpus/{oidc,saml}/`, one JSON record per case:
  `id`, `class` (`forged`, `wrapped`, `replayed`, `misaddressed`, `malformed`), `cites` (the check
  numbers above), `build` (the name of a Go builder in `ssotest` that produces the bytes from a
  known-good response), `expect` (`refuse` and the reason code). Hand-crafted XML for the wrapping
  cases is checked in as files next to the record, because the point is the exact bytes.
- **Test IdP**: `internal/platform/authn/sso/ssotest` runs an in-process OIDC provider and SAML IdP
  with their own keys, a fixed clock and real HTTP endpoints (`httptest`), so every case drives
  `Start` → IdP → `Complete` end to end. Stdlib plus the §3.1 libraries only.
- **Every record runs as its own subtest** (`TestCorpus/<id>`); a case that is accepted, or refused
  with a different reason code, fails.
- **Fuzz targets**: `FuzzSAMLComplete` and `FuzzOIDCComplete` (Go native fuzzing), seeded with every
  corpus record and with the known-good responses. **Oracle**: the harness records every
  (issuer, subject, claims, response ID) tuple that the test IdP actually signed. A `Verified` that
  is not one of those tuples, or the same response ID accepted twice, is a failure. This catches a
  wrapping bug without knowing its shape. CI runs each target for 60 s per `make ci`; nightly runs
  10 minutes and promotes new crashers into the corpus.
- **Coverage gate**: each check number in §4 and §5 is cited by at least one record, and each class
  has at least one record per protocol. FIT-SSO-2 fails CI otherwise.

### 10.2 SAML cases the proof must contain

| ID | Class | Case | Cites |
| --- | --- | --- | --- |
| S-F01 | forged | Unsigned Response and unsigned Assertion | SAML-4 |
| S-F02 | forged | Signed Response, unsigned Assertion | SAML-4 |
| S-F03 | forged | Assertion signed by an attacker key, certificate in `KeyInfo` | SAML-5 |
| S-F04 | forged | Valid signature, then NameID changed | SAML-6 |
| S-F05 | forged | `SignatureValue` bit-flipped | SAML-4 |
| S-F06 | forged | Comment inside NameID (`victim@corp<!---->.attacker`), signed with `#WithComments` and without | SAML-8 |
| S-F07 | forged | `rsa-sha1` signature; SHA-1 digest | SAML-7 |
| S-F08 | forged | HMAC `SignatureMethod` keyed with the IdP's public certificate | SAML-7 |
| S-F09 | forged | RSA-1024 key | SAML-7 |
| S-F10 | forged | Configured algorithm RS256, response signed RS512 with the trusted key | SAML-7 |
| S-F11 | forged | XPath or XSLT transform | SAML-8 |
| S-F12 | forged | `EncryptedAssertion` (including the all-zero-plaintext CBC case of GHSA-hwqm-qvj9-4jr2) | SAML-3 |
| S-W01–W08 | wrapped | XSW1–XSW8 of Somorovsky et al.: signed original moved into `Extensions`, `Object`, sibling or child positions with an evil Assertion where the consumer would look | SAML-3, SAML-6 |
| S-W09 | wrapped | Two Assertions, one signed (CVE-2022-41912 class) | SAML-3 |
| S-W10 | wrapped | Signed Assertion inside `Advice` of an unsigned one | SAML-3 |
| S-W11 | wrapped | Duplicate `ID` attributes | SAML-3 |
| S-W12 | wrapped | `Reference URI=""` (whole document) | SAML-4 |
| S-W13 | wrapped | Two `Reference` elements in one `SignedInfo` (CVE-2026-33487 class) | SAML-4 |
| S-W14 | wrapped | Namespace-prefix confusion that changes on `encoding/xml` round-trip (CVE-2020-29509 class) | SAML-2 |
| S-R01 | replayed | The same Response posted twice | SAML-16, SSO-1 |
| S-R02 | replayed | A captured Response posted from a second browser (other `__Host-adq-sso` cookie) | SAML-13 |
| S-R03 | replayed | Unsolicited: no `InResponseTo` | SAML-13 |
| S-R04 | replayed | `InResponseTo` of an already-consumed request | SAML-13, SSO-1 |
| S-R05 | replayed | `NotOnOrAfter` passed; `IssueInstant` older than 5 min | SAML-15 |
| S-R06 | replayed | `NotBefore` in the future beyond skew | SAML-15 |
| S-R07 | replayed | Replay to a second node (two verifiers, one database) | SAML-16 |
| S-R08 | replayed | Step-up with `AuthnInstant` older than 120 s | SAML-17 |
| S-M01 | misaddressed | Audience is another SP | SAML-14 |
| S-M02 | misaddressed | Two `AudienceRestriction`, one without us | SAML-14 |
| S-M03 | misaddressed | `Recipient` is another ACS | SAML-12 |
| S-M04 | misaddressed | `Destination` is another ACS, or absent | SAML-11 |
| S-M05 | misaddressed | Valid assertion of IdP A posted to IdP B's callback | SAML-10, SSO-2 |
| S-M06 | misaddressed | Response for tenant A posted on tenant B's hostname (saas composition) | SSO-2 |
| S-M07 | misaddressed | Status `Responder` with a signed Assertion | SAML-9 |
| S-M08 | misaddressed | Holder-of-key confirmation only | SAML-12 |
| S-M09 | misaddressed | Transient or email-format NameID as subject | SAML-18 |
| S-M10 | misaddressed | `LogoutRequest` posted to the ACS | SAML-19 |
| S-D01 | malformed | Body over 256 KiB; over 50,000 tokens; nesting over 64 | SAML-1 |
| S-D02 | malformed | `<!DOCTYPE>` with an external entity; with a billion-laughs internal entity | SAML-2 |
| S-D03 | malformed | DEFLATE-encoded or Redirect-binding response at the ACS | SAML-1 |
| S-D04 | malformed | Invalid base64; non-UTF-8 encoding declaration | SAML-1, SAML-2 |

### 10.3 OIDC cases the proof must contain

| ID | Class | Case | Cites |
| --- | --- | --- | --- |
| O-F01 | forged | `alg: none`, empty signature | OIDC-7 |
| O-F02 | forged | `HS256` with the IdP's RSA public key as the secret | OIDC-7 |
| O-F03 | forged | Trusted key, algorithm other than the pinned one | OIDC-7 |
| O-F04 | forged | Attacker key referenced by `jku`, `x5u`, embedded `jwk` or `x5c` | OIDC-8 |
| O-F05 | forged | Unknown `kid` (one refresh, then refusal; a second unknown `kid` within a minute does not refetch) | OIDC-8 |
| O-F06 | forged | Payload changed after signing; signature bit-flipped | OIDC-9 |
| O-F07 | forged | JWE ID token | OIDC-6 |
| O-F08 | forged | `crit` header | OIDC-8 |
| O-F09 | forged | RSA-1024 key in the JWKS | OIDC-7 |
| O-F10 | forged | `id_token` in the authorization response (implicit or hybrid) | OIDC-1 |
| O-R01 | replayed | Callback without `state`; with a `state` from another browser | OIDC-3 |
| O-R02 | replayed | Same callback twice | OIDC-3, SSO-1 |
| O-R03 | replayed | `nonce` missing; `nonce` of another Transaction | OIDC-12 |
| O-R04 | replayed | `exp` passed; `iat` older than 10 min; `nbf` in the future | OIDC-13 |
| O-R05 | replayed | Step-up with `auth_time` older than 120 s, or absent | OIDC-15 |
| O-R06 | replayed | Start never sends `plain` and always sends `S256`; an IdP without `S256` cannot be saved | OIDC-2 |
| O-M01 | misaddressed | `iss` of another issuer; Entra `common` issuer; `tid` mismatch | OIDC-10 |
| O-M02 | misaddressed | Code from IdP B delivered to IdP A's callback; RFC 9207 `iss` mismatch | OIDC-4 |
| O-M03 | misaddressed | `aud` is another client; `aud` has an extra value; `azp` mismatch | OIDC-11 |
| O-M04 | misaddressed | Valid token for tenant A on tenant B's hostname | SSO-2 |
| O-M05 | misaddressed | Discovery `issuer` differs from the configured issuer; an HTTP endpoint | OIDC-17 |
| O-D01 | malformed | ID token over 32 KiB; three or more dots; token response over 64 KiB | OIDC-5, OIDC-6 |
| O-D02 | malformed | `sub` missing, empty, over 255 bytes | OIDC-14 |

### 10.4 Sign-in outcome cases (TM-F-SSO with TM-F-SESSION and TM-F-HYBRID)

| ID | Case | Expect | Cites |
| --- | --- | --- | --- |
| X-01 | IdP not MFA-asserting, valid response | pending sign-in only, no session | MFA-3 |
| X-02 | MFA-asserting, `amr` lacks configured values | pending sign-in only; `sso.mfa_evidence_absent` | MFA-3 |
| X-03 | MFA-asserting with evidence, account holds `tenant-owner` or a `control_plane` permission | pending sign-in only | MFA-5 |
| X-04 | MFA-asserting with evidence, ordinary technician | session | MFA-3, MFA-5 |
| X-05 | Claim mapping to `tenant-owner` or a control-plane role | save refused | MAP-2 |
| X-06 | Group overage | no claim roles, audit warning | MAP-5 |
| X-07 | UPN-only or email-only claim | no binding | §7.2 |
| X-08 | Anchor resolves to a different object than the stored binding | refused, `sso.anchor_changed` | §7.2 |
| X-09 | Not admitted | refused, `sso.not_admitted` | §7.2 |
| X-10 | `forced` on without a sign-in through the designated method this session | refused | FSSO-4 |
| X-11 | `forced` on; `/signin/break-glass` | AN-8 still served | FSSO-3 |
| X-12 | Callback return path is absolute, `//host` or not a console route | ignored; console root | §3 |
| X-13 | Refusal page body is identical for every SAML-n / OIDC-n reason | same body and status | §3 |

---

## 11. Not in v1, and why

| Not offered | Reason | Reversible? |
| --- | --- | --- |
| NTLM integrated sign-in | Relayable (TM-X2); Kerberos covers domain-joined workstations | A later ADR would need channel-bound NTLM and a security-architect review |
| SAML IdP-initiated (unsolicited) SSO | No `InResponseTo` means no browser binding, so login-CSRF and replay rest on the cache alone. IdP portals (Okta, Entra My Apps) can link to `/auth/sso/{idpId}/start` instead | Yes, by adding a check set |
| Encrypted assertions | TLS protects transport. Decryption runs before signature verification, which is where the 2026 gosaml2 DoS lived (GHSA-hwqm-qvj9-4jr2). No SP decryption key exists to manage | Yes |
| SAML Single Logout | Unsigned LogoutRequests were accepted by gosaml2 before v0.11.0 (GHSA-pcgw-qcv5-h8ch, release notes). Our session ends on our sign-out, idle and absolute expiry | Yes |
| WS-Federation | Every IdP ADMP lists also speaks SAML or OIDC | Yes |
| MFA by attestation | §6.1 | — |

These are customer-visible, so they went to the CEO as one notice with SSO-D7 (D-0002).

---

## 12. Data model additions

**DM-39 IdentityProvider** (`T`, owner `platform/authn`) is added to the domain model by this
ticket: protocol; enabled; display name; issuer / entityID; client or SP settings; pinned algorithm;
signing certificates or pinned discovery; sealed client credential (DM-11 pattern, TM-D7);
`mfa` (mode, evidence rule); subject source; anchor claim; `admission`; claim mappings. Its
invariants carry SAML-16 (replay rows) and the Transaction (§3) as tenant tables owned by
`authn`. The tenant setting `signin.mode` and the designated method live with it.

## 13. Fitness functions

| ID | What fails CI | Owner (ticket) |
| --- | --- | --- |
| FIT-SSO-1 | An import of `github.com/russellhaering/*`, `github.com/beevik/etree` or `github.com/mattermost/xml-roundtrip-validator` outside `internal/platform/authn/sso/saml`; of `github.com/coreos/go-oidc/*` or `github.com/go-jose/*` outside `internal/platform/authn/sso/oidc`; of `encoding/xml` anywhere under `internal/platform/authn` except `sso/saml`. A `go.mod` pin of goxmldsig below v1.6.0 or gosaml2 below v0.12.0 | devops-engineer (filed by T-0191) |
| FIT-SSO-2 | A §4/§5 check number cited by no corpus record; a class with no record for a protocol; a corpus record without its subtest | devops-engineer, with T-0073 |
| TM-F-SSO | Any §10 case accepted, or refused with another reason | T-0073 (backend-engineer) |

The verifier build tickets cannot merge without FIT-SSO-1 green, so the fence exists before the
first line that parses SAML.

## 14. Follow-ups filed by this spec

| Ticket | Owner | What |
| --- | --- | --- |
| T-0211 | devops-engineer | FIT-SSO-1 and FIT-SSO-2 (§13), green before T-0201/T-0202 merge |
| T-0212 | security-architect | Threat-model pointers for the closed `[OPEN → ADM-143 spec]` markers, TM-Q3, review of SSO-D4/D5/D7; blueprint `authn` library row |
| T-0213 | project-manager | Re-groom T-0201, T-0202, T-0203, T-0206 with these check numbers; T-0206 is not cancelled |
| T-0214 | docs-writer | IdP setup guide with Entra, Okta and AD FS presets |
| D-0002 | CEO (notice) | The customer-visible calls of §6.1, §9 and §11 |

## Sources

- ADManager Plus SSO help: https://www.manageengine.com/products/ad-manager/help/admin-settings/single-sign-on-authentication.html
- gosaml2 releases: https://github.com/russellhaering/gosaml2/releases ; GHSA-hwqm-qvj9-4jr2: https://github.com/advisories/GHSA-hwqm-qvj9-4jr2
- goxmldsig CVE-2026-33487: https://github.com/advisories/GHSA-479m-364c-43vc
- crewjam/saml CVE-2022-41912: https://osv.dev/vulnerability/GHSA-j2jp-wvqg-wc2g
- go-jose CVE-2025-27144: https://gitlab.com/gitlab-org/gitlab-runner/-/merge_requests/5403 ; CVE-2026-34986: https://www.tenable.com/plugins/nessus/342241
- Module versions and dates: Go module proxy `https://proxy.golang.org/<module>/@latest`, read 2026-10-23
- Entra ID token claims: https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
- OIDC Core 1.0 §3.1.3.7: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
- RFC 8176 (amr values): https://www.rfc-editor.org/rfc/rfc8176 ; RFC 9207 (iss parameter): https://www.rfc-editor.org/rfc/rfc9207 ; RFC 4559 (Negotiate): https://www.rfc-editor.org/rfc/rfc4559
- SAML 2.0 Core: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
- Somorovsky et al., "On Breaking SAML", USENIX Security 2012: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky

---
title: "T-0023 findings: pure-Go LDAP GSSAPI bind with channel binding on go-krb5/krb5"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: directory-engineer
ticket: T-0023
sources_last_checked: 2026-10-02
---

# T-0023 findings: pure-Go LDAP GSSAPI bind with channel binding on go-krb5/krb5

## Verdict

- **Proven on Samba, not yet on Windows.** A `GSSAPIClient` for go-ldap on go-krb5/krb5 binds over LDAPS and StartTLS with an
  AES-only keytab and a `tls-server-end-point` channel binding. A bind without the binding, or with a binding over another
  certificate, is rejected. The WS2025 gate (AC2) is **open**: no Windows lab exists. It is ticket **T-0133**.
- **No fork is warranted today. No patch to go-krb5/krb5 was needed**, but only on its `main` branch, not on the released v0.1.0.
- **ADR-0001 contains a wrong premise and needs an amendment.** It and feasibility §3.1/§3.5 say go-krb5/krb5 v0.1.0 "adds
  channel bindings". It does not: the v0.1.0 tag (2026-02-15) has no channel binding and no SASL layers. Both arrived on `main`
  in August 2026 (channel binding #117, `8b6f497`, 2026-08-09; KILE CBT advertisement #120; SASL layers #114). `main` is 160
  commits ahead of the tag. We must pin a commit (or a later tag) and say so in the ADR.
- The "Revisit when" clock (4 weeks incl. a fork) did not run out: Samba was done in one session. The remaining risk is Windows behaviour.

## What was built

`garage/ldap-cbt-spike/` (own Go module; README carries OWNER and EXPIRES). Pinned: go-krb5/krb5
`v0.1.1-0.20260926041222-f89757a5d4ed`, go-ldap v3.4.14, Go 1.27.0.

- `krb5gssapi.Client` (194 lines incl. comments) implements go-ldap's `GSSAPIClient` interface:
  1. service ticket, then a raw Kerberos AP-REQ (not SPNEGO) with the mutual flag; the channel binding goes into the authenticator
     checksum `Bnd` field and the MS-KILE `KERB_AP_OPTIONS_CBT` bit is set (both done by `spnego.NewKRB5TokenAPREQ(..., spnego.ChannelBinding(cb))`);
  2. decrypts the AP-REP under the session key, checks it echoes our ctime/cusec, keeps the acceptor subkey;
  3. unwraps the server's RFC 4752 security-layer offer and answers **"no security layer"**.
  The binding comes from the leaf certificate the connection actually presented
  (`gssapi.NewChannelBindingTLSServerEndPointFromState`; hash chosen from the certificate's signature algorithm per
  [RFC 5929 §4.1](https://www.rfc-editor.org/rfc/rfc5929#section-4.1)). It refuses a non-TLS connection.
- Why "no layer": Active Directory allows a SASL bind on a TLS connection but not SASL signing/sealing on top of it ([MS-ADTS §5.1.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/284923c1-6a5b-4510-b97a-631963c0c3bd)).
  TLS provides integrity and confidentiality, so "signing required" is met by the TLS channel. go-ldap itself does not support SASL layers (`bind.go`: "SASL security layers are not supported currently").
- Tests: 6 unit tests (RFC 5929 value, no-layer selection and acceptor-subkey flag, refusal of a server that offers no "none",
  refusal before the AP-REP is verified, tampered offer, key wiping) and a bind matrix against the lab.

## Evidence (AC1)

Lab: T-0012 Samba **4.22.11** (Debian), `ldap server require strong auth = yes`, `small` tier, AES-only account `svc-cbt-spike`
(`msDS-SupportedEncryptionTypes = 24`, keytab filtered to etype 17/18 by `cmd/aeskeytab`; client `krb5.conf` permits only AES).
Logs: `garage/ldap-cbt-spike/logs/`.

| Transport | Binding sent | Result (`samba-strong-auth.log`) |
| --- | --- | --- |
| LDAPS 636 | `tls-server-end-point` | **BIND OK**, session etype 18 (AES256), `whoami = u:LAB\svc-cbt-spike` |
| StartTLS 389 | `tls-server-end-point` | **BIND OK**, same |
| LDAPS / StartTLS | none | **rejected**: result 49, `80090346 … AcceptSecurityContext error, data 35b` (SEC_E_BAD_BINDINGS) |
| LDAPS / StartTLS | binding over a different certificate | **rejected**, same error |

`go test ./...` passes (6 unit + 7 integration tests incl. "keytab has only AES entries"). Control run (`samba-control-relaxed.log`,
`ldap server require strong auth = allow_sasl_without_tls_channel_bindings`): no binding → **BIND OK**; wrong binding → still rejected.
So the rejection above is caused by the missing binding and nothing else. Mutation check: making the client select the integrity
layer instead of "none" made `TestNegotiateSelectsNoLayerOverTLS` fail; restored.

## go-krb5/krb5: patches, size, fork (AC3)

| Question | Answer |
| --- | --- |
| Patches needed on `main` (f89757a)? | **None.** Everything the adapter calls exists: `spnego.NewKRB5TokenAPREQ` with `ChannelBinding`, `gssapi.NewChannelBindingTLSServerEndPoint*`, `WrapToken`, `EncAPRepPart`. |
| On v0.1.0? | Cannot build the adapter (`undefined: gssapi.ChannelBinding`, `spnego.ChannelBinding`; `NewKRB5TokenAPREQ` takes no options): `logs/probe-krb5-v0.1.0.log`. A backport would be the whole feature, not a patch. |
| What we own | The ~190-line adapter above (go-ldap needs `GSSAPIClient`; go-krb5 ships no LDAP glue). The go-ldap Kerberos client in `go-ldap/ldap/v3/gssapi` uses gokrb5 v8 and cannot send a binding, so we do not use it. |
| Fork? | **No fork now.** Pin the commit in `go.mod`, keep the spike tests as a regression suite (they run in CI against the lab), and watch for a tagged release. Fork only if (a) upstream stops merging, (b) WS2025 (T-0133) shows a wire defect we must fix, or (c) no tag exists when we ship GA and our policy forbids pseudo-versions. A WS2025 defect would be a small upstreamable patch first. |
| Risks | No tagged release with the feature; project age; `main` moves fast (160 commits in seven months). Maintainer capacity was not assessed. Pseudo-version pins need the licence/provenance review at each bump. |

## Go-ldap's Windows SSPI path (AC3)

- **Status: compiles and vets for `GOOS=windows`; not run.** There is no Windows host or lab. `gssapi.SSPIClient` satisfies `ldap.GSSAPIClient` (`cmd/sspiprobe`).
- By source reading: `NewSSPIClientWithChannelBinding(cert)` builds `tls-server-end-point:` + the RFC 5929 hash and hands it to SSPI via
  `kerberos.NewClientContextWithChannelBindings` (alexbrainman/sspi, BSD-3); it uses the *current user's* credentials, which is what a
  process running as a gMSA has. So the gMSA case plausibly works, but **`[UNVERIFIED]` until T-0133 item 4 runs it.** Windows does the signing/sealing decision itself.
- **Packaging trap for T-0123:** `SSPIClient` lives in the same package as go-ldap's gokrb5-v8 client. On a Windows build, importing
  `github.com/go-ldap/ldap/v3/gssapi` links gokrb5 v8 (about 40 packages), which the licence register marks "Rejected (direct use)" and
  ADR-0001 wants to avoid as a third Kerberos stack. On Linux it is not linked (we do not import the package). Options for T-0123: wrap
  `alexbrainman/sspi` ourselves (about 100 lines, same shape as this adapter), or accept the transitive gokrb5. Recommend the wrapper.

## AC2: WS2025 with signing required and `LdapEnforceChannelBinding = 2` — remaining gate

Not run. No Windows lab exists (lab runbook §5; Windows labs are a CEO matter). It is tracked by **T-0133** (owner directory-engineer, P1,
depends on this ticket, blocks nothing yet but should precede T-0080's exit). T-0133 asks for an event-log export showing no events
2887, 3039, 3074 or 3075. The Microsoft event table is at [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)
(2887 unsigned binds; 3039 CBT unsupported; 3040/3041 CBT failure/success; the page does not list 3074/3075, which come from KB4520412 `[UNVERIFIED]` here).

What Samba could not tell us, and Windows may:
- Windows reads the binding through LSA and may fold the CBT bit or hash differently. We send both the hash and the `KERB_AP_OPTIONS_CBT` authorization-data element, as MS-KILE describes.
- Certificate signature algorithm: Go hashes per RFC 5929 (SHA-256 for SHA-1/SHA-256 signatures, SHA-384/512 for those). Ed25519 certificates give "undefined" and the adapter returns an error, so such a DC cannot be bound with CBT (unlikely on AD CS).
- The reply token's sequence number (we send 0), the acceptor-subkey handling and the "no layer" offer under Windows' signing policy.
- Windows rejects with different codes/diagnostics; Samba's `80090346` mimics SEC_E_BAD_BINDINGS only.

## Lab gotchas learned

- The Samba 4.22 default `ldap server require strong auth = yes` already enforces channel binding. The runbook's "Samba ≥ 4.21 supports it" holds; **4.22 needs no config change** to act as an "Always" DC.
- Samba's `exportkeytab` writes RC4 entries too. A truly AES-only keytab needs filtering (`cmd/aeskeytab`).
- The T-0012 lab container was started from a deleted worktree (no `lab/.lab.env`), so the spike ran its own project on shifted ports (README).
- Keytab and credentials stay in gitignored `.lab/`; no secret is printed or logged.

## Recommendations

1. Amend ADR-0001 (director + notice): replace "v0.1.0 adds channel bindings" with the measured fact; adopt go-krb5/krb5 at a pinned commit; drop "budget to fork" to "fork on trigger" (above).
2. T-0080 builds the production `connector/kerberos` from `krb5gssapi/`, adds the DN/filter-safe wrapper, SecureConn pooling and timeouts, and keeps the three-way test matrix in CI.
3. T-0123 decides the SSPI wrapper vs gokrb5 transitive (above); T-0133 runs the Windows proof; if T-0133 fails the ADR revisit clock starts then.

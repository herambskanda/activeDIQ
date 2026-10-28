---
title: Release signing and key custody — offline root, threshold signatures, targets key in HSM/KMS, rotation, provenance
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: devops-engineer
ticket: T-0140
reviewers: security-architect
refs: TM-A8, TM-R6, TM-TB10-T4, TM-D12, ENH-07
---

# Release signing and key custody

Design for how a skenzeriq release becomes something a customer's Tier-0 install will run. It
implements [threat model §10 (TM-D12)](threat-model.md) and the protocol in
[ENH-07](../../product/specs/enh-07-signed-update-protocol.md); it adds the parts those documents
leave to T-0140: who holds which key, how a signature is produced, how keys rotate, and what
provenance a release carries. The pipeline build is T-0141. **The money decision (HSM/KMS, code-signing
certificate) is prepared separately and is not made here; §9 lists what it must decide.**

Sources: [TUF specification](https://theupdateframework.github.io/specification/latest/),
[SLSA v1.0](https://slsa.dev/spec/v1.0/), [in-toto attestations](https://github.com/in-toto/attestation),
[CISA AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a). Vendor product
claims not re-checked in this ticket are tagged `[UNVERIFIED]`.

## 1. What we defend against

| Threat | Control in this design |
| --- | --- |
| TM-TB10-T4: attacker steals a signing key | Root offline and k-of-n; targets key non-exportable; online keys short-lived and low-power; every key rotatable (§6) |
| One insider or one stolen laptop signs a release | No single person or machine can produce a valid root change (threshold); a release needs a CI run plus an approval (§4) |
| TM-R6 / SolarWinds: the build itself is subverted and signs legitimately | Cannot be prevented by signatures. Reduced by hermetic CI-only builds, reproducibility checks, provenance and a human approval of the exact digest before signing (§7) |
| CI credential theft yields a long-lived signing credential | There is none: CI holds no key. It holds a short-lived workload identity that may *request* a signature from the KMS/HSM, only on a protected tag and only after approval (§4) |
| Stolen key used after we notice | Revocation by the next root/targets metadata; clients reject the key even for newer metadata it signed (ENH-07 §3 rule 5); emergency path in §6.3 |

Out of scope: the server never signs code (TM-D12 rule 7); agent policy signing is T-0142.

## 2. Keys and custody

| Key | Purpose | Algorithm (proposed) | Custody | Who can use it | Lifetime |
| --- | --- | --- | --- | --- | --- |
| **Root** ×5 | Signs root metadata: all role keys and thresholds; pinned in every installer | Ed25519 | Five hardware tokens/HSMs, one per custodian, each offline in a sealed tamper-evident container at its own site. **Threshold 3 of 5** (ENH-07 `[proposed]`) | Custodian + PIN, physically present at a signing ceremony (§3) | Root metadata 12 months; keys 3 years or on custodian change |
| **Targets** | Signs the release manifest (name, length, SHA-256, version, platform, min-from) | Ed25519 or ECDSA P-256, whichever the chosen KMS/HSM supports; the client verifier supports both `[decide in T-0141]` | HSM or cloud KMS, **non-exportable**. Threshold 1 online key now; 2 of 2 (KMS key + offline "release-approver" token) is the upgrade path if the CEO funds it | The release job's workload identity, via a policy that requires protected tag + approval (§4) | 12 months, rotated by root |
| **Snapshot** | Consistency view of metadata | Ed25519 | Online; KMS key or, in the interim, an encrypted CI secret | Scheduled job only | 6 months |
| **Timestamp** | Freshness | Ed25519 | Online; same as snapshot | Scheduled job (every 6 h) | 6 months |
| **Authenticode** (MSI, EXE, DLL) | Windows trust, SmartScreen, WDAC/AppLocker | RSA/ECDSA per CA | Certificate from a public CA; private key in HSM/KMS (CA rules require a hardware-protected key for code-signing certificates — [CA/B Forum Code Signing Baseline Requirements](https://cabforum.org/working-groups/code-signing/requirements/) `[UNVERIFIED: effective date and wording for each CA]`) | Signing step of the release job via the KMS/HSM signer | Per certificate (1–3 years) |
| **OCI image signature** | Container identity | Targets-adjacent key, or keyless OIDC signature `[decide in T-0141]` | Same KMS/HSM, or Sigstore keyless — **not usable offline or air-gapped**, so the TUF targets entry (digest of the image) is the authoritative signature; the OCI signature is defence in depth for registries | Release job | — |

Key separation is deliberate: Authenticode and OCI signatures protect the *host OS and registry*
trust decisions; the TUF targets signature protects the *update decision*. Compromise of the CA
certificate does not let an attacker pass our updater, and vice versa. The updater requires both
(ENH-07 §3 rule 2).

Never: a key in the repository, a CI secret that holds a long-lived targets/Authenticode key, a key
in a log, a build arg or an image layer; keys generated on a developer laptop.

## 3. Root ceremony

Held for: initial root creation, annual re-signing (root metadata expiry), planned rotation, custodian change,
and emergency recovery. Every ceremony is scripted, rehearsed in a dry run on throw-away keys first, and
recorded.

1. **Participants.** Ceremony lead (devops-engineer or delegate), the custodians needed to reach the
   threshold, an independent witness (security-architect or a person who is not a custodian). Custodians
   are named roles held by at least five distinct people; no person holds two keys. No custodian is the
   release approver of §4 where staffing allows `[small-team caveat in §9]`.
2. **Environment.** An offline machine booted from verified read-only media, no network, no radios; the
   signing tool (`tools/release/...`, built reproducibly and hash-verified against a published digest) and
   the unsigned proposed root metadata arrive on a write-once medium. Output leaves on a fresh medium.
3. **Steps.** (a) Verify tool hash and the proposed metadata diff aloud against the change request;
   (b) each custodian signs on their own token; (c) verify the result with the *shipping* client verifier
   (the same one customers run) against the previous root; (d) hash the signed file and read it
   back to the witness; (e) transcribe the ceremony record (date, participants, tool hash, metadata
   hash, key IDs, outcome); (f) tokens return to sealed containers.
4. **Publication.** The signed root is committed to `packaging/release/root/<version>.root.json`
   (public data) via an ordinary reviewed pull request, and published at the release host. The record is
   committed under `knowledge/development/runbooks/` ceremony log (no secrets).
5. **Storage.** Tokens in tamper-evident bags in a safe / safety-deposit box at five separate sites. The
   custody register (who, where, bag serial, last seen, last inventory) is reviewed quarterly; a seal found
   broken is a key-compromise event (§6.3 and §6.5).
6. **Backup.** The threshold is the backup: 3 of 5 means two keys can be lost without recovery. If three are
   lost the root cannot be rotated: see §6.6 for the re-anchoring release, the only recovery.

## 4. How a release is signed

```
tag vX.Y.Z (protected, signed commit, 2-person review of the merge)
  └─ CI release job (ephemeral, hosted-or-self-hosted runner, no secrets on disk)
       1. hermetic build from pinned toolchain + lockfiles  → artefacts, SBOM (CycloneDX), SHA256SUMS
       2. second independent rebuild (different runner)     → digests must match, else stop (§7)
       3. provenance attestation drafted (SLSA/in-toto) from the job's workload identity
       4. ─── pause: approval gate ─── a release approver (≠ tag author) reviews the digest list,
              SBOM diff vs the previous release, licence and vulnerability scan results
       5. job requests signatures from KMS/HSM using short-lived OIDC identity:
            - Authenticode on binaries/MSI      (signer key in HSM/KMS)
            - targets.json (manifest of digests) (targets key)
            - OCI image signatures
       6. snapshot/timestamp regenerated by the scheduled job
       7. publish to release host + build offline bundle (same files, §5)
       8. verify the published set with the shipping client verifier in a clean container; fail = pull
```

Controls that make step 5 meaningful:

- **The KMS/HSM key policy** allows `sign` only for the release workload identity whose token claims
  match repository, protected tag ref and the approved environment. Not for people, not for branches,
  not for pull requests. A fork or branch build cannot obtain a signing-role signature (ENH-07 AC-9).
- **Approval is bound to digests**: the approval records the SHA-256 of the manifest it approved; the signer
  step signs only that digest. A later change to artefacts invalidates the approval.
- **Signing audit**: the KMS/HSM's own audit log (every `sign` call, caller, time, digest) is exported to
  an append-only store outside the CI provider's control and reconciled monthly against the published
  releases. A signature with no release is an alert (key abuse).
- **Break-glass**: if CI is unavailable, no human signs from a laptop. The fallback is a re-run of the same
  job on a rebuilt runner. A manual path would be the bespoke path PatchIQ built; it is refused by design.
- The interim Ed25519 key in `RELEASE_SIGNING_KEY` ([release runbook](../runbooks/release-and-security-txt.md))
  is replaced by this flow in T-0141; the file layout (`packaging/release/`, `*.sig`, `SHA256SUMS`) is kept.

## 5. Offline and air-gapped

An offline install receives the same signed bundle with a different courier (ENH-07 §6 rule 6). Therefore:
all trust is rooted in pinned public keys and signed metadata, never in an online service. Sigstore-style
transparency lookups, OCSP and CRL checks are not required for acceptance (they are best-effort when
online). Authenticode timestamping by the CA's RFC 3161 service is applied at signing so binaries keep
validating after the certificate expires. The root chain inside the bundle starts at the oldest root any
supported install pins (§6.2).

## 6. Rotation and revocation, all through root

Every key except root is rotated by new root metadata signed by the *old* threshold and the *new*
(TUF root rotation; [spec §5.3](https://theupdateframework.github.io/specification/latest/#update-the-root-role)). The client
walks the root chain version by version, so a rotation never needs a flag day.

| # | Event | Action | Who signs | Client effect |
| --- | --- | --- | --- | --- |
| 6.1 | **Routine targets rotation** (every 12 months) | Create new KMS/HSM key; ceremony publishes root N+1 listing new targets key, removing the old one at its expiry date; for the overlap, targets metadata is signed by both | Root threshold | Accepts either until the old is removed; rejects old after |
| 6.2 | **Routine root rotation** (annual re-signing, key change at least every 3 years) | Root N+1 signed by 3 of old keys and 3 of new keys. Planned at least 60 days before expiry (ENH-07). Installers shipped after it pin the new root, but we keep the whole chain so installs up to *two years old* can still walk forward. An install older than the chain cannot self-update: documented manual bundle path with a re-anchoring root (§6.6) | Old and new threshold | Chain walk |
| 6.3 | **Suspected or confirmed compromise of the targets key** | (1) Disable the KMS key version immediately; (2) emergency ceremony within 24 h: root N+1 revokes the key, adds a new one; (3) release a fixed build signed by the new key; (4) targets marks affected releases `withdrawn`; (5) security advisory per the disclosure policy ([`SECURITY.md`](../../../SECURITY.md)); (6) review the KMS audit log to enumerate what was signed | Root threshold | Revoked key rejected everywhere, including for newer metadata it signed (ENH-07 rule 5) |
| 6.4 | **Compromise of snapshot/timestamp keys** | Rotate through root as 6.3. Because these keys cannot change targets content, impact is a freeze/rollback attempt bounded by client rollback state and expiry | Root threshold | Same |
| 6.5 | **Compromise of fewer than the threshold root keys, or a lost key, or custodian leaves** | Root N+1 removes that key, adds a replacement; the removed token is destroyed and its destruction recorded | Remaining threshold | Chain walk |
| 6.6 | **Threshold or more root keys lost or compromised** | Unrecoverable by metadata. Last resort: a *re-anchoring release*: a new root distributed as a normally signed update (signed by whatever still validates) *and* out-of-band for installs that cannot be reached; customers verify the new root fingerprint against a value published on at least two independent channels (website, `SECURITY.md`, support). Treated as a security incident with a customer notice. The design target is to make this scenario improbable: 5 sites, 3-of-5, quarterly inventory | — | Manual trust re-anchoring |
| 6.7 | **Authenticode certificate expiry, revocation or CA distrust** | New certificate, new signature for the next release; the updater does not trust "any valid Authenticode", it pins the expected signer subject and thumbprint chain in signed targets metadata, so a certificate swap is a metadata change under targets | Targets (after root approves the pinned subject policy) | Pinned signer updated |
| 6.8 | **Custodian change** | Counts as 6.5 for that custodian's key; ceremony within 30 days | Remaining threshold | — |

Rotation is practised: a **rotation drill** is run in CI weekly against throw-away keys (§8), and a full
dry-run ceremony with throw-away tokens is run before the first real ceremony and at least annually.

## 7. Provenance and reducing TM-R6

A signature says "skenzeriq's pipeline produced this", not "this is what the source says". To narrow the
gap SolarWinds exploited ([AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)):

1. **Hermetic CI-only builds**: pinned toolchains and base images by digest, lockfiles, vendored or
   hash-verified dependencies, no network in the compile step after fetch. Target: SLSA Build L3 for the
   release job (isolated, ephemeral builder; provenance not forgeable by the build steps — [SLSA v1.0 build levels](https://slsa.dev/spec/v1.0/levels)).
2. **Reproducible builds**: `SOURCE_DATE_EPOCH`, stripped paths and timestamps, deterministic archives. The
   release job builds twice on separate runners and compares digests (§4 step 2); a mismatch blocks
   signing. A third *verifier* build runs on infrastructure under a different administrative domain
   (a CEO-level cost question, §9) so that subverting one build environment is detectable. Windows MSI/Authenticode
   output is compared before signing (the signature is added after the digest comparison).
3. **Provenance**: an in-toto/SLSA provenance statement per artefact (source repo + commit, builder identity,
   build config digest, input digests, tool versions), signed by the same release workload, shipped in the
   bundle and referenced from targets metadata. The client records the provenance reference in the audit
   event `update.verified` but does not need it to accept (acceptance is by TUF); a verifying customer can
   check it independently.
4. **SBOM** (CycloneDX) per release, diffed against the previous release at the approval gate; any new
   dependency, base image or licence class blocks until the licence register is updated.
5. **Source integrity**: protected tags and `main`, signed commits for release tags, mandatory review,
   branch protections enforced in settings and *checked* by a scheduled job that fails if they drift.
6. **Pipeline integrity**: workflows pinned to commit SHAs (already gated by `make workflows-check`),
   no `continue-on-error`, runner images pinned, no self-hosted runner shared with untrusted jobs, release
   workflow changes need security-architect review (CODEOWNERS).
7. **Residual** (TM-R6, accepted): a malicious change merged through review that builds reproducibly and
   passes the approval gate is signed. Provenance makes it attributable and reproducible, not absent.
   Detection relies on review, the SBOM diff and anomaly review of the audit log.

## 8. Fitness functions and proofs (what T-0141 builds)

| ID | Check | Fails when |
| --- | --- | --- |
| KC-1 | `make ci`: gitleaks plus a grep for private-key PEM/PKCS#8/seed patterns in the repo and in release outputs | Any private key material is committed or bundled |
| KC-2 | Release workflow lint (extends `workflows-check`): signing steps run only in `release.yml`, only on `refs/tags/v*`, with the `release` environment; no `secrets.*` key material for targets/Authenticode; `id-token: write` only on that job | A new workflow or trigger can reach the signer |
| KC-3 | KMS/HSM policy as code (IaC file in `packaging/release/`) checked against the claim constraints in §4 | Policy allows branch, PR or user principals |
| KC-4 | Rotation drill: throw-away root/targets/snapshot/timestamp keys; rotate each; verifier accepts the chain, rejects a role signed by a removed key, rejects a root signed by less than threshold, rejects server-signed code. (This is TM-F-UPDATE's key-rotation case.) | Any of those outcomes differ |
| KC-5 | Reproducibility check: two builds of the same commit produce identical digests | Digests differ |
| KC-6 | Published-release verification in a clean container with the shipping verifier, online and from the offline bundle | Either courier rejects, or they disagree |
| KC-7 | Provenance present and consistent: every artefact in targets has a provenance statement whose subject digest equals the manifest digest, and an SBOM | Missing or mismatched |
| KC-8 | Root expiry watch: scheduled job fails when root metadata expires in under 90 days, targets in under 14 | Calendar drift (analogue of the `security.txt` renewal) |
| KC-9 | Signing-audit reconciliation (monthly job, once the KMS exists) | A `sign` event has no matching release |

Each ships with a documented failing fixture (a tampered file or a bad policy) alongside the passing run;
the ticket that builds it provides both as evidence.

## 9. Decisions and inputs for the money decision

Prepared here as inputs; **not decided**. The CEO decision (via factory-director and `ceo-decisions`) needs:

| Item | Options | Notes |
| --- | --- | --- |
| Targets/Authenticode key custody | (a) Cloud KMS/HSM-backed key (AWS KMS, Azure Key Vault Managed HSM, GCP Cloud HSM); (b) dedicated HSM device(s) on-prem; (c) provider-managed cloud signing service for Authenticode `[UNVERIFIED: pricing/availability, check at decision time]` | (a) fits the workload-identity model of §4 best. (b) keeps keys with us but adds an operated device and still needs a networked signer. Neither is an account we may open ourselves |
| Root tokens | Five FIDO2/PIV-class hardware tokens or small HSMs plus tamper-evident storage at five sites | Low cost, relative to the rest |
| Code-signing certificate | OV or EV from a public CA; hardware-key requirement applies | Needed before the first customer MSI; lead time for validation is weeks `[UNVERIFIED]` |
| Independent verifier build | A second administrative domain for the third build in §7.2 | Optional for v1, recommended before M3 (DC code) |
| People | Five root custodians and a release approver who is not the tag author | If we have fewer than five people, custodians may include trusted outside parties (e.g. an advisor or lawyer holding a sealed token) — a CEO matter |

Interim until funded (what exists today): Ed25519 key in a repository secret, signing SBOM and `SHA256SUMS` only
(T-0261). It stays *interim*, it must not be used for anything that installs on a DC or auto-updates, and
the first real customer release is gated on the targets key and Authenticode certificate decisions.

## 10. Acceptance mapping

| T-0140 acceptance element | Where |
| --- | --- |
| Offline root | §2, §3, §6.2, §6.6 |
| Targets key | §2, §4, §6.1, §6.3 |
| Rotation through root | §6 (every key except root; root by old+new threshold) |
| Provenance | §7, §8 KC-5/KC-7 |
| TM-A8, TM-TB10-T4, TM-R6 | §1, §6, §7.7 |

## 11. Follow-ups

- T-0141: implement the pipeline, KMS policy as code, drills KC-1..KC-9.
- Runbook `release-key-ceremony.md` (written with the first ceremony rehearsal, needs the CEO decision first).
- ENH-07 spec: confirm 3-of-5, expiries and the Authenticode signer pinning of §6.7 (TM-F-UPDATE).

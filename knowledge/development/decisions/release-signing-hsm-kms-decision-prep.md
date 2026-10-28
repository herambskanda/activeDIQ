---
title: Code-signing certificates and HSM/KMS for release keys — decision prep
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: security-architect
kind: decision-prep
ticket: T-0141
refs: TM-A8, TM-TB10-T4, TM-R6, TM §16.2
---

# Code-signing certificates and HSM/KMS for release keys

Obligation: threat model §16.2 row "Code-signing certificates and HSM/KMS for release keys" (money, the CEO's).
Design being funded: [`release-signing-key-custody.md`](../architecture/release-signing-key-custody.md) (T-0140; §9 lists
the inputs). Why it matters: a stolen or abused release key is code execution on every customer's Tier-0 install, DCs
included (TM-X8; [CISA AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)). The buyers we want
to displace ManageEngine will ask how we protect our release keys (ME-SEC §4.4 in
[`manageengine-ad-customer-voice-and-security.md`](../../business/market-research/manageengine-ad-customer-voice-and-security.md)).

**Price confidence.** The official vendor pages rendered placeholders or were not retrievable in this session, so most
figures come from vendor documentation mirrors, retailers and third-party guides. They are **indicative ranges to
re-check on the vendor calculator when we sign up**. Tagged `[UNVERIFIED]` where only a secondary source was found.

## 1. What is being bought (three separate things)

| Need | Why | Cannot be skipped because |
| --- | --- | --- |
| **A.** Authenticode certificate + hardware-protected key | Windows trust for the MSI, DC agent, password filter, credential provider (WDAC/AppLocker, SmartScreen) | CA/B Forum rules: private key in a FIPS 140-2 L2 / CC EAL4+ module; certificates issued on or after 1 Mar 2026 valid ≤ 460 days ([CA/B Forum CSBR](https://cabforum.org/working-groups/code-signing/requirements/)). So **annual renewal is built in**. |
| **B.** Non-exportable online key for TUF targets (+ snapshot/timestamp) | Signs the update decision (ENH-07) | The design bans long-lived signing keys in CI secrets (§2, §4). The interim repository-secret Ed25519 key must not touch DC code or auto-update. |
| **C.** Five offline root tokens + tamper-evident storage at five sites | 3-of-5 root | Threshold needs five distinct devices. |

## 2. Options

### A. Authenticode

| Option | Cost (indicative) | For | Against |
| --- | --- | --- | --- |
| **A1. Azure Artifact Signing (formerly Trusted Signing), Basic** | $9.99/account/month, 5,000 signatures; Premium $99.99 / 100,000 ([docs mirror via search](https://azure.microsoft.com/en-us/pricing/details/artifact-signing/), official page showed placeholders) `[UNVERIFIED]` | Cheapest; keys never leave Microsoft; fits CI workload identity; Microsoft recommends it for non-Store distribution and reputation behaves like OV ([Microsoft: code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)); reported generally available in US, Canada and Europe ([DevClass, Jan 2026](https://www.devclass.com/security/2026/01/14/code-signing-windows-apps-may-be-easier-and-more-secure-with-new-azure-artifact-service/4079554)) | Organisation eligibility (country, years in business) **not confirmed**; ties release to an Azure account; certificate profile chain/timestamping behaviour must be verified against our offline verifier (§5 of the design) `[UNVERIFIED]` |
| **A2. Public-CA OV certificate + CA cloud-signing key (DigiCert KeyLocker, SSL.com eSigner)** | Roughly $65–83/month with certificate for KeyLocker (retail listings) `[UNVERIFIED]`; eSigner tiers seen at $250/month for 1,000 signings ([SSL.com eSigner pricing](https://www.ssl.com/guide/esigner-pricing-for-code-signing/amp/)) `[UNVERIFIED]`; certificate itself about $130–$400/year `[UNVERIFIED]` | Mature, works for any organisation; KeyLocker signature quota per certificate is capped ([DigiCert docs](https://docs.digicert.com/en/digicert-keylocker/overview/licensing.html)) | Highest running cost; signing calls leave our KMS audit, so the monthly reconciliation (KC-9) depends on the vendor's log |
| **A3. OV certificate on a hardware token we hold** | Certificate + token, roughly $200–$600 first year `[UNVERIFIED]` | No ongoing service fee; offline | A token cannot be used by an ephemeral CI runner, so signing needs a self-hosted signing host, which the design rejects (no human or laptop signing, §4). Not recommended |
| **A4. EV certificate** | $400+/year ([Microsoft](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)) | None that matters | Microsoft now gives EV the same SmartScreen path as OV; the premium is no longer justified. **Do not buy** |

### B. Online release keys (targets, snapshot, timestamp)

| Option | Cost (indicative) | For | Against |
| --- | --- | --- | --- |
| **B1. Cloud KMS, HSM-backed asymmetric key** (AWS KMS, or the cloud our CI/release host already uses) | AWS: $1/key/month plus $0.15 per 10,000 asymmetric requests, no free tier for asymmetric ([AWS KMS pricing](https://aws.amazon.com/kms/pricing/)). Three keys and a few hundred requests a month: **under $5/month**. GCP Cloud HSM: $1–$2.50 per key version/month ([Google Cloud KMS pricing](https://cloud.google.com/kms/pricing)). Azure Key Vault Premium HSM keys: about $1–$5/key/month `[UNVERIFIED]` | Non-exportable; per-call audit log; IAM conditions on OIDC claims implement the §4 policy as code (KC-3); fits CI | Cloud-provider trust; algorithm support decides ECDSA P-256 vs Ed25519 (design §2, open point) |
| **B2. Azure Key Vault Managed HSM (dedicated, FIPS 140-3 L3)** | About $3.20/hour per pool, roughly **$2,300/month** ([Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/1031620/managed-hsm-aes-keys-pricing) and third-party guides) `[UNVERIFIED]`. GCP single-tenant Cloud HSM: $3,500/month example ([Google Cloud KMS pricing](https://cloud.google.com/kms/pricing)) | Single-tenant hardware, customer-controlled security domain | About 500x B1 for one signing key a month. No threat in TM requires it |
| **B3. On-prem HSM we operate** (YubiHSM 2 about $650 at launch, about €936 net at a retailer today: [Yubico press release](https://www.yubico.com/press-releases/yubico-launches-yubihsm-2-worlds-smallest-best-priceperformance-hardware-security-module-providing-root-trust-servers-computing-devices), [Bechtle](https://www.bechtle.com/at-en/shop/yubico-yubihsm2-fips--4638478--p)) | Device cost plus a networked signer host, patching and a second device for failover | Keys stay with us | Adds an operated Tier-0 signing host and a workload-identity gap; our own ops burden. Choose only if the CEO wants no cloud custody |

### C. Root tokens

Cheapest viable build: five PIV/FIDO2-class tokens that can hold an ECDSA P-256 root key, plus two spares, plus tamper-evident
bags. Itemised (all `[UNVERIFIED]`, retail ranges to re-check):

| Line | Quantity x unit | One-off |
| --- | --- | --- |
| PIV/FIDO2 tokens (5 root + 2 spare) | 7 x $50-$100 | $350-$700 |
| Tamper-evident bags and seals | one lot | $50-$100 |
| **One-off total** | | **$400-$800** |

Storage (a safe-deposit box per site, five sites, about $60-$120 per site per year) is a **running** cost, counted once, in §3.
Fallback if Ed25519 must live on the device: YubiHSM-class devices, 5 x about $650-$940 (the figures in B3) = $3,250-$4,700 plus
bags, so a one-off of about $3,300-$4,800; not recommended unless the design forces it. Needs five distinct custodians; with fewer
people, trusted outside parties may hold sealed tokens (a CEO matter, design §9).

## 3. Cost summary (first year, indicative)

| Package | One-off | Running per year | Notes |
| --- | --- | --- | --- |
| **Recommended, A1 path**: A1 + B1 + C | $400-$800 (C) | A1 about $120 + B1 about $60 + storage $300-$600 = **$480-$780** | **Year one: $880-$1,580** |
| **Recommended, A2 path** (if A1 ineligible): A2 + B1 + C | $400-$800 (C) | A2 $800-$1,500 + B1 $60 + storage $300-$600 = **$1,160-$2,160** | **Year one: $1,560-$2,960** |
| Heavy: A2 + B2 + C | $400-$800 | about $30,000 for the HSM alone | No threat-model driver |
| Minimal: keep interim repository-secret key | $0 | $0 | **Not acceptable** for DC code or auto-update; the first customer release is gated (design §9) |

## 4. Recommendation

1. **Fund the recommended package: B1 + C now, A1 if we are eligible, A2 otherwise.** Year one is $880–$1,580 on the A1 path and $1,560–$2,960 on the A2 path (one-off plus running, §3); about $480–$780 or $1,160–$2,160 a year after that. This is the cheapest option that
   passes the design's fitness functions (no long-lived key in CI, non-exportable, per-sign audit, claim-constrained identity).
2. **Do not buy EV certificates or a dedicated HSM (B2).** No threat in TM-TB10-T4 needs them. Revisit B2 if a named customer's
   procurement or a compliance regime (FIPS 140-3 L3 sole-tenant) demands it in writing.
3. **Cloud choice follows our CI and release host** (devops-engineer picks within this budget); two clouds is allowed
   if Artifact Signing is used for Authenticode and AWS/GCP KMS for TUF keys.
4. **Residual risk if funded as recommended:** a build-system compromise still signs legitimately (TM-R6); a cloud-provider
   or account takeover could sign (mitigated by claim-bound policy, phishing-resistant MFA on the cloud account, monthly reconciliation KC-9).
   Mitigation of TM-R6 is reproducible builds and the optional independent verifier build (design §7, §9), recommended before M3.
5. **Timing:** certificate validation and Artifact Signing onboarding take days to weeks `[UNVERIFIED]`; start before the first customer MSI.

## 5. Facts to verify when signing up (owner devops-engineer)

- Artifact Signing eligibility for skenzeriq's legal entity and country; certificate chain and timestamp compatibility with the offline verifier.
- AWS KMS: Ed25519 support vs ECDSA P-256; RSA-2048 per-request price (sources disagree) ([AWS KMS pricing](https://aws.amazon.com/kms/pricing/)).
- FIPS 140-2 certificates move to Historical status 21 Sep 2026 per vendor commentary; confirm the CA accepts FIPS 140-3 modules ([CSBR](https://cabforum.org/working-groups/code-signing/requirements/)) `[UNVERIFIED]`.
- Current official prices for every line above.

## 6. Decision wanted (for factory-director via `ceo-decisions`)

Approve a release-signing budget of **a first-year ceiling of $3,000 all-in (one-off and running; the estimate tops out at
$2,960 on the A2 path, $1,580 on A1) and up to $2,200 per year from year two** (A2 running top is $2,160), using the recommended
package. The factory chooses vendors within it and escalates only if A1 and A2 both fail eligibility, the YubiHSM-class fallback
becomes necessary (adds about $2,900-$4,000 one-off), or an ask exceeds the ceiling.

**Reversibility and what it blocks.** Spend is small and monthly services can be cancelled, but tokens and certificates are
sunk once bought. Without this approval the first customer MSI and auto-update stay gated (design §9): we may not ship DC
code or enable updates on the interim repository-secret key. **If the CEO declines**, fallback is to ship only a manually
verified, unsigned-update build to design partners with no DC-side components; we recommend against it.

## 7. Fitness function (for ADR status)

This is a decision prep, not an ADR. The funded design is proved by KC-1..KC-9 in the design doc (T-0141 pipeline build). Spend is
tracked against this ceiling in the release runbook.

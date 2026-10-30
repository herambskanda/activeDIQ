---
title: "Spec: ENH-07 signed, staged, automatic updates — protocol, couriers, customer controls"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: heramb
author: product-manager
ticket: T-0138
epic: E-001
milestone: M2
parity: [ADM-209, ADM-213, RMP-046, ADM-210]
scope: locked
sources_last_checked: 2026-10-28
---

# Spec: ENH-07 signed, staged, automatic updates

> An admin never runs an upgrade procedure: new releases arrive signed, apply in the customer's
> window, roll themselves back if the product does not come up healthy, and work the same on an
> air-gapped server. A compromised mirror, a stolen key, a replayed old release or a hijacked
> activeDIQ server cannot make an install run code skenzeriq did not release.

Closes `[OPEN → ENH-07 spec]` in TM-TB10-T8 and TM-TB10-T9 and in blueprint §14 flow 6; answers
**TM-Q11** (update protocol details; courier telemetry; OCI apply without the Docker socket);
names the subject of **TM-F-UPDATE** for T-0139 (the proof). Rules 1–7 are those of
[threat-model §10 (TM-D12)](../../development/architecture/threat-model.md); rule 7 of
[ADR-0002](../../development/decisions/0002-deployment-model.md) fixes "one release train, one
verifier, two couriers". Input to `solution-architect` (update ADR, apply mechanism), `devops-engineer`
(signing pipeline, T-0140/T-0141) and the E2.12 build tickets. Reviewed by `solution-architect`;
`security-architect` reviews §3–§5. **Tag every build ticket from this spec `security-sensitive`.**

## 1. Problem and user

- **Admin / IT operations (the person who owns the activeDIQ server).** Job: keep the product
  current without an outage, a weekend, or a restore from backup. In ManageEngine, upgrades are
  "manual, multi-step" and some reviewers report failed upgrades that forced a restore: ≈16 of
  ~150 coded reviews, present in every product (customer-voice doc, row X3 in
  [manageengine-ad-customer-voice-and-security.md](../../business/market-research/manageengine-ad-customer-voice-and-security.md)).
  ADManager Plus's automatic hotfix checks daily at 11 pm and offers restart now, later or at a set
  time, and is **not available with HA** (matrix ADM-209, source "ADM doc §3.X; ADM doc W1").
- **Security lead / auditor.** Job: prove that the tool with Tier-0 reach cannot be turned into a
  delivery vehicle. SolarWinds shipped a malicious DLL signed by the legitimate certificate
  ([CISA AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)), so
  "it is signed" is not the bar; key separation, freshness and rollback defence are.
- **Air-gapped operator.** Job: update with a file carried across a boundary, with the same
  guarantees (ADR-0002 "air-gapped is a transport, not a third product").
- Frequency: a release train every few weeks plus out-of-band security releases; the admin should
  touch it on the order of never, and review it quarterly.

## 2. Parity baseline and enhancements

| ID | ManageEngine behaviour (source: matrix) | activeDIQ v1 |
| --- | --- | --- |
| ADM-209 Automatic hotfixes (must, leapfrog) | Daily check; restart now/later/at set time; not with HA | Parity: automatic check, apply now / in window / at set time. Leap: signed, zero-downtime, rollback, works under HA |
| RMP-046 Self-maintenance (must, leapfrog) | Automatic patch updater | Same mechanism; no separate updater per module |
| ADM-213 Diagnostics and upgrades (should) | Manual service-pack upgrades | Replaced by the train; diagnostics are out of scope here |
| ADM-210 HA (must) | Hotfix unavailable under HA | Update is node-by-node under HA (§6, AC-10) |

Enhancements (all v1, all tied to X3 and wedge #1 of the matrix "signature" list):
- **E1 Update that just happens, with proof.** Automatic apply inside a customer window; an update
  history showing verified hashes, signer, duration, result.
- **E2 Automatic rollback on failed health check**, tested on every release (P2 upgrade tests).
- **E3 Same guarantees offline**: signed bundle, one verifier.
- **E4 No ingress, no Docker socket, no mandatory egress** — an enhancement over any updater that
  needs a privileged helper.

## 3. The protocol (answers TM-Q11, part 1)

Roles per [TM §10](../../development/architecture/threat-model.md) and the
[TUF specification](https://theupdateframework.github.io/specification/latest/). Values below are
**proposed defaults**; `security-architect` confirms them, and every value lives in signed metadata
or platform settings, never as a constant buried in the client.

| Role | Custody | Signs | Expiry (proposed) | Refresh |
| --- | --- | --- | --- | --- |
| Root | Offline, **3 of 5** threshold `[proposed; T-0140]` | The keys and thresholds of all roles | 12 months | Planned rotation at least 60 days before expiry |
| Targets | HSM/KMS (T-0140/T-0141) | Release manifest: for each artefact its name, **length and SHA-256**, product version, platform, minimum-from version | 30 days | At every release, and at least every 14 days |
| Snapshot | Online | The version of the targets and root metadata (stops mix-and-match) | 7 days | Daily |
| Timestamp | Online | The version and hash of snapshot | 3 days | Every 6 hours |

Protocol behaviour (the client is the one verifier; no courier has its own copy):
1. **Order.** Root chain (each version signed by the previous threshold *and* its own) → timestamp
   → snapshot → targets → artefact. Anything failing stops the sequence. The client refuses
   metadata larger than a fixed limit and artefacts longer than the length the signed manifest
   states (endless-data defence).
2. **Verify before unpack (rule 1).** Hash and length are checked while streaming to a quarantine
   directory outside the product's data path. Nothing is extracted, executed or loaded until the
   artefact, the manifest and the Authenticode or OCI signature all pass.
3. **Rollback protection (rule 2).** Per install, persisted in PostgreSQL *and* the host (so a
   database restore cannot rewind it): highest root, timestamp, snapshot and targets metadata
   versions seen, and the highest **committed** product version. The client refuses metadata
   with a lower version and any artefact whose product version is below the committed one.
   *Downgrade is not a courier function in v1:* a customer who must go back restores from backup
   (ADM-158). The automatic rollback in §6 restores the locally retained, previously verified
   build and is not a downgrade.
4. **Freeze protection (rule 3).** Expired timestamp or snapshot (and targets) is refused for
   *new* updates. The product keeps running; the console shows "update information is stale since
   …". The client also keeps the newest signing time it has verified and refuses a system clock
   earlier than it (no clock-rewind to extend validity).
5. **Key rotation and revocation.** Root rotation is accepted only when signed by the **old**
   threshold and the new one. A key removed from a role by a newer root is rejected everywhere,
   including for metadata that key signed earlier but that is newer than the removal.
   A withdrawn release is marked in targets as `withdrawn`; the client will not start it, and
   if it is the installed one the console shows a security banner and the next release is offered
   immediately, ignoring rings (not windows).
6. **Offline bundle.** One file: the root chain from the oldest root any supported install can
   hold, snapshot, targets, timestamp *signed with a longer expiry for the bundle* (14 days,
   proposed), the artefacts, SBOM and provenance. A fully offline install is therefore exposed to
   a freeze of up to the bundle's timestamp life — an honest, documented residual; rollback
   protection is unaffected.
7. **The server never signs code (rule 7).** The server may *distribute* verified artefacts to
   connectors and agents; they run the same verifier with the root pinned in *their* installer and
   refuse anything not rooted in the release root, including artefacts signed by the server's own
   key.
8. **CI-only builds (rule 5).** Release artefacts come only from the CI release job from one commit,
   each with a CycloneDX SBOM and build provenance; Authenticode for MSI and binaries, container
   signatures for OCI images. A local build has no path to the signing role.

## 4. Couriers (answers TM-Q11, part 1 and 2)

| | Online courier | Offline courier |
| --- | --- | --- |
| Fetch | HTTPS GET of static files from the release host or a customer-configured mirror (proxy supported) | Admin uploads the bundle file in the console or places it in a watched import directory |
| Trust placed in the transport | None. A mirror or CDN is untrusted by design | None |
| Verify and apply | Identical code path to the other courier (ADR-0002 rule 7, P5) | Identical |
| Customer-run mirror | Supported: the mirror serves the same static files | n/a |

**Courier telemetry (TM-TB10-T8).** Default: no install identifier, no tenant, no directory data.
The only data leaving is what an HTTPS GET of public static files inherently carries: source IP
and a User-Agent `activediq-courier/<courier-version> (<profile>; <arch>)`. No cookies, no
per-install URL. Opt-in (off by default, platform setting, audited) reports only the update
result code and version pair to improve rollback detection. The console shows the last request
the courier made, verbatim. The mirror setting and "disable online courier" are platform settings;
disabling never disables the offline courier.

## 5. OCI apply without the Docker socket (answers TM-Q11, part 3)

Requirement (TM-TB10-T9): **no container of the product, including the updater, mounts the Docker
or containerd socket, runs privileged, or holds a capability that grants control of the container
runtime.** Required properties of whatever mechanism `solution-architect` chooses in the update
ADR:
1. The `server` container can only *stage*: it downloads, verifies and writes the verified
   release to a spool volume. It cannot start, stop or replace containers.
2. Applying is done by a small **host-side applier** outside containers (a systemd unit or
   equivalent installed with the Compose file, running under the customer's runtime) that re-runs
   the same verifier over the spool and references images **by digest** from the manifest. It does
   not trust the server's say-so (consistent with rule 7).
3. The applier performs node-by-node replacement, health check and rollback (§6) and writes its
   outcome back to the spool for the console and audit.
4. Where the customer's runtime cannot run a host-side applier (e.g. managed container platform),
   the console shows the verified, staged release with the exact digest list and the product
   goes to "ready, awaiting your orchestrator" — never silently unupdated. `[OPEN → ADR]` whether
   v1 supports a Kubernetes path.

## 6. Customer control, staging and rollback

- **Rings (platform setting).** `early` or `standard` channel, plus a deferral of 0–30 days after
  release. Default: `standard`, 7 days (proposed). Security releases flagged in targets bypass
  the deferral but still honour the window.
- **Window.** Day-of-week and time range, plus "apply now". Default: automatic apply in a window
  the installer asks for once; with no window set, the update stays staged and the console asks.
- **Pinning.** Hold at the committed version up to 90 days (proposed), with a banner while a
  security release is available; verification of timestamp continues while pinned.
- **DC-resident components (M3)** never auto-update unless the customer explicitly approves per
  component; each has a tested rollback (SB checklist G, TM §10 rule 6).
- **Under HA.** Nodes update one at a time behind the lease (blueprint flow 6; migrations are
  expand-only). A node counts as healthy only after its health check passes; users see no outage.
  If any node fails its check, the run stops, **every node updated in this run is rolled back**,
  and the release is marked `held` locally, not retried automatically.
- **Single node.** Stage → short restart → health check → rollback on failure. Expected downtime
  is stated in the console before the window.
- **Retention.** The previously committed build stays on disk until the next release commits.

## 7. Platform matrix

| Platform / component | Online | Offline | Apply | v1 |
| --- | --- | --- | --- | --- |
| Server `windows` — WS2019, 2022, 2025 x64 (Desktop and Core) | Yes | Yes | Signed MSI upgrade by the product's service-side updater | Yes |
| Server `linux-oci` — amd64, arm64 | Yes | Yes | Host-side applier (§5), digests | Yes |
| Embedded connector | with server | with server | with server | Yes |
| Remote connector (Windows or Linux host) | via server or direct | bundle | Same verifier, root pinned in its installer | Yes (M2 if the remote transport ships) |
| Edge / SSPR edge | — | — | — | M4 |
| DC agent, file-server agent | — | — | explicit approval, per §6 | M3 |
| On-prem AD (all functional levels), Entra ID, hybrid | Not relevant to the mechanism: the update path never touches the directory | | | — |
| SaaS | We run rings; same verifier and channel | n/a | n/a | Not in v1 |

Blank cells are decisions: the server is never installed on a DC (ADR-0002 rule 9), so no
update ever executes on a DC in v1.

## 8. Security and audit

- No directory privilege is needed. The updater runs with the least rights its host requires; it
  may not hold a directory credential (`connector` role only).
- Audit events (TM-TB10-T7), each with actor (`system:updater` or the human), version pair,
  signer key IDs, hashes, courier, ring, window: `update.available`, `update.staged`,
  `update.verified`, `update.refused` (with reason: tamper, rollback, freeze, revoked_key,
  unsigned_by_root, withdrawn), `update.applied`, `update.rolled_back`, `update.held`,
  `update.pinned`, `settings.update_changed` (step-up required, TM §7.4).
- `security-architect` focus: root threshold and ceremony; HSM signing of targets in CI;
  host-side persistence of the rollback floor; clock handling; the applier's trust boundary;
  residual TM-R6 (a build-system compromise signs legitimately).

## 9. Acceptance criteria

Verifiable by `qa-verifier`; the first block is the TM-F-UPDATE matrix and must pass for **both**
couriers (AC-1 to AC-8 are each run twice).

| # | Given / When / Then | Maps to |
| --- | --- | --- |
| AC-1 | Given a release whose artefact has one byte changed, When either courier fetches it, Then the update is refused before any extraction, nothing exists outside quarantine, and `update.refused` reason `tamper` is audited | Rule 1 |
| AC-2 | Given a manifest with a modified hash or length, When verified, Then it is refused (`tamper`); an artefact longer than its signed length is aborted mid-stream | Rule 1 |
| AC-3 | Given metadata signed by a key removed by a later root, When verified, Then it is refused (`revoked_key`) | Rules 1, 4 |
| AC-4 | Given the install has committed 1.6, When an older signed release (1.5) or older metadata is offered, Then it is refused (`rollback`), including after the database is restored from a backup taken before 1.6 | Rule 2 |
| AC-5 | Given an expired timestamp or snapshot, When the courier runs, Then no new update starts, the console shows "stale since …", and the product keeps serving; and a system clock set earlier than the last verified signing time is refused | Rule 3 |
| AC-6 | Given a new root signed by the old threshold, When verified, Then it is accepted and the next release signed by the new keys installs; a root signed by fewer than the threshold is refused | TM-F-UPDATE rotation case |
| AC-7 | Given an artefact signed only by the server's own key, When a connector or agent is asked to install it, Then it refuses (`unsigned_by_root`) | Rule 7 |
| AC-8 | Given the same CI release, When delivered online and as an offline bundle in a `--network none` container, Then both end at the same committed version with identical hashes through the same verifier code path (a test asserts one verifier package, no second implementation) | Rule 4, P5 |
| AC-9 | Given a successful CI release, When inspected, Then it has a CycloneDX SBOM, provenance, Authenticode (Windows) and container signatures, and a build not from CI cannot obtain a signing-role signature | Rule 5 |
| AC-10 | Given a 3-node HA install, When an update applies, Then nodes update one at a time, health is continuous for a probe user, and with node 2 deliberately failing its check all updated nodes roll back, the release is `held`, and the audit shows the sequence | Rule 6, ADM-210 |
| AC-11 | Given a single node and a deliberately bad release, When applied, Then the health check fails and the previous build is running again within a stated time (proposed ≤ 5 min), with data intact | E2 |
| AC-12 | Given a window of Sat 02:00–04:00, When a standard release becomes eligible at Mon 10:00, Then it is applied only inside the window; given a security-flagged release, Then the deferral is skipped but the window still holds | Rule 6 |
| AC-13 | Given a pin, When a security release appears, Then the banner shows and nothing applies; the pin expires after its limit | Rule 6 |
| AC-14 | Given the online courier running, When its traffic is captured, Then the only requests are GETs of the documented static URLs with the documented User-Agent, no install identifier, no cookie; opt-in telemetry is off by default and, when on, sends only the documented fields | TM-TB10-T8 |
| AC-15 | Given the Linux compose file and every container's runtime config, When scanned in CI, Then none mounts a Docker or containerd socket, runs privileged or adds a runtime-control capability; and an update still applies | TM-TB10-T9 |
| AC-16 | Given the applier is handed a spool the server tampered with, When it runs, Then it re-verifies and refuses; images are referenced by digest only | §5 |
| AC-17 | Given a DC-resident component (M3 test double), When a release is available, Then nothing applies until an admin approves it for that component | Rule 6 |
| AC-18 | Given no network and a bundle whose timestamp expired, When imported, Then it is refused with the freeze message and the age shown | Rule 3, §3.6 |
| AC-19 | Given a bundle of the largest planned size, When imported, Then verification streams (memory stays bounded) and a failed import leaves no partial state | Large case |
| AC-20 | Given update settings changed, Then the change needs step-up and is audited with before/after | §8 |

## 10. Experience target

Targets, to be confirmed with `product-designer` (no ManageEngine timing measured — the benchmark
exists only for the top admin tasks): normal path **0 interactions**; set the window once in the
installer; approve an out-of-window security release in ≤ 2 clicks; offline import in ≤ 3 steps
(choose file → see signer, version, contents, expiry → Apply). The admin never has to compare
hashes by hand, restart a service, or find the right service pack. Shell banner "update ready"
(information-architecture doc) with the verified version and window.

## 11. Out of scope

Downgrade through the courier; a Kubernetes apply path (open); automatic update of the customer's
PostgreSQL; UEM; the SaaS release operations; HSM procurement (T-0140/T-0141 via the CEO).

## 12. Open questions

1. Root threshold 3-of-5 and ceremony — `security-architect` (T-0140).
2. Apply mechanism and Kubernetes — `solution-architect` ADR.
3. Whether the bundle timestamp window of 14 days suits air-gapped customers — discovery with the
   service manager's pilot accounts `[DISCOVERY]`.
4. No competitor measurements of ManageEngine upgrade duration exist in the matrix; if a "median
   upgrade time" claim (customer-voice §proof metrics) is wanted, `market-analyst` research is
   needed. Not a CEO question.

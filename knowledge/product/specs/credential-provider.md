---
title: "Spec: Windows credential provider (self-service reset at the logon screen) — native fields only, never blocks logon, pinned server"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: windows-engineer
author: windows-engineer
ticket: T-0147
epic: E-001
milestone: M4
parity: []
scope: proposed
sources_last_checked: 2026-10-28
---

# Credential provider (`native/credprov`)

Parity IDs for ADSelfService logon-screen reset are not looked up here `[TODO: product-manager to attach IDs from the parity matrix]`. Controls come from threat model §5.13 (TB13) and §12 (`knowledge/development/architecture/threat-model.md`), blueprint §13 and feasibility §2.6.

## 1. Purpose and non-goals

A user who forgot a password, or whose account is locked, starts the self-service reset (SSPR) flow from the Windows sign-in screen. The provider adds one tile; the user's normal sign-in path is unchanged.

Non-goals: no web content of any kind, no file/print/help dialogs, no new authentication path into Windows (the provider never produces a logon credential for a session; it only starts a reset against the SSPR API and then hands the user back to the system password tile), no smart-card or PLAP work in M4.

## 2. Hard rules (each is a testable control)

| # | Rule | Control / proof |
| --- | --- | --- |
| R1 | No embedded browser, no HTML, no `ShellExecute`, no common dialogs, no help or print. Every screen is native credential-provider fields (`CPFT_LARGE_TEXT`, `CPFT_EDIT_TEXT`, `CPFT_PASSWORD_TEXT`, `CPFT_SUBMIT_BUTTON`, `CPFT_COMMAND_LINK`). Links shown to the user are plain text, never clickable. | TM-TB13-T1; import scan (§8) |
| R2 | The server is trusted only by SPKI pin (§5). A server whose key is not in the pin set is refused before any user input leaves the machine. No pins configured = provider inert (no tile). | TM-TB13-T2; pin tests |
| R3 | The provider never blocks logon. Offline, server down, timeout, TLS failure, pin failure, malformed reply, internal exception: the SSPR tile shows a one-line message or hides, and the system password tile keeps working. No network call on the UI thread. Every probe has a 3 s deadline. | TM-TB13-T3; `logon` tests |
| R4 | Fails safe for the *machine*, not just the tile: a crash in the provider must not take LogonUI down. All entry points catch at the COM boundary (no C++/Rust exception or panic crosses an ABI boundary); a faulting provider is disabled by LogonUI after failure and the system providers remain (Microsoft: keep a system provider available, see §10). | fault tests §7 |
| R5 | Secrets: the new password and OTP live in `CPFT_PASSWORD_TEXT` buffers only; zeroed with `SecureZeroMemory` after the request is built and again after send; never logged, never written to disk. `CoTaskMemFree` the buffers LogonUI hands back per the `ICredentialProviderCredential` contract. | review + memory test |
| R6 | Cannot be used to bypass the lock screen: it returns no `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION` from `GetSerialization` for SSPR (always `CPGSR_NO_CREDENTIAL_NOT_FINISHED`/`NO_CREDENTIAL_FINISHED` with no auth package); a successful reset only shows "now sign in with your new password". | red-team test §7 |
| R7 | Accessibility: every field has a label, tab order is linear, no colour-only state, no timing-only prompts; works with Narrator. | lab check §7 |
| R8 | Least data: the provider sends a user-typed identifier and OTP/answers to the SSPR API and receives opaque tokens/outcomes. It holds no AD credentials, no connector secret, no signing key (blueprint §4: SSPR edge holds no AD credentials). | review |

## 3. Technology

Feasibility (`build-feasibility/ad-technical-feasibility.md` §2.6, table at line 379) recommends **Rust, fall back to C++ if the Phase-0 spike hits COM/LogonUI blockers within 2 weeks**. This spike could **not** attempt that on the factory host (no Windows toolchain, no Windows client VM; see §9), so the clock has not started. Recommendation unchanged: Rust with the `windows` crate (`#[implement]` for COM), x64 and ARM64 targets, `crt-static`, `panic = "abort"` plus `catch_unwind` at every `extern "system"` entry, Control Flow Guard and `/guard:ehcont` on. Microsoft's own sample is C++ ([Windows-classic-samples CredentialProvider](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider)), which is the fallback. Licences of `windows` crates to be checked against the licence register before adoption `[TODO: devops-engineer]`.

Interfaces: V2 provider — `ICredentialProvider`, `ICredentialProviderCredential2`, `ICredentialProviderCredentialEvents`; scenarios `CPUS_LOGON`, `CPUS_UNLOCK_WORKSTATION`, `CPUS_CHANGE_PASSWORD` shown, `CPUS_CREDUI` filtered out (`SetUsageScenario` returns `E_NOTIMPL`) ([usage scenarios](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/ne-credentialprovider-credential_provider_usage_scenario)). Background network work runs on a worker thread and reports to the UI through `ICredentialProviderCredentialEvents` (not by blocking `Advise`/`SetSelected`) — see [credential providers in Windows](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows).

## 4. User flow

1. Tile "Reset or unlock my password" is added next to the system tiles (not replacing them).
2. On first display a worker probes the server (pinned TLS, §5, ≤ 3 s). Result drives the tile text: ready, "Reset unavailable — can't reach your organisation's server" (offline), or "Reset unavailable" with an event-log entry (pin refused). Pin refusal never says why on screen (no oracle).
3. Ready: user enters username → server sends the OTP/verification per the SSPR policy (ENH-09 spec, `enh-09-otp-and-totp-enrolment.md`) → user enters code → new password twice → server sets the password with the SSPR service identity → "Done. Sign in with your new password."
4. Cancel/Escape at any step returns to the system tiles. No step has a timeout that logs the user out or locks the console.

Reset over VPN: the SSPR API must be reachable *at the logon screen*, before any VPN user session exists. Machine-tunnel/Always-On VPN or a public edge (`cmd/edge`, blueprint §13) is required; with neither, the flow is "offline" (R3). Customer-facing guidance is for docs-writer.

## 5. Server trust: SPKI pinning

- Pin set = 1–4 SHA-256 hashes of the DER `SubjectPublicKeyInfo` of a key the SSPR/edge endpoint presents (leaf or issuing key). The set always contains a **backup key** that is not yet deployed on the server, so rotation never strands endpoints (reference implementation: `garage/credprov-spike/pin`).
- Set and server URL are installed by the MSI (properties) or GPO into `HKLM\SOFTWARE\Policies\skenzeriq\activeDIQ\CredProv`, readable by Users, writable by Administrators/SYSTEM only (ACL set through the typed security-descriptor primitive, `safe-primitives-security-descriptor.md`, never string SDDL). A pin set changes only through an Administrator-level write; the SSPR server cannot push one (a compromised server must not be able to re-pin endpoints) `[DECISION proposed — security-architect to confirm]`.
- TLS 1.3 only; system root store, hostnames and revocation are not consulted (pin replaces chain trust). The client is the Windows stack (Schannel via WinHTTP) or `rustls` `[OPEN: pick one; Schannel keeps FIPS/policy behaviour, rustls keeps one TLS implementation across platforms]`; neither pulls in a browser engine.
- Client authentication: endpoints hold no device certificate (R8). User authentication is the OTP/answers carried inside the request. Blueprint §13 says "pinned TLS" for this link, not mTLS. `[OPEN → security-architect: confirm no device identity, or add a per-device enrolment — that is a new component]`.
- Mismatch = refuse, log event, send nothing (not even the username).

## 6. Offline and failure behaviour

Every failure maps to one of four outcomes — `Ready`, `Offline`, `ServerRefused`, `Disabled` — and **none of them is "block logon"**; the type has no such value (`garage/credprov-spike/logon`). TLS < 1.3, DNS failure, connection refused, timeout, alerts, bad certificate and a malformed or oversized reply all land in `Offline` or `ServerRefused`. This is not a fail-open/fail-closed customer risk decision (that applies to the password filter, §16.2): the provider takes no authorization decision, so nothing here needs a CEO call.

## 7. Windows-lab proof (TM-F-CREDPROV) — owed, needs a client VM

Lab note: the lab today is Proxmox VM 119 with `dc1` only (`knowledge/development/runbooks/windows-lab.md` §10, T-0337). A **domain-joined Windows 11 client** (and Windows 10 22H2, and ARM64 for the ARM64 build) is also needed; none exists. Platform matrix to test: Windows 11 23H2/24H2 x64, Windows 11 ARM64, Windows 10 22H2 x64 (Windows 10 support status to be checked against the support matrix before committing to it `[UNVERIFIED]`). Servers (RDP/NLA sessions on Windows Server) are out of scope for M4 unless the product manager adds them.

Acceptance (T-0147 AC1 and the proof) as lab procedures:

| ID | Procedure | Pass |
| --- | --- | --- |
| L1 | Install MSI on the client with pin set = SSPR test server's key. Open sign-in screen. | Tile appears; probe `Ready`. |
| L2 | Stop the test server (or sever network). Lock, then sign in with the system password tile. | Sign-in succeeds; tile reads "unavailable"; ≤ 3 s of added delay; no UI hang. |
| L3 | Replace server cert with a different key (pin unmatched); try the tile; capture traffic. | Tile disabled, event logged, **no application bytes** after the TLS handshake fails; normal logon works. |
| L4 | Kill LogonUI-hosted provider (inject fault: access violation in a worker; then in `GetFieldDescriptorCount`). | LogonUI survives or restarts; system tiles available. |
| L5 | Corrupt/remove the registry config (no pins; malformed URL; oversize value). | Provider inert, no crash. |
| L6 | Import scan of the shipped DLL (§8) and of every DLL it loads at runtime (Process Monitor module list on the sign-in screen). | No denied module is present or loaded. |
| L7 | Red-team: from the tile, try to reach a file dialog, help, print, a link, an on-screen keyboard escape to `cmd`; attempt `GetSerialization` abuse. | None reachable; no credential serialized. |
| L8 | Narrator walk-through; tab order. | Every field announced. |

## 8. Import scan (what the spike covers)

`garage/credprov-spike/importscan` reads the PE import table (`debug/pe`) and fails on web-rendering and shell-dialog DLLs: `ieframe`, `mshtml`, `shdocvw`, `webview2loader`, `msedgewebview2`, `urlmon`, `wininet`, `comdlg32`, `shell32`, `shlwapi`, `windows.ui.xaml`, `winspool.drv`, `xpsprint`, `hhctrl.ocx`, `htmlhelp`, `cef`/`libcef`, and `api-ms-win-shell-*` api-sets. A non-PE input is an error, never a pass. Limits to document honestly: `ImportedLibraries` lists the normal import table; **delay-load and runtime `LoadLibrary`/`GetProcAddress` imports are not covered**, so the production check also (a) bans `LoadLibrary*` with non-constant arguments by lint, (b) scans delay-load tables, and (c) is complemented by L6's runtime module list. `shell32` is on the deny list because `SHGetKnownFolderPath` and friends are avoidable; if a legitimate need appears it is an explicit, reviewed exception, not a silent removal.

Spike result on this host: `go test ./...` in `garage/credprov-spike` passes (pinned accept, unpinned refuse, backup pin, server down → `Offline` within the deadline, hang bounded, no-pin inert, TLS 1.2 server not `Ready`, real Windows PE scanned clean, non-PE rejected). That is a conformance suite for the logic, **not lab evidence** for AC1.

## 9. What is not done (honest status)

- No COM/LogonUI code exists; no Windows client VM and no Windows toolchain on the factory host; therefore AC1 "lab output" is **not produced**. The first build on a Windows client is the real spike question (Rust vs C++, §3).
- The SSPR API does not exist yet (ENH-09/SSPR specs); the provider's wire contract (§4 step 3) is a placeholder until that OpenAPI exists `[OPEN]`.
- Signing: a credential provider DLL loaded by LogonUI should be Authenticode-signed with the release key (release pipeline: devops-engineer; certificate = CEO money action, `release-signing-key-custody.md`). It is not protected-process-light-gated like LSASS plug-ins, but customers with WDAC/App Control will require a signature `[UNVERIFIED — check WDAC behaviour for LogonUI-loaded COM servers in the lab]`.

## 10. Installer and lifecycle

MSI: silent, GPO/SCCM-deployable, per-machine, x64 and ARM64 packages. It registers the provider CLSID under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}` and the COM server under `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32` (`ThreadingModel=Apartment`), no custom action runs a script. Uninstall removes both keys and the DLL; a reboot is never forced (a loaded DLL is replaced at next logon-screen load, "reboot recommended" only). Rollback restores the previous DLL. Emergency removal: safe mode removes provider registration; the runbook documents it. Lab test: install → uninstall → registry and `Credential Providers` key diff is empty. Provider disable switch for operators: GPO "Exclude credential providers" can hide the tile ([policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-credentialproviders)) `[UNVERIFIED: confirm in lab that it also hides third-party providers]`.

## 11. Open questions and follow-ups

1. Rust vs C++ (§3) — decided by the first Windows build; windows-engineer.
2. TLS stack (§5) and whether endpoints get a device identity — security-architect.
3. SSPR wire contract — API/feature specs; blocks implementation, not this spec.
4. Windows client VM (Win 11 x64, domain-joined to `win.activediq.test`; later ARM64) — `ops` ticket for devops-engineer; any cost is a CEO action.
5. Parity IDs and the support matrix — product-manager.

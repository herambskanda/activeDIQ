---
title: "Runbook: Playwright tooling (screenshots, E2E, recording)"
date: 2026-10-02
updated: 2026-10-30
status: draft
owner: devops-engineer
ticket: T-0011
---

# Runbook: Playwright tooling

Pinned Playwright in `tools/playwright/` for QA evidence screenshots, design previews, E2E and demo
recording. Reference for flags and the spec format: `tools/playwright/README.md`.

## 1. Set up (once per machine, and after a Playwright version bump)

```bash
npm ci --prefix tools/playwright
npm --prefix tools/playwright run install-browsers    # or: make playwright-install
npm --prefix tools/playwright test                    # or: make playwright-test — all green means the machine is ready
```

Chromium downloads to the per-user cache (`~/Library/Caches/ms-playwright` on macOS,
`~/.cache/ms-playwright` on Linux), or to `$PLAYWRIGHT_BROWSERS_PATH` if set (use that on CI runners
to cache it). **Browsers are never committed**; the self-test fails if any browser file, `.webm`,
`node_modules` or Playwright output becomes tracked.

## 2. Everyday use

- **QA evidence:** `node tools/playwright/screenshot.mjs <url> factory/demos/evidence/<ticket>/<ac#>-<state>.png`
  (add `--dark`, `--width 1920 --height 1080` for the variants the testing-playbook asks for).
- **Demo take:** write a spec (README), then `node tools/playwright/record.mjs <spec.mjs> <out.webm> --base-url <demo-url>`.
  Raw takes belong under `factory/demos/<M>/video/raw/` (gitignored); credentials come from the
  environment, never from the spec.
- **E2E:** suites live in `web/e2e/`; run `npm --prefix tools/playwright run e2e`.

## 3. Upgrading Playwright

1. Check the new version's licence is still Apache-2.0 and update the register row
   (`knowledge/business/licensing/`).
2. `npm install --prefix tools/playwright --save-exact @playwright/test@<version>`, commit `package.json` and the lockfile.
3. `npm run install-browsers` (the browser build is tied to the Playwright version), then run the self-test.

## 4. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Chromium is not installed for this Playwright version` (exit 2) | Run `install-browsers`; the cache may hold only older builds |
| `answered HTTP 404` (exit 1) | The URL is wrong or the app is not up; `--allow-http-error` only to capture an error page on purpose |
| Video text looks smeared | VP8 at modest bitrate; see `.claude/skills/video-production/recording.md` |
| Download blocked on CI | Mirror the browser archive or pre-populate `PLAYWRIGHT_BROWSERS_PATH`; do not vendor it into git |

## 6. Console E2E against a real server: security-key sign-in (T-0855)

`web/e2e/webauthn-sign-in.spec.ts` drives the real console against a real lab-built server with a Chromium
virtual authenticator (DevTools `WebAuthn.addVirtualAuthenticator`: CTAP2, internal transport, user
verification on). No `page.route`. It is skipped unless `ADIQ_BASE_URL` is set.

**Prerequisite:** the console that is embedded must contain the security-key sign-in screen (T-0772). The
spec clicks "Use a security key"; a console without it fails at the first test.

```bash
npm ci --prefix web && npm --prefix web run build           # (boot-lab-server.sh runs `make web-embed` itself if internal/webui/dist is empty)
dir=$(lab/e2e/boot-lab-server.sh up)                # lab build + PostgreSQL 16 container + kek init + server on https://localhost:<port>
. "$dir/env"                                                # ADIQ_BASE_URL, ADIQ_E2E_SERVER_BIN, ADIQ_E2E_CA, ACTIVEDIQ_*
cd web && ADIQ_E2E_EVIDENCE_DIR=../factory/demos/evidence/<ticket> npx playwright test webauthn-sign-in
cd .. && lab/e2e/boot-lab-server.sh down "$dir"     # stops the server and removes the container
```

What the boot recipe does: builds `go build -tags lab ./cmd/server`; starts a throwaway PostgreSQL container
with the install's roles (`activediq_owner`, `activediq_app`, `activediq_catrust`) and applies `migrations/*.sql`
as the owner; `kek init` with a random passphrase file; starts the server with `ACTIVEDIQ_API_TLS_DIR` (a
per-install certificate) and `ACTIVEDIQ_PUBLIC_URL=https://localhost:<port>`, which is what mounts the
WebAuthn routes and fixes the relying party (`localhost`). Everything random lives under `$dir` and in the
container and dies with `down`.

How the spec seeds, with no registration ceremony yet (T-0573): per test it creates a fresh local account with
`account init-local` (password and TOTP confirmed through the binary's own prompts), generates an ES256 key
pair in Node, hands the private key to the virtual authenticator with `WebAuthn.addCredential`, and stores
the COSE public key with **`account add-passkey`**, which exists only in `-tags lab` builds
(`cmd/server/account_lab.go`, `internal/compose/server/labpasskey_lab.go`). `go test ./cmd/server -run
TestProductionBinaryHasNoPasskeySeeding` builds the server both ways and fails if the production binary has
the command or its symbol; the lab build is its control.

TLS stays verified. Chromium ignores `NODE_EXTRA_CA_CERTS`, so the spec passes
`--ignore-certificate-errors-spki-list=<sha256 of the server certificate's public key>` (from
`ADIQ_E2E_CA`): that one key is trusted and any other certificate still fails.

Sign-in codes: the spec uses the TOTP code for the **next** 30 s step. The server accepts one step either
side of now and refuses a step at or below the last accepted one (replay), and enrolment spends the current
step, so the next one is valid at once, with no sleep and no fake clock.

Run only this file (`npx playwright test webauthn-sign-in`): with `ADIQ_BASE_URL` set the fixture-based suites
in `web/e2e/` also run against the live server and will fail there.

| Symptom | Cause / fix |
| --- | --- |
| A test fails once with `net::ERR_NETWORK_CHANGED` in its trace, then passes on the single retry | Chromium aborts in-flight requests when the host's network interfaces change; on a shared Docker host every container start adds a veth. Environment, not product; the failure carries an `environment` annotation. No known Chromium switch turns it off (tried `--disable-features=NetworkChangeNotifier`, `--disable-background-networking`: no reliable effect) |
| `ERR_CERT_AUTHORITY_INVALID` at the first `goto` | `ADIQ_E2E_CA` is not set or points at a certificate that is not the server's |
| `init-local exited … before the setup key` | the server has not started once (it creates the tenant on first boot) or `ACTIVEDIQ_*` is not in the environment |
| The security-key test cannot find "Use a security key" | the embedded console predates T-0772 |

## 5. Known gaps

- No CI pipeline exists yet (T-0014/T-0015). When it does, add `npm ci` + `npm test` for this tool
  as a job with a cached `PLAYWRIGHT_BROWSERS_PATH`.
- Playwright's bundled ffmpeg (VP8 capture) is a build artefact fetched with the browser; it is not shipped.

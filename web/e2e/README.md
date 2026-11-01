# `e2e`: Playwright suites

End-to-end suites for the console, run from `web/` with `npm run e2e` (config: `web/playwright.config.ts`,
pinned Playwright in `web/package.json`; browsers from `make playwright-install`). Without
`ADIQ_BASE_URL` they build the console, serve it with `vite preview` and answer the API with
fixtures declared in the spec; with it they run against that server. Screenshots land in
`factory/demos/evidence/<ticket>/`.

- `user-search.spec.ts`: user search (T-0670): default, results, empty, loading, capped, error and retry, 403, refused characters, keyboard path, deep link and back/forward, axe check.
- `reports.spec.ts`: reports console (T-0966): `/`, type an ME name, Enter opens the report with results in 3 interactions and one run POST (AC-04); no `reports.run` (403) shows the no-access panel and search finds none (AC-42); loading skeleton; empty states (scope grants nothing, unsupported scope, no row matches); stale; failed and retry; expired; 100,000 rows windowed with server paging and sort; hidden service accounts; library no-match. Fixture API in the spec; the real server needs B5 (T-0960, T-1045). Screenshots in `factory/demos/evidence/T-0966/`.
- `sign-in.spec.ts`: console sign-in (T-0764): no session shows the sign-in screen, a wrong password gives the generic error, password plus code lands on the requested page; axe check.
- `live-user-search.spec.ts`: user search against a live lab server (T-0686). Skipped unless `ADIQ_BASE_URL`, `ADIQ_E2E_SESSION`, `ADIQ_E2E_USER_NAME` and `ADIQ_E2E_USER_SAM` are set. Build the server with the console (`make web-embed`, then `go build -tags lab ./cmd/server`), start it on a lab seed, mint a session through the sign-in API, then (TLS is verified: trust the lab certificate with `NODE_EXTRA_CA_CERTS=ca.pem`, or opt out on a lab with `ADIQ_E2E_INSECURE=1`) `ADIQ_BASE_URL=https://127.0.0.1:8080 … npm run e2e`.
- `webauthn-sign-in.spec.ts`: security-key sign-in against a REAL lab-built server with a Chromium virtual authenticator (T-0855): key signs in (session cookie, `GET /auth/csrf` 200), a valid TOTP code is refused for a key-enrolled account (with a no-key control proving the code is good), an empty authenticator, a failed user verification and a right-ID/wrong-key assertion are all refused with no session. Skipped unless `ADIQ_BASE_URL` is set; boot recipe in `knowledge/development/runbooks/playwright-tooling.md` §6 (`support/boot-lab-server.sh`, `support/lab-server.ts`). Run it by name: with `ADIQ_BASE_URL` set the fixture suites above would also hit the live server.

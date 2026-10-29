# `e2e`: Playwright suites

End-to-end suites for the console, run from `web/` with `npm run e2e` (config: `web/playwright.config.ts`,
pinned Playwright in `web/package.json`; browsers from `make playwright-install`). Without
`ADIQ_BASE_URL` they build the console, serve it with `vite preview` and answer the API with
fixtures declared in the spec; with it they run against that server. Screenshots land in
`factory/demos/evidence/<ticket>/`.

- `user-search.spec.ts`: user search (T-0670): default, results, empty, loading, capped, error and retry, 403, refused characters, keyboard path, deep link and back/forward, axe check.
- `live-user-search.spec.ts`: user search against a live lab server (T-0686). Skipped unless `ADIQ_BASE_URL`, `ADIQ_E2E_SESSION`, `ADIQ_E2E_USER_NAME` and `ADIQ_E2E_USER_SAM` are set. Build the server with the console (`make web-embed`, then `go build -tags lab ./cmd/server`), start it on a lab seed, mint a session through the sign-in API, then (TLS is verified: trust the lab certificate with `NODE_EXTRA_CA_CERTS=ca.pem`, or opt out on a lab with `ADIQ_E2E_INSECURE=1`) `ADIQ_BASE_URL=https://127.0.0.1:8080 … npm run e2e`.

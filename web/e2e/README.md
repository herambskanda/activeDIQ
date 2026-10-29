# `e2e`: Playwright suites

End-to-end suites for the console, run from `web/` with `npm run e2e` (config: `web/playwright.config.ts`,
pinned Playwright in `web/package.json`; browsers from `make playwright-install`). Without
`ADIQ_BASE_URL` they build the console, serve it with `vite preview` and answer the API with
fixtures declared in the spec; with it they run against that server. Screenshots land in
`factory/demos/evidence/<ticket>/`.

- `user-search.spec.ts`: user search (T-0670): default, results, empty, loading, capped, error and retry, 403, refused characters, keyboard path, deep link and back/forward, axe check.

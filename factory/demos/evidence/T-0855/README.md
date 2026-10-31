# T-0855 evidence: WebAuthn console sign-in with a virtual authenticator on the real server

Build: factory/T-0855 on main 9fe045caf, plus the T-0772 console (merged in a scratch tree to build `internal/webui/dist`;
T-0772 is not on main yet, it depends on this ticket). Server: `go build -tags lab ./cmd/server`, PostgreSQL 16, passphrase KEK,
per-install TLS certificate, `ACTIVEDIQ_PUBLIC_URL=https://localhost:<port>`; booted by `web/e2e/support/boot-lab-server.sh up`.

| AC | Evidence |
| --- | --- |
| 1 key signs in, session cookie, `GET /auth/csrf` 200 | `run-green.txt` test 1; `signed-in-with-security-key.png` |
| 2 valid TOTP refused for a key-enrolled account, no cookie | `run-green.txt` tests 2 and 3 (control: same code generator accepted without a key); `totp-refused-for-key-account.png`; the test asserts the verify response is 401, the sign-in-failed message, and `GET /auth/csrf` 401 |
| 3 no credential / UV fails / wrong key refused, no session | `run-green.txt` tests 4, 5, 6 |
| 4 production build has no seeding command | `go-test-production-binary.txt` (pass); `go-test-production-binary-mutant.txt` (fails when the `lab` tag is removed) |
| 5 skipped without `ADIQ_BASE_URL`; runbook | `run-skipped-without-base-url.txt`; runbook diff `playwright-tooling.md` §6 |

Deliberately broken run: `run-mutant-passkey-lock-off.txt` — with the T-0852 passkey lock disabled in a scratch build, test 2 fails (verify answers 204, a session is minted for a TOTP-only sign-in).

Traces (`--trace on`) were produced for every test but are not committed: they hold the throwaway accounts' passwords and session cookies in request headers/bodies.

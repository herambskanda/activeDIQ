# T-0772 QA run — build 1b9817df9 (ticket HEAD) + T-0855 harness merged in a scratch worktree (not in the ticket tree)

Setup (my own): `web` built from HEAD, embedded in `go build -tags lab ./cmd/server` (main 9fe045caf already has T-0852/T-0853/T-0854),
fresh PostgreSQL 16 container, passphrase KEK, per-install TLS, `ACTIVEDIQ_PUBLIC_URL=https://localhost:<port>` (mounts the WebAuthn routes).
Accounts via the binary's own `account init-local` + lab-only `account add-passkey`. Chromium CDP virtual authenticator (CTAP2, UV on).
T-0855 (suite and `account add-passkey`) is "done" but its commit 572be8178 is only on branch factory/T-0855, NOT on main — noted, not blocking this ticket.
Scratch spec of mine: `qa-t0772.spec.ts.txt` (K1–K11). Screenshots `qa-*.png`.

## Earlier rejection items (T-1053)
1. TOTP refused for a key-enrolled account: PASS. Engineer-independent run K3/K4: valid next-step TOTP code for an account with a registered key ->
   401 problem "Sign-in failed", no Set-Cookie, no session cookie, UI shows "Sign-in failed. Check the details and try again." and resets to password step
   (`qa-07-totp-refused-key-account.png`). Control: same code generator accepted for an account WITHOUT a key (T-0855 test 3, ran green 6/6 on this server).
2. Password -> challenge -> verify with the virtual authenticator: PASS. 6/6 of `webauthn-sign-in.spec.ts` green on my server, plus my K1 (keyboard-only).

## AC1 — "user with a registered WebAuthn key: the key is required as second factor and the result is verified server-side": PASS
- Key signs in (K1, T-0855 #1): password 204+pending cookie -> challenge 200 (allowCredentials = enrolled id, rpId localhost, UV required) -> real ES256 assertion
  -> verify 204 -> `__Host-adiq_session` (HttpOnly, Secure, SameSite=Strict, Path=/) -> `GET /auth/csrf` 200 -> console loads; authenticator signCount 0->1.
- Server-side verification is the only gate: authenticator holding the right credential id with a DIFFERENT private key -> UI posts the assertion, server answers 401, no session.
  Empty authenticator -> "The security key was not used…", nothing sent to verify, no session. UV-failing authenticator -> same, signCount stays 0.
- TOTP cannot substitute (above). Pending-less calls (fresh client, K10): challenge/verify/totp -> 401 "Sign-in failed", no Set-Cookie.
- Garbage/metachar body to verify (`*)(cn=*`, `<script>`) -> 400 pattern validation (K4). Unauthenticated /auth/csrf and /directory/users -> 401.
- Screenshots: `qa-05-signed-in-landing.png`, `signed-in-with-security-key.png`.

## Controls on the changed screen (every one clicked/keyed)
- "Continue" (click + Enter): works; wrong pw / hostile usernames -> one generic panel. `*)(cn=*`, `o'brien"; DROP`, `<img onerror>` -> 401 generic; no dialog fired, no <img> in DOM (K5). 300-char Unicode name -> 400 "The request is invalid".
- "Sign in" (TOTP): works for no-key account (T-0855 #3); refused for key account.
- "Use a security key": click and keyboard (Tab Tab Tab, Enter) both sign in (K1); double-click sends ONE challenge request (K6); button disabled while busy.
  No-key account clicking it -> challenge 401 -> "Sign-in failed…" and back to password step (K2, `qa-06`). Prompt unusable -> `qa-09-key-not-used.png`; field and button stay, retry possible.
- Error states: challenge 503 -> "The server could not complete the sign-in. Try again."; network refused -> "Can't reach the server…" (K7); REAL server stopped after the password step ->
  "Can't reach the server. Check your connection, then try again.", no session (K11, `qa-15-server-down.png`). Refresh at code step -> password step (pending state not trusted client-side) (K9).
- `next=//evil.example.org/x` -> after key sign-in landed on own origin /directory/users (K9).
- No numbers/tables on this screen; landing page after sign-in shows the empty prompt "Type a name…" (no sample rows). No hardcoded data in the diff (web/src/app/{session,sign-in}.tsx).

## A11y / layout
- axe (wcag2a, 2aa, 21aa, 22aa) on password step, code step, and error panel, light AND dark: 0 violations (6 scans). 320/1024/1920 px: no horizontal overflow (`qa-14-width-*.png`). Focus ring visible on all controls.
- Keyboard-only sign-in with the key succeeds. Focus order: Account name -> Password -> (Enter) -> Authenticator code -> Sign in -> Use a security key.

## Findings (not rejects)
- Pre-existing (T-0764 code, unchanged by this diff): after "Continue" focus lands on <body>, not the code field (setTimeout(0) focus runs before React renders it). Filed as a bug ticket.
- Design note: "Sign in" and "Use a security key" buttons touch with no gap (`qa-02`); the code field is still shown to key-enrolled accounts (TOTP always refused for them) — product-designer's call.

## Not verified
- Real hardware key / platform authenticators other than Chromium's virtual one (spec's platform matrix: Chromium only exercised). Firefox/Safari not run.
- Registration ceremony (T-0573) — keys seeded by the lab-only command. Directory list after sign-in (no lab DC wired to this server; T-0783 scope).
- Restricted-role/permission-denied: N/A, this screen is pre-authentication.

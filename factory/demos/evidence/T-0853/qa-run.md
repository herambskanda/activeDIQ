# T-0853 QA run, build 1f81220fa (own run, real `cmd/server` binary, PG16 container, passphrase KEK, TLS 127.0.0.1:18853)
Setup: migrations 0001-0056 as activediq_owner; `server kek init`; first boot; `account init-local --username qa.admin2` (TOTP confirmed);
one ES256 software-authenticator credential inserted as public key into authn_webauthn_credentials (registration is T-0573, out of scope).
Independent assertion generator (stdlib Go, written in scratch, not the engineer's test helper). Raw output: webauthn-on-curl.txt.

AC1 PASS  ACTIVEDIQ_PUBLIC_URL=https://diq.example.com: password step 204 + pending cookie; POST webauthn/challenge -> 200
          {"allowCredentials":[{"id":"XVjml_2N8aFZ9MuvuPwZWzks7ZnhhVrOmgfTqsYOYq8"...}],"rpId":"diq.example.com","userVerification":"required"}; id == enrolled credential.
AC2 PASS  valid assertion (origin https://diq.example.com) -> 204; Set-Cookie __Host-adiq_session (HttpOnly; Secure; SameSite=Strict; Max-Age=28799); __Host-adiq_pending cleared (Max-Age=0).
          authn_sessions.methods = {password,webauthn} (TOTP sign-in session = {password,totp}). Session reaches API (GET /directory/users 503 no-connection on non-lab build; 401 without cookie / with pending cookie).
AC3 PASS  each -> 401 problem "Sign-in failed" /problems/sign-in-failed, no Set-Cookie, identical body shape: tampered signature; origin https://evil.example.org; wrong rpIdHash (example.com);
          replay of the accepted assertion; no pending cookie. Failed attempts created no session rows (2 sessions total). Garbage/metachar fields (`*)(cn=*`, `<script>`) -> 400 pattern validation.
AC4 PASS  PUBLIC_URL unset: boot log has exactly one "WebAuthn sign-in is off: ACTIVEDIQ_PUBLIC_URL is not set" (and none when set); challenge and verify -> 501 problem+json
          (with and without pending cookie); TOTP verify -> 204 + session (unchanged). Config at boot: PUBLIC_URL alone accepted; ATTEST_CLIENT_ID alone -> "requires ACTIVEDIQ_PUBLIC_URL";
          http://, path, userinfo, query origins -> "must be an https origin". Extra: https://diq.example.com:8443 -> rpId diq.example.com (no port), assertion for the :8443 origin accepted.
AC5 PASS  go test -count=1 ./internal/compose/...: TestLocalAccountSignInThroughTheMountedRoutes and TestSignInBurstIsCappedAndHoldsNoConnection pass pg16+pg18, plus all T-0853 pg/config/unit tests.
AC6 PASS  git diff main...HEAD -- knowledge/: blueprint.md T-0853 paragraph and api-pipeline.md compose/server row name authn.WebAuthnFactor and ACTIVEDIQ_PUBLIC_URL.
UI: no screen changed (API only). Not verified: a real browser/authenticator (T-0573 registration + Playwright e2e are separate tickets); Windows N/A.
Known, tracked elsewhere: T-0861 (non-canonical public URLs fail closed), TOTP offered to key-enrolled accounts (own ticket).

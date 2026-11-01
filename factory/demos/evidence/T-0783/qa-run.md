# T-0783 QA run, build fabf2fe3e (own run, real binary, PG16 container, passphrase KEK, TLS on 127.0.0.1:18443)
Setup: migrations 0001-0056 as activediq_owner; `diq kek init`; `diq` boot; `diq account init-local --username qa.admin` (TOTP confirmed).
- POST /api/v1/auth/break-glass/password wrong pw -> 401 problem+json "Sign-in failed", no Set-Cookie
- same, right pw -> 204, Set-Cookie __Host-adiq_pending (HttpOnly; Secure; SameSite=Strict; Max-Age=300), no session
- POST /auth/second-factor/totp/verify with pending cookie + valid code -> 204, Set-Cookie __Host-adiq_session (HttpOnly Secure Strict), pending cleared
- totp wrong code -> 401; totp without pending cookie -> 401
- username `*)(cn=*`, `<script>`, `a'b` -> 401 (same as wrong password); empty username -> 400
- GET /api/v1/directory/users with the session cookie -> **404 not-found**. Boot log: "api tag not mounted: no module contributes it tag=directory".
- Cause: T-0680 (searchDirectoryUsers) is not on main nor this branch. Scratch merge of factory/T-0680 into this branch conflicts in
  internal/compose/server/console.go and server.go (scratch worktree discarded, no product code touched).
- Tests re-run by me: TestLocalAccountSignInThroughTheMountedRoutes, TestSignInBurstIsCappedAndHoldsNoConnection, TestInitLocalAttributionAndFailedConfirm PASS pg16+pg18.

## Re-queue check (second QA run)
- main (83802aaa4) still has only the searchDirectoryUsers contract + generated stubs (069b4bebe); no handler. `git merge-base --is-ancestor dfb937649 main` -> NOT on main.
- T-0812 is marked done but its merge commit dfb937649 exists only on branch factory/T-0812 (`git branch --contains` -> factory/T-0812 only).
- Scratch merge of main into T-0783 is clean and builds, but still has no directory handler, so GET /directory/users would remain 404.

## Third QA run (2026-10-30) — branch fabf2fe3e + main 8a32eeb35 (T-0680 handler present), scratch merge
Setup: scratch worktree of T-0783 with `git merge main`; conflicts in internal/compose/server/console.go and server.go (union resolution: both
sides kept, no logic change); builds. Lab build (-tags lab) + Samba lab (make lab-up tier=standard, 5017 users) + PG16 (owner/app roles, migrations 0001-0056),
`kek init`, boot (lab connection active), `account init-local --username qa.admin2` (TOTP confirmed).
- POST /auth/break-glass/password -> 204 + __Host-adiq_pending; POST /auth/second-factor/totp/verify -> 204 + __Host-adiq_session (HttpOnly Secure Strict).
  (Reusing the confirm-step TOTP code within the same 30 s step -> 401: replay protection, fine.)
- unauthenticated GET /directory/users -> 401. LDAP/HTML-metachar usernames -> 401 (same as wrong password). Metachar in q -> 400 (pattern).
- GET /api/v1/directory/users?q=ab with the session, NO lab connection (plain build): 503 problem "no active directory connection" -> session, authz (directory.read) and the real handler are reached.
- Same, lab build, merged exactly as main + T-0783 stand: **500 "Internal error"**; server log (debug-logged in scratch only): `client: read has no tenant in its context` (client.ErrReadTenant).
  Cause: server.go `buildDirectory(db, conns, src)` passes the TunnelSource `src`, not the lab-wrapped `csrc`, so the lab connector is never consulted; TunnelSource.Connector then needs
  authority.WithTenant on ctx, which an HTTP request context never carries (only the operation runner sets it).
- Scratch-only experiment: `buildDirectory(db, conns, csrc)` -> **200** with real rows from the Samba lab (e.g. svc-activediq, ada.bianchi; 3 items, limit honoured). So the session path (T-0783) works; the 200 is blocked by directory wiring.
- Not exercised: restricted role without directory.read (init-local only creates the directory.read holder); real fleet tunnel.

## Fourth QA run (2026-10-30) — branch 595a94f1d as committed (main already merged, csrc fix in server.go:168), no scratch changes
Setup: own Samba lab (make lab-up, standard tier, 5017 users), PG16 (owner/app roles, migrations 0001-0056), `go build -tags lab ./cmd/server`, `kek init` (passphrase),
lab connection active (LAB_LDAPS_PORT/LAB_SVC_PASSWORD/LAB_CA), `diq account init-local --username qa.admin` (TOTP confirmed), TLS on 127.0.0.1:18443.
**AC1 PASS.**
- POST /auth/break-glass/password (right pw) -> 204, `__Host-adiq_pending` (HttpOnly; Secure; SameSite=Strict; Max-Age=300)
- POST /auth/second-factor/totp/verify (valid code, next 30 s step) -> 204, `__Host-adiq_session` (HttpOnly; Secure; SameSite=Strict; Max-Age=28799), pending cleared
- GET /api/v1/directory/users?q=ab&limit=3 with that cookie -> **200**, 3 items from the lab (svc-activediq, ada.abara, ada.alvarez), each with objectGuid/samAccountName/UPN/enabled/hybrid.
- Number/field trace: ada.abara objectGUID de3b7600-f19d-4d6d-9f2b-9acd8637592f, UPN, displayName, userAccountControl 512 (enabled) all match `samba-tool user show` / `ldbsearch` on the DC. q=ada&limit=2 honours limit; limit=200 -> 400 `maximum`.
- Role without directory.read: all assignments set to `revoked` in PG -> same live session -> **403** /problems/forbidden; audit_event seq 34 `authz.permission.denied`; assignments restored -> 200.
Negative / security smoke:
- unauthenticated GET -> 401; wrong password, unknown user, `*)(cn=*`, `<script>alert(1)</script>`, `a'b` as username -> identical 401 "Sign-in failed", no Set-Cookie
- TOTP code reuse in the same step -> 401 (replay); pending cookie presented as session -> 401; tampered session cookie -> 401
- q=`*)(cn=*` and q=`<script>` -> 400 (pattern); q=`o'brien` -> 200 empty; q=zzzzqq -> 200 `{"items":[]}` (real empty state, no sample rows)
- DC stopped -> clean 503 problem "The directory is unavailable" (not 500).
Finding (outside this diff): after `docker start` of the DC, reads stay 503 until the server restarts (lab connector never re-dials; seen once unprovoked too). Filed T-0847 (P2, directory-engineer). Not a reject item.
UI: this ticket changes no screen (API/CLI only), so there are no controls to click; the sign-in screen is T-0764.
Not verified: real fleet-tunnel 200 (gated on T-0843); Windows DC (Samba only); a second local account with a deliberately narrower role (covered by revoking assignments instead).
Build 595a94f1d.

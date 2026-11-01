# T-0772 QA re-run — build b956fa2d8 (ticket HEAD after the main merge)

Reason: the dispatcher reopened the ticket after a merge of main; diff since my pass on 1b9817df9 touches only api/openapi/{modules/reports,shared/operation,shared/problems}.yaml and web/src/api/schema.gen.d.ts (no sign-in code). I rebuilt the stack anyway and re-ran live.
Setup: scratch worktree of HEAD + factory/T-0855 merged (T-0855 commit 572be8178 is still not on main), web build embedded, `go build -tags lab`, fresh PostgreSQL 16, T-0855 `boot-lab-server.sh up`, Chromium CDP virtual authenticator.

- T-0855 suite `webauthn-sign-in`: 5 passed + 1 flaky (passed on retry; the documented ERR_NETWORK_CHANGED environment flake from other containers starting on the shared host) = 6/6.
- My scratch spec (`qa-t0772.spec.ts.txt`, K1–K11): 11/11 pass on this build. Log: `qa-rerun-b956fa2d8-log.txt`.
  K1 keyboard-only key sign-in OK; K2 no-key account clicking the key button -> challenge 401, generic error, back to password; K3/K4 valid TOTP for key-enrolled account -> 401, no Set-Cookie;
  K5 hostile/Unicode usernames safe (no markup injected); K6 one challenge on double-click, unusable authenticator keeps the screen retryable; K7 503 and refused network messages;
  K8 axe light+dark 0 violations; K9 next=//evil not followed, refresh -> password step; K10 no pending cookie -> 401;
  K11 server killed after the password step -> "Can't reach the server…", no session.
- Same findings as before: T-1058 (focus lands on body after Continue, pre-existing; log line "code step focus after 500ms: BODY"), buttons touching (design note).

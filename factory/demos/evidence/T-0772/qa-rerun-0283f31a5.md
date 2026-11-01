# T-0772 QA re-run — build 0283f31a5 (ticket HEAD after the second main merge)

Sign-in code (web/src/app/{sign-in.tsx,session.ts,sign-in-webauthn.test.tsx}, web/e2e/sign-in.spec.ts) is byte-identical to b956fa2d8 (git diff empty). Re-ran live anyway.
Setup: ticket worktree itself (T-0855 harness is now on main), `web/e2e/support/boot-lab-server.sh up` -> real `go build -tags lab` server with the console embedded, fresh PostgreSQL 16, Chromium CDP virtual authenticator.
- T-0855 suite `webauthn-sign-in`: 6/6 pass (no flake this time): key signs in; valid TOTP refused for key-enrolled account (control: accepted without key); empty authenticator, UV failure, right-ID/wrong-key all refused, no session.
- My K1–K11 (qa-t0772.spec.ts.txt): 11/11 pass. K11 (server killed after password step) needs an external killer; first attempt without one timed out (harness, not product), re-run with the server killed mid-flow passed -> "Can't reach the server…", no session.
  Log: qa-rerun-0283f31a5-log.txt. axe 0 violations light+dark (password, code, error panel); no horizontal overflow at 320/1024/1920.
Scratch spec removed from the tree; git status clean. Server and PG container torn down.

# T-0724 QA evidence (build 4434011e6, qa-verifier, 2026-11-01)
AC1: `go run ./tools/fitness/builtmsi -require -glob 'dist/*.msi'` -> "dist/activediq-agent-0.0.1.msi: ok", exit 0 (sha256 f18d8104...23d).
     -require on non-matching glob -> "FAIL: no built MSI found (-require)", exit 1. Without -require -> "inactive", exit 0.
     release.yml publish job: download-artifact agent-msi -> builtmsi -require, before Publish. workflows-check mutations on release.yml copies
     (drop -require, rename artefact, top-level write, persist-credentials true) each exit 1 with the expected message; clean exits 0.
AC2: msidump -t of the real WiX MSI CustomAction.idt == pinned-actions.txt for all 8 rows (3106 x3, 3426 x2, 3170 x2, 3106 ConfigureService).
Extra: go test cmd/agentsetup, tools/fitness/builtmsi, tools/fitness/agenthost ok; GOOS=windows go vet ok; make workflows-check ok.
     ServiceRestart->ServiceReboot in a throwaway worktree fails TestRecoveryPolicyIsRestartOnly (service_windows.go:34).
NOT verified: build-msi on a real windows-2022 runner (needs a v* tag); osslsigncode step fails closed until D-0010 signing; WiX build on Windows not rerun by me (used existing dist MSI built on lab dc1). No UI in this ticket.

## Re-QA after merge of main (292cd2c68), qa-verifier, 2026-11-16
Own run: go test cmd/agentsetup, tools/fitness/builtmsi, tools/fitness/agenthost ok; GOOS=windows go vet cmd/agentsetup cmd/agent ok; make workflows-check ok; make fitness-agent-host PASS; merge-tree vs main 0 conflicts, no markers.
AC1: builtmsi -require -glob 'dist/*.msi' -> ok exit 0; non-matching glob -> "FAIL: no built MSI found (-require)" exit 1. release.yml/workflows-check unchanged by the merge.
AC2: msidump CustomAction table of dist MSI == pinned-actions.txt, 8 rows (3106/3106/3106/3426/3170/3106/3426/3170); Ids/targets also match the 8 CustomActions in Agent.wxs post-merge.
GAP: dist MSI is dated 2026-10-30, i.e. built BEFORE the merge: its ServiceControl Event=162 (no start-on-install), so Agent.wxs Start="install" and the -wx -sw1149 build are NOT exercised. No WiX/Windows here (only wixl); post-merge CustomAction Types derive from unchanged attributes in Agent.wxs. Also not verified: windows-2022 release job (needs v* tag), signing (T-1209).

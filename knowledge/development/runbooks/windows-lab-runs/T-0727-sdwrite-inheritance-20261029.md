---
title: T-0727 — TestWindowsLabSDWriteInheritance with strict VerifyAfter on WS2025
status: draft
---
# T-0727 run, 2026-10-29

Target: external Windows lab (Proxmox VM 119, WS2025) at 192.168.1.9:636, TLS name `dc1.win.activediq.test`, CA verified.
Command: `go test -count=1 -tags 'lab windowslab' -run TestWindowsLabSDWriteInheritance -v ./internal/connector/ad/`
(the same package `make lab-test-connector-windows` runs). Full output: `T-0727-sdwrite-inheritance-20261029.log.txt`.

## Result: PASS (0.72 s), every `verifyAfter` assertion accepted

| Step | VerifyAfter | DC re-ordered stored DACL |
| --- | --- | --- |
| explicit add (inherited marker kept) | accepted | yes — first diff at ACE 0 (planned explicit, stored inherited) |
| BlockKeepInherited (real DC output) | accepted | yes — first diff at ACE 0 (planned inherited ...-553, stored 05/…/S-1-5-32-554) |

Real BlockKeepInherited output: control 0x8c04 → 0x9c04 (PD set), n=58 ACEs unchanged in count, inherited ACEs
became explicit copies (flags 05/00, 05/02, 05/0a), and the DC re-sorted them; the design holds — VerifyAfter's
canonical-order comparison is not rejected by the real output. No revisit of the T-0627 design is needed.

Also observed: a DACL written without DI keeps the INHERITED t1 copy (1 inherited, 0 explicit);
RestoreInheritance leaves the earlier explicit t1 copy (count 1).

## Side finding
The whole-package `make lab-test-connector-windows` exits non-zero because `TestLabUnicodePwdVectors`
(Samba test, `unicodepwd_samba_lab_test.go`) needs `lab/.lab.env` and does not skip under `LAB_TARGET=windows`.
Unrelated to SD write; filed as a bug.

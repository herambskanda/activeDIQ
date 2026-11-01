# Windows lab first build (T-0337)

- Date: 2026-10-28. Host: Proxmox VM 119 (`win-server-2025`), DC1 at 192.168.1.9, snapshot `clean` taken. Built by hand via the guest agent (CEO; the two guest-script bugs it exposed are T-0496).
- Run: `WIN_LAB_MODE=external WIN_LAB_DC_ADDR=192.168.1.9 WIN_LAB_TLS_NAME=dc1.win.activediq.test make lab-test-connector-windows`
- Log: `connector-20261028T063547Z.log`. LDAPS to `dc1.win.activediq.test` with certificate verification on and the lab CA. `TestWindowsLabNoSideDialOnPlantedUNC`, `TestWindowsLabLDAPSBindAndRootDSE` and `TestWindowsLabRejectsWrongPasswordAndUntrustedCert` all PASS.
- Defect found by this run and fixed: the make target ran the whole `internal/connector/ad` package under the `lab` tag, so the Samba-lab `TestLab*` tests failed with "lab not up (make lab-up)". The target now runs `-run '^TestWindowsLab'` (guarded by the offline test).
- Not yet proven on a real DC: `TestReferralWindowsRealDCPending` (LF-32) stays skipped.
- Evaluation licence is 180 days from the build date: rebuild by 2027-04-26 (see section 4); do not rearm.

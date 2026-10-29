---
name: connector-run-lab-lessons
description: lab-tagged end-to-end test of connector.Run (Kerberos keytab on Samba, tunnel mux) - recipe and traps
metadata:
  type: reference
---

- `make lab-up` in a fresh worktree takes ~6 min; source `lab/.lab.env` (LAB_KRB_PORT, LAB_LDAPS_PORT) before `go test -tags lab`.
- Run the tunnel calls INSIDE the `serve` seam of `RunWith`: Run closes the backend (AD session) when serve returns.
- Keytab recipe (AES only, msDS-SupportedEncryptionTypes=24) is copied from ad/kerberos_lab_test.go; the Kerberos service account is an ordinary user and reads root NC + Verify/Read fine on Samba.
- External test seams live in compose/connector/export_test.go (OpenBackend, Backend.Handlers/Close); `tunnelFor(t, binding, timeout)` in mount_test.go builds the server/component mux pair.

---
title: External crossRef in CN=Partitions and the phantom nCName GUID
status: draft
owner: test-engineer
updated: 2026-11-12
---
# External crossRef in CN=Partitions (T-1800, proof for T-1268)

Observed on dc1 (Windows Server 2025, forest `win.activediq.test`), 2026-11-12; raw output in
`knowledge/development/runbooks/windows-lab-runs/T-1800-external-crossref-20261112.log.txt`.
Test: `TestWindowsLabTopologySkipsExternalCrossRef` (`internal/connector/ad`, tags `lab windowslab`).

- An Administrator can add a `crossRef` under `CN=Partitions,CN=Configuration,…` over LDAPS with
  `systemFlags=0` (no FLAG_CR_NTDS_NC 0x1), an `nCName` naming a partition no DC of the forest holds, and a `dnsRoot`.
  This is the shape of an external (referral) crossRef. `enabled` is not set.
- **Phantom GUID:** read with the extended DN control (1.2.840.113556.1.4.529, flag 1), its `nCName` comes back as
  `<GUID=…>;DC=t1800ext,DC=example,DC=test` — the DC mints a phantom object for the referenced DN and returns a
  real-looking GUID (no `<SID=…>`). The GUID is different on every create of the same DN (two runs: `e30cd9b5-…`,
  `dc724cd3-…`). A missing GUID is therefore NOT how an external crossRef is recognised, and the GUID must never be
  used as a stable naming-context identity for it.
- **Connector behaviour (defect):** `Session.Topology` does not look at `systemFlags&0x1`; it listed the external
  crossRef as `NCApplication` with the phantom GUID. Describe does not fail, but it reports a partition that is
  not a naming context of the forest. Filed as **T-1805**; the test records the defect and ends in an explicit
  expected-failure skip naming it, to be removed with the fix. Expected: skip crossRefs lacking 0x1.
- Cleanup: the test deletes the crossRef (fresh LDAPS connection) and also before creating it; run 1 left one behind
  because the DC closed the idle first connection — run 2 removed it and finished clean.

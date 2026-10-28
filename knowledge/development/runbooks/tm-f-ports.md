---
title: TM-F-PORTS — listening sockets of a booted install
date: 2026-10-28
updated: 2026-10-28
ticket: T-0137
status: draft
owner: devops-engineer
---

# TM-F-PORTS: a booted install listens only on threat model §8.1

Covers TM-TB6-T8, TM-TB14-T6 and TM-TB16-T10. The rule: the listening sockets of a booted install equal
the §8.1 rows its configuration enables, in both directions (an extra socket fails; a declared listener
that is absent also fails, so an empty comparison cannot pass).

## Linux / OCI (CI)

`tools/fitness/ports` reads `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` joined to the process's socket fds.
`boot_test.go` builds `cmd/server`, boots it against PostgreSQL 16 and 18 (Docker, `storetest`), and
compares for two configurations: L1 only, and L1 + L4 (`ACTIVEDIQ_OPS_ADDR`, loopback-only asserted).

    go test -count=1 ./tools/fitness/ports/

Unit tests (`ports_test.go`) carry the failing fixtures: a fake `/proc` with a debug listener on 6060 must
fail naming `6060`; a missing declared row, a wildcard bind on a loopback-only row and UDP-for-TCP all fail.

**Adding a listener is a threat-model change (RT-6, §14):** add the §8.1 row first, then the row in the
`cases` of `boot_test.go`. When L2 (fleet gRPC) and L3 (RADIUS, UDP) land, add their cases the same day.
When config selects a deployment profile, expand the case matrix per profile (today every manifest in
`internal/compose/profile` runs the one `server` binary).

## Windows service (lab, manual until the MSI exists)

On the lab VM with the service running as installed (see `windows-lab.md`):

    $svc = (Get-CimInstance Win32_Service -Filter "Name='activediq'").ProcessId
    Get-NetTCPConnection -State Listen -OwningProcess $svc | Select LocalAddress,LocalPort
    Get-NetUDPEndpoint -OwningProcess $svc | Select LocalAddress,LocalPort

The output must equal the §8.1 rows enabled by the service's configuration. Record it in
`windows-lab-runs/`. Automating this is part of the MSI boot smoke (activation check P2).

## Out of scope here

Sockets of the bundled PostgreSQL (§8.1: loopback only, not exposed) belong to a different process and are
checked by the install profile, not by this proof.

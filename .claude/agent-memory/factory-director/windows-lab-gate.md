---
name: windows-lab-gate
description: Windows lab state for triage — dc1 (VM 119) exists and workers may WinRM to it (lab only); fs1, Win11 client, child domain, ADMP still human actions
metadata:
  type: project
---

As of 2026-10-30: the lab is Proxmox VM 119 = dc1 (192.168.1.9, forest win.activediq.test). VM 112 is untouched, and the local KVM path was dropped on 2026-10-27.
The CEO authorised workers to use WinRM on dc1, lab only (A-0025, 2026-10-29). agent-verify (windows-lab.md §13) is the reference
transport. T-0839 adds a dc1 run lock; until it ships, workers use `flock -w 3600 /tmp/claude-1000/activediq-dc1.lock`.

Still human-only (open CEO actions): fs1 member server with gMSA + local user (A-0028 → T-0409, T-0413), Win11 client
(A-0023 → T-0610, T-0147), ADManager Plus trial (A-0024 → T-0673), child-domain DC dc2 (A-0031 → T-1234 → T-0786; kit T-1233 done, runbook §16).
Entra tenant is deferred to after M1 (A-0026). GSSAPI keytab + gMSA files exist beside .win-lab.env (2026-10-30). dc1 signing drifted to LDAPServerIntegrity=1 on 2026-11-01; T-1265 restores and guards it. 2026-11-02: dc1 fell off the LAN because of an IP clash on .9 (A-0032 open).
Unreachable dc1 → first check `ip neigh show 192.168.1.9` = bc:24:11:6e:fd:32.

**How to apply:** a Windows proof whose AC needs only a DC → unblock it, with the WinRM and lock note. One that needs a member,
client or second domain → keep it blocked on the matching action. Actions closed without a note are not evidence. See [[ceo-action-handover]]
and [[triage-apply-done-actions]].

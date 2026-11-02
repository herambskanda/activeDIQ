---
name: windows-lab-gate
description: Windows lab state for triage — dc1 (VM 119) + WinRM; since D-0022 workers build fs1/Win11/dc2 via an adiq-lab pool token; ADMP still human
metadata:
  type: project
---

As of 2026-11-02: the lab is Proxmox VM 119 = dc1 (192.168.1.250 since A-0032; was .9, forest win.activediq.test). VM 112 is untouched, and the local KVM path was dropped on 2026-10-27.
The CEO authorised workers to use WinRM on dc1, lab only (A-0025, 2026-10-29). agent-verify (windows-lab.md §13) is the reference
transport. T-0839 adds a dc1 run lock; until it ships, workers use `flock -w 3600 /tmp/claude-1000/activediq-dc1.lock`.

D-0022 (a, 2026-11-02): workers build lab VMs themselves with a Proxmox token scoped to pool `adiq-lab` (bootstrap T-1326 → scope proof + dc1 snapshot T-1327 → fs1 T-1328, Win11 T-0610, dc2 T-1329). Worker WinRM covers pool VMs, lab only (notice D-0023). A-0023/28/31/33 withdrawn. File the CEO's single bootstrap action only once T-1326 is on main. Still human-only: ADManager Plus trial (A-0024 → T-0673), DHCP reservation for dc1 (A-0034).
Entra tenant is deferred to after M1 (A-0026). GSSAPI keytab + gMSA files exist beside .win-lab.env (2026-10-30). dc1 signing drifted to LDAPServerIntegrity=1 on 2026-11-01; T-1265 restores and guards it. 2026-11-02: an IP clash on .9 → dc1 moved to .250 (A-0032 done); .9 is now another device; T-1279 removes the .9 defaults from the drivers.
Worker reports "dc1 at 192.168.77.10 unreachable / no .win-lab.env" (T-1277, 2026-11-02) usually mean a worktree session missed the gitignored env file in the primary checkout (lab/windows/.win-lab.env) and fell back to a stale default (fix: T-1363). Probe `</dev/tcp/$ADDR/5985` yourself before treating it as a lab outage.
Unreachable dc1 → first check that the `ip neigh` MAC for WIN_LAB_DC_ADDR in .win-lab.env is bc:24:11:6e:fd:32, and read the done notes on recent actions.

**How to apply:** a Windows proof whose AC needs only a DC → unblock it, with the WinRM and lock note. One that needs a member,
client or second domain → keep it blocked on its build ticket (T-1328/T-0610/T-1329) until that is on main. Actions closed without a note are not evidence. See [[ceo-action-handover]]
and [[triage-apply-done-actions]].

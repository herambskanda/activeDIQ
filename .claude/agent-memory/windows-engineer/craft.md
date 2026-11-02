---
name: windows-craft
description: Windows API traps and lab limits met while building the DC agent (T-0555)
metadata:
  type: reference
---
- No Windows lab on the Linux box: only `GOOS=windows go vet` is possible. Say NOT RUN on Windows in advance notes; never imply proof.
- x/sys/windows lacks JOBOBJECT_CPU_RATE_CONTROL_INFORMATION (define locally: class 15, enable 0x1, hard cap 0x4) and LookupPrivilegeName (use advapi32 LookupPrivilegeNameW).
- Edit SDDL via SecurityDescriptorFromString/ACLFromEntries/SetDACL, never string concat.
- Fitness scans of .wxs must strip XML comments first; comments legitimately say "never LocalSystem".
- Samba AD cannot test filters, credential providers or Security events; every acceptance needs a Windows VM.
- Pre-existing red on main: `fitness-modules` (18 violations) and gofmt on oidc/harness_test.go; not ours.
- Module boundary is internal/agenthost/api (module -> api <- host); it may import only pure stdlib, agent/v1, grpc (R3). Host-only types (agentpolicy-using Module iface) stay in platform/agent. Module test fakes must not import the host either.
- WiX: ServiceSid/RequiredPrivilege go in a core ServiceConfig nested in ServiceInstall; WiX actually writing the privilege list is UNVERIFIED (T-0648 reads it back). Mixed-case Id (AgentDir) keeps a directory private; ALLCAPS is a public property.
- SDDL render uses aliases (ER, BA, SY); assert on those, not on S-1-5-32-xxx, in Windows tests.
- Never `git stash` for a quick check; use a tagged WIP commit.
- WiX 5.0.2 (T-1249): core ServiceConfig has ServiceSid+RequiredPrivilege but NO failure-action attrs (WIX0004) and itself raises WIX1149; util:ServiceConfig has only failure actions. Use both, build with `-wx -sw1149`.
- Admin-run `enroll` + service-run `Load`: ACL/owner must name the SERVICE SID (owner Administrators), never the invoking admin's user SID; icacls fixes don't change the owner. Map Load errors by class (absent vs unsafe vs expired): never "not enrolled" for everything.
- dc1 address lives in the MAIN checkout's lab/windows/.win-lab.env (WIN_LAB_DC_ADDR; now .250, was .9); WinRM 5985; libvirt `windows-lab status` is a different lab. If 5985 times out, nothing a worker can do (no Proxmox access): block with the run command.
- agent-fitness (A1) rejects unlisted file types under packaging/windows/agent (even README.md); put docs in the runbook.
- Job-object HARD CPU cap (5 %) stretches a Go dial+TLS handshake from 1.3 s to 25-34 s on dc1: lift it for connection set-up only (Burst), keep memory/priority. Confine must be idempotent (idle loop re-calls it).
- A Load that reads "file missing" as "not enrolled" waits a full poll when it lands mid-`enroll`: classify partial dirs (ErrIncomplete) and re-check in 1 s.
- Lift-and-restore of a Tier-0 resource bound (CPU cap) must report and retry a failed restore, and be read back (QueryInformationJobObject, NULL job = own process's job) in a Windows test; keep the refcount logic OS-neutral (cpucap.go) so Linux tests inject failures.
- Windows tests that need elevation: skip only on `!IsElevated()`, else Fatal; a blanket Skipf on any error makes the test unable to fail.
- Windows PowerShell 5.1 splits `-test.v` at the dot when calling a native exe: quote every `-test.*` arg. Never `pkill -f <name>` from a command whose own text has <name>: it kills your shell.

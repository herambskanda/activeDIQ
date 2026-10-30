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
- WiX 5.0.2 core ServiceConfig (ServiceSid, RequiredPrivilege) DOES write MsiServiceConfig ConfigType 5 (SID, arg 3) / 6 (privs); lab-verified (T-0724). ConfigType 3/4 are delayed-start/failure flag. Mixed-case Id (AgentDir) keeps a directory private; ALLCAPS is a public property.
- SDDL render uses aliases (ER, BA, SY); assert on those, not on S-1-5-32-xxx, in Windows tests.
- Never `git stash` for a quick check; use a tagged WIP commit.
- WiX 5.0.2: core ServiceConfigFailureActions writes names ("restart"); MSI wants 1 -> install error 1939. util:ServiceConfig/EventSource add a DLL CA + HKLM\SYSTEM rows that fitness-built-msi refuses. Recovery + event source live in `agentsetup configure-service`.
- wixl (msitools) fixtures use made-up ConfigType numbers; trust Microsoft Learn + a real msidump. `msidump -t` drops Binary/ in the cwd: run it in a temp dir.
- Real MSI beats any pin: build on dc1 (`agent-verify --build-only --msi-out`), msidump, then judge. Wrap dc1 in `flock /tmp/claude-1000/activediq-dc1.lock`. pywinrm: `pip install --target <scratch>` (no venv).

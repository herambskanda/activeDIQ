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
- Held-dir pattern (ownerfile.Dir, T-1315): open the dir once no-follow, verify the parent first, then only handle-relative I/O. Windows dir handle without FILE_SHARE_DELETE blocks rename of the dir; compare GetFinalPathNameByHandle of each file to dir+name.
- Test dirs: t.TempDir() subdirs are group-writable under umask 002 and fail the parent check; chmod the parent 0700 in the test (tempParent helper).
- A new package linked into cmd/agent needs a line in tools/fitness/agenthost/closure-allow.txt (A4) with what it can reach.
- Pre-existing red: fitness-safeprim (3 hits in directory/inventory), compose/server tests time out here. Not ours.

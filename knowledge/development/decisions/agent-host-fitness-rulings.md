---
title: "Rulings on fitness-agent-host (T-0554) for the agent host and addc: module boundary, closure allowlist, tunnel listener, MSI custom actions"
date: 2026-10-29
updated: 2026-10-29
status: accepted
owner: security-architect
kind: technical
ticket: T-0688
fitness: fitness-agent-host R3, R4, A1, A4 (`make fitness-agent-host`, tools/fitness/agenthost; fixtures in t0688_test.go)
---

# Rulings on fitness-agent-host for the agent host and `addc` (T-0688)

Unblocks T-0555, which reported 154 violations of the T-0554 checker. These rulings refine ADR-0006 and
the contract ([agent-host-addc-contract.md](../architecture/agent-host-addc-contract.md) §1, §6 C1-C5).
They weaken no check: where the code was wrong the code changes; where the allowlist was too thin it
grows by reviewed, exact entries. Measured on `factory/T-0555` at dce3e5ed with `go run ./tools/fitness/agenthost -skip-tests`.

## Ruling 1: R3. Create `internal/agenthost/hostapi`; do not widen R3 to the host

**Decision.** R3 stays allow-by-exception. `addc` may not import `internal/platform/agent`, the generated
`skenzeriq/agent/v1` package, `grpc`, `syscall`, `unsafe` or `x/sys/windows`. The module boundary becomes
a real package, `internal/agenthost/hostapi`, imported by both sides: the host implements it, modules consume
it (module -> api <- host). Amended R3 allowlist (check.go):

| Admitted | Why it is safe |
| --- | --- |
| `internal/agenthost/hostapi` | the boundary: capability interfaces only |
| `internal/proto/activediq/addc/v1` | the module's own contract: typed data (R1, R2, R5 already lint it) |
| `encoding/xml` | pure parsing of event XML; Go's decoder does not fetch external entities |
| `golang.org/x/text/cases`, `.../unicode/norm` | pure text tables; no I/O |

Not admitted: `internal/platform/agent` (the host: it holds the outbox, policy store and token code),
`skenzeriq/agent/v1` and `activediq/fleet/v1` (the host's wire surface), `grpc`.

**What `api` holds (contract §1 "dependency struct"):** `Module` and `ModuleDeps`; an event sink
(`Append(batch)`, bounded); the named-blob store; logger; clock; **`EventSource`**; type aliases for the
wire data types the sink takes (`type Event = agentv1.Event`) and `type ServiceRegistrar = grpc.ServiceRegistrar`
so generated `RegisterXServer` calls compile without a module-side grpc import.

**The Windows event log moves to the host.** `source_windows.go` (wevtapi through `x/sys/windows`,
`syscall`, `unsafe`: `EvtSubscribe/Next/Render/OpenLog`) is raw Windows API reach inside a module, which
is exactly what C1-C3 forbid. The code moves to `internal/platform/agent/eventlog_windows.go` (the host
already owns it) behind `api.EventSource`:

- read-only: subscribe from a record number, receive rendered XML bytes (size-capped), nothing else;
- the **query is built by the host from typed arguments** (`channel` from a closed enum the host
  validates per module, `ids []uint16`, `afterRecord uint64`, rendered with `strconv`). No module-supplied
  string reaches XPath. This also removes the hand-built `query(after, ids)` string from module code;
- access-denied surfaces as a typed error (the fail-closed signal ADR-0006 needs), never as a retry loop.

`DecodeEvent` (XML to typed event, `encoding/xml`) stays in `addc`, pure and fuzzable.

**Boundary guard (new, in check.go).** `internal/agenthost/hostapi` may itself import only the pure stdlib
set, `skenzeriq/agent/v1` and `grpc`; anything else (`os`, `net`, `syscall`, `x/sys`) fails R3. Otherwise
the boundary could be used to smuggle a capability in.

**Tests that prove it:** `TestR3ModuleCapabilities` (existing bypass cases still fail),
`TestT0688R3Boundary`, `TestT0688APIBoundaryAndInsecure`; T-0555 adds a unit test where a fake
`EventSource` returns access-denied and the module reports it without retrying.
**Residual risk:** a module can still be wrong about *which* IDs to ask for; that is bounded by the
signed policy (ADR-0007) and the host's per-module channel enum.

## Ruling 2: A4. The reviewed closure list

**Decision.** `closure-allow.txt` now lists exact paths, with one exception: the `internal/` subtrees of
`google.golang.org/grpc` and `google.golang.org/protobuf`, which our code cannot import and which change
with every release. There is **no public subtree**, so a new `grpc/credentials/alts`, `grpc/xds`,
`grpc/credentials/oauth`, `x/net/proxy`, `x/sys/windows/registry` or `x/sys/windows/svc/mgr` fails until
someone reviews what it can reach. The file is the review record; each block states what it can reach.

Reviewed and admitted (measured closure, windows + linux):

- **Own:** `cmd/agent`, `compose/agent`, `compose/config`, `agenthost/api`, `agentmodules/...`,
  `platform/agent`, `platform/agentpolicy`, `platform/fleet`, `platform/fleet/dial`, `platform/tenant`
  (an ID type), the three generated protos, and `platform/prochardening` (T-0644: `syscall` for
  rlimit/dumpable only; main failed A4 on this package before this ticket).
- **`x/sys/windows`, `.../svc`, `x/sys/unix`:** needed by the host and `cmd/agent` (service control,
  token, job object, event log). R3 keeps them out of modules. `unix` is the Linux test build only.
- **`x/net`:** `http2`, `hpack`, `httpguts`, `idna` and internals (grpc transport); `x/net/trace` is
  grpc's debug tracing. It registers handlers on `http.DefaultServeMux` but opens no socket; it is
  harmless only because R4 forbids a listener. Residual risk, accepted: if a listener ever appears
  those handlers would be served, which is one more reason R4 has no exceptions.
- **`x/text`:** `cases`, `norm`, `language`, `transform`, `bidi`, `bidirule`, internals (addc, idna).
- **grpc / protobuf / genproto:** the client and stream types the dial-out and mux use.

Deliberately **not** admitted: `internal/platform/tablekind` and anything of the fleet gateway, which
means the server half of `platform/fleet` must leave the agent closure (Ruling 3).

**New guard (R4 side).** `grpc/credentials/insecure` is linked by grpc itself, so A4 cannot ban it; R4
now fails any agent-owned package that imports it (C5: outbound mTLS only). Test: `TestT0688APIBoundaryAndInsecure`.
**Tests:** `TestT0688ClosureAllowlist`, `TestA4Judge`, `TestA4RealClosure`, `TestRunOnRepositoryTreeIsConsistent`.

## Ruling 3: R4. The tunnel is not a listener, and there is no exception

**Decision.** The reverse tunnel is a **client dial-out** (`grpc.NewClient`, mTLS) carrying a
Mux whose handlers are registered on a registrar. Nothing on the agent accepts a connection (contract §1,
C5, TM-D13). R4 stays name-based and strict. The three hits are code problems, not rule problems:

1. `internal/platform/fleet/mux.go:133-134`: `Binding.Serve` is a *handler-registration callback*, not a
   socket call. **Rename the field `Register`** (also corrects a misleading name). No R4 allowlist.
2. `internal/platform/fleet/gateway.go:199`: `grpc.NewServer` is the **server side** of the tunnel (tenant
   CA lookup, `tablekind`). It is linked into the DC binary only because it shares a package with the Mux.
   **Move `gateway.go` and `hub.go` (server-only) into `internal/platform/fleet/gateway`** (or
   equivalent); `Mux`, `Contract`, `Identity` and `dial` stay. A server constructor in a DC binary is one
   wiring mistake from a listener on a Tier-0 host; this removes it by construction. A4 enforces the split
   (`tablekind` is off the allowlist).

If a future need is real (for example a local named pipe for a credential provider), it gets its own
ticket and ADR, not an R4 exception.
**Tests:** R4 on the repo tree (T-0555 must run clean); `TestR4NoListener`; lab A2 (`netstat` on a DC) stays in T-0648.

## Ruling 4: A1 and the MSI

**4a. The four custom actions are approved, plus one rollback.** Each runs `agentsetup.exe <one verb>`
as SYSTEM (`Impersonate="no"`, required: it edits the Security channel ACL and the data-directory DACL),
deferred, no PowerShell, no `Binary`, no script, no immediate-sequence action. `installer-allow.txt` now
lists `WriteConfig`, `PrepareDataDir`, `GrantChannel`, `RevokeChannel` and **`RollbackGrantChannel`**
(`Execute="rollback"`, `revoke-channel`, `Return="ignore"`), so a failed install never leaves the ACE.

**A1 now pins attributes, not just Ids.** An Id on the allowlist previously approved *any* attributes,
so editing `ExeCommand` of an approved action would pass. `pinnedActions` in check.go fixes `Execute`,
`Impersonate`, `Return`, `Directory` and the exact `ExeCommand` per Id, and rejects extra attributes.

Required changes to `Agent.wxs` and `agentsetup` (reference shape: `targetWxs` in `t0688_test.go`):

- **Rename `INSTALLFOLDER` to `AgentDir`.** An all-uppercase Id is a public MSI property that can be set on
  the `msiexec` command line (and under AlwaysInstallElevated by a standard user), which would redirect a
  SYSTEM custom action to an attacker's `agentsetup.exe`. A mixed-case Id is private.
- **No arguments.** Drop `--data-dir`: `agentsetup` derives `%ProgramData%\skenzeriq\agent` from the known
  folder (it already does, `run_windows.go`) and exits non-zero on any argument beyond the verb. Test: an
  `agentsetup` unit test that extra arguments fail.
- `GrantChannel` edits the channel access SDDL by parsing the current string into a typed security
  descriptor, adding one ACE for the service SID and serialising once; keep it that way (no concatenation).
  Test: grant then revoke restores the original descriptor, and other ACEs survive.
- `RevokeChannel` keeps `Return="ignore"` so an uninstall cannot be blocked, on condition that
  `revoke-channel` is idempotent and logs its failure to the MSI log and the Application log. Residual
  risk: a stale ACE for a SID without an account; harmless unless an administrator recreates the same
  service name, which already needs administrator.

**4b. Privileges through WiX, never the registry.** Delete the two `RegistryValue` elements under
`HKLM\SYSTEM\CurrentControlSet\Services\activeDIQAgent` (A1 forbids them, correctly). Declare the SID
type and the one privilege in a core `ServiceConfig` **nested inside the `ServiceInstall`**, with a
`RequiredPrivilege` child:

```xml
<ServiceInstall Id="AgentService" Name="activeDIQAgent" Account="NT SERVICE\activeDIQAgent" ...>
  <ServiceConfig ServiceSid="restricted" OnInstall="yes" OnReinstall="yes">
    <RequiredPrivilege Name="SeChangeNotifyPrivilege" />
  </ServiceConfig>
</ServiceInstall>
```

`RequiredPrivilege` is documented with parent `ServiceConfig` ([WiX schema](https://docs.firegiant.com/wix/schema/wxs/requiredprivilege/));
`ServiceSid` is a `ServiceConfig` attribute ([WiX ServiceConfig](https://wixtoolset.org/docs/schema/wxs/serviceconfig)). Recovery actions are NOT on the core `ServiceConfig` (it has no failure-action attributes: WIX0004 with WiX 5.0.2); they are on `util:ServiceConfig`, a second element inside the same `ServiceInstall`, which has only those attributes (T-1249; `sc qfailure` read back on dc1 in the T-0833 log). The core element raises WIX1149 itself, so the build suppresses it on purpose (`-sw1149`) and runs with `-wx` so any other warning fails (runbook "Building the MSI"). It has no privilege attribute beyond the `RequiredPrivilege` child.
So **whether WiX really writes the privilege list is
`[UNVERIFIED — lab]`**: T-0648 must read it back after install (`sc qprivs activeDIQAgent`, and the token of
the running service). If WiX cannot write it, the fallback is **not** the registry: file a ruling request
for a sixth fixed-verb action (`agentsetup pin-service`, typed `ChangeServiceConfig2` call). Defence in
depth already exists and stays: `RunWith` checks its token privileges before any
subscription or network use (`HeldPrivileges`, ADR-0006 decision 3; I did not re-verify the exact mismatch rule).
A1 now also reads a `RequiredPrivilege` child of a `ServiceConfig` placed *beside* the `ServiceInstall`
(`TestT0688PrivilegeBesideServiceInstallIsRead`); previously that placement read as no privileges.

**4c. The local config path stops coming from the Service key.** `ACTIVEDIQ_AGENT_CONFIG` was written
as a service `Environment` registry value. Remove that mechanism on Windows: the service reads
`agent.json` beside its own executable (`os.Executable()`, the `Program Files` directory only
administrators can write). Keep `ConfigEnv` for non-Windows builds and tests only. This removes a
configuration-redirection input from the service key.

**4d. Comment hygiene.** The checker rejects the literal `LocalSystem` and the service-registry key path
anywhere in the file, including comments. Write "never a shared service identity" instead.

**Tests:** `TestT0688TargetInstallerPasses`, `TestT0688ApprovedActionsArePinned`, `TestA1Installer`; the
Windows proofs (identity, privileges, ACE, rollback leaves nothing) stay lab items in T-0648.

## Not a ruling, but found

`TestRunOnRepositoryTreeIsConsistent` was failing on main: T-0644 linked `platform/prochardening` into
`cmd/agent` without an A4 entry. Fixed here (reviewed above).

## Work for T-0555 (windows-engineer), in order

1. Create `internal/agenthost/hostapi`; move host-side types; move wevtapi into the host behind `EventSource`; strip `addc` of `syscall`, `unsafe`, `x/sys/windows`, `grpc`, `platform/agent`, `skenzeriq/agent/v1`.
2. Rename `Binding.Serve` to `Register`; move the gateway and hub out of the agent closure.
3. Rework `Agent.wxs` per 4a-4d; drop `--data-dir` from `agentsetup`; Windows config path.
4. `make fitness-agent-host` must print R3, R4, A1, A4 `ok` (A2/A3 remain T-0648).

Every change to an allowlist is a security-architect review; do not add lines to make the check pass.

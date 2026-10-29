package main

import (
	"strings"
	"testing"
)

// targetWxs is the reference shape T-0688 ruling 4 requires of packaging/windows/agent/Agent.wxs: the
// privilege and SID type through ServiceConfig, no HKLM\SYSTEM registry values, a private AgentDir, five
// pinned custom actions with no arguments.
const targetWxs = `<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:util="http://wixtoolset.org/schemas/v4/wxs/util">
  <Package Name="activeDIQ Agent" Manufacturer="skenzeriq" Version="1.0.0" UpgradeCode="6f3b8c1e-5d1a-4f6e-9a57-3c2b7d0e4a11" Scope="perMachine">
    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="VendorDir" Name="skenzeriq"><Directory Id="AgentDir" Name="agent" /></Directory>
    </StandardDirectory>
    <ComponentGroup Id="AgentFiles" Directory="AgentDir">
      <Component Id="AgentExe" Guid="*">
        <File Id="AgentExeFile" Source="a.exe" Name="activediq-agent.exe" KeyPath="yes" />
        <ServiceInstall Id="AgentService" Name="activeDIQAgent" Type="ownProcess" Start="auto" ErrorControl="normal" Account="NT SERVICE\activeDIQAgent">
          <ServiceConfig ServiceSid="restricted" OnInstall="yes" OnReinstall="yes">
            <RequiredPrivilege Name="SeChangeNotifyPrivilege" />
          </ServiceConfig>
        </ServiceInstall>
        <ServiceControl Id="AgentServiceControl" Name="activeDIQAgent" Start="install" Stop="both" Remove="uninstall" Wait="yes" />
        <util:ServiceConfig ServiceName="activeDIQAgent" FirstFailureActionType="restart" SecondFailureActionType="restart" ThirdFailureActionType="restart" RestartServiceDelayInSeconds="30" ResetPeriodInDays="1" />
      </Component>
      <Component Id="SetupExe" Guid="*"><File Id="SetupExeFile" Source="s.exe" Name="agentsetup.exe" KeyPath="yes" /></Component>
    </ComponentGroup>
    ACTIONS
  </Package>
</Wix>`

const targetActions = `
    <CustomAction Id="WriteConfig" Directory="AgentDir" Execute="deferred" Impersonate="no" Return="check" ExeCommand="&quot;[AgentDir]agentsetup.exe&quot; write-config" />
    <CustomAction Id="PrepareDataDir" Directory="AgentDir" Execute="deferred" Impersonate="no" Return="check" ExeCommand="&quot;[AgentDir]agentsetup.exe&quot; prepare-datadir" />
    <CustomAction Id="GrantChannel" Directory="AgentDir" Execute="deferred" Impersonate="no" Return="check" ExeCommand="&quot;[AgentDir]agentsetup.exe&quot; grant-channel" />
    <CustomAction Id="RollbackGrantChannel" Directory="AgentDir" Execute="rollback" Impersonate="no" Return="ignore" ExeCommand="&quot;[AgentDir]agentsetup.exe&quot; revoke-channel" />
    <CustomAction Id="RevokeChannel" Directory="AgentDir" Execute="deferred" Impersonate="no" Return="ignore" ExeCommand="&quot;[AgentDir]agentsetup.exe&quot; revoke-channel" />`

func TestT0688TargetInstallerPasses(t *testing.T) {
	root := t.TempDir()
	write(t, root, "packaging/windows/agent/Agent.wxs", strings.Replace(targetWxs, "ACTIONS", targetActions, 1))
	wantClean(t, checkInstallerAllow(root, parseAllow(embeddedInstallerAllow)))
}

func TestT0688ApprovedActionsArePinned(t *testing.T) {
	for _, c := range map[string]struct{ from, to, want string }{
		"public INSTALLFOLDER":  {`[AgentDir]agentsetup.exe&quot; grant-channel`, `[INSTALLFOLDER]agentsetup.exe&quot; grant-channel`, "execommand"},
		"data-dir flag":         {`prepare-datadir`, `prepare-datadir --data-dir X`, "execommand"},
		"impersonating":         {`Impersonate="no" Return="check" ExeCommand="&quot;[AgentDir]agentsetup.exe&quot; grant-channel"`, `Impersonate="yes" Return="check" ExeCommand="&quot;[AgentDir]agentsetup.exe&quot; grant-channel"`, "impersonate"},
		"revoke made immediate": {`Execute="rollback"`, `Execute="immediate"`, "execute"},
		"extra attribute":       {`Id="GrantChannel"`, `Id="GrantChannel" HideTarget="no"`, "hidetarget"},
	} {
		root := t.TempDir()
		x := strings.Replace(targetWxs, "ACTIONS", strings.Replace(targetActions, c.from, c.to, 1), 1)
		write(t, root, "packaging/windows/agent/Agent.wxs", x)
		r := checkInstallerAllow(root, parseAllow(embeddedInstallerAllow))
		wantViolation(t, r, c.want)
	}
	// The reviewed Id with a new, unlisted action beside it still fails.
	root := t.TempDir()
	x := strings.Replace(targetWxs, "ACTIONS", targetActions+`<CustomAction Id="Extra" Directory="AgentDir" ExeCommand="x" />`, 1)
	write(t, root, "packaging/windows/agent/Agent.wxs", x)
	wantViolation(t, checkInstallerAllow(root, parseAllow(embeddedInstallerAllow)), `"Extra"`)
}

func TestT0688PrivilegeBesideServiceInstallIsRead(t *testing.T) {
	root := t.TempDir()
	x := strings.Replace(targetWxs, "ACTIONS", targetActions, 1)
	x = strings.Replace(x, `<ServiceConfig ServiceSid="restricted" OnInstall="yes" OnReinstall="yes">
            <RequiredPrivilege Name="SeChangeNotifyPrivilege" />
          </ServiceConfig>
        </ServiceInstall>`, `</ServiceInstall>
        <ServiceConfig ServiceName="activeDIQAgent" ServiceSid="restricted"><RequiredPrivilege Name="SeDebugPrivilege" /></ServiceConfig>`, 1)
	write(t, root, "packaging/windows/agent/Agent.wxs", x)
	wantViolation(t, checkInstallerAllow(root, parseAllow(embeddedInstallerAllow)), "RequiredPrivileges")
}

func TestT0688R3Boundary(t *testing.T) {
	mod := defaultModulePath
	for imp, ok := range map[string]bool{
		"encoding/xml":                             true,
		"golang.org/x/text/cases":                  true,
		"golang.org/x/text/unicode/norm":           true,
		mod + "/internal/agenthost/api":            true,
		mod + "/internal/proto/activediq/addc/v1":  true,
		mod + "/internal/platform/agentpolicy":     true,
		mod + "/internal/platform/agent":           false, // the host: modules get api only
		mod + "/internal/proto/skenzeriq/agent/v1": false,
		mod + "/internal/proto/activediq/fleet/v1": false,
		"google.golang.org/grpc":                   false,
		"golang.org/x/sys/windows":                 false,
		"golang.org/x/text/encoding":               false,
		"syscall":                                  false,
		"unsafe":                                   false,
	} {
		if got := judgeModuleImport(mod, imp, "") == ""; got != ok {
			t.Errorf("import %s: allowed=%v want %v", imp, got, ok)
		}
	}
}

func TestT0688ClosureAllowlist(t *testing.T) {
	allow := parseAllow(embeddedClosureAllow)
	mod := defaultModulePath
	for p, ok := range map[string]bool{
		mod + "/internal/platform/fleet":            true,
		mod + "/internal/platform/tablekind":        false, // server-side tunnel code stays out of the DC binary
		mod + "/internal/platform/fleet/gateway":    false,
		mod + "/internal/agentmodules/addc":         true,
		"google.golang.org/grpc":                    true,
		"google.golang.org/grpc/internal/transport": true,
		"google.golang.org/grpc/credentials/alts":   false,
		"google.golang.org/grpc/xds":                false,
		"google.golang.org/grpc/health":             false,
		"golang.org/x/net/proxy":                    false,
		"golang.org/x/sys/windows/registry":         false,
		"golang.org/x/sys/windows/svc/mgr":          false,
		"golang.org/x/text/encoding/charmap":        false,
	} {
		if got := allowed(p, allow); got != ok {
			t.Errorf("closure %s: allowed=%v want %v", p, got, ok)
		}
	}
}

func TestT0688APIBoundaryAndInsecure(t *testing.T) {
	root := t.TempDir()
	write(t, root, "internal/agentmodules/addc/ok.go", "package addc\n")
	write(t, root, "internal/agenthost/api/api.go", "package api\n\nimport (\n\t\"context\"\n\t\"google.golang.org/grpc\"\n)\n\nvar _ context.Context\nvar _ grpc.ServiceRegistrar\n")
	wantClean(t, checkModuleCapabilities(root))
	for _, imp := range []string{"os/exec", "net", "syscall", "golang.org/x/sys/windows", "os", "unsafe"} {
		bad := t.TempDir()
		write(t, bad, "internal/agentmodules/addc/ok.go", "package addc\n")
		write(t, bad, "internal/agenthost/api/api.go", "package api\n\nimport _ \""+imp+"\"\n")
		if len(checkModuleCapabilities(bad).Violations) == 0 {
			t.Errorf("api package importing %s accepted", imp)
		}
	}
	ins := t.TempDir()
	write(t, ins, "go.mod", "module fx.test\n\ngo 1.22\n")
	write(t, ins, "cmd/agent/main.go", "package main\n\nimport _ \"google.golang.org/grpc/credentials/insecure\"\n\nfunc main() {}\n")
	wantViolation(t, checkNoListener(ins), "credentials/insecure")
}

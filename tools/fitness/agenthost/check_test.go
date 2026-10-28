package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hostProto = `syntax = "proto3";
package skenzeriq.agent.v1;
message Empty {}
message SignedPolicy { bytes payload = 1; bytes signature = 2; }
message SignedKeyset { bytes payload = 1; bytes signature = 2; }
message StageRequest { bytes tuf_metadata = 1; bytes artefact_digest = 2; }
message AckRequest { uint64 through_agent_seq = 1; }
message Status { uint64 policy_seq = 1; }
service Host {
  rpc GetStatus(Empty) returns (Status);
  rpc ApplyPolicy(SignedPolicy) returns (Status);
  rpc ApplyKeyset(SignedKeyset) returns (Status);
  rpc StageUpdate(StageRequest) returns (Status);
  rpc AckEvents(AckRequest) returns (Status);
}
`

const addcProto = `syntax = "proto3";
package activediq.addc.v1;
message Empty {}
message CollectionState { uint64 last_event_record_id = 1; }
message PasswordPolicy { uint32 min_length = 1; repeated string banned_terms = 2; }
message AddcPolicy { PasswordPolicy password = 1; bool collection_enabled = 2; }
service Addc { rpc GetCollectionState(Empty) returns (CollectionState); }
`

const goodWxs = `<?xml version="1.0"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="activeDIQ Agent">
    <ServiceInstall Name="activediq-agent" Account="NT SERVICE\activeDIQAgent" Start="auto" Type="ownProcess" ErrorControl="normal">
      <ServiceConfig ServiceSid="restricted" RequiredPrivileges="SeChangeNotifyPrivilege" />
    </ServiceInstall>
  </Package>
</Wix>
`

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func protoTree(t *testing.T, host, addc string) string {
	root := t.TempDir()
	// The proto tool also requires the fleet contract to exist (F11), so the fixtures carry the real one.
	fleet, err := os.ReadFile("../../../proto/activediq/fleet/v1/fleet.proto")
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "proto/activediq/fleet/v1/fleet.proto", string(fleet))
	write(t, root, "proto/skenzeriq/agent/v1/agent.proto", host)
	write(t, root, "proto/activediq/addc/v1/addc.proto", addc)
	return root
}

func wantViolation(t *testing.T, r Result, sub string) {
	t.Helper()
	if r.Inactive != "" {
		t.Fatalf("%s inactive (%s), want a violation containing %q", r.ID, r.Inactive, sub)
	}
	for _, v := range r.Violations {
		if strings.Contains(v, sub) {
			return
		}
	}
	t.Fatalf("%s: want a violation containing %q, got %v", r.ID, sub, r.Violations)
}

func wantClean(t *testing.T, r Result) {
	t.Helper()
	if r.Inactive != "" || len(r.Violations) != 0 {
		t.Fatalf("%s: want clean, got inactive=%q violations=%v", r.ID, r.Inactive, r.Violations)
	}
}

func TestProtoRulesInactiveWithoutProto(t *testing.T) {
	r := checkProto(t.TempDir(), "R1", "x", []string{"AG1"})
	if r.Inactive == "" {
		t.Fatal("R1 must say inactive when the agent proto does not exist, never pass")
	}
}

func TestProtoRulesR1R2R5(t *testing.T) {
	clean := protoTree(t, hostProto, addcProto)
	wantClean(t, checkProto(clean, "R1", "x", []string{"AG1", "AG2", "AG3", "AG8"}))
	wantClean(t, checkProto(clean, "R2", "x", []string{"AG4", "AG5"}))
	wantClean(t, checkProto(clean, "R5", "x", []string{"AG6", "AG7"}))

	// A denied verb (TM-D13: exec) added to the host.
	denied := protoTree(t, strings.Replace(hostProto, "service Host {", "service Host { rpc RunCommand(Empty) returns (Status);", 1), addcProto)
	wantViolation(t, checkProto(denied, "R1", "x", []string{"AG1", "AG2", "AG3", "AG8"}), "AG2")
	// An RPC outside the golden list, even with a harmless name.
	extra := protoTree(t, hostProto, strings.Replace(addcProto, "service Addc {", "service Addc { rpc Ping(Empty) returns (Empty);", 1))
	wantViolation(t, checkProto(extra, "R1", "x", []string{"AG1", "AG2", "AG3", "AG8"}), "AG1")
	// A path in the policy.
	path := protoTree(t, hostProto, strings.Replace(addcProto, "bool collection_enabled = 2;", "bool collection_enabled = 2; string log_path = 3;", 1))
	wantViolation(t, checkProto(path, "R2", "x", []string{"AG4", "AG5"}), "AG4")
	// A password in the surface.
	pw := protoTree(t, hostProto, strings.Replace(addcProto, "bool collection_enabled = 2;", "bool collection_enabled = 2; uint32 password_hash = 3;", 1))
	wantViolation(t, checkProto(pw, "R5", "x", []string{"AG6", "AG7"}), "AG6")
	// A rule's violation is reported only under its own check.
	if r := checkProto(pw, "R2", "x", []string{"AG4", "AG5"}); len(r.Violations) != 0 {
		t.Fatalf("R2 reported an R5 violation: %v", r.Violations)
	}
}

func TestR3ModuleCapabilities(t *testing.T) {
	root := t.TempDir()
	write(t, root, "internal/agentmodules/addc/ok.go", "package addc\n\nimport \"strings\"\n\nvar _ = strings.ToLower\n")
	wantClean(t, checkModuleCapabilities(root))
	for name, src := range map[string]string{
		"os/exec":      "package addc\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
		"registry":     "package addc\n\nimport \"golang.org/x/sys/windows/registry\"\n\nvar _ = registry.LOCAL_MACHINE\n",
		"service mgr":  "package addc\n\nimport \"golang.org/x/sys/windows/svc/mgr\"\n\nvar _ = mgr.Connect\n",
		"os.WriteFile": "package addc\n\nimport \"os\"\n\nfunc f() { _ = os.WriteFile(\"x\", nil, 0) }\n",
		"os.RemoveAll": "package addc\n\nimport \"os\"\n\nfunc f() { _ = os.RemoveAll(\"x\") }\n",
		// The security review's bypasses: each passed the first version of this check.
		"windows.CreateProcess": "package addc\n\nimport \"golang.org/x/sys/windows\"\n\nvar _ = windows.CreateProcess\n",
		"windows.OpenSCManager": "package addc\n\nimport \"golang.org/x/sys/windows\"\n\nvar _ = windows.OpenSCManager\n",
		"syscall.Unlink":        "package addc\n\nimport \"syscall\"\n\nvar _ = syscall.Unlink\n",
		"io/ioutil.WriteFile":   "package addc\n\nimport \"io/ioutil\"\n\nvar _ = ioutil.WriteFile\n",
		"dot-import of os":      "package addc\n\nimport . \"os\"\n\nfunc f() { _ = WriteFile(\"x\", nil, 0) }\n",
		"blank import":          "package addc\n\nimport _ \"unsafe\"\n",
		"renamed os/exec":       "package addc\n\nimport e \"os/exec\"\n\nvar _ = e.Command\n",
		"unsafe":                "package addc\n\nimport \"unsafe\"\n\nvar _ unsafe.Pointer\n",
		"cgo":                   "package addc\n\nimport \"C\"\n",
		"net (unlisted stdlib)": "package addc\n\nimport \"net\"\n\nvar _ = net.Dial\n",
		"unlisted third party":  "package addc\n\nimport \"example.com/x/y\"\n\nvar _ = y.Z\n",
		"os.NewFile":            "package addc\n\nimport \"os\"\n\nvar _ = os.NewFile\n",
		"os.Lchown":             "package addc\n\nimport \"os\"\n\nvar _ = os.Lchown\n",
		"plugin":                "package addc\n\nimport \"plugin\"\n\nvar _ = plugin.Open\n",
		"os.OpenRoot + Create":  "package addc\n\nimport \"os\"\n\nfunc f() { r, _ := os.OpenRoot(`C:\\Windows\\System32`); _, _ = r.Create(\"evil.dll\") }\n",
		"os.OpenInRoot":         "package addc\n\nimport \"os\"\n\nvar _ = os.OpenInRoot\n",
		"os.CopyFS":             "package addc\n\nimport \"os\"\n\nfunc f() { _ = os.CopyFS(\"d\", os.DirFS(\"s\")) }\n",
		"os.FindProcess Kill":   "package addc\n\nimport \"os\"\n\nfunc f() { p, _ := os.FindProcess(4); _ = p.Kill() }\n",
		"File.Chmod":            "package addc\n\nimport \"os\"\n\nfunc f(f *os.File) { _ = f.Chmod(0) }\n",
		"aliased os OpenRoot":   "package addc\n\nimport o \"os\"\n\nvar _ = o.OpenRoot\n",
		"filepath.WalkDir":      "package addc\n\nimport \"path/filepath\"\n\nvar _ = filepath.WalkDir\n",
		"filepath.Walk":         "package addc\n\nimport \"path/filepath\"\n\nvar _ = filepath.Walk\n",
		"filepath.Glob":         "package addc\n\nimport \"path/filepath\"\n\nvar _ = filepath.Glob\n",
		"filepath.EvalSymlinks": "package addc\n\nimport f \"path/filepath\"\n\nvar _ = f.EvalSymlinks\n",
		"aliased os WriteFile":  "package addc\n\nimport o \"os\"\n\nfunc f() { _ = o.WriteFile(\"x\", nil, 0) }\n",
	} {
		bad := t.TempDir()
		write(t, bad, "internal/agentmodules/addc/bad.go", src)
		r := checkModuleCapabilities(bad)
		if len(r.Violations) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	// Non-Go files link code the AST scan cannot see.
	for name, file := range map[string]string{"a_linux_amd64.s": "TEXT ·sys(SB),0,$0\n\tSYSCALL\n", "x.syso": "obj", "c.c": "int x;", "h.h": "", "m.m": "", "S.S": ""} {
		bad := t.TempDir()
		write(t, bad, "internal/agentmodules/addc/ok.go", "package addc\n")
		write(t, bad, "internal/agentmodules/addc/"+name, file)
		wantViolation(t, checkModuleCapabilities(bad), "only .go files")
	}
	// The os selectors that stay allowed.
	osok := t.TempDir()
	write(t, osok, "internal/agentmodules/addc/ok.go", "package addc\n\nimport (\n\t\"errors\"\n\t\"os\"\n)\n\nfunc f(err error) (string, bool) { return os.Getenv(\"X\"), errors.Is(err, os.ErrNotExist) }\n")
	wantClean(t, checkModuleCapabilities(osok))
	// A foreign module's look-alike path, and a lookalike sibling name, are not ours.
	for name, imp := range map[string]string{
		"foreign agenthost api exec": "github.com/x/internal/agenthost/apix/exec",
		"foreign agentmodules":       "github.com/x/internal/agentmodules/shared",
		"apix prefix":                "github.com/skenzeriq/activediq/internal/agenthost/apix",
		"agentmodulesx":              "github.com/skenzeriq/activediq/internal/agentmodulesx",
		"policy subpackage":          "github.com/skenzeriq/activediq/internal/platform/agentpolicyx",
	} {
		bad := t.TempDir()
		write(t, bad, "internal/agentmodules/addc/bad.go", "package addc\n\nimport _x \""+imp+"\"\n\nvar _ = _x.Y\n")
		if r := checkModuleCapabilities(bad); len(r.Violations) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	// The module path comes from go.mod.
	gm := t.TempDir()
	write(t, gm, "go.mod", "module example.org/m\n\ngo 1.22\n")
	write(t, gm, "internal/agentmodules/addc/ok.go", "package addc\n\nimport _x \"example.org/m/internal/platform/agentpolicy\"\n\nvar _ = _x.X\n")
	wantClean(t, checkModuleCapabilities(gm))
	// Allowed: a sibling module package and the policy package.
	ok := t.TempDir()
	write(t, ok, "internal/agentmodules/addc/ok.go", "package addc\n\nimport (\n\t\"context\"\n\t\"encoding/json\"\n\t\"github.com/skenzeriq/activediq/internal/agentmodules/shared\"\n\t\"github.com/skenzeriq/activediq/internal/platform/agentpolicy\"\n)\n\nvar _ = context.Background\nvar _ = json.Marshal\nvar _ = shared.X\nvar _ = agentpolicy.X\n")
	wantClean(t, checkModuleCapabilities(ok))
}

func TestR4NoListener(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module fx.test\n\ngo 1.22\n")
	write(t, root, "cmd/agent/main.go", "package main\n\nfunc main() {}\n")
	wantClean(t, checkNoListener(root))
	for name, src := range map[string]string{
		"net.Listen":            "package main\n\nimport \"net\"\n\nfunc main() { _, _ = net.Listen(\"tcp\", \":1\") }\n",
		"ListenAndServe":        "package main\n\nimport \"net/http\"\n\nfunc main() { _ = http.ListenAndServe(\":1\", nil) }\n",
		"server ListenAndServe": "package main\n\nimport \"net/http\"\n\nfunc main() { s := &http.Server{}; _ = s.ListenAndServe() }\n",
		"httptest":              "package main\n\nimport \"net/http/httptest\"\n\nvar _ = httptest.NewServer\n\nfunc main() {}\n",
		// The security review's bypasses.
		"net.ListenConfig.Listen": "package main\n\nimport (\"context\"; \"net\")\n\nfunc main() { var lc net.ListenConfig; _, _ = lc.Listen(context.Background(), \"tcp\", \":1\") }\n",
		"ListenConfig type":       "package main\n\nimport \"net\"\n\nvar _ net.ListenConfig\n\nfunc main() {}\n",
		"syscall.Listen":          "package main\n\nimport \"syscall\"\n\nfunc main() { _ = syscall.Listen(3, 1) }\n",
		"syscall.Bind":            "package main\n\nimport \"syscall\"\n\nfunc main() { _ = syscall.Bind(3, nil) }\n",
		"grpc Server.Serve":       "package main\n\ntype s struct{}\n\nfunc (s) Serve(l int) {}\n\nfunc main() { var x struct{ srv s }; x.srv.Serve(0) }\n",
		"dot-import net":          "package main\n\nimport . \"net\"\n\nfunc main() { _, _ = Listen(\"tcp\", \":1\") }\n",
		"tls.Listen":              "package main\n\nimport \"crypto/tls\"\n\nfunc main() { _, _ = tls.Listen(\"tcp\", \":1\", nil) }\n",
	} {
		bad := t.TempDir()
		write(t, bad, "go.mod", "module fx.test\n\ngo 1.22\n")
		write(t, bad, "cmd/agent/main.go", src)
		if r := checkNoListener(bad); len(r.Violations) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	// A listener in a package the agent imports that is not agent-owned by directory name.
	far := t.TempDir()
	write(t, far, "go.mod", "module fx.test\n\ngo 1.22\n")
	write(t, far, "cmd/agent/main.go", "package main\n\nimport _ \"fx.test/internal/platform/net\"\n\nfunc main() {}\n")
	write(t, far, "internal/platform/net/n.go", "package net\n\nimport stdnet \"net\"\n\nfunc init() { _, _ = stdnet.Listen(\"tcp\", \":1\") }\n")
	wantViolation(t, checkNoListener(far), "internal/platform/net/n.go")
}

func TestA1Installer(t *testing.T) {
	if r := checkInstaller(t.TempDir()); r.Inactive == "" {
		t.Fatal("A1 must be inactive, not passing, without installer source")
	}
	mk := func(body string) Result {
		root := t.TempDir()
		write(t, root, "packaging/windows/agent.wxs", body)
		return checkInstaller(root)
	}
	wantClean(t, mk(goodWxs))
	wantViolation(t, mk(strings.Replace(goodWxs, `NT SERVICE\activeDIQAgent`, `LocalSystem`, 1)), "LocalSystem")
	wantViolation(t, mk(strings.Replace(goodWxs, `Start="auto"`, `Start="auto"><!-- runs as LocalSystem --><X`, 1)+"</Wix>"), "LocalSystem")
	wantViolation(t, mk(strings.Replace(goodWxs, `NT SERVICE\activeDIQAgent`, `NT AUTHORITY\NetworkService`, 1)), "Account")
	wantViolation(t, mk(strings.Replace(goodWxs, `NT SERVICE\activeDIQAgent`, `NT SERVICE\SomethingElse`, 1)), "Account is")
	wantViolation(t, mk(strings.Replace(goodWxs, `ServiceSid="restricted"`, `ServiceSid="unrestricted"`, 1)), "service SID type")
	wantViolation(t, mk(strings.Replace(goodWxs, ` ServiceSid="restricted"`, ``, 1)), "ServiceSid")
	wantViolation(t, mk(strings.Replace(goodWxs, `SeChangeNotifyPrivilege"`, `SeChangeNotifyPrivilege SeBackupPrivilege"`, 1)), "RequiredPrivileges")
	wantViolation(t, mk(strings.Replace(goodWxs, ` RequiredPrivileges="SeChangeNotifyPrivilege"`, ``, 1)), "RequiredPrivileges")
	wantViolation(t, mk(strings.Replace(goodWxs, `Start="auto"`, `Start="auto" Password="x"`, 1)), "Password")
	wantViolation(t, mk(`<Wix><Package/></Wix>`), "no ServiceInstall")
	// Last-wins: an unrestricted ServiceConfig followed by a restricted one must not pass.
	wantViolation(t, mk(strings.Replace(goodWxs, `<ServiceConfig ServiceSid="restricted"`,
		`<ServiceConfig ServiceSid="unrestricted" /><ServiceConfig ServiceSid="restricted"`, 1)), "service SID type")
	// And the reverse order.
	wantViolation(t, mk(strings.Replace(goodWxs, `RequiredPrivileges="SeChangeNotifyPrivilege" />`,
		`RequiredPrivileges="SeChangeNotifyPrivilege" /><ServiceConfig ServiceSid="unrestricted" />`, 1)), "service SID type")
	// Two ServiceInstall elements.
	wantViolation(t, mk(strings.Replace(goodWxs, `</Package>`, strings.SplitN(strings.SplitN(goodWxs, "<Package Name=\"activeDIQ Agent\">", 2)[1], "</Package>", 2)[0]+`</Package>`, 1)), "exactly one")
	// The agent is found by its body when the file name does not say so.
	root := t.TempDir()
	write(t, root, "packaging/windows/product.wxs", strings.Replace(goodWxs, `NT SERVICE\activeDIQAgent`, `LocalSystem`, 1))
	wantViolation(t, checkInstaller(root), "LocalSystem")
	// Scripts and custom actions are MSI source too.
	scriptAllow := func(allow []string, name, body string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", goodWxs)
		write(t, r, "packaging/windows/"+name, body)
		return checkInstallerAllow(r, allow)
	}
	script := func(name, body string) Result { return scriptAllow(nil, name, body) }
	// Deny by default: a script in the agent packaging fails unless a reviewed entry lists it.
	good := "sc.exe config activeDIQAgent obj= \"NT SERVICE\\activeDIQAgent\"\n"
	wantViolation(t, script("Install-Agent.ps1", good), "is a script in the agent packaging")
	wantClean(t, scriptAllow([]string{"packaging/windows/Install-Agent.ps1"}, "Install-Agent.ps1", good))
	// An allowlisted script is still judged by content.
	wantViolation(t, scriptAllow([]string{"packaging/windows/Install-Agent.ps1"}, "Install-Agent.ps1", "sc.exe config activeDIQAgent obj= LocalSystem\n"), "LocalSystem")
	wantViolation(t, script("Install-Agent.ps1", "sc.exe config activeDIQAgent obj= LocalSystem\n"), "LocalSystem")
	wantViolation(t, script("Install-Agent.ps1", "sc.exe config activeDIQAgent obj= CORP\\svc-agent password= x\n"), "other than")
	wantViolation(t, script("Install-Agent.ps1", "Set-Service activeDIQAgent -Credential $c\n"), "other than")
	wantViolation(t, script("ca.cmd", "sc config activediqagent obj= .\\admin\n"), "other than")
	// The service registry key sets account, SID type and privileges without ServiceInstall.
	for _, v := range []string{`ObjectName" Value=".\svc-admin`, `ServiceSidType" Value="0`, `RequiredPrivileges" Value="SeDebugPrivilege`} {
		wantViolation(t, script("reg.wxs", `<Wix><Component><RegistryValue Root="HKLM" Key="SYSTEM\CurrentControlSet\\Services\activeDIQAgent" Name="`+v+`" /></Component></Wix>`), "Services registry key")
	}
	wantViolation(t, script("Install-Agent.ps1", "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\activeDIQAgent' ObjectName x\n"), "Services registry key")
	wantViolation(t, script("Install-Agent.ps1", "reg add HKLM\\SYSTEM\\ControlSet001\\Services\\activeDIQAgent /v ObjectName\n"), "Services registry key")
	// WMI / CIM account changes.
	wantViolation(t, script("Install-Agent.ps1", "Invoke-CimMethod -Query \"SELECT * FROM Win32_Service WHERE Name='activeDIQAgent'\" -MethodName Change -Arguments @{StartName='.\\svc-admin'}\n"), "other than")
	wantViolation(t, script("ca.js", "// activediq-agent\nsvc.ChangeServiceConfig(x)\n"), "other than")
	// UTF-16LE (PowerShell 5.1 'Unicode') and BE with and without a BOM are decoded, not skipped.
	u16 := func(s string, le, bom bool) string {
		var b []byte
		if bom && le {
			b = append(b, 0xFF, 0xFE)
		} else if bom {
			b = append(b, 0xFE, 0xFF)
		}
		for _, r := range s {
			if le {
				b = append(b, byte(r), 0)
			} else {
				b = append(b, 0, byte(r))
			}
		}
		return string(b)
	}
	bad16 := "sc.exe config activeDIQAgent obj= LocalSystem\n"
	wantViolation(t, script("Install-Agent.ps1", u16(bad16, true, true)), "LocalSystem")
	wantViolation(t, script("Install-Agent.ps1", u16(bad16, false, true)), "LocalSystem")
	wantViolation(t, script("Install-Agent.ps1", u16(bad16, true, false)), "LocalSystem")
	wantClean(t, scriptAllow([]string{"packaging/windows/Install-Agent.ps1"}, "Install-Agent.ps1", u16(good, true, true)))
	// A neutral file name inside an agent/ directory is selected by relative path.
	dir := t.TempDir()
	write(t, dir, "packaging/windows/agent/Product.wxs", goodWxs)
	write(t, dir, "packaging/windows/agent/setup.cmd", "sc config x obj= LocalSystem\n")
	wantViolation(t, checkInstaller(dir), "LocalSystem")
	// An agent-path file that is not text fails closed; a known binary extension does not.
	opaque := t.TempDir()
	write(t, opaque, "packaging/windows/agent.wxs", goodWxs)
	write(t, opaque, "packaging/windows/agent/blob.dat", "abcdefghijklmnop\x00qrstuvwxyz0123456789ABCDEFGHIJ")
	wantViolation(t, checkInstaller(opaque), "cannot be read as text")
	write(t, opaque, "packaging/windows/agent/blob.dat", "")
	os.Remove(filepath.Join(opaque, "packaging/windows/agent/blob.dat"))
	write(t, opaque, "packaging/windows/agent/icon.ico", "\x00\x01\x02\x00")
	wantClean(t, checkInstaller(opaque))
	third := func(name, body string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", goodWxs)
		write(t, r, "packaging/windows/core/"+name, body)
		return checkInstaller(r)
	}
	// Third security review: WiX files that never name the agent literally are judged too.
	wantViolation(t, third("Product.wxs", `<?define P="activeDIQ"?><Wix><Package><ServiceConfig ServiceName="$(var.P)Agent" ServiceSid="unrestricted"/></Package></Wix>`), "through a variable")
	wantViolation(t, third("Product.wxs", `<Wix><Package><ServiceInstall Name="$(var.P)Agent" Account="LocalSystem"/></Package></Wix>`), "LocalSystem")
	wantViolation(t, third("Product.wxs", `<Wix><Package><ServiceInstall Name="[SVC]" Account="x"/></Package></Wix>`), "through a variable")
	wantViolation(t, third("Product.wxs", `<Wix><Package><ServiceControl Name="!(bind.x)" Stop="both"/></Package></Wix>`), "through a variable")
	wantViolation(t, third("Product.wxs", `<Wix><Package><ServiceInstall Name="Other" Account="LocalSystem"/></Package></Wix>`), "LocalSystem")
	wantClean(t, third("Product.wxs", `<Wix><Package><ServiceInstall Name="Other" Account="NT SERVICE\Other" ServiceSid="restricted" RequiredPrivileges="SeChangeNotifyPrivilege"/></Package></Wix>`))
	// Fifth review, 1: DOCTYPE/ENTITY and named entities are denied in every WiX file.
	ent := `<!DOCTYPE Wix [<!ENTITY g "Agent">]><Wix><Package><Component><ServiceInstall Name="activeDIQ&g;" Account="NT SERVICE\activeDIQ&g;"><ServiceConfig ServiceName="activeDIQ&g;" ServiceSid="unrestricted" RequiredPrivileges="SeDebugPrivilege"/></ServiceInstall></Component></Package></Wix>`
	wantViolation(t, third("core.wxs", ent), "DOCTYPE or ENTITY")
	wantViolation(t, third("core.wxs", `<Wix><Package><ServiceInstall Name="Other&nbsp;" Account="x"/></Package></Wix>`), "named entity")
	wantClean(t, third("core.wxs", `<Wix><Package><ServiceInstall Name="Other" Account="NT SERVICE\Other" ServiceSid="restricted" RequiredPrivileges="SeChangeNotifyPrivilege"/><X a="a&amp;b &lt;"/></Package></Wix>`))
	// Fifth review, 2: WiX outside packaging/ is MSI source too.
	outside := func(rel, body string) Result {
		r := t.TempDir()
		write(t, r, rel, body)
		return checkInstaller(r)
	}
	wantViolation(t, outside("installer/agent.wxs", `<Wix><Package><ServiceInstall Name="activeDIQAgent" Account="LocalSystem"/></Package></Wix>`), "LocalSystem")
	wantViolation(t, outside("src/Product.wxs.in", `<Wix/>`), "template or transform")
	wantViolation(t, outside("tools/x/a.wixproj", `<Project>LocalSystem</Project>`), "LocalSystem")
	if r := outside("testdata/agent.wxs", `<Wix><ServiceInstall Name="activeDIQAgent" Account="LocalSystem"/></Wix>`); r.Inactive == "" {
		t.Fatalf("fixtures under testdata/ must not be scanned: %v", r.Violations)
	}
	// T-0664: the WiX SDK compiles **/*.wxs, so testdata/ and node_modules/ hide nothing under packaging/
	// or below a .wixproj.
	lsys := `<Wix><Package><ServiceInstall Name="skzHelper" Account="LocalSystem"/></Package></Wix>`
	wantViolation(t, third("../testdata/x.wxs", lsys), "LocalSystem")
	wantViolation(t, third("../node_modules/x.wxs", lsys), "LocalSystem")
	{
		r := t.TempDir()
		write(t, r, "src/App.wixproj", `<Project/>`)
		write(t, r, "src/testdata/x.wxs", lsys)
		wantViolation(t, checkInstaller(r), "LocalSystem")
	}
	// Fifth review, 3: every service gets the full pin; an allowlisted Id is the only exception.
	helper := `<Wix><Package><Component><ServiceInstall Id="SkzHelper" Name="skzHelper" Account="NT SERVICE\skzHelper"><ServiceConfig ServiceSid="unrestricted" RequiredPrivileges="SeDebugPrivilege,SeBackupPrivilege"/></ServiceInstall></Component></Package></Wix>`
	wantViolation(t, third("Helper.wxs", helper), "service SID type of")
	wantViolation(t, third("Helper.wxs", helper), "RequiredPrivileges of")
	wantViolation(t, third("Helper.wxs", `<Wix><Package><ServiceInstall Name="skzHelper" Account="NT SERVICE\skzHelper"/></Package></Wix>`), "no ServiceSid")
	wantViolation(t, third("Helper.wxs", `<Wix><Package><ServiceInstall Name="skzHelper" Account="NT SERVICE\skzHelper" ServiceSid="restricted" RequiredPrivileges="SeChangeNotifyPrivilege"/><ServiceConfig ServiceName="skzHelper" ServiceSid="unrestricted"/></Package></Wix>`), "service SID type of")
	wantViolation(t, third("Helper.wxs", `<Wix><Package><ServiceConfig ServiceName="existingSvc" RequiredPrivileges="SeDebugPrivilege"/></Package></Wix>`), "other than the pin")
	{
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", goodWxs)
		write(t, r, "packaging/windows/core/Helper.wxs", helper)
		wantClean(t, checkInstallerAllow(r, []string{"SkzHelper"}))
	}
	// A neighbouring service naming the agent literally is judged against the pin.
	wantViolation(t, third("Product.wxs", `<Wix><Package><ServiceConfig ServiceName="activeDIQAgent" ServiceSid="unrestricted"/></Package></Wix>`), "other than the pin")
	// Custom actions: deny by default, whatever their spelling.
	ca := func(allow []string, body string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", goodWxs)
		write(t, r, "packaging/windows/core/ca.wxs", `<Wix><Package>`+body+`</Package></Wix>`)
		return checkInstallerAllow(r, allow)
	}
	wantViolation(t, ca(nil, `<CustomAction Id="CA_Acct" ExeCommand='"[SystemFolder]sc.exe" config activeDIQAgent obj= [ACCT] password= [PW]' Execute="deferred"/><Property Id="ACCT" Value=".\svc-admin"/>`), "runs code at install time")
	wantViolation(t, ca(nil, `<CustomAction Id="CA_Vbs" Script="vbscript">sc = "sc config x obj= " &amp; Chr(46) &amp; "\svc-admin"</CustomAction>`), "runs code at install time")
	wantViolation(t, ca(nil, `<CustomAction Id="CA_Dll" BinaryRef="B" DllEntry="Go"/>`), "runs code at install time")
	wantViolation(t, ca(nil, `<Binary Id="B" SourceFile="x.dll"/>`), "runs code at install time")
	wantViolation(t, ca([]string{"CA_Other"}, `<CustomAction Id="CA_Acct" ExeCommand="x"/>`), "runs code at install time")
	wantClean(t, ca([]string{"CA_Reviewed"}, `<CustomAction Id="CA_Reviewed" ExeCommand="x"/>`))
	// HKLM\SYSTEM registry writes, including property-split keys and nested RegistryKey elements.
	for name, body := range map[string]string{
		"literal":     `<RegistryValue Root="HKLM" Key="SYSTEM\CurrentControlSet\Services\activeDIQAgent" Name="ObjectName" Value="x"/>`,
		"split":       `<RegistryValue Root="HKLM" Key="SYSTEM\CurrentControlSet\[K]" Name="ObjectName" Value="x"/>`,
		"var":         `<RegistryValue Root="HKLM" Key="$(var.K)" Name="ObjectName" Value="x"/>`,
		"nested":      `<RegistryKey Root="HKLM" Key="SYSTEM"><RegistryKey Key="Foo"><RegistryValue Name="a" Value="b"/></RegistryKey></RegistryKey>`,
		"hkmu":        `<RegistryValue Root="HKMU" Key="System\Foo" Name="a" Value="b"/>`,
		"remove":      `<RemoveRegistryKey Root="HKLM" Key="SYSTEM\Foo" Action="removeOnInstall"/>`,
		"dynamicroot": `<RegistryValue Root="[R]" Key="Foo" Name="a" Value="b"/>`,
	} {
		wantViolation(t, ca(nil, body), "HKLM")
		_ = name
	}
	wantClean(t, ca(nil, `<RegistryValue Root="HKLM" Key="SOFTWARE\skenzeriq\activeDIQ" Name="Version" Value="1"/><RegistryValue Root="HKCU" Key="System\x" Name="a" Value="b"/>`))
	wantViolation(t, script("custom.js", "// activediq-agent\nvar a = 'NT AUTHORITY\\\\SYSTEM';\n"), "NT AUTHORITY")

	// Fourth security review: judge the parsed, entity-decoded structure; deny services, ACLs and file types by default.
	// 1. An entity-encoded agent name still gets the full pin (no agent file, no raw match).
	enc := func(body string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/core/Product.wxs", `<Wix><Package>`+body+`</Package></Wix>`)
		return checkInstaller(r)
	}
	wantViolation(t, enc(`<ServiceInstall Name="activeDIQ&#65;gent" Account="NT SERVICE\activeDIQ&#65;gent"><ServiceConfig ServiceName="activeDIQ&#65;gent" ServiceSid="unrestricted" RequiredPrivileges="SeDebugPrivilege,SeBackupPrivilege"/></ServiceInstall>`), "service SID type")
	wantViolation(t, enc(`<ServiceInstall Name="activeDIQ&#65;gent" Account="NT SERVICE\activeDIQ&#65;gent"><ServiceConfig ServiceName="activeDIQ&#65;gent" ServiceSid="unrestricted" RequiredPrivileges="SeDebugPrivilege"/></ServiceInstall>`), "RequiredPrivileges")
	wantViolation(t, enc(`<ServiceInstall Name="Other" Account="&#76;ocalSystem"/>`), "LocalSystem")
	wantViolation(t, enc(`<ServiceInstall Name="Other" Account="NT SERVICE\Other"/><Property Id="X" Value="&#65;"/>`), "character reference")
	// 2. Implicit LocalSystem and foreign accounts; one service per agent Component and per agent file.
	wantViolation(t, enc(`<ServiceInstall Name="skzHelper" Type="ownProcess" Start="auto" ErrorControl="normal"/>`), "no Account")
	wantViolation(t, enc(`<ServiceInstall Name="Other" Account="NT SERVICE\Different"/>`), "its own virtual account")
	comp := strings.Replace(goodWxs, `<ServiceInstall Name="activediq-agent"`, `<Component Id="C"><ServiceInstall Name="skzHelper" Account="NT SERVICE\skzHelper"/><ServiceInstall Name="activediq-agent"`, 1)
	comp = strings.Replace(comp, `</ServiceInstall>
  </Package>`, `</ServiceInstall></Component>
  </Package>`, 1)
	wantViolation(t, mk(comp), "exactly one")
	wantViolation(t, enc(`<Component Id="C"><ServiceInstall Name="activeDIQ&#65;gent" Account="NT SERVICE\activeDIQ&#65;gent"/><ServiceInstall Name="x" Account=".\svc"/></Component>`), "exactly one")
	wantClean(t, func() Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", goodWxs)
		write(t, r, "packaging/windows/core/Product.wxs", `<Wix><Package><ServiceInstall Id="SvcOther" Name="Other" Account=".\svc"/></Package></Wix>`)
		return checkInstallerAllow(r, []string{"SvcOther"})
	}())
	// 3. Any Permission/PermissionEx/util:PermissionEx fails unless the parent Id is reviewed.
	svcWith := func(p string) string {
		return strings.Replace(goodWxs, `<ServiceConfig ServiceSid`, p+`<ServiceConfig ServiceSid`, 1)
	}
	wantViolation(t, mk(svcWith(`<PermissionEx Sddl="D:(A;;GA;;;WD)"/>`)), "grants an ACL")
	wantViolation(t, mk(svcWith(`<util:PermissionEx xmlns:util="u" User="Everyone" GenericAll="yes"/>`)), "grants an ACL")
	wantViolation(t, mk(strings.Replace(goodWxs, `</Package>`, `<CreateFolder Directory="D"><Permission User="Users" GenericAll="yes"/></CreateFolder></Package>`, 1)), "grants an ACL")
	wantClean(t, func() Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", strings.Replace(goodWxs, `</Package>`, `<CreateFolder Id="DataDir" Directory="D"><PermissionEx Sddl="x"/></CreateFolder></Package>`, 1))
		return checkInstallerAllow(r, []string{"DataDir"})
	}())
	// 4. Templates and unknown file types in the agent packaging are denied unless reviewed.
	tmpl := func(allow []string, rel, body string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent/Product.wxs", goodWxs)
		write(t, r, rel, body)
		return checkInstallerAllow(r, allow)
	}
	tbody := `<ServiceInstall Name="activeDIQAgent" Account="NT SERVICE\activeDIQAgent"><ServiceConfig ServiceSid="unrestricted"/></ServiceInstall>`
	wantViolation(t, tmpl(nil, "packaging/windows/agent/Product.wxs.in", tbody), "template or transform")
	wantViolation(t, tmpl(nil, "packaging/windows/core/heat.xslt", "<x/>"), "template or transform")
	wantViolation(t, tmpl(nil, "packaging/windows/agent/notes.txt", "activeDIQAgent"), "unknown file type")
	wantClean(t, tmpl([]string{"packaging/windows/agent/Product.wxs.in"}, "packaging/windows/agent/Product.wxs.in", "x"))
}

func TestA4Judge(t *testing.T) {
	allow := []string{"github.com/skenzeriq/activediq/internal/platform/agentpolicy", "example.com/ok/..."}
	std := func(p string) pkgInfo { return pkgInfo{Path: p, Std: true} }
	ext := func(p string) pkgInfo { return pkgInfo{Path: p} }
	clean := []pkgInfo{std("fmt"), std("crypto/tls"), ext("github.com/skenzeriq/activediq/internal/platform/agentpolicy"), ext("example.com/ok/sub/pkg")}
	if v := judgeDeps(clean, allow); len(v) != 0 {
		t.Fatalf("clean closure rejected: %v", v)
	}
	for _, bad := range []string{
		"github.com/go-ldap/ldap/v3", "github.com/go-krb5/krb5/client", "github.com/alexbrainman/sspi/negotiate",
		"github.com/skenzeriq/activediq/internal/directory/client", "github.com/skenzeriq/activediq/internal/connector/ad",
		"golang.org/x/sys/windows/registry",
		// Real clients the first (denylist-only) version let through, and one it could never know.
		"github.com/hirochachacha/go-smb2", "github.com/nmcclain/ldap", "github.com/mavricknz/ldap",
		"example.org/some/unlisted/ldapclient", "google.golang.org/grpc",
	} {
		if v := judgeDeps([]pkgInfo{std("fmt"), ext(bad)}, allow); len(v) == 0 {
			t.Errorf("%s accepted in the agent closure", bad)
		}
	}
	// Even if an allowlist line is added by mistake, the named bans still say no.
	if v := judgeDeps([]pkgInfo{ext("github.com/hirochachacha/go-smb2")}, []string{"github.com/hirochachacha/go-smb2"}); len(v) == 0 {
		t.Error("named ban overridden by the allowlist")
	}
}

func TestA4RealClosure(t *testing.T) {
	root := t.TempDir()
	allow := []string{"fx.test/cmd/agent"}
	write(t, root, "go.mod", "module fx.test\n\ngo 1.22\n")
	write(t, root, "cmd/agent/main.go", "package main\n\nfunc main() {}\n")
	wantClean(t, checkAgentImports(root, allow))
	write(t, root, "internal/directory/client/c.go", "package client\n")
	write(t, root, "cmd/agent/main.go", "package main\n\nimport _ \"fx.test/internal/directory/client\"\n\nfunc main() {}\n")
	wantViolation(t, checkAgentImports(root, allow), "internal/directory/client")
	// An own package that is not on the allowlist is refused, not waved through.
	write(t, root, "internal/other/o.go", "package other\n")
	write(t, root, "cmd/agent/main.go", "package main\n\nimport _ \"fx.test/internal/other\"\n\nfunc main() {}\n")
	wantViolation(t, checkAgentImports(root, allow), "not on the allowlist")
	wantClean(t, checkAgentImports(root, append(allow, "fx.test/internal/other")))
}

func TestADRAcceptedWhileInactive(t *testing.T) {
	root := t.TempDir()
	write(t, root, "knowledge/development/decisions/0006-x.md", "---\nstatus: accepted\n---\nbody\n")
	res := Run(root, Options{SkipTests: true})
	for _, r := range res {
		if r.ID == "ADR" && len(r.Violations) > 0 {
			return
		}
	}
	t.Fatal("an accepted ADR-0006 with inactive checks must fail")
}

func TestJudgeTests(t *testing.T) {
	const pa = "github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	const ps = pa + "/signer"
	ev := func(pkg, test, action string) string {
		return `{"Action":"` + action + `","Package":"` + pkg + `","Test":"` + test + `"}` + "\n"
	}
	all := func(skip map[string]string) string {
		var b strings.Builder
		for _, rt := range requiredTests {
			pkg := pa
			if rt.ID == "P8" {
				pkg = ps
			}
			act := "pass"
			if a, ok := skip[rt.Prefix]; ok {
				if a == "missing" {
					continue
				}
				act = a
			}
			b.WriteString(ev(pkg, rt.Prefix+"Something", act))
		}
		return b.String()
	}
	if v := judgeTests([]byte(all(nil))); len(v) != 0 {
		t.Fatalf("clean run rejected: %v", v)
	}
	for _, c := range []struct{ prefix, action, want string }{
		{"TestP1", "fail", "P1"},    // wrong-tenant policy accepted
		{"TestP2", "fail", "P2"},    // replay accepted
		{"TestP3", "skip", "P3"},    // skipped is not passed
		{"TestP8", "missing", "P8"}, // deleted test
		{"TestF1", "fail", "F1"},    // out-of-bounds policy accepted
		{"FuzzF1", "missing", "F1"}, // fuzz target removed
	} {
		v := judgeTests([]byte(all(map[string]string{c.prefix: c.action})))
		if len(v) == 0 || !strings.HasPrefix(v[0], c.want) {
			t.Errorf("%s %s: want %s violation, got %v", c.prefix, c.action, c.want, v)
		}
	}
	// A failing subtest fails its parent even when the parent line says pass.
	sub := all(nil) + ev(pa, "TestF1OutOfBoundsPolicyRejected/min_length_0", "fail")
	if v := judgeTests([]byte(sub)); len(v) == 0 {
		t.Fatal("failing subtest ignored")
	}
}

func TestRunOnRepositoryTreeIsConsistent(t *testing.T) {
	// The real tree: every check either runs clean or says why it is inactive.
	res := Run("../../..", Options{SkipTests: true, Only: "R3,R4,A1,A4"})
	for _, r := range res {
		if len(r.Violations) != 0 {
			t.Errorf("%s: %v", r.ID, r.Violations)
		}
	}
}

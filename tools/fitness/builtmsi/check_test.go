package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// idt writes one table in msidump's format (CRLF).
func idt(t *testing.T, dir, table string, cols []string, keys []string, rows ...[]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString(strings.Join(cols, "\t") + "\r\n")
	ty := make([]string, len(cols))
	for i := range ty {
		ty[i] = "s255"
	}
	b.WriteString(strings.Join(ty, "\t") + "\r\n")
	b.WriteString(table + "\t" + strings.Join(keys, "\t") + "\r\n")
	for _, r := range rows {
		b.WriteString(strings.Join(r, "\t") + "\r\n")
	}
	if err := os.WriteFile(filepath.Join(dir, table+".idt"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

var siCols = []string{"ServiceInstall", "Name", "StartName", "Password", "Component_"}
var mcCols = []string{"MsiServiceConfig", "Name", "Event", "ConfigType", "Argument", "Component_"}
var caCols = []string{"Action", "Type", "Source", "Target"}

type fx struct {
	si, mc, ca [][]string
}

func goodFx() fx {
	return fx{
		si: [][]string{{"Svc", "activeDIQAgent", `NT SERVICE\activeDIQAgent`, "", "C1"}},
		mc: [][]string{
			{"c1", "activeDIQAgent", "1", "3", "3", "C1"},
			{"c2", "activeDIQAgent", "1", "4", "SeChangeNotifyPrivilege", "C1"},
		},
		ca: [][]string{{"WriteConfig", "3106", "AgentDir", `"[AgentDir]agentsetup.exe" write-config`}},
	}
}

func opts() Options {
	pb, _ := os.ReadFile("pinned-actions.txt")
	ab, _ := os.ReadFile("../agenthost/installer-allow.txt")
	return Options{Pinned: ParsePinned(string(pb)), Allow: splitLines(string(ab)), RequireAgent: true}
}

func run(t *testing.T, f fx) []string {
	dir := t.TempDir()
	idt(t, dir, "ServiceInstall", siCols, []string{"ServiceInstall"}, f.si...)
	idt(t, dir, "MsiServiceConfig", mcCols, []string{"MsiServiceConfig"}, f.mc...)
	idt(t, dir, "CustomAction", caCols, []string{"Action"}, f.ca...)
	tabs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return Judge(tabs, opts())
}

func wantFail(t *testing.T, f fx, sub string) {
	t.Helper()
	v := run(t, f)
	if !strings.Contains(strings.Join(v, "\n"), sub) {
		t.Fatalf("want a violation containing %q, got %q", sub, v)
	}
}

func TestPass(t *testing.T) {
	if v := run(t, goodFx()); len(v) != 0 {
		t.Fatalf("clean MSI failed: %q", v)
	}
}

func TestLocalSystemNamesRow(t *testing.T) {
	f := goodFx()
	f.si[0][2] = "LocalSystem"
	wantFail(t, f, `ServiceInstall row "Svc"`)
	f.si[0][2] = ""
	wantFail(t, f, "runs as LocalSystem")
	f.si[0][2] = `NT AUTHORITY\NetworkService`
	wantFail(t, f, "not the pinned")
}

func TestPasswordAndExtraService(t *testing.T) {
	f := goodFx()
	f.si[0][3] = "x"
	wantFail(t, f, "has a Password")
	f = goodFx()
	f.si = append(f.si, []string{"Helper", "skzHelper", "LocalSystem", "", "C2"})
	wantFail(t, f, `ServiceInstall row "Helper"`)
	f = goodFx()
	f.si = append(f.si, []string{"Svc2", "activeDIQAgent", `NT SERVICE\activeDIQAgent`, "", "C2"})
	wantFail(t, f, "want exactly 1")
	f = goodFx()
	f.si = nil
	wantFail(t, f, "want exactly 1")
}

func TestSIDTypeAndPrivileges(t *testing.T) {
	f := goodFx()
	f.mc[0][4] = "1"
	wantFail(t, f, "must be 3 (restricted)")
	f = goodFx()
	f.mc = f.mc[1:]
	wantFail(t, f, "no MsiServiceConfig row of ConfigType 3")
	f = goodFx()
	f.mc[1][4] = "SeChangeNotifyPrivilege[~]SeBackupPrivilege"
	wantFail(t, f, "must be exactly SeChangeNotifyPrivilege")
	f = goodFx()
	f.mc = f.mc[:1]
	wantFail(t, f, "no MsiServiceConfig row of ConfigType 4")
	f = goodFx()
	f.mc = append(f.mc, []string{"c3", "Spooler", "1", "4", "SeDebugPrivilege", "C1"})
	wantFail(t, f, `MsiServiceConfig row "c3"`)
}

func TestCustomActions(t *testing.T) {
	f := goodFx()
	f.ca = append(f.ca, []string{"Sneaky", "3106", "AgentDir", `"[AgentDir]x.exe"`})
	wantFail(t, f, `CustomAction row "Sneaky"`)
	f = goodFx()
	f.ca[0][1] = "3110"
	wantFail(t, f, "differ from the reviewed")
	f = goodFx()
	f.ca[0][3] = `"[AgentDir]agentsetup.exe" write-config --evil`
	wantFail(t, f, "differ from the reviewed")
	f = goodFx()
	f.ca = [][]string{{"WriteConfig", "1", "Bin", "Entry"}}
	wantFail(t, f, "dll-from-binary")
}

func TestOtherTables(t *testing.T) {
	dir := t.TempDir()
	f := goodFx()
	idt(t, dir, "ServiceInstall", siCols, []string{"ServiceInstall"}, f.si...)
	idt(t, dir, "MsiServiceConfig", mcCols, []string{"MsiServiceConfig"}, f.mc...)
	idt(t, dir, "Binary", []string{"Name", "Data"}, []string{"Name"}, []string{"evil", "x"})
	idt(t, dir, "MsiLockPermissionsEx", []string{"MsiLockPermissionsEx", "LockObject", "Table", "SDDLText"}, []string{"MsiLockPermissionsEx"}, []string{"p1", "DataDir", "CreateFolder", "D:(A;;GA;;;WD)"})
	idt(t, dir, "Registry", []string{"Registry", "Root", "Key", "Name", "Value", "Component_"}, []string{"Registry"}, []string{"r1", "2", `SYSTEM\CurrentControlSet\Services\activeDIQAgent`, "ObjectName", "LocalSystem", "C1"}, []string{"r2", "2", `SOFTWARE\skenzeriq`, "v", "1", "C1"})
	tabs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(Judge(tabs, opts()), "\n")
	for _, s := range []string{`Binary row "evil"`, `MsiLockPermissionsEx row "p1"`, `Registry row "r1"`} {
		if !strings.Contains(all, s) {
			t.Errorf("missing %q in %s", s, all)
		}
	}
	if strings.Contains(all, `"r2"`) {
		t.Errorf("HKLM\\SOFTWARE flagged: %s", all)
	}
}

// End to end: a real MSI built by wixl (msitools), dumped by msidump. Skipped without msitools; the proof
// script (make ci-proof) requires them and runs the same cases.
func TestRealMSI(t *testing.T) {
	if _, err := exec.LookPath("wixl"); err != nil {
		t.Skip("wixl not installed")
	}
	if _, err := exec.LookPath("msidump"); err != nil {
		t.Skip("msidump not installed")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "a.wxs")
	wxs := strings.ReplaceAll(realWXS, "ACCOUNT", "LocalSystem")
	if err := os.WriteFile(src, []byte(wxs), 0o600); err != nil {
		t.Fatal(err)
	}
	msi := filepath.Join(dir, "a.msi")
	cmd := exec.Command("wixl", "-o", msi, src)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wixl: %v %s", err, out)
	}
	out := filepath.Join(dir, "idt")
	_ = os.Mkdir(out, 0o700)
	if b, err := exec.Command("msidump", "-t", "-d", out, msi).CombinedOutput(); err != nil {
		t.Fatalf("msidump: %v %s", err, b)
	}
	tabs, err := LoadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	v := strings.Join(Judge(tabs, opts()), "\n")
	if !strings.Contains(v, `ServiceInstall row "Svc"`) || !strings.Contains(v, "LocalSystem") {
		t.Fatalf("real MSI with LocalSystem not caught: %q", v)
	}
}

const realWXS = `<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
 <Product Id="*" Name="x" Language="1033" Version="1.0.0" Manufacturer="m" UpgradeCode="11111111-2222-3333-4444-555555555555">
  <Package Compressed="yes" InstallerVersion="500"/>
  <Media Id="1" Cabinet="a.cab" EmbedCab="yes"/>
  <Directory Id="TARGETDIR" Name="SourceDir"><Directory Id="AgentDir" Name="agent">
   <Component Id="C1" Guid="11111111-2222-3333-4444-555555555556"><File Id="F1" Source="a.wxs" KeyPath="yes"/>
    <ServiceInstall Id="Svc" Name="activeDIQAgent" Type="ownProcess" Start="auto" ErrorControl="normal" Account="ACCOUNT"/>
   </Component></Directory></Directory>
  <Feature Id="F" Level="1"><ComponentRef Id="C1"/></Feature>
 </Product></Wix>
`

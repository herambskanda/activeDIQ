package main

import (
	"strings"
	"testing"
)

// T-0756: a Permission pin's directory chain may only use private (mixed-case) Ids, and none of them may be
// listed in SecureCustomProperties. TARGETDIR is exempt only as a root followed by a standard folder.
func TestT0756PrivateChainIds(t *testing.T) {
	const sddl = `D:(A;;GA;;;BU)`
	px := `<PermissionEx Sddl="` + sddl + `"/>`
	pin := func(chain string) {
		pinnedPermissions["CreateFolder/CF"] = map[string]string{"": "PermissionEx", "sddl": sddl, "parent.directory": chain}
	}
	defer delete(pinnedPermissions, "CreateFolder/CF")
	leaf := func(inner string) string {
		return inner[:strings.Index(inner, "@")] + `<Component Id="C"><CreateFolder Id="CF">` + px + `</CreateFolder></Component>` + inner[strings.Index(inner, "@")+1:]
	}
	run := func(frags ...string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", strings.Replace(goodWxs, `</Package>`, frags[0]+`</Package>`, 1))
		for i, f := range frags[1:] {
			write(t, r, "packaging/windows/other"+string(rune('a'+i))+".wxs", `<Wix><Fragment>`+f+`</Fragment></Wix>`)
		}
		return checkInstallerAllow(r, nil)
	}
	const msg = "no lowercase letter"

	// Acceptance 1: private Ids pass, an all-uppercase Id anywhere in the chain fails.
	pin("Directory:LogDir:Logs")
	wantClean(t, run(leaf(`<Directory Id="LogDir" Name="Logs">@</Directory>`)))
	pin("Directory:LOGDIR:Logs")
	wantViolation(t, run(leaf(`<Directory Id="LOGDIR" Name="Logs">@</Directory>`)), msg)
	pin("Directory:INSTALLFOLDER:x")
	wantViolation(t, run(leaf(`<Directory Id="INSTALLFOLDER" Name="x">@</Directory>`)), msg)
	pin("Directory:AGENT_DIR1:a/Directory:LogDir:Logs")
	wantViolation(t, run(leaf(`<Directory Id="AGENT_DIR1" Name="a"><Directory Id="LogDir" Name="Logs">@</Directory></Directory>`)), msg)
	pin("Directory:Outer:o/Directory:INNER:i")
	wantViolation(t, run(leaf(`<Directory Id="Outer" Name="o"><Directory Id="INNER" Name="i">@</Directory></Directory>`)), msg)

	// TARGETDIR: exempt only as the root with a standard folder next; never blanket, never as the leaf.
	pin("Directory:TARGETDIR:SourceDir/Directory:ProgramFiles64Folder:pf/Directory:AgentDir:Agent")
	wantClean(t, run(leaf(`<Directory Id="TARGETDIR" Name="SourceDir"><Directory Id="ProgramFiles64Folder" Name="pf"><Directory Id="AgentDir" Name="Agent">@</Directory></Directory></Directory>`)))
	pin("Directory:TARGETDIR:SourceDir/Directory:AgentDir:Agent")
	wantViolation(t, run(leaf(`<Directory Id="TARGETDIR" Name="SourceDir"><Directory Id="AgentDir" Name="Agent">@</Directory></Directory>`)), msg)
	pin("Directory:TARGETDIR:SourceDir")
	wantViolation(t, run(leaf(`<Directory Id="TARGETDIR" Name="SourceDir">@</Directory>`)), msg)
	pin("Directory:ProgramFiles64Folder:pf/Directory:TARGETDIR:t/Directory:AgentDir:Agent")
	wantViolation(t, run(leaf(`<Directory Id="ProgramFiles64Folder" Name="pf"><Directory Id="TARGETDIR" Name="t"><Directory Id="AgentDir" Name="Agent">@</Directory></Directory></Directory>`)), msg)
	pin("Directory:TARGETDIR:SourceDir/Directory:ProgramFiles64Folder:pf/Directory:UPPER:u")
	wantViolation(t, run(leaf(`<Directory Id="TARGETDIR" Name="SourceDir"><Directory Id="ProgramFiles64Folder" Name="pf"><Directory Id="UPPER" Name="u">@</Directory></Directory></Directory>`)), msg)

	// Acceptance 2: a private Id in the chain listed in SecureCustomProperties fails (any source, any form).
	pin("Directory:LogDir:Logs")
	dir := leaf(`<Directory Id="LogDir" Name="Logs">@</Directory>`)
	const sec = "listed in SecureCustomProperties"
	wantViolation(t, run(dir+`<Property Id="SecureCustomProperties" Value="Foo;LogDir"/>`), sec)
	wantViolation(t, run(dir, `<Property Id="SecureCustomProperties" Value="LogDir"/>`), sec)
	wantViolation(t, run(dir+`<SetProperty Id="SecureCustomProperties" Value="A; LogDir ;B" Before="CostFinalize"/>`), sec)
	wantViolation(t, run(dir+`<Property Id="LogDir" Secure="yes"/>`), sec)
	wantViolation(t, run(dir+`<Property Id="SecureCustomProperties" Value="[Other]"/>`), "SecureCustomProperties is built through")
	// Unrelated secure properties.
	wantClean(t, run(dir+`<Property Id="SecureCustomProperties" Value="Foo;Bar"/>`))
	wantClean(t, run(dir+`<Property Id="SomeFlag" Secure="yes" Value="1"/>`))
}

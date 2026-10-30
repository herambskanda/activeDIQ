package main

import (
	"strings"
	"testing"
)

// T-0742: SetDirectory/SetProperty are gated like CustomAction, a Property sharing a Directory's Id fails,
// and a Permission's parent directory may not be retargeted from anywhere in the installer source.
func TestT0742DirectoryRetarget(t *testing.T) {
	const sddl = `D:(A;;GA;;;BU)`
	px := `<PermissionEx Sddl="` + sddl + `"/>`
	pinnedPermissions["CreateFolder/CF"] = map[string]string{"": "PermissionEx", "sddl": sddl, "parent.directory": "Directory:LogDir:Logs"}
	defer delete(pinnedPermissions, "CreateFolder/CF")
	pinned := `<Directory Id="LogDir" Name="Logs"><Component Id="C"><CreateFolder Id="CF">` + px + `</CreateFolder></Component></Directory>`
	run := func(allow []string, frags ...string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", strings.Replace(goodWxs, `</Package>`, frags[0]+`</Package>`, 1))
		for i, f := range frags[1:] {
			write(t, r, "packaging/windows/other"+string(rune('a'+i))+".wxs", `<Wix><Fragment>`+f+`</Fragment></Wix>`)
		}
		return checkInstallerAllow(r, allow)
	}
	wantClean(t, run(nil, pinned))

	// 1. SetDirectory / SetProperty need a reviewed Id, like CustomAction.
	for _, el := range []string{`<SetDirectory Id="Other" Value="[System64Folder]"/>`, `<SetProperty Id="Other" Value="x" Before="CostFinalize"/>`} {
		wantViolation(t, run(nil, pinned+el), "runs code at install time")
		wantClean(t, run([]string{"Other"}, pinned+el))
	}
	// 3. A reviewed Id does not excuse retargeting a directory a Permission acts on: same file, other file.
	for _, el := range []string{
		`<SetDirectory Id="LogDir" Value="[System64Folder]"/>`,
		`<SetProperty Id="LogDir" Value="C:\Windows\System32"/>`,
		`<Property Id="LogDir" Value="C:\Windows\System32"/>`,
	} {
		wantViolation(t, run([]string{"LogDir"}, pinned+el), "retargets a directory that a Permission acts on")
		wantViolation(t, run([]string{"LogDir"}, pinned, el), "retargets a directory that a Permission acts on")
	}
	// The whole parent chain counts, not just the leaf.
	chained := `<Directory Id="Outer" Name="o"><Directory Id="LogDir" Name="Logs"><Component Id="C"><CreateFolder Id="CF">` + px + `</CreateFolder></Component></Directory></Directory>`
	pinnedPermissions["CreateFolder/CF"]["parent.directory"] = "Directory:Outer:o/Directory:LogDir:Logs"
	wantClean(t, run(nil, chained))
	wantViolation(t, run(nil, chained, `<Property Id="Outer" Value="C:\Windows"/>`), "retargets a directory that a Permission acts on")
	pinnedPermissions["CreateFolder/CF"]["parent.directory"] = "Directory:LogDir:Logs"

	// 2. A Property whose Id equals any Directory/StandardDirectory Id fails, with or without a permission.
	other := `<Directory Id="DataDir" Name="d"/>`
	wantViolation(t, run(nil, pinned+other+`<Property Id="DataDir" Value="C:\x"/>`), "also the Id of a Directory")
	wantViolation(t, run(nil, pinned, other, `<Property Id="DataDir" Value="C:\x"/>`), "also the Id of a Directory")
	wantViolation(t, run(nil, pinned+`<StandardDirectory Id="ProgramFiles6432Folder"/><Property Id="ProgramFiles6432Folder" Value="C:\x"/>`), "also the Id of a Directory")
	// An unrelated Property is fine.
	wantClean(t, run(nil, pinned+`<Property Id="SomeFlag" Value="1"/>`))

	// Type 35/51 CustomActions retarget too, even when allow-listed.
	for _, el := range []string{
		`<CustomAction Id="Ret" Directory="LogDir" Value="[System64Folder]"/>`,
		`<CustomAction Id="Ret" Property="LogDir" Value="C:\Windows\System32"/>`,
	} {
		wantViolation(t, run([]string{"Ret"}, pinned+el), "retargets a directory that a Permission acts on")
		wantViolation(t, run([]string{"Ret"}, pinned, el), "retargets a directory that a Permission acts on")
	}
	wantViolation(t, run([]string{"Ret"}, pinned+other+`<CustomAction Id="Ret" Directory="DataDir" Value="[System64Folder]"/>`), "also the Id of a Directory")
	// Directory without Value (working directory) and unrelated properties stay clean.
	wantClean(t, run([]string{"Ret"}, pinned+`<CustomAction Id="Ret" Directory="LogDir" ExeCommand="x"/>`))
	wantClean(t, run([]string{"Ret"}, pinned+`<CustomAction Id="Ret" Property="Flag" Value="1"/>`))

	// Fail closed on installer UI: formatted and indirect properties make every per-type rule bypassable.
	ui := func(el string) string { return `<UI><Dialog Id="D">` + el + `</Dialog></UI>` }
	for _, el := range []string{
		`<UI/>`,
		`<UIRef Id="WixUI_InstallDir"/>`,
		ui(`<Control Id="B" Type="PushButton"><Publish Event="[LogDir]" Value="C:\Windows\System32"/></Control>`),
		`<Property Id="P" Value="LogDir"/>` + ui(`<Control Id="B" Type="PushButton"><Publish Event="SetTargetPath" Value="[P]"/></Control>`),
		`<Property Id="P" Value="LogDir"/>` + ui(`<Control Id="E" Type="PathEdit" Property="P" Indirect="yes"/>`),
		ui(`<Control Id="E" Type="Edit" Property="LogDir"/>`),
		ui(`<Control Id="E" Type="ComboBox" Property="LogDir"/>`),
		ui(`<Control Id="E" Type="RadioButtonGroup" Property="LogDir"/>`),
		ui(`<Control Id="B" Type="PushButton"><Publish Event="SetTargetPath" Value=" LogDir "/></Control>`),
	} {
		wantViolation(t, run([]string{"Ret", "D", "B", "E", "P"}, pinned+el), "installer-allow.txt cannot approve one")
		wantViolation(t, run([]string{"Ret", "D", "B", "E", "P"}, pinned, el), "installer-allow.txt cannot approve one")
	}

	// Fail closed on namespaces: the WiX UI extension and unknown namespaces, even when allow-listed.
	for _, el := range []string{
		`<ui:WixUI xmlns:ui="http://wixtoolset.org/schemas/v4/wxs/ui" Id="WixUI_InstallDir" InstallDirectory="LogDir"/>`,
		`<x:Foo xmlns:x="urn:x"/>`,
	} {
		wantViolation(t, run([]string{"Ret", "WixUI_InstallDir"}, pinned+el), "not the WiX core namespace or a reviewed extension")
		wantViolation(t, run([]string{"Ret", "WixUI_InstallDir"}, pinned, el), "not the WiX core namespace or a reviewed extension")
	}
	wantClean(t, run(nil, pinned+`<util:Foo xmlns:util="http://wixtoolset.org/schemas/v4/wxs/util"/>`))

	// Variables hide the retarget Id: fail even when allow-listed.
	for _, el := range []string{
		`<?define T = "LogDir" ?><Property Id="$(var.T)" Value="C:\Windows\System32"/>`,
		`<Property Id="!(wix.T)" Value="x"/>`,
		`<SetProperty Id="$(var.T)" Value="x" Before="CostFinalize"/>`,
		`<SetDirectory Id="$(var.T)" Value="x"/>`,
		`<CustomAction Id="Ret" Property="$(var.T)" Value="x"/>`,
		`<CustomAction Id="Ret" Property="!(wix.T)" Value="x"/>`,
		`<CustomAction Id="Ret" Directory="$(var.T)" Value="x"/>`,
		`<Directory Id="$(var.T)" Name="n"/>`,
		`<StandardDirectory Id="$(var.T)"/>`,
	} {
		wantViolation(t, run([]string{"Ret", "$(var.T)", "!(wix.T)"}, pinned+el), "through a variable or property: a directory/property Id must be a literal")
		wantViolation(t, run([]string{"Ret", "$(var.T)", "!(wix.T)"}, pinned, el), "through a variable or property: a directory/property Id must be a literal")
	}
}

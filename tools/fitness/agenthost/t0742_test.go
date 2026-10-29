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
}

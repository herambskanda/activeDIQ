package main

import "testing"

// T-0762: MSBuild post-processing and MSI transforms fail A1 and cannot be approved via installer-allow.txt.
func TestT0762MSBuildAndTransforms(t *testing.T) {
	const sdk = `<Project Sdk="WixToolset.Sdk/5.0.0">`
	mk := func(allow []string, files map[string]string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", goodWxs)
		for p, b := range files {
			write(t, r, p, b)
		}
		return checkInstallerAllow(r, allow)
	}
	wantClean(t, mk(nil, map[string]string{"packaging/windows/agent.wixproj": sdk + `<PropertyGroup><OutputName>agent</OutputName></PropertyGroup></Project>`}))

	bad := map[string]string{
		"exec target":        sdk + `<Target Name="P" AfterTargets="Build"><Exec Command="msitran -a evil.mst $(TargetPath)"/></Target></Project>`,
		"usingtask":          sdk + `<UsingTask TaskName="X" AssemblyFile="x.dll"/></Project>`,
		"import":             sdk + `<Import Project="evil.targets"/></Project>`,
		"postbuild":          sdk + `<PropertyGroup><PostBuildEvent>MsiDb.exe</PostBuildEvent></PropertyGroup></Project>`,
		"custom hook":        sdk + `<PropertyGroup><CustomAfterMicrosoftCommonTargets>x</CustomAfterMicrosoftCommonTargets></PropertyGroup></Project>`,
		"propfunc":           sdk + `<PropertyGroup><X>$([System.IO.File]::Delete('a'))</X></PropertyGroup></Project>`,
		"import foreign sdk": sdk + `<Import Project="Sdk.targets" Sdk="Evil.Sdk/1.0"/></Project>`,
		"sdk list":           `<Project Sdk="WixToolset.Sdk/5.0.0;Evil.Sdk/1"></Project>`,
		"sdk list spaced":    `<Project Sdk="WixToolset.Sdk/5.0.0; Evil.Sdk/1"></Project>`,
		"sdk element":        sdk + `<Sdk Name="Evil.Sdk/1"/></Project>`,
		"foreign sdk":        `<Project Sdk="Evil.Sdk/1.0">` + `</Project>`,
	}
	for _, body := range bad {
		for _, f := range []string{"packaging/windows/agent.wixproj", "packaging/Directory.Build.targets", "Directory.Build.props"} {
			files := map[string]string{f: body}
			wantViolation(t, mk(nil, files), "T-0762")
			wantViolation(t, mk([]string{f, "agent.wixproj", "Directory.Build.targets"}, files), "T-0762")
		}
	}

	wantClean(t, mk(nil, map[string]string{"packaging/windows/agent.wixproj": sdk + `<Import Project="Sdk.props" Sdk="WixToolset.Sdk/5.0.0"/></Project>`}))

	// A Directory.Build.* unrelated to any WiX source is not judged.
	wantClean(t, mk(nil, map[string]string{"sidecars/Directory.Build.props": `<Project><Target Name="x"/></Project>`}))

	for _, ext := range []string{".mst", ".msp", ".pcp", ".MST"} {
		f := "vendor/evil" + ext
		r := mk(nil, map[string]string{f: "x"})
		wantViolation(t, r, "MSI transform")
		wantViolation(t, mk([]string{f}, map[string]string{f: "x"}), "MSI transform")
	}
}

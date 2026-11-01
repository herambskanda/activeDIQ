package main

import (
	"strings"
	"testing"
)

// T-0759: Merge/MergeRef and .msm files fail A1 and cannot be approved via installer-allow.txt.
func TestT0759MergeModules(t *testing.T) {
	run := func(allow []string, frag string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", strings.Replace(goodWxs, `</Package>`, frag+`</Package>`, 1))
		return checkInstallerAllow(r, allow)
	}
	wantClean(t, run(nil, ``))
	for _, el := range []string{
		`<DirectoryRef Id="LogDir"><Merge Id="M" SourceFile="evil.msm" DiskId="1" Language="0"/></DirectoryRef>`,
		`<Feature Id="F"><MergeRef Id="M"/></Feature>`,
	} {
		wantViolation(t, run(nil, el), "merge module")
		wantViolation(t, run([]string{"M"}, el), "merge module")
	}
	r := t.TempDir()
	write(t, r, "vendor/evil.msm", "x")
	wantViolation(t, checkInstaller(r), "prebuilt WiX intermediate")
}
